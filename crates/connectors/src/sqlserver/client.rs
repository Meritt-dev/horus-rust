//! SQL Server state client (`sqlserver/client.ts`) over `tiberius`. Fixed SELECTs only.
//! Use a SELECT-only SQL login; `readonly` intent is routing, not authorization.

use crate::jsutil::{iso_from_ms, parse_js_date_ms};
use crate::state::analyze::StatusCount;
use crate::state::provider::StateClient;
use anyhow::{anyhow, bail, Result};
use async_trait::async_trait;
use chrono::{DateTime, NaiveDate, NaiveDateTime, Utc};
use horus_core::{redact_error_message, validate_sqlserver, HealthStatus, Issues, SqlServerConfig};
use regex::Regex;
use std::sync::LazyLock;
use std::time::Duration;
use tiberius::{AuthMethod, Client, ColumnData, Config, EncryptionLevel, Row};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_util::compat::{Compat, TokioAsyncWriteCompatExt};

static IDENT_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z_][A-Za-z0-9_$]*$").unwrap());

pub fn sql_identifier(name: &str) -> Result<String> {
    if !IDENT_RE.is_match(name) {
        bail!("Unsafe SQL Server identifier");
    }
    Ok(format!("[{name}]"))
}

type Conn = Client<Compat<TcpStream>>;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(8);

/// `mssql://user:pass@host:port/db?encrypt=true&trustServerCertificate=true` or an ADO
/// connection string (both accepted by node-mssql's `parseConnectionString`).
fn parse_config(url: &str) -> Result<Config> {
    if url.starts_with("mssql://") || url.starts_with("sqlserver://") {
        let u = url::Url::parse(url)?;
        let mut cfg = Config::new();
        cfg.host(u.host_str().unwrap_or("localhost"));
        cfg.port(u.port().unwrap_or(1433));
        if !u.username().is_empty() {
            let user = percent_encoding_decode(u.username());
            let pass = u.password().map(percent_encoding_decode).unwrap_or_default();
            cfg.authentication(AuthMethod::sql_server(user, pass));
        }
        let db = u.path().trim_start_matches('/');
        if !db.is_empty() {
            cfg.database(db);
        }
        let mut trust = false;
        for (k, v) in u.query_pairs() {
            match k.to_ascii_lowercase().as_str() {
                "encrypt" if v == "false" || v == "0" => {
                    cfg.encryption(EncryptionLevel::Off);
                    trust = true;
                }
                "encrypt" => cfg.encryption(EncryptionLevel::Required),
                "trustservercertificate" if v == "true" || v == "1" => trust = true,
                _ => {}
            }
        }
        if trust {
            cfg.trust_cert();
        }
        Ok(cfg)
    } else {
        let mut cfg = Config::from_ado_string(url)?;
        // tedious `encrypt: false` still TLS-wraps the login packet but never validates the
        // certificate; tiberius `Off` validates it (and rustls rejects SQL Server's self-signed
        // v1 cert). Skip validation there too, unless the string pins a CA.
        if ado_value(url, "encrypt").is_some_and(|v| matches!(v.to_ascii_lowercase().as_str(), "false" | "no"))
            && ado_value(url, "trustservercertificateca").is_none()
        {
            cfg.trust_cert();
        }
        Ok(cfg)
    }
}

/// Value of an ADO connection-string key (case-insensitive key, trimmed value).
fn ado_value<'a>(ado: &'a str, key: &str) -> Option<&'a str> {
    ado.split(';').find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        k.trim().eq_ignore_ascii_case(key).then(|| v.trim())
    })
}

/// node-mssql/tedious wording for the failures users actually hit: server errors print only the
/// server's message (`Login failed for user 'x'.`), connection failures `Failed to connect to
/// host:port - …`.
fn tedious_message(e: tiberius::error::Error, addr: &str) -> String {
    use tiberius::error::Error as E;
    match e {
        E::Server(token) => token.message().to_string(),
        E::Io { kind: std::io::ErrorKind::ConnectionRefused, .. } => {
            format!("Failed to connect to {addr} - Could not connect (sequence)")
        }
        // tiberius appends a multi-sentence remediation guide; keep the first sentence.
        E::Tls(msg) => format!("Failed to connect to {addr} - {}", msg.split(". ").next().unwrap_or(&msg)),
        other => other.to_string(),
    }
}

fn percent_encoding_decode(s: &str) -> String {
    url::form_urlencoded::parse(s.as_bytes()).map(|(k, v)| format!("{k}{v}")).collect()
}

/// JS `String(value)` for a result cell; None for SQL NULL.
fn cell_string(c: &ColumnData<'_>) -> Option<String> {
    Some(match c {
        ColumnData::String(v) => v.as_ref()?.to_string(),
        ColumnData::I16(v) => (*v)?.to_string(),
        ColumnData::I32(v) => (*v)?.to_string(),
        ColumnData::I64(v) => (*v)?.to_string(),
        ColumnData::U8(v) => (*v)?.to_string(),
        ColumnData::F32(v) => crate::jsutil::js_number_string((*v)? as f64),
        ColumnData::F64(v) => crate::jsutil::js_number_string((*v)?),
        ColumnData::Bit(v) => (*v)?.to_string(),
        ColumnData::Guid(v) => (*v)?.to_string(),
        ColumnData::Numeric(v) => (*v)?.to_string(),
        ColumnData::Binary(v) => format!("{:?}", v.as_ref()?),
        other => format!("{other:?}"),
    })
}

pub struct SqlServerStateClient {
    pub config: SqlServerConfig,
    pool: Mutex<Option<Conn>>,
}

impl SqlServerStateClient {
    pub fn new(config: SqlServerConfig) -> Result<Self> {
        let mut issues = Issues::default();
        validate_sqlserver(&mut issues, &config);
        if let Some(i) = issues.items.first() {
            bail!("sqlserver config: {}: {}", i.path, i.message);
        }
        Ok(Self { config, pool: Mutex::new(None) })
    }

    async fn connect(&self) -> Result<Conn> {
        let Some(url) = self.config.url.as_deref().filter(|u| !u.is_empty()) else { bail!("SQL Server URL is not configured") };
        let mut cfg = parse_config(url)?;
        cfg.database(&self.config.database);
        cfg.readonly(true);
        cfg.application_name("horus-readonly");
        let addr = cfg.get_addr();
        let connect = async {
            let tcp = TcpStream::connect(&addr).await.map_err(|e| anyhow!(tedious_message(e.into(), &addr)))?;
            tcp.set_nodelay(true)?;
            Client::connect(cfg, tcp.compat_write()).await.map_err(|e| anyhow!(tedious_message(e, &addr)))
        };
        match tokio::time::timeout(CONNECT_TIMEOUT, connect).await {
            Ok(Ok(c)) => Ok(c),
            Ok(Err(e)) => Err(anyhow!(redact_error_message(&e))),
            Err(_) => Err(anyhow!("SQL Server connection timed out")),
        }
    }

    fn table(&self, name: &str) -> Result<String> {
        if !self.config.tables.iter().any(|t| t == name) {
            bail!("Table is not allowlisted");
        }
        Ok(format!("{}.{}", sql_identifier(&self.config.schema)?, sql_identifier(name)?))
    }

    /// Single pooled connection (`pool: { max: 1 }`); the lock serializes requests.
    async fn query(&self, sql: &str, params: &[&dyn tiberius::ToSql]) -> Result<Vec<Row>> {
        let mut guard = self.pool.lock().await;
        if guard.is_none() {
            *guard = Some(self.connect().await?);
        }
        let conn = guard.as_mut().unwrap();
        let rows = tokio::time::timeout(REQUEST_TIMEOUT, async { conn.query(sql, params).await?.into_first_result().await })
            .await
            .map_err(|_| anyhow!("SQL Server request timed out"))?
            .map_err(|e| anyhow!(tedious_message(e, "")))?;
        Ok(rows)
    }
}

#[async_trait]
impl StateClient for SqlServerStateClient {
    async fn list_collections(&self) -> Result<Vec<String>> {
        Ok(self.config.tables.clone())
    }

    async fn count(&self, table: &str) -> Result<i64> {
        let name = self.table(table)?;
        let rows = self.query(&format!("SELECT COUNT_BIG(*) AS n FROM {name}"), &[]).await?;
        match rows.first().and_then(|r| r.get::<i64, _>(0)) {
            Some(n) if n >= 0 => Ok(n),
            _ => bail!("Invalid row count"),
        }
    }

    async fn sample_fields(&self, table: &str) -> Result<Vec<String>> {
        self.table(table)?;
        let rows = self
            .query(
                "SELECT COLUMN_NAME AS name FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=@P1 AND TABLE_NAME=@P2",
                &[&self.config.schema.as_str(), &table],
            )
            .await?;
        Ok(rows.iter().map(|r| r.get::<&str, _>(0).unwrap_or_default().to_string()).collect())
    }

    async fn max_date(&self, table: &str, field: &str) -> Result<Option<String>> {
        let name = self.table(table)?;
        let rows = self.query(&format!("SELECT MAX({}) AS value FROM {name}", sql_identifier(field)?), &[]).await?;
        let Some(row) = rows.first() else { return Ok(None) };
        // `new Date(v)`: datetime columns arrive as dates (read as UTC); strings via Date.parse.
        if let Ok(Some(d)) = row.try_get::<DateTime<Utc>, _>(0) {
            return Ok(Some(iso_from_ms(d.timestamp_millis())));
        }
        if let Ok(Some(d)) = row.try_get::<NaiveDateTime, _>(0) {
            return Ok(Some(iso_from_ms(d.and_utc().timestamp_millis())));
        }
        if let Ok(Some(d)) = row.try_get::<NaiveDate, _>(0) {
            return Ok(d.and_hms_opt(0, 0, 0).map(|d| iso_from_ms(d.and_utc().timestamp_millis())));
        }
        if let Ok(Some(s)) = row.try_get::<&str, _>(0) {
            return Ok(parse_js_date_ms(s).map(iso_from_ms));
        }
        Ok(None)
    }

    async fn group_by(&self, table: &str, field: &str) -> Result<Vec<StatusCount>> {
        let name = self.table(table)?;
        let column = sql_identifier(field)?;
        let rows = self
            .query(&format!("SELECT TOP (25) {column} AS value, COUNT_BIG(*) AS count FROM {name} GROUP BY {column} ORDER BY COUNT_BIG(*) DESC"), &[])
            .await?;
        Ok(rows
            .into_iter()
            .map(|r| {
                let count = r.get::<i64, _>(1).unwrap_or(0);
                let mut cells = r.into_iter();
                let value = cells.next().and_then(|c| cell_string(&c)).map(|s| s.chars().take(200).collect()).unwrap_or_else(|| "(none)".to_string());
                StatusCount { value, count }
            })
            .collect())
    }

    async fn health(&self) -> HealthStatus {
        match self.query("SELECT 1 AS ok", &[]).await {
            Ok(_) => HealthStatus { ok: true, detail: "SQL Server read connection verified".to_string() },
            Err(e) => HealthStatus { ok: false, detail: redact_error_message(&e) },
        }
    }

    async fn close(&self) {
        if let Some(conn) = self.pool.lock().await.take() {
            let _ = conn.close().await;
        }
    }
}
