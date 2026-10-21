//! Read-only Postgres access for the state-evidence provider (HOR-CONNECTORS).
//!
//! Safety: only read operations are exposed (count / columns / aggregate / max), the
//! session is pinned to `default_transaction_read_only = on` with a statement timeout,
//! every call is gated by an allowlist of tables, and identifiers are validated before
//! interpolation (parameters can't be used for table/column names in Postgres). There
//! is no write surface on this client.

use crate::jsutil::{iso_from_ms, js_number_string};
use crate::state::analyze::StatusCount;
use crate::state::provider::StateClient;
use anyhow::{anyhow, bail, Result};
use async_trait::async_trait;
use chrono::{DateTime, NaiveDate, NaiveDateTime, Utc};
use horus_core::{redact_error_message, HealthStatus};
use regex::Regex;
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use tokio::sync::Mutex;
use tokio_postgres::types::Type;
use tokio_postgres::{Config, NoTls, Row};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostgresClientOpts {
    /// Connection string, e.g. postgres://user:pass@host:5432/db
    pub url: String,
    /// Schema to introspect (default: "public").
    pub schema: Option<String>,
    /// Only these tables may be queried (empty = auto-discover, all permitted).
    pub allowlist: Vec<String>,
}

static IDENT_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z_][A-Za-z0-9_$]*$").unwrap());

/// Reject anything that isn't a plain SQL identifier — table/column names can't be parameterized.
pub fn quote_ident(id: &str) -> Result<String> {
    if !IDENT_RE.is_match(id) {
        bail!("Unsafe SQL identifier: {id}");
    }
    Ok(format!("\"{id}\""))
}

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const QUERY_TIMEOUT: Duration = Duration::from_secs(8);

/// `sslmode` the way node-postgres/pg-connection-string reads it: absent or `disable` →
/// plain TCP; `no-verify` → TLS without certificate checks; anything else → verified TLS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SslMode {
    Disable,
    NoVerify,
    Verify,
}

/// Split the `sslmode` query param off the URL (tokio-postgres rejects `no-verify` and
/// would otherwise negotiate TLS on `prefer` by default, unlike node-postgres).
fn split_ssl_mode(url: &str) -> (String, SslMode) {
    let Ok(mut u) = url::Url::parse(url) else { return (url.to_string(), SslMode::Disable) };
    let mut mode = SslMode::Disable;
    let kept: Vec<(String, String)> = u
        .query_pairs()
        .filter_map(|(k, v)| {
            if k == "sslmode" || k == "ssl" {
                mode = match v.as_ref() {
                    "disable" | "false" | "0" => SslMode::Disable,
                    "no-verify" => SslMode::NoVerify,
                    _ => SslMode::Verify,
                };
                None
            } else {
                Some((k.into_owned(), v.into_owned()))
            }
        })
        .collect();
    if kept.is_empty() {
        u.set_query(None);
    } else {
        u.query_pairs_mut().clear().extend_pairs(kept);
    }
    (u.to_string(), mode)
}

#[derive(Debug)]
struct NoVerify;

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &rustls::crypto::ring::default_provider().signature_verification_algorithms)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &rustls::crypto::ring::default_provider().signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider().signature_verification_algorithms.supported_schemes()
    }
}

fn tls_config(mode: SslMode) -> rustls::ClientConfig {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider).with_safe_default_protocol_versions().expect("rustls protocol versions");
    match mode {
        SslMode::NoVerify => builder.dangerous().with_custom_certificate_verifier(Arc::new(NoVerify)).with_no_client_auth(),
        _ => {
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            builder.with_root_certificates(roots).with_no_client_auth()
        }
    }
}

pub struct PostgresStateClient {
    opts: PostgresClientOpts,
    client: Mutex<Option<tokio_postgres::Client>>,
}

impl PostgresStateClient {
    pub fn new(opts: PostgresClientOpts) -> Self {
        Self { opts, client: Mutex::new(None) }
    }

    fn schema(&self) -> &str {
        self.opts.schema.as_deref().unwrap_or("public")
    }

    fn assert_allowed(&self, table: &str) -> Result<()> {
        if self.opts.allowlist.is_empty() {
            return Ok(()); // empty = auto-discover mode
        }
        if !self.opts.allowlist.iter().any(|t| t == table) {
            bail!("Table \"{table}\" is not allowlisted");
        }
        Ok(())
    }

    async fn connect(&self) -> Result<tokio_postgres::Client> {
        let (url, ssl) = split_ssl_mode(&self.opts.url);
        let mut config: Config = url.parse()?;
        config
            .connect_timeout(CONNECT_TIMEOUT)
            .application_name("horus-readonly")
            .options("-c statement_timeout=8000");
        let addr = match (config.get_hosts().first(), config.get_ports().first()) {
            (Some(tokio_postgres::config::Host::Tcp(h)), port) => format!("{h}:{}", port.copied().unwrap_or(5432)),
            _ => String::new(),
        };
        let client = match ssl {
            SslMode::Disable => {
                config.ssl_mode(tokio_postgres::config::SslMode::Disable);
                let (client, conn) = tokio::time::timeout(CONNECT_TIMEOUT, config.connect(NoTls)).await?.map_err(|e| pg_error(e, &addr))?;
                tokio::spawn(async move {
                    let _ = conn.await;
                });
                client
            }
            mode => {
                config.ssl_mode(tokio_postgres::config::SslMode::Require);
                let tls = tokio_postgres_rustls::MakeRustlsConnect::new(tls_config(mode));
                let (client, conn) = tokio::time::timeout(CONNECT_TIMEOUT, config.connect(tls)).await?.map_err(|e| pg_error(e, &addr))?;
                tokio::spawn(async move {
                    let _ = conn.await;
                });
                client
            }
        };
        // Belt-and-braces: pin the session read-only so no statement can mutate.
        client.batch_execute("SET default_transaction_read_only = on").await.map_err(|e| pg_error(e, ""))?;
        Ok(client)
    }

    /// Run `f` against the lazily-opened connection with the query timeout applied.
    async fn query(&self, sql: &str, params: &[&(dyn tokio_postgres::types::ToSql + Sync)]) -> Result<Vec<Row>> {
        let mut guard = self.client.lock().await;
        if guard.is_none() {
            *guard = Some(self.connect().await?);
        }
        let client = guard.as_ref().unwrap();
        let rows = tokio::time::timeout(QUERY_TIMEOUT, client.query(sql, params))
            .await
            .map_err(|_| anyhow!("Postgres query timed out"))?
            .map_err(|e| pg_error(e, ""))?;
        Ok(rows)
    }
}

/// node-postgres wording: a server error is its message (`password authentication failed for
/// user "x"`), a socket failure Node's `connect ECONNREFUSED host:port`. tokio-postgres's own
/// Display (`db error`, `error connecting to server`) hides both.
fn pg_error(e: tokio_postgres::Error, addr: &str) -> anyhow::Error {
    if let Some(db) = e.as_db_error() {
        return anyhow!("{}", db.message());
    }
    let mut src: Option<&(dyn std::error::Error + 'static)> = std::error::Error::source(&e);
    while let Some(s) = src {
        if let Some(io) = s.downcast_ref::<std::io::Error>() {
            if let Some(msg) = crate::jsutil::node_connect_error(io, addr) {
                return anyhow!(msg);
            }
        }
        if s.to_string() == "server does not support TLS" {
            return anyhow!("The server does not support SSL connections");
        }
        src = s.source();
    }
    anyhow::Error::new(e)
}

/// `v instanceof Date ? v.toISOString() : String(v)` for a `MAX(column)` cell.
fn max_cell_to_string(row: &Row) -> Result<Option<Option<String>>> {
    let ty = row.columns()[0].type_().clone();
    let out = match ty {
        Type::TIMESTAMPTZ => row.try_get::<_, Option<DateTime<Utc>>>(0)?.map(|d| iso_from_ms(d.timestamp_millis())),
        // node-postgres parses these in the process-local timezone; we read them as UTC.
        Type::TIMESTAMP => row.try_get::<_, Option<NaiveDateTime>>(0)?.map(|d| iso_from_ms(d.and_utc().timestamp_millis())),
        Type::DATE => row
            .try_get::<_, Option<NaiveDate>>(0)?
            .map(|d| iso_from_ms(d.and_hms_opt(0, 0, 0).unwrap_or_default().and_utc().timestamp_millis())),
        Type::TEXT | Type::VARCHAR | Type::NAME | Type::BPCHAR => row.try_get::<_, Option<String>>(0)?,
        Type::INT2 => row.try_get::<_, Option<i16>>(0)?.map(|n| n.to_string()),
        Type::INT4 => row.try_get::<_, Option<i32>>(0)?.map(|n| n.to_string()),
        Type::INT8 => row.try_get::<_, Option<i64>>(0)?.map(|n| n.to_string()),
        Type::FLOAT4 => row.try_get::<_, Option<f32>>(0)?.map(|n| js_number_string(n as f64)),
        Type::FLOAT8 => row.try_get::<_, Option<f64>>(0)?.map(js_number_string),
        Type::BOOL => row.try_get::<_, Option<bool>>(0)?.map(|b| b.to_string()),
        _ => return Ok(None), // unsupported type: caller re-queries with a ::text cast
    };
    Ok(Some(out))
}

#[async_trait]
impl StateClient for PostgresStateClient {
    /// Base tables in the configured schema (StateClient: "collections" === tables).
    async fn list_collections(&self) -> Result<Vec<String>> {
        let rows = self
            .query(
                "SELECT table_name FROM information_schema.tables
       WHERE table_schema = $1 AND table_type = 'BASE TABLE'
       ORDER BY table_name",
                &[&self.schema()],
            )
            .await?;
        Ok(rows.iter().filter_map(|r| r.try_get::<_, Option<String>>(0).ok().flatten()).filter(|s| !s.is_empty()).collect())
    }

    async fn count(&self, table: &str) -> Result<i64> {
        self.assert_allowed(table)?;
        let sql = format!("SELECT COUNT(*)::bigint AS n FROM {}.{}", quote_ident(self.schema())?, quote_ident(table)?);
        let rows = self.query(&sql, &[]).await?;
        Ok(rows.first().and_then(|r| r.try_get::<_, Option<i64>>(0).ok().flatten()).unwrap_or(0))
    }

    /// Column names (StateClient: "fields" === columns) — for date/status field detection.
    async fn sample_fields(&self, table: &str) -> Result<Vec<String>> {
        self.assert_allowed(table)?;
        let rows = self
            .query(
                "SELECT column_name FROM information_schema.columns
       WHERE table_schema = $1 AND table_name = $2",
                &[&self.schema(), &table],
            )
            .await?;
        Ok(rows.iter().filter_map(|r| r.try_get::<_, Option<String>>(0).ok().flatten()).filter(|s| !s.is_empty()).collect())
    }

    async fn max_date(&self, table: &str, field: &str) -> Result<Option<String>> {
        self.assert_allowed(table)?;
        let from = format!("{}.{}", quote_ident(self.schema())?, quote_ident(table)?);
        let col = quote_ident(field)?;
        let rows = self.query(&format!("SELECT MAX({col}) AS m FROM {from}"), &[]).await?;
        let Some(row) = rows.first() else { return Ok(None) };
        if let Some(v) = max_cell_to_string(row)? {
            return Ok(v);
        }
        let rows = self.query(&format!("SELECT MAX({col})::text AS m FROM {from}"), &[]).await?;
        Ok(rows.first().and_then(|r| r.try_get::<_, Option<String>>(0).ok().flatten()))
    }

    async fn group_by(&self, table: &str, field: &str) -> Result<Vec<StatusCount>> {
        self.assert_allowed(table)?;
        let limit = 25;
        let sql = format!(
            "SELECT {}::text AS value, COUNT(*)::bigint AS count
       FROM {}.{}
       GROUP BY 1 ORDER BY 2 DESC LIMIT {}",
            quote_ident(field)?,
            quote_ident(self.schema())?,
            quote_ident(table)?,
            limit.clamp(1, 100)
        );
        let rows = self.query(&sql, &[]).await?;
        Ok(rows
            .iter()
            .map(|r| StatusCount {
                value: r.try_get::<_, Option<String>>(0).ok().flatten().unwrap_or_else(|| "(none)".to_string()),
                count: r.try_get::<_, Option<i64>>(1).ok().flatten().unwrap_or(0),
            })
            .collect())
    }

    async fn health(&self) -> HealthStatus {
        match self.query("SELECT 1", &[]).await {
            Ok(_) => HealthStatus { ok: true, detail: "postgres reachable".to_string() },
            // Connection failures can wrap the credential-bearing URL.
            Err(err) => HealthStatus { ok: false, detail: redact_error_message(&err) },
        }
    }

    async fn close(&self) {
        // Dropping the client ends the connection task.
        self.client.lock().await.take();
    }
}
