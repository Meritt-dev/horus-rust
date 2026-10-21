//! Read-only MongoDB access for the state-evidence provider (HOR-33).
//!
//! Safety: only read operations are exposed (count / sample / aggregate), every
//! call is gated by an allowlist of collections, and the connection is opened
//! with a read preference. There is no write surface on this client.

use crate::jsutil::{iso_from_ms, js_number_string};
use crate::state::analyze::StatusCount;
use crate::state::provider::StateClient;
use crate::state::record_query::{redact_record_value, validate_state_record_query, RecordValue, StateRecordQuery};
use anyhow::{bail, Result};
use async_trait::async_trait;
use base64::Engine;
use futures::TryStreamExt;
use horus_core::{redact_error_message, HealthStatus};
use mongodb::bson::{doc, oid::ObjectId, Bson, Document};
use mongodb::options::{ClientOptions, ReadPreference, SelectionCriteria};
use mongodb::{Client, Database};
use regex::Regex;
use serde_json::Value;
use std::sync::LazyLock;
use std::time::Duration;
use tokio::sync::Mutex;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MongoClientOpts {
    pub url: String,
    pub database: String,
    /// Only these collections may be queried.
    pub allowlist: Vec<String>,
}

static OBJECT_ID_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)^[a-f0-9]{24}$").unwrap());

/// What `JSON.stringify` makes of a Node-driver document: ObjectId → hex, Date → ISO,
/// Binary → base64, numbers → numbers; exotic types fall back to relaxed extended JSON.
fn bson_to_js_json(b: Bson) -> Option<Value> {
    Some(match b {
        Bson::Null => Value::Null,
        Bson::Undefined => return None, // dropped from objects by JSON.stringify
        Bson::Boolean(v) => Value::Bool(v),
        Bson::String(s) => Value::String(s),
        Bson::Int32(n) => Value::from(n),
        Bson::Int64(n) => Value::from(n),
        Bson::Double(f) => serde_json::Number::from_f64(f).map(Value::Number).unwrap_or(Value::Null),
        Bson::ObjectId(id) => Value::String(id.to_hex()),
        Bson::DateTime(d) => Value::String(iso_from_ms(d.timestamp_millis())),
        Bson::Binary(bin) => Value::String(base64::engine::general_purpose::STANDARD.encode(bin.bytes)),
        Bson::Array(items) => Value::Array(items.into_iter().map(|i| bson_to_js_json(i).unwrap_or(Value::Null)).collect()),
        Bson::Document(d) => Value::Object(d.into_iter().filter_map(|(k, v)| bson_to_js_json(v).map(|v| (k, v))).collect()),
        other => other.into_relaxed_extjson(),
    })
}

/// JS `String(value)` for an aggregation `_id`.
fn bson_to_js_string(b: &Bson) -> String {
    match b {
        Bson::String(s) => s.clone(),
        Bson::Int32(n) => n.to_string(),
        Bson::Int64(n) => n.to_string(),
        Bson::Double(f) => js_number_string(*f),
        Bson::Boolean(v) => v.to_string(),
        Bson::ObjectId(id) => id.to_hex(),
        Bson::DateTime(d) => iso_from_ms(d.timestamp_millis()),
        Bson::Document(_) => "[object Object]".to_string(),
        Bson::Array(items) => items.iter().map(bson_to_js_string).collect::<Vec<_>>().join(","),
        other => other.clone().into_relaxed_extjson().to_string(),
    }
}

fn bson_to_i64(b: Option<&Bson>) -> i64 {
    match b {
        Some(Bson::Int32(n)) => *n as i64,
        Some(Bson::Int64(n)) => *n,
        Some(Bson::Double(f)) => *f as i64,
        _ => 0,
    }
}

pub struct MongoStateClient {
    opts: MongoClientOpts,
    client: Mutex<Option<Client>>,
}

impl MongoStateClient {
    pub fn new(opts: MongoClientOpts) -> Self {
        Self { opts, client: Mutex::new(None) }
    }

    pub fn database(&self) -> &str {
        &self.opts.database
    }

    fn assert_allowed(&self, collection: &str) -> Result<()> {
        if self.opts.allowlist.is_empty() {
            return Ok(()); // empty = auto-discover mode, all collections permitted
        }
        if !self.opts.allowlist.iter().any(|c| c == collection) {
            bail!("Collection \"{collection}\" is not allowlisted for {}", self.opts.database);
        }
        Ok(())
    }

    async fn db(&self) -> Result<Database> {
        let mut guard = self.client.lock().await;
        if guard.is_none() {
            let mut options = ClientOptions::parse(&self.opts.url).await?;
            options.server_selection_timeout = Some(Duration::from_secs(5));
            options.selection_criteria = Some(SelectionCriteria::ReadPreference(ReadPreference::secondary_preferred(None)));
            *guard = Some(Client::with_options(options)?);
        }
        Ok(guard.as_ref().unwrap().database(&self.opts.database))
    }

    /// Bounded projected equality reads from an explicitly allowlisted collection.
    pub async fn records(&self, input: &StateRecordQuery) -> Result<Vec<Value>> {
        validate_state_record_query(input)?;
        if self.opts.allowlist.is_empty() {
            bail!("Projected record reads require an explicit collection allowlist");
        }
        self.assert_allowed(&input.collection)?;
        let mut filter = Document::new();
        for w in &input.where_ {
            let v = match &w.value {
                RecordValue::Str(s) if w.field == "_id" && OBJECT_ID_RE.is_match(s) => Bson::ObjectId(ObjectId::parse_str(s)?),
                RecordValue::Str(s) => Bson::String(s.clone()),
                RecordValue::Num(n) => match n.as_i64() {
                    Some(i) if i32::try_from(i).is_ok() => Bson::Int32(i as i32),
                    Some(i) => Bson::Int64(i),
                    None => Bson::Double(n.as_f64().unwrap_or(0.0)),
                },
                RecordValue::Bool(b) => Bson::Boolean(*b),
            };
            filter.insert(w.field.clone(), v);
        }
        let mut projection = Document::new();
        for f in &input.fields {
            projection.insert(f.clone(), 1);
        }
        if !input.fields.iter().any(|f| f == "_id") {
            projection.insert("_id", 0);
        }
        let rows: Vec<Document> = self
            .db()
            .await?
            .collection::<Document>(&input.collection)
            .find(filter)
            .projection(projection)
            .max_time(Duration::from_secs(5))
            .limit(input.limit)
            .await?
            .try_collect()
            .await?;
        let json: Vec<Value> = rows.into_iter().map(|d| bson_to_js_json(Bson::Document(d)).unwrap_or(Value::Null)).collect();
        if serde_json::to_string(&json)?.len() > 64000 {
            bail!("Record evidence exceeds 64 KB; request fewer fields");
        }
        Ok(json.into_iter().map(redact_record_value).collect())
    }

    pub async fn count_with_filter(&self, collection: &str, filter: Document) -> Result<i64> {
        self.assert_allowed(collection)?;
        Ok(self.db().await?.collection::<Document>(collection).count_documents(filter).await? as i64)
    }
}

#[async_trait]
impl StateClient for MongoStateClient {
    /// List all collection names in the configured database (for auto-discovery).
    async fn list_collections(&self) -> Result<Vec<String>> {
        let names = self.db().await?.list_collection_names().await?;
        Ok(names.into_iter().filter(|n| !n.is_empty()).collect())
    }

    async fn count(&self, collection: &str) -> Result<i64> {
        self.count_with_filter(collection, Document::new()).await
    }

    /// Field names from the most recent document (for field-shape detection).
    async fn sample_fields(&self, collection: &str) -> Result<Vec<String>> {
        self.assert_allowed(collection)?;
        let doc = self
            .db()
            .await?
            .collection::<Document>(collection)
            .find_one(Document::new())
            .sort(doc! { "_id": -1 })
            .projection(Document::new())
            .await?;
        Ok(doc.map(|d| d.keys().cloned().collect()).unwrap_or_default())
    }

    /// ISO timestamp of the newest value of a date field, or None.
    async fn max_date(&self, collection: &str, field: &str) -> Result<Option<String>> {
        self.assert_allowed(collection)?;
        let mut cursor = self
            .db()
            .await?
            .collection::<Document>(collection)
            .find(doc! { field: { "$type": "date" } })
            .projection(doc! { field: 1 })
            .sort(doc! { field: -1 })
            .limit(1)
            .await?;
        let Some(doc) = cursor.try_next().await? else { return Ok(None) };
        Ok(match doc.get(field) {
            Some(Bson::DateTime(d)) => Some(iso_from_ms(d.timestamp_millis())),
            Some(Bson::String(s)) => Some(s.clone()),
            _ => None,
        })
    }

    /// Count documents grouped by a string field (top 25 values).
    async fn group_by(&self, collection: &str, field: &str) -> Result<Vec<StatusCount>> {
        self.assert_allowed(collection)?;
        let limit = 25;
        let rows: Vec<Document> = self
            .db()
            .await?
            .collection::<Document>(collection)
            .aggregate(vec![
                doc! { "$group": { "_id": format!("${field}"), "count": { "$sum": 1 } } },
                doc! { "$sort": { "count": -1 } },
                doc! { "$limit": limit },
            ])
            .await?
            .try_collect()
            .await?;
        Ok(rows
            .iter()
            .map(|r| StatusCount {
                value: match r.get("_id") {
                    None | Some(Bson::Null) | Some(Bson::Undefined) => "(none)".to_string(),
                    Some(v) => bson_to_js_string(v),
                },
                count: bson_to_i64(r.get("count")),
            })
            .collect())
    }

    async fn health(&self) -> HealthStatus {
        let ping = async {
            let db = self.db().await?;
            db.run_command(doc! { "ping": 1 }).await?;
            Ok::<(), anyhow::Error>(())
        };
        match ping.await {
            Ok(()) => HealthStatus { ok: true, detail: format!("mongodb {} reachable", self.opts.database) },
            // Driver errors (parse, server selection) can echo the URI creds.
            Err(err) => HealthStatus { ok: false, detail: redact_error_message(&err) },
        }
    }

    async fn close(&self) {
        if let Some(client) = self.client.lock().await.take() {
            client.shutdown().await;
        }
    }
}

impl std::fmt::Debug for MongoStateClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MongoStateClient").field("database", &self.opts.database).finish()
    }
}
