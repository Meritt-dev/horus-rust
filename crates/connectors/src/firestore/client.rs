//! Firestore state client over the REST API (`firestore/client.ts`). Auth reuses the
//! local `gcloud` login (`auth print-access-token`); explicit collection paths,
//! aggregates and date/status projections only — no customer document export.

use crate::cloud_logs::native_cli::native_output;
use crate::http::{fetch_with_retry, HttpRequestOptions};
use crate::jsutil::{iso_from_ms, now_ms, parse_js_date_ms};
use crate::state::analyze::{StatusCount, DATE_FIELDS, STATUS_FIELDS};
use crate::state::provider::StateClient;
use anyhow::{bail, Result};
use async_trait::async_trait;
use horus_core::{redact_error_message, validate_firestore, FirestoreConfig, Issues, HealthStatus};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use tokio::sync::Mutex;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FsValue {
    string_value: Option<String>,
    timestamp_value: Option<String>,
    integer_value: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct FsDocument {
    fields: Option<HashMap<String, FsValue>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FsAggregate {
    aggregate_fields: HashMap<String, FsValue>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct FsRow {
    document: Option<FsDocument>,
    result: Option<FsAggregate>,
}

pub struct FirestoreStateClient {
    pub config: FirestoreConfig,
    http: reqwest::Client,
    token: Mutex<Option<(String, i64)>>,
}

impl FirestoreStateClient {
    pub fn new(config: FirestoreConfig) -> Result<Self> {
        let mut issues = Issues::default();
        validate_firestore(&mut issues, &config);
        if let Some(i) = issues.items.first() {
            bail!("firestore config: {}: {}", i.path, i.message);
        }
        Ok(Self { config, http: reqwest::Client::new(), token: Mutex::new(None) })
    }

    fn scope(&self, collection: &str) -> Result<(String, Value)> {
        if !self.config.collections.iter().any(|c| c == collection) {
            bail!("Collection is not allowlisted");
        }
        let mut parts: Vec<&str> = collection.split('/').collect();
        let collection_id = parts.pop().unwrap_or_default();
        let path = if parts.is_empty() {
            String::new()
        } else {
            format!("/{}", parts.iter().map(|p| url::form_urlencoded::byte_serialize(p.as_bytes()).collect::<String>()).collect::<Vec<_>>().join("/"))
        };
        Ok((
            format!(
                "https://firestore.googleapis.com/v1/projects/{}/databases/{}/documents{path}",
                self.config.project, self.config.database
            ),
            json!([{ "collectionId": collection_id }]),
        ))
    }

    async fn access_token(&self) -> Result<String> {
        let mut guard = self.token.lock().await;
        if let Some((value, until)) = guard.as_ref() {
            if *until >= now_ms() {
                return Ok(value.clone());
            }
        }
        let value = native_output(&self.config.executable, &["auth", "print-access-token", "--quiet"]).await?;
        *guard = Some((value.clone(), now_ms() + 5 * 60_000));
        Ok(value)
    }

    async fn request(&self, collection: &str, query: Map<String, Value>, aggregate: bool) -> Result<Vec<FsRow>> {
        let (parent, from) = self.scope(collection)?;
        let token = self.access_token().await?;
        let mut structured_query = Map::new();
        structured_query.insert("from".into(), from);
        structured_query.extend(query);
        let body = if aggregate {
            json!({ "structuredAggregationQuery": { "structuredQuery": structured_query, "aggregations": [{ "alias": "count", "count": {} }] } })
        } else {
            json!({ "structuredQuery": structured_query })
        };
        let req = self
            .http
            .post(format!("{parent}{}", if aggregate { ":runAggregationQuery" } else { ":runQuery" }))
            .bearer_auth(&token)
            .header("Content-Type", "application/json")
            .body(serde_json::to_vec(&body)?);
        let r = fetch_with_retry(req, &HttpRequestOptions::with_timeout_ms(15000)).await?;
        let status = r.status().as_u16();
        if !r.status().is_success() {
            if status == 401 {
                self.token.lock().await.take();
            }
            bail!("Firestore HTTP {status}");
        }
        Ok(r.json::<Vec<FsRow>>().await?)
    }

    async fn aggregate(&self, collection: &str, where_: Option<Value>) -> Result<i64> {
        let mut q = Map::new();
        if let Some(w) = where_ {
            q.insert("where".into(), w);
        }
        let rows = self.request(collection, q, true).await?;
        let n = rows
            .iter()
            .find_map(|x| x.result.as_ref())
            .and_then(|r| r.aggregate_fields.get("count"))
            .and_then(|v| v.integer_value.as_deref())
            .and_then(|s| s.trim().parse::<i64>().ok());
        match n {
            Some(n) if n >= 0 && n <= 9_007_199_254_740_991 => Ok(n),
            _ => bail!("Invalid Firestore aggregate count"),
        }
    }

    fn field(field: &str) -> Result<Value> {
        if !DATE_FIELDS.contains(&field) && !STATUS_FIELDS.contains(&field) {
            bail!("Unsupported state field");
        }
        Ok(json!({ "fieldPath": field }))
    }

    fn obj(pairs: Vec<(&str, Value)>) -> Map<String, Value> {
        pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect()
    }
}

#[async_trait]
impl StateClient for FirestoreStateClient {
    async fn list_collections(&self) -> Result<Vec<String>> {
        Ok(self.config.collections.clone())
    }

    async fn count(&self, collection: &str) -> Result<i64> {
        self.aggregate(collection, None).await
    }

    async fn sample_fields(&self, collection: &str) -> Result<Vec<String>> {
        let fields: Vec<Value> = DATE_FIELDS.iter().chain(STATUS_FIELDS.iter()).map(|f| json!({ "fieldPath": f })).collect();
        let rows = self.request(collection, Self::obj(vec![("select", json!({ "fields": fields })), ("limit", json!(20))]), false).await?;
        let mut seen: Vec<String> = Vec::new();
        for x in rows {
            if let Some(fields) = x.document.and_then(|d| d.fields) {
                for k in fields.into_keys() {
                    if !seen.contains(&k) {
                        seen.push(k);
                    }
                }
            }
        }
        Ok(seen)
    }

    async fn max_date(&self, collection: &str, field: &str) -> Result<Option<String>> {
        let f = Self::field(field)?;
        let rows = self
            .request(
                collection,
                Self::obj(vec![
                    ("select", json!({ "fields": [f] })),
                    ("orderBy", json!([{ "field": f, "direction": "DESCENDING" }])),
                    ("limit", json!(1)),
                ]),
                false,
            )
            .await?;
        let v = rows.into_iter().find_map(|x| x.document).and_then(|d| d.fields).and_then(|mut f| f.remove(field));
        let date = v.and_then(|v| v.timestamp_value.or(v.string_value)).filter(|s| !s.is_empty());
        Ok(date.and_then(|d| parse_js_date_ms(&d)).map(iso_from_ms))
    }

    async fn group_by(&self, collection: &str, field: &str) -> Result<Vec<StatusCount>> {
        let f = Self::field(field)?;
        // ponytail: discover at most 25 statuses from 200 projected documents; add explicit status filters if exhaustive coverage is needed.
        let rows = self.request(collection, Self::obj(vec![("select", json!({ "fields": [f] })), ("limit", json!(200))]), false).await?;
        let mut values: Vec<String> = Vec::new();
        for x in rows {
            if let Some(v) = x.document.and_then(|d| d.fields).and_then(|mut f| f.remove(field)).and_then(|v| v.string_value) {
                if !values.contains(&v) {
                    values.push(v);
                }
            }
        }
        values.truncate(25);
        let mut out = Vec::new();
        for value in values {
            let count = self
                .aggregate(collection, Some(json!({ "fieldFilter": { "field": f, "op": "EQUAL", "value": { "stringValue": value } } })))
                .await?;
            out.push(StatusCount { value, count });
        }
        Ok(out)
    }

    async fn health(&self) -> HealthStatus {
        let first = self.config.collections.first().cloned().unwrap_or_default();
        match self.request(&first, Self::obj(vec![("select", json!({ "fields": [] })), ("limit", json!(1))]), false).await {
            Ok(_) => HealthStatus { ok: true, detail: "Firestore collection read access verified".to_string() },
            Err(e) => HealthStatus { ok: false, detail: redact_error_message(&e) },
        }
    }

    async fn close(&self) {
        self.token.lock().await.take();
    }
}
