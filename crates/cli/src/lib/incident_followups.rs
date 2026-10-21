//! Targeted follow-up checks requested by the unattended investigator. Port of
//! `packages/cli/src/lib/incident-followups.ts`. Provider reads produce citable evidence; model
//! text never does. Empty/error results remain explicit.

use std::sync::LazyLock;

use anyhow::{bail, Result};
use horus_connectors::elasticsearch::{LogLevel, LogQuery, LogsProvider, WhereClause};
use horus_connectors::state::{validate_state_record_query, StateProvider, StateRecordQuery};
use horus_connectors::elasticsearch::ElasticsearchLogsProvider;
use horus_connectors::mongodb::MongoStateProvider;
use horus_connectors::shopify::{ShopifyCollectOpts, ShopifyProvider};
use horus_core::{Evidence, ShopifyQuerySpec};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::lib::watch_store::{is_iso_datetime, parse_ms, redact_value, IncidentEvent};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogWhere {
    pub field: String,
    pub value: String,
}

/// `incidentCheckSchema` (discriminated on `kind`, strict).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum IncidentCheck {
    #[serde(rename = "logs")]
    Logs {
        from: String,
        to: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        text: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        service: Option<String>,
        #[serde(default, rename = "where")]
        where_: Vec<LogWhere>,
    },
    #[serde(rename = "state")]
    State { query: StateRecordQuery },
    #[serde(rename = "shopify-variants")]
    ShopifyVariants {
        ids: Vec<String>,
        #[serde(rename = "locationId")]
        location_id: String,
    },
}

static SENSITIVE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(password|secret|token|authorization|credential|api_?key|__proto__|constructor|prototype)").unwrap()
});
static FIELD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$").unwrap());
static VARIANT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^gid://shopify/ProductVariant/\d+$").unwrap());
static LOCATION: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^gid://shopify/Location/\d+$").unwrap());

/// `recordFieldSchema` (connectors keeps its checker private — needs upstreaming).
fn valid_record_field(f: &str) -> bool {
    let n = f.chars().count();
    (1..=160).contains(&n) && FIELD.is_match(f) && !SENSITIVE.is_match(f)
}

impl IncidentCheck {
    /// The zod constraints beyond structure.
    pub fn validate(&self) -> Result<()> {
        let len = |s: &str| s.chars().count();
        match self {
            IncidentCheck::Logs { from, to, text, service, where_ } => {
                if !is_iso_datetime(from) || !is_iso_datetime(to) {
                    bail!("Invalid log check window");
                }
                if text.as_deref().is_some_and(|t| !(1..=512).contains(&len(t))) {
                    bail!("Invalid log check text");
                }
                if service.as_deref().is_some_and(|s| !(1..=200).contains(&len(s))) {
                    bail!("Invalid log check service");
                }
                if where_.len() > 8
                    || where_.iter().any(|w| !valid_record_field(&w.field) || !(1..=512).contains(&len(&w.value)))
                {
                    bail!("Invalid log check filter");
                }
            }
            IncidentCheck::State { query } => validate_state_record_query(query)?,
            IncidentCheck::ShopifyVariants { ids, location_id } => {
                if ids.is_empty() || ids.len() > 10 || ids.iter().any(|i| !VARIANT.is_match(i)) || !LOCATION.is_match(location_id)
                {
                    bail!("Invalid Shopify variant check");
                }
            }
        }
        Ok(())
    }

    fn kind(&self) -> &'static str {
        match self {
            IncidentCheck::Logs { .. } => "logs",
            IncidentCheck::State { .. } => "state",
            IncidentCheck::ShopifyVariants { .. } => "shopify-variants",
        }
    }
}

/// Parse + validate an untrusted check value.
pub fn parse_incident_check(v: &Value) -> Result<IncidentCheck> {
    let check: IncidentCheck = serde_json::from_value(v.clone())?;
    check.validate()?;
    Ok(check)
}

pub fn check_key(check: &IncidentCheck) -> String {
    let s = horus_core::json::to_js_json(check).unwrap_or_default();
    Sha256::digest(s.as_bytes()).iter().map(|b| format!("{b:02x}")).collect::<String>()[..24].to_string()
}

/// The slice of the TS `InvestigationContext` follow-up checks read. Built straight from the
/// connectors factory so it does not wait on the full investigation runner.
pub struct FollowupContext {
    pub logs: Option<ElasticsearchLogsProvider>,
    pub mongo: Option<MongoStateProvider>,
    pub shopify: Option<ShopifyProvider>,
    /// Default service scope for log checks.
    pub service: Option<String>,
}

impl FollowupContext {
    pub fn for_env(renv: &horus_core::ResolvedEnvironment, service: Option<String>) -> Result<Self> {
        use horus_connectors::{logs_for_env, mongo_for_env, shopify_for_env};
        Ok(Self { logs: logs_for_env(renv)?, mongo: mongo_for_env(renv), shopify: shopify_for_env(renv), service })
    }
}

/// Run one check against the configured providers and wrap the outcome as citable evidence.
pub async fn collect_incident_check(
    input: &IncidentCheck,
    context: &FollowupContext,
    event: &IncidentEvent,
) -> Result<Evidence> {
    input.validate()?;
    let check = input;
    let collected_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let outcome: Result<(Vec<Evidence>, usize)> = async {
        let (rows, observations) = match check {
            IncidentCheck::Logs { from, to, text, service, where_ } => {
                let (Some(start), Some(end), Some(incident)) = (parse_ms(from), parse_ms(to), parse_ms(&event.occurred_at))
                else {
                    bail!("Log checks must span at most one hour within one day of the incident");
                };
                if end < start
                    || end - start > 3_600_000
                    || (start - incident).abs() > 86_400_000
                    || (end - incident).abs() > 86_400_000
                {
                    bail!("Log checks must span at most one hour within one day of the incident");
                }
                let Some(logs) = &context.logs else { bail!("No configured logs provider") };
                let records = logs
                    .search_logs(&LogQuery {
                        from: Some(from.clone()),
                        to: Some(to.clone()),
                        service: service.clone().or_else(|| context.service.clone()),
                        text: text.clone(),
                        broad_text: Some(true),
                        where_: Some(where_.iter().map(|w| WhereClause { field: w.field.clone(), value: w.value.clone() }).collect()),
                        limit: Some(100),
                        level: (text.is_none() && where_.is_empty()).then_some(LogLevel::Error),
                        ..Default::default()
                    })
                    .await?;
                (logs.to_evidence(&records), records.len())
            }
            IncidentCheck::State { query } => {
                let Some(mongo) = &context.mongo else { bail!("No configured projected-record provider") };
                let Some(rows) = mongo.query_records(query).await? else {
                    bail!("No configured projected-record provider");
                };
                let n = rows
                    .iter()
                    .map(|r| r.payload.get("records").and_then(Value::as_array).map_or(0, Vec::len))
                    .sum();
                (rows, n)
            }
            IncidentCheck::ShopifyVariants { ids, location_id } => {
                let Some(shopify) = &context.shopify else { bail!("No configured Shopify provider") };
                let spec: ShopifyQuerySpec = serde_json::from_value(json!({
                    "name": "incident-variant-location",
                    "kind": "state",
                    "query": "query IncidentVariantLocation($ids:[ID!]!,$location:ID!){nodes(ids:$ids){... on ProductVariant{id sku product{id title} inventoryItem{id tracked inventoryLevel(locationId:$location){id quantities(names:[\"available\"]){name quantity}}}}}}",
                    "variables": { "ids": ids, "location": location_id },
                }))?;
                let records = shopify
                    .collect(&ShopifyCollectOpts {
                        from: None,
                        to: None,
                        hint_terms: Vec::new(),
                        queries: Some(vec![spec]),
                        collected_at: None,
                    })
                    .await?;
                if records.iter().any(|r| r.errors.as_ref().is_some_and(|e| !e.is_empty())) {
                    bail!("Shopify query returned GraphQL errors");
                }
                let n = records
                    .iter()
                    .map(|r| r.data.get("nodes").and_then(Value::as_array).map_or(0, |a| a.iter().filter(|x| truthy(x)).count()))
                    .sum();
                (shopify.to_evidence(&records, &[], &collected_at), n)
            }
        };
        if horus_core::json::to_js_json(&rows)?.len() > 128_000 {
            bail!("Check exceeds evidence budget; narrow the query");
        }
        Ok((rows, observations))
    }
    .await;

    let (rows, observations, error) = match outcome {
        Ok((rows, n)) => (rows, n, None),
        Err(e) => (Vec::new(), 0, Some(e.to_string().chars().take(2000).collect::<String>())),
    };
    let mut payload = Map::new();
    payload.insert("followup".into(), json!(true));
    payload.insert("observations".into(), json!(observations));
    payload.insert("check".into(), serde_json::to_value(check)?);
    payload.insert("evidence".into(), serde_json::to_value(&rows)?);
    if let Some(e) = &error {
        payload.insert("error".into(), json!(e));
    }
    let is_logs = matches!(check, IncidentCheck::Logs { .. });
    let title_tail = match &error {
        Some(_) => "unavailable".to_string(),
        None => format!("{} evidence item(s)", rows.len()),
    };
    let ev = json!({
        "id": format!("ev_followup_{}", check_key(check)),
        "source": if is_logs { "logs" } else { "state" },
        "kind": if is_logs { "log" } else { "state" },
        "relevance": 0,
        "title": format!("Targeted {} check: {title_tail}", check.kind()),
        "payload": Value::Object(payload),
        "links": {},
        "provenance": { "query": horus_core::json::to_js_json(check)?, "collectedAt": collected_at },
    });
    Ok(serde_json::from_value(redact_value(ev))?)
}

/// JS truthiness of a JSON node (`filter(Boolean)`).
fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        _ => true,
    }
}

/// The default window check around the alert: 10 minutes before to 2 minutes after.
pub fn incident_window_check(event: &IncidentEvent) -> IncidentCheck {
    let at = parse_ms(&event.occurred_at).unwrap_or(0);
    let iso = |ms: i64| {
        chrono::DateTime::<chrono::Utc>::from_timestamp_millis(ms)
            .unwrap_or_default()
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
    };
    IncidentCheck::Logs { from: iso(at - 10 * 60_000), to: iso(at + 2 * 60_000), text: None, service: None, where_: Vec::new() }
}
