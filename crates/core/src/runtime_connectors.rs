//! Runtime connector schemas (cloud logs + runtime systems). serde structs replace the
//! zod objects; `validate_*` reproduces the zod constraints with zod's issue messages.

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::LazyLock;

// ---------------------------------------------------------------------------
// Issue collection shared with config.rs (mirrors zod's issue list)
// ---------------------------------------------------------------------------

/// One validation failure: a normalized path (`projects.*.name`) and a zod-style message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigIssue {
    pub path: String,
    pub message: String,
}

/// Collects issues while walking a config. Array indices are recorded as `*`, matching
/// the TS `normalizePath` used for display.
#[derive(Debug, Default)]
pub struct Issues {
    pub items: Vec<ConfigIssue>,
    path: Vec<String>,
}

impl Issues {
    pub fn push(&mut self, message: impl Into<String>) {
        let path = if self.path.is_empty() { "(root)".to_string() } else { self.path.join(".") };
        self.items.push(ConfigIssue { path, message: message.into() });
    }
    pub fn at<R>(&mut self, key: &str, f: impl FnOnce(&mut Issues) -> R) -> R {
        self.path.push(key.to_string());
        let r = f(self);
        self.path.pop();
        r
    }
    pub fn index<R>(&mut self, f: impl FnOnce(&mut Issues) -> R) -> R {
        self.at("*", f)
    }
}

// ---------------------------------------------------------------------------
// Minimal zod v3 walker: reports every issue (structural + constraint) in zod's parse
// order with zod's wording, so config errors read exactly like the TS CLI's.
// ---------------------------------------------------------------------------

pub enum StrCheck {
    Min(usize),
    Max(usize),
    Url,
    Uuid,
    Regex(&'static LazyLock<Regex>),
}

pub enum NumCheck {
    Int,
    Gte(f64),
    Gt(f64),
    Lte(f64),
}

/// A zod schema node. `.optional()` and `.default(validValue)` both map to `Opt`: they
/// accept a missing key and validate a present one (zod applies neither to `null`).
pub enum Z {
    Str(Vec<StrCheck>),
    Num(Vec<NumCheck>),
    Bool,
    Enum(&'static [&'static str]),
    Arr(Box<Z>, Option<usize>, Option<usize>),
    Obj(Vec<(&'static str, Z)>),
    /// `z.record(z.unknown())`
    Record,
    Opt(Box<Z>),
    /// `.refine(pred, message)`: runs unless the inner parse aborted.
    Refine(Box<Z>, fn(&Value) -> bool, &'static str),
}

pub fn opt(z: Z) -> Z {
    Z::Opt(Box::new(z))
}
pub fn obj(fields: Vec<(&'static str, Z)>) -> Z {
    Z::Obj(fields)
}
pub fn arr(item: Z, min: Option<usize>, max: Option<usize>) -> Z {
    Z::Arr(Box::new(item), min, max)
}
/// `z.string().optional()`
pub fn ostr() -> Z {
    opt(Z::Str(vec![]))
}

/// zod's `getParsedType` for JSON values.
fn parsed_type(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

impl Issues {
    fn invalid_type(&mut self, expected: &str, v: Option<&Value>) {
        match v {
            None => self.push("Required"),
            Some(v) => self.push(format!("Expected {expected}, received {}", parsed_type(v))),
        }
    }
}

/// Parse `v` (None = key absent) against `z`, collecting issues. Returns true when the
/// parse aborted (zod `INVALID`), false when valid or only dirty (constraint failures).
pub fn zod_walk(z: &Z, v: Option<&Value>, i: &mut Issues) -> bool {
    match z {
        Z::Opt(inner) => v.is_some() && zod_walk(inner, v, i),
        Z::Refine(inner, pred, msg) => {
            if zod_walk(inner, v, i) {
                return true;
            }
            if v.is_some_and(|v| !pred(v)) {
                i.push(*msg);
            }
            false
        }
        Z::Str(checks) => {
            let Some(s) = v.and_then(Value::as_str) else {
                i.invalid_type("string", v);
                return true;
            };
            let len = s.encode_utf16().count(); // JS `.length`
            for c in checks {
                match c {
                    StrCheck::Min(n) if len < *n => i.push(format!("String must contain at least {n} character(s)")),
                    StrCheck::Max(n) if len > *n => i.push(format!("String must contain at most {n} character(s)")),
                    StrCheck::Url if url::Url::parse(s).is_err() => i.push("Invalid url"),
                    StrCheck::Uuid if !UUID_RE.is_match(s) => i.push("Invalid uuid"),
                    StrCheck::Regex(re) if !re.is_match(s) => i.push("Invalid"),
                    _ => {}
                }
            }
            false
        }
        Z::Num(checks) => {
            let Some(n) = v.and_then(Value::as_f64) else {
                i.invalid_type("number", v);
                return true;
            };
            for c in checks {
                match c {
                    NumCheck::Int if n.fract() != 0.0 => i.push("Expected integer, received float"),
                    NumCheck::Gte(m) if n < *m => i.push(format!("Number must be greater than or equal to {m}")),
                    NumCheck::Gt(m) if n <= *m => i.push(format!("Number must be greater than {m}")),
                    NumCheck::Lte(m) if n > *m => i.push(format!("Number must be less than or equal to {m}")),
                    _ => {}
                }
            }
            false
        }
        Z::Bool => {
            if v.is_some_and(Value::is_boolean) {
                return false;
            }
            i.invalid_type("boolean", v);
            true
        }
        Z::Enum(values) => {
            let joined = values.iter().map(|s| format!("'{s}'")).collect::<Vec<_>>().join(" | ");
            match v.and_then(Value::as_str) {
                None => i.invalid_type(&joined, v),
                Some(s) if !values.contains(&s) => i.push(format!("Invalid enum value. Expected {joined}, received '{s}'")),
                Some(_) => return false,
            }
            true
        }
        Z::Arr(item, min, max) => {
            let Some(items) = v.and_then(Value::as_array) else {
                i.invalid_type("array", v);
                return true;
            };
            // zod checks length before parsing elements.
            if let Some(m) = min.filter(|m| items.len() < *m) {
                i.push(format!("Array must contain at least {m} element(s)"));
            }
            if let Some(m) = max.filter(|m| items.len() > *m) {
                i.push(format!("Array must contain at most {m} element(s)"));
            }
            let mut aborted = false;
            for x in items {
                aborted |= i.index(|i| zod_walk(item, Some(x), i));
            }
            aborted
        }
        Z::Obj(fields) => {
            let Some(o) = v.and_then(Value::as_object) else {
                i.invalid_type("object", v);
                return true;
            };
            let mut aborted = false;
            for (k, f) in fields {
                aborted |= i.at(k, |i| zod_walk(f, o.get(*k), i));
            }
            aborted
        }
        Z::Record => {
            if v.is_some_and(Value::is_object) {
                return false;
            }
            i.invalid_type("object", v);
            true
        }
    }
}

/// Walk an already-typed config (defaults filled) through its schema.
fn walk_typed(i: &mut Issues, z: &Z, c: &impl Serialize) {
    zod_walk(z, Some(&serde_json::to_value(c).unwrap_or(Value::Null)), i);
}

static UUID_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^[0-9a-f]{8}\b-[0-9a-f]{4}\b-[0-9a-f]{4}\b-[0-9a-f]{4}\b-[0-9a-f]{12}$").unwrap()
});
static TABLE_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z][A-Za-z0-9_]*$").unwrap());
static REGION_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-z]{2}(-gov)?-[a-z]+-[0-9]$").unwrap());
static GCP_PROJECT_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-z][a-z0-9-]{4,61}[a-z0-9]$").unwrap());
static NAME_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_.-]+$").unwrap());
static SB_NAMESPACE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^/subscriptions/[A-Za-z0-9_-]+/resourceGroups/[A-Za-z0-9_.-]+/providers/Microsoft.ServiceBus/namespaces/[A-Za-z0-9_-]+$").unwrap()
});
static BROKER_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_.-]+:[0-9]+$").unwrap());
static FS_DATABASE_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_()-]+$").unwrap());
static FS_COLLECTION_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)*$").unwrap());
static SQL_SCHEMA_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_]+$").unwrap());

fn default_true() -> bool {
    true
}

// ---------------------------------------------------------------------------
// Cloud log connectors
// ---------------------------------------------------------------------------

fn az_tables() -> Vec<String> {
    ["AppTraces", "AppExceptions", "ContainerAppConsoleLogs_CL"].map(String::from).to_vec()
}
fn s_az() -> String {
    "az".into()
}
fn s_aws() -> String {
    "aws".into()
}
fn s_gcloud() -> String {
    "gcloud".into()
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AzureMonitorConfig {
    pub workspace: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subscription: Option<String>,
    #[serde(default = "az_tables")]
    pub tables: Vec<String>,
    #[serde(default = "s_az")]
    pub executable: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudWatchConfig {
    pub region: String,
    pub log_group: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    #[serde(default = "s_aws")]
    pub executable: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GcpLoggingConfig {
    pub project: String,
    #[serde(default)]
    pub filter: String,
    #[serde(default = "s_gcloud")]
    pub executable: String,
}

// ---------------------------------------------------------------------------
// Runtime connectors
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PrometheusQuery {
    pub title: String,
    pub expr: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrometheusConfig {
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    pub queries: Vec<PrometheusQuery>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AzureServiceBusConfig {
    pub namespace_id: String,
    pub queues: Vec<String>,
    #[serde(default = "s_az")]
    pub executable: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum KafkaMechanism {
    #[default]
    #[serde(rename = "plain")]
    Plain,
    #[serde(rename = "scram-sha-256")]
    ScramSha256,
    #[serde(rename = "scram-sha-512")]
    ScramSha512,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KafkaConfig {
    pub brokers: Vec<String>,
    pub topics: Vec<String>,
    pub groups: Vec<String>,
    #[serde(default = "default_true")]
    pub ssl: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(default)]
    pub mechanism: KafkaMechanism,
}

fn fs_default_db() -> String {
    "(default)".into()
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FirestoreConfig {
    pub project: String,
    #[serde(default = "fs_default_db")]
    pub database: String,
    pub collections: Vec<String>,
    #[serde(default = "s_gcloud")]
    pub executable: String,
}

fn dbo() -> String {
    "dbo".into()
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SqlServerConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    pub database: String,
    #[serde(default = "dbo")]
    pub schema: String,
    pub tables: Vec<String>,
}

// ---------------------------------------------------------------------------
// Validation (zod constraints)
// ---------------------------------------------------------------------------

/// `names` schema: array of `[A-Za-z0-9_.-]+`, 1–20 entries.
fn names() -> Z {
    arr(Z::Str(vec![StrCheck::Regex(&NAME_RE)]), Some(1), Some(20))
}
fn min1() -> Z {
    Z::Str(vec![StrCheck::Min(1)])
}
fn re(r: &'static LazyLock<Regex>) -> Z {
    Z::Str(vec![StrCheck::Regex(r)])
}

pub fn azure_monitor_schema() -> Z {
    obj(vec![
        ("workspace", Z::Str(vec![StrCheck::Uuid])),
        ("subscription", opt(min1())),
        ("tables", opt(arr(re(&TABLE_RE), Some(1), Some(10)))),
        ("executable", ostr()),
    ])
}

pub fn cloudwatch_schema() -> Z {
    obj(vec![("region", re(&REGION_RE)), ("logGroup", min1()), ("profile", opt(min1())), ("executable", ostr())])
}

pub fn gcp_logging_schema() -> Z {
    obj(vec![("project", re(&GCP_PROJECT_RE)), ("filter", opt(Z::Str(vec![StrCheck::Max(2000)]))), ("executable", ostr())])
}

pub fn prometheus_schema() -> Z {
    obj(vec![
        ("url", Z::Str(vec![StrCheck::Url])),
        ("token", ostr()),
        ("queries", arr(obj(vec![("title", min1()), ("expr", Z::Str(vec![StrCheck::Min(1), StrCheck::Max(4000)]))]), Some(1), Some(20))),
    ])
}

pub fn azure_service_bus_schema() -> Z {
    obj(vec![("namespaceId", re(&SB_NAMESPACE_RE)), ("queues", names()), ("executable", ostr())])
}

pub fn kafka_schema() -> Z {
    // JS `!!value`: only a non-empty string is truthy here (other types abort earlier).
    fn together(v: &Value) -> bool {
        let truthy = |k: &str| v.get(k).and_then(Value::as_str).is_some_and(|s| !s.is_empty());
        truthy("username") == truthy("password")
    }
    Z::Refine(
        Box::new(obj(vec![
            ("brokers", arr(re(&BROKER_RE), Some(1), Some(10))),
            ("topics", names()),
            ("groups", names()),
            ("ssl", opt(Z::Bool)),
            ("username", ostr()),
            ("password", ostr()),
            ("mechanism", opt(Z::Enum(&["plain", "scram-sha-256", "scram-sha-512"]))),
        ])),
        together,
        "Kafka username and password must be supplied together",
    )
}

pub fn firestore_schema() -> Z {
    obj(vec![
        ("project", re(&GCP_PROJECT_RE)),
        ("database", opt(re(&FS_DATABASE_RE))),
        ("collections", arr(re(&FS_COLLECTION_RE), Some(1), Some(20))),
        ("executable", ostr()),
    ])
}

pub fn sqlserver_schema() -> Z {
    obj(vec![("url", opt(min1())), ("database", min1()), ("schema", opt(re(&SQL_SCHEMA_RE))), ("tables", names())])
}

pub fn validate_azure_monitor(i: &mut Issues, c: &AzureMonitorConfig) {
    walk_typed(i, &azure_monitor_schema(), c);
}

pub fn validate_cloudwatch(i: &mut Issues, c: &CloudWatchConfig) {
    walk_typed(i, &cloudwatch_schema(), c);
}

pub fn validate_gcp_logging(i: &mut Issues, c: &GcpLoggingConfig) {
    walk_typed(i, &gcp_logging_schema(), c);
}

pub fn validate_prometheus(i: &mut Issues, c: &PrometheusConfig) {
    walk_typed(i, &prometheus_schema(), c);
}

pub fn validate_azure_service_bus(i: &mut Issues, c: &AzureServiceBusConfig) {
    walk_typed(i, &azure_service_bus_schema(), c);
}

pub fn validate_kafka(i: &mut Issues, c: &KafkaConfig) {
    walk_typed(i, &kafka_schema(), c);
}

pub fn validate_firestore(i: &mut Issues, c: &FirestoreConfig) {
    walk_typed(i, &firestore_schema(), c);
}

pub fn validate_sqlserver(i: &mut Issues, c: &SqlServerConfig) {
    walk_typed(i, &sqlserver_schema(), c);
}
