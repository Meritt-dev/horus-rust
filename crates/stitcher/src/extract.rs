//! Pure queue-graph extraction — no IO. Parses BullMQ/NestJS queue-name literals out of
//! Source-intelligence symbol "content" and joins producers to workers on the queue-name string.
//!
//! Idioms supported, generically (no project-specific names):
//!  - NestJS @nestjs/bull(mq): `@InjectQueue('<name>')` producers, class-level
//!    `@Processor('<name>')` workers (inline string literals).
//!  - Raw bullmq: `new Queue(<arg>)` / `new Worker(<arg>)` where `<arg>` is a string
//!    literal OR a constant (e.g. `const X_QUEUE_NAME = 'name'`) resolved across files.
//!    A module that DECLARES a queue-name constant is treated as that queue's producer
//!    (its definition site), which links it to the `new Worker(...)` consumer.
//!  - Dynamically-registered queues (HOR-341): `new Queue(<EnumMember>)` /
//!    `new Worker(<EnumMember>)` resolves the enum member (e.g. `ScheduledEvents.MANAGE_SALES`)
//!    to its string value from the enum declaration. When the `new Queue/Worker(<loopVar>)`
//!    is driven by `for (const x of Object.values(SomeEnum))`, it fans out to ONE queue per
//!    enum member. Where a dispatch table maps the enum member to a handler
//!    (`[SomeEnum.MEMBER]: () => this.ctrl.method()`), the queue is linked to that handler
//!    as a worker, so the engine can map the runtime queue to owning code.
//!
//! Resolution is best-effort and additive: if a value can't be resolved statically we fall
//! back to the existing behavior (literal-named queues never regress).

use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ProducerClassInput {
    pub name: String,
    pub file_path: String,
    pub content: String,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct WorkerFileInput {
    pub file_path: String,
    pub content: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SynthEdge {
    pub queue_name: String,
    pub producer_symbol: Option<String>,
    pub producer_file: Option<String>,
    pub worker_symbol: Option<String>,
    pub worker_file: Option<String>,
}

impl horus_core::QueueEdgeLike for SynthEdge {
    fn queue_name(&self) -> &str {
        &self.queue_name
    }
    fn producer_symbol(&self) -> Option<&str> {
        self.producer_symbol.as_deref()
    }
    fn producer_file(&self) -> Option<&str> {
        self.producer_file.as_deref()
    }
    fn worker_symbol(&self) -> Option<&str> {
        self.worker_symbol.as_deref()
    }
    fn worker_file(&self) -> Option<&str> {
        self.worker_file.as_deref()
    }
}

/// `{ queue, symbol, file }` producer/worker row.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct QueueRow {
    pub queue: String,
    pub symbol: String,
    pub file: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct QueueGraph {
    pub queues: Vec<String>,
    pub producers: Vec<QueueRow>,
    pub workers: Vec<QueueRow>,
    pub edges: Vec<SynthEdge>,
}

/// Compile a JS-flavoured pattern: JS `\w` is ASCII-only, Rust's is Unicode.
fn js_re(pattern: &str) -> Regex {
    Regex::new(&pattern.replace("\\w", "[0-9A-Za-z_]")).expect("static regex")
}

// --- NestJS patterns (inline string literals) ---
static INJECT_QUEUE_RE: LazyLock<Regex> = LazyLock::new(|| js_re(r#"@InjectQueue\(\s*['"]([^'"]+)['"]"#));
static PROCESSOR_RE: LazyLock<Regex> = LazyLock::new(|| {
    js_re(r#"@Processor\(\s*['"]([^'"]+)['"][^)]*\)\s*(?:@\w+[^\n]*\s*)*export\s+class\s+(\w+)"#)
});

// --- Raw bullmq patterns ---
// `const IDENT = 'literal'` (also `export const`) — for cross-file constant resolution.
static CONST_DECL_RE: LazyLock<Regex> =
    LazyLock::new(|| js_re(r#"(?:export\s+)?const\s+([A-Za-z_$][\w$]*)\s*=\s*['"]([^'"]+)['"]"#));
// `[<ident> =] new Queue|Worker [<T>] ( <arg>` where arg is a literal, an identifier,
// or a member access (e.g. `ScheduledEvents.MANAGE_SALES`).
static NEW_BULL_RE: LazyLock<Regex> = LazyLock::new(|| {
    js_re(r#"(?:(\w+)\s*[:=]\s*)?new\s+(Queue|Worker)\s*(?:<[^>]*>)?\s*\(\s*(['"][^'"]+['"]|[A-Za-z_$][\w$.]*)"#)
});
// A queue-name constant: identifier contains QUEUE/Queue — its module is the producer.
static QUEUE_NAME_CONST_RE: LazyLock<Regex> = LazyLock::new(|| {
    js_re(r#"(?:export\s+)?const\s+([A-Za-z_$][\w$]*(?:QUEUE|Queue)[\w$]*)\s*=\s*['"]([^'"]+)['"]"#)
});

// --- Enum / indirection patterns (HOR-341) ---
// `enum Name { ... }` — captures the enum body for member parsing. `[const ]enum`.
static ENUM_DECL_RE: LazyLock<Regex> =
    LazyLock::new(|| js_re(r"(?:export\s+)?(?:const\s+)?enum\s+([A-Za-z_$][\w$]*)\s*\{([^}]*)\}"));
// A single enum member inside an enum body: `MEMBER = 'value'` (string-valued) or `MEMBER`
// (implicit — value defaults to the member name, which is the common BullMQ convention).
// The TS pattern uses a `\2` backreference for the closing quote; `regex` has none, so the
// two quote styles are spelled out (groups 2 and 3 — equivalent since `[^'"]*` excludes both).
static ENUM_MEMBER_RE: LazyLock<Regex> =
    LazyLock::new(|| js_re(r#"([A-Za-z_$][\w$]*)\s*(?:=\s*(?:'([^'"]*)'|"([^'"]*)"))?"#));
// `for (const x of Object.values(Enum))` — captures the loop var and the enum name so a
// `new Queue/Worker(x)` inside that loop fans out to every enum member.
static OBJECT_VALUES_LOOP_RE: LazyLock<Regex> = LazyLock::new(|| {
    js_re(r"for\s*\(\s*(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s+of\s+Object\.values\(\s*([A-Za-z_$][\w$]*)\s*\)")
});
// A dispatch-table entry mapping an enum member to a handler:
//   `[Enum.MEMBER]: () => this.ctrl.method(...)`  or  `[Enum.MEMBER]: handlerFn`
// Captures the member-access key and a best-effort handler symbol (method name, or fn name).
// The rhs runs to the entry's trailing comma/brace (NOT the first newline) so a handler that
// wraps onto the next line — `[Enum.MEMBER]: () =>\n  this.ctrl.method()` — still resolves.
static DISPATCH_ENTRY_RE: LazyLock<Regex> =
    LazyLock::new(|| js_re(r"\[\s*([A-Za-z_$][\w$]*)\.([A-Za-z_$][\w$]*)\s*\]\s*:\s*([^,}]+)"));

static JS_EXT_RE: LazyLock<Regex> = LazyLock::new(|| js_re(r"\.[jt]sx?$"));

fn base_name(file_path: &str) -> String {
    let last = file_path.rsplit('/').next().unwrap_or(file_path);
    JS_EXT_RE.replace(last, "").into_owned()
}

fn cap<'a>(m: &regex::Captures<'a>, i: usize) -> &'a str {
    m.get(i).map(|g| g.as_str()).unwrap_or("")
}

#[derive(Debug, Clone)]
struct EnumMember {
    member: String,
    value: String,
}

/// Parsed enums: enum name -> ordered list of `{ member, value }`.
type EnumMap = HashMap<String, Vec<EnumMember>>;

/// Build a map of all enum declarations found across every content unit.
fn build_enum_map(contents: &[&str]) -> EnumMap {
    let mut enums: EnumMap = HashMap::new();
    for content in contents {
        for decl in ENUM_DECL_RE.captures_iter(content) {
            let enum_name = cap(&decl, 1);
            let body = cap(&decl, 2);
            if enum_name.is_empty() || enums.contains_key(enum_name) {
                continue;
            }
            let mut members: Vec<EnumMember> = Vec::new();
            for m in ENUM_MEMBER_RE.captures_iter(body) {
                let member = cap(&m, 1);
                // Skip empties produced by the optional-group regex between commas.
                if member.is_empty() {
                    continue;
                }
                // String-valued enum members get their literal; implicit members fall back to the
                // member name (the dominant convention for queue-name enums, e.g. FOO = 'FOO').
                let value = m.get(2).or_else(|| m.get(3)).map(|g| g.as_str()).unwrap_or(member);
                members.push(EnumMember { member: member.to_string(), value: value.to_string() });
            }
            if !members.is_empty() {
                enums.insert(enum_name.to_string(), members);
            }
        }
    }
    enums
}

/// Resolve an `EnumName.MEMBER` member access to its string value via the enum map.
fn resolve_enum_member(reference: &str, enums: &EnumMap) -> Option<String> {
    let dot = reference.find('.')?;
    let enum_name = &reference[..dot];
    let member = &reference[dot + 1..];
    let members = enums.get(enum_name)?;
    members.iter().find(|e| e.member == member).map(|e| e.value.clone())
}

/// Resolve a `new Queue/Worker` argument to one or more queue names.
///  - string literal               -> [literal]
///  - `EnumName.MEMBER`            -> [enum member value]
///  - constant identifier          -> [constant value]
///  - loop var bound to Object.values(Enum) -> [all enum member values]
///  - otherwise                    -> [] (unresolved; caller falls back)
fn resolve_arg(
    raw: &str,
    const_map: &HashMap<String, String>,
    enums: &EnumMap,
    loop_var_enums: &HashMap<String, String>,
) -> Vec<String> {
    let arg = raw.trim();
    if arg.starts_with('"') || arg.starts_with('\'') {
        // `arg.slice(1, -1)`
        let inner = if arg.len() >= 2 { &arg[1..arg.len() - 1] } else { "" };
        return vec![inner.to_string()];
    }
    // Member access: `ScheduledEvents.MANAGE_SALES`.
    if arg.contains('.') {
        return resolve_enum_member(arg, enums).into_iter().collect();
    }
    // Loop var driven by `for (const arg of Object.values(Enum))` — fan out to all members.
    if let Some(loop_enum) = loop_var_enums.get(arg) {
        if let Some(members) = enums.get(loop_enum) {
            return members.iter().map(|e| e.value.clone()).collect();
        }
    }
    // Cross-file constant (e.g. `const X_QUEUE_NAME = 'name'`).
    const_map.get(arg).cloned().into_iter().collect()
}

/// Build a per-content lookup of loop-variable -> enum name from
/// `for (const x of Object.values(Enum))`. Scoped to the content unit it was found in so a
/// loop var in one file doesn't leak into another.
fn loop_var_enums_for(content: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for m in OBJECT_VALUES_LOOP_RE.captures_iter(content) {
        let loop_var = cap(&m, 1);
        let enum_name = cap(&m, 2);
        if !loop_var.is_empty() && !enum_name.is_empty() {
            map.insert(loop_var.to_string(), enum_name.to_string());
        }
    }
    map
}

struct DispatchHandler {
    value: String,
    handler: String,
}

/// Extract dispatch-table handler links: `enumValue -> handlerSymbol` keyed by the resolved
/// enum-member value. e.g. `[ScheduledEvents.SYNC_BRAND_FULFILLMENTS]: () => this.orderController.syncBrandFulfillments()`
/// yields `'SYNC_BRAND_FULFILLMENTS' -> 'syncBrandFulfillments'`.
fn extract_dispatch_handlers(content: &str, enums: &EnumMap) -> Vec<DispatchHandler> {
    let mut out = Vec::new();
    for m in DISPATCH_ENTRY_RE.captures_iter(content) {
        let enum_name = cap(&m, 1);
        let member = cap(&m, 2);
        let rhs = cap(&m, 3).trim();
        if enum_name.is_empty() || member.is_empty() {
            continue;
        }
        let Some(value) = resolve_enum_member(&format!("{enum_name}.{member}"), enums) else { continue };
        if let Some(handler) = handler_symbol_from_expr(rhs) {
            out.push(DispatchHandler { value, handler });
        }
    }
    out
}

static CALL_RE: LazyLock<Regex> = LazyLock::new(|| js_re(r"([A-Za-z_$][\w$]*)\s*\("));
static MEMBER_RE: LazyLock<Regex> = LazyLock::new(|| js_re(r"(?:[A-Za-z_$][\w$]*\.)+([A-Za-z_$][\w$]*)"));
static IDENT_RE: LazyLock<Regex> = LazyLock::new(|| js_re(r"^([A-Za-z_$][\w$]*)$"));

/// Best-effort handler symbol from a dispatch RHS expression:
///  - `() => this.ctrl.method(...)`  -> `method`
///  - `() => freeFn(...)`            -> `freeFn`
///  - `handlerFn`                    -> `handlerFn`
///  - `this.ctrl.method`            -> `method`
fn handler_symbol_from_expr(expr: &str) -> Option<String> {
    // Last `.method(` call in the expression (handles `this.ctrl.method(`).
    if let Some(c) = CALL_RE.captures(expr) {
        return Some(c[1].to_string());
    }
    // Bare member access `this.ctrl.method` or `a.b.c` -> last segment.
    if let Some(c) = MEMBER_RE.captures(expr) {
        return Some(c[1].to_string());
    }
    // Bare identifier reference.
    IDENT_RE.captures(expr).map(|c| c[1].to_string())
}

pub struct QueueGraphInput {
    pub producer_classes: Vec<ProducerClassInput>,
    pub worker_files: Vec<WorkerFileInput>,
}

fn row(queue: &str, symbol: &str, file: &str) -> QueueRow {
    QueueRow { queue: queue.to_string(), symbol: symbol.to_string(), file: file.to_string() }
}

fn edge(queue: &str, p: Option<&QueueRow>, w: Option<&QueueRow>) -> SynthEdge {
    SynthEdge {
        queue_name: queue.to_string(),
        producer_symbol: p.map(|p| p.symbol.clone()),
        producer_file: p.map(|p| p.file.clone()),
        worker_symbol: w.map(|w| w.symbol.clone()),
        worker_file: w.map(|w| w.file.clone()),
    }
}

/// Cross-product producers × workers for one queue, or one-sided edges when a side is empty.
fn join_edges(queue: &str, producers: &[QueueRow], workers: &[QueueRow], edges: &mut Vec<SynthEdge>) {
    if !producers.is_empty() && !workers.is_empty() {
        for p in producers {
            for w in workers {
                edges.push(edge(queue, Some(p), Some(w)));
            }
        }
    } else if !workers.is_empty() {
        for w in workers {
            edges.push(edge(queue, None, Some(w)));
        }
    } else if !producers.is_empty() {
        for p in producers {
            edges.push(edge(queue, Some(p), None));
        }
    }
}

pub fn extract_queue_graph(input: &QueueGraphInput) -> QueueGraph {
    let all_content: Vec<&str> = input
        .producer_classes
        .iter()
        .map(|p| p.content.as_str())
        .chain(input.worker_files.iter().map(|w| w.content.as_str()))
        .collect();

    // Global constant map (IDENT -> literal) from every unit's content.
    let mut const_map: HashMap<String, String> = HashMap::new();
    for content in &all_content {
        for m in CONST_DECL_RE.captures_iter(content) {
            let ident = cap(&m, 1);
            let value = cap(&m, 2);
            if !ident.is_empty() && !value.is_empty() && !const_map.contains_key(ident) {
                const_map.insert(ident.to_string(), value.to_string());
            }
        }
    }

    // Global enum map (Enum.MEMBER -> value) — declarations can live in any indexed unit.
    let enums = build_enum_map(&all_content);

    // Dispatch handlers (resolved enum value -> handler symbol). Collected globally because the
    // dispatch table often lives in a different file from the `new Worker(...)` site.
    let mut dispatch_handlers: Vec<QueueRow> = Vec::new();
    let units = input
        .producer_classes
        .iter()
        .map(|p| (p.file_path.as_str(), p.content.as_str()))
        .chain(input.worker_files.iter().map(|w| (w.file_path.as_str(), w.content.as_str())));
    for (file, content) in units {
        for h in extract_dispatch_handlers(content, &enums) {
            dispatch_handlers.push(row(&h.value, &h.handler, file));
        }
    }

    let mut producers: Vec<QueueRow> = Vec::new();
    for pc in &input.producer_classes {
        let loop_var_enums = loop_var_enums_for(&pc.content);
        // NestJS @InjectQueue('name')
        for m in INJECT_QUEUE_RE.captures_iter(&pc.content) {
            let queue = cap(&m, 1);
            if !queue.is_empty() {
                producers.push(row(queue, &pc.name, &pc.file_path));
            }
        }
        // Raw `new Queue(<arg>)` — may resolve to several queues (enum fan-out).
        for m in NEW_BULL_RE.captures_iter(&pc.content) {
            if cap(&m, 2) != "Queue" {
                continue;
            }
            for queue in resolve_arg(cap(&m, 3), &const_map, &enums, &loop_var_enums) {
                // `(m[1] ?? pc.name) || baseName(pc.filePath)`
                let symbol = m.get(1).map(|g| g.as_str()).unwrap_or(&pc.name);
                let symbol = if symbol.is_empty() { base_name(&pc.file_path) } else { symbol.to_string() };
                producers.push(row(&queue, &symbol, &pc.file_path));
            }
        }
        // A module declaring a queue-name constant is that queue's definition/producer site.
        for m in QUEUE_NAME_CONST_RE.captures_iter(&pc.content) {
            let ident = cap(&m, 1);
            let queue = cap(&m, 2);
            if !queue.is_empty() {
                let symbol = if ident.is_empty() { base_name(&pc.file_path) } else { ident.to_string() };
                producers.push(row(queue, &symbol, &pc.file_path));
            }
        }
    }

    let mut workers: Vec<QueueRow> = Vec::new();
    for wf in &input.worker_files {
        let loop_var_enums = loop_var_enums_for(&wf.content);
        // NestJS class-level @Processor('name')
        for m in PROCESSOR_RE.captures_iter(&wf.content) {
            let queue = cap(&m, 1);
            let class_name = cap(&m, 2);
            if !queue.is_empty() {
                workers.push(row(queue, class_name, &wf.file_path));
            }
        }
        // Raw `new Worker(<arg>)` — may resolve to several queues (enum fan-out).
        for m in NEW_BULL_RE.captures_iter(&wf.content) {
            if cap(&m, 2) != "Worker" {
                continue;
            }
            for queue in resolve_arg(cap(&m, 3), &const_map, &enums, &loop_var_enums) {
                let symbol = m.get(1).map(|g| g.as_str().to_string()).unwrap_or_else(|| base_name(&wf.file_path));
                workers.push(row(&queue, &symbol, &wf.file_path));
            }
        }
    }

    // Dispatch-table handlers become workers for their queue: the handler is the owning code
    // the runtime queue ultimately runs. This links e.g. `SYNC_BRAND_FULFILLMENTS` to
    // `syncBrandFulfillments` even though the `new Worker(eventName)` is generic.
    workers.extend(dispatch_handlers);

    let queues = sorted_unique(producers.iter().chain(workers.iter()).map(|r| r.queue.as_str()));

    let mut edges: Vec<SynthEdge> = Vec::new();
    for q in &queues {
        // Dedup producers/workers per queue by symbol+file so repeated matches and the generic
        // `new Worker(loopVar)` fan-out + dispatch handlers don't multiply edges unnaturally.
        let p = dedupe_by_symbol_file(producers.iter().filter(|p| &p.queue == q));
        let w = dedupe_by_symbol_file(workers.iter().filter(|w| &w.queue == q));
        join_edges(q, &p, &w, &mut edges);
    }

    QueueGraph { queues, producers, workers, edges }
}

/// `[...new Set(xs)].sort()` — JS default sort is lexical by code unit; byte order on UTF-8
/// agrees for BMP text.
fn sorted_unique<'a>(items: impl Iterator<Item = &'a str>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out: Vec<String> = Vec::new();
    for item in items {
        if seen.insert(item) {
            out.push(item.to_string());
        }
    }
    out.sort();
    out
}

// --- Celery (Python) patterns (HOR-356) ---
// A Python task-queue worker def: a Celery `@task`/`@shared_task`/`@app.task`/`@celery.task`, or
// a huey `@huey.task`/`@db_task`/`@db_periodic_task` decorator (optionally with args + stacked
// decorators) directly on a `def`. The task name is the function name — what
// `.delay()`/`.apply_async()`/`.schedule()`/`.defer()` call sites reference (HOR-356/380).
// Captures the def name. The distinctive named decorators (shared_task / db_task /
// db_periodic_task / periodic_task) keep the broad `(?:[\w]+\.)*` qualifier (covers `huey.`/
// `app.`); db_task/db_periodic_task are huey-specific names the Celery set missed. The bare
// `task` decorator, however, is restricted to Celery's actual convention — `@task` or a
// LOWERCASE-initial app-instance qualifier (`@app.task`, `@celery.task`, `@current_app.task`).
// This deliberately EXCLUDES PascalCase class-qualified `.task` descriptors like faust's
// `@Service.task` (HOR-424): faust's queue model is the Kafka topic (`@app.agent(topic)`), and its
// internal service coroutines (`_fetcher`/`_flush`/`_commit_handler`) are not Celery task queues —
// matching them synthesized pseudo-queues named after framework methods. (`@app.task` from faust's
// own App is indistinguishable from Celery's and remains best-effort matched; the reported faust
// noise is the `@Service.task` form.) dramatiq (`@actor` / `.send()`) is intentionally NOT here —
// its queue model is the broker queue, not the actor name, so it has its own extractor
// (extract_dramatiq_queue_graph, HOR-411).
// Note: rq's `.enqueue()` and arq's `.enqueue_job()` have NO worker-side decorator (workers are
// registered by import path / function reference), so their producers can't be linked to a def
// here and are dropped by the task_queues filter — that's the achievable coverage (HOR-380).
static CELERY_TASK_DEF_RE: LazyLock<Regex> = LazyLock::new(|| {
    js_re(
        r"@(?:(?:[\w]+\.)*(?:shared_task|db_periodic_task|periodic_task|db_task)|(?:[a-z_]\w*\.)*task)\b[^\n]*(?:\n[ \t]*@[^\n]*)*\n[ \t]*(?:async[ \t]+)?def[ \t]+(\w+)",
    )
});
// An enqueue/producer call site: Celery `<task>.delay(`/`<task>.apply_async(`, huey
// `<task>.schedule(`, procrastinate `<task>.defer(`/`<task>.defer_async(`,
// arq `<task>.enqueue_job(`, or rq `<task>.enqueue(` (HOR-380). Captures the immediate identifier
// before the call (the task name), e.g. `tasks.send_email.delay(` -> `send_email`. The broad verbs
// (`.schedule(`/`.enqueue(`/`.defer(`) are kept honest by the task_queues filter, which
// keeps a producer only when it names a real @task def, so non-task call sites
// (cron/APScheduler/event emitters) are dropped. `defer_async` precedes `defer` and `enqueue_job`
// precedes `enqueue` so the longer verb wins. dramatiq's `.send()` is handled separately (HOR-411).
static CELERY_ENQUEUE_RE: LazyLock<Regex> = LazyLock::new(|| {
    js_re(r"([A-Za-z_]\w*)\s*\.\s*(?:delay|apply_async|schedule|defer_async|defer|enqueue_job|enqueue)\s*\(")
});

#[derive(Debug, Clone, Default, PartialEq)]
pub struct CeleryNodeInput {
    pub name: String,
    pub file_path: String,
    pub content: String,
}

// A File node's name is the filename (e.g. `views.py`); its content also contains the
// function bodies, so it double-matches `.delay()` already attributed to the function node.
static FILE_NODE_RE: LazyLock<Regex> = LazyLock::new(|| js_re(r"(?i)\.(py|pyi|js|jsx|ts|tsx|mjs|cjs)$"));

/// Pure Celery queue-graph extraction. A `@task def foo` is the worker for task "foo"; a
/// `foo.delay(...)` / `foo.apply_async(...)` call site is a producer. Edges are only emitted
/// for tasks that have a real `@task` definition, so a stray `.delay()` from an unrelated
/// library (e.g. lodash, animation code) never synthesizes a phantom queue.
pub fn extract_celery_queue_graph(nodes: &[CeleryNodeInput]) -> QueueGraph {
    let mut producers: Vec<QueueRow> = Vec::new();
    let mut workers: Vec<QueueRow> = Vec::new();

    for n in nodes {
        for m in CELERY_TASK_DEF_RE.captures_iter(&n.content) {
            let task = cap(&m, 1);
            // Exclude pytest-style test defs/files from workers (HOR-424): a project's own
            // `@shared_task def test_*` suite (or anything under tests/) is not real topology — the
            // same discipline the dramatiq extractor applies (HOR-411/HOR-420).
            if !task.is_empty() && !is_test_unit(task, &n.file_path) {
                workers.push(row(task, task, &n.file_path));
            }
        }
        // Skip producer attribution from File nodes so the producer symbol is the function, not the
        // file (workers are unaffected — they derive their symbol from the `def` name, not n.name).
        if FILE_NODE_RE.is_match(&n.name) {
            continue;
        }
        // Exclude test functions/files from producers too (HOR-424).
        if is_test_unit(&n.name, &n.file_path) {
            continue;
        }
        for m in CELERY_ENQUEUE_RE.captures_iter(&n.content) {
            let task = cap(&m, 1);
            if !task.is_empty() {
                let symbol = if n.name.is_empty() { base_name(&n.file_path) } else { n.name.clone() };
                producers.push(row(task, &symbol, &n.file_path));
            }
        }
    }

    // Only tasks with a real @task definition are queues — drops `.delay()` false positives.
    let task_queues: HashSet<&str> = workers.iter().map(|w| w.queue.as_str()).collect();
    let queues = sorted_unique(task_queues.iter().copied());
    let mut edges: Vec<SynthEdge> = Vec::new();
    for q in &queues {
        let p = dedupe_by_symbol_file(producers.iter().filter(|p| &p.queue == q));
        let w = dedupe_by_symbol_file(workers.iter().filter(|w| &w.queue == q));
        if !p.is_empty() {
            for p in &p {
                for w in &w {
                    edges.push(edge(q, Some(p), Some(w)));
                }
            }
        } else {
            for w in &w {
                edges.push(edge(q, None, Some(w)));
            }
        }
    }

    let producers = producers.into_iter().filter(|p| task_queues.contains(p.queue.as_str())).collect();
    QueueGraph { queues, producers, workers, edges }
}

// --- dramatiq (Python) patterns (HOR-411) ---
// dramatiq's queue model differs from Celery/huey: an `@actor`-decorated `def` binds to a *broker
// queue* (the `queue_name=` kwarg, default `"default"`), NOT to a queue named after the function.
// `foo.send(...)` / `foo.send_with_options(...)` enqueues to actor `foo`'s queue. So we link a
// producer to its worker by ACTOR NAME (`foo`), but the edge's `queueName` is the real broker queue
// — otherwise we conflate actor/function names with queue names and massively over-report topology.
//
// `@actor` / `@dramatiq.actor(...)` directly on a `def` (optionally with args + stacked decorators).
// Group 1 = the decorator's arg text (to find `queue_name=`); group 2 = the actor/def name.
// The arg text is captured with `[\s\S]*?` (lazy, up to the first following `def`) rather than a
// single-line `[^\n]*` so a multi-line decorator — `@dramatiq.actor(\n  queue_name="emails",\n)\n
// def foo` — is still matched and its `queue_name=` resolved (HOR-420). Lazy + the `\n...def`
// anchor keep the span minimal (stops at the nearest def), and any stacked decorators between the
// `@actor` line and the `def` fall inside group 1 harmlessly (queue_name is searched within it).
static DRAMATIQ_ACTOR_RE: LazyLock<Regex> =
    LazyLock::new(|| js_re(r"@(?:[\w]+\.)*actor\b([\s\S]*?)\n[ \t]*(?:async[ \t]+)?def[ \t]+(\w+)"));
// `<actor>.send(` / `<actor>.send_with_options(` — captures the actor identifier before the call.
static DRAMATIQ_SEND_RE: LazyLock<Regex> = LazyLock::new(|| js_re(r"([A-Za-z_]\w*)\s*\.\s*send(?:_with_options)?\s*\("));
// `queue_name="emails"` inside an `@actor(...)` decorator's arg text.
static DRAMATIQ_QUEUE_NAME_RE: LazyLock<Regex> = LazyLock::new(|| js_re(r#"queue_name\s*=\s*['"]([^'"]+)['"]"#));

static TEST_FILE_RE: LazyLock<Regex> = LazyLock::new(|| js_re(r"_test\.[A-Za-z]+$"));
static TESTS_DIR_RE: LazyLock<Regex> = LazyLock::new(|| js_re(r"(?i)(^|/)tests?/"));

/// A pytest-style test function/file should not be reported as a real producer OR worker.
fn is_test_unit(name: &str, file_path: &str) -> bool {
    if name.starts_with("test_") || name.ends_with("_test") {
        return true;
    }
    let file = file_path.rsplit('/').next().unwrap_or(file_path);
    if file.starts_with("test_") || TEST_FILE_RE.is_match(file) {
        return true;
    }
    TESTS_DIR_RE.is_match(file_path)
}

// A Python `def`/`async def` header — used to resolve the function that ENCLOSES a `.send()` call
// site so the producer is attributed to the real enqueuing function, not the node's class/module
// name (HOR-411 round 2: a Class node like `results/middleware.py::Results` would otherwise report
// the producer symbol as "Results" rather than the method that actually calls `.send()`).
static PY_DEF_RE: LazyLock<Regex> = LazyLock::new(|| js_re(r"(?:^|\n)[ \t]*(?:async[ \t]+)?def[ \t]+(\w+)"));

/// The name of the `def` immediately enclosing `index` in `content`, or None if the call sits at
/// class/module body level (no enclosing function — we'd otherwise fall back to an arbitrary
/// class/module name, which is exactly the misattribution we're avoiding).
fn enclosing_def_name(content: &str, index: usize) -> Option<String> {
    let mut name: Option<String> = None;
    for m in PY_DEF_RE.captures_iter(content) {
        if m.get(0).map(|g| g.start()).unwrap_or(0) <= index {
            name = m.get(1).map(|g| g.as_str().to_string()).or(name);
        } else {
            break;
        }
    }
    name
}

/// Pure dramatiq queue-graph extraction (HOR-411). An `@actor def foo` is a worker bound to a broker
/// queue (default `"default"`, or its `queue_name=` kwarg); a `foo.send(...)` call site is a producer
/// for that same actor. Producers and workers are joined by actor name, and the edge's `queueName` is
/// the actor's broker queue — NOT the actor/function name. Honesty rules:
///  - only actors with a real `@actor` def become queues (a stray `socket.send()` never synthesizes one),
///  - test functions/files are excluded from BOTH workers and producers (dramatiq's own `test_*` suite
///    is not topology — neither the ~45 `@actor` test workers nor their `.send()` call sites),
///  - producers are attributed to the function ENCLOSING the `.send()` call, not the node's
///    class/module name (a Class node's `.send()` reports the method, never the class name),
///  - `actor -> actor` self-edges (an actor re-enqueueing itself) are dropped.
pub fn extract_dramatiq_queue_graph(nodes: &[CeleryNodeInput]) -> QueueGraph {
    // actor name -> broker queue (first declaration wins).
    let mut actor_queue: HashMap<String, String> = HashMap::new();
    // (row, actor)
    let mut workers: Vec<(QueueRow, String)> = Vec::new();
    let mut producers: Vec<(QueueRow, String)> = Vec::new();

    // Pass 1: collect actors and the broker queue each binds to. Skip test files/functions so the
    // worker list (and the queues derived from it) isn't polluted by dramatiq's own `@actor` test
    // suite (~45 `test_*` actors under tests/ — HOR-411 round 2). A test-only actor never registers,
    // so a `.send()` referencing it also drops in pass 2.
    for n in nodes {
        if is_test_unit(&n.name, &n.file_path) {
            continue;
        }
        for m in DRAMATIQ_ACTOR_RE.captures_iter(&n.content) {
            let args = cap(&m, 1);
            let actor = cap(&m, 2);
            if actor.is_empty() {
                continue;
            }
            // Exclude test actors by DEF NAME too, not just by container node/file (HOR-420): a
            // non-test File/Class node can still contain `@actor def test_*` defs (dramatiq's own
            // `test_*` actors live inside regular module nodes), which HOR-411's node-level check let
            // through — ~234 leaked test workers. A test-only actor never registers, so the matching
            // `.send()` producer also drops in pass 2 (actor_queue miss).
            if is_test_unit(actor, &n.file_path) {
                continue;
            }
            let queue = DRAMATIQ_QUEUE_NAME_RE.captures(args).map(|c| c[1].to_string()).unwrap_or_else(|| "default".into());
            let queue = actor_queue.entry(actor.to_string()).or_insert(queue).clone();
            workers.push((row(&queue, actor, &n.file_path), actor.to_string()));
        }
    }

    // Pass 2: `.send()` producers that reference a real actor. Skip File nodes (so producers attribute
    // to the enclosing function, not the file) and test functions/files (dramatiq's own test suite).
    // Attribute each producer to the function that ENCLOSES the `.send()` call, not the node's name:
    // for a Class node (e.g. `results/middleware.py::Results`) `n.name` is the class, which is an
    // arbitrary symbol, not the real enqueue site. If the call has no enclosing `def` (class/module
    // body level), we can't name a real call site, so we drop it rather than report the class/module.
    for n in nodes {
        if FILE_NODE_RE.is_match(&n.name) {
            continue;
        }
        if is_test_unit(&n.name, &n.file_path) {
            continue;
        }
        for m in DRAMATIQ_SEND_RE.captures_iter(&n.content) {
            let actor = cap(&m, 1);
            let Some(queue) = actor_queue.get(actor) else { continue };
            let Some(symbol) = enclosing_def_name(&n.content, m.get(0).map(|g| g.start()).unwrap_or(0)) else {
                continue;
            };
            // The enclosing call site can itself be a test function inside a non-test node (HOR-420).
            if is_test_unit(&symbol, &n.file_path) {
                continue;
            }
            producers.push((row(queue, &symbol, &n.file_path), actor.to_string()));
        }
    }

    let mut actors: Vec<&String> = actor_queue.keys().collect();
    actors.sort();
    let queues = sorted_unique(actors.iter().map(|a| actor_queue[*a].as_str()));
    let mut edges: Vec<SynthEdge> = Vec::new();
    for actor in actors {
        let queue = &actor_queue[actor];
        let w = dedupe_by_symbol_file(workers.iter().filter(|(_, a)| a == actor).map(|(r, _)| r));
        if w.is_empty() {
            continue;
        }
        // Drop self-edges: a producing node that is itself this actor's worker def (the actor
        // re-enqueueing itself) is not a real cross-component producer.
        let p: Vec<QueueRow> = dedupe_by_symbol_file(producers.iter().filter(|(_, a)| a == actor).map(|(r, _)| r))
            .into_iter()
            .filter(|p| !w.iter().any(|w| w.symbol == p.symbol && w.file == p.file))
            .collect();
        if !p.is_empty() {
            for p in &p {
                for w in &w {
                    edges.push(edge(queue, Some(p), Some(w)));
                }
            }
        } else {
            for w in &w {
                edges.push(edge(queue, None, Some(w)));
            }
        }
    }

    QueueGraph {
        queues,
        producers: producers.into_iter().map(|(r, _)| r).collect(),
        workers: workers.into_iter().map(|(r, _)| r).collect(),
        edges,
    }
}

/// Dedup queue rows by symbol+file. Previously keyed by file alone, but enum fan-out and
/// dispatch tables can legitimately yield several distinct symbols per file (e.g. a generic
/// `new Worker(loopVar)` worker AND named dispatch handlers), so we keep symbol in the key.
fn dedupe_by_symbol_file<'a>(rows: impl Iterator<Item = &'a QueueRow>) -> Vec<QueueRow> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut out = Vec::new();
    for r in rows {
        let key = format!("{} {}", r.symbol, r.file);
        if seen.insert(key) {
            out.push(r.clone());
        }
    }
    out
}
