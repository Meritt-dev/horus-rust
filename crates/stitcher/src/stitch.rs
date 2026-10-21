//! The stitcher orchestration: pull producer Class nodes and worker File nodes from source
//! intelligence over the typed content-search endpoint (HOR-392), run the pure extractor, and
//! replace the stitcher-owned rows in `queue_edges`. This is the one source-intelligence layer
//! the static graph can't give.

use std::collections::HashSet;

use horus_connectors::source::SourceHttpClient;
use horus_core::filter_queue_edges;
use horus_db::{replace_queue_edges, DbHandle, NewQueueEdge};
use serde::Serialize;

use crate::extract::{
    extract_celery_queue_graph, extract_dramatiq_queue_graph, extract_queue_graph, CeleryNodeInput,
    ProducerClassInput, QueueGraphInput, WorkerFileInput,
};

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct StitchSummary {
    pub queues: usize,
    pub producers: usize,
    pub workers: usize,
    pub edges: usize,
}

fn tokens(xs: &[&str]) -> Vec<String> {
    xs.iter().map(|s| s.to_string()).collect()
}

pub async fn stitch(client: &SourceHttpClient, db: &DbHandle, project: Option<&str>) -> anyhow::Result<StitchSummary> {
    // Producers: NestJS @InjectQueue (Class), raw `new Queue(...)`, and modules that
    // declare a queue-name constant (the queue's definition site). `MATCH (n)` (any
    // label) because raw bullmq lives in Files/Functions, not just Classes.
    //
    // Also pulls the indirection sources the extractor needs to resolve dynamically
    // registered queues (HOR-341): enum declarations (`new Queue(Enum.MEMBER)` /
    // `Object.values(Enum)` resolution) and dispatch tables that map enum members to
    // handler functions. These are harmless extra rows for the literal-string path.
    let producer_rows = client
        .content_search(
            &tokens(&[
                // "new Queue" (no paren) so generic-typed `new Queue<T>(...)` also matches.
                "@InjectQueue(",
                "new Queue",
                "QUEUE_NAME",
                "QueueName",
                "enum ",
                "Object.values(",
                // HOR-341: dispatch tables `[Enum.MEMBER]: () => this.ctrl.handler()` map runtime
                // queues to owning code, and often live in a file with NO new Queue/Worker of their
                // own (e.g. a scheduler controller) — so pull computed-key arrow entries too.
                "]: (",
            ]),
            None,
        )
        .await?;
    let producer_classes: Vec<ProducerClassInput> = producer_rows
        .into_iter()
        .map(|r| ProducerClassInput { name: r.name, file_path: r.file_path, content: r.content })
        .collect();

    // Workers: NestJS class-level @Processor, and raw `new Worker(...)`.
    // "new Worker" (no paren) so generic-typed `new Worker<T>(...)` also matches.
    let worker_rows = client.content_search(&tokens(&["@Processor(", "new Worker"]), None).await?;
    let worker_files: Vec<WorkerFileInput> =
        worker_rows.into_iter().map(|r| WorkerFileInput { file_path: r.file_path, content: r.content }).collect();

    let graph = extract_queue_graph(&QueueGraphInput { producer_classes, worker_files });

    // Python task-queue boundaries — Celery (HOR-356) + huey/procrastinate/dramatiq (HOR-380): a
    // `@task`/`@actor def foo` is the worker for task "foo"; a `foo.delay()`/`foo.apply_async()`
    // (Celery), `foo.schedule()` (huey), `foo.defer()`/`foo.defer_async()` (procrastinate), or
    // `foo.send()` (dramatiq) call site is the producer. The static flow graph can't connect them —
    // the same gap BullMQ has — so stitch them here. This CONTAINS pre-filter MUST stay in lockstep
    // with extract.rs's CELERY_ENQUEUE_RE/CELERY_TASK_DEF_RE: candidate nodes that aren't fetched
    // here are invisible to the regex. arq's `.enqueue_job(` / rq's `.enqueue(` are fetched too, but
    // they have no worker-side decorator so their producers drop under the task_queues filter.
    let celery_rows = client
        .content_search(
            &tokens(&[
                ".delay(",
                ".apply_async(",
                ".schedule(",
                ".defer(",
                ".defer_async(",
                ".send(",
                ".enqueue_job(",
                ".enqueue(",
                "@shared_task",
                "@task",
                ".task",
                "@actor",
                "periodic_task",
                "db_task",
            ]),
            None,
        )
        .await?;
    let celery_nodes: Vec<CeleryNodeInput> = celery_rows
        .into_iter()
        .map(|r| CeleryNodeInput { name: r.name, file_path: r.file_path, content: r.content })
        .collect();
    let celery = extract_celery_queue_graph(&celery_nodes);
    // dramatiq is fetched by the same CONTAINS pre-filter (`.send(` + `@actor`) but modeled
    // separately: its queue is the broker queue (default "default"), not the actor name (HOR-411).
    let dramatiq = extract_dramatiq_queue_graph(&celery_nodes);

    // Queue-edge hygiene at the WRITE path (canonical rules in horus-core's
    // queue-hygiene module, shared with the engine and `horus queues`): refuse
    // implausible names, fixture-only edges, and generic residue at persist time so
    // the database never stores garbage for readers to re-filter.
    let all_edges = graph.edges.into_iter().chain(celery.edges).chain(dramatiq.edges).collect();
    let edges: Vec<NewQueueEdge> = filter_queue_edges(all_edges)
        .into_iter()
        .map(|e| NewQueueEdge {
            queue_name: e.queue_name,
            producer_symbol: e.producer_symbol,
            producer_file: e.producer_file,
            worker_symbol: e.worker_symbol,
            worker_file: e.worker_file,
            source: Some("stitcher".into()),
            project: project.map(str::to_string),
        })
        .collect();

    // Summary counts describe what was KEPT (and therefore persisted) — the
    // "Stitched N queue edge(s)…" log line must not count dropped garbage.
    let mut queue_names: HashSet<&str> = HashSet::new();
    let mut producer_keys: HashSet<String> = HashSet::new();
    let mut worker_keys: HashSet<String> = HashSet::new();
    for e in &edges {
        queue_names.insert(&e.queue_name);
        if let Some(sym) = e.producer_symbol.as_deref().filter(|s| !s.is_empty()) {
            producer_keys.insert(format!("{} {} {}", e.queue_name, sym, e.producer_file.as_deref().unwrap_or("")));
        }
        if let Some(sym) = e.worker_symbol.as_deref().filter(|s| !s.is_empty()) {
            worker_keys.insert(format!("{} {} {}", e.queue_name, sym, e.worker_file.as_deref().unwrap_or("")));
        }
    }
    let summary = StitchSummary {
        queues: queue_names.len(),
        producers: producer_keys.len(),
        workers: worker_keys.len(),
        edges: edges.len(),
    };

    replace_queue_edges(db, edges, project).await?;

    Ok(summary)
}
