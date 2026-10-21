//! Queue-edge persistence for the stitcher.

use anyhow::Result;
use rusqlite::{params, params_from_iter, types::Value};

use crate::client::DbHandle;
use crate::schema::{parse_ts, NewQueueEdge, QueueEdge};

/// Replace all stitcher-produced queue edges for a given project atomically
/// (`None` = the legacy unlabelled rows).
pub async fn replace_queue_edges(db: &DbHandle, edges: Vec<NewQueueEdge>, project: Option<&str>) -> Result<()> {
    let project = project.map(str::to_string);
    db.with_conn(move |c| {
        let tx = c.unchecked_transaction()?;
        match &project {
            Some(p) => tx.execute("DELETE FROM queue_edges WHERE source = 'stitcher' AND project = ?1", params![p])?,
            None => tx.execute("DELETE FROM queue_edges WHERE source = 'stitcher' AND project IS NULL", [])?,
        };
        if !edges.is_empty() {
            let mut stmt = tx.prepare(
                "INSERT INTO queue_edges \
                 (queue_name, producer_symbol, producer_file, worker_symbol, worker_file, source, project) \
                 VALUES (?1, ?2, ?3, ?4, ?5, COALESCE(?6, 'stitcher'), ?7)",
            )?;
            for e in &edges {
                stmt.execute(params![
                    e.queue_name,
                    e.producer_symbol,
                    e.producer_file,
                    e.worker_symbol,
                    e.worker_file,
                    e.source,
                    e.project,
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    })
    .await
}

/// List queue edges, optionally filtered by project and/or queue name.
pub async fn list_queue_edges(db: &DbHandle, project: Option<&str>, queue_name: Option<&str>) -> Result<Vec<QueueEdge>> {
    let mut conditions: Vec<String> = Vec::new();
    let mut args: Vec<Value> = Vec::new();
    if let Some(p) = project {
        args.push(Value::Text(p.to_string()));
        conditions.push(format!("project = ?{}", args.len()));
    }
    if let Some(q) = queue_name {
        args.push(Value::Text(q.to_string()));
        conditions.push(format!("queue_name = ?{}", args.len()));
    }
    let where_clause = if conditions.is_empty() { String::new() } else { format!(" WHERE {}", conditions.join(" AND ")) };
    db.with_conn(move |c| {
        let mut stmt = c.prepare(&format!(
            "SELECT id, queue_name, producer_symbol, producer_file, worker_symbol, worker_file, source, project, \
             created_at, updated_at FROM queue_edges{where_clause}"
        ))?;
        let rows = stmt.query_map(params_from_iter(args), |r| {
            Ok(QueueEdgeRaw {
                id: r.get(0)?,
                queue_name: r.get(1)?,
                producer_symbol: r.get(2)?,
                producer_file: r.get(3)?,
                worker_symbol: r.get(4)?,
                worker_file: r.get(5)?,
                source: r.get(6)?,
                project: r.get(7)?,
                created_at: r.get(8)?,
                updated_at: r.get(9)?,
            })
        })?;
        rows.map(|r| {
            let raw = r?;
            Ok(QueueEdge {
                id: raw.id,
                queue_name: raw.queue_name,
                producer_symbol: raw.producer_symbol,
                producer_file: raw.producer_file,
                worker_symbol: raw.worker_symbol,
                worker_file: raw.worker_file,
                source: raw.source,
                project: raw.project,
                created_at: parse_ts(&raw.created_at)?,
                updated_at: parse_ts(&raw.updated_at)?,
            })
        })
        .collect()
    })
    .await
}

struct QueueEdgeRaw {
    id: String,
    queue_name: String,
    producer_symbol: Option<String>,
    producer_file: Option<String>,
    worker_symbol: Option<String>,
    worker_file: Option<String>,
    source: String,
    project: Option<String>,
    created_at: String,
    updated_at: String,
}
