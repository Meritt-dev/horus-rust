//! `MemoryStorage` over the real embedded SQLite store (`horus-db`, `~/.horus/horus-rust.db`).
//!
//! Each method is the SQLite translation of one drizzle statement from `memory.ts` /
//! `memory-view.ts` (see the doc comments on [`MemoryStorage`]). Column conventions follow the
//! db crate: jsonb and text[] → JSON text, timestamptz → ISO text (`format_ts` / `parse_ts`).

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use horus_db::{format_ts, parse_ts, DbHandle};
use rusqlite::types::Value as Sql;
use rusqlite::{params_from_iter, Connection, Row};
use serde_json::Value;

use crate::memory_store::{
    IncidentMemory, InvestigationRow, MemoryAudit, MemoryItem, MemoryItemFilter, MemoryItemPatch, MemoryLink,
    MemoryStorage, NewIncidentMemory, NewMemoryAudit, NewMemoryItem, NewMemoryLink,
};

/// [`MemoryStorage`] backed by a `horus-db` handle.
#[derive(Clone, Debug)]
pub struct SqliteMemoryStorage {
    db: DbHandle,
}

impl SqliteMemoryStorage {
    pub fn new(db: DbHandle) -> Self {
        Self { db }
    }
}

// ---------------------------------------------------------------------------
// Value conversion
// ---------------------------------------------------------------------------

fn text(s: impl Into<String>) -> Sql {
    Sql::Text(s.into())
}

fn opt_text(s: Option<impl Into<String>>) -> Sql {
    s.map(|s| Sql::Text(s.into())).unwrap_or(Sql::Null)
}

fn json_text(v: Option<&Value>) -> Sql {
    match v {
        Some(v) => Sql::Text(v.to_string()),
        None => Sql::Null,
    }
}

fn tags_text(t: Option<&Vec<String>>) -> Sql {
    match t {
        Some(t) => Sql::Text(serde_json::to_string(t).unwrap_or_else(|_| "[]".into())),
        None => Sql::Null,
    }
}

fn ts(t: Option<&DateTime<Utc>>) -> Sql {
    opt_text(t.map(format_ts))
}

fn parse_json(s: Option<String>) -> Option<Value> {
    s.and_then(|s| serde_json::from_str(&s).ok())
}

fn parse_tags(s: Option<String>) -> Option<Vec<String>> {
    s.and_then(|s| serde_json::from_str(&s).ok())
}

fn parse_opt_ts(s: Option<String>) -> Result<Option<DateTime<Utc>>> {
    s.map(|s| parse_ts(&s)).transpose()
}

// ---------------------------------------------------------------------------
// Row mapping (by column name — robust to ALTER TABLE column order)
// ---------------------------------------------------------------------------

const ITEM_COLS: &str = "id, kind, claim, scope, source, evidence, confidence, status, created_at, last_verified_at, \
    last_verified_hash, org_id, workspace_id, repo, user_id, visibility, sync_scope, sync_generation, origin, cloud_id, \
    author_name, pulled_at, payload, signature, tags";

fn row_item(r: &Row<'_>) -> Result<MemoryItem> {
    Ok(MemoryItem {
        id: r.get("id")?,
        kind: r.get("kind")?,
        claim: r.get("claim")?,
        scope: r.get("scope")?,
        source: r.get("source")?,
        evidence: parse_json(r.get("evidence")?).unwrap_or(Value::Array(vec![])),
        confidence: r.get("confidence")?,
        status: r.get("status")?,
        created_at: parse_ts(&r.get::<_, String>("created_at")?)?,
        last_verified_at: parse_opt_ts(r.get("last_verified_at")?)?,
        last_verified_hash: r.get("last_verified_hash")?,
        org_id: r.get("org_id")?,
        workspace_id: r.get("workspace_id")?,
        repo: r.get("repo")?,
        user_id: r.get("user_id")?,
        visibility: r.get("visibility")?,
        sync_scope: r.get("sync_scope")?,
        sync_generation: r.get("sync_generation")?,
        origin: r.get("origin")?,
        cloud_id: r.get("cloud_id")?,
        author_name: r.get("author_name")?,
        pulled_at: parse_opt_ts(r.get("pulled_at")?)?,
        payload: parse_json(r.get("payload")?),
        signature: r.get("signature")?,
        tags: parse_tags(r.get("tags")?),
    })
}

const LINK_COLS: &str = "id, from_memory_id, rel, to_kind, to_ref, to_file_path, created_at";

fn row_link(r: &Row<'_>) -> Result<MemoryLink> {
    Ok(MemoryLink {
        id: r.get("id")?,
        from_memory_id: r.get("from_memory_id")?,
        rel: r.get("rel")?,
        to_kind: r.get("to_kind")?,
        to_ref: r.get("to_ref")?,
        to_file_path: r.get("to_file_path")?,
        created_at: parse_ts(&r.get::<_, String>("created_at")?)?,
    })
}

const INCIDENT_COLS: &str = "id, investigation_id, project, title, summary, signature, tags, payload, created_at";

fn row_incident(r: &Row<'_>) -> Result<IncidentMemory> {
    Ok(IncidentMemory {
        id: r.get("id")?,
        investigation_id: r.get("investigation_id")?,
        project: r.get("project")?,
        title: r.get("title")?,
        summary: r.get("summary")?,
        signature: r.get("signature")?,
        tags: parse_tags(r.get("tags")?),
        payload: parse_json(r.get("payload")?),
        created_at: parse_ts(&r.get::<_, String>("created_at")?)?,
    })
}

fn query_rows<T>(c: &Connection, sql: &str, args: Vec<Sql>, map: fn(&Row<'_>) -> Result<T>) -> Result<Vec<T>> {
    let mut stmt = c.prepare(sql)?;
    let mut rows = stmt.query(params_from_iter(args))?;
    let mut out = Vec::new();
    while let Some(r) = rows.next()? {
        out.push(map(r)?);
    }
    Ok(out)
}

fn select_item(c: &Connection, id: &str) -> Result<Option<MemoryItem>> {
    Ok(query_rows(c, &format!("SELECT {ITEM_COLS} FROM memory_item WHERE id = ?1 LIMIT 1"), vec![text(id)], row_item)?
        .into_iter()
        .next())
}

fn report_value(report: Option<String>) -> Option<Value> {
    parse_json(report)
}

/// Placeholders `?start, ?start+1, …` for an IN list.
fn placeholders(start: usize, n: usize) -> String {
    (start..start + n).map(|i| format!("?{i}")).collect::<Vec<_>>().join(", ")
}

#[async_trait]
impl MemoryStorage for SqliteMemoryStorage {
    // ---- incident_memory ----
    async fn select_incident_memory_by_project(&self, project: &str, limit: usize) -> Result<Vec<IncidentMemory>> {
        let args = vec![text(project), Sql::Integer(limit as i64)];
        self.db
            .with_conn(move |c| query_rows(c, &format!("SELECT {INCIDENT_COLS} FROM incident_memory WHERE project = ?1 LIMIT ?2"), args, row_incident))
            .await
    }

    async fn insert_incident_memory(&self, row: &NewIncidentMemory) -> Result<()> {
        let args = vec![
            opt_text(row.investigation_id.clone()),
            opt_text(row.project.clone()),
            text(row.title.clone()),
            opt_text(row.summary.clone()),
            opt_text(row.signature.clone()),
            tags_text(row.tags.as_ref()),
            json_text(row.payload.as_ref()),
        ];
        self.db
            .with_conn(move |c| {
                c.execute(
                    "INSERT INTO incident_memory (investigation_id, project, title, summary, signature, tags, payload) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params_from_iter(args),
                )?;
                Ok(())
            })
            .await
    }

    // ---- memory_item ----
    async fn get_memory_item(&self, id: &str) -> Result<Option<MemoryItem>> {
        let id = id.to_string();
        self.db.with_conn(move |c| select_item(c, &id)).await
    }

    async fn insert_memory_item(&self, item: &NewMemoryItem) -> Result<MemoryItem> {
        let id = item.id.clone();
        // Columns left None take their DB default via COALESCE (drizzle omits undefined columns).
        let args = vec![
            text(item.id.clone()),
            text(item.kind.clone()),
            text(item.claim.clone()),
            text(item.scope.clone()),
            text(item.source.clone()),
            json_text(item.evidence.as_ref()),
            Sql::Real(item.confidence),
            opt_text(item.status.clone()),
            ts(item.created_at.as_ref()),
            ts(item.last_verified_at.as_ref()),
            opt_text(item.last_verified_hash.clone()),
            opt_text(item.org_id.clone()),
            opt_text(item.workspace_id.clone()),
            text(item.repo.clone()),
            opt_text(item.user_id.clone()),
            opt_text(item.visibility.clone()),
            opt_text(item.sync_scope.clone()),
            item.sync_generation.map(Sql::Integer).unwrap_or(Sql::Null),
            opt_text(item.origin.clone()),
            opt_text(item.cloud_id.clone()),
            opt_text(item.author_name.clone()),
            ts(item.pulled_at.as_ref()),
            json_text(item.payload.as_ref()),
            opt_text(item.signature.clone()),
            tags_text(item.tags.as_ref()),
        ];
        self.db
            .with_conn(move |c| {
                c.execute(
                    "INSERT INTO memory_item (id, kind, claim, scope, source, evidence, confidence, status, created_at, \
                     last_verified_at, last_verified_hash, org_id, workspace_id, repo, user_id, visibility, sync_scope, \
                     sync_generation, origin, cloud_id, author_name, pulled_at, payload, signature, tags) VALUES \
                     (?1, ?2, ?3, ?4, ?5, COALESCE(?6, '[]'), ?7, COALESCE(?8, 'fresh'), \
                      COALESCE(?9, strftime('%Y-%m-%dT%H:%M:%fZ', 'now')), ?10, ?11, ?12, ?13, ?14, ?15, \
                      COALESCE(?16, 'private'), ?17, COALESCE(?18, 1), COALESCE(?19, 'local'), ?20, ?21, ?22, ?23, ?24, ?25)",
                    params_from_iter(args),
                )?;
                // `returning()` — re-read so triggers/defaults are reflected.
                select_item(c, &id)?.ok_or_else(|| anyhow!("memory_item insert returned no row"))
            })
            .await
    }

    async fn upsert_cached_memory_item(&self, item: &NewMemoryItem) -> Result<()> {
        let args = vec![
            text(item.id.clone()),
            text(item.kind.clone()),
            text(item.claim.clone()),
            text(item.scope.clone()),
            text(item.source.clone()),
            json_text(item.evidence.as_ref()),
            Sql::Real(item.confidence),
            opt_text(item.status.clone()),
            ts(item.created_at.as_ref()),
            ts(item.last_verified_at.as_ref()),
            opt_text(item.last_verified_hash.clone()),
            opt_text(item.org_id.clone()),
            opt_text(item.workspace_id.clone()),
            text(item.repo.clone()),
            opt_text(item.user_id.clone()),
            opt_text(item.visibility.clone()),
            opt_text(item.sync_scope.clone()),
            item.sync_generation.map(Sql::Integer).unwrap_or(Sql::Null),
            opt_text(item.origin.clone()),
            opt_text(item.cloud_id.clone()),
            opt_text(item.author_name.clone()),
            ts(item.pulled_at.as_ref()),
            json_text(item.payload.as_ref()),
            opt_text(item.signature.clone()),
            tags_text(item.tags.as_ref()),
        ];
        self.db
            .with_conn(move |c| {
                // drizzle `set` skips undefined values: `evidence` keeps the stored value when absent.
                c.execute(
                    "INSERT INTO memory_item (id, kind, claim, scope, source, evidence, confidence, status, created_at, \
                     last_verified_at, last_verified_hash, org_id, workspace_id, repo, user_id, visibility, sync_scope, \
                     sync_generation, origin, cloud_id, author_name, pulled_at, payload, signature, tags) VALUES \
                     (?1, ?2, ?3, ?4, ?5, COALESCE(?6, '[]'), ?7, COALESCE(?8, 'fresh'), \
                      COALESCE(?9, strftime('%Y-%m-%dT%H:%M:%fZ', 'now')), ?10, ?11, ?12, ?13, ?14, ?15, \
                      COALESCE(?16, 'private'), ?17, COALESCE(?18, 1), COALESCE(?19, 'local'), ?20, ?21, ?22, ?23, ?24, ?25) \
                     ON CONFLICT(id) DO UPDATE SET kind = ?2, claim = ?3, scope = ?4, source = ?5, \
                       status = COALESCE(?8, 'fresh'), confidence = ?7, visibility = COALESCE(?16, 'team'), \
                       evidence = COALESCE(?6, memory_item.evidence), cloud_id = ?20, author_name = ?21, \
                       last_verified_at = ?10, last_verified_hash = ?11, origin = 'cloud', repo = ?14, \
                       sync_scope = ?17, pulled_at = ?22",
                    params_from_iter(args),
                )?;
                Ok(())
            })
            .await
    }

    async fn update_memory_item(&self, id: &str, patch: &MemoryItemPatch) -> Result<()> {
        let mut sets: Vec<&str> = Vec::new();
        let mut args: Vec<Sql> = Vec::new();
        let mut add = |col: &'static str, v: Sql| {
            sets.push(col);
            args.push(v);
        };
        if let Some(v) = &patch.claim {
            add("claim", text(v.clone()));
        }
        if let Some(v) = patch.confidence {
            add("confidence", Sql::Real(v));
        }
        if let Some(v) = &patch.payload {
            add("payload", json_text(v.as_ref()));
        }
        if let Some(v) = &patch.status {
            add("status", text(v.clone()));
        }
        if let Some(v) = &patch.visibility {
            add("visibility", text(v.clone()));
        }
        if let Some(v) = &patch.last_verified_hash {
            add("last_verified_hash", opt_text(v.clone()));
        }
        if let Some(v) = &patch.last_verified_at {
            add("last_verified_at", ts(v.as_ref()));
        }
        if let Some(v) = &patch.origin {
            add("origin", text(v.clone()));
        }
        if let Some(v) = &patch.cloud_id {
            add("cloud_id", opt_text(v.clone()));
        }
        if let Some(v) = &patch.author_name {
            add("author_name", opt_text(v.clone()));
        }
        if sets.is_empty() {
            return Ok(());
        }
        let assignments: Vec<String> = sets.iter().enumerate().map(|(i, c)| format!("{c} = ?{}", i + 1)).collect();
        let sql = format!("UPDATE memory_item SET {} WHERE id = ?{}", assignments.join(", "), args.len() + 1);
        args.push(text(id));
        self.db
            .with_conn(move |c| {
                c.execute(&sql, params_from_iter(args))?;
                Ok(())
            })
            .await
    }

    async fn query_memory_items(&self, filter: &MemoryItemFilter) -> Result<Vec<MemoryItem>> {
        let mut conds: Vec<String> = vec!["repo = ?1".into()];
        let mut args: Vec<Sql> = vec![text(filter.repo.clone())];
        let eq = |col: &str, v: &Option<String>, conds: &mut Vec<String>, args: &mut Vec<Sql>| {
            if let Some(v) = v {
                args.push(text(v.clone()));
                conds.push(format!("{col} = ?{}", args.len()));
            }
        };
        eq("scope", &filter.scope, &mut conds, &mut args);
        eq("origin", &filter.origin, &mut conds, &mut args);
        eq("visibility", &filter.visibility, &mut conds, &mut args);
        eq("org_id", &filter.org_id, &mut conds, &mut args);
        eq("workspace_id", &filter.workspace_id, &mut conds, &mut args);
        eq("user_id", &filter.user_id, &mut conds, &mut args);
        for (col, values) in [("status", &filter.status), ("kind", &filter.kind)] {
            if let Some(values) = values.as_ref().filter(|v| !v.is_empty()) {
                let start = args.len() + 1;
                args.extend(values.iter().map(|v| text(v.clone())));
                conds.push(format!("{col} IN ({})", placeholders(start, values.len())));
            }
        }
        let sql = format!("SELECT {ITEM_COLS} FROM memory_item WHERE {} ORDER BY created_at DESC, id ASC", conds.join(" AND "));
        self.db.with_conn(move |c| query_rows(c, &sql, args, row_item)).await
    }

    async fn delete_cloud_memory_items(&self, repo: &str, keep_ids: &[String]) -> Result<usize> {
        let mut args = vec![text(repo)];
        let mut sql = "DELETE FROM memory_item WHERE repo = ?1 AND origin = 'cloud'".to_string();
        if !keep_ids.is_empty() {
            sql.push_str(&format!(" AND id NOT IN ({})", placeholders(2, keep_ids.len())));
            args.extend(keep_ids.iter().map(|k| text(k.clone())));
        }
        self.db.with_conn(move |c| Ok(c.execute(&sql, params_from_iter(args))?)).await
    }

    // ---- memory_link ----
    async fn insert_memory_link(&self, link: &NewMemoryLink) -> Result<MemoryLink> {
        let id = link.id.clone();
        let args = vec![
            text(link.id.clone()),
            text(link.from_memory_id.clone()),
            text(link.rel.clone()),
            text(link.to_kind.clone()),
            text(link.to_ref.clone()),
            opt_text(link.to_file_path.clone()),
        ];
        self.db
            .with_conn(move |c| {
                c.execute(
                    "INSERT INTO memory_link (id, from_memory_id, rel, to_kind, to_ref, to_file_path) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params_from_iter(args),
                )?;
                query_rows(c, &format!("SELECT {LINK_COLS} FROM memory_link WHERE id = ?1"), vec![text(id)], row_link)?
                    .into_iter()
                    .next()
                    .ok_or_else(|| anyhow!("memory_link insert returned no row"))
            })
            .await
    }

    async fn find_memory_link(&self, from_memory_id: &str, rel: &str, to_ref: &str, to_kind: &str) -> Result<Option<MemoryLink>> {
        let args = vec![text(from_memory_id), text(rel), text(to_ref), text(to_kind)];
        self.db
            .with_conn(move |c| {
                Ok(query_rows(
                    c,
                    &format!("SELECT {LINK_COLS} FROM memory_link WHERE from_memory_id = ?1 AND rel = ?2 AND to_ref = ?3 AND to_kind = ?4 LIMIT 1"),
                    args,
                    row_link,
                )?
                .into_iter()
                .next())
            })
            .await
    }

    async fn delete_memory_links(&self, from_memory_id: &str, rel: &str, to_ref: &str, to_kind: &str) -> Result<usize> {
        let args = vec![text(from_memory_id), text(rel), text(to_ref), text(to_kind)];
        self.db
            .with_conn(move |c| {
                Ok(c.execute(
                    "DELETE FROM memory_link WHERE from_memory_id = ?1 AND rel = ?2 AND to_ref = ?3 AND to_kind = ?4",
                    params_from_iter(args),
                )?)
            })
            .await
    }

    async fn links_from(&self, from_memory_id: &str) -> Result<Vec<MemoryLink>> {
        let args = vec![text(from_memory_id)];
        self.db
            .with_conn(move |c| query_rows(c, &format!("SELECT {LINK_COLS} FROM memory_link WHERE from_memory_id = ?1"), args, row_link))
            .await
    }

    async fn links_to(&self, to_kind: &str, to_ref: &str) -> Result<Vec<MemoryLink>> {
        let args = vec![text(to_kind), text(to_ref)];
        self.db
            .with_conn(move |c| query_rows(c, &format!("SELECT {LINK_COLS} FROM memory_link WHERE to_kind = ?1 AND to_ref = ?2"), args, row_link))
            .await
    }

    // ---- memory_audit ----
    async fn insert_memory_audit(&self, row: &NewMemoryAudit) -> Result<()> {
        let args = vec![
            text(row.id.clone()),
            text(row.memory_id.clone()),
            text(row.action.clone()),
            text(row.actor.to_string()),
            opt_text(row.from_status.clone()),
            opt_text(row.to_status.clone()),
            opt_text(row.note.clone()),
            json_text(row.detail.as_ref()),
        ];
        self.db
            .with_conn(move |c| {
                c.execute(
                    "INSERT INTO memory_audit (id, memory_id, action, actor, from_status, to_status, note, detail) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    params_from_iter(args),
                )?;
                Ok(())
            })
            .await
    }

    async fn audit_history(&self, memory_id: &str) -> Result<Vec<MemoryAudit>> {
        let args = vec![text(memory_id)];
        self.db
            .with_conn(move |c| {
                query_rows(
                    c,
                    "SELECT id, memory_id, action, actor, from_status, to_status, note, detail, at FROM memory_audit \
                     WHERE memory_id = ?1 ORDER BY at DESC, id DESC",
                    args,
                    |r| {
                        Ok(MemoryAudit {
                            id: r.get("id")?,
                            memory_id: r.get("memory_id")?,
                            action: r.get("action")?,
                            actor: parse_json(r.get("actor")?).unwrap_or(Value::Null),
                            from_status: r.get("from_status")?,
                            to_status: r.get("to_status")?,
                            note: r.get("note")?,
                            detail: parse_json(r.get("detail")?),
                            at: parse_ts(&r.get::<_, String>("at")?)?,
                        })
                    },
                )
            })
            .await
    }

    // ---- investigations (memory-view) ----
    async fn get_investigation(&self, id: &str) -> Result<Option<InvestigationRow>> {
        Ok(horus_db::get_investigation(&self.db, id).await?.map(|i| InvestigationRow {
            id: i.id,
            title: i.title,
            created_at: i.created_at,
            report: report_value(i.report),
        }))
    }

    async fn list_investigations_with_reports(&self, limit: usize, project: Option<&str>) -> Result<Vec<InvestigationRow>> {
        Ok(horus_db::list_investigations_with_reports(&self.db, limit as i64, project)
            .await?
            .into_iter()
            .map(|i| InvestigationRow { id: i.id, title: i.title, created_at: i.created_at, report: report_value(i.report) })
            .collect())
    }
}
