//! Investigation reads/writes. The shared local DB holds EVERY project's investigations;
//! unscoped reads leaked one project's incident titles into another's lists (dogfood N1), so
//! every list/last read takes an optional project scope (`None` = unscoped: single-project
//! setups / id-addressed access).

use anyhow::Result;
use chrono::{DateTime, Utc};
use rusqlite::{params, params_from_iter, types::Value, Connection, Row};
use serde::Serialize;

use crate::client::DbHandle;
use crate::schema::{format_ts, parse_ts, Investigation, NewInvestigation};

const COLUMNS: &str =
    "id, title, incident_input, status, summary, narrative, report, project, created_at, updated_at";

fn row_to_investigation(r: &Row<'_>) -> Result<Investigation> {
    Ok(Investigation {
        id: r.get(0)?,
        title: r.get(1)?,
        incident_input: r.get(2)?,
        status: r.get(3)?,
        summary: r.get(4)?,
        narrative: r.get(5)?,
        report: r.get(6)?,
        project: r.get(7)?,
        created_at: parse_ts(&r.get::<_, String>(8)?)?,
        updated_at: parse_ts(&r.get::<_, String>(9)?)?,
    })
}

/// `listInvestigations` projection.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InvestigationSummary {
    pub id: String,
    pub title: String,
    pub status: String,
    pub summary: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// `listInvestigationsWithReports` projection.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InvestigationWithReport {
    pub id: String,
    pub title: String,
    pub created_at: DateTime<Utc>,
    /// JSON text, verbatim.
    pub report: Option<String>,
}

fn scope_clause(project: Option<&str>) -> (&'static str, Vec<Value>) {
    match project {
        Some(p) => (" WHERE project = ?1", vec![Value::Text(p.to_string())]),
        None => ("", vec![]),
    }
}

/// Insert one investigation row (the engine's `persist` write). JSON columns are stored exactly
/// as given. Returns the row id.
pub async fn save_investigation(db: &DbHandle, input: NewInvestigation) -> Result<String> {
    db.with_conn(move |c| insert_investigation(c, input)).await
}

fn insert_investigation(c: &Connection, input: NewInvestigation) -> Result<String> {
    let id = input.id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let created_at = input.created_at.map(|t| format_ts(&t));
    c.execute(
        "INSERT INTO investigations \
         (id, title, incident_input, status, summary, narrative, report, project, created_at, updated_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, \
                 COALESCE(?9, strftime('%Y-%m-%dT%H:%M:%fZ', 'now')), \
                 COALESCE(?9, strftime('%Y-%m-%dT%H:%M:%fZ', 'now')))",
        params![
            id,
            input.title,
            input.incident_input,
            input.status.unwrap_or_else(|| "open".into()),
            input.summary,
            input.narrative,
            input.report,
            input.project,
            created_at,
        ],
    )?;
    Ok(id)
}

/// Insert shape for one `evidence` row. JSON columns (`payload`/`links`/`provenance`) are text.
#[derive(Debug, Clone, Default)]
pub struct NewEvidenceRow {
    pub id: String,
    pub source: String,
    pub kind: String,
    pub title: String,
    pub timestamp: Option<DateTime<Utc>>,
    pub relevance: f64,
    pub payload: Option<String>,
    pub links: Option<String>,
    pub provenance: Option<String>,
}

/// Insert shape for one `findings` row (`evidence_ids` is a JSON text array; id defaulted).
#[derive(Debug, Clone, Default)]
pub struct NewFindingRow {
    pub kind: String,
    pub title: String,
    pub detail: Option<String>,
    pub confidence: f64,
    pub evidence_ids: Option<String>,
}

/// Insert shape for one `hypotheses` row (`supporting_evidence` is a JSON text array; id defaulted).
#[derive(Debug, Clone, Default)]
pub struct NewHypothesisRow {
    pub rank: i64,
    pub statement: String,
    pub score: f64,
    pub supporting_evidence: Option<String>,
    pub verdict: Option<String>,
}

/// The engine's `persist`: the investigation row plus its evidence, findings, and hypotheses,
/// all-or-nothing in ONE transaction (TS wraps the same inserts in `db.transaction`).
/// Returns the investigation id.
pub async fn save_investigation_bundle(
    db: &DbHandle,
    input: NewInvestigation,
    evidence: Vec<NewEvidenceRow>,
    findings: Vec<NewFindingRow>,
    hypotheses: Vec<NewHypothesisRow>,
) -> Result<String> {
    db.with_conn(move |c| {
        let tx = c.unchecked_transaction()?;
        let id = insert_investigation(&tx, input)?;
        for e in evidence {
            tx.execute(
                "INSERT INTO evidence (id, investigation_id, source, kind, title, timestamp, relevance, payload, links, provenance) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![e.id, id, e.source, e.kind, e.title, e.timestamp.map(|t| format_ts(&t)), e.relevance, e.payload, e.links, e.provenance],
            )?;
        }
        for f in findings {
            tx.execute(
                "INSERT INTO findings (id, investigation_id, kind, title, detail, confidence, evidence_ids) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![uuid::Uuid::new_v4().to_string(), id, f.kind, f.title, f.detail, f.confidence, f.evidence_ids],
            )?;
        }
        for h in hypotheses {
            tx.execute(
                "INSERT INTO hypotheses (id, investigation_id, rank, statement, score, supporting_evidence, verdict) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![uuid::Uuid::new_v4().to_string(), id, h.rank, h.statement, h.score, h.supporting_evidence, h.verdict],
            )?;
        }
        tx.commit()?;
        Ok(id)
    })
    .await
}

/// Update the stored report JSON blob for an investigation (used to persist AI judgment).
pub async fn update_investigation_report(db: &DbHandle, id: &str, report: &str) -> Result<()> {
    let (id, report) = (id.to_string(), report.to_string());
    db.with_conn(move |c| {
        c.execute("UPDATE investigations SET report = ?1 WHERE id = ?2", params![report, id])?;
        Ok(())
    })
    .await
}

/// Full row (incident input + report are the replay payload), or None.
pub async fn get_investigation(db: &DbHandle, id: &str) -> Result<Option<Investigation>> {
    let id = id.to_string();
    db.with_conn(move |c| {
        let mut stmt = c.prepare(&format!("SELECT {COLUMNS} FROM investigations WHERE id = ?1 LIMIT 1"))?;
        let mut rows = stmt.query(params![id])?;
        match rows.next()? {
            Some(r) => Ok(Some(row_to_investigation(r)?)),
            None => Ok(None),
        }
    })
    .await
}

/// Id of the most recently created investigation (same ordering as `list_investigations`, so
/// "the last investigation" means the same row both surfaces show first), or None.
pub async fn get_last_investigation_id(db: &DbHandle, project: Option<&str>) -> Result<Option<String>> {
    let (clause, args) = scope_clause(project);
    db.with_conn(move |c| {
        let mut stmt =
            c.prepare(&format!("SELECT id FROM investigations{clause} ORDER BY created_at DESC LIMIT 1"))?;
        let mut rows = stmt.query(params_from_iter(args))?;
        Ok(rows.next()?.map(|r| r.get(0)).transpose()?)
    })
    .await
}

/// Newest-first summaries, capped by `limit` (TS default 20).
pub async fn list_investigations(
    db: &DbHandle,
    limit: i64,
    project: Option<&str>,
) -> Result<Vec<InvestigationSummary>> {
    let (clause, mut args) = scope_clause(project);
    args.push(Value::Integer(limit));
    let limit_ref = if clause.is_empty() { "?1" } else { "?2" };
    db.with_conn(move |c| {
        let mut stmt = c.prepare(&format!(
            "SELECT id, title, status, summary, created_at FROM investigations{clause} \
             ORDER BY created_at DESC LIMIT {limit_ref}"
        ))?;
        let rows = stmt.query_map(params_from_iter(args), |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get::<_, String>(4)?))
        })?;
        rows.map(|r| {
            let (id, title, status, summary, created_at) = r?;
            Ok(InvestigationSummary { id, title, status, summary, created_at: parse_ts(&created_at)? })
        })
        .collect()
    })
    .await
}

/// Newest-first id/title/createdAt/report rows, capped by `limit` (TS default 20).
pub async fn list_investigations_with_reports(
    db: &DbHandle,
    limit: i64,
    project: Option<&str>,
) -> Result<Vec<InvestigationWithReport>> {
    let (clause, mut args) = scope_clause(project);
    args.push(Value::Integer(limit));
    let limit_ref = if clause.is_empty() { "?1" } else { "?2" };
    db.with_conn(move |c| {
        let mut stmt = c.prepare(&format!(
            "SELECT id, title, created_at, report FROM investigations{clause} \
             ORDER BY created_at DESC LIMIT {limit_ref}"
        ))?;
        let rows = stmt.query_map(params_from_iter(args), |r| {
            Ok((r.get(0)?, r.get(1)?, r.get::<_, String>(2)?, r.get(3)?))
        })?;
        rows.map(|r| {
            let (id, title, created_at, report) = r?;
            Ok(InvestigationWithReport { id, title, created_at: parse_ts(&created_at)?, report })
        })
        .collect()
    })
    .await
}
