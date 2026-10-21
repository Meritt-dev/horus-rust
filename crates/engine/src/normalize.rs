//! Evidence normalization layer (HOR-13).
//!
//! Providers emit raw Evidence with source/kind/relevance/payload set. This layer
//! adds the cross-provider dimensions the engine and renderers use:
//!   • category — broad functional bucket
//!   • priority — investigation-priority tier (NOT operational severity)
//!   • subject  — the entity under investigation, from connector config + scope
//! Assigned here, never by providers; inert when nothing is known.

use horus_core::{Evidence, EvidenceCategory, EvidenceKind, EvidencePriority, EvidenceSubject, ProviderKind};

fn category_for(e: &Evidence) -> EvidenceCategory {
    // ProviderKind 'state' covers both MongoDB and Redis. Distinguish by kind
    // so redis-key evidence is not misclassified as database.
    if e.kind == EvidenceKind::RedisKey {
        return EvidenceCategory::Cache;
    }
    match e.source {
        ProviderKind::Queue => EvidenceCategory::Queue,
        ProviderKind::Logs => EvidenceCategory::Logs,
        ProviderKind::Metrics => EvidenceCategory::Metrics,
        ProviderKind::State => EvidenceCategory::Database,
        ProviderKind::History => EvidenceCategory::Deployment,
        ProviderKind::Code => EvidenceCategory::Code,
    }
}

/// Structural kinds are never anomalous by themselves.
fn is_structural(kind: EvidenceKind) -> bool {
    matches!(kind, EvidenceKind::Symbol | EvidenceKind::Flow | EvidenceKind::Impact | EvidenceKind::QueueEdge)
}

fn priority_for(e: &Evidence) -> EvidencePriority {
    if is_structural(e.kind) {
        return EvidencePriority::Info;
    }
    // Commits are structural unless a particularly relevant change is flagged.
    if e.kind == EvidenceKind::Commit {
        return if e.relevance >= 0.8 { EvidencePriority::Medium } else { EvidencePriority::Info };
    }
    // State snapshots: low-relevance items represent healthy or legacy state. Skip 'low'.
    if matches!(e.kind, EvidenceKind::QueueState | EvidenceKind::State | EvidenceKind::RedisKey) {
        if e.relevance >= 0.9 {
            return EvidencePriority::Critical;
        }
        if e.relevance >= 0.8 {
            return EvidencePriority::High;
        }
        if e.relevance >= 0.6 {
            return EvidencePriority::Medium;
        }
        return EvidencePriority::Info;
    }
    // Operational signals (log, metric, …): full relevance scale.
    if e.relevance >= 0.9 {
        EvidencePriority::Critical
    } else if e.relevance >= 0.8 {
        EvidencePriority::High
    } else if e.relevance >= 0.6 {
        EvidencePriority::Medium
    } else if e.relevance >= 0.4 {
        EvidencePriority::Low
    } else {
        EvidencePriority::Info
    }
}

/// The investigation/connector scope used to stamp the subject onto evidence.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct NormalizeContext {
    pub service: Option<String>,
    pub environment: Option<String>,
}

/// Build an EvidenceSubject from scope, or `None` when nothing is known.
fn subject_from(ctx: Option<&NormalizeContext>) -> Option<EvidenceSubject> {
    let ctx = ctx?;
    let mut subject = EvidenceSubject::default();
    if let Some(s) = &ctx.service {
        if !s.is_empty() {
            subject.service = Some(s.clone());
        }
    }
    if let Some(env) = &ctx.environment {
        if !env.is_empty() {
            subject.environment = Some(env.clone());
        }
    }
    if subject.service.is_some() || subject.environment.is_some() {
        Some(subject)
    } else {
        None
    }
}

/// Fill in `priority`, `category`, and (when scope is known) `subject` for every
/// evidence item in-place. Idempotent: values already set are left unchanged.
pub fn normalize_evidence(evidence: &mut [Evidence], context: Option<&NormalizeContext>) {
    let subject = subject_from(context);
    for e in evidence.iter_mut() {
        if e.category.is_none() {
            e.category = Some(category_for(e));
        }
        if e.priority.is_none() {
            e.priority = Some(priority_for(e));
        }
        if e.subject.is_none() {
            if let Some(s) = &subject {
                e.subject = Some(s.clone());
            }
        }
    }
}
