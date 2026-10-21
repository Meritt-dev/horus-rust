//! @horus/eval — the read-only accuracy harness (HOR-403).
//!
//! READ-ONLY by construction: this package only reads the outcome-label store + joined investigation
//! reports and transforms them into an evaluable corpus, a baseline hit-rate report (same math as
//! `horus memory accuracy`), and a no-model feature-separation diagnostic. It NEVER writes the
//! outcome_label store — only `horus feedback` + `horus memory confirm` write labels.
//!
//! Surfaced through the CLI as `horus eval build` + `horus eval baseline`.

pub mod baseline;
pub mod corpus;
pub mod reranker;
pub mod types;

pub use baseline::{compute_baseline, feature_separation};
pub use corpus::{build_corpus, corpus_filename, holdout_split, pick_headline_cause, serialize_corpus, ReportResolver};
pub use reranker::{
    apply_reranker, baseline_top, collect_feature_keys, derive_labels, extract_raw_features, is_reranker_model,
    matches_confirmed_cause, train_reranker, DerivedLabels, LabeledExample, RankableCause, RerankInvestigation,
    RerankTrainResult, RerankTrainSkip, RerankerHoldout, RerankerModel, TrainOptions, MIN_TRAIN_INVESTIGATIONS,
    RERANKER_VERSION,
};
pub use types::*;
