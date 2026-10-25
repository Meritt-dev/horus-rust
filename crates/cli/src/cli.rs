//! clap definition of the whole `horus` command surface. Port of `buildProgram()` in
//! `packages/cli/src/index.ts`: same command names, positionals, option names, defaults and
//! help text (Commander `addHelpText('after', …)` lives in `after_help`).
//!
//! Commands are listed in the same order as the TS source so `horus --help` matches it.

use clap::{ArgAction, Args, Parser, Subcommand};
use horus_core::HORUS_VERSION;

const REPO_HELP: &str = "project name in the loaded config (default: inferred from cwd); to target another repo, pass --config or cd into it";
const CONFIG_TS_HELP: &str = "path to a Horus config file (.json, .js or .ts; default: nearest .horus/config.json)";
const AI_MODEL_HELP: &str = "override the AI model (default: the model saved by `horus connect ai`, else claude-opus-4-8)";

#[derive(Debug, Parser)]
#[command(
    name = "horus",
    bin_name = "horus",
    about = "Local-first, source-aware production-incident investigation engine",
    version = HORUS_VERSION,
    disable_version_flag = true,
    subcommand_required = true,
    arg_required_else_help = true
)]
pub struct Cli {
    /// output the version number
    #[arg(short = 'V', long, action = ArgAction::Version)]
    version: (),

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    #[command(
        about = "Check local readiness: CLI version, git root, .horus config, and source-intelligence setup",
        after_help = "\nExamples:\n  horus doctor\n  horus doctor --json\n  horus doctor --config ./horus.config.js\n"
    )]
    Doctor(DoctorArgs),

    #[command(about = "Local AI provider management")]
    Providers(ProvidersArgs),

    #[command(
        about = "Set up this repo for Horus: check prerequisites, write/register .horus config, start the source-intelligence host, and index the code",
        after_help = "\nExamples:\n  horus init\n  horus init --changed --fast          # pre-push: refresh project knowledge only (no source reanalysis)\n  horus init --reindex                 # full source re-analysis (e.g. after a backend update)\n  horus init --source http://127.0.0.1:8420   # use an already-running external host\n"
    )]
    Init(InitArgs),

    #[command(about = "List projects registered in the global registry (~/.horus/registry.json)")]
    Projects,

    #[command(
        about = "Summarize release/demo readiness: DB, source intelligence, connectors, and local config"
    )]
    Readiness(ReadinessArgs),

    #[command(about = "Local database utilities (the single embedded persistence tier)")]
    Db(DbArgs),

    #[command(
        about = "Add or update a runtime connector in .horus/config.json (e.g. elasticsearch, mongodb, postgres, grafana, redis, kafka, sentry, shopify, or ai)"
    )]
    Connect(ConnectArgs),

    #[command(
        about = "Configure the outbound notify sink for `horus watch` (webhook / cloud)"
    )]
    Notify(NotifyArgs),

    #[command(
        about = "Manage encrypted connector credentials (.horus/secrets.local.json)"
    )]
    Secrets(SecretsArgs),

    #[command(
        about = "Stop the source-intelligence host for the current repo (or --all to stop every host)"
    )]
    Stop(StopArgs),

    #[command(
        about = "List registered source-intelligence hosts and their live status (port, repo, running/stopped)"
    )]
    Hosts(HostsArgs),

    #[command(about = "Show config, provider health, and project/environment matrix")]
    Status(StatusArgs),

    #[command(
        about = "Explain a symbol: location, community, callers/callees, impact, related flows"
    )]
    Explain(ExplainArgs),

    #[command(
        about = "Query the local project-knowledge index (.horus/index) — offline; push/pull sync with the linked cloud project"
    )]
    Knowledge(KnowledgeArgs),

    #[command(
        about = "Inspect and manage deterministic incident memory + code-knowledge (project-scoped; works offline)"
    )]
    Memory(MemoryArgs),

    #[command(
        about = "Read-only accuracy harness over Horus's outcome-label eval set (never writes labels)"
    )]
    Eval(EvalArgs),

    #[command(
        about = "Fit the local, per-tenant reranker over your outcome-label corpus (off until it beats baseline)",
        after_help = "\nThe reranker is LOCAL and per-tenant: your corpus never leaves this machine. It only REORDERS\ncandidate causes among those that already clear Horus's confidence gates — it never changes a\nscore, a confidence, or a verdict. It ships OFF; once trained, enable with:\n  HORUS_RERANK=1 horus investigate \"<hint>\""
    )]
    Train(TrainArgs),

    #[command(
        about = "Run the Horus MCP server (stdio) — exposes the local project-knowledge index to agents"
    )]
    Mcp,

    #[command(
        about = "Show queue topology from source intelligence; --live adds real-time Redis/BullMQ state"
    )]
    Queues(QueuesArgs),

    #[command(
        about = "Run a deterministic investigation for an incident hint",
        after_help = "\nExamples:\n  horus investigate \"checkout latency spike\"\n  horus investigate --ai \"payment failures\"\n"
    )]
    Investigate(InvestigateArgs),

    #[command(
        about = "Build a compact, honesty-framed agent packet from a hint (fresh run) or saved investigation id",
        after_help = "\nExamples:\n  horus packet \"checkout latency spike\"\n  horus packet \"queue backlog\" --for claude --json\n  horus packet <savedId> --json          # project a saved investigation (no re-query)\n"
    )]
    Packet(PacketArgs),

    #[command(about = "Run the durable configured watcher in the foreground")]
    Watch(WatchArgs),

    #[command(
        about = "macOS watcher: check, install, start, run, status, pause, resume, stop, remove, retry"
    )]
    Service(ServiceArgs),

    #[command(
        about = "Show what changed between two git refs and which flows are affected (source change-impact)"
    )]
    Changes(ChangesArgs),

    #[command(
        about = "Reconstruct what changed in a time window (git + change-impact) — evidence, not conclusions"
    )]
    Timeline(TimelineArgs),

    #[command(
        name = "what-changed",
        about = "Concise, evidence-backed summary of what changed for a service in a time window"
    )]
    WhatChanged(WhatChangedArgs),

    #[command(
        about = "Discover the living architecture (subsystems, async boundaries, external systems, fragility)"
    )]
    Architecture(ArchitectureArgs),

    #[command(
        name = "blast-radius",
        about = "Failure-propagation analysis: upstream/downstream dependencies + blast radius across async boundaries"
    )]
    BlastRadius(BlastRadiusArgs),

    #[command(
        about = "Shortest relationship path between two symbols across all edges (calls, imports, extends, implements, uses_type), both directions"
    )]
    Trace(TraceArgs),

    #[command(
        about = "Graph-shape insights: the codebase's hubs (most-connected symbols), surprising cross-community connections, and suggested questions"
    )]
    Insights(InsightsArgs),

    #[command(about = "List configured repositories and their source-intelligence host health")]
    Repos(ReposArgs),

    #[command(
        about = "Search symbols across ALL configured repositories (you need not know which repo holds the answer)"
    )]
    Search(SearchArgs),

    #[command(
        about = "List recent investigations (ids for replay)",
        after_help = "\nExamples:\n  horus investigations\n  horus investigations -n 20\n  horus investigations --json\n"
    )]
    Investigations(InvestigationsArgs),

    #[command(
        about = "Client-reported issues (Lens work queue) — needs `horus login` + `horus cloud link`",
        args_conflicts_with_subcommands = true
    )]
    Lens(LensArgs),

    #[command(
        about = "Re-render a saved investigation from the audit store (no re-query)",
        after_help = "\nExamples:\n  horus replay <id>\n  horus replay <id> --format markdown\n  horus replay <id> --format json\n  horus replay <id> --ai\n  horus replay <id> --ai --ai-model claude-sonnet-4-6\n  horus replay <id> --ai --refresh-ai\n\n  (Use 'horus investigations' to list saved investigation ids.)\n"
    )]
    Replay(ReplayArgs),

    #[command(
        about = "Draft an editable incident postmortem from a saved investigation",
        after_help = "\nExamples:\n  horus postmortem <id>\n  horus postmortem <id> --output ./postmortem.md\n  horus postmortem <id> --output ./postmortem.md --force\n  horus postmortem <id> --ai-summary\n  horus postmortem <id> --output ./postmortem.md --ai-summary --ai-model claude-sonnet-4-6\n  horus postmortem <id> --ai-summary --refresh-ai\n\n  (Use 'horus investigations' to list saved investigation ids.)\n"
    )]
    Postmortem(PostmortemArgs),

    #[command(
        about = "Estimate who likely owns a component (git history, with confidence + evidence)"
    )]
    Owner(OwnerArgs),

    #[command(
        about = "Score a saved investigation's quality (a feedback loop for Horus, not engineers)"
    )]
    Score(ScoreArgs),

    #[command(
        about = "Ask about or refine a saved investigation — reuses evidence; code-locating questions re-query the source host for fresh file:line citations",
        after_help = "\nExamples:\n  Code-locating (fresh source lookup):\n    \"where is processOrder defined?\" · \"which file has OrderService?\"\n  Questions (direct answers):\n    \"what evidence contradicts <topic>?\"  · \"what evidence is missing?\"\n    \"why is confidence not higher?\"\n  Topic filters (deterministic scoping):\n    \"focus on queue behavior\" · \"ignore deployment changes\" · \"retry\"\n"
    )]
    Ask(AskArgs),

    #[command(about = "List recent investigation quality scores + the average (trend)")]
    Scores(ScoresArgs),

    #[command(
        about = "Understand a system fast: architecture, critical paths, what breaks, ownership, past incidents"
    )]
    Onboard(OnboardArgs),

    #[command(
        about = "Practice an incident: pick a synthetic scenario and compare your reasoning with Horus"
    )]
    Simulate(SimulateArgs),

    #[command(
        about = "Synthesize error evidence from logs (signatures, first/last, affected services); --raw for lines"
    )]
    Logs(LogsArgs),

    #[command(
        about = "Surface application-state evidence from MongoDB (read-only, allowlisted): counts, staleness, anomalous statuses"
    )]
    State(StateArgs),

    #[command(
        about = "Grafana metrics evidence: find dashboards/panels for a hint and detect latency spikes, error-rate changes, throughput drops, queue growth"
    )]
    Metrics(MetricsArgs),

    #[command(
        about = "Manage the Horus agent skill — install playbooks that teach agents to use Horus as their evidence layer"
    )]
    Skill(SkillArgs),

    #[command(
        about = "Update Horus to the latest release from GitHub",
        after_help = "\nExamples:\n  horus update              # update to latest\n  horus update --check      # check without installing\n  horus update --force      # re-download current version\n"
    )]
    Update(UpdateArgs),

    #[command(
        about = "Log in to Horus Cloud; stores a CLI token in ~/.horus/auth.json (never in the repo)",
        after_help = "\nExamples:\n  horus login --token <token>\n  HORUS_TOKEN=<token> horus login"
    )]
    Login(LoginArgs),

    #[command(about = "Revoke the current CLI token and clear local credentials")]
    Logout,

    #[command(
        about = "Select where this repo stores investigations (local or a cloud project)"
    )]
    Context(ContextArgs),

    #[command(about = "Link this repo to a Horus Cloud project and inspect cloud state")]
    Cloud(CloudArgs),

    #[command(
        about = "Leave quick impact feedback on an investigation — defaults to the latest (helps improve Horus)"
    )]
    Feedback(FeedbackArgs),

    #[command(
        about = "File a Horus bug or capability gap — opens a pre-filled GitHub issue (no auth, no data sent)",
        after_help = "\nExamples:\n  horus report \"explain command crashes on monorepos\"\n  horus report --title \"Axiom connector ignores --service\" --labels bug,connectors"
    )]
    Report(ReportArgs),

    #[command(
        about = "Manage anonymous usage telemetry that helps improve Horus",
        after_help = "\nDefaults: usage metadata ON (with this notice), content sharing OFF.\nHard opt-out via env: HORUS_TELEMETRY=0 or DO_NOT_TRACK=1.\n\nExamples:\n  horus telemetry status\n  horus telemetry disable\n  horus telemetry enable-content"
    )]
    Telemetry(TelemetryArgs),
}

// ---------------------------------------------------------------------------------------------
// doctor / providers / init / readiness / db
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Args)]
pub struct DoctorArgs {
    /// path to a Horus config file for connector checks (default: nearest .horus/config.json)
    #[arg(short, long, value_name = "path")]
    pub config: Option<String>,
    /// output JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct ProvidersArgs {
    #[command(subcommand)]
    pub command: ProvidersCommand,
}

#[derive(Debug, Subcommand)]
pub enum ProvidersCommand {
    #[command(
        about = "Check which local AI providers (Codex, Claude, Gemini, etc.) are available"
    )]
    Doctor,
}

#[derive(Debug, Args)]
pub struct InitArgs {
    /// environment name (default: production)
    #[arg(long, value_name = "name")]
    pub env: Option<String>,
    /// external source-intelligence host URL — recorded verbatim, skips the local host/index
    #[arg(long, value_name = "url")]
    pub source: Option<String>,
    /// repository root (default: nearest git root, else cwd)
    #[arg(long, value_name = "dir")]
    pub path: Option<String>,
    #[arg(short, long, value_name = "path", help = CONFIG_TS_HELP)]
    pub config: Option<String>,
    /// build a full project-knowledge snapshot (default)
    #[arg(long)]
    pub full: bool,
    /// pre-push-safe: refresh PROJECT KNOWLEDGE for changed files only (does not reanalyze the source graph)
    #[arg(long)]
    pub changed: bool,
    /// accepted with --changed for compatibility (no additional effect)
    #[arg(long)]
    pub fast: bool,
    /// force a full source re-analysis: stop the host, wipe .horus/source, rebuild (purges stale graph edges)
    #[arg(long)]
    pub reindex: bool,
    /// import a knowledge-base JSON (e.g. an MCP knowledge-base export) as the knowledge source
    #[arg(long, value_name = "path")]
    pub import_kb: Option<String>,
}

#[derive(Debug, Args)]
pub struct ReadinessArgs {
    /// path to a Horus config file (default: nearest .horus/config.json)
    #[arg(short, long, value_name = "path")]
    pub config: Option<String>,
    /// append AI readiness summary and recommended next action
    #[arg(long)]
    pub ai: bool,
    #[arg(long, value_name = "model", help = AI_MODEL_HELP)]
    pub ai_model: Option<String>,
}

#[derive(Debug, Args)]
pub struct DbArgs {
    #[command(subcommand)]
    pub command: DbCommand,
}

#[derive(Debug, Subcommand)]
pub enum DbCommand {
    #[command(
        about = "One-time import of a legacy Postgres into the embedded database (--from defaults to $DATABASE_URL)"
    )]
    Import(DbImportArgs),
    #[command(
        name = "migrate-from-ts",
        about = "Copy history from the TypeScript Horus database (~/.horus/horus.db) into this one (needs node/npx)"
    )]
    MigrateFromTs(DbMigrateFromTsArgs),
}

#[derive(Debug, Args)]
pub struct DbMigrateFromTsArgs {
    /// data directory of the TypeScript Horus database (default: ~/.horus/horus.db, beside this CLI's database)
    #[arg(long, value_name = "dir")]
    pub from: Option<String>,
}

#[derive(Debug, Args)]
pub struct DbImportArgs {
    /// source Postgres URL (defaults to $DATABASE_URL)
    #[arg(long, value_name = "postgres-url")]
    pub from: Option<String>,
}

// ---------------------------------------------------------------------------------------------
// connect
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Args)]
pub struct ConnectArgs {
    #[arg(value_name = "type")]
    pub r#type: String,
    /// Google Cloud project ID (Logging or Firestore)
    #[arg(long, value_name = "id")]
    pub gcp_project: Option<String>,
    /// Prometheus queries: [{"title":"...","expr":"..."}]
    #[arg(long, value_name = "json")]
    pub queries: Option<String>,
    /// Azure Service Bus namespace ARM ID
    #[arg(long, value_name = "id")]
    pub namespace_id: Option<String>,
    /// Service Bus queue allowlist (comma-separated)
    #[arg(long, value_name = "names")]
    pub queues: Option<String>,
    /// Kafka host:port endpoints (comma-separated)
    #[arg(long, value_name = "addresses")]
    pub brokers: Option<String>,
    /// Kafka topic allowlist (comma-separated)
    #[arg(long, value_name = "names")]
    pub topics: Option<String>,
    /// Kafka consumer group allowlist (comma-separated)
    #[arg(long, value_name = "names")]
    pub groups: Option<String>,
    /// Disable Kafka TLS for a trusted local broker
    #[arg(long)]
    pub no_ssl: bool,
    /// Kafka SASL: plain, scram-sha-256, scram-sha-512
    #[arg(long, value_name = "type")]
    pub mechanism: Option<String>,
    /// Azure Log Analytics workspace GUID
    #[arg(long, value_name = "id")]
    pub workspace: Option<String>,
    /// Azure subscription ID
    #[arg(long, value_name = "id")]
    pub subscription: Option<String>,
    /// AWS region
    #[arg(long, value_name = "region")]
    pub region: Option<String>,
    /// CloudWatch log group
    #[arg(long, value_name = "name")]
    pub log_group: Option<String>,
    /// Local AWS profile
    #[arg(long, value_name = "name")]
    pub profile: Option<String>,
    /// Google Cloud Logging base filter
    #[arg(long, value_name = "filter")]
    pub filter: Option<String>,
    /// Vendor CLI executable (absolute path for background service)
    #[arg(long, value_name = "path")]
    pub executable: Option<String>,
    /// target environment (default: first environment in config)
    #[arg(long, value_name = "name")]
    pub env: Option<String>,
    /// AI provider for `connect ai` (anthropic / claude / codex / gemini / kimi / cursor)
    #[arg(long, value_name = "name")]
    pub provider: Option<String>,
    /// Anthropic API key for `connect ai`
    #[arg(long, value_name = "key")]
    pub api_key: Option<String>,
    /// default model for `connect ai`
    #[arg(long, value_name = "id")]
    pub model: Option<String>,
    /// connector URL or connection string (Redis with auth: redis://:password@host:6379)
    #[arg(long, value_name = "url")]
    pub url: Option<String>,
    /// username (elasticsearch / grafana)
    #[arg(long, value_name = "user")]
    pub username: Option<String>,
    /// password (elasticsearch / grafana; for Redis embed in --url)
    #[arg(long, value_name = "pass")]
    pub password: Option<String>,
    /// Elasticsearch index pattern (required for elasticsearch)
    #[arg(long, value_name = "pattern")]
    pub index_pattern: Option<String>,
    /// service name scope for log queries
    #[arg(long, value_name = "name")]
    pub service: Option<String>,
    /// database name (required for mongodb)
    #[arg(long, value_name = "name")]
    pub database: Option<String>,
    /// comma-separated collection allowlist (mongodb)
    #[arg(long, value_name = "list")]
    pub collections: Option<String>,
    /// schema to introspect (postgres; default public)
    #[arg(long, value_name = "name")]
    pub schema: Option<String>,
    /// comma-separated table allowlist (postgres)
    #[arg(long, value_name = "list")]
    pub tables: Option<String>,
    /// Sentry API auth token (required for sentry)
    #[arg(long, value_name = "token")]
    pub auth_token: Option<String>,
    /// Sentry org slug (required for sentry)
    #[arg(long, value_name = "slug")]
    pub org: Option<String>,
    /// Sentry project slug — provider domain data (required for sentry)
    #[arg(long, value_name = "slug")]
    pub sentry_project: Option<String>,
    /// Axiom API token (required for axiom)
    #[arg(long, value_name = "token")]
    pub token: Option<String>,
    /// Axiom dataset to query (required for axiom)
    #[arg(long, value_name = "name")]
    pub dataset: Option<String>,
    /// Shopify store subdomain, e.g. my-store — .myshopify.com is added automatically (required for shopify)
    #[arg(long, value_name = "name")]
    pub store: Option<String>,
    /// Shopify Admin API version, e.g. 2025-10 (shopify; defaults to a recent version)
    #[arg(long, value_name = "ver")]
    pub api_version: Option<String>,
    /// Shopify app client_id — omit for a static Admin API token (shopify)
    #[arg(long, value_name = "id")]
    pub access_id: Option<String>,
    /// Shopify client_secret, or a static Admin API access token — encrypted at rest (required for shopify)
    #[arg(long, value_name = "secret")]
    pub secret: Option<String>,
    /// default dashboard uid (grafana)
    #[arg(long, value_name = "uid")]
    pub dashboard: Option<String>,
    /// redis logical DB as db:role1,role2 (e.g. 0:cache,state or 1:bullmq,queues); repeatable
    #[arg(long, value_name = "spec", action = ArgAction::Append)]
    pub db: Vec<String>,
    /// BullMQ key prefix for redis queue DBs (default: bull)
    #[arg(long, value_name = "prefix")]
    pub bullmq_prefix: Option<String>,
    /// skip interactive Redis DB scan
    #[arg(long)]
    pub no_scan_dbs: bool,
    /// skip live connection probe
    #[arg(long)]
    pub no_test: bool,
}

// ---------------------------------------------------------------------------------------------
// notify / secrets / stop / hosts / status / explain
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Args)]
pub struct NotifyArgs {
    #[command(subcommand)]
    pub command: NotifyCommand,
}

#[derive(Debug, Subcommand)]
pub enum NotifyCommand {
    #[command(about = "Set the webhook URL (and optional signing secret) for an environment")]
    Set(NotifySetArgs),
    #[command(about = "Show the configured notify sink (secret masked)")]
    Show(NotifyShowArgs),
    #[command(about = "Send a sample signed dispatch to the configured webhook to verify it")]
    Test(NotifyTestArgs),
    #[command(about = "Remove the notify sink from an environment")]
    Remove(NotifyRemoveArgs),
}

#[derive(Debug, Args)]
pub struct NotifySetArgs {
    /// path to a .horus/config.json file (default: nearest one)
    #[arg(short, long, value_name = "path")]
    pub config: Option<String>,
    /// environment to configure (default: first)
    #[arg(long, value_name = "name")]
    pub env: Option<String>,
    /// webhook URL to POST confident auto-investigations to
    #[arg(long, value_name = "url")]
    pub url: Option<String>,
    /// HMAC signing secret (stored encrypted, never plaintext)
    #[arg(long, value_name = "secret")]
    pub secret: Option<String>,
    /// only dispatch at/above this confidence (0..1, default 0.6)
    #[arg(long, value_name = "n")]
    pub min_confidence: Option<String>,
    /// also push headlines to Horus Cloud
    #[arg(long, overrides_with = "no_cloud")]
    pub cloud: bool,
    /// disable the Horus Cloud push
    #[arg(long)]
    pub no_cloud: bool,
}

#[derive(Debug, Args)]
pub struct NotifyShowArgs {
    /// path to a .horus/config.json file (default: nearest one)
    #[arg(short, long, value_name = "path")]
    pub config: Option<String>,
    /// environment to show (default: first)
    #[arg(long, value_name = "name")]
    pub env: Option<String>,
}

#[derive(Debug, Args)]
pub struct NotifyTestArgs {
    /// path to a Horus config file (default: nearest .horus/config.json)
    #[arg(short, long, value_name = "path")]
    pub config: Option<String>,
    /// environment to test (default: first)
    #[arg(long, value_name = "name")]
    pub env: Option<String>,
}

#[derive(Debug, Args)]
pub struct NotifyRemoveArgs {
    /// path to a .horus/config.json file (default: nearest one)
    #[arg(short, long, value_name = "path")]
    pub config: Option<String>,
    /// environment to clear (default: first)
    #[arg(long, value_name = "name")]
    pub env: Option<String>,
}

#[derive(Debug, Args)]
pub struct SecretsArgs {
    #[command(subcommand)]
    pub command: SecretsCommand,
}

#[derive(Debug, Subcommand)]
pub enum SecretsCommand {
    #[command(
        about = "Show the master key source, stored secrets, plaintext in config, and gitignore state"
    )]
    Status,
    #[command(
        about = "Move plaintext connector secrets out of config.json into the encrypted store"
    )]
    Migrate(SecretsMigrateArgs),
    #[command(
        about = "Show the master key source; --show prints it (base64) for CI (HORUS_SECRET_KEY)"
    )]
    Key(SecretsKeyArgs),
}

#[derive(Debug, Args)]
pub struct SecretsMigrateArgs {
    /// list what would be migrated without changing anything
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Debug, Args)]
pub struct SecretsKeyArgs {
    /// print the master key (treat as a credential)
    #[arg(long)]
    pub show: bool,
}

#[derive(Debug, Args)]
pub struct StopArgs {
    /// stop all registered source-intelligence hosts
    #[arg(long)]
    pub all: bool,
}

#[derive(Debug, Args)]
pub struct HostsArgs {
    /// stop orphaned source hosts that no registered repo owns
    #[arg(long)]
    pub reap: bool,
}

#[derive(Debug, Args)]
pub struct StatusArgs {
    #[arg(short, long, value_name = "path", help = CONFIG_TS_HELP)]
    pub config: Option<String>,
    /// show only this environment (default: all environments)
    #[arg(long, value_name = "name")]
    pub env: Option<String>,
    /// output JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct ExplainArgs {
    #[arg(value_name = "query")]
    pub query: String,
    #[arg(short, long, value_name = "path", help = CONFIG_TS_HELP)]
    pub config: Option<String>,
    /// impact depth
    #[arg(short, long, value_name = "n")]
    pub depth: Option<u32>,
    #[arg(long, value_name = "name", help = REPO_HELP)]
    pub repo: Option<String>,
    /// output JSON
    #[arg(long)]
    pub json: bool,
    /// full JSON: uncapped lists + snippets, and include test callers (default: compact, product-only)
    #[arg(long)]
    pub full: bool,
}

// ---------------------------------------------------------------------------------------------
// knowledge
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Args)]
pub struct KnowledgeArgs {
    #[command(subcommand)]
    pub command: KnowledgeCommand,
}

#[derive(Debug, Subcommand)]
pub enum KnowledgeCommand {
    #[command(
        about = "Show last indexed commit, schema version, item counts, and stale/dirty status"
    )]
    Status(KnowledgeStatusArgs),
    #[command(
        about = "Keyword search across indexed operations, types, concepts, and patterns"
    )]
    Search {
        #[arg(value_name = "query")]
        query: String,
    },
    #[command(
        about = "Show operations/types/enums/auth rules verbatim (no hallucinated values)"
    )]
    Contracts {
        #[arg(value_name = "name")]
        name: String,
    },
    #[command(about = "Walk known concept ↔ operation ↔ type / data-flow links")]
    Trace {
        #[arg(value_name = "query")]
        query: String,
    },
    #[command(about = "Grounded answer from the local index, with provenance (offline)")]
    Ask {
        #[arg(value_name = "question")]
        question: String,
    },
    #[command(
        about = "Validate the index (schema + content hash + staleness) — pre-push friendly"
    )]
    Validate,
    #[command(
        about = "Upload the local knowledge snapshot to the linked cloud project (optional; content-hash deduped)"
    )]
    Push(KnowledgePushArgs),
    #[command(about = "Download the latest knowledge snapshot from the linked cloud project")]
    Pull(KnowledgePullArgs),
}

#[derive(Debug, Args)]
pub struct KnowledgeStatusArgs {
    /// also compare the local index with the linked cloud snapshot
    #[arg(long)]
    pub cloud: bool,
}

#[derive(Debug, Args)]
pub struct KnowledgePushArgs {
    /// preview what would be uploaded without sending
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Debug, Args)]
pub struct KnowledgePullArgs {
    /// overwrite local knowledge that differs from the cloud snapshot
    #[arg(long)]
    pub force: bool,
}

// ---------------------------------------------------------------------------------------------
// memory
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Args)]
pub struct MemoryArgs {
    #[command(subcommand)]
    pub command: MemoryCommand,
}

#[derive(Debug, Subcommand)]
pub enum MemoryCommand {
    #[command(
        about = "Synthesize owned areas, runtime paths, past investigations and weak spots for a scope"
    )]
    Show(MemoryShowArgs),
    #[command(about = "Add an authored memory claim (human source) for the repo")]
    Add(MemoryAddArgs),
    #[command(
        about = "Record a confirmed-outcome memory item from an investigation (private, PII-gated)"
    )]
    Confirm(MemoryConfirmArgs),
    #[command(
        about = "Soft-delete a memory item (retained + audited, excluded from recall, reversible)"
    )]
    Forget(MemoryIdNoteArgs),
    #[command(
        about = "Pin a memory item so it floats to the top of recall (never auto-hidden)"
    )]
    Pin(MemoryIdNoteArgs),
    #[command(about = "List persisted authored memory items for the repo")]
    List(MemoryListArgs),
    // Memory→memory link graph (FROZEN day-0 rels). NB: these are `memory link/unlink`
    // SUBcommands — distinct from the unrelated top-level `cloud link`.
    #[command(
        about = "Author a memory→memory edge (supersedes|contradicts|recurs-with) between two items"
    )]
    Link(MemoryEdgeArgs),
    #[command(
        about = "Remove a memory→memory edge (inverse of `memory link`); a missing edge is a no-op"
    )]
    Unlink(MemoryEdgeArgs),
    #[command(
        about = "Auto-detect memory→memory edges (recurrence/contradiction); --dry-run previews only"
    )]
    Detect(MemoryDetectArgs),
    #[command(
        about = "Report Horus's measured hit-rate from the converged outcome-label eval set"
    )]
    Accuracy(MemoryAccuracyArgs),
    #[command(about = "Inspect and recover automatic durable memory push/pull")]
    Sync(MemorySyncArgs),
    #[command(
        about = "Promote a local memory item into the shared team memory (one-way; refuses confirmed-outcome)"
    )]
    Promote(MemoryPromoteArgs),
    #[command(
        about = "Refresh the local cache of shared team memory (full pull; offline serves stale cache)"
    )]
    Pull(MemoryPullArgs),
}

#[derive(Debug, Args)]
pub struct MemoryShowArgs {
    #[arg(value_name = "scope")]
    pub scope: String,
    #[arg(short, long, value_name = "path", help = CONFIG_TS_HELP)]
    pub config: Option<String>,
    #[arg(long, value_name = "name", help = REPO_HELP)]
    pub repo: Option<String>,
    /// output JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct MemoryAddArgs {
    #[arg(value_name = "claim")]
    pub claim: String,
    #[arg(short, long, value_name = "path", help = CONFIG_TS_HELP)]
    pub config: Option<String>,
    #[arg(long, value_name = "name", help = REPO_HELP)]
    pub repo: Option<String>,
    /// applicability scope: global|repo|module:<area>|symbol:<node_id>
    #[arg(long, value_name = "scope", default_value = "repo")]
    pub scope: String,
    /// code-fact|contract|decision|pitfall|incident-pattern (default code-fact, or incident-pattern with --outcome-file)
    #[arg(long, value_name = "kind")]
    pub kind: Option<String>,
    /// evidence reference (repeatable); "kind:ref" or bare "ref"
    #[arg(long, value_name = "kind:ref", action = ArgAction::Append)]
    pub evidence: Vec<String>,
    /// confidence in the claim (default 0.75)
    #[arg(long, value_name = "0..1")]
    pub confidence: Option<String>,
    /// inferred incident disposition JSON with investigation and evidence provenance (private)
    #[arg(long, value_name = "path")]
    pub outcome_file: Option<String>,
    /// output JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct MemoryConfirmArgs {
    #[arg(value_name = "investigationId")]
    pub investigation_id: String,
    #[arg(short, long, value_name = "path", help = CONFIG_TS_HELP)]
    pub config: Option<String>,
    #[arg(long, value_name = "name", help = REPO_HELP)]
    pub repo: Option<String>,
    /// explicit incident disposition JSON with attester and evidence provenance
    #[arg(long, value_name = "path")]
    pub outcome_file: Option<String>,
    /// note recorded in the audit trail
    #[arg(long, value_name = "note")]
    pub note: Option<String>,
    /// output JSON
    #[arg(long)]
    pub json: bool,
}

/// `memory forget <id>` and `memory pin <id>`.
#[derive(Debug, Args)]
pub struct MemoryIdNoteArgs {
    #[arg(value_name = "id")]
    pub id: String,
    #[arg(short, long, value_name = "path", help = CONFIG_TS_HELP)]
    pub config: Option<String>,
    /// note recorded in the audit trail
    #[arg(long, value_name = "note")]
    pub note: Option<String>,
    /// output JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct MemoryListArgs {
    #[arg(short, long, value_name = "path", help = CONFIG_TS_HELP)]
    pub config: Option<String>,
    #[arg(long, value_name = "name", help = REPO_HELP)]
    pub repo: Option<String>,
    /// include forgotten/deprecated/contradicted items
    #[arg(long)]
    pub all: bool,
    /// output JSON
    #[arg(long)]
    pub json: bool,
}

/// `memory link <a> <b>` and `memory unlink <a> <b>`.
#[derive(Debug, Args)]
pub struct MemoryEdgeArgs {
    #[arg(value_name = "a")]
    pub a: String,
    #[arg(value_name = "b")]
    pub b: String,
    /// relation: supersedes | contradicts | recurs-with
    #[arg(long, value_name = "rel", required = true)]
    pub rel: String,
    #[arg(short, long, value_name = "path", help = CONFIG_TS_HELP)]
    pub config: Option<String>,
    #[arg(long, value_name = "name", help = REPO_HELP)]
    pub repo: Option<String>,
    /// note recorded in the audit trail
    #[arg(long, value_name = "note")]
    pub note: Option<String>,
    /// output JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct MemoryDetectArgs {
    #[arg(short, long, value_name = "path", help = CONFIG_TS_HELP)]
    pub config: Option<String>,
    #[arg(long, value_name = "name", help = REPO_HELP)]
    pub repo: Option<String>,
    /// print proposed edges for confirmation without writing
    #[arg(long)]
    pub dry_run: bool,
    /// max items to scan
    #[arg(long, value_name = "n")]
    pub limit: Option<u32>,
    /// output JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct MemoryAccuracyArgs {
    #[arg(short, long, value_name = "path", help = CONFIG_TS_HELP)]
    pub config: Option<String>,
    #[arg(long, value_name = "name", help = REPO_HELP)]
    pub repo: Option<String>,
    /// filter to one signal source: feedback | confirm
    #[arg(long, value_name = "source")]
    pub source: Option<String>,
    /// only count labels on/after this date (e.g. 2026-06-01)
    #[arg(long, value_name = "date")]
    pub since: Option<String>,
    /// only count labels from the last N days
    #[arg(long, value_name = "n")]
    pub days: Option<u32>,
    /// count the full retained history (default window: last 30 days)
    #[arg(long)]
    pub all: bool,
    /// max labels to scan
    #[arg(long, value_name = "n")]
    pub limit: Option<u32>,
    /// output JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct MemorySyncArgs {
    #[arg(short, long, value_name = "path", help = CONFIG_TS_HELP)]
    pub config: Option<String>,
    #[arg(long, value_name = "name", help = REPO_HELP)]
    pub repo: Option<String>,
    /// resolve a visible synchronization conflict
    #[arg(long, value_name = "memoryId")]
    pub resolve: Option<String>,
    /// explicit correction to retain
    #[arg(long, value_name = "side", value_parser = ["local", "cloud"])]
    pub choice: Option<String>,
    /// deliberately restore a synchronized forgotten memory
    #[arg(long, value_name = "memoryId")]
    pub restore: Option<String>,
    /// max pending local items per pass
    #[arg(long, value_name = "n")]
    pub limit: Option<u32>,
    /// preview what would be synced without uploading
    #[arg(long)]
    pub dry_run: bool,
    /// accepted for compatibility; synchronization is automatic
    #[arg(long)]
    pub yes: bool,
    /// output JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct MemoryPromoteArgs {
    #[arg(value_name = "id")]
    pub id: String,
    #[arg(short, long, value_name = "path", help = CONFIG_TS_HELP)]
    pub config: Option<String>,
    #[arg(long, value_name = "name", help = REPO_HELP)]
    pub repo: Option<String>,
    /// output JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct MemoryPullArgs {
    #[arg(short, long, value_name = "path", help = CONFIG_TS_HELP)]
    pub config: Option<String>,
    #[arg(long, value_name = "name", help = REPO_HELP)]
    pub repo: Option<String>,
    /// force a full refresh even if the cache looks current
    #[arg(long)]
    pub force: bool,
    /// output JSON
    #[arg(long)]
    pub json: bool,
}

// ---------------------------------------------------------------------------------------------
// eval / train
// ---------------------------------------------------------------------------------------------

// `eval` — the read-only accuracy harness (HOR-403). READ-ONLY over the outcome-label eval
// store: it never writes labels (only `horus feedback` + `horus memory confirm` do). Shares the
// read flags (--source/--days/--limit/--repo) with `horus memory accuracy`.
#[derive(Debug, Args)]
pub struct EvalArgs {
    #[command(subcommand)]
    pub command: EvalCommand,
}

#[derive(Debug, Subcommand)]
pub enum EvalCommand {
    #[command(
        about = "Emit a byte-stable corpus-<version>.jsonl + manifest from the eval set (read-only)"
    )]
    Build(EvalBuildArgs),
    #[command(
        about = "Print the baseline hit-rate (same as `memory accuracy`) + a feature-separation diagnostic"
    )]
    Baseline(EvalBaselineArgs),
}

#[derive(Debug, Args)]
pub struct EvalBuildArgs {
    #[arg(short, long, value_name = "path", help = CONFIG_TS_HELP)]
    pub config: Option<String>,
    #[arg(long, value_name = "name", help = REPO_HELP)]
    pub repo: Option<String>,
    /// filter to one signal source: feedback | confirm
    #[arg(long, value_name = "source")]
    pub source: Option<String>,
    /// only include labels from the last N days
    #[arg(long, value_name = "n")]
    pub days: Option<u32>,
    /// max labels to scan
    #[arg(long, value_name = "n")]
    pub limit: Option<u32>,
    /// output directory for the corpus + manifest (default: ./.horus/eval)
    #[arg(long, value_name = "dir")]
    pub out: Option<String>,
    /// corpus schema version tag (default: v1)
    #[arg(long, value_name = "v")]
    pub version: Option<String>,
    /// output JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct EvalBaselineArgs {
    #[arg(short, long, value_name = "path", help = CONFIG_TS_HELP)]
    pub config: Option<String>,
    #[arg(long, value_name = "name", help = REPO_HELP)]
    pub repo: Option<String>,
    /// filter to one signal source: feedback | confirm
    #[arg(long, value_name = "source")]
    pub source: Option<String>,
    /// only count labels from the last N days
    #[arg(long, value_name = "n")]
    pub days: Option<u32>,
    /// max labels to scan
    #[arg(long, value_name = "n")]
    pub limit: Option<u32>,
    /// output JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct TrainArgs {
    #[arg(short, long, value_name = "path", help = CONFIG_TS_HELP)]
    pub config: Option<String>,
    /// filter to one signal source: feedback | confirm
    #[arg(long, value_name = "source")]
    pub source: Option<String>,
    /// only train on labels from the last N days
    #[arg(long, value_name = "n")]
    pub days: Option<u32>,
    /// max labels to scan
    #[arg(long, value_name = "n")]
    pub limit: Option<u32>,
}

// ---------------------------------------------------------------------------------------------
// queues / investigate / packet / watch / service
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Args)]
pub struct QueuesArgs {
    #[arg(value_name = "name")]
    pub name: Option<String>,
    #[arg(short, long, value_name = "path", help = CONFIG_TS_HELP)]
    pub config: Option<String>,
    /// fetch real-time queue depths and failed-job counts from Redis/BullMQ
    #[arg(long)]
    pub live: bool,
    /// output JSON
    #[arg(long)]
    pub json: bool,
    /// append AI narration of queue topology and live state (most useful with --live)
    #[arg(long)]
    pub ai: bool,
    #[arg(long, value_name = "model", help = AI_MODEL_HELP)]
    pub ai_model: Option<String>,
}

#[derive(Debug, Args)]
pub struct InvestigateArgs {
    #[arg(value_name = "hint")]
    pub hint: String,
    #[arg(short, long, value_name = "path", help = CONFIG_TS_HELP)]
    pub config: Option<String>,
    /// environment name (default: the only environment, else production)
    #[arg(long, value_name = "name")]
    pub env: Option<String>,
    #[arg(long, value_name = "name", help = REPO_HELP)]
    pub repo: Option<String>,
    /// resolve the seed only from symbols under this path (e.g. packages/core) — useful in monorepos
    #[arg(long, value_name = "path")]
    pub scope: Option<String>,
    /// git ref/range for change-impact (e.g. HEAD~5)
    #[arg(long, value_name = "ref")]
    pub since: Option<String>,
    /// runtime-log window as a duration (e.g. 30d, 24h); independent of --since
    #[arg(long, value_name = "dur")]
    pub logs_since: Option<String>,
    /// Shopify Admin GraphQL query to run as evidence: @file, - (stdin), or a raw string; repeatable
    #[arg(long, value_name = "q", action = ArgAction::Append)]
    pub shopify_query: Vec<String>,
    /// variables (@file or inline JSON object) applied to every --shopify-query
    #[arg(long, value_name = "json")]
    pub shopify_variables: Option<String>,
    /// overall investigation deadline in seconds (default 120)
    #[arg(long, value_name = "sec")]
    pub timeout: Option<String>,
    /// service name to scope runtime logs, e.g. checkout-api-prod
    #[arg(long, value_name = "name")]
    pub service: Option<String>,
    /// output JSON (alias for --format json)
    #[arg(long)]
    pub json: bool,
    /// output format: text | markdown | json
    #[arg(long, value_name = "fmt", default_value = "text")]
    pub format: String,
    /// include raw evidence payloads in JSON output (default: compact)
    #[arg(long)]
    pub full: bool,
    /// enrich report with AI narrative (needs an Anthropic key from `horus connect ai` or ANTHROPIC_API_KEY; skipped for JSON output; falls back to deterministic on failure)
    #[arg(long)]
    pub ai: bool,
    /// AI model for --ai (default: the model saved by `horus connect ai`, else claude-opus-4-8)
    #[arg(long, value_name = "model")]
    pub ai_model: Option<String>,
}

#[derive(Debug, Args)]
pub struct PacketArgs {
    #[arg(value_name = "hint|savedId")]
    pub hint_or_id: String,
    #[arg(short, long, value_name = "path", help = CONFIG_TS_HELP)]
    pub config: Option<String>,
    /// environment name (default: the only environment, else production)
    #[arg(long, value_name = "name")]
    pub env: Option<String>,
    /// resolve the seed only from symbols under this path (e.g. packages/core)
    #[arg(long, value_name = "path")]
    pub scope: Option<String>,
    /// service name to scope runtime logs, e.g. checkout-api-prod
    #[arg(long, value_name = "name")]
    pub service: Option<String>,
    /// git ref/range for the change window (e.g. HEAD~5)
    #[arg(long, value_name = "ref")]
    pub since: Option<String>,
    /// overall investigation deadline in seconds (default 120)
    #[arg(long, value_name = "sec")]
    pub timeout: Option<String>,
    /// presentation preset: claude | cursor | generic (tightens caps only)
    #[arg(long = "for", value_name = "agent")]
    pub r#for: Option<String>,
    /// emit the packet as JSON (clean for piping into agents)
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct WatchArgs {
    /// service settings JSON (default ~/.horus/service/settings.json)
    #[arg(long, value_name = "path")]
    pub settings: Option<String>,
    /// one detection/execution cycle
    #[arg(long)]
    pub once: bool,
}

#[derive(Debug, Args)]
pub struct ServiceArgs {
    #[arg(value_name = "action")]
    pub action: String,
    /// service settings JSON (default ~/.horus/service/settings.json)
    #[arg(long, value_name = "path")]
    pub settings: Option<String>,
    /// launchd profile label
    #[arg(long, value_name = "name", default_value = "default")]
    pub profile: String,
    /// job identity for retry/worker
    #[arg(long, value_name = "id")]
    pub job: Option<String>,
    /// session id for the internal activity hook (set by the service, not by users)
    #[arg(long, value_name = "id")]
    pub session: Option<String>,
    /// project root to pause/resume (default: cwd)
    #[arg(long, value_name = "dir")]
    pub path: Option<String>,
    /// environment to pause/resume
    #[arg(long, value_name = "name")]
    pub env: Option<String>,
    /// one foreground cycle
    #[arg(long)]
    pub once: bool,
    /// confirm destination was inspected before retrying an uncertain delivery
    #[arg(long)]
    pub delivery_checked: bool,
    /// skip the Claude CLI auth preflight on check/install (isolated test profiles only)
    #[arg(long)]
    pub skip_checks: bool,
}

// ---------------------------------------------------------------------------------------------
// changes / timeline / what-changed / architecture / blast-radius / trace / insights
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Args)]
pub struct ChangesArgs {
    #[arg(value_name = "base")]
    pub base: String,
    #[arg(value_name = "compare")]
    pub compare: Option<String>,
    #[arg(short, long, value_name = "path", help = CONFIG_TS_HELP)]
    pub config: Option<String>,
    /// output JSON (compact by default)
    #[arg(long)]
    pub json: bool,
    /// with --json: uncapped raw structure instead of the compact summary
    #[arg(long)]
    pub full: bool,
    /// append AI change-impact review
    #[arg(long)]
    pub ai: bool,
    #[arg(long, value_name = "model", help = AI_MODEL_HELP)]
    pub ai_model: Option<String>,
}

#[derive(Debug, Args)]
pub struct TimelineArgs {
    #[arg(value_name = "service")]
    pub service: Option<String>,
    #[arg(short, long, value_name = "path", help = CONFIG_TS_HELP)]
    pub config: Option<String>,
    #[arg(long, value_name = "name", help = REPO_HELP)]
    pub repo: Option<String>,
    /// git --since (default "7 days ago"; e.g. "30 days ago", a date)
    #[arg(long, value_name = "when")]
    pub since: Option<String>,
    /// git --until
    #[arg(long, value_name = "when")]
    pub until: Option<String>,
    /// include all history instead of the default recent window
    #[arg(long)]
    pub all: bool,
    /// output JSON (compact by default)
    #[arg(long)]
    pub json: bool,
    /// with --json: uncapped raw structure instead of the compact summary
    #[arg(long)]
    pub full: bool,
    /// append AI narrative interpretation of the timeline
    #[arg(long)]
    pub ai: bool,
    #[arg(long, value_name = "model", help = AI_MODEL_HELP)]
    pub ai_model: Option<String>,
}

#[derive(Debug, Args)]
pub struct WhatChangedArgs {
    #[arg(value_name = "service")]
    pub service: Option<String>,
    #[arg(short, long, value_name = "path", help = CONFIG_TS_HELP)]
    pub config: Option<String>,
    #[arg(long, value_name = "name", help = REPO_HELP)]
    pub repo: Option<String>,
    /// git --since date, or a git ref such as HEAD~10 (default "7 days ago")
    #[arg(long, value_name = "when")]
    pub since: Option<String>,
    /// git --until
    #[arg(long, value_name = "when")]
    pub until: Option<String>,
    /// output JSON (compact by default)
    #[arg(long)]
    pub json: bool,
    /// with --json: uncapped raw structure instead of the compact summary
    #[arg(long)]
    pub full: bool,
    /// append AI interpretation of the changes
    #[arg(long)]
    pub ai: bool,
    #[arg(long, value_name = "model", help = AI_MODEL_HELP)]
    pub ai_model: Option<String>,
    /// push the report to the linked Horus Cloud project
    #[arg(long)]
    pub push: bool,
}

#[derive(Debug, Args)]
pub struct ArchitectureArgs {
    #[arg(short, long, value_name = "path", help = CONFIG_TS_HELP)]
    pub config: Option<String>,
    /// output JSON
    #[arg(long)]
    pub json: bool,
    /// append AI system explanation grounded in discovered architecture
    #[arg(long)]
    pub ai: bool,
    #[arg(long, value_name = "model", help = AI_MODEL_HELP)]
    pub ai_model: Option<String>,
}

#[derive(Debug, Args)]
pub struct BlastRadiusArgs {
    #[arg(value_name = "query")]
    pub query: String,
    #[arg(short, long, value_name = "path", help = CONFIG_TS_HELP)]
    pub config: Option<String>,
    /// traversal depth
    #[arg(short, long, value_name = "n")]
    pub depth: Option<u32>,
    /// include test/docs/example callers in the traversal (product-only by default)
    #[arg(long)]
    pub include_tests: bool,
    /// output JSON
    #[arg(long)]
    pub json: bool,
    /// append AI severity and containment interpretation
    #[arg(long)]
    pub ai: bool,
    #[arg(long, value_name = "model", help = AI_MODEL_HELP)]
    pub ai_model: Option<String>,
}

#[derive(Debug, Args)]
pub struct TraceArgs {
    #[arg(value_name = "from")]
    pub from: String,
    #[arg(value_name = "to")]
    pub to: String,
    #[arg(short, long, value_name = "path", help = CONFIG_TS_HELP)]
    pub config: Option<String>,
    /// maximum hops (default 10, max 10)
    #[arg(short = 'd', long, value_name = "n")]
    pub max_depth: Option<u32>,
    /// comma-separated edge kinds to restrict the walk (e.g. calls,imports)
    #[arg(long, value_name = "list")]
    pub relations: Option<String>,
    /// output JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct InsightsArgs {
    #[arg(short, long, value_name = "path", help = CONFIG_TS_HELP)]
    pub config: Option<String>,
    /// how many top hubs to show (default 8)
    #[arg(long, value_name = "n")]
    pub hubs: Option<u32>,
    /// how many cross-community edges to show (default 8)
    #[arg(long, value_name = "n")]
    pub bridges: Option<u32>,
    /// output JSON
    #[arg(long)]
    pub json: bool,
}

// ---------------------------------------------------------------------------------------------
// repos / search / investigations / lens
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Args)]
pub struct ReposArgs {
    #[arg(short, long, value_name = "path", help = CONFIG_TS_HELP)]
    pub config: Option<String>,
}

#[derive(Debug, Args)]
pub struct SearchArgs {
    #[arg(value_name = "query")]
    pub query: String,
    #[arg(short, long, value_name = "path", help = CONFIG_TS_HELP)]
    pub config: Option<String>,
    /// results per repo
    #[arg(short = 'n', long, value_name = "n")]
    pub limit: Option<u32>,
    /// output JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct InvestigationsArgs {
    #[arg(short, long, value_name = "path", help = CONFIG_TS_HELP)]
    pub config: Option<String>,
    /// max rows
    #[arg(short = 'n', long, value_name = "n")]
    pub limit: Option<u32>,
    /// output JSON
    #[arg(long)]
    pub json: bool,
}

/// `horus lens` with no subcommand is `lens list` (Commander `isDefault: true`), so the list
/// flags are flattened onto the parent.
#[derive(Debug, Args)]
pub struct LensArgs {
    #[command(subcommand)]
    pub command: Option<LensCommand>,
    #[command(flatten)]
    pub list: LensListArgs,
}

#[derive(Debug, Subcommand)]
pub enum LensCommand {
    #[command(
        about = "List every client-reported Lens issue (newest first)",
        after_help = "\nExamples:\n  horus lens\n  horus lens --json\n  horus lens --status open -n 100\n  horus lens show rep_abc123\n"
    )]
    List(LensListArgs),
    #[command(
        about = "Show one client report in full — comment, route, error, and the code seed to fix"
    )]
    Show(LensShowArgs),
}

#[derive(Debug, Args)]
pub struct LensListArgs {
    /// filter by report status (default: submitted)
    #[arg(long, value_name = "status")]
    pub status: Option<String>,
    /// include every status (drop the default submitted filter)
    #[arg(long)]
    pub all: bool,
    /// max reports (1–200, default 50)
    #[arg(short = 'n', long, value_name = "n")]
    pub limit: Option<u32>,
    /// only reports created on/after this ISO date
    #[arg(long, value_name = "date")]
    pub since: Option<String>,
    /// restrict to a single Lens site id
    #[arg(long, value_name = "id")]
    pub site: Option<String>,
    /// output JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct LensShowArgs {
    #[arg(value_name = "reportId")]
    pub report_id: String,
    /// the report's Lens site id (skips the cross-site scan)
    #[arg(long, value_name = "id")]
    pub site: Option<String>,
    /// output JSON
    #[arg(long)]
    pub json: bool,
}

// ---------------------------------------------------------------------------------------------
// replay / postmortem / owner / score / ask / scores / onboard / simulate
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Args)]
pub struct ReplayArgs {
    #[arg(value_name = "id")]
    pub id: String,
    #[arg(short, long, value_name = "path", help = CONFIG_TS_HELP)]
    pub config: Option<String>,
    /// text | markdown | json
    #[arg(long, value_name = "fmt", default_value = "text")]
    pub format: String,
    /// enrich report with AI narrative (needs an Anthropic key from `horus connect ai` or ANTHROPIC_API_KEY; skipped for --format json; falls back to deterministic on failure)
    #[arg(long)]
    pub ai: bool,
    /// AI model for --ai (default: the model saved by `horus connect ai`, else claude-opus-4-8)
    #[arg(long, value_name = "model")]
    pub ai_model: Option<String>,
    /// re-run AI even if a stored judgment already exists
    #[arg(long)]
    pub refresh_ai: bool,
}

#[derive(Debug, Args)]
pub struct PostmortemArgs {
    #[arg(value_name = "id")]
    pub id: String,
    #[arg(short, long, value_name = "path", help = CONFIG_TS_HELP)]
    pub config: Option<String>,
    /// write Markdown to a file instead of printing to stdout
    #[arg(long, value_name = "path")]
    pub output: Option<String>,
    /// overwrite the output file if it already exists
    #[arg(long)]
    pub force: bool,
    /// append an AI-generated summary section (needs an Anthropic key from `horus connect ai` or ANTHROPIC_API_KEY; falls back gracefully)
    #[arg(long)]
    pub ai_summary: bool,
    /// AI model for --ai-summary (default: the model saved by `horus connect ai`, else claude-opus-4-8)
    #[arg(long, value_name = "model")]
    pub ai_model: Option<String>,
    /// re-run AI even if a stored judgment already exists
    #[arg(long)]
    pub refresh_ai: bool,
}

#[derive(Debug, Args)]
pub struct OwnerArgs {
    #[arg(value_name = "query")]
    pub query: String,
    #[arg(short, long, value_name = "path", help = CONFIG_TS_HELP)]
    pub config: Option<String>,
    #[arg(long, value_name = "name", help = REPO_HELP)]
    pub repo: Option<String>,
    /// output JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct ScoreArgs {
    #[arg(value_name = "id")]
    pub id: String,
    #[arg(short, long, value_name = "path", help = CONFIG_TS_HELP)]
    pub config: Option<String>,
    /// output JSON
    #[arg(long)]
    pub json: bool,
    /// append AI score explanation and improvement suggestions
    #[arg(long)]
    pub ai: bool,
    #[arg(long, value_name = "model", help = AI_MODEL_HELP)]
    pub ai_model: Option<String>,
}

#[derive(Debug, Args)]
pub struct AskArgs {
    #[arg(value_name = "id")]
    pub id: String,
    #[arg(value_name = "directive")]
    pub directive: String,
    #[arg(short, long, value_name = "path", help = CONFIG_TS_HELP)]
    pub config: Option<String>,
    /// output JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct ScoresArgs {
    #[arg(short, long, value_name = "path", help = CONFIG_TS_HELP)]
    pub config: Option<String>,
    /// max rows
    #[arg(short = 'n', long, value_name = "n")]
    pub limit: Option<u32>,
    /// output JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct OnboardArgs {
    #[arg(value_name = "area")]
    pub area: Option<String>,
    #[arg(short, long, value_name = "path", help = CONFIG_TS_HELP)]
    pub config: Option<String>,
    #[arg(long, value_name = "name", help = REPO_HELP)]
    pub repo: Option<String>,
    /// output JSON
    #[arg(long)]
    pub json: bool,
    /// append AI onboarding guide grounded in discovered system evidence
    #[arg(long)]
    pub ai: bool,
    #[arg(long, value_name = "model", help = AI_MODEL_HELP)]
    pub ai_model: Option<String>,
}

#[derive(Debug, Args)]
pub struct SimulateArgs {
    #[arg(value_name = "scenario")]
    pub scenario: Option<String>,
    #[arg(short, long, value_name = "path", help = CONFIG_TS_HELP)]
    pub config: Option<String>,
    #[arg(long, value_name = "name", help = REPO_HELP)]
    pub repo: Option<String>,
}

// ---------------------------------------------------------------------------------------------
// logs / state / metrics
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Args)]
pub struct LogsArgs {
    #[arg(value_name = "service")]
    pub service: Option<String>,
    #[arg(short, long, value_name = "path", help = CONFIG_TS_HELP)]
    pub config: Option<String>,
    /// environment name (default: the only environment, else production)
    #[arg(long, value_name = "name")]
    pub env: Option<String>,
    /// time window, e.g. 24h, 7d, or an ISO date (default 7d)
    #[arg(long, value_name = "when")]
    pub since: Option<String>,
    /// minimum level (with --raw): trace|debug|info|warn|error|fatal
    #[arg(long, value_name = "level")]
    pub level: Option<String>,
    /// match text in the message
    #[arg(long, value_name = "text")]
    pub grep: Option<String>,
    /// dump individual log lines instead of synthesized evidence (error+ by default)
    #[arg(long)]
    pub raw: bool,
    /// with --raw: show all severity levels, not just error+
    #[arg(long)]
    pub all_levels: bool,
    /// aggregate error counts by a context field, e.g. context.brand_id
    #[arg(long, value_name = "field")]
    pub group_by: Option<String>,
    /// filter by a structured context field (repeatable, AND-combined), e.g. --where context.brand_id=42
    #[arg(long = "where", value_name = "field=value", action = ArgAction::Append)]
    pub r#where: Vec<String>,
    /// max records (with --raw)
    #[arg(long, value_name = "n")]
    pub limit: Option<String>,
    /// output JSON
    #[arg(long)]
    pub json: bool,
    /// append AI narration of error signatures (default mode only, not --raw or --json)
    #[arg(long)]
    pub ai: bool,
    #[arg(long, value_name = "model", help = AI_MODEL_HELP)]
    pub ai_model: Option<String>,
}

#[derive(Debug, Args)]
pub struct StateArgs {
    #[arg(short, long, value_name = "path", help = CONFIG_TS_HELP)]
    pub config: Option<String>,
    /// environment name (default: the only environment, else production)
    #[arg(long, value_name = "name")]
    pub env: Option<String>,
    /// staleness threshold in hours (default 24)
    #[arg(long, value_name = "n")]
    pub stale_hours: Option<String>,
    /// output JSON
    #[arg(long)]
    pub json: bool,
    /// append AI narration of MongoDB state evidence
    #[arg(long)]
    pub ai: bool,
    #[arg(long, value_name = "model", help = AI_MODEL_HELP)]
    pub ai_model: Option<String>,
}

#[derive(Debug, Args)]
pub struct MetricsArgs {
    #[arg(value_name = "hint")]
    pub hint: Option<String>,
    #[arg(short, long, value_name = "path", help = CONFIG_TS_HELP)]
    pub config: Option<String>,
    /// window, e.g. 1h, 6h, 24h (default 1h)
    #[arg(long, value_name = "when")]
    pub since: Option<String>,
    /// range step seconds
    #[arg(long, value_name = "secs")]
    pub step: Option<String>,
    /// restrict to a dashboard uid
    #[arg(long, value_name = "uid")]
    pub dashboard: Option<String>,
    /// raw datasource query escape hatch
    #[arg(long, value_name = "promql")]
    pub query: Option<String>,
    /// output JSON
    #[arg(long)]
    pub json: bool,
    /// append AI narration of metric findings (default mode only, not --query or --json)
    #[arg(long)]
    pub ai: bool,
    #[arg(long, value_name = "model", help = AI_MODEL_HELP)]
    pub ai_model: Option<String>,
}

// ---------------------------------------------------------------------------------------------
// skill / update / login / context / cloud
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Args)]
pub struct SkillArgs {
    #[command(subcommand)]
    pub command: SkillCommand,
}

#[derive(Debug, Subcommand)]
pub enum SkillCommand {
    #[command(
        about = "Install the Horus skill for a coding agent (claude | codex | gemini | cursor | generic)",
        after_help = "\nTargets:\n  claude   → .claude/skills/horus/SKILL.md  (Claude Code skill)\n  codex    → AGENTS.md                     (Codex CLI project instructions)\n  gemini   → GEMINI.md                     (Gemini CLI project context)\n  cursor   → .cursor/rules/horus.mdc        (Cursor project rule)\n  generic  → .horus/skills/horus-generic.md (plain Markdown)\n\nExamples:\n  horus skill install claude\n  horus skill install generic --force\n  horus skill install claude --global\n"
    )]
    Install(SkillInstallArgs),
    #[command(
        about = "Print the Horus skill to stdout — copy it into any agent setup",
        after_help = "\nExamples:\n  horus skill print generic\n  horus skill print claude\n"
    )]
    Print {
        #[arg(value_name = "target")]
        target: String,
    },
    #[command(
        about = "Print the install path for the given target",
        after_help = "\nExamples:\n  horus skill path claude\n  horus skill path generic --global\n"
    )]
    Path(SkillPathArgs),
}

#[derive(Debug, Args)]
pub struct SkillInstallArgs {
    #[arg(value_name = "target")]
    pub target: String,
    /// overwrite an existing skill file
    #[arg(long)]
    pub force: bool,
    /// install into the home directory instead of the current repo
    #[arg(long)]
    pub global: bool,
}

#[derive(Debug, Args)]
pub struct SkillPathArgs {
    #[arg(value_name = "target")]
    pub target: String,
    /// show the global (home directory) path
    #[arg(long)]
    pub global: bool,
}

#[derive(Debug, Args)]
pub struct UpdateArgs {
    /// check for a newer version without downloading
    #[arg(long)]
    pub check: bool,
    /// re-download even if already on the latest version
    #[arg(long)]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct LoginArgs {
    /// CLI token (or set HORUS_TOKEN); otherwise prompts when interactive
    #[arg(long, value_name = "token")]
    pub token: Option<String>,
    /// Horus Cloud API base URL (or set HORUS_CLOUD_API_URL)
    #[arg(long, value_name = "url")]
    pub api_url: Option<String>,
}

#[derive(Debug, Args)]
pub struct ContextArgs {
    #[command(subcommand)]
    pub command: ContextCommand,
}

#[derive(Debug, Subcommand)]
pub enum ContextCommand {
    #[command(about = "List the local context and the cloud contexts you can use")]
    List,
    #[command(
        about = "Switch context: \"local\" or \"<org>/<workspace>/<project>\". With no target, pick from a list of your accessible contexts."
    )]
    Use {
        #[arg(value_name = "target")]
        target: Option<String>,
    },
    #[command(about = "Show the active context and the selected project's sync metadata")]
    Show,
}

#[derive(Debug, Args)]
pub struct CloudArgs {
    #[command(subcommand)]
    pub command: CloudCommand,
}

#[derive(Debug, Subcommand)]
pub enum CloudCommand {
    #[command(
        about = "Link the current repo to a cloud project (Git-aware); pass <org/workspace/project> to skip the interactive picker",
        after_help = "\nExamples:\n  horus cloud link                                # interactive / git-remote auto-match\n  horus cloud link my-org/main/checkout-api       # non-interactive target\n"
    )]
    Link(CloudLinkArgs),
    #[command(about = "Remove this repo's cloud link (returns to local mode)")]
    Unlink,
    #[command(
        about = "Show the active context, linked project, sync metadata, and auth state"
    )]
    Status,
    #[command(
        about = "Upload existing local investigations to the linked cloud project",
        after_help = "\nExamples:\n  horus cloud sync --dry-run     # preview what would upload\n  horus cloud sync               # confirm, then upload\n  horus cloud sync --yes         # upload without prompting"
    )]
    Sync(CloudSyncArgs),
}

#[derive(Debug, Args)]
pub struct CloudLinkArgs {
    #[arg(value_name = "target")]
    pub target: Option<String>,
    /// skip confirmation prompts
    #[arg(short = 'y', long)]
    pub yes: bool,
}

#[derive(Debug, Args)]
pub struct CloudSyncArgs {
    /// path to a Horus config file (selects which project's investigations to upload)
    #[arg(short, long, value_name = "path")]
    pub config: Option<String>,
    /// max local investigations to consider
    #[arg(long, value_name = "n")]
    pub limit: Option<u32>,
    /// show what would be uploaded without uploading
    #[arg(long)]
    pub dry_run: bool,
    /// skip the confirmation prompt
    #[arg(short = 'y', long)]
    pub yes: bool,
}

// ---------------------------------------------------------------------------------------------
// feedback / report / telemetry
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Args)]
pub struct FeedbackArgs {
    #[arg(value_name = "investigationId")]
    pub investigation_id: Option<String>,
    /// did Horus point at the cause? yes | partly | no — non-interactive, for agents/scripts
    #[arg(long, value_name = "verdict")]
    pub resolved: Option<String>,
    /// estimated minutes this would have taken manually (optional, pair with --resolved)
    #[arg(long, value_name = "minutes")]
    pub manual_estimate_min: Option<String>,
    /// the human-confirmed root cause, recorded onto the outcome label (pair with --resolved)
    #[arg(long, value_name = "text")]
    pub cause: Option<String>,
    /// free-text context recorded onto the outcome label (pair with --resolved)
    #[arg(long, value_name = "text")]
    pub note: Option<String>,
    #[arg(short, long, value_name = "path", help = CONFIG_TS_HELP)]
    pub config: Option<String>,
    #[arg(long, value_name = "name", help = REPO_HELP)]
    pub repo: Option<String>,
}

#[derive(Debug, Args)]
pub struct ReportArgs {
    #[arg(value_name = "hint")]
    pub hint: Option<String>,
    /// issue title (default: derived from the hint)
    #[arg(long, value_name = "text")]
    pub title: Option<String>,
    /// issue body / description
    #[arg(long, value_name = "text")]
    pub body: Option<String>,
    /// comma-separated GitHub labels (e.g. bug,cli)
    #[arg(long, value_name = "list")]
    pub labels: Option<String>,
    #[arg(short, long, value_name = "path", help = "accepted for compatibility; not used by this command")]
    pub config: Option<String>,
}

#[derive(Debug, Args)]
pub struct TelemetryArgs {
    #[command(subcommand)]
    pub command: TelemetryCommand,
}

#[derive(Debug, Subcommand)]
pub enum TelemetryCommand {
    #[command(
        about = "Show the effective telemetry decision, saved preferences, and install ID"
    )]
    Status,
    #[command(about = "Turn on anonymous usage metadata (Tier A)")]
    Enable,
    #[command(about = "Turn off all telemetry (Tier A and Tier B)")]
    Disable,
    #[command(
        name = "enable-content",
        about = "Opt in to sharing redacted investigation inputs/outputs (Tier B)"
    )]
    EnableContent,
    #[command(
        name = "disable-content",
        about = "Stop sharing inputs/outputs; keep usage metadata (Tier B off)"
    )]
    DisableContent,
    #[command(name = "reset-id", about = "Generate a new random install ID")]
    ResetId,
    #[command(about = "Delete local telemetry state (install ID + saved preferences)")]
    Delete,
}
