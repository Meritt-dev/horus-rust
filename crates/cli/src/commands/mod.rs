//! One module per TS file in `packages/cli/src/commands/`, plus the dispatcher that maps every
//! clap command to its `run`. Later agents replace a module's `bail!` body with the real port.

pub mod architecture;
pub mod ask;
pub mod blast_radius;
pub mod changes;
pub mod cloud;
pub mod connect;
pub mod connect_ai;
pub mod context;
pub mod db;
pub mod doctor;
pub mod eval;
pub mod explain;
pub mod feedback;
pub mod hosts;
pub mod init;
pub mod init_index;
pub mod init_prereqs;
pub mod insights;
pub mod investigate;
pub mod investigations;
pub mod knowledge;
pub mod knowledge_cloud;
pub mod lens;
pub mod login;
pub mod logs;
pub mod memory;
pub mod metrics;
pub mod notify;
pub mod onboard;
pub mod owner;
pub mod packet;
pub mod postmortem;
pub mod projects;
pub mod providers_doctor;
pub mod queues;
pub mod readiness;
pub mod replay;
pub mod report_issue;
pub mod repos;
pub mod score;
pub mod search;
pub mod secrets;
pub mod service;
pub mod simulate;
pub mod skill;
pub mod state;
pub mod status;
pub mod stop;
pub mod telemetry;
pub mod timeline;
pub mod trace;
pub mod train;
pub mod update;
pub mod watch;
pub mod what_changed;
pub mod mcp;

use anyhow::Result;

use crate::cli::{Cli, Command, KnowledgeCommand};

/// Non-zero exit without a message: the command already printed its own diagnostics
/// (the TS commands `return 1` after `console.error`). `main` maps it to the exit code.
#[derive(Debug)]
pub struct SilentExit(pub u8);

impl std::fmt::Display for SilentExit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "exit {}", self.0)
    }
}

impl std::error::Error for SilentExit {}

pub async fn dispatch(cli: &Cli) -> Result<()> {
    match &cli.command {
        Command::Doctor(a) => doctor::run(a).await,
        Command::Providers(a) => providers_doctor::run(a).await,
        Command::Init(a) => init::run(a).await,
        Command::Projects => projects::run().await,
        Command::Readiness(a) => readiness::run(a).await,
        Command::Db(a) => db::run(a).await,
        Command::Connect(a) => connect::run(a).await,
        Command::Notify(a) => notify::run(a).await,
        Command::Secrets(a) => secrets::run(a).await,
        Command::Stop(a) => stop::run(a).await,
        Command::Hosts(a) => hosts::run(a).await,
        Command::Status(a) => status::run(a).await,
        Command::Explain(a) => explain::run(a).await,
        // `knowledge push|pull` live in knowledge-cloud.ts; `knowledge status --cloud` is the
        // local status followed by the cloud comparison, so it stays in `knowledge`.
        Command::Knowledge(a) => match a.command {
            KnowledgeCommand::Push(_) | KnowledgeCommand::Pull(_) => knowledge_cloud::run(a).await,
            _ => knowledge::run(a).await,
        },
        Command::Memory(a) => memory::run(a).await,
        Command::Eval(a) => eval::run(a).await,
        Command::Train(a) => train::run(a).await,
        Command::Mcp => mcp::run().await,
        Command::Queues(a) => queues::run(a).await,
        Command::Investigate(a) => investigate::run(a).await,
        Command::Packet(a) => packet::run(a).await,
        Command::Watch(a) => watch::run(a).await,
        Command::Service(a) => service::run(a).await,
        Command::Changes(a) => changes::run(a).await,
        Command::Timeline(a) => timeline::run(a).await,
        Command::WhatChanged(a) => what_changed::run(a).await,
        Command::Architecture(a) => architecture::run(a).await,
        Command::BlastRadius(a) => blast_radius::run(a).await,
        Command::Trace(a) => trace::run(a).await,
        Command::Insights(a) => insights::run(a).await,
        Command::Repos(a) => repos::run(a).await,
        Command::Search(a) => search::run(a).await,
        Command::Investigations(a) => investigations::run(a).await,
        Command::Lens(a) => lens::run(a).await,
        Command::Replay(a) => replay::run(a).await,
        Command::Postmortem(a) => postmortem::run(a).await,
        Command::Owner(a) => owner::run(a).await,
        Command::Score(a) => score::run(a).await,
        Command::Ask(a) => ask::run(a).await,
        Command::Scores(a) => score::run_scores(a).await,
        Command::Onboard(a) => onboard::run(a).await,
        Command::Simulate(a) => simulate::run(a).await,
        Command::Logs(a) => logs::run(a).await,
        Command::State(a) => state::run(a).await,
        Command::Metrics(a) => metrics::run(a).await,
        Command::Skill(a) => skill::run(a).await,
        Command::Update(a) => update::run(a).await,
        Command::Login(a) => login::run(a).await,
        Command::Logout => login::run_logout().await,
        Command::Context(a) => context::run(a).await,
        Command::Cloud(a) => cloud::run(a).await,
        Command::Feedback(a) => feedback::run(a).await,
        Command::Report(a) => report_issue::run(a).await,
        Command::Telemetry(a) => telemetry::run(a).await,
    }
}
