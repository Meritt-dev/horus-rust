//! `horus login` / `horus logout` (HOR-303, per HOR-223 §3). Port of
//! `packages/cli/src/commands/login.ts`.
//!
//! Default UX is a browser device-login: start a session, print a URL + short code, poll until a
//! Horus-issued `hct_` token is minted. The token is stored in `~/.horus/auth.json` — never in
//! the repo, never a DB credential. `--token` / `HORUS_TOKEN` (CI) validates against `/v1/me`.

use std::time::{Duration, Instant};

use anyhow::Result;

use crate::cli::*;
use crate::commands::context::exit;
use crate::lib::cloud::api::{CloudClient, CloudError};
use crate::lib::cloud::auth_store::{clear_auth, read_auth, write_auth, AuthState, CloudAccount};
use crate::lib::cloud::session::{authed_client, resolve_api_base_url};
use crate::lib::format::{bold, cyan, dim, green, red};
use crate::lib::open_url::open_browser;

/// Validate a directly-supplied token (CI path) and persist it.
async fn login_with_token(api_base_url: &str, token: &str) -> Result<u8> {
    let client = CloudClient::new(api_base_url, Some(token));
    match client.me().await {
        Ok(me) => {
            write_auth(&AuthState {
                api_base_url: api_base_url.into(),
                token: token.into(),
                account: CloudAccount {
                    user_id: me.user.id,
                    email: me.user.primary_email.clone(),
                    display_name: me.user.display_name,
                },
            })?;
            println!(
                "{} Logged in as {}. Run {} to connect this repo.",
                green("✓"),
                bold(&me.user.primary_email),
                bold("horus cloud link")
            );
            Ok(0)
        }
        Err(CloudError::Offline(m)) => {
            eprintln!("{}", red(&m));
            Ok(1)
        }
        Err(CloudError::Http { status: 401, .. }) => {
            eprintln!("{}", red("That token is not valid. Create a fresh one in the dashboard and try again."));
            Ok(1)
        }
        Err(e) => {
            eprintln!("{}", red(&format!("Login failed: {e}")));
            Ok(1)
        }
    }
}

/// Browser device-login: start a session, print the code, poll until resolved.
async fn login_with_browser(api_base_url: &str) -> Result<u8> {
    let client = CloudClient::new(api_base_url, None);
    let session = match client.start_cli_session().await {
        Ok(s) => s,
        Err(CloudError::Offline(m)) => {
            eprintln!("{}", red(&m));
            return Ok(1);
        }
        Err(e) => {
            eprintln!("{}", red(&format!("Could not start login: {e}")));
            return Ok(1);
        }
    };
    println!();
    println!("  To sign in, open this URL in your browser:");
    println!("    {}", cyan(&bold(&session.verification_uri)));
    println!();
    println!("  and enter the code:  {}", bold(&session.user_code));
    println!();
    println!("{}", dim("  Waiting for approval…  (press Ctrl+C to cancel)"));

    open_browser(&session.verification_uri_complete);

    let deadline = Instant::now() + Duration::from_secs_f64(session.expires_in.max(0.0));
    let mut interval_ms = (session.interval.max(1.0) * 1000.0) as u64;
    while Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(interval_ms)).await;
        let poll = match client.poll_cli_session(&session.device_code).await {
            Ok(p) => p,
            Err(CloudError::Offline(m)) => {
                eprintln!("{}", red(&format!("\n{m}")));
                return Ok(1);
            }
            // Transient HTTP error — keep polling until the deadline.
            Err(_) => continue,
        };
        match poll.status.as_str() {
            "slow_down" => interval_ms += 2000,
            "denied" => {
                eprintln!("{}", red("\nLogin was denied in the browser."));
                return Ok(1);
            }
            "expired" => {
                eprintln!("{}", red("\nThis login request expired. Run `horus login` again."));
                return Ok(1);
            }
            "approved" => {
                let (Some(token), Some(account)) = (poll.token, poll.account) else {
                    eprintln!("{}", red("\nLogin approved but no token was returned. Try again."));
                    return Ok(1);
                };
                write_auth(&AuthState {
                    api_base_url: api_base_url.into(),
                    token,
                    account: CloudAccount { user_id: account.user_id, email: account.email.clone(), display_name: None },
                })?;
                println!(
                    "\n{} Logged in as {}. Run {} to connect this repo.",
                    green("✓"),
                    bold(&account.email),
                    bold("horus cloud link")
                );
                return Ok(0);
            }
            _ => {} // pending
        }
    }
    eprintln!("{}", red("\nTimed out waiting for approval. Run `horus login` again."));
    Ok(1)
}

pub async fn run_login(token: Option<&str>, api_url: Option<&str>) -> Result<u8> {
    let api_base_url = resolve_api_base_url(api_url);
    let env_token = std::env::var("HORUS_TOKEN").ok();
    // CI / machine path: an explicit token skips the browser entirely.
    match token.map(str::to_string).or(env_token).filter(|t| !t.is_empty()) {
        Some(t) => login_with_token(&api_base_url, &t).await,
        None => login_with_browser(&api_base_url).await,
    }
}

pub async fn run_logout_inner() -> Result<u8> {
    let Some(auth) = read_auth() else {
        println!("{}", dim("Not logged in."));
        return Ok(0);
    };
    // Best-effort server-side revoke of the active token (matched by prefix), so a logout truly
    // invalidates it — not just locally. Offline / already-invalid: clearing local creds suffices.
    if let Some(session) = authed_client() {
        let prefix: String = auth.token.chars().take(12).collect();
        if let Ok(list) = session.client.list_tokens().await {
            if let Some(m) = list.tokens.iter().find(|t| t.prefix == prefix && t.revoked_at.is_none()) {
                let _ = session.client.revoke_token(&m.id).await;
            }
        }
    }
    clear_auth();
    println!("{} Logged out. Local mode still works.", green("✓"));
    Ok(0)
}

pub async fn run(args: &LoginArgs) -> Result<()> {
    exit(run_login(args.token.as_deref(), args.api_url.as_deref()).await?)
}

pub async fn run_logout() -> Result<()> {
    exit(run_logout_inner().await?)
}
