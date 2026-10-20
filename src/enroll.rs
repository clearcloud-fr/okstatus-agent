// OKS-401 — private-agent enrollment. A customer-deployed agent starts with
// a single-use enrollment token (OKSTATUS_TOKEN); on first boot it exchanges
// the token at POST /internal/enroll for per-agent credentials, persists
// them, and from then on authenticates every /internal/* call with
// X-Agent-Id + its own X-Agent-Secret instead of the fleet-wide secret.
// Fleet agents (no token, no credentials file) are untouched.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tracing::{info, warn};

use crate::config::Config;

#[derive(Serialize, Deserialize)]
struct StoredCredentials {
    agent_id: String,
    agent_secret: String,
}

fn credentials_path() -> PathBuf {
    std::env::var("OKSTATUS_CREDENTIALS_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/var/lib/okstatus-agent/credentials.json"))
}

/// Switch the running config into private mode with the given credentials.
fn apply_private_identity(config: &mut Config, agent_id: String, agent_secret: String) {
    config.agent_id = Some(agent_id);
    config.agent_secret = agent_secret;
    config.region = "private".to_string();
    config.agent_type = "private".to_string();
    crate::ssrf::set_allow_private_targets(true);
}

fn looks_like_uuid(id: &str) -> bool {
    id.len() == 36
        && id.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => b.is_ascii_hexdigit(),
        })
}

/// OKS-873 — identity of an agent of OUR network (not a customer agent).
/// Only the credentials change: region, agent type and the SSRF guard stay
/// exactly as configured (unlike `apply_private_identity`). Returns true
/// when FLEET_AGENT_ID / FLEET_AGENT_SECRET are set and valid; exits on a
/// misconfiguration so it shows on the first screen of logs.
fn apply_fleet_identity(config: &mut Config) -> bool {
    let id = std::env::var("FLEET_AGENT_ID").unwrap_or_default();
    let secret = std::env::var("FLEET_AGENT_SECRET").unwrap_or_default();
    if id.is_empty() && secret.is_empty() {
        return false;
    }
    if id.is_empty() || secret.is_empty() {
        eprintln!("FLEET_AGENT_ID and FLEET_AGENT_SECRET must be set together.");
        std::process::exit(1);
    }
    if !looks_like_uuid(&id) {
        eprintln!("FLEET_AGENT_ID is '{id}' — this must be the UUID printed by fleet-agent.js create.");
        std::process::exit(1);
    }
    if !secret.starts_with("oksf_") {
        eprintln!("FLEET_AGENT_SECRET must be the oksf_… secret printed by fleet-agent.js create.");
        std::process::exit(1);
    }
    if std::env::var("OKSTATUS_AGENT_ID").is_ok() || std::env::var("OKSTATUS_TOKEN").is_ok() {
        eprintln!(
            "FLEET_AGENT_* (agent of the OKStatus network) and OKSTATUS_AGENT_ID / \
             OKSTATUS_TOKEN (customer private agent) are mutually exclusive."
        );
        std::process::exit(1);
    }
    info!(agent_id = %id, region = %config.region, "fleet agent identity loaded from environment");
    config.agent_id = Some(id);
    config.agent_secret = secret;
    true
}

/// Returns Ok(true) when the agent runs in private mode after this call.
/// Exits the process on a rejected enrollment token — running on with no
/// valid credentials would just hammer the API with 401s.
pub async fn bootstrap(config: &mut Config) -> bool {
    // OKS-873 — an agent of our network with its own identity is never a
    // private agent: no credentials file, no enrollment.
    if apply_fleet_identity(config) {
        return false;
    }

    let path = credentials_path();

    // 0. Pre-provisioned credentials straight from the environment (a Secret).
    // The cleanest deploy: enroll once out-of-band to obtain the long-lived
    // agent_id/agent_secret, drop them into OKSTATUS_AGENT_ID /
    // OKSTATUS_AGENT_SECRET, and the pod runs private mode with no enrollment
    // token, no credentials file, and no writable/persistent volume — fully
    // stateless and reproducible.
    if let (Ok(id), Ok(secret)) = (
        std::env::var("OKSTATUS_AGENT_ID"),
        std::env::var("OKSTATUS_AGENT_SECRET"),
    ) {
        if !id.is_empty() && !secret.is_empty() {
            // OKS-597 — fail fast on the two misconfigurations seen in the
            // wild instead of hammering the aggregator with doomed requests:
            // the agent's NAME pasted as its id, and the single-use
            // enrollment token (oksa_live_…) pasted as the long-lived secret
            // (oksas_…). Exiting keeps the error on the pod's first screen
            // of logs, where a restart loop makes it impossible to miss.
            if !looks_like_uuid(&id) {
                eprintln!(
                    "OKSTATUS_AGENT_ID is '{id}' — this must be the agent's UUID \
                     (shown when the agent was created), not its name."
                );
                std::process::exit(1);
            }
            if secret.starts_with("oksa_live_") {
                eprintln!(
                    "OKSTATUS_AGENT_SECRET is an enrollment token (oksa_live_…), \
                     not an agent secret (oksas_…). Either set it as OKSTATUS_TOKEN \
                     (with a persistent volume so the minted credentials survive \
                     restarts), or exchange it once via POST /internal/enroll and \
                     store the returned agentId/agentSecret in the environment."
                );
                std::process::exit(1);
            }
            info!(agent_id = %id, "private agent credentials loaded from environment");
            apply_private_identity(config, id, secret);
            return true;
        }
    }

    // 1. Credentials persisted by a previous enrollment win.
    if let Ok(raw) = std::fs::read_to_string(&path) {
        match serde_json::from_str::<StoredCredentials>(&raw) {
            Ok(creds) => {
                info!(agent_id = %creds.agent_id, "private agent credentials loaded");
                apply_private_identity(config, creds.agent_id, creds.agent_secret);
                return true;
            }
            Err(e) => warn!(path = %path.display(), error = %e, "credentials file unreadable — re-enrolling"),
        }
    }

    // 2. Fresh install: exchange the enrollment token.
    let Ok(token) = std::env::var("OKSTATUS_TOKEN") else {
        return false; // fleet mode
    };

    let url = format!("{}/internal/enroll", config.aggregator_url);
    // OKS-355 — same empty-safe fallback as main.rs.
    let version = std::env::var("APP_VERSION")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string());
    let client = reqwest::Client::new();

    let resp = client
        .post(&url)
        .json(&serde_json::json!({ "token": token, "version": version }))
        .send()
        .await;

    let resp = match resp {
        Ok(r) => r,
        Err(e) => {
            // Network trouble at boot — systemd/docker restart policy will
            // retry us; the token is only spent on a successful exchange.
            eprintln!("enrollment failed (network): {e}");
            std::process::exit(1);
        }
    };

    if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
        eprintln!("enrollment token rejected — it was already used or revoked. Generate a new one from the Private Agents page (Rotate token).");
        std::process::exit(1);
    }
    if !resp.status().is_success() {
        eprintln!("enrollment failed: HTTP {}", resp.status());
        std::process::exit(1);
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct EnrollResponse {
        agent_id: String,
        agent_secret: String,
    }
    let body: EnrollResponse = match resp.json().await {
        Ok(b) => b,
        Err(e) => {
            eprintln!("enrollment failed (bad response): {e}");
            std::process::exit(1);
        }
    };

    // Persist for the next boot — the token is spent now, so losing these
    // credentials means a manual "Rotate token". Best-effort: a read-only
    // filesystem still works for this run.
    let stored = StoredCredentials {
        agent_id: body.agent_id.clone(),
        agent_secret: body.agent_secret.clone(),
    };
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    match std::fs::write(&path, serde_json::to_string_pretty(&stored).unwrap()) {
        Ok(()) => info!(path = %path.display(), "private agent credentials saved"),
        Err(e) => warn!(path = %path.display(), error = %e, "could not persist credentials — agent will need a rotated token after restart"),
    }

    info!(agent_id = %body.agent_id, "private agent enrolled");
    apply_private_identity(config, body.agent_id, body.agent_secret);
    true
}

#[cfg(test)]
mod fleet_identity_tests {
    use super::looks_like_uuid;

    #[test]
    fn uuid_shape() {
        assert!(looks_like_uuid("f1ee7000-1234-4abc-9def-000000000001"));
        assert!(!looks_like_uuid("okstatus-agent-upc-es-mad"));
        assert!(!looks_like_uuid("f1ee7000x1234-4abc-9def-000000000001"));
    }
}
