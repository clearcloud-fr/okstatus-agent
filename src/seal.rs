// OKS-880 — monitor secrets sealed for this agent.
//
// The backend no longer puts a monitor's credentials in clear in the task
// (and so in Redis): headers, body, Basic auth, auth_config and the LLM key
// travel in `sealed`, encrypted for the agents that may run the task. This
// agent derives an X25519 key pair from its own secret (the same derivation
// as src/agents/task-seal.ts on the backend), publishes the public half in
// every heartbeat, and opens `sealed` in memory right before the check.
//
//   sk  = HKDF-SHA256(ikm = secret, salt = "okstatus-agent-seal-v1", info = "x25519", 32)
//   kek = HKDF-SHA256(ikm = X25519(sk, epk), salt = epk || pk, info = "okstatus-seal-v1/kek", 32)
//   dek = ChaCha20-Poly1305-open(kek, n_i, k_i, aad = agent id)
//   secrets = ChaCha20-Poly1305-open(dek, n, ct,
//               aad = "okstatus-seal-v1|<taskId>|<monitorId>|<region>")
//
// Crypto comes from aws-lc-rs, already in the build through the AWS SDK
// (ring only has ephemeral X25519 keys). Nothing here ever logs a secret.

use std::collections::HashMap;
use std::sync::OnceLock;

use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use aws_lc_rs::agreement::{agree, PrivateKey, UnparsedPublicKey, X25519};
use aws_lc_rs::hkdf::{Salt, HKDF_SHA256};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::Deserialize;
use serde_json::Value;
use zeroize::Zeroize;

use crate::models::CheckTask;

const SEAL_VERSION: u8 = 1;
const SEAL_KEY_SALT: &[u8] = b"okstatus-agent-seal-v1";
const SEAL_KEY_INFO: &[u8] = b"x25519";
const KEK_INFO: &[u8] = b"okstatus-seal-v1/kek";
const AAD_PREFIX: &str = "okstatus-seal-v1";

pub struct SealKey {
    private: PrivateKey,
    public_raw: Vec<u8>,
    public_b64: String,
}

impl SealKey {
    pub fn derive(secret: &str) -> Self {
        let mut raw = [0u8; 32];
        Salt::new(HKDF_SHA256, SEAL_KEY_SALT)
            .extract(secret.as_bytes())
            .expand(&[SEAL_KEY_INFO], HKDF_SHA256)
            .and_then(|okm| okm.fill(&mut raw))
            .expect("HKDF-SHA256 of 32 bytes cannot fail");
        let private =
            PrivateKey::from_private_key(&X25519, &raw).expect("32 bytes is a valid X25519 key");
        raw.zeroize();
        let public_raw = private
            .compute_public_key()
            .expect("X25519 public key")
            .as_ref()
            .to_vec();
        let public_b64 = B64.encode(&public_raw);
        Self { private, public_raw, public_b64 }
    }

    pub fn public_key_b64(&self) -> &str {
        &self.public_b64
    }
}

static KEY: OnceLock<SealKey> = OnceLock::new();

/// Called once at startup by an identified agent (fleet or private).
pub fn init(secret: &str) {
    let _ = KEY.set(SealKey::derive(secret));
}

/// The public key sent in heartbeats, if this agent has an identity.
pub fn public_key() -> Option<&'static str> {
    KEY.get().map(|k| k.public_key_b64())
}

#[derive(Deserialize, Debug, Clone, serde::Serialize)]
pub struct SealedEnvelope {
    pub v: u8,
    pub epk: String,
    pub n: String,
    pub ct: String,
    pub to: Vec<SealedRecipient>,
}

#[derive(Deserialize, Debug, Clone, serde::Serialize)]
pub struct SealedRecipient {
    pub id: String,
    pub n: String,
    pub k: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SealedSecrets {
    http_headers: Option<HashMap<String, String>>,
    http_body: Option<String>,
    basic_auth_user: Option<String>,
    basic_auth_pass: Option<String>,
    auth_config: Option<Value>,
    llm_api_key: Option<String>,
}

fn b64(field: &str, value: &str) -> Result<Vec<u8>, String> {
    B64.decode(value).map_err(|_| format!("sealed.{field} is not base64"))
}

fn chacha_open(key: &[u8], nonce: &[u8], sealed: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    let key = LessSafeKey::new(
        UnboundKey::new(&CHACHA20_POLY1305, key).map_err(|_| "bad key length".to_string())?,
    );
    let nonce = Nonce::try_assume_unique_for_key(nonce).map_err(|_| "bad nonce length".to_string())?;
    let mut buf = sealed.to_vec();
    let plain_len = key
        .open_in_place(nonce, Aad::from(aad), &mut buf)
        .map_err(|_| "authentication failed".to_string())?
        .len();
    buf.truncate(plain_len);
    Ok(buf)
}

/// Opens `task.sealed` with `key` as agent `agent_id` and puts the secrets
/// back into the task. A task without `sealed` is left as is.
pub fn open_with(key: &SealKey, agent_id: &str, task: &mut CheckTask) -> Result<(), String> {
    let Some(env) = task.sealed.take() else { return Ok(()) };
    if env.v != SEAL_VERSION {
        return Err(format!("unsupported seal version {}", env.v));
    }
    let mine = env
        .to
        .iter()
        .find(|r| r.id == agent_id)
        .ok_or_else(|| "task not sealed for this agent".to_string())?;

    let epk = b64("epk", &env.epk)?;
    let mut shared = agree(
        &key.private,
        UnparsedPublicKey::new(&X25519, &epk),
        "key agreement failed".to_string(),
        |s| Ok(s.to_vec()),
    )?;
    let mut kek = [0u8; 32];
    let mut salt = epk.clone();
    salt.extend_from_slice(&key.public_raw);
    Salt::new(HKDF_SHA256, &salt)
        .extract(&shared)
        .expand(&[KEK_INFO], HKDF_SHA256)
        .and_then(|okm| okm.fill(&mut kek))
        .map_err(|_| "HKDF failed".to_string())?;
    shared.zeroize();

    let dek = chacha_open(&kek, &b64("to.n", &mine.n)?, &b64("to.k", &mine.k)?, agent_id.as_bytes());
    kek.zeroize();
    let mut dek = dek?;

    let aad = format!("{AAD_PREFIX}|{}|{}|{}", task.task_id, task.monitor_id, task.region);
    let plain = chacha_open(&dek, &b64("n", &env.n)?, &b64("ct", &env.ct)?, aad.as_bytes());
    dek.zeroize();
    let mut plain = plain?;

    let parsed: Result<SealedSecrets, _> = serde_json::from_slice(&plain);
    plain.zeroize();
    let secrets = parsed.map_err(|_| "sealed payload is not valid JSON".to_string())?;
    task.http_headers = secrets.http_headers;
    task.http_body = secrets.http_body;
    task.basic_auth_user = secrets.basic_auth_user;
    task.basic_auth_pass = secrets.basic_auth_pass;
    task.auth_config = secrets.auth_config;
    task.llm_api_key = secrets.llm_api_key;
    Ok(())
}

/// Opens a sealed task with this agent's key (see `init`).
pub fn open(agent_id: Option<&str>, task: &mut CheckTask) -> Result<(), String> {
    if task.sealed.is_none() {
        return Ok(());
    }
    match (KEY.get(), agent_id) {
        (Some(key), Some(id)) => open_with(key, id, task),
        _ => Err("sealed task but this agent has no identity key".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Same secret, id and envelope as tests/task-seal.test.ts on the backend:
    // the two implementations must agree byte for byte.
    const SECRET: &str = "oksf_es-mad-test-secret";
    const AGENT_ID: &str = "8a22c97d-eaf7-480a-a8ce-92db044e345c";
    const PINNED_PUBLIC_KEY: &str = "Ss8i5zfUmu7hBL6seflK3964shCXVPoPv6z8K+zg6S8=";
    const VECTOR: &str = r#"{"taskId":"11111111-2222-4333-8444-555555555555","monitorId":"66666666-7777-4888-9999-aaaaaaaaaaaa","orgId":"o","tenantId":"t","target":"https://api.example.com/health","checkType":"http","timeout":5000,"region":"es-mad","sealed":{"v":1,"epk":"bIaAo+myeyHRb+H5EJmFqjEWuurVXX56dmwRP0lgywc=","n":"sDfDLYPLeNtMLGxh","ct":"rnbOSf5dOG/Hf6Jgjdhd+CiAT8yRJkofT/OnG18UxCHtaTbKl0MDZSn5dJ4rItRr8s7/Iw/ZOlQL+Ftv7UmNaU79ERCSc2ltSGpT4oQBMJKG8cV13GPklP7VB1M0kR0RW5NA/fQQoVr9QkAgjBwR9Ev0X7wUu7x8H59SEHOjrulysg+wYeI4V/RQ8529cFRtwloOjZesTG3+9aaO33y38kGdl3vM+V6K+QKTcvFRJIdoPvHppvUzlAD04MU4o/ytF008Hw==","to":[{"id":"8a22c97d-eaf7-480a-a8ce-92db044e345c","n":"XEA1Wd78EqZ0C3os","k":"MiPh5OcHVtF93ujKnNp1irtTRrf1tKnZTAJ+cusjIodKkQNCIs3NTW+kFWNKZokh"}]}}"#;

    fn vector() -> CheckTask {
        serde_json::from_str(VECTOR).expect("vector parses as a task")
    }

    #[test]
    fn derives_the_same_public_key_as_the_backend() {
        assert_eq!(SealKey::derive(SECRET).public_key_b64(), PINNED_PUBLIC_KEY);
    }

    #[test]
    fn opens_a_task_sealed_by_the_backend() {
        let key = SealKey::derive(SECRET);
        let mut task = vector();
        open_with(&key, AGENT_ID, &mut task).expect("opens");
        assert!(task.sealed.is_none());
        assert_eq!(
            task.http_headers.as_ref().and_then(|h| h.get("Authorization")).map(String::as_str),
            Some("Bearer s3cr3t")
        );
        assert_eq!(task.basic_auth_user.as_deref(), Some("admin"));
        assert_eq!(task.basic_auth_pass.as_deref(), Some("p4ss"));
        assert_eq!(task.http_body.as_deref(), Some("body"));
        assert_eq!(task.llm_api_key.as_deref(), Some("sk-llm"));
        assert_eq!(task.auth_config.as_ref().and_then(|v| v.get("token")).and_then(|v| v.as_str()), Some("tok"));
    }

    #[test]
    fn refuses_another_agent_secret() {
        let key = SealKey::derive("oksf_some-other-secret");
        let mut task = vector();
        assert!(open_with(&key, AGENT_ID, &mut task).is_err());
        assert!(task.basic_auth_pass.is_none());
    }

    #[test]
    fn refuses_a_task_not_sealed_for_this_agent() {
        let key = SealKey::derive(SECRET);
        let mut task = vector();
        assert_eq!(
            open_with(&key, "00000000-0000-4000-8000-000000000000", &mut task),
            Err("task not sealed for this agent".to_string())
        );
    }

    #[test]
    fn refuses_a_sealed_block_moved_to_another_task() {
        let key = SealKey::derive(SECRET);
        for mutate in [
            |t: &mut CheckTask| t.monitor_id = "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff".into(),
            |t: &mut CheckTask| t.region = "de-fra".into(),
            |t: &mut CheckTask| t.task_id = "99999999-2222-4333-8444-555555555555".into(),
        ] {
            let mut task = vector();
            mutate(&mut task);
            assert!(open_with(&key, AGENT_ID, &mut task).is_err());
            assert!(task.basic_auth_pass.is_none());
        }
    }

    #[test]
    fn leaves_an_unsealed_task_alone() {
        let key = SealKey::derive(SECRET);
        let mut task = vector();
        task.sealed = None;
        task.basic_auth_pass = Some("clear".into());
        open_with(&key, AGENT_ID, &mut task).expect("no-op");
        assert_eq!(task.basic_auth_pass.as_deref(), Some("clear"));
    }
}
