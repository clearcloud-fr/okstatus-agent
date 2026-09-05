use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CheckTask {
    pub task_id: String,
    pub monitor_id: String,
    pub org_id: String,
    pub tenant_id: String,
    pub target: String,
    pub check_type: CheckType,
    // OKS-204 — jobs queued before TCP port support existed never send this
    // key; without #[serde(default)] a missing key fails deserialization of
    // the whole task rather than defaulting to None like every other
    // optional field below.
    #[serde(default)]
    pub port: Option<u16>,
    pub timeout: Option<u64>,
    pub region: String,
    #[serde(default)]
    pub accepted_status_codes: Option<Vec<String>>,
    #[serde(default)]
    pub http_headers: Option<HashMap<String, String>>,
    // OKS-471 — request shape (method/body/encoding); None method = GET.
    #[serde(default)]
    pub http_method: Option<String>,
    #[serde(default)]
    pub http_body: Option<String>,
    #[serde(default)]
    pub http_body_encoding: Option<String>,
    // OKS-472 — skip TLS certificate validation for this check.
    #[serde(default)]
    pub ignore_tls: Option<bool>,
    // OKS-592 — follow HTTP redirects (max 5 hops, each hop SSRF-checked in
    // checks/http.rs). Missing/None = true: agents older than the field
    // simply keep not following, agents newer than the backend default on.
    #[serde(default)]
    pub follow_redirects: Option<bool>,
    #[serde(default)]
    pub basic_auth_user: Option<String>,
    #[serde(default)]
    pub basic_auth_pass: Option<String>,
    #[serde(default)]
    pub keyword: Option<String>,
    #[serde(default)]
    pub keyword_invert: Option<bool>,
    #[serde(default)]
    pub json_path: Option<String>,
    #[serde(default)]
    pub json_operator: Option<String>,
    #[serde(default)]
    pub json_expected_value: Option<String>,
    #[serde(default)]
    pub dns_record_type: Option<String>,
    #[serde(default)]
    pub dns_expected_value: Option<String>,
    #[serde(default)]
    pub dns_server: Option<String>,
    // OKS-169 — llm_config carries provider/model/prompt/timeouts/assertions
    // as raw JSON rather than a dozen flat fields (mirrors llmConfig jsonb on
    // the monitors table); checks/llm.rs parses it into its own local struct.
    #[serde(default)]
    pub llm_provider: Option<String>,
    #[serde(default)]
    pub llm_api_key: Option<String>,
    #[serde(default)]
    pub llm_config: Option<Value>,
    // OKS-668 — database checks (checks/db.rs): the query / command to run
    // after connecting. None = the type's default (SELECT 1 / { ping: 1 }).
    #[serde(default)]
    pub db_query: Option<String>,
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum CheckType {
    Http,
    Ping,
    Tcp,
    Dns,
    Llm,
    // OKS-474 — grpc.health.v1 health checks (checks/grpc.rs)
    Grpc,
    // OKS-668 — database checks (checks/db.rs). "mysql" covers MariaDB too.
    Postgres,
    Mysql,
    Mongodb,
    // Catch-all for any check_type the aggregator sends that this build
    // doesn't know about yet (e.g. a new check type shipped server-side
    // before this agent image was rebuilt/redeployed). Without this,
    // serde_json::from_str on the whole tasks array fails on the single
    // unrecognized task, silently dropping every other task in the same
    // poll batch — including unrelated orgs' ordinary http/ping/tcp/dns
    // checks sharing the same region queue.
    #[serde(other)]
    Unknown,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct CheckResult {
    pub task_id: String,
    pub monitor_id: String,
    pub region: String,
    pub agent_type: String,
    pub success: bool,
    pub latency_ms: Option<u64>,
    pub status_code: Option<u16>,
    pub ssl_days_left: Option<i64>,
    // OKS-169 — only check_llm sets these. `state` carries the 4-way result
    // (up/degraded/down/ratelimit) that `success: bool` can't express on its
    // own; every other check type leaves both None and the backend keeps
    // deriving status from `success` exactly as before.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttft_ms: Option<u64>,
    // TPOT (time per output token, averaged) and ITL (the single worst
    // inter-token gap) — only check_llm sets these, same as ttft_ms above.
    // Approximated from streamed-chunk arrival timing (see compute_pacing in
    // checks/llm.rs) since providers don't expose true token boundaries to
    // the client.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tpot_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub itl_ms: Option<u64>,
    pub error: Option<String>,
    pub checked_at: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct TasksResponse {
    pub tasks: Vec<CheckTask>,
}

#[cfg(test)]
mod tests {
    use super::*;

    // Regression: an org's `llm` monitor scheduled on a region whose deployed
    // agent predates LLM support (check_type wasn't a recognized variant)
    // made serde_json::from_str fail on the *entire* tasks array — silently
    // dropping every other org's ordinary http/ping/tcp/dns checks sharing
    // that same region's poll batch, not just the llm one. CheckType::Unknown
    // (#[serde(other)]) fixes that: the array always deserializes, and only
    // the unrecognized task ends up untyped.
    #[test]
    fn tasks_response_tolerates_unrecognized_check_type_without_failing_the_batch() {
        let body = r#"{"tasks":[
            {"taskId":"t1","monitorId":"m1","orgId":"o1","tenantId":"okstatus","target":"https://example.com","checkType":"http","region":"fr"},
            {"taskId":"t2","monitorId":"m2","orgId":"o2","tenantId":"okstatus","target":"llm-target","checkType":"llm-v2","region":"fr"},
            {"taskId":"t3","monitorId":"m3","orgId":"o3","tenantId":"okstatus","target":"1.1.1.1","checkType":"ping","region":"fr"}
        ]}"#;

        let parsed: TasksResponse =
            serde_json::from_str(body).expect("batch must parse even with an unrecognized check_type");

        assert_eq!(parsed.tasks.len(), 3);
        assert_eq!(parsed.tasks[0].check_type, CheckType::Http);
        assert_eq!(parsed.tasks[1].check_type, CheckType::Unknown);
        assert_eq!(parsed.tasks[2].check_type, CheckType::Ping);
    }

    #[test]
    fn known_check_types_still_round_trip() {
        for (raw, expected) in [
            ("http", CheckType::Http),
            ("ping", CheckType::Ping),
            ("tcp", CheckType::Tcp),
            ("dns", CheckType::Dns),
            ("llm", CheckType::Llm),
            ("grpc", CheckType::Grpc),
            ("postgres", CheckType::Postgres),
            ("mysql", CheckType::Mysql),
            ("mongodb", CheckType::Mongodb),
        ] {
            let json = format!(r#""{}""#, raw);
            let parsed: CheckType = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, expected);
        }
    }
}
