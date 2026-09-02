// OKS-169 — LLM canary check: a synthetic HTTP POST against an LLM
// provider's chat-completions endpoint, streamed, measuring the time to
// first token (TTFT) and validating the aggregated content/format.
//
// Three provider families, three request/parse shapes:
//   - openai-compatible: SSE `data: {...}` chunks, `choices[0].delta.content`
//     (covers OpenAI itself, Azure, Mistral, Groq, Together, Fireworks,
//     OpenRouter, DeepSeek, xAI, self-hosted vLLM/TGI — same wire format)
//   - anthropic: SSE typed events, `content_block_delta` / `text_delta`
//   - bedrock: AWS SigV4 + binary eventstream framing, handled by
//     aws-sdk-bedrockruntime's ConverseStream rather than hand-rolled
//
// TTFT is measured at the first chunk that actually carries text — not the
// first HTTP byte, and not a role-only opening chunk (OpenAI) or
// message_start (Anthropic) — per the spec this check type is modeled on.

use std::time::{Duration, Instant};

use aws_sdk_bedrockruntime::types::{ContentBlock, ContentBlockDelta, ConverseStreamOutput, Message};
use futures_util::StreamExt;
use regex::Regex;
use serde::Deserialize;
use serde_json::Value;

use crate::models::{CheckResult, CheckTask};

#[derive(Deserialize)]
struct LlmTimeouts {
    connect_ms: u64,
    first_token_ms: u64,
    total_ms: u64,
}

#[derive(Deserialize, Default)]
struct LlmFormat {
    json_parse: bool,
    #[serde(default)]
    #[allow(dead_code)] // schema shape validation is a follow-up, json_parse alone ships first
    schema: Option<Value>,
}

#[derive(Deserialize)]
struct LlmAssertions {
    ttft_ms_max: u64,
    #[serde(default)]
    content_equals: Option<String>,
    #[serde(default)]
    content_regex: Option<String>,
    #[serde(default)]
    format: Option<LlmFormat>,
}

// No `endpoint` field — the provider URL is task.target (same field every
// other check type reads its target from), not a second one to keep in sync.
#[derive(Deserialize)]
struct LlmConfig {
    model: String,
    prompt: String,
    #[serde(default)]
    region: Option<String>,
    timeouts: LlmTimeouts,
    assertions: LlmAssertions,
}

enum CheckState {
    Up,
    Degraded,
    Down,
    RateLimit,
}

impl CheckState {
    fn as_str(&self) -> &'static str {
        match self {
            CheckState::Up => "up",
            CheckState::Degraded => "degraded",
            CheckState::Down => "down",
            CheckState::RateLimit => "ratelimit",
        }
    }
}

#[derive(Default)]
struct StreamOutcome {
    ttft_ms: Option<u64>,
    // TPOT (avg ms between successive streamed chunks after the first) and
    // ITL (the single worst gap) — see compute_pacing below for what these
    // actually measure and its limitation.
    tpot_ms: Option<u64>,
    itl_ms: Option<u64>,
    content: String,
}

/// Approximates TPOT (time per output token) and ITL (inter-token latency)
/// from the arrival time of each non-empty streamed chunk. This is a proxy,
/// not a true per-token measurement: providers stream text deltas, not
/// individual tokens, over SSE/event-stream framing, and the client has no
/// visibility into how many tokens a given delta actually contained without
/// a tokenizer for that model. In practice chat-completion streams emit
/// close to one token (or a small, consistent handful) per chunk, so
/// inter-chunk timing is the closest signal observable from here.
/// `token_times` are per-chunk elapsed-since-request-start timestamps, in
/// arrival order. Returns (tpot_ms, itl_ms), both None when fewer than two
/// chunks arrived (nothing to compute an interval from).
fn compute_pacing(token_times: &[Duration]) -> (Option<u64>, Option<u64>) {
    if token_times.len() < 2 {
        return (None, None);
    }
    let mut max_gap_ms: u64 = 0;
    let mut total_gap_ms: u64 = 0;
    for pair in token_times.windows(2) {
        let gap_ms = pair[1].saturating_sub(pair[0]).as_millis() as u64;
        total_gap_ms += gap_ms;
        max_gap_ms = max_gap_ms.max(gap_ms);
    }
    let tpot_ms = total_gap_ms / (token_times.len() as u64 - 1);
    (Some(tpot_ms), Some(max_gap_ms))
}

enum SendError {
    RateLimited,
    Other(String),
}

pub async fn check_llm(client: &reqwest::Client, task: &CheckTask) -> CheckResult {
    let start = Instant::now();

    let Some(config_val) = &task.llm_config else {
        return error_result(task, &start, "missing llm_config".into(), CheckState::Down);
    };
    let config: LlmConfig = match serde_json::from_value(config_val.clone()) {
        Ok(c) => c,
        Err(e) => {
            return error_result(task, &start, format!("invalid llm_config: {e}"), CheckState::Down)
        }
    };
    let provider = task.llm_provider.as_deref().unwrap_or("openai-compatible");
    let api_key = task.llm_api_key.clone().unwrap_or_default();

    let connect_timeout = Duration::from_millis(config.timeouts.connect_ms);
    let first_token_timeout = Duration::from_millis(config.timeouts.first_token_ms);
    let total_timeout = Duration::from_millis(config.timeouts.total_ms);

    let outcome = match provider {
        "anthropic" => {
            send_anthropic(
                client,
                &task.target,
                &config,
                &api_key,
                connect_timeout,
                first_token_timeout,
                total_timeout,
            )
            .await
        }
        "bedrock" => {
            send_bedrock(&config, &api_key, connect_timeout, first_token_timeout, total_timeout).await
        }
        _ => {
            send_openai_compatible(
                client,
                &task.target,
                &config,
                &api_key,
                connect_timeout,
                first_token_timeout,
                total_timeout,
            )
            .await
        }
    };

    let latency_ms = start.elapsed().as_millis() as u64;

    let outcome = match outcome {
        Ok(o) => o,
        Err(SendError::RateLimited) => {
            return CheckResult {
                task_id: task.task_id.clone(),
                monitor_id: task.monitor_id.clone(),
                region: task.region.clone(),
                agent_type: String::new(),
                success: false,
                latency_ms: Some(latency_ms),
                status_code: Some(429),
                ssl_days_left: None,
                state: Some(CheckState::RateLimit.as_str().to_string()),
                ttft_ms: None,
                tpot_ms: None,
                itl_ms: None,
                error: Some("HTTP 429 — isolated rate limit, not treated as a provider outage".into()),
                checked_at: chrono::Utc::now().to_rfc3339(),
            }
        }
        Err(SendError::Other(msg)) => return error_result(task, &start, msg, CheckState::Down),
    };

    let (state, error) = evaluate_assertions(&config.assertions, &outcome);

    CheckResult {
        task_id: task.task_id.clone(),
        monitor_id: task.monitor_id.clone(),
        region: task.region.clone(),
        agent_type: String::new(),
        // Only a clean Up counts as success for legacy consumers of this
        // field (uptime% accounting, retry/alert state machine) — Degraded
        // and RateLimit are new nuance that `state` carries; keeping
        // `success` conservative means nothing downstream has to know about
        // the new states to stay correct.
        success: matches!(state, CheckState::Up),
        latency_ms: Some(latency_ms),
        status_code: Some(200),
        ssl_days_left: None,
        state: Some(state.as_str().to_string()),
        ttft_ms: outcome.ttft_ms,
        tpot_ms: outcome.tpot_ms,
        itl_ms: outcome.itl_ms,
        error,
        checked_at: chrono::Utc::now().to_rfc3339(),
    }
}

/// Strips inline `<think>…</think>` blocks (qwen-style thinking models put
/// their chain-of-thought INSIDE delta.content) so assertions run against
/// the model's actual answer. An unterminated `<think>` (the whole rest of
/// the output is reasoning, no final answer) strips to the end.
fn strip_think_blocks(content: &str) -> String {
    let mut out = String::with_capacity(content.len());
    let mut rest = content;
    while let Some(start) = rest.find("<think>") {
        out.push_str(&rest[..start]);
        match rest[start..].find("</think>") {
            Some(end_rel) => rest = &rest[start + end_rel + "</think>".len()..],
            None => {
                rest = "";
                break;
            }
        }
    }
    out.push_str(rest);
    out
}

fn evaluate_assertions(assertions: &LlmAssertions, outcome: &StreamOutcome) -> (CheckState, Option<String>) {
    let Some(ttft_ms) = outcome.ttft_ms else {
        return (CheckState::Down, Some("stream ended with no text content".into()));
    };

    if ttft_ms > assertions.ttft_ms_max {
        return (
            CheckState::Degraded,
            Some(format!("TTFT {ttft_ms}ms exceeded threshold {}ms", assertions.ttft_ms_max)),
        );
    }

    let stripped = strip_think_blocks(&outcome.content);
    let trimmed = stripped.trim();

    // The stream produced tokens (TTFT fired) but everything was reasoning —
    // either a truncated <think> block or a reasoning-only channel. Only an
    // issue when a content assertion actually needs the final answer.
    if trimmed.is_empty()
        && (assertions.content_equals.is_some()
            || assertions.content_regex.is_some()
            || assertions.format.is_some())
    {
        return (
            CheckState::Degraded,
            Some("response contained only reasoning (no final answer to assert on)".into()),
        );
    }

    if let Some(ref expected) = assertions.content_equals {
        if trimmed != expected.trim() {
            return (
                CheckState::Degraded,
                Some(format!("content '{trimmed}' does not equal expected '{expected}'")),
            );
        }
    }

    if let Some(ref pattern) = assertions.content_regex {
        match Regex::new(pattern) {
            Ok(re) if re.is_match(trimmed) => {}
            Ok(_) => {
                return (
                    CheckState::Degraded,
                    Some(format!("content '{trimmed}' does not match pattern '{pattern}'")),
                )
            }
            Err(e) => return (CheckState::Degraded, Some(format!("invalid content_regex: {e}"))),
        }
    }

    if let Some(ref format) = assertions.format {
        if format.json_parse {
            if let Err(e) = serde_json::from_str::<Value>(trimmed) {
                return (CheckState::Degraded, Some(format!("response is not valid JSON: {e}")));
            }
        }
    }

    (CheckState::Up, None)
}

fn error_result(task: &CheckTask, start: &Instant, error: String, state: CheckState) -> CheckResult {
    CheckResult {
        task_id: task.task_id.clone(),
        monitor_id: task.monitor_id.clone(),
        region: task.region.clone(),
        agent_type: String::new(),
        success: false,
        latency_ms: Some(start.elapsed().as_millis() as u64),
        status_code: None,
        ssl_days_left: None,
        state: Some(state.as_str().to_string()),
        ttft_ms: None,
        tpot_ms: None,
        itl_ms: None,
        error: Some(error),
        checked_at: chrono::Utc::now().to_rfc3339(),
    }
}

/// One text delta pulled out of a stream chunk. Reasoning deltas (a thinking
/// model's chain-of-thought: Groq/DeepSeek's `delta.reasoning[_content]`,
/// Anthropic's `thinking_delta`) count for TTFT/TPOT/ITL — they ARE the
/// first tokens the provider produced — but are excluded from the aggregated
/// content that assertions run against, so `contentEquals: "PONG"` keeps
/// matching the model's actual answer instead of its scratchpad.
enum TextDelta {
    Content(String),
    Reasoning(String),
}

/// Reads an SSE byte stream, tracking TTFT at the first chunk for which
/// `extract_text` returns non-empty text, aggregating content-kind text
/// into the final content. `extract_text` gets one already-parsed `data:`
/// JSON payload per call and returns the text delta it carries (if any).
/// `is_terminator` flags a raw data line (e.g. OpenAI's "[DONE]") that ends
/// the stream without needing to be JSON-parsed.
async fn read_sse<F>(
    resp: reqwest::Response,
    req_start: Instant,
    first_token_timeout: Duration,
    total_timeout: Duration,
    is_terminator: impl Fn(&str) -> bool,
    mut extract_text: F,
) -> Result<StreamOutcome, SendError>
where
    F: FnMut(&Value) -> Option<TextDelta>,
{
    let mut stream = resp.bytes_stream();
    let mut buffer = String::new();
    let mut content = String::new();
    let mut ttft_ms: Option<u64> = None;
    let mut token_times: Vec<Duration> = Vec::new();

    loop {
        let elapsed = req_start.elapsed();
        if ttft_ms.is_none() && elapsed >= first_token_timeout {
            return Err(SendError::Other(format!(
                "no token received within {first_token_timeout:?} (provider may be saturated)"
            )));
        }
        if elapsed >= total_timeout {
            return Err(SendError::Other(format!("total timeout after {total_timeout:?}")));
        }
        let deadline = if ttft_ms.is_none() {
            first_token_timeout - elapsed
        } else {
            total_timeout.saturating_sub(elapsed)
        };

        let next = match tokio::time::timeout(deadline, stream.next()).await {
            Ok(Some(Ok(chunk))) => chunk,
            Ok(Some(Err(e))) => return Err(SendError::Other(format!("stream read error: {e}"))),
            Ok(None) => break,
            Err(_) => continue, // loop back to top, which resolves the exact timeout reason
        };

        buffer.push_str(&String::from_utf8_lossy(&next));

        while let Some(pos) = buffer.find("\n\n") {
            let frame = buffer[..pos].to_string();
            buffer.drain(..pos + 2);

            for line in frame.lines() {
                let Some(data) = line.strip_prefix("data:") else { continue };
                let data = data.trim();
                if is_terminator(data) {
                    let (tpot_ms, itl_ms) = compute_pacing(&token_times);
                    return Ok(StreamOutcome { ttft_ms, tpot_ms, itl_ms, content });
                }
                let Ok(parsed) = serde_json::from_str::<Value>(data) else { continue };
                if let Some(delta) = extract_text(&parsed) {
                    let (text, is_content) = match &delta {
                        TextDelta::Content(t) => (t, true),
                        TextDelta::Reasoning(t) => (t, false),
                    };
                    if !text.is_empty() {
                        let elapsed = req_start.elapsed();
                        if ttft_ms.is_none() {
                            ttft_ms = Some(elapsed.as_millis() as u64);
                        }
                        token_times.push(elapsed);
                        if is_content {
                            content.push_str(text);
                        }
                    }
                }
            }
        }
    }

    let (tpot_ms, itl_ms) = compute_pacing(&token_times);
    Ok(StreamOutcome { ttft_ms, tpot_ms, itl_ms, content })
}

async fn send_openai_compatible(
    client: &reqwest::Client,
    target: &str,
    config: &LlmConfig,
    api_key: &str,
    connect_timeout: Duration,
    first_token_timeout: Duration,
    total_timeout: Duration,
) -> Result<StreamOutcome, SendError> {
    let body = serde_json::json!({
        "model": config.model,
        "max_tokens": 512,
        "temperature": 0,
        "stream": true,
        "messages": [{ "role": "user", "content": config.prompt }],
    });

    let req_start = Instant::now();
    let resp = match tokio::time::timeout(
        connect_timeout,
        client.post(target).bearer_auth(api_key).json(&body).send(),
    )
    .await
    {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => return Err(SendError::Other(format!("request failed: {e}"))),
        Err(_) => return Err(SendError::Other(format!("connect timeout after {connect_timeout:?}"))),
    };

    if resp.status().as_u16() == 429 {
        return Err(SendError::RateLimited);
    }
    if !resp.status().is_success() {
        return Err(SendError::Other(format!("HTTP {}", resp.status().as_u16())));
    }

    read_sse(
        resp,
        req_start,
        first_token_timeout,
        total_timeout,
        |data| data == "[DONE]",
        |parsed| {
            let delta = &parsed["choices"][0]["delta"];
            if let Some(s) = delta["content"].as_str() {
                if !s.is_empty() {
                    return Some(TextDelta::Content(s.to_string()));
                }
            }
            // Thinking models that stream their chain-of-thought on a
            // separate channel: Groq (gpt-oss, qwen) uses `reasoning`,
            // DeepSeek uses `reasoning_content`. These are real first
            // tokens for latency purposes but not part of the answer.
            if let Some(s) = delta["reasoning"].as_str() {
                return Some(TextDelta::Reasoning(s.to_string()));
            }
            if let Some(s) = delta["reasoning_content"].as_str() {
                return Some(TextDelta::Reasoning(s.to_string()));
            }
            None
        },
    )
    .await
}

async fn send_anthropic(
    client: &reqwest::Client,
    target: &str,
    config: &LlmConfig,
    api_key: &str,
    connect_timeout: Duration,
    first_token_timeout: Duration,
    total_timeout: Duration,
) -> Result<StreamOutcome, SendError> {
    let body = serde_json::json!({
        "model": config.model,
        "max_tokens": 512,
        "temperature": 0,
        "stream": true,
        "messages": [{ "role": "user", "content": config.prompt }],
    });

    let req_start = Instant::now();
    let resp = match tokio::time::timeout(
        connect_timeout,
        client
            .post(target)
            .header("x-api-key", api_key)
            .header("anthropic-version", "2023-06-01")
            .json(&body)
            .send(),
    )
    .await
    {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => return Err(SendError::Other(format!("request failed: {e}"))),
        Err(_) => return Err(SendError::Other(format!("connect timeout after {connect_timeout:?}"))),
    };

    if resp.status().as_u16() == 429 {
        return Err(SendError::RateLimited);
    }
    if !resp.status().is_success() {
        return Err(SendError::Other(format!("HTTP {}", resp.status().as_u16())));
    }

    // Anthropic SSE frames carry an `event: <type>` line ahead of `data:` —
    // read_sse only inspects `data:` lines, so the event type is recovered
    // from the parsed payload's own "type" field instead (message_stop is
    // both the terminator and never carries a text_delta, so treating a
    // frame's data as "empty text" for anything but content_block_delta is
    // sufficient without needing the event: line separately).
    read_sse(
        resp,
        req_start,
        first_token_timeout,
        total_timeout,
        |data| {
            // No standalone [DONE] sentinel in Anthropic's protocol — the
            // stream just ends after message_stop's data line comes through,
            // which read_sse's extract_text below lets fall through to
            // "no text" instead of terminating early on it.
            let _ = data;
            false
        },
        |parsed| {
            if parsed["type"] == "message_stop" {
                return None;
            }
            if parsed["delta"]["type"] == "thinking_delta" {
                // Extended-thinking chain-of-thought — counts for TTFT,
                // excluded from content assertions (same as reasoning
                // deltas on the openai-compatible path).
                if let Some(s) = parsed["delta"]["thinking"].as_str() {
                    return Some(TextDelta::Reasoning(s.to_string()));
                }
            }
            parsed["delta"]["text"]
                .as_str()
                .filter(|_| parsed["delta"]["type"] == "text_delta")
                .map(|s| TextDelta::Content(s.to_string()))
        },
    )
    .await
}

async fn send_bedrock(
    config: &LlmConfig,
    api_key: &str,
    connect_timeout: Duration,
    first_token_timeout: Duration,
    total_timeout: Duration,
) -> Result<StreamOutcome, SendError> {
    // Bedrock auth is AWS SigV4, not a bearer token — llmApiKey carries
    // "access_key_id:secret_access_key" (session token unsupported for now,
    // same limitation the create-monitor form documents).
    let (access_key, secret_key) = api_key
        .split_once(':')
        .ok_or_else(|| SendError::Other("bedrock llmApiKey must be \"access_key_id:secret_access_key\"".into()))?;

    let region = config
        .region
        .clone()
        .ok_or_else(|| SendError::Other("bedrock requires llmConfig.region".into()))?;

    let credentials = aws_sdk_bedrockruntime::config::Credentials::new(
        access_key,
        secret_key,
        None,
        None,
        "okstatus-llm-check",
    );
    let sdk_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_sdk_bedrockruntime::config::Region::new(region))
        .credentials_provider(credentials)
        .load()
        .await;
    let client = aws_sdk_bedrockruntime::Client::new(&sdk_config);

    let req_start = Instant::now();
    let message = match Message::builder()
        .role(aws_sdk_bedrockruntime::types::ConversationRole::User)
        .content(ContentBlock::Text(config.prompt.clone()))
        .build()
    {
        Ok(m) => m,
        Err(e) => return Err(SendError::Other(format!("invalid bedrock message: {e}"))),
    };

    let send_fut = client
        .converse_stream()
        .model_id(&config.model)
        .messages(message)
        .inference_config(
            aws_sdk_bedrockruntime::types::InferenceConfiguration::builder()
                .max_tokens(512)
                .temperature(0.0)
                .build(),
        )
        .send();

    let output = match tokio::time::timeout(connect_timeout, send_fut).await {
        Ok(Ok(o)) => o,
        Ok(Err(e)) => {
            let msg = e.to_string();
            if msg.contains("ThrottlingException") || msg.contains("429") {
                return Err(SendError::RateLimited);
            }
            return Err(SendError::Other(format!("bedrock request failed: {msg}")));
        }
        Err(_) => return Err(SendError::Other(format!("connect timeout after {connect_timeout:?}"))),
    };

    let mut stream = output.stream;
    let mut content = String::new();
    let mut ttft_ms: Option<u64> = None;
    let mut token_times: Vec<Duration> = Vec::new();

    loop {
        let elapsed = req_start.elapsed();
        if ttft_ms.is_none() && elapsed >= first_token_timeout {
            return Err(SendError::Other(format!(
                "no token received within {first_token_timeout:?} (provider may be saturated)"
            )));
        }
        if elapsed >= total_timeout {
            return Err(SendError::Other(format!("total timeout after {total_timeout:?}")));
        }
        let deadline = if ttft_ms.is_none() {
            first_token_timeout - elapsed
        } else {
            total_timeout.saturating_sub(elapsed)
        };

        let event = match tokio::time::timeout(deadline, stream.recv()).await {
            Ok(Ok(Some(e))) => e,
            Ok(Ok(None)) => break,
            Ok(Err(e)) => return Err(SendError::Other(format!("bedrock stream error: {e}"))),
            Err(_) => continue,
        };

        if let ConverseStreamOutput::ContentBlockDelta(ev) = event {
            if let Some(ContentBlockDelta::Text(text)) = ev.delta {
                if !text.is_empty() {
                    let elapsed = req_start.elapsed();
                    if ttft_ms.is_none() {
                        ttft_ms = Some(elapsed.as_millis() as u64);
                    }
                    token_times.push(elapsed);
                    content.push_str(&text);
                }
            }
        }
    }

    let (tpot_ms, itl_ms) = compute_pacing(&token_times);
    Ok(StreamOutcome { ttft_ms, tpot_ms, itl_ms, content })
}

// evaluate_assertions is pure/synchronous and the part most likely to have a
// subtle off-by-one or ordering bug, so it gets unit tests even though the
// rest of this module (network I/O) follows the existing convention in
// checks/http.rs, checks/tcp.rs, checks/dns.rs of no unit tests — those are
// covered by the e2e smoke test instead.
#[cfg(test)]
mod tests {
    use super::*;

    fn assertions(ttft_ms_max: u64) -> LlmAssertions {
        LlmAssertions { ttft_ms_max, content_equals: None, content_regex: None, format: None }
    }

    #[test]
    fn compute_pacing_needs_at_least_two_chunks() {
        assert_eq!(compute_pacing(&[]), (None, None));
        assert_eq!(compute_pacing(&[Duration::from_millis(100)]), (None, None));
    }

    #[test]
    fn compute_pacing_averages_gaps_for_tpot_and_takes_the_worst_for_itl() {
        // gaps: 50ms, 50ms, 200ms → avg 100ms, worst 200ms
        let times = [
            Duration::from_millis(100),
            Duration::from_millis(150),
            Duration::from_millis(200),
            Duration::from_millis(400),
        ];
        assert_eq!(compute_pacing(&times), (Some(100), Some(200)));
    }

    #[test]
    fn compute_pacing_two_chunks_tpot_equals_itl() {
        let times = [Duration::from_millis(50), Duration::from_millis(130)];
        assert_eq!(compute_pacing(&times), (Some(80), Some(80)));
    }

    #[test]
    fn no_ttft_means_down() {
        let outcome = StreamOutcome { ttft_ms: None, content: String::new(), ..Default::default() };
        let (state, error) = evaluate_assertions(&assertions(1500), &outcome);
        assert!(matches!(state, CheckState::Down));
        assert!(error.unwrap().contains("no text content"));
    }

    #[test]
    fn ttft_over_threshold_is_degraded_not_down() {
        let outcome = StreamOutcome { ttft_ms: Some(2000), content: "PONG".into(), ..Default::default() };
        let (state, error) = evaluate_assertions(&assertions(1500), &outcome);
        assert!(matches!(state, CheckState::Degraded));
        assert!(error.unwrap().contains("2000ms"));
    }

    #[test]
    fn content_equals_mismatch_is_degraded() {
        let mut a = assertions(1500);
        a.content_equals = Some("PONG".into());
        let outcome = StreamOutcome { ttft_ms: Some(400), content: "WRONG".into(), ..Default::default() };
        let (state, _) = evaluate_assertions(&a, &outcome);
        assert!(matches!(state, CheckState::Degraded));
    }

    #[test]
    fn content_equals_trims_whitespace_both_sides() {
        let mut a = assertions(1500);
        a.content_equals = Some("PONG".into());
        let outcome =
            StreamOutcome { ttft_ms: Some(400), content: "  PONG\n".into(), ..Default::default() };
        let (state, _) = evaluate_assertions(&a, &outcome);
        assert!(matches!(state, CheckState::Up));
    }

    // Thinking models (qwen3, deepseek-r1 without a reasoning channel) put
    // their chain-of-thought inline as a <think>…</think> block ahead of the
    // answer — assertions must run on the answer, not the scratchpad.
    #[test]
    fn think_block_is_stripped_before_content_assertions() {
        let mut a = assertions(1500);
        a.content_equals = Some("PONG".into());
        let outcome = StreamOutcome {
            ttft_ms: Some(400),
            content: "<think>\nThe user wants PONG.\n</think>\n\nPONG".into(),
            ..Default::default()
        };
        let (state, _) = evaluate_assertions(&a, &outcome);
        assert!(matches!(state, CheckState::Up));
    }

    #[test]
    fn unterminated_think_block_with_content_assertion_is_degraded() {
        let mut a = assertions(1500);
        a.content_equals = Some("PONG".into());
        // max_tokens truncation mid-reasoning: no final answer ever arrived
        let outcome = StreamOutcome {
            ttft_ms: Some(400),
            content: "<think>\nHere's a thinking process: the user".into(),
            ..Default::default()
        };
        let (state, error) = evaluate_assertions(&a, &outcome);
        assert!(matches!(state, CheckState::Degraded));
        assert!(error.unwrap().contains("only reasoning"));
    }

    #[test]
    fn reasoning_only_without_assertions_is_up() {
        // No content assertions configured — a reasoning-only stream that
        // produced tokens in time is a healthy provider.
        let outcome = StreamOutcome {
            ttft_ms: Some(400),
            content: "<think>truncated reasoning".into(),
            ..Default::default()
        };
        let (state, _) = evaluate_assertions(&assertions(1500), &outcome);
        assert!(matches!(state, CheckState::Up));
    }

    #[test]
    fn strip_think_blocks_handles_multiple_and_unterminated() {
        assert_eq!(strip_think_blocks("a<think>x</think>b<think>y</think>c"), "abc");
        assert_eq!(strip_think_blocks("<think>never closed"), "");
        assert_eq!(strip_think_blocks("no blocks"), "no blocks");
    }

    #[test]
    fn content_regex_mismatch_is_degraded() {
        let mut a = assertions(1500);
        a.content_regex = Some(r"^\d+$".into());
        let outcome =
            StreamOutcome { ttft_ms: Some(400), content: "not a number".into(), ..Default::default() };
        let (state, _) = evaluate_assertions(&a, &outcome);
        assert!(matches!(state, CheckState::Degraded));
    }

    #[test]
    fn content_regex_match_is_up() {
        let mut a = assertions(1500);
        a.content_regex = Some(r"^\d+$".into());
        let outcome = StreamOutcome { ttft_ms: Some(400), content: "42".into(), ..Default::default() };
        let (state, _) = evaluate_assertions(&a, &outcome);
        assert!(matches!(state, CheckState::Up));
    }

    #[test]
    fn invalid_json_with_format_assertion_is_degraded() {
        let mut a = assertions(1500);
        a.format = Some(LlmFormat { json_parse: true, schema: None });
        let outcome =
            StreamOutcome { ttft_ms: Some(400), content: "not json".into(), ..Default::default() };
        let (state, _) = evaluate_assertions(&a, &outcome);
        assert!(matches!(state, CheckState::Degraded));
    }

    #[test]
    fn valid_json_with_format_assertion_is_up() {
        let mut a = assertions(1500);
        a.format = Some(LlmFormat { json_parse: true, schema: None });
        let outcome = StreamOutcome {
            ttft_ms: Some(400),
            content: r#"{"status":"ok"}"#.into(),
            ..Default::default()
        };
        let (state, _) = evaluate_assertions(&a, &outcome);
        assert!(matches!(state, CheckState::Up));
    }

    #[test]
    fn all_assertions_passing_is_up() {
        let mut a = assertions(1500);
        a.content_equals = Some("PONG".into());
        let outcome = StreamOutcome { ttft_ms: Some(410), content: "PONG".into(), ..Default::default() };
        let (state, error) = evaluate_assertions(&a, &outcome);
        assert!(matches!(state, CheckState::Up));
        assert!(error.is_none());
    }

    // Fixtures below are the exact SSE excerpts from the OKS-169 spec
    // (rapport-2-real-uptime-llm-checks-synthetiques.html), reused verbatim
    // as regression fixtures for the frame/JSON extraction logic that
    // send_openai_compatible / send_anthropic hand to read_sse.
    #[test]
    fn openai_extract_text_skips_role_only_chunk_takes_content_chunk() {
        let extract = |parsed: &Value| -> Option<String> {
            parsed["choices"][0]["delta"]["content"].as_str().map(|s| s.to_string())
        };
        let role_only: Value = serde_json::from_str(
            r#"{"choices":[{"delta":{"role":"assistant"},"index":0}]}"#,
        )
        .unwrap();
        let with_content: Value = serde_json::from_str(
            r#"{"choices":[{"delta":{"content":"PONG"},"index":0}]}"#,
        )
        .unwrap();
        assert_eq!(extract(&role_only), None);
        assert_eq!(extract(&with_content), Some("PONG".to_string()));
    }

    #[test]
    fn anthropic_extract_text_only_fires_on_text_delta_type() {
        let extract = |parsed: &Value| -> Option<String> {
            if parsed["type"] == "message_stop" {
                return None;
            }
            parsed["delta"]["text"]
                .as_str()
                .filter(|_| parsed["delta"]["type"] == "text_delta")
                .map(|s| s.to_string())
        };
        let content_delta: Value = serde_json::from_str(
            r#"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"PONG"}}"#,
        )
        .unwrap();
        let message_stop: Value = serde_json::from_str(r#"{"type":"message_stop"}"#).unwrap();
        assert_eq!(extract(&content_delta), Some("PONG".to_string()));
        assert_eq!(extract(&message_stop), None);
    }
}
