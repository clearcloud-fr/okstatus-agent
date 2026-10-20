use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use base64::Engine;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

use crate::models::{CheckResult, CheckTask};

// Accept a shared client (built once at startup) to avoid rebuilding the native-tls
// context on every check — per-task timeout is set at the request level.
pub async fn check_http(client: &reqwest::Client, task: &CheckTask) -> CheckResult {
    let timeout = Duration::from_millis(task.timeout.unwrap_or(5_000));
    let start = Instant::now();

    // Build custom headers
    let mut headers = HeaderMap::new();
    if let Some(ref custom) = task.http_headers {
        for (key, value) in custom {
            if let (Ok(name), Ok(val)) = (
                HeaderName::from_bytes(key.as_bytes()),
                HeaderValue::from_str(value),
            ) {
                headers.insert(name, val);
            }
        }
    }
    // Basic Auth
    if let (Some(ref user), Some(ref pass)) = (&task.basic_auth_user, &task.basic_auth_pass) {
        let encoded = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"));
        if let Ok(val) = HeaderValue::from_str(&format!("Basic {encoded}")) {
            headers.insert(reqwest::header::AUTHORIZATION, val);
        }
    }

    // Authentification non-Basic (auth.rs). Bearer / clé d'API / cookie ne
    // touchent qu'aux en-têtes et à l'URL ; OAuth2 demande d'abord un jeton
    // (mis en cache jusqu'à expiration) ; mTLS impose son propre client.
    let auth = crate::auth::parse(task.auth_config.as_ref());
    let mut authed_target = task.target.clone();
    if let Some(ref auth) = auth {
        authed_target = crate::auth::apply_static(auth, &mut headers, authed_target);
    }
    if let Some(crate::auth::MonitorAuth::Oauth2(ref oauth)) = auth {
        // Le jeton se prend sur le budget de temps du check : un IdP lent
        // doit se voir dans la latence, pas déborder silencieusement.
        let remaining = timeout.saturating_sub(start.elapsed());
        if remaining.is_zero() {
            return error_result(task, &start, "Timeout before the OAuth2 token request".into());
        }
        match crate::auth::oauth2_token(client, oauth, remaining).await {
            Ok(token) => {
                if let Ok(value) = HeaderValue::from_str(&format!("Bearer {token}")) {
                    headers.insert(reqwest::header::AUTHORIZATION, value);
                }
            }
            // Panne de l'émetteur de jetons ≠ panne de la cible : le message
            // doit le dire, sinon on cherche au mauvais endroit.
            Err(e) => return error_result(task, &start, format!("OAuth2 authentication failed: {e}")),
        }
    }

    // OKS-472 — per-monitor TLS validation opt-out: swap in the shared
    // insecure client (falls back to the normal one if it failed to build).
    // Un client mTLS, lui, porte déjà le réglage de vérification.
    let mtls_client = match auth {
        Some(crate::auth::MonitorAuth::Mtls(ref mtls)) => {
            match crate::auth::mtls_client(mtls, task.ignore_tls == Some(true)) {
                Ok(c) => Some(c),
                Err(e) => return error_result(task, &start, format!("mTLS setup failed: {e}")),
            }
        }
        _ => None,
    };
    let client = if let Some(ref client) = mtls_client {
        client
    } else if task.ignore_tls == Some(true) {
        INSECURE_CLIENT.as_ref().unwrap_or(client)
    } else {
        client
    };

    // OKS-471 — request method (default GET) and optional body for the
    // methods that carry one; the encoding picks Content-Type unless the
    // custom headers already set it.
    let method = task
        .http_method
        .as_deref()
        .and_then(|m| reqwest::Method::from_bytes(m.to_uppercase().as_bytes()).ok())
        .unwrap_or(reqwest::Method::GET);
    let send_body = task
        .http_body
        .as_deref()
        .filter(|b| !b.is_empty() && method != reqwest::Method::GET && method != reqwest::Method::HEAD);
    if send_body.is_some() && !headers.contains_key(reqwest::header::CONTENT_TYPE) {
        let content_type = match task.http_body_encoding.as_deref() {
            Some("form") => "application/x-www-form-urlencoded",
            Some("xml") => "application/xml",
            Some("text") => "text/plain",
            _ => "application/json",
        };
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            HeaderValue::from_static(content_type),
        );
    }

    // OKS-592 — manual redirect loop. The client keeps Policy::none (UPT-48):
    // following automatically would skip SSRF validation of intermediate
    // hops. Each Location target is resolved and checked against the private
    // IP guard before being fetched; the whole chain shares the check's one
    // timeout budget, and the final response is what gets classified.
    let follow_redirects = task.follow_redirects.unwrap_or(true);
    let mut current_target = authed_target;
    let mut hops = 0u8;

    // OKS-668 — the same private-address guard the redirect hops get, on the
    // first hop. The backend only vets the literal hostname at creation time;
    // a public name pointed at 10.x afterwards (or resolving differently from
    // inside our network) reached this request unchecked.
    if !crate::ssrf::allow_private_targets() {
        if let Ok(url) = reqwest::Url::parse(&current_target) {
            let host = url.host_str().unwrap_or_default().to_string();
            let port = url.port_or_known_default().unwrap_or(443);
            if crate::ssrf::is_private_hostname(&host) {
                return error_result(task, &start, format!("Target is a private address: {host}"));
            }
            if let Ok(addrs) = tokio::net::lookup_host(format!("{host}:{port}")).await {
                if addrs.into_iter().any(|a| crate::ssrf::is_private_ip(&a.ip())) {
                    return error_result(task, &start, format!("Target resolves to a private address: {host}"));
                }
            }
        }
    }

    let resp = loop {
        let elapsed = start.elapsed();
        if elapsed >= timeout {
            return error_result(task, &start, "Timeout while following redirects".into());
        }
        let mut request = client
            .request(method.clone(), &current_target)
            .timeout(timeout - elapsed)
            .headers(headers.clone());
        // Only the first request carries the configured body — a redirect is
        // followed as a plain GET-style fetch of the new location.
        if hops == 0 {
            if let Some(body) = send_body {
                request = request.body(body.to_string());
            }
        }

        let resp = match request.send().await {
            Ok(r) => r,
            Err(e) => return error_result(task, &start, error_chain(&e)),
        };

        let status = resp.status().as_u16();
        let is_redirect = matches!(status, 301 | 302 | 303 | 307 | 308);
        // A 3xx the monitor explicitly accepts is a final answer, not a hop.
        if !follow_redirects
            || !is_redirect
            || is_status_accepted(status, task.accepted_status_codes.as_deref())
        {
            break resp;
        }

        let Some(location) = resp
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
        else {
            break resp; // 3xx without Location — classify it as-is
        };

        hops += 1;
        if hops > 5 {
            return error_result(task, &start, "Too many redirects (more than 5)".into());
        }

        // Resolve relative Locations against the URL that issued them.
        let next_url = match reqwest::Url::parse(&current_target)
            .ok()
            .and_then(|base| base.join(&location).ok())
        {
            Some(u) if u.scheme() == "http" || u.scheme() == "https" => u,
            _ => {
                return error_result(
                    task,
                    &start,
                    format!("Redirect to unsupported location: {location}"),
                )
            }
        };

        // Anti-SSRF (UPT-48): a public target must not redirect the probe
        // into private address space. DNS is resolved here for the guard;
        // reqwest resolves again for the actual request — the residual
        // TOCTOU window is accepted, same as the guard on DNS servers.
        if !crate::ssrf::allow_private_targets() {
            let host = next_url.host_str().unwrap_or_default().to_string();
            let port = next_url.port_or_known_default().unwrap_or(443);
            let resolved: Result<Vec<std::net::SocketAddr>, _> =
                tokio::net::lookup_host(format!("{host}:{port}"))
                    .await
                    .map(|addrs| addrs.collect());
            match resolved {
                Ok(addrs) => {
                    if addrs.iter().any(|a| crate::ssrf::is_private_ip(&a.ip())) {
                        return error_result(
                            task,
                            &start,
                            format!("Redirect to private address blocked: {host}"),
                        );
                    }
                }
                Err(_) => {
                    return error_result(
                        task,
                        &start,
                        format!("Redirect target DNS resolution failed: {host}"),
                    )
                }
            }
        }

        // Drain the redirect response so its pooled connection stays usable.
        let _ = resp.bytes().await;
        current_target = next_url.to_string();
    };

    let latency = start.elapsed().as_millis() as u64;
    let status = resp.status().as_u16();
    let status_ok = is_status_accepted(status, task.accepted_status_codes.as_deref());
    let ssl_days_left = extract_ssl_days(&task.target, timeout).await;

    // Capture body for keyword/JSON matching (limit 1MB)
    let needs_body = task.keyword.is_some() || task.json_path.is_some();
    let body_text = if needs_body {
        read_body_capped(resp, BODY_CAP_BYTES).await
    } else {
        drop(resp);
        None
    };

    let (body_match, body_error) = evaluate_body_match(task, body_text.as_deref());
    let success = status_ok && body_match;

    CheckResult {
        task_id: task.task_id.clone(),
        monitor_id: task.monitor_id.clone(),
        region: task.region.clone(),
        agent_type: String::new(),
        success,
        latency_ms: Some(latency),
        status_code: Some(status),
        ssl_days_left,
        error: body_error,
        state: None,
        ttft_ms: None,
        tpot_ms: None,
        itl_ms: None,
        checked_at: chrono::Utc::now().to_rfc3339(),
    }
}

/// Evaluate keyword or JSON matching on the response body.
/// Returns (match_success, optional_error_message).
fn evaluate_body_match(task: &CheckTask, body: Option<&str>) -> (bool, Option<String>) {
    // Keyword matching
    if let Some(ref keyword) = task.keyword {
        let Some(body) = body else {
            return (false, Some("Failed to read response body for keyword match".into()));
        };
        let found = body.contains(keyword.as_str());
        let invert = task.keyword_invert.unwrap_or(false);
        let matched = if invert { !found } else { found };
        if !matched {
            let msg = if invert {
                format!("Keyword '{}' was found but should be absent", keyword)
            } else {
                format!("Keyword '{}' not found in response body", keyword)
            };
            return (false, Some(msg));
        }
        return (true, None);
    }

    // JSON path matching
    if let Some(ref json_path) = task.json_path {
        let Some(body) = body else {
            return (false, Some("Failed to read response body for JSON match".into()));
        };

        // "$" alone = compare the raw (trimmed) body as a string, no JSON
        // parse — for plain-text endpoints ("OK", "pong"…). Otherwise a
        // simple dot-notation path traversal (e.g. "data.status",
        // "items.0.name"); a leading "$." is accepted and ignored.
        let actual_str = if json_path.trim() == "$" {
            body.trim().to_string()
        } else {
            let parsed: serde_json::Value = match serde_json::from_str(body) {
                Ok(v) => v,
                Err(e) => return (false, Some(format!("JSON parse error: {e}"))),
            };
            let value = resolve_json_path(&parsed, json_path);
            let Some(value) = value else {
                return (false, Some(format!("JSON path '{}' not found", json_path)));
            };
            match value {
                serde_json::Value::String(s) => s.to_string(),
                other => other.to_string(),
            }
        };

        let Some(ref operator) = task.json_operator else {
            // No operator = just check path exists
            return (true, None);
        };
        let Some(ref expected) = task.json_expected_value else {
            return (true, None);
        };

        let matched = match operator.as_str() {
            "==" => actual_str == *expected,
            "!=" => actual_str != *expected,
            "contains" => actual_str.contains(expected.as_str()),
            ">" | "<" | ">=" | "<=" => {
                match (actual_str.parse::<f64>(), expected.parse::<f64>()) {
                    (Ok(a), Ok(e)) => match operator.as_str() {
                        ">"  => a > e,
                        "<"  => a < e,
                        ">=" => a >= e,
                        "<=" => a <= e,
                        _ => false,
                    },
                    _ => false,
                }
            }
            _ => false,
        };

        if !matched {
            return (false, Some(format!(
                "JSON match failed: '{}' {} '{}' (actual: '{}')",
                json_path, operator, expected, actual_str
            )));
        }
        return (true, None);
    }

    // No body matching configured
    (true, None)
}

/// Resolve a simple dot-notation JSON path (e.g. "data.status", "items.0.name").
fn resolve_json_path<'a>(value: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    let mut current = value;
    let path = path.trim();
    let path = path.strip_prefix("$.").or_else(|| path.strip_prefix('$')).unwrap_or(path);
    if path.is_empty() {
        return Some(current);
    }
    for segment in path.split('.') {
        if let Ok(idx) = segment.parse::<usize>() {
            current = current.get(idx)?;
        } else {
            current = current.get(segment)?;
        }
    }
    Some(current)
}

/// Check if the HTTP status code is in the accepted list.
/// Format: each entry is either "NNN" (single code) or "NNN-NNN" (range).
/// Default: 200-299 if no codes provided.
fn is_status_accepted(status: u16, accepted: Option<&[String]>) -> bool {
    let codes = match accepted {
        Some(c) if !c.is_empty() => c,
        _ => return (200..=299).contains(&status),
    };

    for entry in codes {
        if let Some((start_s, end_s)) = entry.split_once('-') {
            if let (Ok(start), Ok(end)) = (start_s.parse::<u16>(), end_s.parse::<u16>()) {
                if (start..=end).contains(&status) {
                    return true;
                }
            }
        } else if let Ok(code) = entry.parse::<u16>() {
            if code == status {
                return true;
            }
        }
    }

    false
}

/// The whole cause chain of a request error, outermost first.
///
/// reqwest's Display stops at "error sending request for url (…)": for a
/// refused client certificate, an unknown server CA or a reset, the only
/// reason the user could act on lived in `source()`, and the check history
/// said nothing more (QA auth server, 2026-09-14). Secrets that a cause might
/// quote are scrubbed afterwards by `execute_check`.
fn error_chain(error: &(dyn std::error::Error + 'static)) -> String {
    let mut message = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        let text = cause.to_string();
        if !text.is_empty() && !message.contains(&text) {
            message.push_str(": ");
            message.push_str(&text);
        }
        source = cause.source();
    }
    message
}

fn error_result(task: &CheckTask, start: &Instant, error: String) -> CheckResult {
    CheckResult {
        task_id: task.task_id.clone(),
        monitor_id: task.monitor_id.clone(),
        region: task.region.clone(),
        agent_type: String::new(),
        success: false,
        latency_ms: Some(start.elapsed().as_millis() as u64),
        status_code: None,
        ssl_days_left: None,
        error: Some(error),
        state: None,
        ttft_ms: None,
        tpot_ms: None,
        itl_ms: None,
        checked_at: chrono::Utc::now().to_rfc3339(),
    }
}

// OKS-415 — this extra handshake used to run on every single HTTPS check,
// unbounded: a target that accepts TCP but never completes the TLS handshake
// held a semaphore permit forever and (with the batch barrier in main.rs)
// froze the whole agent. Days-left moves once a day, so one probe per host
// per hour is plenty; failures are retried sooner so a cert swap after an
// outage isn't masked for a full hour.
const SSL_CACHE_OK_TTL: Duration = Duration::from_secs(3600);
const SSL_CACHE_ERR_TTL: Duration = Duration::from_secs(300);

struct SslCacheEntry {
    expires_at: Instant,
    days_left: Option<i64>,
}

static SSL_CACHE: LazyLock<Mutex<HashMap<String, SslCacheEntry>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

// OKS-472 — client for monitors that opt out of TLS validation. Built once
// (same reason as the shared check client) and only ever used when a task
// carries ignore_tls=true; same no-redirect policy (anti-SSRF, UPT-48).
static INSECURE_CLIENT: LazyLock<Option<reqwest::Client>> = LazyLock::new(|| {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::none())
        .dns_resolver(std::sync::Arc::new(crate::ssrf::GuardedResolver)) // F7
        .build()
        .ok()
});

// Building a native-tls connector loads the CA bundle from disk — done once,
// not per check (same reason the reqwest check client is shared).
static SSL_CONNECTOR: LazyLock<Option<tokio_native_tls::TlsConnector>> = LazyLock::new(|| {
    native_tls::TlsConnector::new()
        .ok()
        .map(tokio_native_tls::TlsConnector::from)
});

/// Extract SSL certificate days remaining via TLS handshake + x509-parser.
/// Returns None for non-HTTPS targets or on any TLS/parsing error.
/// Bounded by `timeout` and cached per host (see SSL_CACHE above).
async fn extract_ssl_days(url: &str, timeout: Duration) -> Option<i64> {
    if !url.starts_with("https://") {
        return None;
    }

    let host = url
        .strip_prefix("https://")
        .and_then(|s| s.split('/').next())
        .and_then(|s| s.split(':').next())?;

    if let Ok(cache) = SSL_CACHE.lock() {
        if let Some(entry) = cache.get(host) {
            if entry.expires_at > Instant::now() {
                return entry.days_left;
            }
        }
    }

    let days_left = tokio::time::timeout(timeout, fetch_ssl_days(host))
        .await
        .ok()
        .flatten();

    let ttl = if days_left.is_some() { SSL_CACHE_OK_TTL } else { SSL_CACHE_ERR_TTL };
    if let Ok(mut cache) = SSL_CACHE.lock() {
        // Drop expired entries so the map stays bounded by the live host set.
        cache.retain(|_, entry| entry.expires_at > Instant::now());
        cache.insert(
            host.to_string(),
            SslCacheEntry { expires_at: Instant::now() + ttl, days_left },
        );
    }

    days_left
}

async fn fetch_ssl_days(host: &str) -> Option<i64> {
    let connector = SSL_CONNECTOR.as_ref()?;
    let addr = format!("{host}:443");

    let tcp = tokio::net::TcpStream::connect(&addr).await.ok()?;
    let tls = connector.connect(host, tcp).await.ok()?;

    // Get peer certificate DER bytes
    let cert = tls.get_ref().peer_certificate().ok()??;
    let der = cert.to_der().ok()?;

    // Parse with x509-parser to extract notAfter
    let (_, x509) = x509_parser::parse_x509_certificate(&der).ok()?;
    let not_after = x509.validity().not_after;

    // Convert ASN1Time to timestamp
    let expiry_ts = not_after.timestamp();
    let now_ts = chrono::Utc::now().timestamp();
    let days_left = (expiry_ts - now_ts) / 86_400;

    Some(days_left)
}

/// Upper bound on what a keyword/JSON check will read from a target.
const BODY_CAP_BYTES: usize = 1_048_576;

/// OKS-414 #10 — read at most `cap` bytes of the body, chunk by chunk, and
/// stop pulling from the socket once the cap is reached. `resp.text()` used
/// to buffer the *whole* body first and only then slice it, so one target
/// answering a multi-GB body could spike the shared agent's memory. The
/// lossy UTF-8 conversion also removes the old panic risk of slicing a
/// String on a non-char boundary.
async fn read_body_capped(mut resp: reqwest::Response, cap: usize) -> Option<String> {
    let mut buf: Vec<u8> = Vec::new();
    loop {
        match resp.chunk().await {
            Ok(Some(chunk)) => {
                let room = cap - buf.len();
                if chunk.len() >= room {
                    buf.extend_from_slice(&chunk[..room]);
                    break;
                }
                buf.extend_from_slice(&chunk);
            }
            Ok(None) => break,
            Err(_) => return None,
        }
    }
    Some(String::from_utf8_lossy(&buf).into_owned())
}

#[cfg(test)]
mod error_chain_tests {
    use super::error_chain;
    use std::fmt;

    #[derive(Debug)]
    struct Layer(&'static str, Option<Box<Layer>>);
    impl fmt::Display for Layer {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(self.0)
        }
    }
    impl std::error::Error for Layer {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            self.1.as_deref().map(|l| l as &(dyn std::error::Error + 'static))
        }
    }

    #[test]
    fn keeps_the_root_cause_a_tls_failure_hides_behind() {
        let err = Layer(
            "error sending request for url (https://auth.internal:8443/mtls)",
            Some(Box::new(Layer(
                "client error (Connect)",
                Some(Box::new(Layer("tlsv13 alert certificate required", None))),
            ))),
        );
        assert_eq!(
            error_chain(&err),
            "error sending request for url (https://auth.internal:8443/mtls): client error (Connect): tlsv13 alert certificate required"
        );
    }

    #[test]
    fn does_not_repeat_a_cause_already_in_the_message() {
        let err = Layer("timed out: operation timed out", Some(Box::new(Layer("operation timed out", None))));
        assert_eq!(error_chain(&err), "timed out: operation timed out");
    }
}
