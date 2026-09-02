// OKS-474 — gRPC health checks: standard `grpc.health.v1.Health/Check`
// against the monitor's target.
//
// Target format (monitor.url): `[scheme://]host:port[/service]`
//   - scheme `grpcs` (or `https`) → TLS; `grpc` (or `http`) → plaintext;
//     no scheme → TLS iff port is 443, plaintext otherwise
//   - optional path = the service name passed in HealthCheckRequest
//     (empty = overall server health, per the health protocol spec)
//
// Result mapping:
//   SERVING                        → success
//   NOT_SERVING / SERVICE_UNKNOWN  → failure with the reported status
//   Unimplemented                  → success ("server answered over gRPC but
//     doesn't expose the health service" — the transport + HTTP/2 + gRPC
//     stack all work, which is what an uptime check fundamentally asserts;
//     the error field still says so, for visibility in the event log)
//   connect/TLS/timeout errors     → failure

use std::time::{Duration, Instant};

use tonic::transport::{ClientTlsConfig, Endpoint};
use tonic::Code;
use tonic_health::pb::health_check_response::ServingStatus;
use tonic_health::pb::health_client::HealthClient;
use tonic_health::pb::HealthCheckRequest;

use crate::models::{CheckResult, CheckTask};

struct GrpcTarget {
    uri: String,
    tls: bool,
    service: String,
}

fn parse_target(raw: &str) -> Result<GrpcTarget, String> {
    let (scheme, rest) = match raw.split_once("://") {
        Some((s, r)) => (Some(s.to_ascii_lowercase()), r),
        None => (None, raw),
    };

    let (authority, service) = match rest.split_once('/') {
        Some((a, s)) => (a, s.to_string()),
        None => (rest, String::new()),
    };
    if authority.is_empty() {
        return Err("empty gRPC target".into());
    }

    let port: Option<u16> = authority.rsplit_once(':').and_then(|(_, p)| p.parse().ok());

    let tls = match scheme.as_deref() {
        Some("grpcs") | Some("https") => true,
        Some("grpc") | Some("http") => false,
        Some(other) => return Err(format!("unsupported gRPC scheme '{other}'")),
        None => port == Some(443),
    };

    // tonic wants a full http(s) URI; default gRPC port 443/80 by TLS.
    let uri = if port.is_some() {
        format!("{}://{}", if tls { "https" } else { "http" }, authority)
    } else {
        format!(
            "{}://{}:{}",
            if tls { "https" } else { "http" },
            authority,
            if tls { 443 } else { 80 }
        )
    };

    Ok(GrpcTarget { uri, tls, service })
}

pub async fn check_grpc(task: &CheckTask) -> CheckResult {
    let timeout = Duration::from_millis(task.timeout.unwrap_or(10_000));
    let start = Instant::now();

    let target = match parse_target(&task.target) {
        Ok(t) => t,
        Err(e) => return result(task, &start, false, None, Some(e)),
    };

    let endpoint = match Endpoint::from_shared(target.uri.clone()) {
        Ok(e) => e,
        Err(e) => return result(task, &start, false, None, Some(format!("invalid gRPC target: {e}"))),
    };
    let mut endpoint = endpoint.connect_timeout(timeout).timeout(timeout);
    if target.tls {
        endpoint = match endpoint.tls_config(ClientTlsConfig::new().with_enabled_roots()) {
            Ok(e) => e,
            Err(e) => return result(task, &start, false, None, Some(format!("TLS config error: {e}"))),
        };
    }

    let channel = match tokio::time::timeout(timeout, endpoint.connect()).await {
        Ok(Ok(ch)) => ch,
        Ok(Err(e)) => return result(task, &start, false, None, Some(format!("gRPC connect failed: {e}"))),
        Err(_) => return result(task, &start, false, None, Some(format!("gRPC connect timeout after {timeout:?}"))),
    };

    let mut client = HealthClient::new(channel);
    let request = HealthCheckRequest { service: target.service.clone() };

    match tokio::time::timeout(timeout, client.check(request)).await {
        Ok(Ok(resp)) => {
            let latency = start.elapsed().as_millis() as u64;
            let status = resp.into_inner().status();
            match status {
                ServingStatus::Serving => result(task, &start, true, Some(latency), None),
                other => result(
                    task,
                    &start,
                    false,
                    Some(latency),
                    Some(format!("gRPC health status: {other:?}")),
                ),
            }
        }
        Ok(Err(status)) if status.code() == Code::Unimplemented => {
            // Server is alive and speaking gRPC — it just doesn't expose
            // grpc.health.v1. Counted as up (see module docs).
            let latency = start.elapsed().as_millis() as u64;
            result(
                task,
                &start,
                true,
                Some(latency),
                Some("gRPC server up (health service unimplemented)".into()),
            )
        }
        Ok(Err(status)) => result(
            task,
            &start,
            false,
            None,
            Some(format!("gRPC error: {} ({:?})", status.message(), status.code())),
        ),
        Err(_) => result(task, &start, false, None, Some(format!("gRPC check timeout after {timeout:?}"))),
    }
}

fn result(
    task: &CheckTask,
    start: &Instant,
    success: bool,
    latency_ms: Option<u64>,
    error: Option<String>,
) -> CheckResult {
    CheckResult {
        task_id: task.task_id.clone(),
        monitor_id: task.monitor_id.clone(),
        region: task.region.clone(),
        agent_type: String::new(),
        success,
        latency_ms: latency_ms.or(Some(start.elapsed().as_millis() as u64)),
        status_code: None,
        ssl_days_left: None,
        state: None,
        ttft_ms: None,
        tpot_ms: None,
        itl_ms: None,
        error,
        checked_at: chrono::Utc::now().to_rfc3339(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bare_host_port_as_plaintext() {
        let t = parse_target("api.internal:50051").unwrap();
        assert_eq!(t.uri, "http://api.internal:50051");
        assert!(!t.tls);
        assert_eq!(t.service, "");
    }

    #[test]
    fn port_443_defaults_to_tls() {
        let t = parse_target("api.example.com:443").unwrap();
        assert_eq!(t.uri, "https://api.example.com:443");
        assert!(t.tls);
    }

    #[test]
    fn grpcs_scheme_and_service_path() {
        let t = parse_target("grpcs://api.example.com:8443/my.pkg.Service").unwrap();
        assert_eq!(t.uri, "https://api.example.com:8443");
        assert!(t.tls);
        assert_eq!(t.service, "my.pkg.Service");
    }

    #[test]
    fn grpc_scheme_forces_plaintext_even_on_443() {
        let t = parse_target("grpc://api.example.com:443").unwrap();
        assert!(!t.tls);
    }

    #[test]
    fn unsupported_scheme_is_rejected() {
        assert!(parse_target("ftp://api.example.com:21").is_err());
        assert!(parse_target("grpcs://").is_err());
    }
}
