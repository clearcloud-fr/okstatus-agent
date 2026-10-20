// OKS-668 — database checks: PostgreSQL, MySQL/MariaDB, MongoDB.
//
// The task's `target` is a connection URL WITHOUT credentials (the backend
// splits `user:pass@` off on every write path — shared/db-target.ts); the
// credentials arrive in `basic_auth_user` / `basic_auth_pass`, the same
// encrypted columns the HTTP check uses for Basic Auth. Any userinfo that
// does reach us is still honoured, with the explicit fields taking precedence.
//
// A check = connect, run the configured query (or the type's default), apply
// the keyword / json_path assertion to the result, report connect+query time.
// The password is scrubbed from every error message before it leaves here.
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::models::{CheckResult, CheckTask, CheckType};

pub const DEFAULT_PORT_POSTGRES: u16 = 5432;
pub const DEFAULT_PORT_MYSQL: u16 = 3306;
pub const DEFAULT_PORT_MONGODB: u16 = 27017;

/// Mirror of shared/db-target.ts parseDsn(): `scheme://[user[:pass]@]host
/// [:port][,host…][/path][?query]`. `url::Url` cannot parse MongoDB seed lists.
#[derive(Debug, Clone, PartialEq)]
pub struct Dsn {
    pub scheme: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub hosts: Vec<(String, Option<u16>)>,
    /// Path without the leading slash (the database name), empty when absent.
    pub database: String,
    pub params: HashMap<String, String>,
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub fn parse_dsn(url: &str) -> Option<Dsn> {
    let sep = url.find("://")?;
    let scheme = url[..sep].to_ascii_lowercase();
    if scheme.is_empty()
        || !scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '.' || c == '-')
    {
        return None;
    }
    let mut rest = &url[sep + 3..];
    if let Some(h) = rest.find('#') {
        rest = &rest[..h];
    }
    let (rest, query) = match rest.find('?') {
        Some(q) => (&rest[..q], &rest[q + 1..]),
        None => (rest, ""),
    };
    let (authority, path) = match rest.find('/') {
        Some(p) => (&rest[..p], &rest[p + 1..]),
        None => (rest, ""),
    };
    // The password may itself contain "@" — split on the LAST one.
    let (userinfo, hostlist) = match authority.rfind('@') {
        Some(at) => (Some(&authority[..at]), &authority[at + 1..]),
        None => (None, authority),
    };
    let (username, password) = match userinfo {
        Some(ui) => match ui.find(':') {
            Some(c) => (
                Some(percent_decode(&ui[..c])).filter(|s| !s.is_empty()),
                Some(percent_decode(&ui[c + 1..])).filter(|s| !s.is_empty()),
            ),
            None => (Some(percent_decode(ui)).filter(|s| !s.is_empty()), None),
        },
        None => (None, None),
    };
    let mut hosts = Vec::new();
    for part in hostlist.split(',') {
        let h = part.trim();
        if h.is_empty() {
            continue;
        }
        if let Some(stripped) = h.strip_prefix('[') {
            // [IPv6]:port
            if let Some(end) = stripped.find(']') {
                let host = stripped[..end].to_string();
                let port = stripped[end + 1..]
                    .strip_prefix(':')
                    .and_then(|p| p.parse::<u16>().ok());
                hosts.push((host, port));
                continue;
            }
        }
        match h.rfind(':') {
            Some(c) if h[c + 1..].chars().all(|ch| ch.is_ascii_digit()) && c > 0 => {
                hosts.push((h[..c].to_string(), h[c + 1..].parse::<u16>().ok()));
            }
            _ => hosts.push((h.to_string(), None)),
        }
    }
    if hosts.is_empty() {
        return None;
    }
    let mut params = HashMap::new();
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = match pair.find('=') {
            Some(e) => (&pair[..e], &pair[e + 1..]),
            None => (pair, ""),
        };
        params
            .entry(percent_decode(k).to_ascii_lowercase())
            .or_insert_with(|| percent_decode(v));
    }
    Some(Dsn {
        scheme,
        username,
        password,
        hosts,
        database: path.to_string(),
        params,
    })
}

fn truthy(v: Option<&String>) -> bool {
    matches!(
        v.map(|s| s.to_ascii_lowercase()).as_deref(),
        Some("true") | Some("1") | Some("yes") | Some("on")
    )
}

/// Same TLS intent rules as shared/db-target.ts dsnWantsTls().
pub fn wants_tls(kind: &CheckType, dsn: &Dsn) -> bool {
    match kind {
        CheckType::Postgres => {
            let mode = dsn
                .params
                .get("sslmode")
                .map(|s| s.to_ascii_lowercase())
                .unwrap_or_default();
            matches!(mode.as_str(), "require" | "verify-ca" | "verify-full") || truthy(dsn.params.get("ssl"))
        }
        CheckType::Mysql => {
            let mode = dsn
                .params
                .get("ssl-mode")
                .or_else(|| dsn.params.get("sslmode"))
                .map(|s| s.to_ascii_uppercase())
                .unwrap_or_default();
            matches!(mode.as_str(), "REQUIRED" | "VERIFY_CA" | "VERIFY_IDENTITY")
                || truthy(dsn.params.get("tls"))
                || truthy(dsn.params.get("ssl"))
        }
        CheckType::Mongodb => {
            dsn.scheme == "mongodb+srv" || truthy(dsn.params.get("tls")) || truthy(dsn.params.get("ssl"))
        }
        _ => false,
    }
}

/// Removes the password (raw and percent-encoded) from a driver message.
pub fn scrub(message: &str, secret: Option<&str>) -> String {
    match secret {
        Some(s) if !s.is_empty() => {
            let mut out = message.replace(s, "***");
            let encoded: String = s
                .bytes()
                .map(|b| {
                    if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
                        (b as char).to_string()
                    } else {
                        format!("%{b:02X}")
                    }
                })
                .collect();
            if encoded != s {
                out = out.replace(&encoded, "***");
            }
            out
        }
        _ => message.to_string(),
    }
}

/// The value assertions run against, once the query has returned.
enum QueryValue {
    /// SQL: first column of the first row, as text (None = no rows).
    Text(Option<String>),
    /// MongoDB: the command reply document.
    Json(serde_json::Value),
}

fn resolve_json_path<'a>(value: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    let normalized = path.trim().trim_start_matches('$').trim_start_matches('.');
    if normalized.is_empty() {
        return Some(value);
    }
    let mut current = value;
    for segment in normalized.split('.') {
        current = match current {
            serde_json::Value::Object(map) => map.get(segment)?,
            serde_json::Value::Array(arr) => arr.get(segment.parse::<usize>().ok()?)?,
            _ => return None,
        };
    }
    Some(current)
}

fn value_to_string(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

fn compare(actual: &str, op: &str, expected: &str) -> bool {
    let num = |s: &str| s.trim().parse::<f64>().ok();
    match op {
        "==" => actual == expected,
        "!=" => actual != expected,
        "contains" => actual.contains(expected),
        ">" | "<" | ">=" | "<=" => match (num(actual), num(expected)) {
            (Some(a), Some(b)) => match op {
                ">" => a > b,
                "<" => a < b,
                ">=" => a >= b,
                _ => a <= b,
            },
            _ => false,
        },
        _ => false,
    }
}

/// Mirror of shared/test-check.ts evaluateDbResult(). Returns the failure
/// message, or None when the result passes (or nothing is asserted).
fn evaluate(task: &CheckTask, value: &QueryValue) -> Option<String> {
    let as_string = || match value {
        QueryValue::Text(t) => t.clone().unwrap_or_default(),
        QueryValue::Json(j) => value_to_string(j),
    };
    if let Some(keyword) = task.keyword.as_deref().filter(|k| !k.is_empty()) {
        let found = as_string().contains(keyword);
        let matched = if task.keyword_invert.unwrap_or(false) { !found } else { found };
        if !matched {
            return Some(if task.keyword_invert.unwrap_or(false) {
                format!("Result contains '{keyword}' but should not")
            } else {
                format!("Result does not contain '{keyword}'")
            });
        }
        return None;
    }
    let (Some(op), Some(expected)) = (task.json_operator.as_deref(), task.json_expected_value.as_deref()) else {
        return None;
    };
    let actual = match (value, task.json_path.as_deref().map(str::trim)) {
        (QueryValue::Json(doc), Some(path)) if !path.is_empty() && path != "$" => match resolve_json_path(doc, path) {
            Some(v) => value_to_string(v),
            None => return Some(format!("Path '{path}' not found in result")),
        },
        _ => as_string(),
    };
    if compare(&actual, op, expected) {
        None
    } else {
        let mut shown = actual;
        if shown.len() > 200 {
            shown.truncate(200);
            shown.push('…');
        }
        Some(format!("Result check failed: {op} '{expected}' (actual: '{shown}')"))
    }
}

/// Anti-SSRF for the seed list: every host is resolved and refused if any
/// address is private — unless this is a customer's private agent (OKS-401).
/// `mongodb+srv` hosts are expanded through their SRV record first.
async fn ensure_public(dsn: &Dsn, default_port: u16) -> Result<(), String> {
    if crate::ssrf::allow_private_targets() {
        return Ok(());
    }
    let mut targets: Vec<(String, u16)> = Vec::new();
    if dsn.scheme == "mongodb+srv" {
        use hickory_resolver::net::runtime::TokioRuntimeProvider;
        use hickory_resolver::Resolver;
        // Same empty-ResolverConfig::default() trap as the DNS check (hickory
        // 0.26): every mongodb+srv SRV lookup failed "no connections available".
        let (config, options) = super::dns::default_resolver_config();
        let resolver = Resolver::builder_with_config(config, TokioRuntimeProvider::default())
            .with_options(options)
            .build()
            .map_err(|e| format!("Resolver setup failed: {e}"))?;
        for (host, _) in &dsn.hosts {
            let srv = resolver
                .lookup(format!("_mongodb._tcp.{host}"), hickory_resolver::proto::rr::RecordType::SRV)
                .await
                .map_err(|e| format!("SRV lookup failed for {host}: {e}"))?;
            for record in srv.answers() {
                if let hickory_resolver::proto::rr::RData::SRV(record) = &record.data {
                    targets.push((record.target.to_utf8().trim_end_matches('.').to_string(), record.port));
                }
            }
        }
    } else {
        for (host, port) in &dsn.hosts {
            targets.push((host.clone(), port.unwrap_or(default_port)));
        }
    }
    // Literal names/addresses first, for the whole seed list — no DNS needed
    // to refuse `…,192.168.1.10` or `db.svc.cluster.local`, and a public host
    // that fails to resolve must not hide a private one behind it.
    for (host, _) in &targets {
        if crate::ssrf::is_private_hostname(host) {
            return Err(format!("Target {host} is a private or reserved address"));
        }
    }
    for (host, port) in targets {
        let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), port))
            .await
            .map_err(|e| format!("DNS resolution failed for {host}: {e}"))?
            .collect();
        if addrs.iter().any(|a| crate::ssrf::is_private_ip(&a.ip())) {
            return Err(format!("Target {host} resolves to a private or reserved address"));
        }
    }
    Ok(())
}

pub async fn check_db(task: &CheckTask) -> CheckResult {
    let timeout = Duration::from_millis(task.timeout.unwrap_or(10_000));
    let start = Instant::now();

    let Some(dsn) = parse_dsn(&task.target) else {
        return error_result(task, &start, "Invalid database connection URL".to_string());
    };
    let (label, default_port, scheme_ok) = match task.check_type {
        CheckType::Postgres => ("PostgreSQL", DEFAULT_PORT_POSTGRES, matches!(dsn.scheme.as_str(), "postgres" | "postgresql")),
        CheckType::Mysql => ("MySQL", DEFAULT_PORT_MYSQL, matches!(dsn.scheme.as_str(), "mysql" | "mariadb")),
        CheckType::Mongodb => ("MongoDB", DEFAULT_PORT_MONGODB, matches!(dsn.scheme.as_str(), "mongodb" | "mongodb+srv")),
        _ => return error_result(task, &start, "check_db called for a non-database task".to_string()),
    };
    if !scheme_ok {
        return error_result(task, &start, format!("{label} check needs a {label}-scheme URL, got '{}://'", dsn.scheme));
    }
    let username = task.basic_auth_user.clone().filter(|s| !s.is_empty()).or_else(|| dsn.username.clone());
    let password = task.basic_auth_pass.clone().filter(|s| !s.is_empty()).or_else(|| dsn.password.clone());
    let secret = password.as_deref();

    if let Err(msg) = ensure_public(&dsn, default_port).await {
        return error_result(task, &start, msg);
    }

    let ignore_tls = task.ignore_tls == Some(true);
    let tls = wants_tls(&task.check_type, &dsn);
    let query = task
        .db_query
        .as_deref()
        .map(str::trim)
        .filter(|q| !q.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| match task.check_type {
            CheckType::Mongodb => "{ \"ping\": 1 }".to_string(),
            _ => "SELECT 1".to_string(),
        });

    let run = async {
        match task.check_type {
            CheckType::Postgres => run_postgres(&dsn, username.as_deref(), password.as_deref(), &query, tls, ignore_tls).await,
            CheckType::Mysql => run_mysql(&dsn, username.as_deref(), password.as_deref(), &query, tls, ignore_tls).await,
            _ => run_mongo(&task.target, &dsn, username.as_deref(), password.as_deref(), &query, timeout, ignore_tls).await,
        }
    };
    let value = match tokio::time::timeout(timeout, run).await {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => return error_result(task, &start, scrub(&e, secret)),
        Err(_) => return error_result(task, &start, format!("{label} check timed out after {timeout:?}")),
    };
    let latency = start.elapsed().as_millis() as u64;

    if let Some(msg) = evaluate(task, &value) {
        return CheckResult { error: Some(scrub(&msg, secret)), ..ok_result(task, latency) };
    }
    ok_result(task, latency)
}

async fn run_postgres(
    dsn: &Dsn,
    username: Option<&str>,
    password: Option<&str>,
    query: &str,
    tls: bool,
    ignore_tls: bool,
) -> Result<QueryValue, String> {
    let mut config = tokio_postgres::Config::new();
    for (host, port) in &dsn.hosts {
        config.host(host);
        config.port(port.unwrap_or(DEFAULT_PORT_POSTGRES));
    }
    if !dsn.database.is_empty() {
        config.dbname(&dsn.database);
    }
    config.user(username.unwrap_or("postgres"));
    if let Some(p) = password {
        config.password(p);
    }
    config.ssl_mode(if tls {
        tokio_postgres::config::SslMode::Require
    } else {
        tokio_postgres::config::SslMode::Prefer
    });
    config.application_name("okstatus-agent");
    let connector = native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(ignore_tls)
        .danger_accept_invalid_hostnames(ignore_tls)
        .build()
        .map_err(|e| format!("TLS setup failed: {e}"))?;
    let (client, connection) = config
        .connect(postgres_native_tls::MakeTlsConnector::new(connector))
        .await
        .map_err(|e| format!("PostgreSQL connect failed: {e}"))?;
    let conn_task = tokio::spawn(connection);
    // simple_query returns every value as text, whatever the column type.
    let result = client
        .simple_query(query)
        .await
        .map_err(|e| format!("PostgreSQL query failed: {e}"));
    drop(client);
    let _ = conn_task.await;
    let messages = result?;
    let first = messages.into_iter().find_map(|m| match m {
        tokio_postgres::SimpleQueryMessage::Row(row) => Some(row.get(0).map(str::to_string)),
        _ => None,
    });
    Ok(QueryValue::Text(first.flatten()))
}

async fn run_mysql(
    dsn: &Dsn,
    username: Option<&str>,
    password: Option<&str>,
    query: &str,
    tls: bool,
    ignore_tls: bool,
) -> Result<QueryValue, String> {
    use mysql_async::prelude::Queryable;
    let (host, port) = dsn.hosts.first().cloned().ok_or("no host")?;
    let mut opts = mysql_async::OptsBuilder::default()
        .ip_or_hostname(host)
        .tcp_port(port.unwrap_or(DEFAULT_PORT_MYSQL))
        .user(username.map(str::to_string))
        .pass(password.map(str::to_string))
        .db_name((!dsn.database.is_empty()).then(|| dsn.database.clone()))
        .prefer_socket(false)
        .stmt_cache_size(0);
    if tls {
        let mut ssl = mysql_async::SslOpts::default();
        if ignore_tls {
            ssl = ssl.with_danger_accept_invalid_certs(true).with_danger_skip_domain_validation(true);
        }
        opts = opts.ssl_opts(Some(ssl));
    }
    let mut conn = mysql_async::Conn::new(opts)
        .await
        .map_err(|e| format!("MySQL connect failed: {e}"))?;
    let rows: Result<Vec<mysql_async::Row>, _> = conn.query(query).await;
    let _ = conn.disconnect().await;
    let rows = rows.map_err(|e| format!("MySQL query failed: {e}"))?;
    let first = rows.first().and_then(|row| row.as_ref(0).map(mysql_value_to_string));
    Ok(QueryValue::Text(first))
}

fn mysql_value_to_string(v: &mysql_async::Value) -> String {
    use mysql_async::Value;
    match v {
        Value::NULL => String::new(),
        Value::Bytes(b) => String::from_utf8_lossy(b).into_owned(),
        Value::Int(i) => i.to_string(),
        Value::UInt(u) => u.to_string(),
        Value::Float(f) => f.to_string(),
        Value::Double(d) => d.to_string(),
        other => other.as_sql(true).trim_matches('\'').to_string(),
    }
}

async fn run_mongo(
    target: &str,
    dsn: &Dsn,
    username: Option<&str>,
    password: Option<&str>,
    query: &str,
    timeout: Duration,
    ignore_tls: bool,
) -> Result<QueryValue, String> {
    use mongodb::options::{ClientOptions, Credential, Tls, TlsOptions};
    let json: serde_json::Value = serde_json::from_str::<serde_json::Value>(query)
        .ok()
        .filter(|v: &serde_json::Value| v.is_object())
        .ok_or_else(|| "The MongoDB query must be a command document in JSON, e.g. { \"ping\": 1 }".to_string())?;
    let command = mongodb::bson::to_document(&json).map_err(|e| format!("Invalid command document: {e}"))?;

    // The driver parses the URL itself (seed list, replicaSet, tls, authSource…);
    // credentials are injected separately so they never need to be in it.
    let mut options = ClientOptions::parse(target)
        .await
        .map_err(|e| format!("Invalid MongoDB URL: {e}"))?;
    if let Some(user) = username {
        let mut cred = Credential::builder().username(user.to_string()).build();
        cred.password = password.map(str::to_string);
        if cred.source.is_none() {
            cred.source = dsn
                .params
                .get("authsource")
                .cloned()
                .or_else(|| (!dsn.database.is_empty()).then(|| dsn.database.clone()));
        }
        options.credential = Some(cred);
    }
    options.server_selection_timeout = Some(timeout);
    options.connect_timeout = Some(timeout);
    options.max_pool_size = Some(1);
    options.app_name = Some("okstatus-agent".to_string());
    if ignore_tls {
        options.tls = Some(Tls::Enabled(
            TlsOptions::builder().allow_invalid_certificates(true).build(),
        ));
    }
    let client = mongodb::Client::with_options(options).map_err(|e| format!("MongoDB client error: {e}"))?;
    let db = client
        .default_database()
        .unwrap_or_else(|| client.database("admin"));
    let reply = db.run_command(command).await;
    client.shutdown().await;
    let reply = reply.map_err(|e| format!("MongoDB command failed: {e}"))?;
    let json = serde_json::to_value(mongodb::bson::Bson::Document(reply).into_relaxed_extjson())
        .map_err(|e| format!("Reply serialisation failed: {e}"))?;
    Ok(QueryValue::Json(json))
}

fn ok_result(task: &CheckTask, latency: u64) -> CheckResult {
    CheckResult {
        task_id: task.task_id.clone(),
        monitor_id: task.monitor_id.clone(),
        region: task.region.clone(),
        agent_type: String::new(),
        success: true,
        latency_ms: Some(latency),
        status_code: None,
        ssl_days_left: None,
        error: None,
        state: None,
        ttft_ms: None,
        tpot_ms: None,
        itl_ms: None,
        checked_at: chrono::Utc::now().to_rfc3339(),
    }
}

fn error_result(task: &CheckTask, start: &Instant, error: String) -> CheckResult {
    CheckResult {
        success: false,
        error: Some(error),
        ..ok_result(task, start.elapsed().as_millis() as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn task(kind: CheckType, target: &str) -> CheckTask {
        serde_json::from_str(&format!(
            r#"{{"taskId":"t","monitorId":"m","orgId":"o","tenantId":"okstatus","target":"{target}","checkType":"{}","region":"fr-dc3"}}"#,
            match kind {
                CheckType::Postgres => "postgres",
                CheckType::Mysql => "mysql",
                _ => "mongodb",
            }
        ))
        .unwrap()
    }

    #[test]
    fn parses_a_mongodb_seed_list_with_credentials() {
        let dsn = parse_dsn("mongodb://test:53vukIhrF6O1wLqfS4aT@node2.example.net,node3.example.net:27018,node1.example.net/admin?replicaSet=replicaset&tls=true").unwrap();
        assert_eq!(dsn.scheme, "mongodb");
        assert_eq!(dsn.username.as_deref(), Some("test"));
        assert_eq!(dsn.password.as_deref(), Some("53vukIhrF6O1wLqfS4aT"));
        assert_eq!(
            dsn.hosts,
            vec![
                ("node2.example.net".to_string(), None),
                ("node3.example.net".to_string(), Some(27018)),
                ("node1.example.net".to_string(), None)
            ]
        );
        assert_eq!(dsn.database, "admin");
        assert_eq!(dsn.params.get("replicaset").map(String::as_str), Some("replicaset"));
        assert!(wants_tls(&CheckType::Mongodb, &dsn));
    }

    #[test]
    fn parses_ports_ipv6_and_percent_encoding() {
        let dsn = parse_dsn("postgres://app:p%40ss%3Aword@[2001:db8::1]:5433/prod?sslmode=require").unwrap();
        assert_eq!(dsn.password.as_deref(), Some("p@ss:word"));
        assert_eq!(dsn.hosts, vec![("2001:db8::1".to_string(), Some(5433))]);
        assert!(wants_tls(&CheckType::Postgres, &dsn));
        // password containing a raw "@": split on the LAST one
        assert_eq!(parse_dsn("mysql://u:a@b@db.example.com/x").unwrap().password.as_deref(), Some("a@b"));
        assert!(parse_dsn("db.example.com:5432").is_none());
        assert!(!wants_tls(&CheckType::Mysql, &parse_dsn("mysql://h/db").unwrap()));
        assert!(wants_tls(&CheckType::Mysql, &parse_dsn("mysql://h/db?ssl-mode=REQUIRED").unwrap()));
    }

    #[test]
    fn scrub_removes_raw_and_encoded_password() {
        assert_eq!(scrub("auth failed for p@ss w / p%40ss%20w", Some("p@ss w")), "auth failed for *** / ***");
        assert_eq!(scrub("nothing", None), "nothing");
    }

    #[test]
    fn evaluates_sql_scalar_and_mongo_document() {
        let mut t = task(CheckType::Postgres, "postgres://db.example.com/x");
        t.json_operator = Some("<".into());
        t.json_expected_value = Some("10".into());
        assert!(evaluate(&t, &QueryValue::Text(Some("7".into()))).is_none());
        assert!(evaluate(&t, &QueryValue::Text(Some("42".into()))).unwrap().contains("actual: '42'"));

        let mut m = task(CheckType::Mongodb, "mongodb://db.example.com/admin");
        m.json_path = Some("members.0.stateStr".into());
        m.json_operator = Some("==".into());
        m.json_expected_value = Some("PRIMARY".into());
        let doc = serde_json::json!({"ok": 1, "members": [{"stateStr": "PRIMARY"}]});
        assert!(evaluate(&m, &QueryValue::Json(doc.clone())).is_none());
        m.json_path = Some("set".into());
        assert!(evaluate(&m, &QueryValue::Json(doc)).unwrap().contains("not found"));

        let mut k = task(CheckType::Mysql, "mysql://db.example.com/x");
        k.keyword = Some("ok".into());
        assert!(evaluate(&k, &QueryValue::Text(Some("status ok".into()))).is_none());
        assert!(evaluate(&k, &QueryValue::Text(None)).is_some());
    }

    #[tokio::test]
    async fn refuses_private_targets_without_connecting() {
        crate::ssrf::set_allow_private_targets(false);
        let r = check_db(&task(CheckType::Postgres, "postgres://10.0.0.5:5432/app")).await;
        assert!(!r.success);
        assert!(r.error.as_deref().unwrap().contains("private"));
        let r = check_db(&task(CheckType::Mongodb, "mongodb://db.example.com,192.168.1.10/admin")).await;
        assert!(r.error.as_deref().unwrap().contains("private"));
        let r = check_db(&task(CheckType::Mysql, "mysql://mysql.okstatus.svc.cluster.local/x")).await;
        assert!(r.error.as_deref().unwrap().contains("private"));
    }

    // Run by hand against a real server:
    //   OKS_TEST_DB_URL='mongodb://user:pw@host1,host2/admin?replicaSet=rs&tls=true' \
    //   OKS_TEST_DB_TYPE=mongodb cargo test live_database_check -- --ignored --nocapture
    #[tokio::test]
    #[ignore]
    async fn live_database_check() {
        let Ok(url) = std::env::var("OKS_TEST_DB_URL") else { return };
        let kind = match std::env::var("OKS_TEST_DB_TYPE").as_deref() {
            Ok("postgres") => CheckType::Postgres,
            Ok("mysql") => CheckType::Mysql,
            _ => CheckType::Mongodb,
        };
        let mut t = task(kind, &url);
        t.timeout = Some(20_000);
        t.db_query = std::env::var("OKS_TEST_DB_QUERY").ok();
        let r = check_db(&t).await;
        eprintln!("live result: {r:?}");
        assert!(r.success, "{:?}", r.error);
        // whatever happened, the password must not appear in the result
        if let Some(dsn) = parse_dsn(&url) {
            if let Some(pw) = dsn.password {
                assert!(!format!("{r:?}").contains(&pw));
            }
        }
    }

    #[tokio::test]
    async fn refuses_a_scheme_that_does_not_match_the_type() {
        let r = check_db(&task(CheckType::Postgres, "mysql://db.example.com/app")).await;
        assert!(!r.success);
        assert!(r.error.as_deref().unwrap().contains("PostgreSQL"));
    }
}
