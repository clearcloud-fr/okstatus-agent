//! Checks SMTP / IMAP / Redis.
//!
//! Les trois protocoles sont parlés à la main sur le socket, sans crate
//! cliente : ce sont trois dialogues de quelques lignes, et une dépendance de
//! plus est une surface de CVE de plus dans une image que l'on vient de
//! ramener à zéro vulnérabilité (OKS-689, agent distroless).
//!
//! Le backend exécute EXACTEMENT le même dialogue pour le bouton « Tester »
//! (`src/shared/service-probe.ts`) : les deux doivent rester d'accord sur ce
//! qui vaut succès, sinon un test vert produit un monitor rouge.
//!
//! Identifiants : `basic_auth_user` / `basic_auth_pass` (chiffrés en base),
//! jamais dans l'URL — même règle que les monitors base de données.
//!
//! TLS, trois formes :
//!   - implicite (`smtps` 465, `imaps` 993, `rediss`) : TLS dès la connexion
//!   - STARTTLS  (`smtp` 587, `imap` 143) : passage en TLS après négociation
//!   - aucune    (Redis 6379, MTA interne en clair)

use std::time::{Duration, Instant};

use base64::Engine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_native_tls::TlsStream;

use crate::models::{CheckResult, CheckTask, CheckType};

/// Nom annoncé dans EHLO : un MTA correct exige un argument.
const EHLO_NAME: &str = "okstatus.eu";

/// Garde-fou de lecture : aucune réponse légitime de ces protocoles n'est
/// volumineuse (une bannière, des capacités, un +PONG).
const MAX_RESPONSE_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq)]
enum TlsMode {
    Implicit,
    StartTls,
    None,
}

struct ServiceTarget {
    host: String,
    port: u16,
    tls: TlsMode,
}

pub async fn check_service(task: &CheckTask) -> CheckResult {
    let timeout = Duration::from_millis(task.timeout.unwrap_or(10_000));
    let start = Instant::now();

    let kind = match task.check_type {
        CheckType::Smtp => "smtp",
        CheckType::Imap => "imap",
        CheckType::Redis => "redis",
        // check_service n'est appelé que pour ces trois types (main.rs).
        _ => return result(task, &start, false, Some("unsupported check type".into())),
    };

    let target = match resolve_target(kind, &task.target, task.port) {
        Ok(t) => t,
        Err(e) => return result(task, &start, false, Some(e)),
    };

    // Même garde que tcp.rs : pas de balayage du réseau où tourne l'agent
    // partagé (OKS-414 #5).
    if let Err(e) = crate::ssrf::check_public_target(&target.host, target.port).await {
        return result(task, &start, false, Some(e));
    }

    let insecure = task.ignore_tls == Some(true);
    let deadline = start + timeout;

    let outcome = match Session::connect(&target, deadline, insecure).await {
        Ok(mut session) => {
            let dialogue = match kind {
                "smtp" => smtp_dialogue(&mut session, &target, task, insecure).await,
                "imap" => imap_dialogue(&mut session, &target, task, insecure).await,
                _ => redis_dialogue(&mut session, task).await,
            };
            session.close().await;
            dialogue
        }
        Err(e) => Err(e),
    };

    match outcome {
        Ok(()) => result(task, &start, true, None),
        // Le mot de passe peut revenir dans le message d'un serveur bavard.
        Err(e) => result(task, &start, false, Some(scrub(&e, task.basic_auth_pass.as_deref()))),
    }
}

/* ------------------------------- cible ---------------------------------- */

fn resolve_target(kind: &str, raw: &str, port_override: Option<u16>) -> Result<ServiceTarget, String> {
    let (plain_scheme, secure_scheme, default_plain, default_secure) = match kind {
        "smtp" => ("smtp", "smtps", 587u16, 465u16),
        "imap" => ("imap", "imaps", 143, 993),
        _ => ("redis", "rediss", 6379, 6379),
    };

    let (scheme, rest) = match raw.split_once("://") {
        Some((s, r)) => (Some(s.to_ascii_lowercase()), r),
        None => (None, raw),
    };

    // Un `?starttls=false` explicite pour les MTA internes en clair.
    let (authority, query) = match rest.split_once('?') {
        Some((a, q)) => (a, Some(q.to_ascii_lowercase())),
        None => (rest, None),
    };
    // Le chemin (numéro de base Redis) n'entre pas dans la cible réseau.
    let authority = authority.split('/').next().unwrap_or(authority);
    if authority.is_empty() {
        return Err(format!("empty {} target", kind.to_uppercase()));
    }

    let secure_scheme_used = match scheme.as_deref() {
        Some(s) if s == secure_scheme => true,
        Some(s) if s == plain_scheme => false,
        Some(other) => {
            return Err(format!(
                "unsupported scheme '{other}' for a {} monitor (expected {plain_scheme}:// or {secure_scheme}://)",
                kind.to_uppercase()
            ))
        }
        None => false,
    };

    let (host, port_from_url) = split_host_port(authority);
    if host.is_empty() {
        return Err(format!("empty host in {} target", kind.to_uppercase()));
    }
    let port = port_from_url
        .or(port_override)
        .unwrap_or(if secure_scheme_used { default_secure } else { default_plain });

    // Un port « sécurisé » vaut TLS implicite même sans schéma : `host:993`
    // est de l'IMAPS, pas de l'IMAP en clair.
    let starttls_disabled = query
        .as_deref()
        .map(|q| q.contains("starttls=false") || q.contains("starttls=0") || q.contains("starttls=off"))
        .unwrap_or(false);
    let tls = if secure_scheme_used || (kind != "redis" && port == default_secure) {
        TlsMode::Implicit
    } else if kind == "redis" || starttls_disabled {
        TlsMode::None
    } else {
        TlsMode::StartTls
    };

    Ok(ServiceTarget { host: host.to_string(), port, tls })
}

fn split_host_port(authority: &str) -> (&str, Option<u16>) {
    if let Some(rest) = authority.strip_prefix('[') {
        // [IPv6]:port
        if let Some((host, tail)) = rest.split_once(']') {
            let port = tail.strip_prefix(':').and_then(|p| p.parse().ok());
            return (host, port);
        }
        return (rest, None);
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if port.chars().all(|c| c.is_ascii_digit()) && !port.is_empty() => {
            (host, port.parse().ok())
        }
        _ => (authority, None),
    }
}

/* -------------------------------- SMTP ---------------------------------- */

async fn smtp_dialogue(
    session: &mut Session,
    target: &ServiceTarget,
    task: &CheckTask,
    insecure: bool,
) -> Result<(), String> {
    let banner = session.read_response(smtp_complete).await?;
    require_smtp_code(&banner, "220", "SMTP greeting")?;

    let mut capabilities = smtp_ehlo(session).await?;

    if target.tls == TlsMode::StartTls {
        if !capabilities.to_uppercase().contains("STARTTLS") {
            return Err(
                "Server does not advertise STARTTLS on this port — use the implicit-TLS port (465) or add ?starttls=false"
                    .into(),
            );
        }
        session.write("STARTTLS\r\n").await?;
        require_smtp_code(&session.read_response(smtp_complete).await?, "220", "STARTTLS")?;
        session.upgrade_tls(&target.host, insecure).await?;
        // Les capacités d'avant TLS ne valent plus rien : AUTH n'apparaît
        // typiquement qu'une fois le canal chiffré.
        capabilities = smtp_ehlo(session).await?;
    }

    if let (Some(user), Some(pass)) = (task.basic_auth_user.as_deref(), task.basic_auth_pass.as_deref()) {
        smtp_authenticate(session, &capabilities, user, pass).await?;
    }

    let _ = session.write("QUIT\r\n").await;
    Ok(())
}

async fn smtp_ehlo(session: &mut Session) -> Result<String, String> {
    session.write(&format!("EHLO {EHLO_NAME}\r\n")).await?;
    let response = session.read_response(smtp_complete).await?;
    if response.starts_with("250") {
        return Ok(response);
    }
    // Un serveur qui ne connaît que HELO (RFC 821) reste un serveur qui répond.
    session.write(&format!("HELO {EHLO_NAME}\r\n")).await?;
    let fallback = session.read_response(smtp_complete).await?;
    require_smtp_code(&fallback, "250", "EHLO/HELO")?;
    Ok(fallback)
}

async fn smtp_authenticate(
    session: &mut Session,
    capabilities: &str,
    user: &str,
    pass: &str,
) -> Result<(), String> {
    let upper = capabilities.to_uppercase();
    let mechanisms = upper
        .lines()
        .find(|l| l.contains("AUTH"))
        .unwrap_or("")
        .to_string();

    if mechanisms.contains("PLAIN") {
        let token = base64::engine::general_purpose::STANDARD.encode(format!("\0{user}\0{pass}"));
        session.write(&format!("AUTH PLAIN {token}\r\n")).await?;
        return require_smtp_code(&session.read_response(smtp_complete).await?, "235", "AUTH PLAIN");
    }
    if mechanisms.contains("LOGIN") || mechanisms.is_empty() {
        session.write("AUTH LOGIN\r\n").await?;
        require_smtp_code(&session.read_response(smtp_complete).await?, "334", "AUTH LOGIN")?;
        let encoded_user = base64::engine::general_purpose::STANDARD.encode(user);
        session.write(&format!("{encoded_user}\r\n")).await?;
        require_smtp_code(&session.read_response(smtp_complete).await?, "334", "AUTH LOGIN (user)")?;
        let encoded_pass = base64::engine::general_purpose::STANDARD.encode(pass);
        session.write(&format!("{encoded_pass}\r\n")).await?;
        return require_smtp_code(
            &session.read_response(smtp_complete).await?,
            "235",
            "AUTH LOGIN (password)",
        );
    }
    Err(format!(
        "Server advertises no supported SMTP AUTH mechanism (got '{}', expected PLAIN or LOGIN)",
        mechanisms.trim()
    ))
}

/// Une réponse SMTP est complète quand sa dernière ligne est `NNN ` (espace),
/// et non `NNN-` (continuation).
fn smtp_complete(buffer: &str) -> bool {
    match buffer.lines().rfind(|l| !l.is_empty()) {
        Some(last) => {
            let bytes = last.as_bytes();
            bytes.len() >= 3
                && bytes[..3].iter().all(|b| b.is_ascii_digit())
                && (bytes.len() == 3 || bytes[3] == b' ')
        }
        None => false,
    }
}

fn require_smtp_code(response: &str, code: &str, step: &str) -> Result<(), String> {
    let last = response.lines().rfind(|l| !l.is_empty()).unwrap_or("");
    if last.starts_with(code) {
        Ok(())
    } else {
        Err(format!("{step} refused: {}", truncate(response.trim(), 200)))
    }
}

/* -------------------------------- IMAP ---------------------------------- */

async fn imap_dialogue(
    session: &mut Session,
    target: &ServiceTarget,
    task: &CheckTask,
    insecure: bool,
) -> Result<(), String> {
    let greeting = session.read_response(|b| b.contains('\n')).await?;
    let trimmed = greeting.trim_start();
    if !(trimmed.starts_with("* OK") || trimmed.starts_with("* PREAUTH")) {
        return Err(format!("IMAP greeting refused: {}", truncate(greeting.trim(), 200)));
    }

    let mut capabilities = imap_command(session, "a1", "CAPABILITY").await?;

    if target.tls == TlsMode::StartTls {
        if !capabilities.to_uppercase().contains("STARTTLS") {
            return Err(
                "Server does not advertise STARTTLS on this port — use the implicit-TLS port (993) or an imaps:// URL"
                    .into(),
            );
        }
        imap_command(session, "a2", "STARTTLS").await?;
        session.upgrade_tls(&target.host, insecure).await?;
        capabilities = imap_command(session, "a3", "CAPABILITY").await?;
    }

    if let (Some(user), Some(pass)) = (task.basic_auth_user.as_deref(), task.basic_auth_pass.as_deref()) {
        if capabilities.to_uppercase().contains("LOGINDISABLED") {
            return Err("Server advertises LOGINDISABLED — plaintext LOGIN is refused on this connection".into());
        }
        let command = format!("LOGIN {} {}", imap_quote(user), imap_quote(pass));
        imap_command(session, "a4", &command).await?;
        let _ = imap_command(session, "a5", "LOGOUT").await;
    }

    Ok(())
}

/// Envoie une commande étiquetée et attend sa ligne de statut `<tag> OK|NO|BAD`.
async fn imap_command(session: &mut Session, tag: &str, command: &str) -> Result<String, String> {
    session.write(&format!("{tag} {command}\r\n")).await?;
    let tag_owned = tag.to_string();
    let response = session
        .read_response(move |buffer| {
            buffer.lines().any(|line| {
                line.starts_with(&format!("{tag_owned} OK"))
                    || line.starts_with(&format!("{tag_owned} NO"))
                    || line.starts_with(&format!("{tag_owned} BAD"))
            })
        })
        .await?;

    let status_line = response
        .lines()
        .find(|line| line.starts_with(&format!("{tag} ")))
        .unwrap_or("");
    if status_line.starts_with(&format!("{tag} OK")) {
        return Ok(response);
    }
    // Ne JAMAIS réafficher la commande LOGIN : elle porte le mot de passe.
    let safe_command = if command.starts_with("LOGIN") { "LOGIN" } else { command };
    Err(format!(
        "IMAP {safe_command} refused: {}",
        truncate(status_line.trim(), 200)
    ))
}

fn imap_quote(value: &str) -> String {
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

/* -------------------------------- Redis --------------------------------- */

async fn redis_dialogue(session: &mut Session, task: &CheckTask) -> Result<(), String> {
    if let Some(pass) = task.basic_auth_pass.as_deref() {
        // Redis 6+ : AUTH prend un utilisateur ET un mot de passe (ACL).
        // Sans utilisateur, c'est le `requirepass` historique.
        let args: Vec<&str> = match task.basic_auth_user.as_deref() {
            Some(user) if !user.is_empty() => vec!["AUTH", user, pass],
            _ => vec!["AUTH", pass],
        };
        session.write(&resp_command(&args)).await?;
        let reply = session.read_response(|b| b.contains("\r\n")).await?;
        if reply.starts_with('-') {
            return Err(format!("AUTH refused: {}", truncate(reply.trim(), 200)));
        }
    }

    session.write(&resp_command(&["PING"])).await?;
    let pong = session.read_response(|b| b.contains("\r\n")).await?;
    if !pong.trim_start().starts_with("+PONG") {
        // Un serveur protégé répond -NOAUTH ici : mot de passe manquant, pas
        // panne — et le message doit le dire.
        return Err(format!("PING refused: {}", truncate(pong.trim(), 200)));
    }

    let _ = session.write(&resp_command(&["QUIT"])).await;
    Ok(())
}

/// Encode une commande en RESP (tableau de bulk strings).
fn resp_command(args: &[&str]) -> String {
    let mut out = format!("*{}\r\n", args.len());
    for arg in args {
        out.push_str(&format!("${}\r\n{arg}\r\n", arg.len()));
    }
    out
}

/* ------------------------------ transport ------------------------------- */

enum Stream {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

/// Socket texte avec échéance GLOBALE : le temps imparti couvre tout le
/// dialogue (connexion + STARTTLS + authentification), pas chaque lecture
/// prise isolément — sinon un serveur lent à chaque étape tiendrait le check
/// bien au-delà du délai annoncé.
struct Session {
    stream: Option<Stream>,
    buffer: String,
    deadline: Instant,
}

impl Session {
    async fn connect(target: &ServiceTarget, deadline: Instant, insecure: bool) -> Result<Self, String> {
        let remaining = remaining_time(deadline)?;
        let addr = format!("{}:{}", target.host, target.port);
        let tcp = tokio::time::timeout(remaining, TcpStream::connect(&addr))
            .await
            .map_err(|_| format!("Connection to {addr} timed out"))?
            .map_err(|e| format!("Connection to {addr} failed: {e}"))?;

        let stream = if target.tls == TlsMode::Implicit {
            Stream::Tls(Box::new(tls_handshake(tcp, &target.host, insecure, deadline).await?))
        } else {
            Stream::Plain(tcp)
        };

        Ok(Session { stream: Some(stream), buffer: String::new(), deadline })
    }

    async fn write(&mut self, data: &str) -> Result<(), String> {
        let remaining = remaining_time(self.deadline)?;
        let write = async {
            match self.stream.as_mut() {
                Some(Stream::Plain(s)) => s.write_all(data.as_bytes()).await,
                Some(Stream::Tls(s)) => s.write_all(data.as_bytes()).await,
                None => Ok(()),
            }
        };
        tokio::time::timeout(remaining, write)
            .await
            .map_err(|_| "Timed out while sending to the server".to_string())?
            .map_err(|e| format!("Write failed: {e}"))
    }

    /// Lit jusqu'à ce que `is_complete` accepte le tampon accumulé.
    async fn read_response<F>(&mut self, is_complete: F) -> Result<String, String>
    where
        F: Fn(&str) -> bool,
    {
        loop {
            if !self.buffer.is_empty() && is_complete(&self.buffer) {
                return Ok(std::mem::take(&mut self.buffer));
            }
            if self.buffer.len() > MAX_RESPONSE_BYTES {
                return Err("Server response exceeded the size limit".into());
            }

            let remaining = remaining_time(self.deadline)?;
            let mut chunk = [0u8; 4096];
            let read = async {
                match self.stream.as_mut() {
                    Some(Stream::Plain(s)) => s.read(&mut chunk).await,
                    Some(Stream::Tls(s)) => s.read(&mut chunk).await,
                    None => Ok(0),
                }
            };
            let count = tokio::time::timeout(remaining, read)
                .await
                .map_err(|_| "Timed out waiting for the server response".to_string())?
                .map_err(|e| format!("Read failed: {e}"))?;

            if count == 0 {
                // Une coupure sans un mot après authentification est presque
                // toujours un refus : le dire plutôt que « réponse vide ».
                let partial = std::mem::take(&mut self.buffer);
                return Err(if partial.trim().is_empty() {
                    "Connection closed by server without a response".into()
                } else {
                    format!("Connection closed by server: {}", truncate(partial.trim(), 200))
                });
            }
            self.buffer.push_str(&String::from_utf8_lossy(&chunk[..count]));
        }
    }

    /// Bascule la connexion en TLS après un STARTTLS accepté.
    async fn upgrade_tls(&mut self, host: &str, insecure: bool) -> Result<(), String> {
        let stream = self.stream.take().ok_or("connection already closed")?;
        let tcp = match stream {
            Stream::Plain(tcp) => tcp,
            // Déjà chiffré : un second STARTTLS n'a pas de sens.
            Stream::Tls(tls) => {
                self.stream = Some(Stream::Tls(tls));
                return Ok(());
            }
        };
        // Tout ce qui restait en tampon appartient au canal en clair.
        self.buffer.clear();
        let tls = tls_handshake(tcp, host, insecure, self.deadline).await?;
        self.stream = Some(Stream::Tls(Box::new(tls)));
        Ok(())
    }

    async fn close(&mut self) {
        if let Some(stream) = self.stream.as_mut() {
            let _ = match stream {
                Stream::Plain(s) => s.shutdown().await,
                Stream::Tls(s) => s.shutdown().await,
            };
        }
        self.stream = None;
    }
}

async fn tls_handshake(
    tcp: TcpStream,
    host: &str,
    insecure: bool,
    deadline: Instant,
) -> Result<TlsStream<TcpStream>, String> {
    let remaining = remaining_time(deadline)?;
    let connector = native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(insecure)
        .danger_accept_invalid_hostnames(insecure)
        .build()
        .map_err(|e| format!("TLS setup failed: {e}"))?;
    let connector = tokio_native_tls::TlsConnector::from(connector);
    tokio::time::timeout(remaining, connector.connect(host, tcp))
        .await
        .map_err(|_| "TLS handshake timed out".to_string())?
        .map_err(|e| format!("TLS handshake failed: {e}"))
}

fn remaining_time(deadline: Instant) -> Result<Duration, String> {
    let now = Instant::now();
    if now >= deadline {
        return Err("Timed out".into());
    }
    Ok(deadline - now)
}

fn truncate(value: &str, max: usize) -> String {
    value.chars().take(max).collect()
}

fn scrub(message: &str, secret: Option<&str>) -> String {
    match secret {
        Some(s) if !s.is_empty() => message.replace(s, "***"),
        _ => message.to_string(),
    }
}

fn result(task: &CheckTask, start: &Instant, success: bool, error: Option<String>) -> CheckResult {
    CheckResult {
        task_id: task.task_id.clone(),
        monitor_id: task.monitor_id.clone(),
        region: task.region.clone(),
        agent_type: String::new(),
        success,
        latency_ms: Some(start.elapsed().as_millis() as u64),
        status_code: None,
        ssl_days_left: None,
        error,
        state: None,
        ttft_ms: None,
        tpot_ms: None,
        itl_ms: None,
        checked_at: chrono::Utc::now().to_rfc3339(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn implicit_tls_is_deduced_from_the_scheme_and_from_the_port() {
        // Le schéma le dit…
        let t = resolve_target("imap", "imaps://mail.example.com", None).unwrap();
        assert_eq!((t.port, t.tls), (993, TlsMode::Implicit));
        // …et à défaut, le port : `host:993` est de l'IMAPS, pas de l'IMAP
        // en clair, et se tromper ici donne un monitor rouge sur un serveur
        // parfaitement sain.
        let t = resolve_target("imap", "mail.example.com:993", None).unwrap();
        assert_eq!((t.port, t.tls), (993, TlsMode::Implicit));
        let t = resolve_target("smtp", "smtp.example.com:465", None).unwrap();
        assert_eq!((t.port, t.tls), (465, TlsMode::Implicit));
    }

    #[test]
    fn plain_ports_default_to_starttls_except_for_redis() {
        let t = resolve_target("smtp", "smtp.example.com", None).unwrap();
        assert_eq!((t.port, t.tls), (587, TlsMode::StartTls));
        let t = resolve_target("imap", "imap://mail.example.com", None).unwrap();
        assert_eq!((t.port, t.tls), (143, TlsMode::StartTls));
        // Redis ne connaît pas STARTTLS : c'est rediss ou rien.
        let t = resolve_target("redis", "cache.example.com", None).unwrap();
        assert_eq!((t.port, t.tls), (6379, TlsMode::None));
        let t = resolve_target("redis", "rediss://cache.example.com:6380", None).unwrap();
        assert_eq!((t.port, t.tls), (6380, TlsMode::Implicit));
    }

    #[test]
    fn port_override_only_applies_when_the_url_has_no_port() {
        let t = resolve_target("smtp", "smtp.example.com:2525", Some(587)).unwrap();
        assert_eq!(t.port, 2525);
        let t = resolve_target("smtp", "smtp.example.com", Some(2525)).unwrap();
        assert_eq!(t.port, 2525);
    }

    #[test]
    fn starttls_can_be_turned_off_for_a_plaintext_internal_mta() {
        let t = resolve_target("smtp", "smtp://mta.internal:25?starttls=false", None).unwrap();
        assert_eq!((t.port, t.tls), (25, TlsMode::None));
    }

    #[test]
    fn a_foreign_scheme_is_rejected_rather_than_probed() {
        assert!(resolve_target("smtp", "https://smtp.example.com", None).is_err());
        assert!(resolve_target("redis", "postgres://cache.example.com", None).is_err());
    }

    #[test]
    fn ipv6_literals_keep_their_brackets_out_of_the_host() {
        let t = resolve_target("redis", "[2001:db8::1]:6379", None).unwrap();
        assert_eq!((t.host.as_str(), t.port), ("2001:db8::1", 6379));
    }

    #[test]
    fn smtp_multiline_responses_are_only_complete_on_the_final_line() {
        assert!(!smtp_complete("250-smtp.example.com\r\n250-PIPELINING\r\n"));
        assert!(smtp_complete("250-smtp.example.com\r\n250-PIPELINING\r\n250 STARTTLS\r\n"));
        assert!(smtp_complete("220 mail.example.com ESMTP\r\n"));
    }

    #[test]
    fn resp_encodes_commands_with_byte_lengths() {
        assert_eq!(resp_command(&["PING"]), "*1\r\n$4\r\nPING\r\n");
        assert_eq!(
            resp_command(&["AUTH", "default", "s3cret"]),
            "*3\r\n$4\r\nAUTH\r\n$7\r\ndefault\r\n$6\r\ns3cret\r\n"
        );
    }

    #[test]
    fn imap_quoting_escapes_what_would_break_the_command() {
        assert_eq!(imap_quote("user"), "\"user\"");
        assert_eq!(imap_quote("pa\"ss\\word"), "\"pa\\\"ss\\\\word\"");
    }

    #[test]
    fn secrets_never_survive_in_an_error_message() {
        assert_eq!(scrub("AUTH refused for s3cret", Some("s3cret")), "AUTH refused for ***");
        assert_eq!(scrub("AUTH refused", None), "AUTH refused");
    }
}
