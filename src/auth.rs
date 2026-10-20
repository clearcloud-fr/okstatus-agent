//! Authentification des checks, au-delà du Basic auth.
//!
//! Miroir Rust de `src/shared/monitor-auth.ts` : la configuration arrive
//! telle quelle dans `CheckTask::auth_config` (colonne jsonb chiffrée côté
//! backend, déchiffrée à la lecture, jamais journalisée).
//!
//! Cinq modes :
//!
//! - `bearer` : en-tête `Authorization: Bearer <jeton>`
//! - `apikey` : en-tête nommé, ou paramètre d'URL
//! - `cookie` : en-tête `Cookie` brut
//! - `oauth2` : client_credentials — un jeton est obtenu auprès du token
//!   endpoint puis GARDÉ EN CACHE jusqu'à son expiration. Sans cache, un
//!   monitor à 30 s d'intervalle sur 5 régions ferait 14 400 demandes de
//!   jeton par jour à l'IdP du client, qui finirait par nous limiter — et la
//!   panne ressemblerait à une panne de la cible.
//! - `mtls` : certificat client présenté pendant la poignée de main. Chaque
//!   configuration a son propre client reqwest (le matériel TLS se règle à la
//!   construction du client), lui aussi mis en cache : reconstruire un
//!   connecteur native-tls à chaque check coûte plus cher que le check.

use std::collections::HashMap;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use base64::Engine;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use serde::Deserialize;

#[derive(Deserialize, Debug, Clone)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum MonitorAuth {
    Bearer(BearerAuth),
    Apikey(ApiKeyAuth),
    Cookie(CookieAuth),
    Oauth2(OAuth2Auth),
    Mtls(MtlsAuth),
}

#[derive(Deserialize, Debug, Clone)]
pub struct BearerAuth {
    pub token: String,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ApiKeyAuth {
    /// `header` (défaut) ou `query`.
    #[serde(rename = "in", default = "default_api_key_location")]
    pub location: String,
    pub name: String,
    pub value: String,
}

fn default_api_key_location() -> String {
    "header".to_string()
}

#[derive(Deserialize, Debug, Clone)]
pub struct CookieAuth {
    pub cookie: String,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct OAuth2Auth {
    pub token_url: String,
    pub client_id: String,
    pub client_secret: String,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub audience: Option<String>,
    /// `basic` (client_secret_basic, défaut) ou `post` (client_secret_post).
    #[serde(default)]
    pub auth_style: Option<String>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct MtlsAuth {
    pub cert: String,
    /// PKCS#8 NON chiffrée : native-tls ne sait pas déchiffrer une clé
    /// protégée par mot de passe, et le backend refuse donc d'en enregistrer
    /// une (shared/monitor-auth.ts).
    pub key: String,
    #[serde(default)]
    pub ca: Option<String>,
}

/// Lit la configuration d'un `CheckTask`. Une configuration illisible est
/// ignorée (le check part sans authentification et échouera avec le 401 du
/// serveur, ce qui est plus parlant qu'une erreur d'agent) — mais elle est
/// signalée par l'appelant.
pub fn parse(config: Option<&serde_json::Value>) -> Option<MonitorAuth> {
    let value = config?;
    match serde_json::from_value::<MonitorAuth>(value.clone()) {
        Ok(auth) => Some(auth),
        Err(e) => {
            tracing::warn!(error = %e, "unreadable auth_config, check runs unauthenticated");
            None
        }
    }
}

/// Applique les modes sans aller-retour réseau. Renvoie l'URL éventuellement
/// réécrite (clé d'API en paramètre).
pub fn apply_static(auth: &MonitorAuth, headers: &mut HeaderMap, url: String) -> String {
    match auth {
        MonitorAuth::Bearer(b) => {
            if let Ok(value) = HeaderValue::from_str(&format!("Bearer {}", b.token)) {
                headers.insert(reqwest::header::AUTHORIZATION, value);
            }
            url
        }
        MonitorAuth::Apikey(k) => {
            if k.location == "query" {
                let separator = if url.contains('?') { '&' } else { '?' };
                format!(
                    "{url}{separator}{}={}",
                    urlencode(&k.name),
                    urlencode(&k.value)
                )
            } else {
                if let (Ok(name), Ok(value)) = (
                    HeaderName::from_bytes(k.name.as_bytes()),
                    HeaderValue::from_str(&k.value),
                ) {
                    headers.insert(name, value);
                }
                url
            }
        }
        MonitorAuth::Cookie(c) => {
            // Ne pas écraser un Cookie déjà posé par les en-têtes personnalisés.
            let merged = match headers.get(reqwest::header::COOKIE).and_then(|v| v.to_str().ok()) {
                Some(existing) => format!("{existing}; {}", c.cookie),
                None => c.cookie.clone(),
            };
            if let Ok(value) = HeaderValue::from_str(&merged) {
                headers.insert(reqwest::header::COOKIE, value);
            }
            url
        }
        // Traités ailleurs : le jeton demande une requête, le mTLS un client.
        MonitorAuth::Oauth2(_) | MonitorAuth::Mtls(_) => url,
    }
}

fn urlencode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/* ------------------------------- OAuth2 --------------------------------- */

struct CachedToken {
    token: String,
    /// Instant à partir duquel le jeton doit être redemandé.
    expires_at: Instant,
}

static TOKEN_CACHE: LazyLock<Mutex<HashMap<u64, CachedToken>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Marge retirée à la durée de vie annoncée : un jeton qui expire pendant le
/// vol produirait un 401 attribué à tort à la cible.
const TOKEN_EXPIRY_MARGIN: Duration = Duration::from_secs(30);

/// Durée retenue quand le serveur n'annonce pas d'`expires_in`.
const TOKEN_DEFAULT_TTL: Duration = Duration::from_secs(300);

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    expires_in: Option<u64>,
}

/// Récupère (ou relit dans le cache) un jeton client_credentials.
///
/// L'erreur renvoyée dit explicitement qu'elle vient du token endpoint : un
/// IdP en panne n'est pas une panne de la cible surveillée, et les deux ne se
/// débuguent pas au même endroit.
pub async fn oauth2_token(
    client: &reqwest::Client,
    auth: &OAuth2Auth,
    timeout: Duration,
) -> Result<String, String> {
    let key = oauth2_cache_key(auth);

    if let Ok(cache) = TOKEN_CACHE.lock() {
        if let Some(entry) = cache.get(&key) {
            if entry.expires_at > Instant::now() {
                return Ok(entry.token.clone());
            }
        }
    }

    // Le token endpoint est une URL fournie par le client : elle passe la même
    // garde anti-SSRF que la cible, sinon l'authentification devient le trou
    // par lequel on fait parler le réseau interne de l'agent.
    if let Ok(parsed) = reqwest::Url::parse(&auth.token_url) {
        let host = parsed.host_str().unwrap_or_default().to_string();
        let port = parsed.port_or_known_default().unwrap_or(443);
        crate::ssrf::check_public_target(&host, port)
            .await
            .map_err(|e| format!("token endpoint rejected: {e}"))?;
    } else {
        return Err("token endpoint is not a valid URL".into());
    }

    let mut form: Vec<(&str, &str)> = vec![("grant_type", "client_credentials")];
    if let Some(scope) = auth.scope.as_deref() {
        form.push(("scope", scope));
    }
    if let Some(audience) = auth.audience.as_deref() {
        form.push(("audience", audience));
    }

    let use_basic = auth.auth_style.as_deref().unwrap_or("basic") == "basic";
    let mut request = client.post(&auth.token_url).timeout(timeout);
    if use_basic {
        let credentials = base64::engine::general_purpose::STANDARD.encode(format!(
            "{}:{}",
            urlencode(&auth.client_id),
            urlencode(&auth.client_secret)
        ));
        request = request.header(reqwest::header::AUTHORIZATION, format!("Basic {credentials}"));
    } else {
        form.push(("client_id", &auth.client_id));
        form.push(("client_secret", &auth.client_secret));
    }

    let response = request
        .form(&form)
        .send()
        .await
        .map_err(|e| format!("token request failed: {e}"))?;

    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    if !status.is_success() {
        let detail: String = body.chars().take(200).collect();
        return Err(format!("token endpoint returned HTTP {status}: {detail}"));
    }

    let parsed: TokenResponse =
        serde_json::from_str(&body).map_err(|e| format!("token response is not valid JSON: {e}"))?;

    let ttl = parsed
        .expires_in
        .map(Duration::from_secs)
        .unwrap_or(TOKEN_DEFAULT_TTL)
        .saturating_sub(TOKEN_EXPIRY_MARGIN)
        .max(Duration::from_secs(5));

    if let Ok(mut cache) = TOKEN_CACHE.lock() {
        cache.insert(
            key,
            CachedToken {
                token: parsed.access_token.clone(),
                expires_at: Instant::now() + ttl,
            },
        );
        // Un agent tourne des semaines : sans purge, le cache garde les
        // jetons de monitors supprimés ou réauthentifiés depuis longtemps.
        if cache.len() > 512 {
            let now = Instant::now();
            cache.retain(|_, entry| entry.expires_at > now);
        }
    }

    Ok(parsed.access_token)
}

/* --------------------------------- mTLS --------------------------------- */

static MTLS_CLIENTS: LazyLock<Mutex<HashMap<u64, reqwest::Client>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Client reqwest présentant le certificat client demandé. Mis en cache par
/// empreinte de la configuration : le coût est la construction du connecteur
/// TLS, pas la requête.
pub fn mtls_client(auth: &MtlsAuth, ignore_tls: bool) -> Result<reqwest::Client, String> {
    let key = cache_key(&[
        &auth.cert,
        &auth.key,
        auth.ca.as_deref().unwrap_or(""),
        if ignore_tls { "insecure" } else { "verify" },
    ]);

    if let Ok(cache) = MTLS_CLIENTS.lock() {
        if let Some(client) = cache.get(&key) {
            return Ok(client.clone());
        }
    }

    let identity = reqwest::Identity::from_pkcs8_pem(auth.cert.as_bytes(), auth.key.as_bytes())
        .map_err(|e| format!("client certificate/key rejected: {e}"))?;

    let mut builder = reqwest::Client::builder()
        .identity(identity)
        // Même politique que le client partagé : les redirections sont
        // suivies à la main dans checks/http.rs pour revalider chaque saut.
        .redirect(reqwest::redirect::Policy::none())
        .danger_accept_invalid_certs(ignore_tls);

    if let Some(ca) = auth.ca.as_deref() {
        let certificate = reqwest::Certificate::from_pem(ca.as_bytes())
            .map_err(|e| format!("custom CA rejected: {e}"))?;
        builder = builder.add_root_certificate(certificate);
    }

    let client = builder
        .build()
        .map_err(|e| format!("failed to build mTLS client: {e}"))?;

    if let Ok(mut cache) = MTLS_CLIENTS.lock() {
        cache.insert(key, client.clone());
    }
    Ok(client)
}

/// Everything that decides whether the token endpoint accepts the request.
/// `auth_style` was missing: a monitor switched from client_secret_basic to
/// client_secret_post (or the reverse) kept reusing the token obtained the
/// other way, so a style the IdP refuses looked healthy until that token
/// expired — then every check failed with no config change to explain it.
/// Found on the QA auth server, 2026-09-14.
fn oauth2_cache_key(auth: &OAuth2Auth) -> u64 {
    cache_key(&[
        &auth.token_url,
        &auth.client_id,
        auth.scope.as_deref().unwrap_or(""),
        auth.audience.as_deref().unwrap_or(""),
        auth.auth_style.as_deref().unwrap_or("basic"),
        &auth.client_secret,
    ])
}

fn cache_key(parts: &[&str]) -> u64 {
    let mut hasher = DefaultHasher::new();
    for part in parts {
        part.hash(&mut hasher);
    }
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_every_auth_mode_from_the_backend_shape() {
        // Les noms de champs sont ceux écrits par shared/monitor-auth.ts : un
        // renommage côté backend doit casser ici, pas silencieusement priver
        // les checks d'authentification en production.
        assert!(matches!(
            parse(Some(&json!({ "type": "bearer", "token": "t" }))),
            Some(MonitorAuth::Bearer(_))
        ));
        assert!(matches!(
            parse(Some(&json!({ "type": "apikey", "in": "query", "name": "k", "value": "v" }))),
            Some(MonitorAuth::Apikey(_))
        ));
        assert!(matches!(
            parse(Some(&json!({ "type": "cookie", "cookie": "s=1" }))),
            Some(MonitorAuth::Cookie(_))
        ));
        assert!(matches!(
            parse(Some(&json!({
                "type": "oauth2",
                "tokenUrl": "https://login.example/token",
                "clientId": "id",
                "clientSecret": "secret",
                "authStyle": "post"
            }))),
            Some(MonitorAuth::Oauth2(_))
        ));
        assert!(matches!(
            parse(Some(&json!({ "type": "mtls", "cert": "-----BEGIN CERTIFICATE-----", "key": "-----BEGIN PRIVATE KEY-----" }))),
            Some(MonitorAuth::Mtls(_))
        ));
    }

    #[test]
    fn unknown_or_broken_config_does_not_panic() {
        assert!(parse(None).is_none());
        assert!(parse(Some(&json!({ "type": "kerberos" }))).is_none());
        assert!(parse(Some(&json!({ "type": "bearer" }))).is_none());
    }

    #[test]
    fn oauth2_token_cache_distinguishes_the_client_auth_style() {
        let parse_oauth = |style: &str| match parse(Some(&json!({
            "type": "oauth2", "tokenUrl": "https://idp.example.com/token",
            "clientId": "c", "clientSecret": "s", "authStyle": style
        }))) {
            Some(MonitorAuth::Oauth2(a)) => a,
            _ => panic!("oauth2 config did not parse"),
        };
        assert_ne!(oauth2_cache_key(&parse_oauth("basic")), oauth2_cache_key(&parse_oauth("post")));
        assert_eq!(oauth2_cache_key(&parse_oauth("post")), oauth2_cache_key(&parse_oauth("post")));
    }

    #[test]
    fn api_key_defaults_to_a_header() {
        let auth = parse(Some(&json!({ "type": "apikey", "name": "X-Api-Key", "value": "v" }))).unwrap();
        let mut headers = HeaderMap::new();
        let url = apply_static(&auth, &mut headers, "https://example.com/".into());
        assert_eq!(url, "https://example.com/");
        assert_eq!(headers.get("X-Api-Key").unwrap(), "v");
    }

    #[test]
    fn api_key_in_query_appends_to_an_existing_query_string() {
        let auth = parse(Some(
            &json!({ "type": "apikey", "in": "query", "name": "api_key", "value": "a/b+c" }),
        ))
        .unwrap();
        let mut headers = HeaderMap::new();
        let url = apply_static(&auth, &mut headers, "https://example.com/?a=1".into());
        // Même encodage que shared/monitor-auth.ts côté backend : une clé
        // contenant / ou + doit arriver telle quelle au serveur.
        assert_eq!(url, "https://example.com/?a=1&api_key=a%2Fb%2Bc");
        assert!(headers.is_empty());
    }

    #[test]
    fn cookie_auth_is_appended_to_custom_cookie_headers() {
        let auth = parse(Some(&json!({ "type": "cookie", "cookie": "session=abc" }))).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(reqwest::header::COOKIE, HeaderValue::from_static("consent=1"));
        apply_static(&auth, &mut headers, "https://example.com/".into());
        assert_eq!(
            headers.get(reqwest::header::COOKIE).unwrap(),
            "consent=1; session=abc"
        );
    }

    #[test]
    fn bearer_sets_the_authorization_header() {
        let auth = parse(Some(&json!({ "type": "bearer", "token": "xyz" }))).unwrap();
        let mut headers = HeaderMap::new();
        apply_static(&auth, &mut headers, "https://example.com/".into());
        assert_eq!(headers.get(reqwest::header::AUTHORIZATION).unwrap(), "Bearer xyz");
    }
}

/// Toutes les valeurs secrètes portées par une tâche : mot de passe Basic,
/// clé LLM, et le secret du mode d'authentification choisi.
fn secret_values(task: &crate::models::CheckTask) -> Vec<String> {
    let mut secrets: Vec<String> = Vec::new();
    if let Some(pass) = task.basic_auth_pass.as_deref() {
        secrets.push(pass.to_string());
    }
    if let Some(key) = task.llm_api_key.as_deref() {
        secrets.push(key.to_string());
    }
    match parse(task.auth_config.as_ref()) {
        Some(MonitorAuth::Bearer(b)) => secrets.push(b.token),
        Some(MonitorAuth::Apikey(k)) => {
            // La forme « paramètre d'URL » est celle qui ressort le plus
            // facilement : reqwest cite l'URL entière dans ses erreurs.
            secrets.push(urlencode(&k.value));
            secrets.push(k.value);
        }
        Some(MonitorAuth::Cookie(c)) => secrets.push(c.cookie),
        Some(MonitorAuth::Oauth2(o)) => secrets.push(o.client_secret),
        Some(MonitorAuth::Mtls(m)) => secrets.push(m.key),
        None => {}
    }
    secrets.retain(|s| !s.is_empty());
    secrets
}

/// Remplace dans un message toute valeur secrète de la tâche par `***`.
pub fn scrub_secrets(message: &str, task: &crate::models::CheckTask) -> String {
    let mut out = message.to_string();
    for secret in secret_values(task) {
        if out.contains(&secret) {
            out = out.replace(&secret, "***");
        }
    }
    out
}

#[cfg(test)]
mod scrub_tests {
    use super::*;
    use crate::models::{CheckTask, CheckType};
    use serde_json::json;

    fn task_with_auth(auth: serde_json::Value) -> CheckTask {
        CheckTask {
            task_id: "t".into(),
            monitor_id: "m".into(),
            org_id: "o".into(),
            tenant_id: "okstatus".into(),
            target: "https://api.example.com".into(),
            check_type: CheckType::Http,
            port: None,
            timeout: None,
            region: "fr-dc3".into(),
            accepted_status_codes: None,
            http_headers: None,
            http_method: None,
            http_body: None,
            http_body_encoding: None,
            ignore_tls: None,
            follow_redirects: None,
            basic_auth_user: None,
            basic_auth_pass: None,
            auth_config: Some(auth),
            keyword: None,
            keyword_invert: None,
            json_path: None,
            json_operator: None,
            json_expected_value: None,
            dns_record_type: None,
            dns_expected_value: None,
            dns_server: None,
            llm_provider: None,
            llm_api_key: None,
            llm_config: None,
            db_query: None,
            test_id: None,
            sealed: None,
        }
    }

    #[test]
    fn an_api_key_in_the_url_never_survives_in_the_error_message() {
        // reqwest cite l'URL complète dans ses erreurs de transport, et ce
        // champ finit en base, dans les alertes et dans les exports.
        let task = task_with_auth(json!({ "type": "apikey", "in": "query", "name": "api_key", "value": "k3y/secret" }));
        let message = "error sending request for url (https://api.example.com/?api_key=k3y%2Fsecret)";
        let scrubbed = scrub_secrets(message, &task);
        assert!(!scrubbed.contains("k3y"), "got: {scrubbed}");
    }

    #[test]
    fn a_bearer_token_echoed_by_the_server_is_masked_too() {
        let task = task_with_auth(json!({ "type": "bearer", "token": "tok-42" }));
        assert_eq!(
            scrub_secrets("401: token tok-42 is expired", &task),
            "401: token *** is expired"
        );
    }
}
