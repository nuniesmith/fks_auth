use axum::{routing::{get, post}, Router, extract::{State}, Json, http::{StatusCode, header, HeaderMap}};
use axum::{extract::Query, response::IntoResponse};
use serde::{Serialize, Deserialize};
use std::{net::SocketAddr, sync::{Arc, RwLock}};
use uuid::Uuid;
use chrono::{Utc, Duration};
use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey, Algorithm};
use tower_http::cors::{CorsLayer, Any};
use tracing::{info, Level};
use tracing_subscriber::{FmtSubscriber, util::SubscriberInitExt};

// Passkey module
pub mod passkey;

#[derive(Clone)]
pub struct AppState { 
    pub dev_user: Arc<DevUser>, 
    pub jwt: Arc<JwtKeys>, 
    pub started_at: i64, 
    pub revoked: Arc<RwLock<Vec<String>>>,
    // Passkey (WebAuthn) support
    pub webauthn: Option<Arc<webauthn_rs::prelude::Webauthn>>,
    pub passkey_store: Option<passkey::PasskeyStore>,
    pub registration_state: Option<passkey::RegistrationState>,
    pub auth_state: Option<passkey::AuthenticationState>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct DevUser { pub username: String, pub password: String, pub display_name: String }

#[derive(Deserialize)] struct LoginRequest { username: String, password: String }
#[derive(Serialize)] struct LoginResponse { access_token: String, refresh_token: String, token_type: &'static str, username: String, display_name: String, expires_at: i64, user: UserProfile }
#[derive(Deserialize)] struct RefreshRequest { refresh_token: String }
#[derive(Serialize)] struct RefreshResponse { access_token: String, expires_at: i64, token_type: &'static str }
#[derive(Serialize, Clone)] struct UserProfile { id: String, username: String, display_name: String, role: String }
#[derive(Serialize)] struct MeResponse { user: UserProfile, expires_at: i64, issued_at: i64 }
#[derive(Serialize, Deserialize)] struct Claims { sub: String, exp: usize, typ: String, iss: String, aud: String, jti: String }
pub struct JwtKeys { enc: EncodingKey, dec: DecodingKey, algorithm: Algorithm, access_ttl: i64, refresh_ttl: i64, issuer: String, audience: String }

pub async fn run() -> anyhow::Result<()> { run_internal(None).await }

/// Run the server on a specific port (used by integration tests)
pub async fn run_with_port(port: u16) -> anyhow::Result<()> { run_internal(Some(port)).await }

async fn run_internal(override_port: Option<u16>) -> anyhow::Result<()> {
    init_tracing();
    let port: u16 = override_port.or_else(|| {
        std::env::var("SERVICE_PORT")
            .or_else(|_| std::env::var("AUTH_PORT"))
            .ok()
            .and_then(|s| s.parse().ok())
    }).unwrap_or(4100);
    let user = DevUser { username: "jordan".into(), password: "567326".into(), display_name: "Jordan Dev".into() };
    // Generate secure random secret if not set (secure by default)
    // Uses cryptographically secure random generation via rand crate
    let secret = std::env::var("AUTH_SECRET").unwrap_or_else(|_| {
        use rand::Rng;
        use rand::distributions::Alphanumeric;
        let mut rng = rand::thread_rng();
        let secret_bytes: String = (0..64)
            .map(|_| rng.sample(&Alphanumeric) as char)
            .collect();
        tracing::warn!("AUTH_SECRET not set. Using randomly generated secret. Set AUTH_SECRET environment variable for production.");
        secret_bytes
    });
    let access_ttl = std::env::var("AUTH_ACCESS_TTL_MINUTES").ok().and_then(|s| s.parse().ok()).unwrap_or(30);
    let refresh_ttl = std::env::var("AUTH_REFRESH_TTL_MINUTES").ok().and_then(|s| s.parse().ok()).unwrap_or(60*24);
    let issuer = std::env::var("AUTH_ISSUER").unwrap_or_else(|_| "fks_auth".into());
    let audience = std::env::var("AUTH_AUDIENCE").unwrap_or_else(|_| "fks_web".into());
    let jwt = JwtKeys { enc: EncodingKey::from_secret(secret.as_bytes()), dec: DecodingKey::from_secret(secret.as_bytes()), algorithm: Algorithm::HS256, access_ttl, refresh_ttl, issuer, audience };
    
    // Initialize WebAuthn/Passkey support
    let (webauthn, passkey_store, registration_state, auth_state) = {
        let origin = std::env::var("WEBAUTHN_ORIGIN").unwrap_or_else(|_| "http://localhost:8009".to_string());
        let rp_id = std::env::var("WEBAUTHN_RP_ID").unwrap_or_else(|_| "localhost".to_string());
        let rp_name = std::env::var("WEBAUTHN_RP_NAME").unwrap_or_else(|_| "FKS Trading Platform".to_string());
        
        match passkey::init_webauthn(&origin, &rp_id, &rp_name) {
            Ok(wa) => {
                info!("WebAuthn/Passkey support enabled (origin: {}, rp_id: {})", origin, rp_id);
                (
                    Some(Arc::new(wa)),
                    Some(passkey::PasskeyStore::default()),
                    Some(passkey::RegistrationState::default()),
                    Some(passkey::AuthenticationState::default()),
                )
            }
            Err(e) => {
                tracing::warn!("Failed to initialize WebAuthn: {}. Passkey support disabled.", e);
                (None, None, None, None)
            }
        }
    };
    
    let state = AppState { 
        dev_user: Arc::new(user), 
        jwt: Arc::new(jwt), 
        started_at: Utc::now().timestamp(), 
        revoked: Arc::new(RwLock::new(Vec::new())),
        webauthn,
        passkey_store,
        registration_state,
        auth_state,
    };
    
    let cors = CorsLayer::new().allow_methods(Any).allow_headers(Any).allow_origin(Any);
    
    // Set up Prometheus metrics
    let (prometheus_layer, metric_handle) = {
        use axum_prometheus::PrometheusMetricLayer;
        use prometheus::{Gauge, IntGaugeVec, Registry, Encoder, TextEncoder};
        use std::env;
        
        let (layer, axum_handle) = PrometheusMetricLayer::pair();
        let registry = Registry::new();
        
        // Build info
        let commit = env::var("GIT_COMMIT")
            .or_else(|_| env::var("COMMIT_SHA"))
            .unwrap_or_else(|_| "unknown".to_string());
        let build_date = env::var("BUILD_DATE")
            .or_else(|_| env::var("BUILD_TIMESTAMP"))
            .unwrap_or_else(|_| "unknown".to_string());
        
        let build_info = Gauge::with_opts(
            prometheus::opts!(
                "fks_build_info",
                "Build information for FKS service"
            )
            .const_label("service", "fks_auth")
            .const_label("version", env!("CARGO_PKG_VERSION"))
            .const_label("commit", &commit[..commit.len().min(8)])
            .const_label("build_date", &build_date),
        ).expect("Failed to create build_info metric");
        build_info.set(1.0);
        registry.register(Box::new(build_info)).expect("Failed to register build_info");
        
        // Service health
        let service_health = IntGaugeVec::new(
            prometheus::opts!("fks_service_health", "Service health status (1=healthy, 0=unhealthy)"),
            &["service"],
        ).expect("Failed to create service_health metric");
        service_health.with_label_values(&["fks_auth"]).set(1);
        registry.register(Box::new(service_health)).expect("Failed to register service_health");
        
        // Create combined handle
        struct MetricHandle {
            registry: Registry,
            axum_handle: axum_prometheus::MetricHandle,
        }
        impl MetricHandle {
            fn render(&self) -> String {
                let mut output = self.axum_handle.render();
                let encoder = TextEncoder::new();
                let metric_families = self.registry.gather();
                let mut buffer = Vec::new();
                if encoder.encode(&metric_families, &mut buffer).is_ok() {
                    if let Ok(metrics_text) = String::from_utf8(buffer) {
                        output.push_str(&metrics_text);
                    }
                }
                output
            }
        }
        let handle = MetricHandle { registry, axum_handle };
        (layer, handle)
    };
    
    // Build router with optional passkey routes
    let mut app = Router::new()
        .route("/health", get(health))
        .route("/login", get(login_redirect).post(login))
        .route("/refresh", post(refresh))
        .route("/me", get(me))
        .route("/logout", post(logout))
        .route("/introspect", post(introspect))
        .route("/config", get(config))
        .route("/verify", get(verify))
        .route("/metrics", get(|| async move { metric_handle.render() }));
    
    // Add passkey routes if WebAuthn is enabled
    if state.webauthn.is_some() {
        app = app
            .route("/passkey/register/start", post(passkey_start_registration))
            .route("/passkey/register/complete", post(passkey_complete_registration))
            .route("/passkey/authenticate/start", post(passkey_start_authentication))
            .route("/passkey/authenticate/complete", post(passkey_complete_authentication));
    }
    
    let app = app
        .layer(prometheus_layer)
        .with_state(state)
        .layer(cors);
    let addr = SocketAddr::from(([0,0,0,0], port));
    info!("starting fks_auth dev server on {addr}");
    axum::serve(tokio::net::TcpListener::bind(addr).await.unwrap(), app).await.unwrap();
    Ok(())
}

fn init_tracing() { let _ = FmtSubscriber::builder().with_max_level(Level::INFO).with_env_filter(tracing_subscriber::EnvFilter::from_default_env()).finish().try_init(); }

async fn health(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "service": "fks_auth",
        "version": env!("CARGO_PKG_VERSION"),
        "started_at": state.started_at,
        "access_ttl_min": state.jwt.access_ttl,
        "refresh_ttl_min": state.jwt.refresh_ttl,
        "passkey_enabled": state.webauthn.is_some()
    }))
}

async fn login(State(state): State<AppState>, Json(req): Json<LoginRequest>) -> Result<Json<LoginResponse>, (StatusCode, String)> {
    if req.username != state.dev_user.username || req.password != state.dev_user.password { return Err((StatusCode::UNAUTHORIZED, "invalid credentials".into())); }
    let TokensIssued { access_token, refresh_token, access_exp } = issue_tokens(&state, &req.username).map_err(internal)?;
    let user = UserProfile { id: req.username.clone(), username: req.username.clone(), display_name: state.dev_user.display_name.clone(), role: "developer".into() };
    Ok(Json(LoginResponse { access_token, refresh_token, token_type: "Bearer", username: req.username, display_name: state.dev_user.display_name.clone(), expires_at: access_exp, user }))
}

#[derive(Deserialize)] struct LoginRedirectParams { redirect_uri: Option<String> }

async fn login_redirect(State(state): State<AppState>, Query(params): Query<LoginRedirectParams>) -> impl IntoResponse {
    if let Some(redirect) = params.redirect_uri.clone() {
        // Very permissive (dev). In production validate host/allowlist.
        let username = state.dev_user.username.clone();
        let issued = match issue_tokens(&state, &username) {
            Ok(t) => t,
            Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("token issue failed: {e}")).into_response(),
        };
        // Simulate OAuth style: code=access, state=refresh
    let sep = if redirect.contains('?') { '&' } else { '?' };
        let loc = format!("{}{}code={}&state={}",
            redirect,
            sep,
            urlencoding::encode(&issued.access_token),
            urlencoding::encode(&issued.refresh_token));
        let mut headers = HeaderMap::new();
        headers.insert(header::LOCATION, loc.parse().unwrap_or_else(|_| redirect.parse().unwrap()));
        return (StatusCode::FOUND, headers).into_response();
    }
    // Simple HTML helper for manual testing
    let html = r#"<!DOCTYPE html><html><head><title>fks_auth dev login</title></head><body><h3>fks_auth dev login</h3><p>Supply ?redirect_uri=... to receive tokens (code=access, state=refresh)</p></body></html>"#;
    (StatusCode::OK, [(header::CONTENT_TYPE, "text/html; charset=utf-8")], html).into_response()
}

struct TokensIssued { access_token: String, refresh_token: String, access_exp: i64 }

fn issue_tokens(state: &AppState, username: &str) -> Result<TokensIssued, String> {
    let now = Utc::now();
    let access_exp = (now + Duration::minutes(state.jwt.access_ttl)).timestamp();
    let refresh_exp = (now + Duration::minutes(state.jwt.refresh_ttl)).timestamp();
    let access_claims = Claims { sub: username.to_string(), exp: access_exp as usize, typ: "access".into(), iss: state.jwt.issuer.clone(), aud: state.jwt.audience.clone(), jti: Uuid::new_v4().to_string() };
    let refresh_claims = Claims { sub: username.to_string(), exp: refresh_exp as usize, typ: "refresh".into(), iss: state.jwt.issuer.clone(), aud: state.jwt.audience.clone(), jti: Uuid::new_v4().to_string() };
    let access_token = encode(&Header::new(state.jwt.algorithm), &access_claims, &state.jwt.enc).map_err(|e| e.to_string())?;
    let refresh_token = encode(&Header::new(state.jwt.algorithm), &refresh_claims, &state.jwt.enc).map_err(|e| e.to_string())?;
    Ok(TokensIssued { access_token, refresh_token, access_exp })
}

async fn refresh(State(state): State<AppState>, Json(req): Json<RefreshRequest>) -> Result<Json<RefreshResponse>, (StatusCode, String)> {
    let mut validation = Validation::new(state.jwt.algorithm);
    // Disable built-in audience validation; we'll enforce manually for clearer diagnostics
    validation.validate_aud = false;
    let data = decode::<Claims>(&req.refresh_token, &state.jwt.dec, &validation).map_err(|_| (StatusCode::UNAUTHORIZED, "invalid refresh".into()))?;
    if data.claims.typ != "refresh" { return Err((StatusCode::UNAUTHORIZED, "wrong token type".into())); }
    if data.claims.iss != state.jwt.issuer || data.claims.aud != state.jwt.audience { return Err((StatusCode::UNAUTHORIZED, "claim mismatch".into())); }
    if is_revoked(&state, &data.claims.jti) { return Err((StatusCode::UNAUTHORIZED, "revoked".into())); }
    let now = Utc::now();
    let access_exp = (now + Duration::minutes(state.jwt.access_ttl)).timestamp();
    let access_claims = Claims { sub: data.claims.sub, exp: access_exp as usize, typ: "access".into(), iss: state.jwt.issuer.clone(), aud: state.jwt.audience.clone(), jti: Uuid::new_v4().to_string() };
    let access_token = encode(&Header::new(state.jwt.algorithm), &access_claims, &state.jwt.enc).map_err(internal)?;
    Ok(Json(RefreshResponse { access_token, expires_at: access_exp, token_type: "Bearer" }))
}

async fn me(State(state): State<AppState>, headers: HeaderMap) -> Result<Json<MeResponse>, (StatusCode, String)> {
    let auth = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).ok_or((StatusCode::UNAUTHORIZED, "missing authorization".into()))?;
    let token = auth.strip_prefix("Bearer ").ok_or((StatusCode::UNAUTHORIZED, "invalid scheme".into()))?;
    // Perform decode; if audience mismatch give specific message
    let mut base_validation = Validation::new(state.jwt.algorithm);
    base_validation.validate_aud = false; // manual audience check below
    let data = decode::<Claims>(token, &state.jwt.dec, &base_validation).map_err(|_| (StatusCode::UNAUTHORIZED, "invalid token".into()))?;
    if data.claims.iss != state.jwt.issuer || data.claims.aud != state.jwt.audience { return Err((StatusCode::UNAUTHORIZED, "claim mismatch".into())); }
    if data.claims.typ != "access" { return Err((StatusCode::UNAUTHORIZED, "wrong token type".into())); }
    if data.claims.iss != state.jwt.issuer || data.claims.aud != state.jwt.audience { return Err((StatusCode::UNAUTHORIZED, "claim mismatch".into())); }
    if is_revoked(&state, &data.claims.jti) { return Err((StatusCode::UNAUTHORIZED, "revoked".into())); }
    let expires_at = data.claims.exp as i64;
    // issued_at not stored; approximate as expires_at - access_ttl
    let issued_at = expires_at - (state.jwt.access_ttl * 60);
    let user = UserProfile { id: state.dev_user.username.clone(), username: state.dev_user.username.clone(), display_name: state.dev_user.display_name.clone(), role: "developer".into() };
    Ok(Json(MeResponse { user, expires_at, issued_at }))
}

// Lightweight verification endpoint for Nginx auth_request.
// Returns 200 on valid access token, 401 otherwise (empty body).
async fn verify(State(state): State<AppState>, headers: HeaderMap) -> StatusCode {
    let auth = match headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()) { Some(v) => v, None => return StatusCode::UNAUTHORIZED };
    let token = match auth.strip_prefix("Bearer ") { Some(t) => t, None => return StatusCode::UNAUTHORIZED };
    let mut validation = Validation::new(state.jwt.algorithm);
    validation.validate_aud = false; // manual audience check below
    let Ok(data) = decode::<Claims>(token, &state.jwt.dec, &validation) else { return StatusCode::UNAUTHORIZED };
    if data.claims.typ != "access" { return StatusCode::UNAUTHORIZED; }
    if data.claims.iss != state.jwt.issuer || data.claims.aud != state.jwt.audience { return StatusCode::UNAUTHORIZED; }
    if is_revoked(&state, &data.claims.jti) { return StatusCode::UNAUTHORIZED; }
    StatusCode::OK
}

async fn logout(State(state): State<AppState>, headers: HeaderMap) -> StatusCode {
    // Extract refresh token (optional) or access token and revoke its jti.
    let auth = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok());
    if let Some(a) = auth.and_then(|v| v.strip_prefix("Bearer ")) {
        if let Ok(data) = decode::<Claims>(a, &state.jwt.dec, &Validation::new(state.jwt.algorithm)) {
            revoke(&state, data.claims.jti);
        }
    }
    StatusCode::NO_CONTENT
}

fn revoke(state: &AppState, jti: String) {
    if let Ok(mut guard) = state.revoked.write() {
        guard.push(jti);
        if guard.len() > 10_000 {
            // Keep only the most recent 5k entries without reallocating unnecessarily
            let len = guard.len();
            let start = len.saturating_sub(5_000);
            guard.drain(0..start); // remove older entries
        }
    }
}
fn is_revoked(state: &AppState, jti: &str) -> bool { state.revoked.read().map(|g| g.iter().any(|v| v==jti)).unwrap_or(false) }

fn internal<E: std::fmt::Display>(e: E) -> (StatusCode, String) { (StatusCode::INTERNAL_SERVER_ERROR, format!("internal error: {e}")) }

#[derive(Deserialize)] struct IntrospectRequest { token: Option<String> }
#[derive(Serialize)] struct IntrospectResponse { valid: bool, reason: Option<String>, claims: Option<Claims> }

async fn introspect(State(state): State<AppState>, Json(req): Json<IntrospectRequest>) -> Json<IntrospectResponse> {
    let Some(token) = req.token else { return Json(IntrospectResponse { valid: false, reason: Some("missing token".into()), claims: None }); };
    let mut validation = Validation::new(state.jwt.algorithm);
    validation.validate_aud = false; // manual check after decode
    match decode::<Claims>(&token, &state.jwt.dec, &validation) {
        Ok(data) => {
            if data.claims.iss != state.jwt.issuer || data.claims.aud != state.jwt.audience {
                return Json(IntrospectResponse { valid: false, reason: Some("claim mismatch".into()), claims: Some(data.claims) });
            }
            if is_revoked(&state, &data.claims.jti) {
                return Json(IntrospectResponse { valid: false, reason: Some("revoked".into()), claims: Some(data.claims) });
            }
            Json(IntrospectResponse { valid: true, reason: None, claims: Some(data.claims) })
        }
    Err(e) => Json(IntrospectResponse { valid: false, reason: Some(format!("decode error: {e}")), claims: None })
    }
}

// Return basic runtime config (issuer & audience) for debugging audience mismatches
async fn config(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "issuer": state.jwt.issuer,
        "audience": state.jwt.audience,
        "access_ttl_min": state.jwt.access_ttl,
        "refresh_ttl_min": state.jwt.refresh_ttl,
        "passkey_enabled": state.webauthn.is_some()
    }))
}

// ============================================================
// Passkey (WebAuthn) Route Handlers
// ============================================================

async fn passkey_start_registration(
    State(state): State<AppState>,
    Json(req): Json<passkey::StartRegistrationRequest>,
) -> Result<Json<passkey::StartRegistrationResponse>, (StatusCode, String)> {
    let webauthn = state.webauthn.as_ref().ok_or_else(|| (StatusCode::SERVICE_UNAVAILABLE, "Passkey support not enabled".to_string()))?;
    let passkey_store = state.passkey_store.as_ref().ok_or_else(|| (StatusCode::SERVICE_UNAVAILABLE, "Passkey store not initialized".to_string()))?;
    let registration_state = state.registration_state.as_ref().ok_or_else(|| (StatusCode::SERVICE_UNAVAILABLE, "Registration state not initialized".to_string()))?;
    
    passkey::start_registration(
        webauthn.clone(),
        passkey_store.clone(),
        registration_state.clone(),
        Json(req),
    ).await
}

async fn passkey_complete_registration(
    State(state): State<AppState>,
    Json(req): Json<passkey::CompleteRegistrationRequest>,
) -> Result<Json<passkey::CompleteRegistrationResponse>, (StatusCode, String)> {
    let webauthn = state.webauthn.as_ref().ok_or_else(|| (StatusCode::SERVICE_UNAVAILABLE, "Passkey support not enabled".to_string()))?;
    let passkey_store = state.passkey_store.as_ref().ok_or_else(|| (StatusCode::SERVICE_UNAVAILABLE, "Passkey store not initialized".to_string()))?;
    let registration_state = state.registration_state.as_ref().ok_or_else(|| (StatusCode::SERVICE_UNAVAILABLE, "Registration state not initialized".to_string()))?;
    
    passkey::complete_registration(
        webauthn.clone(),
        passkey_store.clone(),
        registration_state.clone(),
        Json(req),
    ).await
}

async fn passkey_start_authentication(
    State(state): State<AppState>,
    Json(req): Json<passkey::StartAuthenticationRequest>,
) -> Result<Json<passkey::StartAuthenticationResponse>, (StatusCode, String)> {
    let webauthn = state.webauthn.as_ref().ok_or_else(|| (StatusCode::SERVICE_UNAVAILABLE, "Passkey support not enabled".to_string()))?;
    let passkey_store = state.passkey_store.as_ref().ok_or_else(|| (StatusCode::SERVICE_UNAVAILABLE, "Passkey store not initialized".to_string()))?;
    let auth_state = state.auth_state.as_ref().ok_or_else(|| (StatusCode::SERVICE_UNAVAILABLE, "Auth state not initialized".to_string()))?;
    
    passkey::start_authentication(
        webauthn.clone(),
        passkey_store.clone(),
        auth_state.clone(),
        Json(req),
    ).await
}

async fn passkey_complete_authentication(
    State(state): State<AppState>,
    Json(req): Json<passkey::CompleteAuthenticationRequest>,
) -> Result<Json<passkey::CompleteAuthenticationResponse>, (StatusCode, String)> {
    let webauthn = state.webauthn.as_ref().ok_or_else(|| (StatusCode::SERVICE_UNAVAILABLE, "Passkey support not enabled".to_string()))?;
    let passkey_store = state.passkey_store.as_ref().ok_or_else(|| (StatusCode::SERVICE_UNAVAILABLE, "Passkey store not initialized".to_string()))?;
    let auth_state = state.auth_state.as_ref().ok_or_else(|| (StatusCode::SERVICE_UNAVAILABLE, "Auth state not initialized".to_string()))?;
    
    passkey::complete_authentication(
        webauthn.clone(),
        passkey_store.clone(),
        auth_state.clone(),
        state.jwt.clone(),
        Json(req),
    ).await
}
