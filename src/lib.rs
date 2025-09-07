use axum::{routing::{get, post}, Router, extract::{State}, Json, http::{StatusCode, header, HeaderMap}};
use serde::{Serialize, Deserialize};
use std::{net::SocketAddr, sync::Arc};
use chrono::{Utc, Duration};
use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey, Algorithm};
use tower_http::cors::{CorsLayer, Any};
use tracing::{info, Level};
use tracing_subscriber::{FmtSubscriber, util::SubscriberInitExt};

#[derive(Clone)]
pub struct AppState { pub dev_user: Arc<DevUser>, pub jwt: Arc<JwtKeys>, pub started_at: i64 }

#[derive(Clone, Serialize, Deserialize)]
pub struct DevUser { pub username: String, pub password: String, pub display_name: String }

#[derive(Deserialize)] struct LoginRequest { username: String, password: String }
#[derive(Serialize)] struct LoginResponse { access_token: String, refresh_token: String, token_type: &'static str, username: String, display_name: String, expires_at: i64 }
#[derive(Deserialize)] struct RefreshRequest { refresh_token: String }
#[derive(Serialize)] struct RefreshResponse { access_token: String, expires_at: i64, token_type: &'static str }
#[derive(Serialize, Deserialize)] struct Claims { sub: String, exp: usize, typ: String }
pub struct JwtKeys { enc: EncodingKey, dec: DecodingKey, algorithm: Algorithm, access_ttl: i64, refresh_ttl: i64 }

pub async fn run() -> anyhow::Result<()> {
    init_tracing();
    let port: u16 = std::env::var("AUTH_PORT").ok().and_then(|s| s.parse().ok()).unwrap_or(4100);
    let user = DevUser { username: "jordan".into(), password: "567326".into(), display_name: "Jordan Dev".into() };
    let secret = std::env::var("AUTH_SECRET").unwrap_or_else(|_| "dev-insecure-secret-change".repeat(2));
    let access_ttl = std::env::var("AUTH_ACCESS_TTL_MINUTES").ok().and_then(|s| s.parse().ok()).unwrap_or(30);
    let refresh_ttl = std::env::var("AUTH_REFRESH_TTL_MINUTES").ok().and_then(|s| s.parse().ok()).unwrap_or(60*24);
    let jwt = JwtKeys { enc: EncodingKey::from_secret(secret.as_bytes()), dec: DecodingKey::from_secret(secret.as_bytes()), algorithm: Algorithm::HS256, access_ttl, refresh_ttl };
    let state = AppState { dev_user: Arc::new(user), jwt: Arc::new(jwt), started_at: Utc::now().timestamp() };
    let cors = CorsLayer::new().allow_methods(Any).allow_headers(Any).allow_origin(Any);
    let app = Router::new()
        .route("/health", get(health))
        .route("/login", post(login))
        .route("/refresh", post(refresh))
        .route("/me", get(me))
        .route("/verify", get(verify))
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
        "refresh_ttl_min": state.jwt.refresh_ttl
    }))
}

async fn login(State(state): State<AppState>, Json(req): Json<LoginRequest>) -> Result<Json<LoginResponse>, (StatusCode, String)> {
    if req.username != state.dev_user.username || req.password != state.dev_user.password { return Err((StatusCode::UNAUTHORIZED, "invalid credentials".into())); }
    let now = Utc::now();
    let access_exp = (now + Duration::minutes(state.jwt.access_ttl)).timestamp();
    let refresh_exp = (now + Duration::minutes(state.jwt.refresh_ttl)).timestamp();
    let access_claims = Claims { sub: req.username.clone(), exp: access_exp as usize, typ: "access".into() };
    let refresh_claims = Claims { sub: req.username.clone(), exp: refresh_exp as usize, typ: "refresh".into() };
    let access_token = encode(&Header::new(state.jwt.algorithm), &access_claims, &state.jwt.enc).map_err(internal)?;
    let refresh_token = encode(&Header::new(state.jwt.algorithm), &refresh_claims, &state.jwt.enc).map_err(internal)?;
    Ok(Json(LoginResponse { access_token, refresh_token, token_type: "Bearer", username: req.username, display_name: state.dev_user.display_name.clone(), expires_at: access_exp }))
}

async fn refresh(State(state): State<AppState>, Json(req): Json<RefreshRequest>) -> Result<Json<RefreshResponse>, (StatusCode, String)> {
    let data = decode::<Claims>(&req.refresh_token, &state.jwt.dec, &Validation::new(state.jwt.algorithm)).map_err(|_| (StatusCode::UNAUTHORIZED, "invalid refresh".into()))?;
    if data.claims.typ != "refresh" { return Err((StatusCode::UNAUTHORIZED, "wrong token type".into())); }
    let now = Utc::now();
    let access_exp = (now + Duration::minutes(state.jwt.access_ttl)).timestamp();
    let access_claims = Claims { sub: data.claims.sub, exp: access_exp as usize, typ: "access".into() };
    let access_token = encode(&Header::new(state.jwt.algorithm), &access_claims, &state.jwt.enc).map_err(internal)?;
    Ok(Json(RefreshResponse { access_token, expires_at: access_exp, token_type: "Bearer" }))
}

async fn me(State(state): State<AppState>, headers: HeaderMap) -> Result<Json<DevUser>, (StatusCode, String)> {
    let auth = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).ok_or((StatusCode::UNAUTHORIZED, "missing authorization".into()))?;
    let token = auth.strip_prefix("Bearer ").ok_or((StatusCode::UNAUTHORIZED, "invalid scheme".into()))?;
    let data = decode::<Claims>(token, &state.jwt.dec, &Validation::new(state.jwt.algorithm)).map_err(|_| (StatusCode::UNAUTHORIZED, "invalid token".into()))?;
    if data.claims.typ != "access" { return Err((StatusCode::UNAUTHORIZED, "wrong token type".into())); }
    Ok(Json((*state.dev_user).clone()))
}

// Lightweight verification endpoint for Nginx auth_request.
// Returns 200 on valid access token, 401 otherwise (empty body).
async fn verify(State(state): State<AppState>, headers: HeaderMap) -> StatusCode {
    let auth = match headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()) { Some(v) => v, None => return StatusCode::UNAUTHORIZED };
    let token = match auth.strip_prefix("Bearer ") { Some(t) => t, None => return StatusCode::UNAUTHORIZED };
    let Ok(data) = decode::<Claims>(token, &state.jwt.dec, &Validation::new(state.jwt.algorithm)) else { return StatusCode::UNAUTHORIZED };
    if data.claims.typ != "access" { return StatusCode::UNAUTHORIZED; }
    StatusCode::OK
}

fn internal<E: std::fmt::Display>(e: E) -> (StatusCode, String) { (StatusCode::INTERNAL_SERVER_ERROR, format!("internal error: {e}")) }
