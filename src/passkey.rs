// Passkey (WebAuthn) authentication module for fks_auth

use axum::{Json, http::StatusCode};
use serde::{Serialize, Deserialize};
use std::sync::Arc;
use webauthn_rs::prelude::*;
use std::collections::HashMap;
use url::Url;
use uuid::Uuid;
use chrono::Utc;

// Passkey storage - maps username to their passkey credentials
pub type PasskeyStore = Arc<tokio::sync::RwLock<HashMap<String, Vec<PasskeyCredential>>>>;

// Store pending registration state (includes both CreationChallengeResponse and PasskeyRegistration)
pub type RegistrationState = Arc<tokio::sync::RwLock<HashMap<String, (CreationChallengeResponse, PasskeyRegistration)>>>;

// Store pending authentication state (includes both RequestChallengeResponse and PasskeyAuthentication)
pub type AuthenticationState = Arc<tokio::sync::RwLock<HashMap<String, (RequestChallengeResponse, PasskeyAuthentication)>>>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PasskeyCredential {
    pub cred_id: Vec<u8>,
    pub counter: u32,
    pub verified: bool,
    pub registration_time: i64,
    pub device_name: Option<String>,
    pub credential: Passkey, // Store the full Passkey object
}

#[derive(Deserialize)]
pub struct StartRegistrationRequest {
    pub username: String,
    pub device_name: Option<String>,
}

#[derive(Serialize)]
pub struct StartRegistrationResponse {
    #[serde(flatten)]
    pub challenge: CreationChallengeResponse,
    pub session_id: String,
}

#[derive(Deserialize)]
pub struct CompleteRegistrationRequest {
    pub session_id: String,
    pub username: String,
    pub credential: RegisterPublicKeyCredential,
    pub device_name: Option<String>,
}

#[derive(Serialize)]
pub struct CompleteRegistrationResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Deserialize)]
pub struct StartAuthenticationRequest {
    pub username: String,
}

#[derive(Serialize)]
pub struct StartAuthenticationResponse {
    #[serde(flatten)]
    pub challenge: RequestChallengeResponse,
    pub session_id: String,
}

#[derive(Deserialize)]
pub struct CompleteAuthenticationRequest {
    pub session_id: String,
    pub username: String,
    pub credential: PublicKeyCredential,
}

#[derive(Serialize)]
pub struct CompleteAuthenticationResponse {
    pub success: bool,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub token_type: Option<String>,
    pub username: Option<String>,
    pub display_name: Option<String>,
    pub expires_at: Option<i64>,
    pub message: Option<String>,
}

// Initialize WebAuthn instance
pub fn init_webauthn(origin: &str, rp_id: &str, rp_name: &str) -> anyhow::Result<Webauthn> {
    let origin_url = Url::parse(origin)?;
    let builder = WebauthnBuilder::new(rp_id, &origin_url)?;
    let builder = builder.rp_name(rp_name);
    Ok(builder.build()?)
}

// Start passkey registration
pub async fn start_registration(
    webauthn: Arc<Webauthn>,
    passkey_store: PasskeyStore,
    registration_state: RegistrationState,
    req: Json<StartRegistrationRequest>,
) -> Result<Json<StartRegistrationResponse>, (StatusCode, String)> {
    // Get user ID (use username hash as UUID for now, or lookup from user database)
    let user_uuid = Uuid::new_v5(&Uuid::NAMESPACE_DNS, req.username.as_bytes());

    // Get existing credentials for user - convert to Base64UrlSafeData for exclusion list
    let existing_creds: Option<Vec<Base64UrlSafeData>> = {
        let store = passkey_store.read().await;
        if let Some(creds) = store.get(&req.username) {
            Some(creds.iter().map(|c| c.credential.cred_id().clone()).collect())
        } else {
            None
        }
    };

    // Start registration challenge
    let (ccr, skr) = match webauthn.start_passkey_registration(
        user_uuid,
        &req.username,
        &req.username, // Use username as display name
        existing_creds,
    ) {
        Ok(result) => result,
        Err(e) => return Err((StatusCode::BAD_REQUEST, format!("Failed to start registration: {}", e))),
    };

    // Store registration state with session ID
    let session_id = Uuid::new_v4().to_string();
    {
        let mut state = registration_state.write().await;
        state.insert(session_id.clone(), (ccr.clone(), skr));
    }

    Ok(Json(StartRegistrationResponse {
        challenge: ccr,
        session_id,
    }))
}

// Complete passkey registration
pub async fn complete_registration(
    webauthn: Arc<Webauthn>,
    passkey_store: PasskeyStore,
    registration_state: RegistrationState,
    req: Json<CompleteRegistrationRequest>,
) -> Result<Json<CompleteRegistrationResponse>, (StatusCode, String)> {
    // Retrieve and remove registration state
    let (_ccr, skr) = {
        let mut state = registration_state.write().await;
        state.remove(&req.session_id)
            .ok_or_else(|| (StatusCode::BAD_REQUEST, "Invalid or expired session".to_string()))?
    };

    // Complete registration
    let credential = match webauthn.finish_passkey_registration(&req.credential, &skr) {
        Ok(result) => result,
        Err(e) => return Err((StatusCode::BAD_REQUEST, format!("Registration failed: {}", e))),
    };

    // Store the credential
    let passkey_cred = PasskeyCredential {
        cred_id: credential.cred_id().clone().into(), // Convert Base64UrlSafeData to Vec<u8>
        counter: 0, // Initial counter is 0, will be updated on authentication
        verified: true, // Credential is verified after successful registration
        registration_time: Utc::now().timestamp(),
        device_name: req.device_name.clone(),
        credential: credential.clone(),
    };

    {
        let mut store = passkey_store.write().await;
        store.entry(req.username.clone())
            .or_insert_with(Vec::new)
            .push(passkey_cred);
    }

    Ok(Json(CompleteRegistrationResponse {
        success: true,
        message: "Passkey registered successfully".to_string(),
    }))
}

// Start passkey authentication
pub async fn start_authentication(
    webauthn: Arc<Webauthn>,
    passkey_store: PasskeyStore,
    auth_state: AuthenticationState,
    req: Json<StartAuthenticationRequest>,
) -> Result<Json<StartAuthenticationResponse>, (StatusCode, String)> {
    // Get user's credentials
    let user_creds: Vec<Passkey> = {
        let store = passkey_store.read().await;
        let creds = store.get(&req.username)
            .ok_or_else(|| (StatusCode::NOT_FOUND, "User not found or has no passkeys".to_string()))?;
        
        creds.iter().map(|c| c.credential.clone()).collect()
    };

    if user_creds.is_empty() {
        return Err((StatusCode::NOT_FOUND, "No passkeys found for user".to_string()));
    }

    // Start authentication challenge - pass user credentials
    let (acr, sar) = match webauthn.start_passkey_authentication(&user_creds) {
        Ok(result) => result,
        Err(e) => return Err((StatusCode::BAD_REQUEST, format!("Failed to start authentication: {}", e))),
    };

    // Store authentication state with session ID
    let session_id = Uuid::new_v4().to_string();
    {
        let mut state = auth_state.write().await;
        state.insert(session_id.clone(), (acr.clone(), sar));
    }

    Ok(Json(StartAuthenticationResponse {
        challenge: acr,
        session_id,
    }))
}

// Complete passkey authentication - returns JWT tokens
pub async fn complete_authentication(
    webauthn: Arc<Webauthn>,
    passkey_store: PasskeyStore,
    auth_state: AuthenticationState,
    jwt_keys: Arc<crate::JwtKeys>,
    req: Json<CompleteAuthenticationRequest>,
) -> Result<Json<CompleteAuthenticationResponse>, (StatusCode, String)> {
    // Retrieve and remove authentication state
    let (_acr, sar) = {
        let mut state = auth_state.write().await;
        state.remove(&req.session_id)
            .ok_or_else(|| (StatusCode::BAD_REQUEST, "Invalid or expired session".to_string()))?
    };

    // Get user's credentials
    let _user_creds: Vec<Passkey> = {
        let store = passkey_store.read().await;
        let creds = store.get(&req.username)
            .ok_or_else(|| (StatusCode::NOT_FOUND, "User not found".to_string()))?;
        
        creds.iter().map(|c| c.credential.clone()).collect()
    };

    // Complete authentication
    let auth_result = match webauthn.finish_passkey_authentication(&req.credential, &sar) {
        Ok(result) => result,
        Err(e) => return Err((StatusCode::UNAUTHORIZED, format!("Authentication failed: {}", e))),
    };

    // Update credential counter
    {
        let mut store = passkey_store.write().await;
        if let Some(creds) = store.get_mut(&req.username) {
            let auth_cred_id_bytes: Vec<u8> = auth_result.cred_id().clone().into();
            for cred in creds.iter_mut() {
                if cred.cred_id == auth_cred_id_bytes {
                    cred.counter = auth_result.counter();
                    break;
                }
            }
        }
    }

    // Issue JWT tokens
    let now = chrono::Utc::now();
    let access_exp = (now + chrono::Duration::minutes(jwt_keys.access_ttl)).timestamp();
    let refresh_exp = (now + chrono::Duration::minutes(jwt_keys.refresh_ttl)).timestamp();
    
    let access_claims = crate::Claims {
        sub: req.username.clone(),
        exp: access_exp as usize,
        typ: "access".to_string(),
        iss: jwt_keys.issuer.clone(),
        aud: jwt_keys.audience.clone(),
        jti: Uuid::new_v4().to_string(),
    };
    
    let refresh_claims = crate::Claims {
        sub: req.username.clone(),
        exp: refresh_exp as usize,
        typ: "refresh".to_string(),
        iss: jwt_keys.issuer.clone(),
        aud: jwt_keys.audience.clone(),
        jti: Uuid::new_v4().to_string(),
    };

    use jsonwebtoken::{encode, Header};
    let access_token = encode(&Header::new(jsonwebtoken::Algorithm::HS256), &access_claims, &jwt_keys.enc)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to create token: {}", e)))?;
    
    let refresh_token = encode(&Header::new(jsonwebtoken::Algorithm::HS256), &refresh_claims, &jwt_keys.enc)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to create token: {}", e)))?;

    Ok(Json(CompleteAuthenticationResponse {
        success: true,
        access_token: Some(access_token),
        refresh_token: Some(refresh_token),
        token_type: Some("Bearer".to_string()),
        username: Some(req.username.clone()),
        display_name: Some(req.username.clone()), // Can be enhanced with user profile lookup
        expires_at: Some(access_exp),
        message: Some("Authentication successful".to_string()),
    }))
}
