use reqwest::Client;
use tokio::time::{sleep, Duration};
use serde::{Deserialize};

#[derive(Deserialize)]
struct LoginResponse { 
    access_token: String, 
    refresh_token: String, 
    #[serde(rename = "username")]
    _username: String 
}
#[derive(Deserialize)]
struct RefreshResponse { access_token: String }
#[derive(Deserialize)]
struct MeResponse { user: UserProfile }
#[derive(Deserialize)]
struct UserProfile { username: String, display_name: String }

// Helper to wait until health endpoint responds or timeout
async fn wait_health(port: u16) {
    let client = Client::new();
    for _ in 0..30 { // up to ~6s
        if let Ok(r) = client.get(format!("http://127.0.0.1:{port}/health")).send().await {
            if r.status().is_success() { return; }
        }
        sleep(Duration::from_millis(200)).await;
    }
    panic!("health endpoint not ready after timeout");
}

#[tokio::test]
async fn test_login_refresh_verify_me_flow() {
    // Set env vars FIRST before spawning server
    std::env::set_var("AUTH_SECRET", "testsecretkey1234567890");
    std::env::set_var("AUTH_ISSUER", "fks_auth");
    std::env::set_var("AUTH_AUDIENCE", "fks_web");
    
    let port = 5011u16;
    tokio::spawn(async move { 
        let _ = fks_auth::run_with_port(port).await; 
    });
    wait_health(port).await;
    
    // Extra wait to ensure server is fully initialized
    sleep(Duration::from_millis(500)).await;

    let client = Client::new();

    // Login
    let login_resp = client
        .post(format!("http://127.0.0.1:{port}/login"))
        .json(&serde_json::json!({"username":"jordan","password":"567326"}))
        .send().await.expect("login request")
        .error_for_status().expect("login status ok")
        .json::<LoginResponse>().await.expect("login json");

    assert!(!login_resp.access_token.is_empty());
    assert!(!login_resp.refresh_token.is_empty());

    // Debug: Check server config
    let config_resp = client
        .get(format!("http://127.0.0.1:{port}/config"))
        .send().await.expect("config req")
        .json::<serde_json::Value>().await.expect("config json");
    println!("Server config: {}", serde_json::to_string_pretty(&config_resp).unwrap());
    
    // Debug: Introspect the access token
    let introspect_resp = client
        .post(format!("http://127.0.0.1:{port}/introspect"))
        .json(&serde_json::json!({"token": login_resp.access_token}))
        .send().await.expect("introspect req")
        .json::<serde_json::Value>().await.expect("introspect json");
    println!("Token introspection: {}", serde_json::to_string_pretty(&introspect_resp).unwrap());
    
    // Verify endpoint
    let verify_resp = client
        .get(format!("http://127.0.0.1:{port}/verify"))
        .header("Authorization", format!("Bearer {}", login_resp.access_token))
        .send().await.expect("verify req");
    let verify_status = verify_resp.status();
    let verify_body = verify_resp.text().await.unwrap_or_default();
    println!("/verify status: {:?}, body: {}", verify_status, verify_body);
    assert!(verify_status.is_success(), "verify should succeed");

    // Refresh
    let refresh_resp = client
        .post(format!("http://127.0.0.1:{port}/refresh"))
        .json(&serde_json::json!({"refresh_token": login_resp.refresh_token}))
        .send().await.expect("refresh req")
        .error_for_status().expect("refresh status ok")
        .json::<RefreshResponse>().await.expect("refresh json");

    assert!(!refresh_resp.access_token.is_empty());
    assert_ne!(refresh_resp.access_token, login_resp.access_token, "new access token issued");

    // Me
    let me_resp = client
        .get(format!("http://127.0.0.1:{port}/me"))
        .header("Authorization", format!("Bearer {}", refresh_resp.access_token))
        .send().await.expect("me req")
        .error_for_status().expect("me status ok")
        .json::<MeResponse>().await.expect("me json");

    assert_eq!(me_resp.user.username, "jordan");
    assert!(!me_resp.user.display_name.is_empty());
}
