use reqwest::Client; use std::time::Duration; use std::net::TcpListener;

#[tokio::test]
async fn end_to_end_flow() {
    // Spawn service
    let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    std::env::set_var("AUTH_PORT", port.to_string());
    tokio::spawn(async { fks_auth::run().await.unwrap(); });
    // Allow startup
    tokio::time::sleep(Duration::from_millis(300)).await;
    let client = Client::new();
    let base = format!("http://localhost:{port}");
    let login: serde_json::Value = client.post(format!("{base}/login"))
        .json(&serde_json::json!({"username":"jordan","password":"567326"}))
        .send().await.unwrap().json().await.unwrap();
    let access = login["access_token"].as_str().unwrap();
    // Unauthorized hit should fail
    let unauth = client.get(format!("{base}/me")).send().await.unwrap();
    assert_eq!(unauth.status(), reqwest::StatusCode::UNAUTHORIZED);
    let me = client.get(format!("{base}/me"))
        .bearer_auth(access)
        .send().await.unwrap();
    assert!(me.status().is_success());
    // Restart with custom TTLs and new port
    std::env::set_var("AUTH_ACCESS_TTL_MINUTES", "5");
    std::env::set_var("AUTH_REFRESH_TTL_MINUTES", "10");
    let port2 = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    std::env::set_var("AUTH_PORT", port2.to_string());
    tokio::spawn(async { fks_auth::run().await.unwrap(); });
    tokio::time::sleep(Duration::from_millis(300)).await;
    let base2 = format!("http://localhost:{port2}");
    let health: serde_json::Value = client.get(format!("{base2}/health")).send().await.unwrap().json().await.unwrap();
    assert_eq!(health["status"], "ok");
    assert_eq!(health["service"], "fks_auth");
    assert_eq!(health["access_ttl_min"], 5);
    assert_eq!(health["refresh_ttl_min"], 10);
}
