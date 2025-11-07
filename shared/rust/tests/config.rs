use shared_rust::env::get_var;

#[test]
fn test_defaults() {
    // Accept either "dev" (our default) or an externally provided value like "development"
    let v = get_var("APP_ENV").to_lowercase();
    assert!(v == "dev" || v == "development", "unexpected APP_ENV={v}");
}
