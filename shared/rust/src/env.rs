use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::env;

static DEFAULTS: Lazy<HashMap<&'static str, &'static str>> = Lazy::new(|| {
    HashMap::from([
        ("APP_ENV", "dev"),
        ("LOG_LEVEL", "INFO"),
        ("RISK_MAX_PER_TRADE", "0.01"),
        ("DEBUG_MODE", "false"),
    ])
});

static ENV_CACHE: Lazy<HashMap<String, String>> = Lazy::new(|| {
    let _ = dotenvy::dotenv();
    let mut map: HashMap<String, String> = DEFAULTS
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    for (k, v) in env::vars() {
        map.insert(k, v);
    }
    map
});

pub fn get_var(key: &str) -> String {
    ENV_CACHE
        .get(key)
        .cloned()
        .unwrap_or_else(|| DEFAULTS.get(key).unwrap_or(&"").to_string())
}

pub fn get_bool(key: &str) -> bool {
    matches!(get_var(key).to_lowercase().as_str(), "1" | "true" | "yes" | "on")
}

pub fn get_f64(key: &str) -> f64 {
    get_var(key).parse().unwrap_or(0.0)
}
