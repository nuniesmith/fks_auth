# FKS Rust Service Template - Environment Configuration
# Standard environment handling for FKS Rust microservices

use serde::{Deserialize, Serialize};
use std::env;
use std::fmt;
use anyhow::{Result, Context};

/// FKS standard health check response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub service: String,
    pub service_type: String,
    pub version: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub environment: String,
    pub uptime_seconds: Option<u64>,
    pub dependencies: std::collections::HashMap<String, String>,
}

impl HealthResponse {
    pub fn healthy(service_name: &str, service_type: &str, environment: &str) -> Self {
        Self {
            status: "healthy".to_string(),
            service: service_name.to_string(),
            service_type: service_type.to_string(),
            version: "1.0.0".to_string(),
            timestamp: chrono::Utc::now(),
            environment: environment.to_string(),
            uptime_seconds: None,
            dependencies: std::collections::HashMap::new(),
        }
    }

    pub fn unhealthy(service_name: &str, service_type: &str, environment: &str, reason: &str) -> Self {
        let mut response = Self::healthy(service_name, service_type, environment);
        response.status = "unhealthy".to_string();
        response.dependencies.insert("error".to_string(), reason.to_string());
        response
    }
}

/// FKS standard environment configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FKSConfig {
    // FKS Standard Environment Variables
    pub fks_service_name: String,
    pub fks_service_type: String,
    pub fks_service_port: u16,
    pub fks_environment: String,
    pub fks_log_level: String,
    pub fks_health_check_path: String,
    pub fks_metrics_path: String,
    pub fks_config_path: String,
    pub fks_data_path: String,

    // Database Configuration
    pub database_url: Option<String>,
    pub database_host: String,
    pub database_port: u16,
    pub database_name: String,
    pub database_user: String,
    pub database_password: Option<String>,

    // Redis Configuration
    pub redis_url: Option<String>,
    pub redis_host: String,
    pub redis_port: u16,
    pub redis_password: Option<String>,

    // Security Configuration
    pub secret_key: String,
    pub api_key: Option<String>,
    pub jwt_secret: Option<String>,

    // Trading Configuration
    pub risk_max_per_trade: f64,
    pub risk_max_drawdown: f64,
    pub trading_mode: String,

    // Performance Configuration
    pub worker_threads: Option<usize>,
    pub max_connections: u32,

    // Monitoring Configuration
    pub enable_metrics: bool,
    pub enable_tracing: bool,
}

impl Default for FKSConfig {
    fn default() -> Self {
        Self {
            fks_service_name: "fks-service".to_string(),
            fks_service_type: "engine".to_string(),
            fks_service_port: 8080,
            fks_environment: "development".to_string(),
            fks_log_level: "INFO".to_string(),
            fks_health_check_path: "/health".to_string(),
            fks_metrics_path: "/metrics".to_string(),
            fks_config_path: "/app/config".to_string(),
            fks_data_path: "/app/data".to_string(),
            database_url: None,
            database_host: "localhost".to_string(),
            database_port: 5432,
            database_name: "fks".to_string(),
            database_user: "fks".to_string(),
            database_password: None,
            redis_url: None,
            redis_host: "localhost".to_string(),
            redis_port: 6379,
            redis_password: None,
            secret_key: "dev-secret-key".to_string(),
            api_key: None,
            jwt_secret: None,
            risk_max_per_trade: 0.01,
            risk_max_drawdown: 0.05,
            trading_mode: "simulation".to_string(),
            worker_threads: None,
            max_connections: 1000,
            enable_metrics: true,
            enable_tracing: false,
        }
    }
}

impl FKSConfig {
    /// Load configuration from environment variables
    pub fn from_env() -> Result<Self> {
        let mut config = Self::default();

        // FKS Standard Environment Variables
        config.fks_service_name = env::var("FKS_SERVICE_NAME").unwrap_or(config.fks_service_name);
        config.fks_service_type = env::var("FKS_SERVICE_TYPE").unwrap_or(config.fks_service_type);
        config.fks_service_port = env::var("FKS_SERVICE_PORT")
            .unwrap_or(config.fks_service_port.to_string())
            .parse()
            .context("Invalid FKS_SERVICE_PORT")?;
        config.fks_environment = env::var("FKS_ENVIRONMENT").unwrap_or(config.fks_environment);
        config.fks_log_level = env::var("FKS_LOG_LEVEL").unwrap_or(config.fks_log_level);
        config.fks_health_check_path = env::var("FKS_HEALTH_CHECK_PATH").unwrap_or(config.fks_health_check_path);
        config.fks_metrics_path = env::var("FKS_METRICS_PATH").unwrap_or(config.fks_metrics_path);
        config.fks_config_path = env::var("FKS_CONFIG_PATH").unwrap_or(config.fks_config_path);
        config.fks_data_path = env::var("FKS_DATA_PATH").unwrap_or(config.fks_data_path);

        // Database Configuration
        config.database_url = env::var("DATABASE_URL").ok();
        config.database_host = env::var("DATABASE_HOST").unwrap_or(config.database_host);
        config.database_port = env::var("DATABASE_PORT")
            .unwrap_or(config.database_port.to_string())
            .parse()
            .context("Invalid DATABASE_PORT")?;
        config.database_name = env::var("DATABASE_NAME").unwrap_or(config.database_name);
        config.database_user = env::var("DATABASE_USER").unwrap_or(config.database_user);
        config.database_password = env::var("DATABASE_PASSWORD").ok();

        // Redis Configuration
        config.redis_url = env::var("REDIS_URL").ok();
        config.redis_host = env::var("REDIS_HOST").unwrap_or(config.redis_host);
        config.redis_port = env::var("REDIS_PORT")
            .unwrap_or(config.redis_port.to_string())
            .parse()
            .context("Invalid REDIS_PORT")?;
        config.redis_password = env::var("REDIS_PASSWORD").ok();

        // Security Configuration
        config.secret_key = env::var("SECRET_KEY").unwrap_or(config.secret_key);
        config.api_key = env::var("API_KEY").ok();
        config.jwt_secret = env::var("JWT_SECRET").ok();

        // Trading Configuration
        config.risk_max_per_trade = env::var("RISK_MAX_PER_TRADE")
            .unwrap_or(config.risk_max_per_trade.to_string())
            .parse()
            .context("Invalid RISK_MAX_PER_TRADE")?;
        config.risk_max_drawdown = env::var("RISK_MAX_DRAWDOWN")
            .unwrap_or(config.risk_max_drawdown.to_string())
            .parse()
            .context("Invalid RISK_MAX_DRAWDOWN")?;
        config.trading_mode = env::var("TRADING_MODE").unwrap_or(config.trading_mode);

        // Performance Configuration
        config.worker_threads = env::var("WORKER_THREADS").ok().and_then(|v| v.parse().ok());
        config.max_connections = env::var("MAX_CONNECTIONS")
            .unwrap_or(config.max_connections.to_string())
            .parse()
            .context("Invalid MAX_CONNECTIONS")?;

        // Monitoring Configuration
        config.enable_metrics = env::var("ENABLE_METRICS")
            .unwrap_or(config.enable_metrics.to_string())
            .parse()
            .context("Invalid ENABLE_METRICS")?;
        config.enable_tracing = env::var("ENABLE_TRACING")
            .unwrap_or(config.enable_tracing.to_string())
            .parse()
            .context("Invalid ENABLE_TRACING")?;

        Ok(config)
    }

    /// Get complete database URL
    pub fn get_database_url(&self) -> String {
        if let Some(url) = &self.database_url {
            url.clone()
        } else {
            let password_part = if let Some(password) = &self.database_password {
                format!(":{}", password)
            } else {
                String::new()
            };
            format!(
                "postgresql://{}{}@{}:{}/{}",
                self.database_user,
                password_part,
                self.database_host,
                self.database_port,
                self.database_name
            )
        }
    }

    /// Get complete Redis URL
    pub fn get_redis_url(&self) -> String {
        if let Some(url) = &self.redis_url {
            url.clone()
        } else {
            let password_part = if let Some(password) = &self.redis_password {
                format!("{}@", password)
            } else {
                String::new()
            };
            format!(
                "redis://{}{}:{}",
                password_part,
                self.redis_host,
                self.redis_port
            )
        }
    }

    /// Check if running in production environment
    pub fn is_production(&self) -> bool {
        self.fks_environment.to_lowercase() == "production"
    }

    /// Check if running in development environment
    pub fn is_development(&self) -> bool {
        matches!(self.fks_environment.to_lowercase().as_str(), "development" | "dev")
    }

    /// Initialize service with logging
    pub fn initialize_service(&self) -> Result<()> {
        // Create required directories
        std::fs::create_dir_all(&self.fks_config_path)
            .context("Failed to create config directory")?;
        std::fs::create_dir_all(&self.fks_data_path)
            .context("Failed to create data directory")?;

        // Initialize logging
        env_logger::Builder::from_env(
            env_logger::Env::default().default_filter_or(&self.fks_log_level)
        ).init();

        log::info!("🚀 Initializing {} ({})", self.fks_service_name, self.fks_service_type);
        log::info!("📊 Environment: {}", self.fks_environment);
        log::info!("🔌 Port: {}", self.fks_service_port);
        log::info!("🏥 Health Check: {}", self.fks_health_check_path);
        log::info!("📈 Metrics: {}", self.fks_metrics_path);

        Ok(())
    }

    /// Create health check response
    pub fn get_health_response(&self) -> HealthResponse {
        HealthResponse::healthy(&self.fks_service_name, &self.fks_service_type, &self.fks_environment)
    }
}

impl fmt::Display for FKSConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "FKSConfig {{ service: {}, type: {}, port: {}, env: {} }}",
            self.fks_service_name,
            self.fks_service_type,
            self.fks_service_port,
            self.fks_environment
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_default_config() {
        let config = FKSConfig::default();
        assert_eq!(config.fks_service_name, "fks-service");
        assert_eq!(config.fks_service_port, 8080);
        assert_eq!(config.fks_environment, "development");
    }

    #[test]
    fn test_config_from_env() {
        env::set_var("FKS_SERVICE_NAME", "test-service");
        env::set_var("FKS_SERVICE_PORT", "9090");
        env::set_var("FKS_ENVIRONMENT", "test");

        let config = FKSConfig::from_env().unwrap();
        assert_eq!(config.fks_service_name, "test-service");
        assert_eq!(config.fks_service_port, 9090);
        assert_eq!(config.fks_environment, "test");

        // Clean up
        env::remove_var("FKS_SERVICE_NAME");
        env::remove_var("FKS_SERVICE_PORT");
        env::remove_var("FKS_ENVIRONMENT");
    }

    #[test]
    fn test_database_url_generation() {
        let mut config = FKSConfig::default();
        config.database_user = "testuser".to_string();
        config.database_password = Some("testpass".to_string());
        config.database_host = "testhost".to_string();
        config.database_port = 5433;
        config.database_name = "testdb".to_string();

        let url = config.get_database_url();
        assert_eq!(url, "postgresql://testuser:testpass@testhost:5433/testdb");
    }

    #[test]
    fn test_health_response() {
        let config = FKSConfig::default();
        let health = config.get_health_response();
        assert_eq!(health.status, "healthy");
        assert_eq!(health.service, config.fks_service_name);
        assert_eq!(health.service_type, config.fks_service_type);
    }
}
