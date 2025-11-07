# FKS Shared Templates 🎯

Comprehensive template system for all FKS microservices and components. These templates provide standardized patterns with environment variables, health endpoints, and nginx/docker integration.

## 📁 Template Structure

```
shared_templates/
├── docker/          # Docker & containerization templates
├── python/          # Python service templates  
├── rust/           # Rust service templates
├── dotnet/         # .NET service templates
├── react/          # React/Node.js frontend templates
├── nginx/          # Nginx reverse proxy templates
├── scripts/        # Shell script templates
├── actions/        # GitHub Actions workflows
├── schema/         # JSON schema definitions
└── common/         # Common configuration templates
```

## 🎯 Design Philosophy

### Standardized Environment Variables
All templates use consistent environment variable patterns:
- `FKS_SERVICE_NAME` - Service identifier
- `FKS_SERVICE_PORT` - Service port assignment
- `FKS_SERVICE_TYPE` - Service category (api, engine, data, etc.)
- `FKS_ENVIRONMENT` - Deployment environment (dev, staging, prod)
- `FKS_LOG_LEVEL` - Logging verbosity
- `FKS_HEALTH_CHECK_PATH` - Health endpoint path

### Health Check Integration
Every template includes:
- Basic health endpoint (`/health`)
- Detailed health endpoint (`/health/detailed`)
- Readiness probe (`/health/ready`)
- Liveness probe (`/health/live`)
- Standardized health response format

### Nginx Integration
Templates are designed for nginx reverse proxy:
- Service discovery through environment variables
- Consistent URL routing patterns
- Load balancing support
- SSL termination integration
- CORS header management

### Docker Optimization
- Multi-stage builds for minimal production images
- Consistent layer caching strategies
- Security best practices (non-root users)
- Resource limit definitions
- Health check configurations

## 🚀 Quick Start

1. **Choose Template Category**: Select appropriate template based on service type
2. **Copy Template**: Copy to your service directory
3. **Customize Variables**: Update environment-specific values
4. **Test Locally**: Validate with Docker Compose
5. **Deploy**: Use with nginx reverse proxy

## 📋 Template Categories

### Docker Templates
- **Base Images**: Foundation containers with common utilities
- **Runtime Templates**: Language-specific optimized runtimes
- **Multi-stage Patterns**: Build/runtime separation
- **Security Configurations**: Non-root users, minimal attack surface

### Service Templates
- **Python APIs**: FastAPI/Flask with health endpoints
- **Rust Services**: High-performance backend services
- **.NET Applications**: ASP.NET Core web applications
- **React Frontends**: Production-ready static hosting

### Infrastructure Templates
- **Nginx Configurations**: Reverse proxy with service routing
- **GitHub Actions**: CI/CD pipeline definitions
- **Shell Scripts**: Deployment and maintenance automation
- **Schema Definitions**: API contract specifications

## 🛡️ Security Features

- **Environment Isolation**: Proper secret management
- **Non-root Execution**: All containers run as unprivileged users
- **Network Segmentation**: Service-specific network policies
- **TLS Configuration**: SSL/TLS termination at nginx layer
- **Input Validation**: Schema-based request validation

## 📊 Monitoring Integration

- **Structured Logging**: JSON format with correlation IDs
- **Metrics Collection**: Prometheus-compatible metrics
- **Distributed Tracing**: OpenTelemetry integration
- **Health Monitoring**: Multi-level health check system
- **Error Tracking**: Centralized error aggregation

## 🔧 Customization Guide

Each template supports customization through:
1. **Environment Variables**: Runtime configuration
2. **Build Arguments**: Build-time customization
3. **Configuration Files**: Service-specific settings
4. **Feature Flags**: Optional functionality toggles

## 📚 Template Documentation

Detailed documentation for each template category is available in their respective directories:
- [Docker Templates](./docker/README.md)
- [Python Templates](./python/README.md)
- [Rust Templates](./rust/README.md)
- [React Templates](./react/README.md)
- [Nginx Templates](./nginx/README.md)
- [Scripts Templates](./scripts/README.md)
- [Actions Templates](./actions/README.md)
- [Schema Templates](./schema/README.md)

## 🎉 Benefits

✅ **Consistency**: Standardized patterns across all services
✅ **Maintainability**: Centralized template updates
✅ **Security**: Built-in security best practices  
✅ **Performance**: Optimized build and runtime configurations
✅ **Monitoring**: Comprehensive observability integration
✅ **Documentation**: Self-documenting template system

---

*Last updated: August 29, 2025 - FKS Template System v1.0*
