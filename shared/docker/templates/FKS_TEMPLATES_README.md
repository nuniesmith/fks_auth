# FKS Docker Templates - Enhanced Version

## Updated Templates with FKS Standards

All templates now include:

### FKS Standard Environment Variables
- `FKS_SERVICE_NAME` - Service identifier
- `FKS_SERVICE_TYPE` - Service category
- `FKS_SERVICE_PORT` - Port assignment
- `FKS_ENVIRONMENT` - Deployment environment
- `FKS_LOG_LEVEL` - Logging verbosity
- `FKS_HEALTH_CHECK_PATH` - Health endpoint path
- `FKS_METRICS_PATH` - Metrics endpoint path

### Health Check Integration
- Basic health endpoint (`/health`)
- Detailed health endpoint (`/health/detailed`)
- Readiness probe (`/health/ready`)
- Liveness probe (`/health/live`)

### Security Features
- Non-root execution (UID 1088)
- Multi-stage builds for minimal images
- Security header configuration
- Vulnerability scanning support

### Performance Optimizations
- Layer caching strategies
- Dependency caching with BuildKit
- Resource limit configurations
- Connection pooling

## Template Usage

Each template can be used directly or extended for service-specific needs:

```dockerfile
# Example extension
FROM shared/python:3.13-slim AS base
# Add service-specific customizations
```

## Port Assignments
- fks-api: 8001
- fks-auth: 8002 
- fks-data: 8003
- fks-engine: 8004
- fks-training: 8005
- fks-transformer: 8006
- fks-worker: 8007
- fks-execution/nodes/config: 8080
- fks-ninja: 8080
- fks-web: 3000
- fks-nginx: 80
