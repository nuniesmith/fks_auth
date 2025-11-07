# FKS Docker Templates ✅

This directory contains centralized Docker templates for all FKS microservices. These templates provide reusable, optimized Docker foundations that services can extend.

## 🎯 Template Status: PRODUCTION READY

All templates have been updated, tested, and are working successfully as service-agnostic bases.

## 📁 Available Templates

| Template | Status | Runtime | Description | Size |
|----------|--------|---------|-------------|------|
| `Dockerfile.base` | ✅ Working | Ubuntu 24.04 | Common utilities, Python 3.12, standard user setup | ~180MB |
| `Dockerfile.python` | ✅ Working | Python 3.13-slim | Virtual environment, build tools, security practices | ~150MB |
| `Dockerfile.rust` | ✅ Working | Distroless | Cargo tools, distroless runtime, security optimization | ~25MB |
| `Dockerfile.dotnet` | ✅ Working | ASP.NET 9.0 | Optimized builds, health checks, console app base | ~200MB |
| `Dockerfile.node` | ✅ Working | Node 22 + Nginx | Multi-stage builds, nginx serving, build optimization | ~50MB |
| `Dockerfile.nginx` | ✅ Working | Nginx 1.27.1-alpine | Security hardening, non-root user, basic config | ~20MB |

## 🏗️ Template Philosophy

These templates are **service-agnostic bases** that provide:
- ✅ Runtime environment setup
- ✅ Common dependencies and tools  
- ✅ Security best practices (non-root users)
- ✅ Multi-stage build optimization
- ✅ Health check patterns
- ❌ No service-specific source code copying
- ❌ No assumptions about project structure

## 🚀 Quick Start

### Build All Templates
```bash
cd shared/docker/templates
./build-images.sh base python rust dotnet node nginx
```

### Build Individual Template
```bash
./build-images.sh python  # Build Python template only
```

### Test with Real Service (✅ Verified Working)
```bash
cd ../../../fks_api
docker build -t fks-api:test .
docker run --rm -p 8000:8000 fks-api:test
curl http://localhost:8000/health  # Should return healthy status
```

## 📋 Usage Pattern

Services should **extend** these templates in their own Dockerfiles:

```dockerfile
# Example: fks_api/Dockerfile (✅ Working Implementation)
FROM python:3.13-slim AS build

# Follow template pattern from Dockerfile.python
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libpq-dev curl git \
    && rm -rf /var/lib/apt/lists/*
RUN python -m venv /venv

# Service-specific: add your requirements and source
COPY requirements*.txt ./
RUN pip install --no-cache-dir --upgrade pip wheel \
    && pip install --no-cache-dir -r requirements.txt
COPY src/ ./src/

# Runtime stage
FROM python:3.13-slim AS final
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 curl \
    && apt-get clean && rm -rf /var/lib/apt/lists/*
COPY --from=build /venv /venv
COPY --from=build /app/src ./src
RUN useradd --uid 1088 --create-home --shell /bin/bash appuser
USER appuser
ENV PATH="/venv/bin:$PATH"
EXPOSE 8000
CMD ["uvicorn", "src.fastapi_app:app", "--host", "0.0.0.0", "--port", "8000"]
```

## 🔧 Build Scripts

- **`build-images.sh`**: Automated template building with versioning and tagging ✅ Working
- **`deploy-fks.sh`**: Template deployment to registry  
- **`test-templates.sh`**: Template validation and testing

## 🛡️ Security Features

All templates include:
- **Non-root execution**: UID 1088 for all services
- **Minimal attack surface**: Only required dependencies
- **Multi-stage builds**: Reduced final image size
- **Latest security patches**: Regular base image updates
- **Health check patterns**: Built-in monitoring support

## ✅ Verification Results

### Build Status (All Passing ✅)
```bash
[SUCCESS] Successful builds: base python rust dotnet node nginx
[SUCCESS] All builds completed successfully!
```

### Service Integration Test (✅ Verified)
- fks_api builds successfully with new template pattern
- Container runs and serves API on port 8000  
- Health endpoint returns: `{"status":"healthy","service":"FKS Trading API","version":"1.0.0"}`
- All security practices implemented correctly

## 🔄 Next Steps for Services

1. **Update service Dockerfiles** to follow the new pattern shown above
2. **Extend templates** rather than copying/modifying them  
3. **Test builds** with the new approach
4. **Implement health checks** using provided patterns

## 📈 Benefits Achieved

- **Consistency**: All services use same security and optimization patterns
- **Maintainability**: Changes to templates propagate to all services
- **Performance**: Optimized layer caching and multi-stage builds
- **Security**: Standardized non-root execution and minimal dependencies
- **Flexibility**: Templates work as both standalone and extensible bases

Last updated: August 29, 2024 - All templates verified working ✅

## 📁 Template Overview

| Template | Description | Use Case | Size |
|----------|-------------|----------|------|
| `Dockerfile.base` | Common base image with system deps | Base layer for all services | ~200MB |
| `Dockerfile.python.improved` | Python web services (CPU/GPU) | API services, ML services | ~300MB |
| `Dockerfile.rust.improved` | High-performance Rust services | Engine, execution services | ~50MB |
| `Dockerfile.dotnet.improved` | .NET trading applications | NinjaTrader integration | ~200MB |
| `Dockerfile.node.improved` | React/Node.js web frontend | User interfaces, dashboards | ~100MB |
| `Dockerfile.nginx.improved` | Reverse proxy and static serving | Load balancing, static assets | ~25MB |

## 🚀 Quick Start

### Build Single Template
```bash
# Build Python template for CPU
./build-images.sh python

# Build with GPU support
./build-images.sh --type gpu python

# Build and push to registry
./build-images.sh --push --registry your-registry.com python
```

### Build All Templates
```bash
# Build all templates
./build-images.sh

# Build all with custom version
./build-images.sh --version 1.2.0 --push
```

## 🏗️ Architecture Decisions

### Multi-Stage Builds
All templates use multi-stage builds for:
- **Smaller images**: Separate build dependencies from runtime
- **Better caching**: Dependencies cached independently from source
- **Security**: Reduced attack surface in production images

### Security Best Practices
- **Non-root users**: All containers run as unprivileged user (UID 1088)
- **Distroless images**: Where possible (Rust template)
- **Minimal base images**: Alpine/slim variants
- **No secrets in layers**: Secrets mounted at runtime

### Performance Optimizations
- **Layer caching**: Dependencies installed before source copy
- **Cache mounts**: Package manager caches mounted during build
- **Multi-platform**: Support for CPU/GPU variants

## 📋 Template Details

### Python Template (`Dockerfile.python.improved`)
**Features:**
- Python 3.13 (latest stable)
- CPU/GPU support with conditional base images
- Virtual environment isolation
- Optimized for FastAPI/uvicorn applications

**Build Arguments:**
```bash
--build-arg PYTHON_VERSION=3.13
--build-arg BUILD_TYPE=cpu|gpu
--build-arg CUDA_VERSION=12.8.0
--build-arg SERVICE_PORT=8000
```

**Usage:**
```dockerfile
FROM your-registry.com/fks-python:latest
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY src/ ./src/
```

### Rust Template (`Dockerfile.rust.improved`)
**Features:**
- Rust 1.81 (latest stable)
- Dependency caching optimization
- Distroless runtime for minimal size
- Cargo registry optimizations

**Build Arguments:**
```bash
--build-arg RUST_VERSION=1.81
--build-arg SERVICE_PORT=8080
--build-arg APP_NAME=your-service
```

### .NET Template (`Dockerfile.dotnet.improved`)
**Features:**
- .NET 9.0 (latest LTS)
- ASP.NET Core runtime
- ReadyToRun compilation
- Optimized for web applications

**Build Arguments:**
```bash
--build-arg DOTNET_VERSION=9.0
--build-arg PROJECT_NAME=YourProject
--build-arg SERVICE_PORT=8080
```

### Node.js Template (`Dockerfile.node.improved`)
**Features:**
- Node.js 22 (latest LTS)
- React build optimization
- Nginx serving for production
- Environment variable substitution

**Build Arguments:**
```bash
--build-arg NODE_VERSION=22
--build-arg SERVICE_PORT=80
--build-arg APP_ENV=production
```

## 🔧 Customization

### Service-Specific Customization
Create service-specific Dockerfiles that extend these templates:

```dockerfile
# Example: fks_api/Dockerfile
ARG BASE_IMAGE=your-registry.com/fks-python:latest
FROM ${BASE_IMAGE}

# Service-specific dependencies
COPY requirements-api.txt .
RUN pip install -r requirements-api.txt

# Copy service code
COPY src/ ./src/

# Service-specific configuration
ENV SERVICE_NAME=fks-api
EXPOSE 8001

# Override entrypoint if needed
CMD ["uvicorn", "src.api.main:app", "--host", "0.0.0.0", "--port", "8001"]
```

### Environment-Specific Builds
```bash
# Development build
./build-images.sh --version dev python

# Staging build
./build-images.sh --version staging --registry staging-registry.com

# Production build with GPU
./build-images.sh --version 1.0.0 --type gpu --push --registry prod-registry.com
```

## 🐛 Troubleshooting

### Common Build Issues

**Build fails with permission errors:**
```bash
# Fix file permissions
find . -name "*.sh" -exec chmod +x {} \;
```

**GPU build fails:**
```bash
# Verify Docker GPU support
docker run --rm --gpus all nvidia/cuda:12.8.0-base nvidia-smi
```

**Large image sizes:**
```bash
# Analyze image layers
docker history your-image:latest
dive your-image:latest  # If dive is installed
```

### Debugging Builds
```bash
# Build with debug output
docker build --progress=plain -f Dockerfile.python.improved .

# Build specific stage
docker build --target build -f Dockerfile.python.improved .

# Interactive debugging
docker run -it --rm your-image:latest /bin/bash
```

## 📈 Performance Tips

### Build Performance
1. **Use BuildKit**: Enable Docker BuildKit for parallel builds
   ```bash
   export DOCKER_BUILDKIT=1
   ```

2. **Registry cache**: Use registry as build cache
   ```bash
   docker build --cache-from your-registry.com/fks-python:cache .
   ```

3. **Local registry**: Use local registry for faster pulls
   ```bash
   docker run -d -p 5000:5000 registry:2
   ```

### Runtime Performance
1. **Resource limits**: Set appropriate CPU/memory limits
2. **Health checks**: Implement proper health check endpoints
3. **Graceful shutdown**: Handle SIGTERM signals properly

## 🔄 CI/CD Integration

### GitHub Actions
```yaml
name: Build Docker Images
on:
  push:
    branches: [main]
    
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build images
        run: |
          cd shared/docker/templates
          ./build-images.sh --version ${{ github.sha }} --push
```

### Docker Compose
```yaml
services:
  fks-api:
    build:
      context: .
      dockerfile: shared/docker/templates/Dockerfile.python.improved
      args:
        BUILD_TYPE: cpu
    ports:
      - "8000:8000"
    environment:
      - SERVICE_NAME=fks-api
```

## 🛡️ Security Considerations

### Image Scanning
```bash
# Scan with Docker Scout
docker scout cves your-image:latest

# Scan with Trivy
trivy image your-image:latest
```

### Secrets Management
- Never bake secrets into images
- Use Docker secrets or Kubernetes secrets
- Mount secrets as files, not environment variables

### Regular Updates
- Update base images regularly
- Monitor CVE databases
- Automate security scanning in CI/CD

## 📊 Monitoring & Logging

### Health Checks
All templates include health check endpoints. Override in your services:
```dockerfile
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/api/health || exit 1
```

### Logging
Configure structured logging:
```json
{
  "timestamp": "2025-08-29T10:30:00Z",
  "level": "INFO",
  "service": "fks-api",
  "message": "Server started"
}
```

## 🤝 Contributing

1. Test changes locally with `./build-images.sh`
2. Ensure all templates build successfully
3. Update documentation for any new features
4. Follow semantic versioning for releases

## 📚 References

- [Docker Best Practices](https://docs.docker.com/develop/dev-best-practices/)
- [Multi-stage Builds](https://docs.docker.com/build/building/multi-stage/)
- [BuildKit Features](https://docs.docker.com/build/buildkit/)
- [Security Best Practices](https://docs.docker.com/engine/security/)
