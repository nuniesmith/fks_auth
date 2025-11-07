# Docker Build Job Separation

## 🎯 Problem Solved

The FKS deployment was building all Docker services simultaneously on a single GitHub runner, causing:
- Runner resource exhaustion (CPU/Memory limits)
- 33+ minute build timeouts 
- Failed deployments due to resource limits
- Wasted GitHub Actions minutes

## 🚀 Solution: Separated Docker Build Jobs

The workflow now uses **three separate Docker build jobs** that run in parallel:

### 1. 🐳 `build-docker-api` 
**Purpose**: Python servers and backend services
- **Services**: `api`, `worker`, `data`, `backend`, `server`
- **Target Files**: `docker-compose.api.yml` or filtered services from main compose
- **Use Case**: FKS API servers, data processing workers

### 2. 🌐 `build-docker-web`
**Purpose**: React web interface and frontend services  
- **Services**: `web`, `frontend`, `ui`, `client`, `app`
- **Target Files**: `docker-compose.web.yml` or filtered services from main compose
- **Use Case**: FKS React web interface, client applications

### 3. 🔐 `build-docker-auth`
**Purpose**: Authentication and authorization services
- **Services**: `auth`, `oauth`, `keycloak`, `identity`, `session`
- **Target Files**: `docker-compose.auth.yml` or filtered services from main compose
- **Use Case**: Custom auth services (skips if using external auth)

## 📋 How It Works

### Priority Order:
1. **Specific Compose Files**: Looks for `docker-compose.{type}.yml` first
2. **Service Filtering**: Filters services from main `docker-compose.yml` by name patterns
3. **Single Dockerfile**: Builds single service based on service name pattern
4. **Graceful Skip**: Logs info and continues if no relevant services found

### Example Service Detection:
```bash
# API Job detects these services:
docker-compose.yml:
  api: ...      ✅ Builds
  worker: ...   ✅ Builds  
  web: ...      ❌ Skips (wrong job)
  
# Web Job detects these services:
docker-compose.yml:
  web: ...      ✅ Builds
  frontend: ... ✅ Builds
  api: ...      ❌ Skips (wrong job)
```

## 🎁 Benefits

### Performance:
- **Parallel Building**: Each job runs on separate runners
- **Resource Distribution**: No single runner overload
- **Faster Builds**: Parallel execution vs sequential

### Reliability:
- **Reduced Timeouts**: Smaller build scope per job
- **Isolated Failures**: One service type failure doesn't block others
- **Better Error Isolation**: Easier to identify which service type failed

### Resource Efficiency:
- **GitHub Minutes**: More efficient runner usage
- **Memory Usage**: Distributed across multiple runners
- **Build Cache**: Better cache utilization per service type

## 🔧 Configuration Examples

### FKS Project Structure:
```yaml
# For FKS, this creates optimal separation:
build-docker-api:    # api, worker, data services
build-docker-web:    # web React interface  
build-docker-auth:   # (skips - FKS uses external auth)
```

### ATS Project Structure:
```yaml
# For ATS (simpler), this works efficiently:
build-docker-api:    # Main ATS server (if service name contains 'server')
build-docker-web:    # (skips - no web interface)
build-docker-auth:   # (skips - no custom auth)
```

## 🎯 Service Naming Patterns

The system uses these patterns to auto-detect service types:

### API Services:
- `api`, `backend`, `server`, `worker`, `data`

### Web Services:  
- `web`, `frontend`, `ui`, `client`, `app`

### Auth Services:
- `auth`, `oauth`, `keycloak`, `identity`, `session`

## 💡 Usage Tips

1. **Use Specific Compose Files**: For best control, use `docker-compose.api.yml`, etc.
2. **Service Naming**: Follow naming patterns for automatic detection
3. **Monitor Builds**: Each job provides detailed logging about what it's building
4. **Fallback Behavior**: System gracefully handles missing services

## 🔍 Troubleshooting

### Service Not Building?
- Check service name matches patterns above
- Verify compose file exists or main compose has the service
- Look at job logs to see detection results

### Build Still Slow?
- Consider further splitting large services
- Check if service has large dependencies
- Optimize Dockerfile layers

## 🚀 Next Steps

This separation is now ready for all services:
- ✅ **FKS**: Will now build api/web/auth separately
- ✅ **ATS**: Will efficiently handle single service builds  
- ✅ **Nginx**: Will skip unnecessary builds gracefully

The system maintains full backward compatibility while providing much better performance and reliability!
- **Smart Building**: Detects code changes and only builds when necessary
- **Consistent Tagging**: Uses branch name + git SHA for reliable versioning
- **Multi-Service Support**: Builds all services with appropriate configurations
- **Docker Hub Integration**: Pushes to your Docker registry for reuse

### 🚀 **Server Deployment Jobs**
**Purpose**: Deploy physical servers and pull pre-built images
**Dependencies**: Each depends on `build-docker-images` job completion

#### **Modified Deployment Flow:**
1. **build-docker-images** ➜ Builds all Docker images
2. **deploy-fks_auth** ➜ Creates auth server, pulls pre-built images
3. **deploy-fks_api** ➜ Creates API server, pulls pre-built images  
4. **deploy-fks_web** ➜ Creates web server, pulls pre-built images
5. **deployment-summary** ➜ Updates DNS and shows summary

## Benefits

### ⚡ **Performance Improvements**
- **Parallel Building**: All images build simultaneously instead of per-server
- **Build Once, Deploy Many**: Images can be reused across multiple servers
- **Faster Deployments**: Servers just pull pre-built images instead of building

### 🔄 **Workflow Efficiency**
- **Independent Concerns**: Building and deployment are separate responsibilities
- **Reusable Artifacts**: Built images can be used for testing, staging, production
- **Selective Building**: Only builds when code actually changes

### 🛠️ **Maintenance Benefits**
- **Cleaner Logs**: Build logs separate from deployment logs
- **Better Debugging**: Easier to identify build vs deployment issues
- **Resource Optimization**: GitHub Actions runners used more efficiently

## Configuration Changes

### **Deployment Jobs Updated:**
```yaml
with:
  skip_docker_build: true          # Skip building in deployment
  build_docker_on_changes: false  # Not needed anymore
```

### **Dependencies Updated:**
```yaml
needs: [build-docker-images, previous-job]  # Wait for images + previous server
```

### **Conditional Logic:**
- Build job only runs for 'deploy' actions
- Deployment jobs proceed even if build is skipped (reuse existing images)
- DNS updates only run if at least one deployment succeeds

## Image Versioning Strategy

### **Tags Generated:**
- **Versioned**: `fks_auth:main-a1b2c3d4` (branch + 8-char SHA)
- **Latest**: `fks_auth:latest` (always points to newest)

### **Advantages:**
- **Reproducible Deployments**: Exact image versions are trackable
- **Rollback Capability**: Can deploy specific versions if needed
- **Development Support**: Different branches get different tags

## Environment Variables

### **Build-Time Variables:**
- `SERVICE_TYPE`: Configures which service to build (auth, api, web, worker, data)
- `SERVICE_PORT`: Sets the service port
- `BUILD_ENV`: Set to 'production' for optimized builds
- `NODE_VERSION`: Node.js version for web service (20)

### **Runtime Variables:**
- All existing environment variables still work
- Docker images are pre-configured but can be overridden at runtime

## Usage

### **Normal Deployment** (builds images + deploys):
```bash
# Workflow will build images first, then deploy servers
gh workflow run fks_deploy.yml --ref main -f action_type=deploy
```

### **Skip Docker Build** (use existing images):
```bash
# Skip building, use existing latest images
gh workflow run fks_deploy.yml --ref main -f action_type=deploy -f skip_docker_build=true
```

### **Infrastructure Only** (servers without new images):
```bash
# Deploy infrastructure but skip building new images
gh workflow run fks_deploy.yml --ref main -f action_type=deploy -f skip_docker_build=true
```

## Next Steps

1. **Test the new workflow** with a deployment
2. **Verify images** are built and pushed to Docker Hub
3. **Check server deployments** pull the correct images
4. **Monitor performance** improvements in build/deploy times

This separation makes the workflow more modular, efficient, and easier to maintain while supporting your multi-service architecture on dedicated servers!
