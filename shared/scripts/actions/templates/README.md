# Universal Service Startup Templates

This directory contains standardized startup script templates that can be shared across all service repositories.

## Files

### `start.sh` - Universal Startup Template
The main template that provides common functionality for all services:
- Environment detection (cloud, laptop, container, etc.)
- Docker and Docker Compose validation
- Smart Docker networking checks (skips in deployment environments)
- Build strategy detection (local vs remote images)
- Standardized logging and error handling
- Service connectivity testing

### Service-Specific Templates
- `nginx-start.sh` - Nginx Reverse Proxy configuration
- `ats-start.sh` - ATS Game Server configuration  
- `fks_start.sh` - FKS Trading System configuration

## Usage in Service Repositories

To use these templates in a service repository:

1. **Download and use directly:**
   ```bash
   curl -s https://raw.githubusercontent.com/nuniesmith/actions/main/scripts/templates/nginx-start.sh -o start.sh
   chmod +x start.sh
   ```

2. **Create a service-specific wrapper:**
   ```bash
   #!/bin/bash
   export SERVICE_NAME="myservice"
   export SERVICE_DISPLAY_NAME="My Service"
   export DEFAULT_HTTP_PORT="8080"
   export DEFAULT_HTTPS_PORT="8443"
   
   curl -s https://raw.githubusercontent.com/nuniesmith/actions/main/scripts/templates/start.sh | bash
   ```

## Key Features

### Smart Environment Detection
- **Cloud**: Detected via cloud metadata files, environment variables
- **Container**: Docker/Kubernetes environment detection
- **Laptop**: Local development with `.local` marker file
- **Resource Constrained**: Memory-based detection

### Deployment Environment Compatibility
- Skips Docker network tests when running as service users (`*_user`)
- Compatible with GitHub Actions deployment workflow
- Handles both root and non-root execution contexts

### Build Strategy
- **Local**: Builds images on the machine (laptops, dev environments)
- **Remote**: Pulls pre-built images from Docker Hub (cloud, production)
- Automatic fallback from pull failures to local build

### Docker Hub Integration
- Automatic login with `DOCKER_USERNAME` and `DOCKER_TOKEN`
- Configurable namespace and registry
- Pull failure handling with local build fallback

## Customization

Services can override the following functions:
- `create_custom_env()` - Add service-specific environment variables
- `test_connectivity()` - Custom connectivity tests
- `parse_args()` - Additional command-line arguments

## Command Line Options

- `--help, -h` - Show help message
- `--set-laptop` - Mark environment as laptop (creates `.local` file)
- `--show-env` - Display detected environment information

## Environment Variables

- `BUILD_LOCAL=true/false` - Override build strategy
- `DOCKER_NAMESPACE=name` - Docker Hub namespace (default: nuniesmith)
- `DOCKER_REGISTRY=url` - Docker registry URL (default: docker.io)
- `DOCKER_USERNAME=user` - Docker Hub username for authentication
- `DOCKER_TOKEN=token` - Docker Hub token for authentication
- `SERVICE_NAME=name` - Service identifier (required)
- `SERVICE_DISPLAY_NAME=name` - Human-readable service name
- `DEFAULT_HTTP_PORT=port` - Default HTTP port (default: 80)
- `DEFAULT_HTTPS_PORT=port` - Default HTTPS port (default: 443)

## Integration with GitHub Actions

These templates are designed to work seamlessly with the GitHub Actions deployment workflow:

1. The workflow handles Docker network creation
2. Templates skip network tests in deployment environments
3. Service users are automatically detected
4. Build strategy adapts to cloud deployment context

## Maintenance

To update all service repositories with new template versions:

1. Update the universal template in this repository
2. Service repositories will automatically use the latest version on next deployment
3. For immediate updates, re-run deployments or manually update start.sh files

## Migration Guide

To migrate existing service repositories:

1. Backup existing `start.sh` file
2. Replace with service-specific template from this repository
3. Test in development environment
4. Deploy to production

The templates maintain backward compatibility with existing service configurations while providing enhanced functionality and standardization.
