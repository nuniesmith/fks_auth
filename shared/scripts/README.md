# FKS Trading Systems - Modular Script System

## Overview

This directory contains the modular breakdown of the original monolithic `run.sh` script into focused, maintainable components. Each module has a specific responsibility and can be used independently or as part of the larger orchestration system.

## Directory Structure

```
scripts/
├── main.sh                    # Main entry point (orchestrator)
├── core/                      # Core system functionality
│   ├── config.sh             # Configuration management
│   ├── logging.sh            # Centralized logging system
│   ├── validation.sh         # System validation functions
│   └── environment.sh        # Environment detection
├── deployment/                # Deployment scripts and tools
│   ├── actions_user/        # GitHub Actions support scripts
│   ├── linode/               # Linode-specific deployment scripts
│   ├── manual/               # Manual deployment scripts
│   └── tools/                # Deployment utilities and tools
├── yaml/                      # YAML processing and generation
│   ├── processor.sh          # YAML parsing and manipulation
│   ├── generator.sh          # Generate .env and docker-compose.yml
│   └── validator.sh          # YAML syntax and structure validation
├── docker/                    # Docker management
│   ├── setup.sh              # Docker environment setup
│   ├── services.sh           # Service lifecycle management
│   ├── compose.sh            # Docker Compose operations
│   └── monitoring.sh         # Health checks and monitoring
├── python/                    # Python environment management
│   ├── environment.sh        # Environment detection and setup
│   ├── conda.sh              # Conda-specific operations
│   ├── venv.sh               # Virtual environment operations
│   └── execution.sh          # Python application execution
├── maintenance/               # System maintenance
│   ├── cleanup.sh            # Cleanup operations
│   ├── reset.sh              # Reset operations
│   ├── update.sh             # Update operations
│   └── health.sh             # Health check operations
├── ninja/                     # NinjaTrader 8 development scripts
│   ├── README.md             # Detailed NinjaTrader documentation
│   ├── startup.sh            # Interactive NinjaTrader development menu
│   ├── linux/                # Linux/WSL scripts
│   │   ├── troubleshoot.sh   # SSH and deployment troubleshooting
│   │   ├── start-api-servers.sh  # Start development API services
│   │   └── stop-api-servers.sh   # Stop development API services
│   └── windows/              # Windows PowerShell scripts
│       ├── build.ps1         # Complete build and package script
│       ├── enhanced-package.ps1  # Advanced packaging with verification
│       ├── deploy-strategy.ps1   # Deploy built DLL to NinjaTrader
│       ├── verify-package.ps1    # Verify NT8 package structure
│       ├── health-check.ps1      # Project health verification
│       └── start-api-servers.ps1 # Start development services (Windows)
└── utils/                     # Utility functions
    ├── helpers.sh            # Common helper functions
    ├── menu.sh               # Interactive menu system
    ├── install.sh            # Installation helpers
    └── test-api.js           # API endpoint testing utility
```

## Key Features

### 1. Modular Architecture
- **Single Responsibility**: Each script handles one specific area
- **Loose Coupling**: Modules can be used independently
- **Clear Dependencies**: Explicit sourcing of required modules
- **Reusable Components**: Functions can be imported across scripts

### 2. YAML Processing
- **Automatic Generation**: Creates `.env` and `docker-compose.yml` from YAML configs
- **Validation**: Syntax and structure validation for all YAML files
- **yq Integration**: Automatic installation and management of yq processor
- **Template Creation**: Generate sample configurations

### 3. Comprehensive Logging
- **Centralized System**: All modules use the same logging functions
- **Multiple Levels**: DEBUG, INFO, WARN, ERROR, FATAL, SUCCESS
- **File Rotation**: Automatic log rotation with configurable size limits
- **Colored Output**: readability with color-coded messages
- **Performance Timing**: Built-in timer functions for performance monitoring

### 4. Advanced Docker Management
- **Service Groups**: Predefined service combinations (core, ml, web, all)
- **Health Monitoring**: Comprehensive health checks and endpoint testing
- **Scaling**: Dynamic service scaling capabilities
- **Resource Monitoring**: Container metrics and resource usage
- **Log Management**: Centralized log viewing and following

### 5. Python Environment Management
- **Multi-Environment Support**: Conda, venv, and system Python
- **Auto-Detection**: Automatic environment detection and setup
- **Package Management**: Dependency installation and updates
- **Health Checks**: Environment validation and diagnostics
- **Activation Scripts**: Generate environment activation scripts

### 6. Interactive Menu System
- **User-Friendly**: Intuitive navigation and options
- **Context-Aware**: Different menus based on available systems
- **Comprehensive**: Full coverage of all system operations
- **Status Display**: Real-time system status information

### 7. Deployment Automation
- **GitHub Actions Integration**: Automated deployment workflows
- **Linode Server Management**: Server creation and provisioning
- **Manual Deployment**: Direct server deployment scripts
- **Troubleshooting Tools**: SSH and connectivity diagnostics
- **Security Management**: Token verification and secret setup

### 8. NinjaTrader 8 Development
- **Complete Build Pipeline**: Automated C#/.NET building and packaging
- **Package Management**: Create and verify NinjaTrader 8 packages
- **Development Tools**: Quick deployment and health checking
- **Cross-Platform Support**: Windows PowerShell and Linux/WSL scripts
- **Interactive Workflow**: Guided development process with startup menus

## Usage

### Basic Usage

```bash
# Run the main entry point
./scripts/main.sh

# With command line options
./scripts/main.sh --docker --clean
./scripts/main.sh --python --config ./custom_config.yaml
./scripts/main.sh --regenerate-all
```

### Direct Module Usage

```bash
# Use specific modules directly
source ./scripts/yaml/generator.sh
generate_env_from_yaml_configs

source ./scripts/docker/setup.sh
run_docker_stack

source ./scripts/python/environment.sh
setup_python_environment
```

### YAML Configuration Management

```bash
# Regenerate configuration files
./scripts/main.sh --regenerate-env
./scripts/main.sh --regenerate-compose
./scripts/main.sh --regenerate-all

# Validate YAML files
./scripts/main.sh --validate-yaml

# Show configuration summary
./scripts/main.sh --show-config
```

## Configuration Files

### Primary Configuration Sources

1. **docker_config.yaml** - Docker and infrastructure settings
2. **./config/services/*.yaml** - Individual service configurations
3. **app_config.yaml** - Application and model settings

### Generated Files

1. **.env** - Environment variables generated from YAML configs
2. **docker-compose.yml** - Docker Compose file generated from YAML configs

## Module Details

### Core Modules

#### logging.sh
- Centralized logging system with multiple levels
- File rotation and configurable output
- Performance timing functions
- Color-coded console output

#### config.sh
- Configuration file management
- Environment variable handling
- Path resolution and validation

#### validation.sh
- System requirement validation
- Dependency checking
- Health verification

#### environment.sh
- System environment detection
- Available service discovery
- Capability assessment

### YAML Modules

#### processor.sh
- YAML file parsing and manipulation
- yq installation and management
- Value extraction and path conversion
- Template creation

#### generator.sh
- Generate .env from YAML configurations
- Generate docker-compose.yml from YAML configs
- Service definition creation
- Network and volume configuration

#### validator.sh
- YAML syntax validation
- Structure verification
- Configuration consistency checks
- Error reporting

### Docker Modules

#### setup.sh
- Docker environment validation
- Service orchestration
- Container lifecycle management
- Health monitoring

#### services.sh
- Individual service management
- Service group operations
- Scaling and load balancing
- Status monitoring

#### monitoring.sh
- Health check implementation
- Endpoint testing
- Resource monitoring
- Performance metrics

### Python Modules

#### environment.sh
- Multi-environment support (conda, venv, system)
- Environment detection and setup
- Package management
- Health verification

#### execution.sh
- Application launch and monitoring
- Process management
- Error handling
- Performance tracking

### Maintenance Modules

#### cleanup.sh
- System cleanup operations
- Docker resource management
- File and directory cleanup
- Cache management

#### reset.sh
- Environment reset operations
- Configuration restoration
- Service reset
- Fresh installation

#### update.sh
- Dependency updates
- Image updates
- Package management
- Version management

#### health.sh
- Comprehensive health checks
- System diagnostics
- Performance monitoring
- Issue detection

### Utility Modules

#### menu.sh
- Interactive menu system
- User input handling
- Option presentation
- Navigation logic

#### helpers.sh
- Common utility functions
- Shared operations
- Helper utilities
- Cross-module functions

#### install.sh
- Installation helpers
- Dependency installation
- Setup assistance
- Configuration guidance

#### test-api.js
- API endpoint testing utility
- Validates FKS Trading Systems API endpoints
- Automated health checks for build server
- Response validation and error reporting

### Deployment Modules

#### actions_user/setup-github-secrets.sh
- GitHub repository secret configuration
- Interactive secret setup
- Validation and verification
- Security best practices

#### manual/deploy-dev.sh
- Direct server deployment
- Service-specific deployment
- Git repository synchronization
- Docker container management

#### linode/linode-stackscript.sh
- Automated server provisioning
- User account setup
- Security configuration
- Service installation

#### tools/verify-linode-token.sh
- API token validation
- Permission verification
- Connectivity testing
- Troubleshooting diagnostics

#### tools/troubleshoot-ssh.sh
- SSH connectivity diagnosis
- Authentication troubleshooting
- Network configuration testing
- Security verification

## Migration from Monolithic Script

### Benefits of the New Structure

1. **Maintainability**: Easier to update and modify specific functionality
2. **Testing**: Individual modules can be tested in isolation
3. **Reusability**: Functions can be used across different contexts
4. **Debugging**: Issues can be isolated to specific modules
5. **Documentation**: Each module can have focused documentation
6. **Collaboration**: Multiple developers can work on different modules

### Backward Compatibility

The main entry point (`main.sh`) maintains compatibility with the original `run.sh` interface:

- All original command line options are supported
- Same environment variables are recognized
- Identical output and behavior for standard operations

### Migration Process

1. **Phase 1**: Replace original `run.sh` with `main.sh`
2. **Phase 2**: Update any scripts that source `run.sh` functions
3. **Phase 3**: Optimize workflows to use specific modules directly
4. **Phase 4**: Customize modules for specific requirements

## Best Practices

### Module Development

1. **Single Responsibility**: Each function should have one clear purpose
2. **Error Handling**: Always include proper error handling and logging
3. **Documentation**: Document all functions and their parameters
4. **Testing**: Include basic validation and testing
5. **Consistency**: Follow established patterns and conventions

### Usage Guidelines

1. **Source Dependencies**: Always source required modules before use
2. **Check Prerequisites**: Validate system requirements before execution
3. **Handle Errors**: Implement proper error handling and cleanup
4. **Log Operations**: Use the centralized logging system
5. **Follow Conventions**: Use established naming and structure patterns

## Troubleshooting

### Common Issues

1. **Module Not Found**: Ensure proper path resolution and file existence
2. **Permission Issues**: Check file permissions and execution rights
3. **Missing Dependencies**: Verify all required tools are installed
4. **Configuration Errors**: Validate YAML syntax and structure
5. **Environment Issues**: Check Python/Docker environment setup

### Debug Mode

Enable debug logging for detailed troubleshooting:

```bash
export LOG_LEVEL=DEBUG
./scripts/main.sh
```

### Manual Module Testing

Test individual modules in isolation:

```bash
# Test YAML processing
source ./scripts/core/logging.sh
source ./scripts/yaml/processor.sh
ensure_yq_available
validate_yaml_syntax ./docker_config.yaml

# Test Docker setup
source ./scripts/core/logging.sh
source ./scripts/docker/setup.sh
check_docker_availability
```

## Future Enhancements

### Planned Features

1. **Plugin System**: Support for custom plugins and extensions
2. **Remote Configuration**: Support for remote YAML configurations
3. **Advanced Monitoring**: metrics and alerting
4. **Multi-Environment**: Support for multiple deployment environments
5. **CI/CD Integration**: continuous integration support

### Contributing

1. Follow the established module structure
2. Include comprehensive logging and error handling
3. Document all new functions and parameters
4. Test modules both individually and as part of the system
5. Maintain backward compatibility where possible

## Support

For issues, questions, or contributions:

1. Check the troubleshooting section
2. Enable debug logging for detailed information
3. Test individual modules to isolate issues
4. Review the configuration files for syntax errors
5. Consult the original documentation for context