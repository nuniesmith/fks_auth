#!/usr/bin/env python3
"""
Generate .env file from YAML configuration
Usage: python generate_env.py [--config CONFIG_PATH] [--output OUTPUT_PATH]
"""

import yaml
import argparse
import os
import sys
from datetime import datetime
from typing import Dict, Any, List


def flatten_dict(d: Dict[str, Any], parent_key: str = '', sep: str = '_') -> Dict[str, Any]:
    """Flatten nested dictionary into single-level dictionary with underscore-separated keys."""
    items = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict) and not any(isinstance(vv, dict) for vv in v.values()):
            # If it's a dict but doesn't contain nested dicts, flatten it
            items.append((new_key.upper(), v))
        elif isinstance(v, dict):
            # Recursively flatten nested dicts
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        else:
            items.append((new_key.upper(), v))
    return dict(items)


def generate_env_from_config(config: Dict[str, Any]) -> List[str]:
    """Generate environment variable lines from configuration dictionary."""
    env_lines = []
    
    # Header
    env_lines.append("# =================================================================")
    env_lines.append("# === FKS TRADING SYSTEM - MASTER ENVIRONMENT CONFIGURATION ========")
    env_lines.append("# =================================================================")
    env_lines.append("")
    env_lines.append("# =================================================================")
    env_lines.append("# === CORE SYSTEM CONFIGURATIONS =================================")
    env_lines.append("# =================================================================")
    env_lines.append("")
    
    # Core system configuration
    env_lines.append("# --- Application Versions and Environment ---")
    env_lines.append(f"APP_VERSION={config['system']['app']['version']}")
    env_lines.append(f"APP_ENV={config['system']['app']['environment']}                # Options: production, staging, development")
    env_lines.append(f"APP_LOG_LEVEL={config['system']['app']['log_level']}")
    env_lines.append(f"TZ={config['system']['app']['timezone']}")
    env_lines.append("")
    
    # Docker Hub configuration
    env_lines.append("# --- Docker Hub Configuration ---")
    env_lines.append(f"DOCKER_USERNAME={config['system']['docker']['hub']['username']}")
    env_lines.append(f"DOCKER_REPO={config['system']['docker']['hub']['repository']}")
    env_lines.append("# DOCKER_TOKEN should be set via CI/CD secrets and not stored in this file")
    env_lines.append("")
    
    # User configuration
    env_lines.append("# --- User Configuration ---")
    env_lines.append(f"USER_NAME={config['system']['user']['name']}")
    env_lines.append(f"USER_ID={config['system']['user']['id']}")
    env_lines.append(f"GROUP_ID={config['system']['user']['group_id']}")
    env_lines.append("")
    
    # Directory paths
    env_lines.append("# --- Directory Paths ---")
    env_lines.append(f"CONFIG_DIR={config['system']['paths']['config_dir']}")
    env_lines.append(f"CONFIG_FILE={config['system']['paths']['config_file']}")
    env_lines.append(f"PYTHONPATH={config['system']['paths']['pythonpath']}")
    env_lines.append("")
    
    # Build environment section
    env_lines.append("# =================================================================")
    env_lines.append("# === BUILD ENVIRONMENT CONFIGURATIONS ===========================")
    env_lines.append("# =================================================================")
    env_lines.append("")
    
    # Docker build common settings
    env_lines.append("# --- Docker Build Common Settings ---")
    env_lines.append(f"COMPOSE_BAKE={str(config['build']['common']['compose_bake']).lower()}")
    env_lines.append(f"VOLUME_DRIVER={config['build']['common']['volume_driver']}")
    env_lines.append(f"DOCKER_DEBUG={str(config['build']['common']['docker_debug']).lower()}")
    env_lines.append(f"KEEP_CONTAINER_ALIVE={str(config['build']['common']['keep_container_alive']).lower()}")
    env_lines.append("")
    
    # Dockerfile paths
    env_lines.append("# --- Dockerfile and Entrypoint Paths ---")
    env_lines.append(f"COMMON_DOCKERFILE_PATH={config['build']['dockerfiles']['common']}")
    env_lines.append(f"COMMON_ENTRYPOINT_PATH={config['build']['dockerfiles']['entrypoint']}")
    env_lines.append(f"NGINX_DOCKERFILE_PATH={config['build']['dockerfiles']['nginx']}")
    env_lines.append("")
    
    # Runtime versions
    env_lines.append("# --- Runtime Versions ---")
    env_lines.append(f"PYTHON_VERSION={config['build']['runtime_versions']['python']}")
    env_lines.append(f"RUST_VERSION={config['build']['runtime_versions']['rust']}")
    env_lines.append(f"CUDA_VERSION={config['build']['runtime_versions']['cuda']}")
    env_lines.append(f"CUDNN_VERSION={config['build']['runtime_versions']['cudnn']}")
    env_lines.append(f"UBUNTU_VERSION={config['build']['runtime_versions']['ubuntu']}")
    env_lines.append("")
    
    # Build configuration
    env_lines.append("# --- Build Configuration ---")
    env_lines.append(f"USE_SYSTEM_PACKAGES={str(config['build']['configuration']['use_system_packages']).lower()}          # Use system-site-packages in venv (builder stage)")
    env_lines.append(f"INSTALL_DEV_DEPS={str(config['build']['configuration']['install_dev_deps']).lower()}             # Install development dependencies (builder stage)")
    env_lines.append(f"DEFAULT_PYTHON_CMD={config['build']['configuration']['default_python_cmd']}")
    env_lines.append("")
    
    # Healthcheck configuration
    env_lines.append("# --- Healthcheck Configuration ---")
    env_lines.append(f"ENABLE_HEALTHCHECK={str(config['build']['healthcheck']['enabled']).lower()}")
    env_lines.append(f"HEALTHCHECK_INTERVAL={config['build']['healthcheck']['interval']}")
    env_lines.append(f"HEALTHCHECK_TIMEOUT={config['build']['healthcheck']['timeout']}")
    env_lines.append(f"HEALTHCHECK_RETRIES={config['build']['healthcheck']['retries']}")
    env_lines.append(f"HEALTHCHECK_START_PERIOD={config['build']['healthcheck']['start_period']}")
    env_lines.append("")
    
    # Source code directories
    env_lines.append("# --- Source Code Directory Paths ---")
    env_lines.append(f"PYTHON_SRC_DIR={config['build']['source_directories']['python_src']}")
    env_lines.append(f"NETWORK_CONNECTOR_DIR={config['build']['source_directories']['network_connector']}")
    env_lines.append(f"RUST_NETWORK_DIR={config['build']['source_directories']['rust_network']}")
    env_lines.append(f"RUST_EXECUTION_DIR={config['build']['source_directories']['rust_execution']}")
    env_lines.append(f"BINARY_PATH={config['build']['source_directories']['binary_path']}")
    env_lines.append("")
    
    # CI/CD configuration
    env_lines.append("# --- CI/CD Configuration ---")
    env_lines.append(f"CI_ENABLED={str(config['build']['ci_cd']['enabled']).lower()}")
    env_lines.append(f"CI_DEBUG={str(config['build']['ci_cd']['debug']).lower()}")
    env_lines.append(f"CI_BUILD_NUMBER={config['build']['ci_cd']['build_number']}")
    env_lines.append(f"CI_COMMIT_SHA={config['build']['ci_cd']['commit_sha']}")
    env_lines.append(f"CI_TAG_VERSION={config['build']['ci_cd']['tag_version']}")
    env_lines.append("")
    
    # Requirements and module configuration
    env_lines.append("# --- Requirements and Module Configuration ---")
    env_lines.append(f"REQUIREMENTS_PATH={config['build']['requirements']['path']}        # Primary requirements file")
    env_lines.append(f"DISPATCHER_MODULE={config['build']['requirements']['dispatcher_module']}                     # Unified dispatcher module")
    env_lines.append("")
    
    # Data storage paths
    env_lines.append("# =================================================================")
    env_lines.append("# === DATA STORAGE PATHS =========================================")
    env_lines.append("# =================================================================")
    env_lines.append("")
    
    # Application data paths
    env_lines.append("# --- Application Data Paths ---")
    env_lines.append(f"MODELS_DIR={config['storage']['application']['models_dir']}")
    env_lines.append(f"CHECKPOINTS_DIR={config['storage']['application']['checkpoints_dir']}")
    env_lines.append(f"DATASETS_DIR={config['storage']['application']['datasets_dir']}")
    env_lines.append(f"APP_DATA_PATH={config['storage']['application']['data_path']}")
    env_lines.append(f"APP_CONFIGS_PATH={config['storage']['application']['configs_path']}")
    env_lines.append(f"APP_RESULTS_PATH={config['storage']['application']['results_path']}")
    env_lines.append("")
    
    # Monitoring data paths
    env_lines.append("# --- Monitoring Data Paths ---")
    env_lines.append(f"PROMETHEUS_DATA_PATH={config['storage']['monitoring']['prometheus']['data_path']}")
    env_lines.append(f"PROMETHEUS_CONFIG_PATH={config['storage']['monitoring']['prometheus']['config_path']}")
    env_lines.append(f"GRAFANA_DATA_PATH={config['storage']['monitoring']['grafana']['data_path']}")
    env_lines.append(f"GRAFANA_CONFIG_PATH={config['storage']['monitoring']['grafana']['config_path']}")
    env_lines.append(f"POSTGRES_EXPORTER_DATA_PATH={config['storage']['monitoring']['postgres_exporter']['data_path']}")
    env_lines.append(f"REDIS_EXPORTER_DATA_PATH={config['storage']['monitoring']['redis_exporter']['data_path']}")
    env_lines.append("")
    
    # Service runtime configurations
    env_lines.append("# =================================================================")
    env_lines.append("# === SERVICE RUNTIME CONFIGURATIONS =============================")
    env_lines.append("# =================================================================")
    env_lines.append("")
    
    # Service runtime types
    env_lines.append("# --- Service Runtime Types ---")
    env_lines.append(f"DEFAULT_SERVICE_RUNTIME={config['runtime']['types']['default']}")
    env_lines.append(f"RUST_SERVICE_RUNTIME={config['runtime']['types']['rust']}")
    env_lines.append(f"HYBRID_SERVICE_RUNTIME={config['runtime']['types']['hybrid']}")
    env_lines.append("")
    
    # Python module configurations
    env_lines.append("# --- Python Module Configurations ---")
    env_lines.append("# All services now use the unified dispatcher module pattern")
    dispatcher_module = config['build']['requirements']['dispatcher_module']
    for service in ['api', 'worker', 'app', 'data', 'web', 'training', 'transformer']:
        env_lines.append(f"{service.upper()}_PYTHON_MODULE=${dispatcher_module}")
    env_lines.append("")
    
    # Python CPU services
    env_lines.append("# =================================================================")
    env_lines.append("# === PYTHON CPU SERVICES ========================================")
    env_lines.append("# =================================================================")
    env_lines.append("")
    
    # Generate all Python CPU service configurations
    for service_name, service_config in config['services']['python_cpu'].items():
        service_upper = service_name.upper()
        env_lines.append(f"# --- {service_name.title()} Service Configuration ---")
        env_lines.append(f"{service_upper}_IMAGE_TAG=${{DOCKER_USERNAME}}/${{DOCKER_REPO}}:{service_name}")
        env_lines.append(f"{service_upper}_CONTAINER_NAME={service_config['container_name']}")
        env_lines.append(f"{service_upper}_SERVICE_NAME={service_config['service_name']}")
        env_lines.append(f"{service_upper}_SERVICE_TYPE={service_config['service_type']}")
        env_lines.append(f"{service_upper}_SERVICE_PORT={service_config['port']}")
        
        if service_name == 'nginx':
            if 'ssl_port' in service_config:
                env_lines.append(f"{service_upper}_SERVICE_SSL_PORT={service_config['ssl_port']}")
        else:
            env_lines.append(f"{service_upper}_SERVICE_RUNTIME=${{DEFAULT_SERVICE_RUNTIME}}")
            if service_name == 'worker' and 'count' in service_config:
                env_lines.append(f"WORKER_COUNT={service_config['count']}")
            if service_name == 'app' and 'trading_mode' in service_config:
                env_lines.append(f"TRADING_MODE={service_config['trading_mode']}")
        
        env_lines.append(f"{service_upper}_HEALTHCHECK_CMD={service_config['healthcheck_cmd']}")
        
        if service_name != 'nginx':
            # Add extra packages configuration
            build_packages = ""
            runtime_packages = ""
            if 'extra_packages' in service_config:
                if 'build' in service_config['extra_packages']:
                    build_packages = ' '.join(service_config['extra_packages']['build'])
                if 'runtime' in service_config['extra_packages']:
                    runtime_packages = ' '.join(service_config['extra_packages']['runtime'])
            env_lines.append(f"{service_upper}_EXTRA_BUILD_PACKAGES={build_packages}")
            env_lines.append(f"{service_upper}_EXTRA_RUNTIME_PACKAGES={runtime_packages}")
        
        env_lines.append("")
    
    # Python GPU services
    env_lines.append("# =================================================================")
    env_lines.append("# === PYTHON GPU SERVICES ========================================")
    env_lines.append("# =================================================================")
    env_lines.append("")
    
    # Generate all Python GPU service configurations
    for service_name, service_config in config['services']['python_gpu'].items():
        service_upper = service_name.upper()
        env_lines.append(f"# --- {service_name.title()} Service Configuration ---")
        env_lines.append(f"{service_upper}_IMAGE_TAG=${{DOCKER_USERNAME}}/${{DOCKER_REPO}}:{service_name}")
        env_lines.append(f"{service_upper}_CONTAINER_NAME={service_config['container_name']}")
        env_lines.append(f"{service_upper}_SERVICE_NAME={service_config['service_name']}")
        env_lines.append(f"{service_upper}_SERVICE_TYPE={service_config['service_type']}")
        env_lines.append(f"{service_upper}_SERVICE_PORT={service_config['port']}")
        env_lines.append(f"{service_upper}_SERVICE_RUNTIME=${{DEFAULT_SERVICE_RUNTIME}}")
        
        if service_name == 'training' and 'epochs' in service_config:
            env_lines.append(f"TRAINING_EPOCHS={service_config['epochs']}")
        
        env_lines.append(f"{service_upper}_HEALTHCHECK_CMD={service_config['healthcheck_cmd']}")
        
        # Add extra packages configuration
        build_packages = ""
        runtime_packages = ""
        if 'extra_packages' in service_config:
            if 'build' in service_config['extra_packages']:
                build_packages = ' '.join(service_config['extra_packages']['build'])
            if 'runtime' in service_config['extra_packages']:
                runtime_packages = ' '.join(service_config['extra_packages']['runtime'])
        env_lines.append(f"{service_upper}_EXTRA_BUILD_PACKAGES={build_packages}")
        env_lines.append(f"{service_upper}_EXTRA_RUNTIME_PACKAGES={runtime_packages}")
        env_lines.append("")
    
    # Rust services
    env_lines.append("# =================================================================")
    env_lines.append("# === RUST SERVICES (NODE NETWORK) ===============================")
    env_lines.append("# =================================================================")
    env_lines.append("")
    
    # Node network common configuration
    env_lines.append("# --- Node Network Common Configuration ---")
    env_lines.append(f"RUST_NODE_REGISTRY_IMAGE_TAG=${{DOCKER_USERNAME}}/${{DOCKER_REPO}}:node-registry")
    env_lines.append(f"RUST_NODE_IMAGE_TAG=${{DOCKER_USERNAME}}/${{DOCKER_REPO}}:node")
    env_lines.append(f"NODE_PING_INTERVAL_MS={config['services']['rust_services']['common']['ping_interval_ms']}")
    env_lines.append(f"NODE_DISCOVERY_INTERVAL_MS={config['services']['rust_services']['common']['discovery_interval_ms']}")
    env_lines.append("")
    
    # Registry node configuration
    env_lines.append("# --- Registry Node Configuration ---")
    env_lines.append(f"NODE_REGISTRY_CONTAINER_NAME={config['services']['rust_services']['registry']['container_name']}")
    env_lines.append(f"NODE_REGISTRY_SERVICE_TYPE={config['services']['rust_services']['registry']['service_type']}")
    env_lines.append(f"NODE_REGISTRY_SERVICE_PORT={config['services']['rust_services']['registry']['port']}")
    env_lines.append(f"NODE_REGISTRY_SERVICE_RUNTIME=${{RUST_SERVICE_RUNTIME}}")
    env_lines.append(f"NODE_REGISTRY_HEALTHCHECK_CMD={config['services']['rust_services']['registry']['healthcheck_cmd']}")
    env_lines.append("")
    
    # Python connector (hybrid service)
    env_lines.append("# --- Python Connector (Hybrid Service) ---")
    env_lines.append(f"PYTHON_CONNECTOR_IMAGE_TAG=${{DOCKER_USERNAME}}/${{DOCKER_REPO}}:node-connector")
    env_lines.append(f"PYTHON_CONNECTOR_CONTAINER_NAME={config['services']['rust_services']['connector']['container_name']}")
    env_lines.append(f"PYTHON_CONNECTOR_SERVICE_TYPE={config['services']['rust_services']['connector']['service_type']}")
    env_lines.append(f"PYTHON_CONNECTOR_SERVICE_PORT={config['services']['rust_services']['connector']['port']}")
    env_lines.append(f"PYTHON_CONNECTOR_SERVICE_RUNTIME=${{HYBRID_SERVICE_RUNTIME}}")
    env_lines.append(f"PYTHON_CONNECTOR_UPDATE_INTERVAL={config['services']['rust_services']['connector']['update_interval']}")
    env_lines.append(f"PYTHON_CONNECTOR_HEALTHCHECK_CMD={config['services']['rust_services']['connector']['healthcheck_cmd']}")
    env_lines.append("")
    
    # Individual node configurations
    for node_name, node_config in config['services']['rust_services']['nodes'].items():
        node_upper = node_name.upper()
        env_lines.append(f"# --- {node_name.title().replace('_', ' ')} Node Configuration ---*")
        env_lines.append(f"NODE_{node_upper}_CONTAINER_NAME={node_config['container_name']}")
        env_lines.append(f"NODE_{node_upper}_REGION={node_config['region']}")
        env_lines.append(f"NODE_{node_upper}_TIMEZONE={node_config['timezone']}")
        env_lines.append(f"NODE_{node_upper}_SERVICE_PORT={node_config['port']}")
        env_lines.append(f"NODE_{node_upper}_SERVICE_RUNTIME=${{RUST_SERVICE_RUNTIME}}")
        env_lines.append(f"NODE_{node_upper}_HEALTHCHECK_CMD={node_config['healthcheck_cmd']}")
        env_lines.append("")
    
    # Database services
    env_lines.append("# =================================================================")
    env_lines.append("# === DATABASE SERVICES ==========================================")
    env_lines.append("# =================================================================")
    env_lines.append("")
    
    # Redis configuration
    env_lines.append("# --- Redis Configuration ---")
    env_lines.append(f"REDIS_IMAGE_TAG={config['databases']['redis']['image_tag']}")
    env_lines.append(f"REDIS_PORT={config['databases']['redis']['port']}")
    env_lines.append(f"REDIS_PASSWORD={config['databases']['redis']['password']}")
    env_lines.append(f"REDIS_HEALTHCHECK_CMD={config['databases']['redis']['healthcheck_cmd']}")
    env_lines.append("")
    
    # PostgreSQL configuration
    env_lines.append("# --- PostgreSQL Configuration ---")
    env_lines.append(f"POSTGRES_IMAGE_TAG={config['databases']['postgresql']['image_tag']}")
    env_lines.append(f"POSTGRES_PORT={config['databases']['postgresql']['port']}")
    env_lines.append(f"POSTGRES_DB={config['databases']['postgresql']['database']}")
    env_lines.append(f"POSTGRES_USER={config['databases']['postgresql']['user']}")
    env_lines.append(f"POSTGRES_PASSWORD={config['databases']['postgresql']['password']}")
    env_lines.append(f"POSTGRES_HEALTHCHECK_CMD={config['databases']['postgresql']['healthcheck_cmd']}")
    env_lines.append("")
    
    # Monitoring services
    env_lines.append("# =================================================================")
    env_lines.append("# === MONITORING SERVICES ========================================")
    env_lines.append("# =================================================================")
    env_lines.append("")
    
    # Datadog configuration
    env_lines.append("# --- Datadog Configuration ---")
    env_lines.append(f"DATADOG_IMAGE_TAG={config['monitoring']['datadog']['image_tag']}")
    env_lines.append(f"DATADOG_PORT={config['monitoring']['datadog']['port']}")
    env_lines.append(f"DATADOG_HEALTHCHECK_CMD={config['monitoring']['datadog']['healthcheck_cmd']}")
    env_lines.append("")
    
    # Prometheus configuration
    env_lines.append("# --- Prometheus Configuration ---")
    env_lines.append(f"PROMETHEUS_IMAGE_TAG={config['monitoring']['prometheus']['image_tag']}")
    env_lines.append(f"PROMETHEUS_PORT={config['monitoring']['prometheus']['port']}")
    env_lines.append(f"PROMETHEUS_HEALTHCHECK_CMD={config['monitoring']['prometheus']['healthcheck_cmd']}")
    env_lines.append("")
    
    # Grafana configuration
    env_lines.append("# --- Grafana Configuration ---")
    env_lines.append(f"GRAFANA_IMAGE_TAG={config['monitoring']['grafana']['image_tag']}")
    env_lines.append(f"GRAFANA_PORT={config['monitoring']['grafana']['port']}")
    env_lines.append(f"GRAFANA_HEALTHCHECK_CMD={config['monitoring']['grafana']['healthcheck_cmd']}")
    env_lines.append("")
    
    # Database exporters
    env_lines.append("# --- Database Exporters ---")
    env_lines.append(f"POSTGRES_EXPORTER_IMAGE_TAG={config['monitoring']['exporters']['postgres']['image_tag']}")
    env_lines.append(f"POSTGRES_EXPORTER_PORT={config['monitoring']['exporters']['postgres']['port']}")
    env_lines.append(f"POSTGRES_EXPORTER_HEALTHCHECK_CMD={config['monitoring']['exporters']['postgres']['healthcheck_cmd']}")
    env_lines.append("")
    env_lines.append(f"REDIS_EXPORTER_IMAGE_TAG={config['monitoring']['exporters']['redis']['image_tag']}")
    env_lines.append(f"REDIS_EXPORTER_PORT={config['monitoring']['exporters']['redis']['port']}")
    env_lines.append(f"REDIS_EXPORTER_HEALTHCHECK_CMD={config['monitoring']['exporters']['redis']['healthcheck_cmd']}")
    
    return env_lines


def main():
    parser = argparse.ArgumentParser(description='Generate .env file from YAML configuration')
    parser.add_argument('--config', '-c', 
                        default='./config/services/environment.yaml',
                        help='Path to YAML configuration file')
    parser.add_argument('--output', '-o',
                        default='.env',
                        help='Output path for .env file')
    parser.add_argument('--validate', '-v',
                        action='store_true',
                        help='Validate configuration without writing file')
    
    args = parser.parse_args()
    
    # Check if config file exists
    if not os.path.exists(args.config):
        print(f"Error: Configuration file '{args.config}' not found!", file=sys.stderr)
        sys.exit(1)
    
    try:
        # Load YAML configuration
        with open(args.config, 'r') as f:
            config = yaml.safe_load(f)
        
        # Generate environment variables
        env_lines = generate_env_from_config(config)
        
        if args.validate:
            print("Configuration validation successful!")
            print(f"Would generate {len([l for l in env_lines if l and not l.startswith('#')])} environment variables")
            return
        
        # Write .env file
        with open(args.output, 'w') as f:
            f.write('\n'.join(env_lines))
        
        print(f"Successfully generated {args.output} with {len([l for l in env_lines if l and not l.startswith('#')])} variables")
        
        # Optionally display the generated file
        if os.environ.get('SHOW_ENV', '').lower() == 'true':
            print("\nGenerated .env file:")
            print("=" * 50)
            with open(args.output, 'r') as f:
                print(f.read())
                
    except yaml.YAMLError as e:
        print(f"Error parsing YAML file: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error generating .env file: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()