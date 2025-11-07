#!/usr/bin/env python3
"""
FKS Service Diagnostic Script

This script helps diagnose import and path issues with FKS services.
Run this inside the failing containers to understand what's going wrong.

Usage:
    python diagnose.py [service_name]
"""
import os
import sys
import importlib
import traceback
from pathlib import Path

def print_separator(title):
    """Print a separator with title"""
    print("\n" + "="*60)
    print(f" {title}")
    print("="*60)

def check_environment():
    """Check environment variables and basic setup"""
    print_separator("ENVIRONMENT CHECK")
    
    important_vars = [
        "SERVICE_TYPE", "APP_ENV", "APP_LOG_LEVEL", "PYTHONPATH",
        "WEB_SERVICE_PORT", "DATA_SERVICE_PORT", "API_SERVICE_PORT"
    ]
    
    for var in important_vars:
        value = os.environ.get(var, "NOT SET")
        print(f"{var:20} = {value}")
    
    print(f"\nCurrent Directory: {os.getcwd()}")
    print(f"Python Version: {sys.version}")
    print(f"Python Executable: {sys.executable}")

def check_python_path():
    """Check Python path and sys.path"""
    print_separator("PYTHON PATH CHECK")
    
    print("sys.path entries:")
    for i, path in enumerate(sys.path):
        exists = "✅" if os.path.exists(path) else "❌"
        print(f"  {i:2d}. {exists} {path}")
    
    print(f"\nPYTHONPATH environment variable:")
    pythonpath = os.environ.get('PYTHONPATH', 'NOT SET')
    if pythonpath != 'NOT SET':
        for path in pythonpath.split(':'):
            exists = "✅" if os.path.exists(path) else "❌"
            print(f"  {exists} {path}")
    else:
        print(f"  {pythonpath}")

def check_directory_structure():
    """Check if expected directories and files exist"""
    print_separator("DIRECTORY STRUCTURE CHECK")
    
    # Check common directories
    common_dirs = [
        "/app",
        "/app/src", 
        "/app/src",
        "/app/core",
        "/app/src/core",
        "/app/src/core",
        "/app/services",
        "/app/src/services",
        "/app/src/services",
        "/home/${USER}/fks",
        "fks/src",
        "fks/src/python",
        "fks/src/python/core",
        "fks/src/python/services",
        "./core",
        "./src",
        "./src/core",
        "./services"
    ]
    
    print("Common directories:")
    for dir_path in common_dirs:
        if os.path.exists(dir_path):
            print(f"  ✅ {dir_path}")
            # List contents if it's a small directory
            try:
                contents = os.listdir(dir_path)
                if len(contents) <= 10:
                    print(f"     Contents: {', '.join(contents)}")
                else:
                    print(f"     Contents: {len(contents)} items")
            except PermissionError:
                print(f"     Contents: Permission denied")
        else:
            print(f"  ❌ {dir_path}")

def check_core_module():
    """Check if core module and its components can be imported"""
    print_separator("CORE MODULE CHECK")
    
    # Try different import paths for core
    core_import_paths = [
        "core",
        "src.core", 
        "src.python.core",
        "app.core",
        "app.src.core"
    ]
    
    print("Trying to import core module:")
    core_module = None
    for import_path in core_import_paths:
        try:
            core_module = importlib.import_module(import_path)
            print(f"  ✅ Successfully imported: {import_path}")
            print(f"     Module file: {getattr(core_module, '__file__', 'N/A')}")
            break
        except ImportError as e:
            print(f"  ❌ Failed to import {import_path}: {e}")
    
    if not core_module:
        print("\n❌ Could not import core module from any path!")
        return False
    
    # Try to import core.services.template
    print("\nTrying to import core.services.template:")
    template_import_paths = [
        "core.services.template",
        "src.core.services.template",
        "src.python.core.services.template"
    ]
    
    template_module = None
    for import_path in template_import_paths:
        try:
            template_module = importlib.import_module(import_path)
            print(f"  ✅ Successfully imported: {import_path}")
            print(f"     Module file: {getattr(template_module, '__file__', 'N/A')}")
            
            # Check if it has the expected function
            if hasattr(template_module, 'start_template_service'):
                print(f"  ✅ Found start_template_service function")
            else:
                print(f"  ❌ start_template_service function not found")
                print(f"     Available attributes: {dir(template_module)}")
            break
        except ImportError as e:
            print(f"  ❌ Failed to import {import_path}: {e}")
    
    return template_module is not None

def check_service_modules(service_name):
    """Check if service-specific modules can be imported"""
    print_separator(f"SERVICE MODULE CHECK ({service_name})")
    
    # Try different import paths for the service
    service_import_paths = [
        f"services.{service_name}.main",
        f"{service_name}.main",
        f"src.{service_name}.main",
        f"src.python.services.{service_name}.main"
    ]
    
    print(f"Trying to import {service_name} service module:")
    service_module = None
    for import_path in service_import_paths:
        try:
            service_module = importlib.import_module(import_path)
            print(f"  ✅ Successfully imported: {import_path}")
            print(f"     Module file: {getattr(service_module, '__file__', 'N/A')}")
            
            # Check what functions are available
            functions = [attr for attr in dir(service_module) if callable(getattr(service_module, attr)) and not attr.startswith('_')]
            print(f"     Available functions: {functions}")
            break
        except ImportError as e:
            print(f"  ❌ Failed to import {import_path}: {e}")
        except Exception as e:
            print(f"  ❌ Error importing {import_path}: {e}")
            print(f"     Traceback: {traceback.format_exc()}")
    
    # Check for service files
    print(f"\nLooking for {service_name} service files:")
    service_file_paths = [
        f"/app/src/{service_name}/main.py",
        f"/app/{service_name}/main.py",
        f"/app/services/{service_name}/main.py",
        f"/app/src/services/{service_name}/main.py",
        f"/app/src/services/{service_name}/main.py", 
        f"fks/src/python/services/{service_name}/main.py",
        f"./services/{service_name}/main.py",
        f"./{service_name}/main.py",
        f"./src/{service_name}/main.py"
    ]
    
    for file_path in service_file_paths:
        if os.path.exists(file_path):
            print(f"  ✅ Found file: {file_path}")
            # Try to read first few lines
            try:
                with open(file_path, 'r') as f:
                    lines = f.readlines()[:5]
                    print(f"     First few lines:")
                    for i, line in enumerate(lines, 1):
                        print(f"       {i}: {line.rstrip()}")
            except Exception as e:
                print(f"     Could not read file: {e}")
        else:
            print(f"  ❌ Not found: {file_path}")
    
    return service_module is not None

def check_flask_availability():
    """Check if Flask is available for health endpoints"""
    print_separator("FLASK CHECK")
    
    try:
        import flask
        print(f"✅ Flask is available, version: {flask.__version__}")
        print(f"   Flask location: {flask.__file__}")
        return True
    except ImportError as e:
        print(f"❌ Flask is not available: {e}")
        return False

def check_loguru_availability():
    """Check if loguru is available for logging"""
    print_separator("LOGURU CHECK")
    
    try:
        import loguru
        print(f"✅ Loguru is available")
        print(f"   Loguru location: {loguru.__file__}")
        return True
    except ImportError as e:
        print(f"❌ Loguru is not available: {e}")
        print("   Will fall back to standard logging")
        return False

def suggest_fixes():
    """Suggest potential fixes based on findings"""
    print_separator("SUGGESTED FIXES")
    
    print("Based on the diagnostic results, here are potential fixes:")
    print()
    
    print("1. PYTHONPATH Issues:")
    print("   - Add the following to your Dockerfile or docker-compose.yml:")
    print("     ENV PYTHONPATH=/app:/app/src:/app/src")
    print("   - Or mount the source code to the right location")
    print()
    
    print("2. Missing core module:")
    print("   - Ensure the core directory is copied to the container")
    print("   - Check if the COPY commands in Dockerfile include core/")
    print("   - Verify the directory structure in the container")
    print()
    
    print("3. Service module issues:")
    print("   - Ensure service-specific modules exist and are copied")
    print("   - Check if the service modules have the right entry points")
    print("   - Verify imports within service modules")
    print()
    
    print("4. Docker compose fixes:")
    print("   - Add volume mount for source code during development")
    print("   - Set PYTHONPATH environment variable")
    print("   - Check that all services use the same base image")
    print()
    
    print("5. Immediate workaround:")
    print("   - The enhanced main.py should help by using template service as fallback")
    print("   - Services will run in placeholder mode if modules can't be imported")

def main():
    """Main diagnostic function"""
    service_name = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("SERVICE_TYPE", "unknown")
    
    print("FKS Service Diagnostic Script")
    print(f"Diagnosing service: {service_name}")
    
    # Run all checks
    check_environment()
    check_python_path()
    check_directory_structure()
    
    core_ok = check_core_module()
    service_ok = check_service_modules(service_name)
    flask_ok = check_flask_availability()
    loguru_ok = check_loguru_availability()
    
    # Summary
    print_separator("DIAGNOSTIC SUMMARY")
    print(f"Core module available:      {'✅' if core_ok else '❌'}")
    print(f"Service module available:   {'✅' if service_ok else '❌'}")
    print(f"Flask available:            {'✅' if flask_ok else '❌'}")
    print(f"Loguru available:           {'✅' if loguru_ok else '❌'}")
    
    if not core_ok:
        print("\n🚨 CRITICAL: Core module cannot be imported!")
        print("   This is likely the root cause of the service failures.")
    
    if not service_ok:
        print(f"\n⚠️  WARNING: {service_name} service module cannot be imported!")
        print("   Service will fall back to template or placeholder mode.")
    
    suggest_fixes()

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"Error running diagnostic: {e}")
        print(f"Traceback: {traceback.format_exc()}")