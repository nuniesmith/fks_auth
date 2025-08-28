"""
API Service Entry Point

This module serves as the entry point for the API service using FastAPI with CORS support.
"""

import os
import sys
import uvicorn
import importlib.util
from types import ModuleType

# Ensure both /app/src and /app/src/python are on sys.path so `services.*` imports resolve
for p in ("/app/src/python", "/app/src"):
    if p not in sys.path:
        sys.path.insert(0, p)


def main():
    # Set the service name and port from environment variables or defaults
    service_name = os.getenv("API_SERVICE_NAME", "api")
    port = int(os.getenv("API_SERVICE_PORT", "8000"))
    host = os.getenv("API_SERVICE_HOST", "0.0.0.0")
    env = os.getenv("APP_ENV", "development")

    # Log the service startup
    print(f"Starting {service_name} service on {host}:{port}")
    
    # Import the FastAPI app directly; if package import fails, fall back to file path import
    app = None
    try:
        from services.api.fastapi_main import app as fastapi_app  # type: ignore
        app = fastapi_app
    except Exception as e:
        print(f"[api.main] Package import failed: {e}. Falling back to path import.")
        module_path = "/app/src/python/services/api/fastapi_main.py"
        try:
            # Ensure parent namespace packages exist so relative imports work
            services_pkg_path = "/app/src/python/services"
            api_pkg_path = "/app/src/python/services/api"
            if "services" not in sys.modules:
                services_pkg = ModuleType("services")
                setattr(services_pkg, "__path__", [services_pkg_path])  # namespace package
                sys.modules["services"] = services_pkg
            else:
                # Ensure __path__ includes our expected path
                pkg = sys.modules["services"]
                if not hasattr(pkg, "__path__") or services_pkg_path not in getattr(pkg, "__path__", []):
                    setattr(pkg, "__path__", list(getattr(pkg, "__path__", [])) + [services_pkg_path])

            if "services.api" not in sys.modules:
                api_pkg = ModuleType("services.api")
                setattr(api_pkg, "__path__", [api_pkg_path])
                sys.modules["services.api"] = api_pkg
            else:
                pkg_api = sys.modules["services.api"]
                if not hasattr(pkg_api, "__path__") or api_pkg_path not in getattr(pkg_api, "__path__", []):
                    setattr(pkg_api, "__path__", list(getattr(pkg_api, "__path__", [])) + [api_pkg_path])

            spec = importlib.util.spec_from_file_location("services.api.fastapi_main", module_path)
            if spec and spec.loader:
                mod = importlib.util.module_from_spec(spec)
                sys.modules[spec.name] = mod
                spec.loader.exec_module(mod)  # type: ignore[attr-defined]
                app = getattr(mod, "app", None)
        except Exception as ee:
            print(f"[api.main] Path import failed: {ee}")
    if app is None:
        raise RuntimeError("FastAPI app could not be imported")
    
    # Start the service using uvicorn without reload to avoid circular imports
    uvicorn.run(
        app,
        host=host,
        port=port,
        reload=False,  # Disable reload to avoid circular import issues
        log_level="info"
    )


if __name__ == "__main__":
    sys.exit(main())
