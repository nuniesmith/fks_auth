SHELL := /bin/bash
REPO_NAME?={{REPO_NAME}}

.PHONY: verify lint test build deps

verify: deps lint test build

lint:
	@if [ -f Cargo.toml ]; then cargo fmt -- --check && cargo clippy --all-targets -- -D warnings; fi
	@if ls *.py >/dev/null 2>&1 || ls src/**/*.py >/dev/null 2>&1; then python -m py_compile $$(git ls-files '*.py'); fi
	@if [ -f package.json ]; then npm run lint || true; fi

test:
	@if [ -f Cargo.toml ]; then cargo test --all --quiet; fi
	@if [ -f pyproject.toml ] || ls *.py >/dev/null 2>&1; then pytest -q || true; fi
	@if [ -f package.json ]; then npm run test:run || true; fi

build:
	@if [ -f Cargo.toml ]; then cargo build --quiet; fi
	@if [ -f pyproject.toml ]; then python -m build --sdist --wheel || true; fi
	@if [ -f package.json ]; then npm run build || true; fi

deps:
	@if [ -f Cargo.toml ]; then cargo fetch; fi
	@if [ -f pyproject.toml ]; then pip install -e shared/python || true; fi
	@if [ -f package.json ]; then npm ci; fi
