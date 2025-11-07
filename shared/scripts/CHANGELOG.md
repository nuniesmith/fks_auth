# Changelog

All notable changes to this project will be documented in this file. The format loosely follows Keep a Changelog and Semantic Versioning.

## [0.3.0] - 2025-08-31

### Added

- VERSION file established for semantic version tracking.
- Introduced PROJECT_NS and SERVICE_FAMILY environment variable support.
- Dynamic PROJECT_ROOT autodetection with OVERRIDE_ROOT override.
- JSON logging output option via LOG_FORMAT=json.

### Changed

- Refactored `main.sh` to remove hardcoded `/home/$USER/fks` paths making script service-agnostic.
- Centralized logging now sourced from `lib/log.sh` when available.
- Updated status and help output to use neutral naming.

### Deprecated

- Implicit hardcoded FKS path resolution (will be removed in a future major release). Use OVERRIDE_ROOT or run within a detected project root.

## [0.2.0] - (pre-existing)

- Previous enhanced main script with hardcoded path strategy.

## [0.1.0] - (historical)

- Initial extraction of monolithic run script.
