One-off Extraction Utilities
===========================

Scripts:

1. extract-fks_api.sh

   - Purpose: Opinionated, hand-tuned extraction for the API service.
   - Usage: `./migration/one-off/extract-fks_api.sh MONO_ROOT TARGET_DIR [REMOTE]`

2. extract-service.sh (generic)

    - Purpose: Generic single-service extractor parsing `extraction-map.yml` for paths & submodules.
    - Usage:
       `./migration/extract-service.sh fks_api . ./_out --org yourorg --remote git@github.com:yourorg/fks_api.git`

3. validate-service.sh

    - Purpose: Post-extraction smoke test (build / test / minimal security audit).
    - Usage:
       `./migration/validate-service.sh ./_out/fks_api`

Recommended Flow (Single Service):

1. Create empty GitHub repository (e.g., fks_api).
2. Run generic extractor with `--remote` pointing to SSH/HTTPS URL.
3. Review diff, adjust any import or path edge cases.
4. Run validation script.
5. Open PR for initial import (keep commit message as `chore: initial extraction`).

Notes:

- Import rewrite currently only handles `from fks_shared.` -> `from shared_python.`. Extend as needed.
- Multiple service paths are supported; first-level directories named `fks_*` are flattened.
- Submodule mapping derives from `submodules:` line in `extraction-map.yml`; ensure names are correct before extraction.
- For Rust or Web services, build/test steps are scaffolded automatically if config files are present.

Extending:

- To add service-specific tweaks, create a new script in `one-off/` that wraps `extract-service.sh` and then applies custom edits.
- Consider adding a lint phase or mypy check inside `validate-service.sh` for stricter gating.

Automation Next Ideas:

- GitHub Action workflow to call `extract-service.sh` via `workflow_dispatch` with inputs.
- Batch extraction matrix job (service list) for preview comparisons.
