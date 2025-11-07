#!/usr/bin/env bash
set -euo pipefail
# Re-scan for empty files excluding VCS, backups, trash, virtual envs, build caches
find . -type f -empty \
	-not -path '*/.git/*' \
	-not -path '*fks_backup_*/*' \
	-not -path '*/.trash/*' \
	-not -path '*/node_modules/*' \
	-not -path '*/target/*' \
	-not -path '*/.venv/*' \
	-print | sort > empty_files.list
echo "Empty files listed in empty_files.list (count: $(wc -l < empty_files.list))"
echo "Next: ./tools/curate_empty_files.sh to filter placeholders before trashing."
