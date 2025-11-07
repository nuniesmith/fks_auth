#!/usr/bin/env python3
"""Verify that service-declared schema version matches shared schema repo tag.

Usage: python schema_assert.py --expected-file schema_version.txt --schema-path shared/schema

Place a file `schema_version.txt` at repo root containing required tag (e.g., v1.2.0).
Exits non-zero if mismatch.
"""
from __future__ import annotations
import argparse, pathlib, re, subprocess, sys

def get_current_schema_tag(schema_path: pathlib.Path) -> str:
    # Try git describe in the submodule
    try:
        tag = subprocess.check_output([
            'git','-C', str(schema_path), 'describe','--tags','--abbrev=0'
        ], text=True).strip()
        if re.match(r'^v\d+\.\d+\.\d+$', tag):
            return tag
    except Exception:
        pass
    # Fallback: read VERSION file if exists
    version_file = schema_path / 'VERSION'
    if version_file.exists():
        return version_file.read_text().strip()
    return ''

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--expected-file', default='schema_version.txt')
    ap.add_argument('--schema-path', default='shared/schema')
    args = ap.parse_args()
    expected_file = pathlib.Path(args.expected_file)
    if not expected_file.exists():
        print(f"[WARN] Expected file {expected_file} missing; skipping check.")
        return 0
    expected = expected_file.read_text().strip()
    current = get_current_schema_tag(pathlib.Path(args.schema_path))
    if not current:
        print('[ERROR] Could not determine current schema tag')
        return 2
    if expected != current:
        print(f'[ERROR] Schema version mismatch: expected {expected} got {current}')
        return 3
    print(f'[OK] Schema version {current} matches expected {expected}')
    return 0

if __name__ == '__main__':
    sys.exit(main())
