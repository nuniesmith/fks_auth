#!/usr/bin/env python3
"""Scan repository for Dockerfiles, classify patterns, and emit consolidation hints.
Outputs JSON summary to stdout.
"""
from __future__ import annotations
import os, re, json, hashlib, sys, textwrap

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..'))  # workspace root
TARGET_DIRS = [
    os.path.join(ROOT, 'fks'),
    os.path.join(ROOT, 'personal'),
]
IGNORE = {'shared/docker/Dockerfile'}

PATTERNS = {
    'python_poetry': re.compile(r'poetry (install|lock)') ,
    'python_uvicorn': re.compile(r'uvicorn'),
    'multi_stage': re.compile(r'^FROM .* AS ', re.MULTILINE),
    'cuda': re.compile(r'nvidia|cuda', re.IGNORECASE),
    'rust_cargo': re.compile(r'cargo build'),
    'node_react': re.compile(r'npm (ci|install)|yarn'),
    'dotnet': re.compile(r'dotnet (build|restore)'),
}

records = []
for base in TARGET_DIRS:
    for dirpath, _, filenames in os.walk(base):
        for fn in filenames:
            if fn == 'Dockerfile':
                full = os.path.join(dirpath, fn)
                rel = os.path.relpath(full, ROOT)
                if any(part.startswith('.') for part in rel.split(os.sep)):
                    continue
                with open(full, 'r', errors='ignore') as f:
                    content = f.read()
                h = hashlib.sha256(content.encode()).hexdigest()[:12]
                tags = [k for k, rgx in PATTERNS.items() if rgx.search(content)]
                base_images = re.findall(r'^FROM +([^\s]+)', content, re.MULTILINE)
                records.append({
                    'path': rel,
                    'hash': h,
                    'size': len(content.splitlines()),
                    'base_images': base_images,
                    'tags': tags,
                })

# Group by hash to find duplicates
by_hash = {}
for r in records:
    by_hash.setdefault(r['hash'], []).append(r)

for group in by_hash.values():
    if len(group) > 1:
        for r in group:
            r['duplicate_group'] = group[0]['hash']

summary = {
    'total': len(records),
    'duplicates': sum(1 for g in by_hash.values() if len(g) > 1),
    'patterns': {p: sum(1 for r in records if p in r['tags']) for p in PATTERNS},
    'records': records,
}
print(json.dumps(summary, indent=2))
