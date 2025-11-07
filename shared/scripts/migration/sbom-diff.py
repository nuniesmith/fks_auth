#!/usr/bin/env python3
"""Compute delta between two SBOM aggregate JSON files produced by generate-sbom.sh.
Usage: sbom-diff.py --old old.json --new new.json --out sbom-delta.md
Outputs a markdown summary and prints machine summary line to stdout.
Exit code 0 always (informational).
"""
from __future__ import annotations
import argparse, json, pathlib, sys
from collections import defaultdict

def load(path: pathlib.Path):
    if not path.exists():
        return []
    try:
        return json.loads(path.read_text())
    except Exception:
        return []

def pk_set(entry, key):
    return set(entry.get(key, []) or [])

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--old', required=True)
    ap.add_argument('--new', required=True)
    ap.add_argument('--out', default='sbom-delta.md')
    args = ap.parse_args()
    old = load(pathlib.Path(args.old))
    new = load(pathlib.Path(args.new))

    # Map repo -> entry
    o_map = {e.get('repo'): e for e in old if isinstance(e, dict)}
    n_map = {e.get('repo'): e for e in new if isinstance(e, dict)}

    repos_added = sorted(set(n_map) - set(o_map))
    repos_removed = sorted(set(o_map) - set(n_map))
    changed = []

    lang_keys = ['python','node','rust']
    delta_counts = defaultdict(int)

    for repo, n_ent in n_map.items():
        o_ent = o_map.get(repo)
        if not o_ent:
            continue
        repo_changes = []
        # license change
        if (o_ent.get('license') or '') != (n_ent.get('license') or ''):
            repo_changes.append(f"license: {o_ent.get('license') or '-'} -> {n_ent.get('license') or '-'}")
            delta_counts['license'] += 1
        # packages
        for k in lang_keys:
            added_pk = sorted(pk_set(n_ent,k) - pk_set(o_ent,k))
            removed_pk = sorted(pk_set(o_ent,k) - pk_set(n_ent,k))
            if added_pk:
                repo_changes.append(f"{k} +{len(added_pk)}: {', '.join(added_pk[:5])}{' …' if len(added_pk)>5 else ''}")
                delta_counts[f'{k}_added'] += len(added_pk)
            if removed_pk:
                repo_changes.append(f"{k} -{len(removed_pk)}: {', '.join(removed_pk[:5])}{' …' if len(removed_pk)>5 else ''}")
                delta_counts[f'{k}_removed'] += len(removed_pk)
        if repo_changes:
            changed.append((repo, repo_changes))

    lines = ["# SBOM Delta","",]
    if repos_added:
        lines.append("## New Repos")
        lines += [f"- {r}" for r in repos_added]
    if repos_removed:
        lines.append("## Removed Repos")
        lines += [f"- {r}" for r in repos_removed]
    if changed:
        lines.append("## Changed Repos")
        for repo, c_list in changed:
            lines.append(f"- {repo}")
            for c in c_list:
                lines.append(f"  - {c}")
    if len(lines)==2:
        lines.append("(No changes detected)")

    summary = (
        f"SUMMARY repos_added={len(repos_added)} repos_removed={len(repos_removed)} changed={len(changed)} "
        + " ".join(f"{k}={v}" for k,v in sorted(delta_counts.items()))
    )
    lines.append("")
    lines.append(summary)
    pathlib.Path(args.out).write_text("\n".join(lines)+"\n")
    print(summary)
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
