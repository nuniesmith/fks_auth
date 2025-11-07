#!/usr/bin/env python3
"""Compare two verify.json reports and output a delta summary.
Usage: compare-verify.py --old old.json --new new.json --out delta.md
Exit code 0 always (informational).
"""
from __future__ import annotations
import argparse, json, pathlib, sys

def index(report):
    return {r['repo']: r for r in report}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--old', required=True)
    ap.add_argument('--new', required=True)
    ap.add_argument('--out', default='verify-delta.md')
    args = ap.parse_args()
    old_p = pathlib.Path(args.old)
    new_p = pathlib.Path(args.new)
    if not new_p.exists():
        print('New report missing', file=sys.stderr)
        return 0
    old = []
    if old_p.exists():
        try:
            old = json.loads(old_p.read_text())
        except Exception:
            pass
    new = json.loads(new_p.read_text())
    i_old = index(old)
    i_new = index(new)
    added = [r for name, r in i_new.items() if name not in i_old]
    removed = [r for name, r in i_old.items() if name not in i_new]
    status_changes = []
    for name, r in i_new.items():
        if name in i_old and r.get('status') != i_old[name].get('status'):
            status_changes.append((name, i_old[name].get('status'), r.get('status')))
    lines = ["# Verification Delta",""]
    if not old:
        lines.append("(No previous report; treating all as new)")
    if added:
        lines.append("## Added Repos")
        for r in added:
            lines.append(f"- {r['repo']} (status: {r['status']})")
    if removed:
        lines.append("## Removed Repos")
        for r in removed:
            lines.append(f"- {r['repo']}")
    if status_changes:
        lines.append("## Status Changes")
        for name, o, n in status_changes:
            lines.append(f"- {name}: {o} -> {n}")
    failing = [r for r in new if r.get('status') == 'fail']
    if failing:
        lines.append("## Current Failing Repos")
        for r in failing:
            lines.append(f"- {r['repo']} (build={r['build']} test={r['test']} schema={r['schema']})")
    # Machine summary footer
    summary_line = f"SUMMARY added={len(added)} removed={len(removed)} status_changed={len(status_changes)} failing={len(failing)}"
    lines.append("")
    lines.append(summary_line)
    pathlib.Path(args.out).write_text("\n".join(lines) + "\n")
    print(summary_line)
    print(f"Wrote {args.out}")
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
