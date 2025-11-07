#!/usr/bin/env python3
"""Generate dependency graph markdown from extraction-map.yml.
Outputs dependency-graph.md in current directory or specified --out.
"""
from __future__ import annotations
import argparse, re, sys, pathlib

def parse_map(text: str):
    section = None
    current = None
    data = {"services": {}, "shared": {}}
    for line in text.splitlines():
        raw=line
        line=line.split('#',1)[0].rstrip()
        if not line: continue
        if re.match(r'^shared:', line):
            section='shared'; continue
        if re.match(r'^services:', line):
            section='services'; continue
        m=re.match(r'^\s{2}([a-z0-9_-]+):', line)
        if m:
            current=m.group(1)
            data[section][current]={}
            continue
        if 'submodules:' in line and current:
            subs=line.split(':',1)[1].strip().strip('[]')
            subs=[s.strip() for s in subs.split(',') if s.strip()]
            data[section][current]['submodules']=subs
    return data

def build_matrix(data):
    # Collect all shared names appearing in services
    shared=set()
    for svc, meta in data['services'].items():
        for s in meta.get('submodules',[]): shared.add(s)
    shared=sorted(shared)
    lines=["# Service → Shared Module Dependency Matrix","",'| Service | ' + ' | '.join(shared) + ' |','|---|' + '|'.join(['---']*len(shared)) + '|']
    for svc, meta in sorted(data['services'].items()):
        row=[]
        have=set(meta.get('submodules',[]))
        for s in shared:
            row.append('✅' if s in have else '')
        lines.append('| ' + svc + ' | ' + ' | '.join(row) + ' |')
    return '\n'.join(lines)+"\n"

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--map', default='extraction-map.yml')
    ap.add_argument('--out', default='dependency-graph.md')
    args=ap.parse_args()
    p=pathlib.Path(args.map)
    if not p.exists():
        print(f"Map file {p} not found", file=sys.stderr); return 1
    data=parse_map(p.read_text())
    md=build_matrix(data)
    pathlib.Path(args.out).write_text(md)
    print(f"Wrote {args.out}")
    return 0

if __name__=='__main__':
    raise SystemExit(main())
