#!/usr/bin/env bash
set -euo pipefail

# merge_compose.sh (final enhanced version)
# Merge docker-compose.yml files across service directories into docker-compose.generated.yml.
# Features: collision-aware rename, optional filtering, port collision warnings, SHA256 digest.
# Usage: merge_compose.sh [--output path] [--dirs dir1,dir2] [--only svc1,svc2] [--no-port-warn]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export SCRIPT_DIR
python3 - "$@" <<'PY'
import os, sys, hashlib, datetime, argparse, json
try:
  import yaml
except ImportError:
  sys.stderr.write('PyYAML not installed. Run: pip install pyyaml\n')
  sys.exit(1)

script_dir = os.environ.get('SCRIPT_DIR', '.')
root_dir = os.path.abspath(os.path.join(script_dir, '..', '..'))  # repo root containing service dirs
DEFAULT_DIRS = [
  'fks_api','fks_auth','fks_config','fks_data','fks_engine','fks_execution',
  'fks_master','fks_nginx','fks_ninja','fks_nodes','fks_training',
  'fks_transformer','fks_web','fks_worker'
]
env_dirs = os.environ.get('MERGE_SERVICE_DIRS')
if env_dirs:
  DEFAULT_DIRS = [d.strip() for d in env_dirs.split(',') if d.strip()]

ap = argparse.ArgumentParser()
ap.add_argument('--output','-o', default=os.path.join(root_dir,'docker-compose.generated.yml'))
ap.add_argument('--dirs')
ap.add_argument('--only')
ap.add_argument('--no-port-warn', action='store_true')
ap.add_argument('--sort', action='store_true', default=True, help='Alphabetically sort services & resource keys for deterministic output (default on). Use --no-sort to disable.')
ap.add_argument('--no-sort', action='store_true', help='Disable sorting (paired with default --sort).')
ap.add_argument('--drop-colliding-ports', action='store_true', help='If host port collisions detected, drop host mapping for later services (container port only).')
ap.add_argument('--remap-colliding-ports', type=int, help='Base port to remap colliding host ports (keeps first occurrence, remaps others starting at this base).')
ap.add_argument('--profiles', help='Comma-separated list of compose profile names to INCLUDE (keep only services matching any).')
ap.add_argument('--exclude-profiles', help='Comma-separated list of profiles to EXCLUDE (drop services having any).')
ap.add_argument('--dry-run', action='store_true', help='Analyze and report but do not write output files.')
ap.add_argument('--summary-json', help='Write a JSON summary report to the given path (or - for stdout).')
args = ap.parse_args()

service_dirs = DEFAULT_DIRS
if args.dirs:
  service_dirs = [d.strip() for d in args.dirs.split(',') if d.strip()]

def preprocess(path):
  with open(path,'r') as f: lines = f.readlines()
  defined=set(); out=[]
  for line in lines:
    if '&' in line:
      for part in line.split('&')[1:]:
        a = part.split()[0].rstrip(':')
        if a: defined.add(a)
    if '<<:' in line and '*' in line:
      aliases=[seg.split()[0].strip(',') for seg in line.split('*')[1:]]
      if any(a not in defined for a in aliases):
        continue
    out.append(line)
  try:
    return yaml.safe_load(''.join(out)) or {}
  except yaml.YAMLError as e:
    sys.stderr.write(f'Warn parse {path}: {e}\n'); return {}

def h(o):
  return hashlib.sha1(yaml.safe_dump(o, sort_keys=True).encode()).hexdigest()

compose_files=[]
for d in service_dirs:
  p=os.path.abspath(os.path.join(root_dir,d,'docker-compose.yml'))
  if os.path.isfile(p): compose_files.append(p)
  else: sys.stderr.write(f'Skip missing compose: {d}\n')
if not compose_files:
  sys.stderr.write('No compose files found.\n'); sys.exit(1)

acc={'version':'3.9','services':{},'networks':{},'volumes':{},'configs':{},'secrets':{}}
sources=[]
for f in compose_files:
  data=preprocess(f); sources.append(f)
  for sec in ('networks','volumes','configs','secrets'):
    for name,spec in (data.get(sec) or {}).items():
      acc[sec].setdefault(name,spec)
  base=os.path.basename(os.path.dirname(f))
  for name,spec in (data.get('services') or {}).items():
    if name not in acc['services']:
      acc['services'][name]=spec; continue
    if h(acc['services'][name])==h(spec):
      continue
    new=f'{base}_{name}'; i=1
    while new in acc['services'] and h(acc['services'][new])!=h(spec):
      i+=1; new=f'{base}_{name}_{i}'
    if new not in acc['services']:
      acc['services'][new]=spec

if args.only:
  keep={s.strip() for s in args.only.split(',') if s.strip()}
  acc['services']={k:v for k,v in acc['services'].items() if k in keep}
  if not acc['services']:
    sys.stderr.write('After filtering, no services remain.\n'); sys.exit(2)

# Profile-based filtering (compose v3 profiles field: list of strings)
include_profiles = set()
exclude_profiles = set()
if args.profiles:
  include_profiles = {p.strip() for p in args.profiles.split(',') if p.strip()}
if args.exclude_profiles:
  exclude_profiles = {p.strip() for p in args.exclude_profiles.split(',') if p.strip()}

if include_profiles or exclude_profiles:
  filtered = {}
  for name, spec in acc['services'].items():
    svc_profiles = set(spec.get('profiles', []) or [])
    if include_profiles and svc_profiles.isdisjoint(include_profiles):
      continue
    if exclude_profiles and not svc_profiles.isdisjoint(exclude_profiles):
      continue
    filtered[name] = spec
  removed = set(acc['services']) - set(filtered)
  if removed:
    sys.stderr.write(f'Profile filter removed services: {", ".join(sorted(removed))}\n')
  acc['services'] = filtered
  if not acc['services']:
    sys.stderr.write('After profile filtering, no services remain.\n'); sys.exit(4)

for k in ('networks','volumes','configs','secrets'):
  if not acc[k]: acc.pop(k)
#############################################
# Port collision detection (and optional drop)
#############################################
hp = {}            # host_port -> first service
collisions = {}    # host_port -> set(services)
remap_log = []      # (service, old_host, new_host, container_port)
drop_log = []       # (service, old_host, container_port)
service_ports_index = {}  # svc -> list reference for mutation
for svc, spec in acc['services'].items():
  port_list = (spec or {}).get('ports', []) or []
  service_ports_index[svc] = port_list
  for i, port in enumerate(list(port_list)):
    if not isinstance(port, str):
      continue
    parts = port.split(':')
    host = None
    container = None
    if len(parts) == 2: # host:container
      host, container = parts
    elif len(parts) == 3: # ip:host:container
      host, container = parts[1], parts[2]
    else:
      continue
    if host and host.isdigit():
      if host in hp:
        collisions.setdefault(host, set()).update({hp[host], svc})
      else:
        hp[host] = svc

# Validate mutually exclusive options
if getattr(args, 'drop_colliding_ports', False) and getattr(args, 'remap_colliding_ports', None) is not None:
  sys.stderr.write('Cannot use --drop-colliding-ports and --remap-colliding-ports together.\n')
  sys.exit(3)

# If requested, drop duplicate host mappings (keep first service's mapping)
if collisions and getattr(args, 'drop_colliding_ports', False):
  for host_port, svcs in collisions.items():
    keeper = hp.get(host_port)
    for svc in svcs:
      if svc == keeper:
        continue
      new_ports = []
      changed = False
      for port in service_ports_index.get(svc, []):
        if isinstance(port, str):
          parts = port.split(':')
          if len(parts) == 2 and parts[0] == host_port:
            new_ports.append(parts[1])  # keep only container
            drop_log.append((svc, host_port, parts[1]))
            changed = True
            continue
          elif len(parts) == 3 and parts[1] == host_port:
            new_ports.append(parts[2])
            drop_log.append((svc, host_port, parts[2]))
            changed = True
            continue
        new_ports.append(port)
      if changed:
        acc['services'][svc]['ports'] = new_ports
  sys.stderr.write('Dropped host port mappings for collisions (keeping first occurrence).\n')

# Remap colliding ports if requested
if collisions and getattr(args, 'remap_colliding_ports', None) is not None:
  base = args.remap_colliding_ports
  used = set(hp.keys())
  remap_counter = 0
  # remap_log already defined
  for host_port, svcs in collisions.items():
    keeper = hp.get(host_port)
    others = [s for s in svcs if s != keeper]
    for svc in sorted(others):  # deterministic
      new_ports = []
      changed = False
      for port in acc['services'][svc].get('ports', []) or []:
        if not isinstance(port, str):
          new_ports.append(port)
          continue
        parts = port.split(':')
        if len(parts) == 2 and parts[0] == host_port:
          container = parts[1]
        elif len(parts) == 3 and parts[1] == host_port:
          container = parts[2]
        else:
          new_ports.append(port)
          continue
        # Find next free host port
        new_host = None
        while True:
          candidate = base + remap_counter
          remap_counter += 1
          if str(candidate) not in used:
            new_host = candidate
            used.add(str(candidate))
            break
        if len(parts) == 2:
          new_ports.append(f'{new_host}:{container}')
        else:
          # ip:host:container -> replace host
          new_ports.append(f'{parts[0]}:{new_host}:{container}')
        remap_log.append((svc, host_port, str(new_host), container))
        changed = True
      if changed:
        acc['services'][svc]['ports'] = new_ports
  if remap_log:
    sys.stderr.write('Remapped colliding host ports:\n')
    for svc, old, new, container in remap_log:
      sys.stderr.write(f'  {svc}: {old} -> {new} (container {container})\n')

# Optional sorting (services and resource sections)
if args.sort and not args.no_sort:
  acc['services'] = dict(sorted(acc['services'].items(), key=lambda kv: kv[0]))
  for section in ('networks','volumes','configs','secrets'):
    if section in acc:
      acc[section] = dict(sorted(acc[section].items(), key=lambda kv: kv[0]))

summary = {
  'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
  'source_files': sources,
  'service_count': len(acc['services']),
  'services': sorted(acc['services'].keys()),
  'collisions': {hp: sorted(list(svcs)) for hp, svcs in collisions.items()},
  'dropped_host_ports': [
    {'service': svc, 'host_port': old, 'container_port': container}
    for svc, old, container in drop_log
  ],
  'remapped_host_ports': [
    {'service': svc, 'old_host_port': old, 'new_host_port': new, 'container_port': container}
    for svc, old, new, container in remap_log
  ],
  'options': {
    'drop_colliding_ports': bool(getattr(args,'drop_colliding_ports', False)),
    'remap_colliding_ports_base': getattr(args,'remap_colliding_ports', None),
    'profiles': sorted(list(include_profiles)) if include_profiles else None,
    'exclude_profiles': sorted(list(exclude_profiles)) if exclude_profiles else None,
    'only_services': sorted(list(keep)) if 'keep' in locals() and keep else None,
    'sorted': bool(args.sort and not args.no_sort),
    'dry_run': bool(args.dry_run)
  },
  'output_file': None,
  'output_digest': None
}

# Prepare header & optionally write AFTER any port adjustments
header=[f'# Auto-generated on {summary["timestamp"]}','# Source files:']+[f'#  - {s}' for s in sources]
if not args.dry_run:
  os.makedirs(os.path.dirname(args.output),exist_ok=True)
  with open(args.output,'w') as out:
    out.write('\n'.join(header)+'\n'); ver=acc.pop('version'); out.write(f'version: "{ver}"\n'); yaml.safe_dump(acc,out,sort_keys=False,default_flow_style=False)
  if collisions and not args.no_port_warn:
    sys.stderr.write('\nPort collision warnings:\n')
    for hpv, svcs in collisions.items():
      sys.stderr.write(f'  {hpv}: {", ".join(sorted(svcs))}\n')
  elif not args.no_port_warn and not collisions:
    sys.stderr.write('No host port collisions detected.\n')
  sha=args.output+'.sha256'
  with open(args.output,'rb') as f: digest=hashlib.sha256(f.read()).hexdigest()
  with open(sha,'w') as f: f.write(f'{digest}  {os.path.basename(args.output)}\n')
  sys.stderr.write(f'Generated {args.output} (sha256 {digest[:12]}...)\n')
  summary['output_file'] = args.output
  summary['output_digest'] = digest
else:
  sys.stderr.write('Dry run: no compose or digest file written.\n')
  # Remove version before potential future writing but keep count accurate
  acc.pop('version', None)

# Write JSON summary if requested
if args.summary_json:
  target = args.summary_json
  payload = json.dumps(summary, indent=2)
  if target == '-':
    print(payload)
  else:
    with open(target, 'w') as jf:
      jf.write(payload + '\n')
    sys.stderr.write(f'Wrote summary JSON to {target}\n')
PY

echo "Compose merge complete." >&2
