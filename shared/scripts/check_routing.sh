#!/usr/bin/env bash
set -uo pipefail

hosts=(
  fkstrading.xyz
  api.fkstrading.xyz
  data.fkstrading.xyz
  auth.fkstrading.xyz
  code.fkstrading.xyz
)
path="/health"

ok=0
fail=0
for host in "${hosts[@]}"; do
  printf "Checking %-24s -> %s ... " "$host" "$path"
  code=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $host" "http://127.0.0.1$path")
  if [[ "$code" == "200" ]]; then
    echo "OK (200)"; ((ok++))
  else
    echo "FAIL ($code)"; ((fail++))
  fi
done

echo "Summary: $ok OK, $fail FAIL"
if [[ "$fail" -ne 0 ]]; then exit 1; fi
