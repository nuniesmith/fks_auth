#!/bin/bash
# (Relocated) Single SSH public key helper.
set -e
[[ -z ${1:-} ]] && { echo "Usage: $0 'ssh-ed25519 AAAA... comment'"; exit 1; }
KEY=$1
[[ ! $KEY =~ ^ssh-(rsa|ed25519|ecdsa) ]] && { echo "Invalid key"; exit 1; }
echo "Add as ACTIONS_USER_SSH_PUB secret and Deploy Key (write)"; echo "$KEY"
