#!/bin/bash
# (Relocated) SSH key generation helper.
set -e
mkdir -p "$HOME/.ssh"; chmod 700 "$HOME/.ssh"
gen(){ local name=$1; ssh-keygen -t ed25519 -f "$HOME/.ssh/$name" -N '' -C "$name@fks"; echo "Generated $name:"; cat "$HOME/.ssh/$name.pub"; }
gen actions_user_fks
gen jordan_fks
echo "Add public keys as repository secrets / deploy keys.";
