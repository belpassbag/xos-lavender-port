#!/usr/bin/env bash
set -euo pipefail

for command_name in dirname python3 readlink; do
  command -v "$command_name" >/dev/null 2>&1 || {
    printf 'ERROR: required command not found: %s\n' "$command_name" >&2
    exit 1
  }
done

script_dir=$(dirname "$(readlink -f "$0")")
repository_root=$(dirname "$script_dir")
exec python3 "$repository_root/tools/case5ctl.py" "$@"
