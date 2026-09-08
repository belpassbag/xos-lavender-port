#!/usr/bin/env bash
set -euo pipefail

die() {
  printf 'ERROR: %s\n' "$1" >&2
  exit 1
}

if [[ $# -ne 4 ]]; then
  die "usage: $0 DRIVE_FILE_ID EXPECTED_BYTES EXPECTED_SHA256 ABSOLUTE_DESTINATION"
fi

drive_id=$1
expected_size=$2
expected_sha256=$3
destination=$4

for command_name in awk curl df dirname flock mkdir mv sha256sum stat sync tail touch tr; do
  command -v "$command_name" >/dev/null 2>&1 || die "required command not found: $command_name"
done

[[ "$drive_id" =~ ^[A-Za-z0-9_-]+$ ]] || die "unsafe Drive file ID"
[[ "$expected_size" =~ ^[1-9][0-9]*$ ]] || die "invalid expected byte count"
[[ "$expected_sha256" =~ ^[0-9a-f]{64}$ ]] || die "invalid expected SHA-256"
[[ "$destination" =~ ^/[A-Za-z0-9._/-]+$ ]] || die "destination must be absolute and whitespace-free"
[[ ! -L "$destination" ]] || die "refusing symbolic-link destination"

destination_parent=$(dirname "$destination")
mkdir -p "$destination_parent"
[[ -d "$destination_parent" && ! -L "$destination_parent" ]] || die "invalid destination directory"

lock_path="${destination}.lock"
[[ ! -L "$lock_path" ]] || die "refusing symbolic-link lock"
exec 9>"$lock_path"
flock -n 9 || die "another download is already using $destination"

verify_complete() {
  local path=$1
  local actual_size
  local actual_sha256

  [[ -f "$path" && ! -L "$path" ]] || die "download is not a regular file: $path"
  actual_size=$(stat -c %s "$path")
  [[ "$actual_size" == "$expected_size" ]] \
    || die "download size mismatch: expected $expected_size, got $actual_size"
  actual_sha256=$(sha256sum "$path" | awk '{ print $1 }')
  [[ "$actual_sha256" == "$expected_sha256" ]] || die "download SHA-256 mismatch"
}

if [[ -e "$destination" ]]; then
  verify_complete "$destination"
  printf 'VERIFIED existing bytes=%s sha256=%s path=%s\n' \
    "$expected_size" "$expected_sha256" "$destination"
  exit 0
fi

partial="${destination}.partial"
[[ ! -L "$partial" ]] || die "refusing symbolic-link partial download"
if [[ ! -e "$partial" ]]; then
  (umask 077 && touch "$partial")
fi
[[ -f "$partial" && ! -L "$partial" ]] || die "partial download is not a regular file"

partial_size=$(stat -c %s "$partial")
(( partial_size <= expected_size )) || die "partial download exceeds expected size"
remaining=$((expected_size - partial_size))
available=$(df -B1 --output=avail "$destination_parent" | tail -n 1 | tr -d '[:space:]')
reserve=$((512 * 1024 * 1024))
(( available >= remaining + reserve )) \
  || die "insufficient free space: need $((remaining + reserve)) bytes, have $available"

if (( partial_size < expected_size )); then
  printf 'RESUME offset=%s remaining=%s path=%s\n' "$partial_size" "$remaining" "$destination"
  curl --proto '=https' --tlsv1.2 -L --fail --silent --show-error \
    --connect-timeout 30 --retry 8 --retry-delay 2 --retry-all-errors \
    --continue-at - \
    "https://drive.usercontent.google.com/download?id=${drive_id}&export=download&confirm=t" \
    --output "$partial"
fi

verify_complete "$partial"
sync "$partial"
mv "$partial" "$destination"
printf 'COMPLETE bytes=%s sha256=%s path=%s\n' \
  "$expected_size" "$expected_sha256" "$destination"
