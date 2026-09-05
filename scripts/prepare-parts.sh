#!/usr/bin/env bash
set -euo pipefail

BASE_NAME="lineage-18.1-20221025-nightly-lavender-signed.zip"
DONOR_NAME="X6812B-H6912KL-R-OP-231009V922.zip"
BASE_SHA256="4845c4910593a6b8a612c5ea9af1b6752fe8ab2514f62e062abe759e760b82ba"
DONOR_SHA256="5066e7b7e397bad14b81d91f42a1d79e05c150e37c7b047f7b52e5b4b8a178b0"
CHUNK_SIZE="200M"

usage() {
  printf 'Usage: %s BASE_ZIP DONOR_ZIP [OUTPUT_DIRECTORY]\n' "$0" >&2
}

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

if [[ $# -lt 2 || $# -gt 3 ]]; then
  usage
  exit 2
fi

base_zip=$1
donor_zip=$2
output_dir=${3:-XOS-Lavender-Parts}

for command_name in awk basename df find mkdir sha256sum split stat tail tr; do
  command -v "$command_name" >/dev/null 2>&1 || die "Required command not found: $command_name"
done

[[ -f "$base_zip" ]] || die "Base ZIP not found: $base_zip"
[[ -f "$donor_zip" ]] || die "Donor ZIP not found: $donor_zip"
[[ $(basename "$base_zip") == "$BASE_NAME" ]] || die "Unexpected base filename: $(basename "$base_zip")"
[[ $(basename "$donor_zip") == "$DONOR_NAME" ]] || die "Unexpected donor filename: $(basename "$donor_zip")"

actual_base_sha=$(sha256sum "$base_zip" | awk '{print $1}')
actual_donor_sha=$(sha256sum "$donor_zip" | awk '{print $1}')
[[ "$actual_base_sha" == "$BASE_SHA256" ]] || die "Base SHA-256 mismatch"
[[ "$actual_donor_sha" == "$DONOR_SHA256" ]] || die "Donor SHA-256 mismatch"

required_bytes=$(( $(stat -c '%s' "$base_zip") + $(stat -c '%s' "$donor_zip") + 536870912 ))
output_parent=$(dirname "$output_dir")
mkdir -p "$output_parent"
available_bytes=$(df --output=avail -B1 "$output_parent" | tail -n 1 | tr -d ' ')
[[ "$available_bytes" =~ ^[0-9]+$ ]] || die "Could not determine available disk space"
(( available_bytes >= required_bytes )) || die "Insufficient free space; at least $required_bytes bytes are required"

if [[ -e "$output_dir" ]]; then
  [[ -d "$output_dir" ]] || die "Output path exists and is not a directory: $output_dir"
  [[ -z $(find "$output_dir" -mindepth 1 -maxdepth 1 -print -quit) ]] || die "Output directory is not empty: $output_dir"
else
  mkdir -p "$output_dir"
fi

split -b "$CHUNK_SIZE" -d -a 3 "$base_zip" "$output_dir/lineage.zip.part-"
split -b "$CHUNK_SIZE" -d -a 3 "$donor_zip" "$output_dir/xos.zip.part-"

(
  cd "$output_dir"
  sha256sum lineage.zip.part-* xos.zip.part-* > SHA256SUMS-parts.txt
)

printf 'Created verified source chunks in %s\n' "$output_dir"
printf 'Upload every part and SHA256SUMS-parts.txt together. Originals were not modified.\n'
