#!/usr/bin/env bash
set -euo pipefail

die() {
  printf 'ERROR: %s\n' "$1" >&2
  exit 1
}

if [[ $# -ne 4 ]]; then
  die "usage: $0 SHA256SUMS ID_MAP OUTPUT_DIR PART_PREFIX"
fi

checksum_manifest=$1
id_map=$2
output_dir=$3
part_prefix=$4

for command_name in awk cmp cp curl flock mkdir mktemp mv sed sha256sum stat sync unlink; do
  command -v "$command_name" >/dev/null 2>&1 || die "required command not found: $command_name"
done

[[ -f "$checksum_manifest" && ! -L "$checksum_manifest" ]] || die "invalid checksum manifest: $checksum_manifest"
[[ -f "$id_map" && ! -L "$id_map" ]] || die "invalid Drive ID map: $id_map"
[[ "$part_prefix" =~ ^[A-Za-z0-9._-]+-$ ]] || die "unsafe part prefix: $part_prefix"

if [[ -L "$output_dir" ]]; then
  die "refusing symbolic-link output directory: $output_dir"
fi
mkdir -p "$output_dir"
[[ -d "$output_dir" && ! -L "$output_dir" ]] || die "invalid output directory: $output_dir"

lock_path="$output_dir/.download.lock"
[[ ! -L "$lock_path" ]] || die "refusing symbolic-link lock file: $lock_path"
[[ ! -e "$lock_path" || -f "$lock_path" ]] || die "invalid lock file: $lock_path"
exec 9>"$lock_path"
flock -n 9 || die "another part download is already using $output_dir"

mapfile -t part_names < <(
  awk -v prefix="$part_prefix" '
    index($2, prefix) == 1 { print $2 }
  ' "$checksum_manifest" | LC_ALL=C sort
)
[[ ${#part_names[@]} -gt 0 ]] || die "manifest has no parts with prefix: $part_prefix"

case3_probe=
case3_partial=
cleanup() {
  if [[ -n "$case3_probe" && -f "$case3_probe" ]]; then
    unlink "$case3_probe" 2>/dev/null || true
  fi
  if [[ -n "$case3_partial" && -f "$case3_partial" ]]; then
    unlink "$case3_partial" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

previous_name=
for part_name in "${part_names[@]}"; do
  [[ "$part_name" =~ ^[A-Za-z0-9._-]+$ ]] || die "unsafe part filename: $part_name"
  [[ "$part_name" != "$previous_name" ]] || die "duplicate part in manifest: $part_name"
  previous_name=$part_name

  expected_hash=$(awk -v name="$part_name" '$2 == name { print $1 }' "$checksum_manifest")
  [[ "$expected_hash" =~ ^[0-9a-f]{64}$ ]] || die "invalid or duplicate checksum for: $part_name"

  drive_id=$(awk -v name="$part_name" '$2 == name { print $1 }' "$id_map")
  [[ "$drive_id" =~ ^[A-Za-z0-9_-]+$ ]] || die "missing, duplicate, or unsafe Drive ID for: $part_name"

  destination="$output_dir/$part_name"
  [[ ! -L "$destination" ]] || die "refusing symbolic-link destination: $destination"
  if [[ -f "$destination" ]]; then
    actual_hash=$(sha256sum "$destination" | awk '{ print $1 }')
    [[ "$actual_hash" == "$expected_hash" ]] || die "existing part checksum mismatch: $destination"
    printf 'VERIFIED existing %s bytes=%s\n' "$part_name" "$(stat -c %s "$destination")"
    continue
  fi
  [[ ! -e "$destination" ]] || die "destination is not a regular file: $destination"

  case3_probe=$(mktemp "$output_dir/.${part_name}.probe.XXXXXX")
  case3_partial=$(mktemp "$output_dir/.${part_name}.partial.XXXXXX")

  curl --proto '=https' --tlsv1.2 -L --fail --silent --show-error \
    --connect-timeout 30 --retry 4 --retry-delay 2 \
    "https://drive.google.com/uc?export=download&id=$drive_id" \
    -o "$case3_probe"

  probe_hash=$(sha256sum "$case3_probe" | awk '{ print $1 }')
  if [[ "$probe_hash" == "$expected_hash" ]]; then
    mv "$case3_probe" "$case3_partial"
    case3_probe=
  else
    download_uuid=$(sed -n 's/.*name="uuid" value="\([^"]*\)".*/\1/p' "$case3_probe")
    [[ "$download_uuid" =~ ^[A-Za-z0-9-]+$ ]] || die "Drive confirmation token missing for: $part_name"
    curl --proto '=https' --tlsv1.2 -L --fail --silent --show-error \
      --connect-timeout 30 --retry 4 --retry-delay 2 \
      --get 'https://drive.usercontent.google.com/download' \
      --data-urlencode "id=$drive_id" \
      --data-urlencode 'export=download' \
      --data-urlencode 'confirm=t' \
      --data-urlencode "uuid=$download_uuid" \
      -o "$case3_partial"
  fi

  actual_hash=$(sha256sum "$case3_partial" | awk '{ print $1 }')
  [[ "$actual_hash" == "$expected_hash" ]] || die "downloaded part checksum mismatch: $part_name"
  sync "$case3_partial"
  mv "$case3_partial" "$destination"
  case3_partial=
  if [[ -n "$case3_probe" && -f "$case3_probe" ]]; then
    unlink "$case3_probe"
    case3_probe=
  fi
  printf 'VERIFIED downloaded %s bytes=%s\n' "$part_name" "$(stat -c %s "$destination")"
done

destination_manifest="$output_dir/SHA256SUMS-parts.txt"
[[ ! -L "$destination_manifest" ]] || die "refusing symbolic-link destination manifest"
if [[ -e "$destination_manifest" ]]; then
  [[ -f "$destination_manifest" && ! -L "$destination_manifest" ]] || die "invalid destination manifest"
  cmp -s "$checksum_manifest" "$destination_manifest" || die "destination manifest differs from source"
else
  cp "$checksum_manifest" "$destination_manifest"
fi

printf 'COMPLETE prefix=%s parts=%s output=%s\n' "$part_prefix" "${#part_names[@]}" "$output_dir"
