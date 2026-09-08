#!/usr/bin/env bash
set -euo pipefail

die() {
  printf 'ERROR: %s\n' "$1" >&2
  exit 1
}

if [[ $# -lt 2 || $# -gt 4 ]]; then
  die "usage: $0 {base|donor} SOURCE_ZIP OUTPUT_ROOT [--consume-source] | $0 verify OUTPUT_ROOT"
fi

mode=$1
if [[ "$mode" == "verify" ]]; then
  [[ $# -eq 2 ]] || die "verify mode takes only OUTPUT_ROOT"
  source_zip=
  output_root=$2
  consume_source=false
else
  [[ "$mode" == "base" || "$mode" == "donor" ]] || die "mode must be base, donor, or verify"
  [[ $# -eq 3 || $# -eq 4 ]] || die "$mode mode requires SOURCE_ZIP and OUTPUT_ROOT"
  source_zip=$2
  output_root=$3
  consume_source=false
  if [[ $# -eq 4 ]]; then
    [[ "$4" == "--consume-source" ]] || die "unknown option: $4"
    consume_source=true
  fi
fi

for command_name in dirname e2fsck flock mkdir mv python3 readlink rm rmdir; do
  command -v "$command_name" >/dev/null 2>&1 || die "required command not found: $command_name"
done

[[ "$output_root" =~ ^/[A-Za-z0-9._/-]+$ ]] || die "output root must be absolute and whitespace-free"
[[ ! -L "$output_root" ]] || die "refusing symbolic-link output root"
mkdir -p "$output_root/images" "$output_root/extracted" "$output_root/reports/generated"

script_dir=$(dirname "$(readlink -f "$0")")
repository_root=$(dirname "$script_dir")
portctl=(python3 "$repository_root/tools/portctl.py")
imagectl=(python3 "$repository_root/tools/imagectl.py")
compatctl=(python3 "$repository_root/tools/compatctl.py")

exec 9>"$output_root/.materialize.lock"
flock -n 9 || die "another Case 4 materializer is using $output_root"

verify_one() {
  local identifier=$1
  local image=$2
  local fsck_log="$output_root/reports/generated/e2fsck-${identifier}.log"

  e2fsck -fn "$image" >"$fsck_log" 2>&1 \
    || die "read-only e2fsck failed for $identifier; see $fsck_log"
  "${compatctl[@]}" verify-image --id "$identifier" --image "$image"
}

consume_downloaded_source() {
  local source_real
  local output_real

  [[ "$consume_source" == true ]] || return 0
  source_real=$(readlink -f "$source_zip")
  output_real=$(readlink -f "$output_root")
  case "$source_real" in
    "$output_real"/*) ;;
    *) die "--consume-source is restricted to a source inside OUTPUT_ROOT" ;;
  esac
  "${portctl[@]}" verify-source "$mode" "$source_zip"
  rm -- "$source_zip"
  printf 'PRUNED verified source %s\n' "$source_real"
}

verify_all() {
  "${compatctl[@]}" verify-images \
    --base-system "$output_root/images/base_system.img" \
    --base-vendor "$output_root/images/base_vendor.img" \
    --donor-system "$output_root/images/donor_system.img" \
    --donor-product "$output_root/images/donor_product.img" \
    --donor-system-ext "$output_root/images/donor_system_ext.img" \
    --report "$output_root/reports/generated/images.json"
}

if [[ "$mode" == "verify" ]]; then
  verify_all
  exit 0
fi

[[ "$source_zip" =~ ^/[A-Za-z0-9._/-]+$ ]] || die "source ZIP must be absolute and whitespace-free"
[[ -f "$source_zip" && ! -L "$source_zip" ]] || die "invalid source ZIP"
"${portctl[@]}" verify-source "$mode" "$source_zip"
"${portctl[@]}" extract "$mode" "$source_zip" --output-dir "$output_root/extracted"

if [[ "$mode" == "base" ]]; then
  base_extract="$output_root/extracted/base"
  if [[ ! -e "$output_root/images/base_system.img" ]]; then
    "${imagectl[@]}" ota-image \
      --transfer-list "$base_extract/system.transfer.list" \
      --brotli-data "$base_extract/system.new.dat.br" \
      --output "$output_root/images/base_system.img"
  fi
  verify_one base_system "$output_root/images/base_system.img"

  if [[ ! -e "$output_root/images/base_vendor.img" ]]; then
    "${imagectl[@]}" ota-image \
      --transfer-list "$base_extract/vendor.transfer.list" \
      --brotli-data "$base_extract/vendor.new.dat.br" \
      --output "$output_root/images/base_vendor.img"
  fi
  verify_one base_vendor "$output_root/images/base_vendor.img"

  rm -- \
    "$base_extract/system.new.dat.br" \
    "$base_extract/system.transfer.list" \
    "$base_extract/vendor.new.dat.br" \
    "$base_extract/vendor.transfer.list"
  consume_downloaded_source
  printf 'COMPLETE mode=base output=%s\n' "$output_root"
  exit 0
fi

donor_extract="$output_root/extracted/donor"
for mapping in \
  'system_a:donor_system' \
  'product_a:donor_product' \
  'system_ext_a:donor_system_ext'; do
  partition=${mapping%%:*}
  identifier=${mapping#*:}
  destination="$output_root/images/${identifier}.img"
  if [[ ! -e "$destination" ]]; then
    "${imagectl[@]}" lp-extract "$donor_extract/super.img" \
      --partition "$partition" \
      --output-dir "$output_root/images/.lp-${identifier}"
    mv_source="$output_root/images/.lp-${identifier}/${partition}.img"
    [[ -f "$mv_source" && ! -L "$mv_source" ]] || die "logical-partition output missing: $partition"
    mv -- "$mv_source" "$destination"
    rmdir "$output_root/images/.lp-${identifier}"
  fi
  verify_one "$identifier" "$destination"
done

verify_all
rm -- "$donor_extract/super.img"
consume_downloaded_source
printf 'COMPLETE mode=donor output=%s\n' "$output_root"
