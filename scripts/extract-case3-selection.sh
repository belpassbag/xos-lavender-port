#!/usr/bin/env bash
set -euo pipefail

die() {
  printf 'ERROR: %s\n' "$1" >&2
  exit 1
}

if [[ $# -ne 6 ]]; then
  die "usage: $0 BASE_SYSTEM BASE_VENDOR DONOR_SYSTEM DONOR_PRODUCT DONOR_SYSTEM_EXT OUTPUT_DIR"
fi

base_system=$1
base_vendor=$2
donor_system=$3
donor_product=$4
donor_system_ext=$5
output_dir=$6

for command_name in awk debugfs dirname find flock mkdir mktemp mv rmdir sha256sum sort stat sync wc; do
  command -v "$command_name" >/dev/null 2>&1 || die "required command not found: $command_name"
done

for image in "$base_system" "$base_vendor" "$donor_system" "$donor_product" "$donor_system_ext"; do
  [[ "$image" =~ ^/[A-Za-z0-9._/-]+$ ]] || die "image path must be absolute and whitespace-free: $image"
  [[ -f "$image" && ! -L "$image" ]] || die "invalid image: $image"
done
[[ "$output_dir" =~ ^/[A-Za-z0-9._/-]+$ ]] || die "output path must be absolute and whitespace-free"
[[ ! -L "$output_dir" ]] || die "refusing symbolic-link output directory: $output_dir"
mkdir -p "$output_dir"

lock_path="$output_dir/.extract.lock"
[[ ! -L "$lock_path" ]] || die "refusing symbolic-link lock file: $lock_path"
[[ ! -e "$lock_path" || -f "$lock_path" ]] || die "invalid lock file: $lock_path"
exec 9>"$lock_path"
flock -n 9 || die "another Case 3 extraction is already using $output_dir"

dump_file() {
  local image=$1
  local source_path=$2
  local destination=$3
  local destination_parent
  local partial

  [[ "$source_path" =~ ^/[A-Za-z0-9._/-]+$ ]] || die "unsafe ext4 source path: $source_path"
  [[ ! -L "$destination" ]] || die "refusing symbolic-link destination: $destination"
  if [[ -e "$destination" ]]; then
    [[ -f "$destination" ]] || die "existing destination is not a regular file: $destination"
    printf 'REUSED file %s bytes=%s\n' "$destination" "$(stat -c %s "$destination")"
    return
  fi

  destination_parent=$(dirname "$destination")
  mkdir -p "$destination_parent"
  partial=$(mktemp "$destination_parent/.${destination##*/}.partial.XXXXXX")
  debugfs -R "dump -p $source_path $partial" "$image" >/dev/null 2>&1 \
    || die "debugfs failed to dump: $source_path"
  [[ -s "$partial" ]] || die "debugfs produced an empty file: $source_path"
  sync "$partial"
  mv "$partial" "$destination"
  printf 'EXTRACTED file %s bytes=%s\n' "$destination" "$(stat -c %s "$destination")"
}

dump_directory() {
  local image=$1
  local source_path=$2
  local destination=$3
  local destination_parent
  local temporary_root
  local extracted

  [[ "$source_path" =~ ^/[A-Za-z0-9._/-]+$ ]] || die "unsafe ext4 source directory: $source_path"
  [[ ! -L "$destination" ]] || die "refusing symbolic-link destination: $destination"
  if [[ -e "$destination" ]]; then
    [[ -d "$destination" ]] || die "existing destination is not a directory: $destination"
    [[ -z $(find "$destination" -type l -print -quit) ]] || die "symbolic link in reused directory: $destination"
    printf 'REUSED directory %s\n' "$destination"
    return
  fi

  destination_parent=$(dirname "$destination")
  mkdir -p "$destination_parent"
  temporary_root=$(mktemp -d "$destination_parent/.${destination##*/}.partial.XXXXXX")
  debugfs -R "rdump $source_path $temporary_root" "$image" >/dev/null 2>&1 \
    || die "debugfs failed to recursively dump: $source_path"
  extracted="$temporary_root/${source_path##*/}"
  [[ -d "$extracted" ]] || die "debugfs directory output missing: $source_path"
  [[ -z $(find "$extracted" -type l -print -quit) ]] || die "symbolic link in extracted directory: $source_path"
  mv "$extracted" "$destination"
  rmdir "$temporary_root"
  printf 'EXTRACTED directory %s\n' "$destination"
}

dump_directory "$donor_product" /app/SystemUIOverlay "$output_dir/donor/product/app/SystemUIOverlay"
dump_directory "$donor_product" /app/SettingsOverlay "$output_dir/donor/product/app/SettingsOverlay"
dump_directory "$donor_product" /priv-app/XOSLauncher_res "$output_dir/donor/product/priv-app/XOSLauncher_res"

dump_directory "$donor_system_ext" /app/XLauncher "$output_dir/donor/system_ext/app/XLauncher"
dump_directory "$donor_system_ext" /app/OSSettingsExt "$output_dir/donor/system_ext/app/OSSettingsExt"
dump_directory "$donor_system_ext" /priv-app/TranSystemUI "$output_dir/donor/system_ext/priv-app/TranSystemUI"
dump_directory "$donor_system_ext" /priv-app/TranSettings "$output_dir/donor/system_ext/priv-app/TranSettings"
dump_directory "$donor_system_ext" /priv-app/TranSettingsIntelligence "$output_dir/donor/system_ext/priv-app/TranSettingsIntelligence"

dump_file "$donor_system" /system/apex/com.transsion.mi.os.framework.apex "$output_dir/donor/system/apex/com.transsion.mi.os.framework.apex"
dump_file "$donor_system_ext" /apex/com.transsion.kolun.apex "$output_dir/donor/system_ext/apex/com.transsion.kolun.apex"
dump_file "$donor_system_ext" /framework/transsion-res.apk "$output_dir/donor/system_ext/framework/transsion-res.apk"

for jar in framework.jar services.jar ext.jar mediatek-common.jar mediatek-ims-common.jar mediatek-telephony-base.jar mediatek-telephony-common.jar; do
  dump_file "$donor_system" "/system/framework/$jar" "$output_dir/donor/system/framework/$jar"
done
for jar in org.ifaa.android.manager.jar telephony-ext.jar; do
  dump_file "$base_system" "/system/framework/$jar" "$output_dir/base/system/framework/$jar"
done

for directory in etc/vintf etc/selinux etc/permissions etc/init; do
  dump_directory "$base_system" "/system/$directory" "$output_dir/base/system/$directory"
  dump_directory "$donor_system" "/system/$directory" "$output_dir/donor/system/$directory"
done
for directory in etc/selinux etc/permissions; do
  dump_directory "$base_system" "/system/product/$directory" "$output_dir/base/product/$directory"
  dump_directory "$base_system" "/system/system_ext/$directory" "$output_dir/base/system_ext/$directory"
  dump_directory "$donor_product" "/$directory" "$output_dir/donor/product/$directory"
  dump_directory "$donor_system_ext" "/$directory" "$output_dir/donor/system_ext/$directory"
done
dump_directory "$base_system" /system/system_ext/etc/init "$output_dir/base/system_ext/etc/init"
dump_directory "$donor_product" /etc/init "$output_dir/donor/product/etc/init"
dump_directory "$donor_system_ext" /etc/init "$output_dir/donor/system_ext/etc/init"
for directory in etc/vintf etc/selinux etc/init; do
  dump_directory "$base_vendor" "/$directory" "$output_dir/base/vendor/$directory"
done

dump_file "$base_vendor" /etc/fstab.qcom "$output_dir/base/vendor/etc/fstab.qcom"
dump_file "$base_system" /system/build.prop "$output_dir/base/system/build.prop"
dump_file "$donor_system" /system/build.prop "$output_dir/donor/system/build.prop"
dump_file "$donor_product" /build.prop "$output_dir/donor/product/build.prop"
dump_file "$donor_system_ext" /build.prop "$output_dir/donor/system_ext/build.prop"

manifest_partial=$(mktemp "$output_dir/.selection-files.sha256.partial.XXXXXX")
(
  cd "$output_dir"
  while IFS= read -r -d '' relative_path; do
    sha256sum "$relative_path"
  done < <(find base donor -type f -print0 | sort -z)
) >"$manifest_partial"
sync "$manifest_partial"
mv "$manifest_partial" "$output_dir/selection-files.sha256"

printf 'COMPLETE files=%s bytes=%s output=%s\n' \
  "$(find "$output_dir/base" "$output_dir/donor" -type f | wc -l)" \
  "$(find "$output_dir/base" "$output_dir/donor" -type f -printf '%s\n' | awk '{ total += $1 } END { print total }')" \
  "$output_dir"
