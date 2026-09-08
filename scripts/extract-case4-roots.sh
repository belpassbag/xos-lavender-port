#!/usr/bin/env bash
set -euo pipefail

die() {
  printf 'ERROR: %s\n' "$1" >&2
  exit 1
}

if [[ $# -ne 2 ]]; then
  die "usage: $0 IMAGE_ROOT OUTPUT_ROOT"
fi

image_root=$1
output_root=$2

for command_name in awk debugfs df dirname flock mkdir mktemp mv python3 readlink rm sha256sum stat sync tail tr; do
  command -v "$command_name" >/dev/null 2>&1 || die "required command not found: $command_name"
done
for path in "$image_root" "$output_root"; do
  [[ "$path" =~ ^/[A-Za-z0-9._/-]+$ ]] || die "paths must be absolute and whitespace-free: $path"
done
[[ -d "$image_root" && ! -L "$image_root" ]] || die "invalid image root: $image_root"
[[ ! -L "$output_root" ]] || die "refusing symbolic-link output root: $output_root"
mkdir -p "$output_root/roots" "$output_root/reports/generated"

script_dir=$(dirname "$(readlink -f "$0")")
repository_root=$(dirname "$script_dir")
compatctl=(python3 "$repository_root/tools/compatctl.py")
selection_script="$repository_root/scripts/extract-case3-selection.sh"

declare -A images=(
  [base_system]="$image_root/images/base_system.img"
  [base_vendor]="$image_root/images/base_vendor.img"
  [donor_system]="$image_root/images/donor_system.img"
  [donor_product]="$image_root/images/donor_product.img"
  [donor_system_ext]="$image_root/images/donor_system_ext.img"
)
declare -A hashes=(
  [base_system]="3536fa28745278ecbd38cc0a0f09329a1c19cf1f959aeb189ee71c1c9f904501"
  [base_vendor]="967a4b560b774e869a5ce16f6b5ee6b73dedfdfde7fa4ef641b3b9cdce4f8f60"
  [donor_system]="2fb5bf44091b6ddd9d63799351c38f75c26499809f6db832e24ced3f5700313d"
  [donor_product]="a3e760d683423b419f2b859fbf3ac24cfd41276939291e819cbeb05e9db6fcbb"
  [donor_system_ext]="7de9ac35bd7c51e683b86546278e2c630024e9f8c9a01c9d4b99f1836324b002"
)

lock_path="$output_root/.extract-case4.lock"
[[ ! -L "$lock_path" ]] || die "refusing symbolic-link lock: $lock_path"
exec 9>"$lock_path"
flock -n 9 || die "another Case 4 root extractor is using $output_root"

for identifier in base_system base_vendor donor_system donor_product donor_system_ext; do
  image=${images[$identifier]}
  [[ -f "$image" && ! -L "$image" ]] || die "verified image is missing: $image"
  "${compatctl[@]}" verify-image --id "$identifier" --image "$image" >/dev/null
done
"${compatctl[@]}" verify-images \
  --base-system "${images[base_system]}" \
  --base-vendor "${images[base_vendor]}" \
  --donor-system "${images[donor_system]}" \
  --donor-product "${images[donor_product]}" \
  --donor-system-ext "${images[donor_system_ext]}" \
  --report "$output_root/reports/generated/images.json" >/dev/null

verify_marker() {
  local marker=$1
  local identifier=$2
  local destination=$3

  python3 - "$marker" "$identifier" "${hashes[$identifier]}" "$destination" <<'PY'
import json
from pathlib import Path
import sys

marker = Path(sys.argv[1])
identifier = sys.argv[2]
expected_hash = sys.argv[3]
destination = Path(sys.argv[4])
if marker.is_symlink() or not marker.is_file():
    raise SystemExit("root completion marker is missing or unsafe")
value = json.loads(marker.read_text(encoding="utf-8"))
if value != {
    "image_id": identifier,
    "image_sha256": expected_hash,
    "root": str(destination),
    "status": "complete",
}:
    raise SystemExit("root completion marker drift")
PY
}

write_marker() {
  local marker=$1
  local identifier=$2
  local destination=$3

  python3 - "$marker" "$identifier" "${hashes[$identifier]}" "$destination" <<'PY'
import json
import os
from pathlib import Path
import tempfile
import sys

path = Path(sys.argv[1])
value = {
    "image_id": sys.argv[2],
    "image_sha256": sys.argv[3],
    "root": sys.argv[4],
    "status": "complete",
}
fd, name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".partial", dir=path.parent)
temporary = Path(name)
try:
    with os.fdopen(fd, "w", encoding="utf-8") as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, path)
except Exception:
    temporary.unlink(missing_ok=True)
    raise
PY
}

extract_root() {
  local identifier=$1
  local image=$2
  local destination=$3
  local required_bytes=$4
  local marker="$output_root/reports/generated/root-${identifier}.json"
  local available
  local temporary
  local log="$output_root/reports/generated/debugfs-${identifier}.log"

  [[ ! -L "$destination" ]] || die "refusing symbolic-link root: $destination"
  if [[ -e "$destination" ]]; then
    [[ -d "$destination" ]] || die "existing root is not a directory: $destination"
    verify_marker "$marker" "$identifier" "$destination" \
      || die "cannot reuse unverified root: $destination"
    [[ -d "$destination/system" ]] || die "reused root has no /system: $destination"
    printf 'REUSED root %s image=%s\n' "$destination" "$identifier"
    return
  fi
  [[ ! -e "$marker" && ! -L "$marker" ]] || die "completion marker exists without root: $marker"
  available=$(df -B1 --output=avail "$(dirname "$destination")" | tail -n 1 | tr -d '[:space:]')
  (( available >= required_bytes + 536870912 )) \
    || die "insufficient space for $identifier root: need $((required_bytes + 536870912)), have $available"
  temporary=$(mktemp -d "$(dirname "$destination")/.${destination##*/}.partial.XXXXXX")
  if ! debugfs -R "rdump / $temporary" "$image" >"$log" 2>&1; then
    rm -rf -- "$temporary"
    die "debugfs failed for $identifier; see $log"
  fi
  [[ -d "$temporary/system" ]] || {
    rm -rf -- "$temporary"
    die "debugfs output for $identifier has no /system"
  }
  sync "$temporary"
  mv -- "$temporary" "$destination"
  write_marker "$marker" "$identifier" "$destination"
  printf 'EXTRACTED root %s image=%s\n' "$destination" "$identifier"
}

extract_root base_system "${images[base_system]}" "$output_root/roots/base" 1627586560
extract_root donor_system "${images[donor_system]}" "$output_root/roots/donor-system" 1100521472

"$selection_script" \
  "${images[base_system]}" \
  "${images[base_vendor]}" \
  "${images[donor_system]}" \
  "${images[donor_product]}" \
  "${images[donor_system_ext]}" \
  "$output_root/selection"

python3 "$repository_root/tools/buildctl.py" inspect-inputs \
  --base-root "$output_root/roots/base" \
  --donor-system-root "$output_root/roots/donor-system" \
  --donor-product-root "$output_root/selection/donor/product" \
  --donor-system-ext-root "$output_root/selection/donor/system_ext" \
  --report "$output_root/reports/generated/case4-inputs.json" >/dev/null

printf 'COMPLETE roots=%s selection=%s\n' "$output_root/roots" "$output_root/selection"
