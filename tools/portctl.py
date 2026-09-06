#!/usr/bin/env python3
"""Deterministic source-intake controls for the XOS lavender port."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import sys
import tempfile
import tomllib
from typing import BinaryIO, Iterable
import zipfile
import zlib


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = REPOSITORY_ROOT / "config" / "port.toml"
BUFFER_SIZE = 4 * 1024 * 1024
HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
PART_SUFFIX = re.compile(r"^(?P<prefix>.+?)(?P<number>[0-9]+)$")

LOCKED_PROJECT = {
    "name": "xos-lavender-port",
    "mode": "xos-core-debloated",
    "android_version": 11,
    "sdk": 30,
    "architecture": "arm64",
}

LOCKED_BASE = {
    "role": "target",
    "device": "lavender",
    "model": "Redmi Note 7",
    "platform": "sdm660",
    "filename": "lineage-18.1-20221025-nightly-lavender-signed.zip",
    "parts_prefix": "lineage.zip.part-",
    "size": 851061345,
    "sha256": "4845c4910593a6b8a612c5ea9af1b6752fe8ab2514f62e062abe759e760b82ba",
    "system_partition_size": 3640619008,
    "system_filesystem_data_size": 3583086592,
    "vendor_partition_size": 2080305152,
    "boot_partition_size": 67108864,
    "dtbo_partition_size": 8388608,
    "required_zip_entries": [
        "system.new.dat.br",
        "system.transfer.list",
        "vendor.new.dat.br",
        "vendor.transfer.list",
        "boot.img",
        "vbmeta.img",
    ],
    "extract_entries": [
        "META-INF/com/android/metadata",
        "META-INF/com/google/android/updater-script",
        "system.new.dat.br",
        "system.transfer.list",
        "vendor.new.dat.br",
        "vendor.transfer.list",
        "boot.img",
        "vbmeta.img",
    ],
    "expected_entry_sizes": {
        "META-INF/com/android/metadata": 306,
        "META-INF/com/google/android/updater-script": 1599,
        "system.new.dat.br": 629925639,
        "system.transfer.list": 8269,
        "vendor.new.dat.br": 207113214,
        "vendor.transfer.list": 2897,
        "boot.img": 67108864,
        "vbmeta.img": 8192,
    },
}

LOCKED_DONOR = {
    "role": "framework-source",
    "device": "Infinix-X6812B",
    "model": "Infinix HOT 11S NFC",
    "platform": "mt6768",
    "filename": "X6812B-H6912KL-R-OP-231009V922.zip",
    "parts_prefix": "xos.zip.part-",
    "size": 3939359066,
    "sha256": "5066e7b7e397bad14b81d91f42a1d79e05c150e37c7b047f7b52e5b4b8a178b0",
    "required_zip_entries": [
        "super.img",
        "boot.img",
        "dtbo.img",
        "vbmeta.img",
        "vbmeta_system.img",
        "vbmeta_vendor.img",
        "MT6768_Android_scatter.txt",
    ],
    "extract_entries": [
        "super.img",
        "vbmeta.img",
        "vbmeta_system.img",
        "vbmeta_vendor.img",
        "MT6768_Android_scatter.txt",
        "MT6768_Android_scatter.xml",
        "android-info.txt",
        "installed-files-product.txt",
        "installed-files-system_ext.txt",
        "installed-files-vendor.txt",
    ],
    "expected_entry_sizes": {
        "super.img": 6808452712,
        "boot.img": 33554432,
        "dtbo.img": 8388608,
        "vbmeta.img": 4096,
        "vbmeta_system.img": 4096,
        "vbmeta_vendor.img": 4096,
        "MT6768_Android_scatter.txt": 22391,
        "MT6768_Android_scatter.xml": 37883,
        "android-info.txt": 21,
        "installed-files-product.txt": 26327,
        "installed-files-system_ext.txt": 25750,
        "installed-files-vendor.txt": 112428,
    },
}

LOCKED_POLICY = {
    "keep_from_base": [
        "boot",
        "vendor",
        "dtbo",
        "vbmeta",
        "kernel",
        "fstab",
        "init",
        "modem",
        "firmware",
        "persist",
    ],
    "forbidden_donor_output_images": [
        "boot.img",
        "boot-adb.img",
        "dtbo.img",
        "vendor.img",
        "vbmeta.img",
        "vbmeta_system.img",
        "vbmeta_vendor.img",
        "preloader.img",
        "preloader_emmc.img",
        "preloader_raw.img",
        "preloader_ufs.img",
        "preloader_x6812_h6912.bin",
        "kernel",
        "lk.img",
        "md1img.img",
        "scp.img",
        "spmfw.img",
        "sspm.img",
        "tee.img",
    ],
    "core_xos_packages": [
        "TranSystemUI",
        "TranSettings",
        "XLauncher",
        "OSSettingsExt",
    ],
    "core_xos_dependencies": [
        "TranSettingsIntelligence",
        "SystemUIOverlay",
        "SettingsOverlay",
        "XOSLauncher_res",
        "com.transsion.mi.os.framework",
    ],
    "donor_product_selection": "allowlist-only",
    "donor_product_package_allowlist": [
        "/product/app/SystemUIOverlay",
        "/product/app/SettingsOverlay",
        "/product/priv-app/XOSLauncher_res",
    ],
    "donor_system_ext_selection": "allowlist-only",
    "donor_system_ext_package_allowlist": [
        "/system_ext/priv-app/TranSystemUI",
        "/system_ext/priv-app/TranSettings",
        "/system_ext/priv-app/TranSettingsIntelligence",
        "/system_ext/app/XLauncher",
        "/system_ext/app/OSSettingsExt",
    ],
    "first_boot_exclusions": [
        "/product/operator",
        "/system_ext/app/TranssionCamera",
        "/system_ext/app/FaceID",
        "/system_ext/app/Nfc_st",
        "/system_ext/app/CalibrationTool2",
        "/system_ext/app/AfterSaleCalibrationTool",
        "/system_ext/app/VideoCallEnhancer",
    ],
}


class PortError(RuntimeError):
    """Expected validation or source-intake failure."""


def _require_locked_section(name: str, actual: object, expected: dict) -> None:
    if actual == expected:
        return
    if not isinstance(actual, dict):
        raise PortError(f"{name} section differs from the locked profile")
    missing = sorted(expected.keys() - actual.keys())
    unexpected = sorted(actual.keys() - expected.keys())
    changed = sorted(
        key for key in expected.keys() & actual.keys() if actual[key] != expected[key]
    )
    details: list[str] = []
    if missing:
        details.append("missing=" + ",".join(missing))
    if unexpected:
        details.append("unexpected=" + ",".join(unexpected))
    if changed:
        details.append("changed=" + ",".join(changed))
    raise PortError(f"{name} section differs from the locked profile: {'; '.join(details)}")


def load_config(path: Path = DEFAULT_CONFIG) -> dict:
    try:
        with path.open("rb") as config_file:
            config = tomllib.load(config_file)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise PortError(f"cannot load configuration {path}: {exc}") from exc
    validate_config(config)
    return config


def validate_config(config: dict) -> None:
    if config.get("schema_version") != 1:
        raise PortError("unsupported configuration schema")

    project = config.get("project", {})
    _require_locked_section("project", project, LOCKED_PROJECT)
    if project.get("android_version") != 11 or project.get("sdk") != 30:
        raise PortError("profile must remain Android 11 / SDK 30")
    if project.get("architecture") != "arm64":
        raise PortError("profile architecture must remain arm64")

    base = config.get("base", {})
    donor = config.get("donor", {})
    _require_locked_section("base", base, LOCKED_BASE)
    _require_locked_section("donor", donor, LOCKED_DONOR)
    if base.get("device") != "lavender" or base.get("platform") != "sdm660":
        raise PortError("target must remain lavender / sdm660")
    if donor.get("device") != "Infinix-X6812B" or donor.get("platform") != "mt6768":
        raise PortError("donor must remain Infinix-X6812B / mt6768")

    for source_name, source in (("base", base), ("donor", donor)):
        if not HEX_SHA256.fullmatch(str(source.get("sha256", ""))):
            raise PortError(f"invalid {source_name} SHA-256")
        if not isinstance(source.get("size"), int) or source["size"] <= 0:
            raise PortError(f"invalid {source_name} size")
        if not source.get("filename") or not source.get("parts_prefix"):
            raise PortError(f"incomplete {source_name} file profile")
        required_entries = source.get("required_zip_entries")
        extract_entries = source.get("extract_entries")
        expected_sizes = source.get("expected_entry_sizes")
        if not isinstance(required_entries, list) or not required_entries:
            raise PortError(f"missing {source_name} required ZIP entries")
        if not isinstance(extract_entries, list) or not extract_entries:
            raise PortError(f"missing {source_name} extraction allowlist")
        if not isinstance(expected_sizes, dict) or not expected_sizes:
            raise PortError(f"missing {source_name} expected entry sizes")
        if not set(extract_entries).issubset(expected_sizes):
            raise PortError(f"{source_name} extraction allowlist lacks expected sizes")
        if not set(required_entries).issubset(expected_sizes):
            raise PortError(f"{source_name} required entries lack expected sizes")

    policy = config.get("policy", {})
    _require_locked_section("policy", policy, LOCKED_POLICY)
    forbidden = set(policy.get("forbidden_donor_output_images", []))
    required_forbidden = {"boot.img", "dtbo.img", "vendor.img", "vbmeta.img", "preloader.img"}
    if not required_forbidden.issubset(forbidden):
        missing = ", ".join(sorted(required_forbidden - forbidden))
        raise PortError(f"hardware safety policy is incomplete: {missing}")

    if base["system_filesystem_data_size"] > base["system_partition_size"]:
        raise PortError("base system filesystem exceeds its physical partition")

    forbidden_donor_extraction = {"boot.img", "dtbo.img"}
    unsafe_extraction = forbidden_donor_extraction & set(donor["extract_entries"])
    if unsafe_extraction:
        raise PortError(
            "donor hardware images may not enter normal extraction: "
            + ", ".join(sorted(unsafe_extraction))
        )

    broad_product_exclusions = {"/product/app", "/product/priv-app"}
    if broad_product_exclusions & set(policy["first_boot_exclusions"]):
        raise PortError("broad product exclusion conflicts with the XOS dependency allowlist")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(BUFFER_SIZE), b""):
                digest.update(chunk)
    except OSError as exc:
        raise PortError(f"cannot hash {path}: {exc}") from exc
    return digest.hexdigest()


def verify_source(path: Path, source: dict) -> None:
    if not path.is_file():
        raise PortError(f"source file not found: {path}")
    actual_size = path.stat().st_size
    if actual_size != source["size"]:
        raise PortError(f"size mismatch for {path.name}: expected {source['size']}, got {actual_size}")
    actual_sha256 = sha256_file(path)
    if actual_sha256 != source["sha256"]:
        raise PortError(
            f"SHA-256 mismatch for {path.name}: expected {source['sha256']}, got {actual_sha256}"
        )


def is_safe_zip_name(name: str) -> bool:
    if not name or "\x00" in name or "\\" in name:
        return False
    path = PurePosixPath(name)
    return not path.is_absolute() and ".." not in path.parts


def audit_zip(path: Path, source: dict) -> dict:
    verify_source(path, source)
    try:
        archive = zipfile.ZipFile(path)
    except (OSError, zipfile.BadZipFile) as exc:
        raise PortError(f"cannot open ZIP {path}: {exc}") from exc

    with archive:
        entries: dict[str, zipfile.ZipInfo] = {}
        for info in archive.infolist():
            if not is_safe_zip_name(info.filename):
                raise PortError(f"unsafe ZIP entry: {info.filename!r}")
            if info.filename in entries:
                raise PortError(f"duplicate ZIP entry: {info.filename}")
            if info.flag_bits & 0x1:
                raise PortError(f"encrypted ZIP entry is unsupported: {info.filename}")
            mode = info.external_attr >> 16
            if mode and stat.S_ISLNK(mode):
                raise PortError(f"symbolic-link ZIP entry is unsupported: {info.filename}")
            entries[info.filename] = info

        missing = sorted(set(source["required_zip_entries"]) - entries.keys())
        if missing:
            raise PortError(f"required ZIP entries missing: {', '.join(missing)}")

        for name, expected_size in source["expected_entry_sizes"].items():
            info = entries.get(name)
            if info is None:
                raise PortError(f"expected ZIP entry missing: {name}")
            if info.file_size != expected_size:
                raise PortError(
                    f"ZIP entry size mismatch for {name}: expected {expected_size}, got {info.file_size}"
                )

        return {
            "filename": path.name,
            "size": path.stat().st_size,
            "sha256": source["sha256"],
            "entry_count": len(entries),
            "uncompressed_size": sum(info.file_size for info in entries.values()),
            "extract_entries": [
                {
                    "path": name,
                    "size": entries[name].file_size,
                    "crc32": f"{entries[name].CRC:08x}",
                    "compression": entries[name].compress_type,
                }
                for name in source["extract_entries"]
            ],
        }


def crc32_file(path: Path) -> int:
    checksum = 0
    try:
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(BUFFER_SIZE), b""):
                checksum = zlib.crc32(chunk, checksum)
    except OSError as exc:
        raise PortError(f"cannot calculate CRC32 for {path}: {exc}") from exc
    return checksum & 0xFFFFFFFF


def verify_extracted_file(path: Path, info: zipfile.ZipInfo) -> None:
    if not path.is_file():
        raise PortError(f"extracted file not found: {path}")
    if path.stat().st_size != info.file_size:
        raise PortError(f"extracted size mismatch: {path}")
    if crc32_file(path) != info.CRC:
        raise PortError(f"extracted CRC32 mismatch: {path}")


def atomic_extract_entry(archive: zipfile.ZipFile, info: zipfile.ZipInfo, destination: Path) -> None:
    if destination.is_symlink():
        raise PortError(f"refusing symbolic-link extraction destination: {destination}")
    if destination.exists():
        verify_extracted_file(destination, info)
        return

    destination.parent.mkdir(parents=True, exist_ok=True)
    file_descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".partial", dir=destination.parent
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(file_descriptor, "wb") as output, archive.open(info, "r") as source:
            copy_stream(source, output)
            output.flush()
            os.fsync(output.fileno())
        verify_extracted_file(temporary_path, info)
        os.replace(temporary_path, destination)
    except Exception:
        temporary_path.unlink(missing_ok=True)
        raise


def write_manifest_once(path: Path, manifest: dict) -> None:
    content = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    if path.is_symlink():
        raise PortError(f"refusing symbolic-link manifest destination: {path}")
    if path.exists():
        try:
            existing = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise PortError(f"cannot read existing manifest {path}: {exc}") from exc
        if existing != content:
            raise PortError(f"existing extraction manifest differs: {path}")
        return
    file_descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".partial", dir=path.parent
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(file_descriptor, "w", encoding="utf-8") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary_path, path)
    except Exception:
        temporary_path.unlink(missing_ok=True)
        raise


def safe_extraction_destination(root: Path, relative_path: PurePosixPath) -> Path:
    current = root
    for component in relative_path.parts[:-1]:
        current = current / component
        if current.is_symlink():
            raise PortError(f"refusing symbolic-link extraction directory: {current}")
        if current.exists() and not current.is_dir():
            raise PortError(f"extraction path component is not a directory: {current}")
        current.mkdir(exist_ok=True)
    destination = current / relative_path.name
    if destination.is_symlink():
        raise PortError(f"refusing symbolic-link extraction destination: {destination}")
    return destination


def extract_source(path: Path, output_dir: Path, source_name: str, source: dict) -> Path:
    report = audit_zip(path, source)
    destination_root = output_dir / source_name
    if destination_root.is_symlink():
        raise PortError(f"refusing symbolic-link extraction root: {destination_root}")
    destination_root.mkdir(parents=True, exist_ok=True)

    required_space = sum(entry["size"] for entry in report["extract_entries"]) + 256 * 1024 * 1024
    available_space = shutil.disk_usage(destination_root).free
    if available_space < required_space:
        raise PortError(
            f"insufficient extraction space: need {required_space} bytes, have {available_space}"
        )

    try:
        archive = zipfile.ZipFile(path)
    except (OSError, zipfile.BadZipFile) as exc:
        raise PortError(f"cannot reopen ZIP {path}: {exc}") from exc

    with archive:
        for name in source["extract_entries"]:
            relative_path = PurePosixPath(name)
            destination = safe_extraction_destination(destination_root, relative_path)
            atomic_extract_entry(archive, archive.getinfo(name), destination)

    manifest = {
        "source": source_name,
        "source_filename": report["filename"],
        "source_size": report["size"],
        "source_sha256": report["sha256"],
        "entries": report["extract_entries"],
    }
    write_manifest_once(destination_root / "extraction-manifest.json", manifest)
    return destination_root


def discover_parts(parts_dir: Path, prefix: str) -> list[Path]:
    if not parts_dir.is_dir():
        raise PortError(f"parts directory not found: {parts_dir}")
    candidates = sorted(path for path in parts_dir.iterdir() if path.is_file() and path.name.startswith(prefix))
    if not candidates:
        raise PortError(f"no parts found with prefix {prefix!r} in {parts_dir}")

    numbered: list[tuple[int, Path]] = []
    width: int | None = None
    for path in candidates:
        match = PART_SUFFIX.fullmatch(path.name)
        if not match or match.group("prefix") != prefix:
            raise PortError(f"invalid part name: {path.name}")
        suffix = match.group("number")
        width = width if width is not None else len(suffix)
        if len(suffix) != width:
            raise PortError("part suffix widths are inconsistent")
        numbered.append((int(suffix), path))

    numbered.sort(key=lambda item: item[0])
    first = numbered[0][0]
    if first != 0:
        raise PortError(f"part sequence must start at zero, got {first}")
    expected_numbers = list(range(first, first + len(numbered)))
    actual_numbers = [number for number, _ in numbered]
    if actual_numbers != expected_numbers:
        raise PortError(f"part sequence is not contiguous: {actual_numbers}")
    return [path for _, path in numbered]


def parse_checksum_manifest(path: Path) -> dict[str, str]:
    checksums: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise PortError(f"cannot read checksum manifest {path}: {exc}") from exc

    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        fields = line.split(maxsplit=1)
        if len(fields) != 2 or not HEX_SHA256.fullmatch(fields[0]):
            raise PortError(f"invalid checksum manifest line {line_number}")
        name = fields[1].lstrip(" *")
        if not name or Path(name).name != name:
            raise PortError(f"unsafe checksum filename on line {line_number}")
        if name in checksums:
            raise PortError(f"duplicate checksum entry: {name}")
        checksums[name] = fields[0]
    return checksums


def verify_parts(parts: Iterable[Path], manifest: dict[str, str]) -> None:
    for part in parts:
        expected = manifest.get(part.name)
        if expected is None:
            raise PortError(f"checksum missing for part: {part.name}")
        actual = sha256_file(part)
        if actual != expected:
            raise PortError(f"checksum mismatch for part: {part.name}")


def copy_stream(source: BinaryIO, destination: BinaryIO) -> None:
    while True:
        chunk = source.read(BUFFER_SIZE)
        if not chunk:
            return
        destination.write(chunk)


def assemble_source(parts_dir: Path, output_dir: Path, source: dict) -> Path:
    parts = discover_parts(parts_dir, source["parts_prefix"])
    manifest_path = parts_dir / "SHA256SUMS-parts.txt"
    if not manifest_path.is_file():
        raise PortError(f"part checksum manifest not found: {manifest_path}")
    manifest = parse_checksum_manifest(manifest_path)
    verify_parts(parts, manifest)

    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / source["filename"]
    if output_path.exists():
        verify_source(output_path, source)
        return output_path

    file_descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{source['filename']}.", suffix=".partial", dir=output_dir
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(file_descriptor, "wb") as destination:
            for part in parts:
                with part.open("rb") as source_part:
                    copy_stream(source_part, destination)
            destination.flush()
            os.fsync(destination.fileno())
        verify_source(temporary_path, source)
        os.replace(temporary_path, output_path)
    except Exception:
        temporary_path.unlink(missing_ok=True)
        raise
    return output_path


def source_profile(config: dict, source_name: str) -> dict:
    if source_name not in {"base", "donor"}:
        raise PortError(f"unknown source: {source_name}")
    return config[source_name]


def command_check(config: dict, _args: argparse.Namespace) -> None:
    base = config["base"]
    donor = config["donor"]
    headroom = base["system_filesystem_data_size"] - (
        1_103_863_808 + 3_155_759_104 + 1_679_302_656
    )
    print("Configuration: OK")
    print(f"Target: {base['device']} / {base['platform']}")
    print(f"Donor: {donor['device']} / {donor['platform']}")
    print(f"Untouched donor system payload headroom: {headroom} bytes (negative means it cannot fit)")


def command_verify_source(config: dict, args: argparse.Namespace) -> None:
    source = source_profile(config, args.source)
    verify_source(args.path, source)
    print(f"Verified {args.source}: {args.path}")


def command_verify_parts(config: dict, args: argparse.Namespace) -> None:
    source = source_profile(config, args.source)
    parts = discover_parts(args.parts_dir, source["parts_prefix"])
    manifest = parse_checksum_manifest(args.parts_dir / "SHA256SUMS-parts.txt")
    verify_parts(parts, manifest)
    print(f"Verified {len(parts)} {args.source} parts")


def command_assemble(config: dict, args: argparse.Namespace) -> None:
    source = source_profile(config, args.source)
    output = assemble_source(args.parts_dir, args.output_dir, source)
    print(f"Assembled and verified {args.source}: {output}")


def command_audit_zip(config: dict, args: argparse.Namespace) -> None:
    source = source_profile(config, args.source)
    report = audit_zip(args.path, source)
    print(json.dumps(report, indent=2, sort_keys=True))


def command_extract(config: dict, args: argparse.Namespace) -> None:
    source = source_profile(config, args.source)
    output = extract_source(args.path, args.output_dir, args.source, source)
    print(f"Extracted and verified {args.source}: {output}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    subparsers = parser.add_subparsers(dest="command", required=True)

    check_parser = subparsers.add_parser("check", help="validate the locked port profile")
    check_parser.set_defaults(handler=command_check)

    verify_source_parser = subparsers.add_parser("verify-source", help="verify one complete source ZIP")
    verify_source_parser.add_argument("source", choices=("base", "donor"))
    verify_source_parser.add_argument("path", type=Path)
    verify_source_parser.set_defaults(handler=command_verify_source)

    verify_parts_parser = subparsers.add_parser("verify-parts", help="verify uploaded source parts")
    verify_parts_parser.add_argument("source", choices=("base", "donor"))
    verify_parts_parser.add_argument("--parts-dir", type=Path, required=True)
    verify_parts_parser.set_defaults(handler=command_verify_parts)

    assemble_parser = subparsers.add_parser("assemble", help="atomically reconstruct one source ZIP")
    assemble_parser.add_argument("source", choices=("base", "donor"))
    assemble_parser.add_argument("--parts-dir", type=Path, required=True)
    assemble_parser.add_argument("--output-dir", type=Path, required=True)
    assemble_parser.set_defaults(handler=command_assemble)

    audit_parser = subparsers.add_parser("audit-zip", help="verify ZIP structure and approved entries")
    audit_parser.add_argument("source", choices=("base", "donor"))
    audit_parser.add_argument("path", type=Path)
    audit_parser.set_defaults(handler=command_audit_zip)

    extract_parser = subparsers.add_parser("extract", help="extract only the source allowlist atomically")
    extract_parser.add_argument("source", choices=("base", "donor"))
    extract_parser.add_argument("path", type=Path)
    extract_parser.add_argument("--output-dir", type=Path, required=True)
    extract_parser.set_defaults(handler=command_extract)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        config = load_config(args.config)
        args.handler(config, args)
    except PortError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
