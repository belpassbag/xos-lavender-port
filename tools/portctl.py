#!/usr/bin/env python3
"""Deterministic source-intake controls for the XOS lavender port."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import re
import sys
import tempfile
import tomllib
from typing import BinaryIO, Iterable


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = REPOSITORY_ROOT / "config" / "port.toml"
BUFFER_SIZE = 4 * 1024 * 1024
HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
PART_SUFFIX = re.compile(r"^(?P<prefix>.+?)(?P<number>[0-9]+)$")


class PortError(RuntimeError):
    """Expected validation or source-intake failure."""


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
    if project.get("android_version") != 11 or project.get("sdk") != 30:
        raise PortError("profile must remain Android 11 / SDK 30")
    if project.get("architecture") != "arm64":
        raise PortError("profile architecture must remain arm64")

    base = config.get("base", {})
    donor = config.get("donor", {})
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

    forbidden = set(config.get("policy", {}).get("forbidden_donor_output_images", []))
    required_forbidden = {"boot.img", "dtbo.img", "vendor.img", "vbmeta.img", "preloader.img"}
    if not required_forbidden.issubset(forbidden):
        missing = ", ".join(sorted(required_forbidden - forbidden))
        raise PortError(f"hardware safety policy is incomplete: {missing}")

    if base["system_filesystem_data_size"] > base["system_partition_size"]:
        raise PortError("base system filesystem exceeds its physical partition")


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
