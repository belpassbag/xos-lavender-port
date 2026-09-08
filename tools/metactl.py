#!/usr/bin/env python3
"""Capture deterministic Android filesystem metadata directly from locked ext4 images."""

from __future__ import annotations

import argparse
import base64
from collections import Counter, deque
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tempfile
import tomllib


TOOLS_DIRECTORY = Path(__file__).resolve().parent
if str(TOOLS_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIRECTORY))

import buildctl  # noqa: E402
import compatctl  # noqa: E402


REPOSITORY_ROOT = TOOLS_DIRECTORY.parent
DEFAULT_PROFILE = REPOSITORY_ROOT / "config" / "case5.toml"
DEFAULT_COMPATIBILITY_PROFILE = REPOSITORY_ROOT / "config" / "compatibility.toml"
DEFAULT_PORT_PROFILE = REPOSITORY_ROOT / "config" / "port.toml"
DEFAULT_PIPELINE_PROFILE = REPOSITORY_ROOT / "config" / "pipeline.toml"
LOCKED_PROFILE_SHA256 = "7238eab915ca53aca65cb14c9d60ce466f36efd6428ab621b951c5dee3714d6e"
SNAPSHOT_SCHEMA = "xos-ext4-metadata-v1"
DEBUGFS_BATCH_SIZE = 1000

EXPECTED_SOURCE_PLAN = [
    {
        "id": "base_system",
        "mode": "snapshot",
        "purpose": "system-as-root base, protected paths, and retained shared-UID packages",
        "roots": ["/"],
    },
    {
        "id": "base_vendor",
        "mode": "preserve-image",
        "purpose": "byte-exact lavender hardware partition",
        "roots": [],
    },
    {
        "id": "donor_system",
        "mode": "snapshot",
        "purpose": "donor TSSI system transplant",
        "roots": ["/system"],
    },
    {
        "id": "donor_product",
        "mode": "snapshot",
        "purpose": "selected XOS product overlays",
        "roots": [
            "/app/SettingsOverlay",
            "/app/SystemUIOverlay",
            "/priv-app/XOSLauncher_res",
        ],
    },
    {
        "id": "donor_system_ext",
        "mode": "snapshot",
        "purpose": "selected XOS core apps and runtime files",
        "roots": [
            "/apex/com.transsion.kolun.apex",
            "/app/OSSettingsExt",
            "/app/XLauncher",
            "/framework/transsion-res.apk",
            "/priv-app/TranSettings",
            "/priv-app/TranSettingsIntelligence",
            "/priv-app/TranSystemUI",
        ],
    },
]

LS_RECORD = re.compile(
    r"^/(?P<inode>[0-9]+)/(?P<mode>[0-7]+)/(?P<uid>[0-9]+)/"
    r"(?P<gid>[0-9]+)/(?P<name>[^/]*)/(?P<size>[0-9]*)/$"
)
EA_COMMAND = re.compile(r"^debugfs: ea_list <(?P<inode>[0-9]+)>$")
EA_RECORD = re.compile(
    r"^  (?P<name>[A-Za-z0-9_.-]+) \((?P<size>[0-9]+)\) = (?P<value>.*)$"
)


class MetadataError(RuntimeError):
    """The metadata profile, image, or debugfs output is unsafe or inconsistent."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise MetadataError(message)


def _read_toml(path: Path) -> dict:
    if path.is_symlink() or not path.is_file():
        raise MetadataError(f"profile is not a regular file: {path}")
    try:
        with path.open("rb") as source:
            return tomllib.load(source)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise MetadataError(f"cannot read profile {path}: {exc}") from exc


def _safe_roots(values: object) -> list[str]:
    _require(isinstance(values, list), "metadata roots must be a list")
    _require(all(isinstance(value, str) for value in values), "metadata root must be a string")
    roots = list(values)
    _require(len(roots) == len(set(roots)), "duplicate metadata root")
    for value in roots:
        path = PurePosixPath(value)
        _require(value.startswith("/") and str(path) == value, f"metadata root is not normalized: {value}")
        _require("." not in path.parts and ".." not in path.parts, f"unsafe metadata root: {value}")
        _require(re.fullmatch(r"/[A-Za-z0-9._/+-]*", value) is not None, f"unsafe metadata root: {value}")
    for index, root in enumerate(roots):
        prefix = root.rstrip("/") + "/"
        for other in roots[index + 1 :]:
            other_prefix = other.rstrip("/") + "/"
            _require(
                not other.startswith(prefix) and not root.startswith(other_prefix),
                f"overlapping metadata roots: {root}, {other}",
            )
    return roots


def validate_profile(
    profile: dict,
    compatibility: dict,
    port: dict,
    pipeline: dict,
    *,
    enforce_lock: bool = True,
) -> dict:
    digest = compatctl.canonical_digest(profile)
    if enforce_lock:
        _require(digest == LOCKED_PROFILE_SHA256, "Case 5 profile digest is not locked")
    _require(profile.get("schema_version") == 1, "unsupported Case 5 profile schema")

    project = profile.get("project", {})
    _require(project.get("case") == "5.1", "Case 5 subcase drift")
    _require(project.get("device") == "lavender", "target device drift")
    _require(project.get("donor") == "Infinix-X6812B", "donor device drift")
    for field, expected in (("android_version", 11), ("sdk", 30), ("architecture", "arm64")):
        _require(project.get(field) == expected, f"project {field} drift")
    _require(project.get("mode") == "development", "Case 5.1 must remain development-only")
    _require(
        project.get("port_profile_sha256") == compatctl.canonical_digest(port),
        "port profile reference drift",
    )
    _require(
        project.get("compatibility_profile_sha256") == compatctl.canonical_digest(compatibility),
        "compatibility profile reference drift",
    )
    _require(
        project.get("pipeline_profile_sha256") == compatctl.canonical_digest(pipeline),
        "pipeline profile reference drift",
    )

    local = profile.get("local", {})
    _require(local.get("minimum_fresh_free_bytes") == 24 * 1024**3, "fresh-space floor drift")
    _require(local.get("state_schema") == "xos-lavender-case5-local-v1", "state schema drift")
    _require(local.get("report_schema") == "xos-lavender-case5-checkpoint-v1", "report schema drift")
    _require(local.get("background_mode") == "detached-session", "background mode drift")

    signing = profile.get("signing", {})
    _require(
        signing
        == {
            "mode": "project-development",
            "private_key_name": "platform-development.pem",
            "certificate_name": "platform-development.der",
            "private_directory_mode": "0700",
            "private_key_mode": "0600",
        },
        "development-signing contract drift",
    )
    _require(pipeline.get("signing", {}).get("allow_production_key") is False, "production key enabled")

    metadata = profile.get("metadata", {})
    _require(metadata.get("schema") == SNAPSHOT_SCHEMA, "metadata schema drift")
    _require(metadata.get("capture_all_extended_attributes") is True, "full xattr capture is required")
    _require(metadata.get("required_label_xattr") == "security.selinux", "SELinux label contract drift")
    _require(metadata.get("capability_xattr") == "security.capability", "capability contract drift")
    _require(
        metadata.get("allowed_file_types") == ["directory", "regular", "symlink"],
        "metadata file-type contract drift",
    )
    sources = metadata.get("sources")
    _require(sources == EXPECTED_SOURCE_PLAN, "metadata source plan drift")
    for source in sources:
        _safe_roots(source["roots"])

    image_ids = [row.get("id") for row in compatibility.get("images", [])]
    _require(image_ids == [row["id"] for row in EXPECTED_SOURCE_PLAN], "compatibility image order drift")

    guards = profile.get("guards", {})
    _require(guards.get("preserve_source_archives") is True, "source archives must be preserved")
    for guard in ("consume_source_archives", "allow_production_key", "allow_repack", "allow_automatic_flash"):
        _require(guards.get(guard) is False, f"unsafe Case 5.1 guard enabled: {guard}")
    _require(guards.get("require_data_outside_repository") is True, "external data-root guard missing")
    _require(port.get("policy", {}).get("forbidden_donor_output_images"), "donor image guard missing")

    return {
        "status": "verified",
        "profile_sha256": digest,
        "snapshot_sources": 4,
        "preserved_images": 1,
        "snapshot_roots": sum(len(row["roots"]) for row in sources),
        "production_signing": False,
        "repack": False,
        "automatic_flash": False,
    }


def load_and_validate(
    profile_path: Path = DEFAULT_PROFILE,
    compatibility_path: Path = DEFAULT_COMPATIBILITY_PROFILE,
    port_path: Path = DEFAULT_PORT_PROFILE,
    pipeline_path: Path = DEFAULT_PIPELINE_PROFILE,
) -> tuple[dict, dict, dict, dict, dict]:
    profile = _read_toml(profile_path)
    try:
        compatibility, port, _ = compatctl.load_and_validate(compatibility_path, port_path)
        pipeline = buildctl._read_toml(pipeline_path)
        buildctl.validate_profile(pipeline, compatibility, port)
    except (compatctl.CompatibilityError, buildctl.BuildError) as exc:
        raise MetadataError(str(exc)) from exc
    summary = validate_profile(profile, compatibility, port, pipeline)
    return profile, compatibility, port, pipeline, summary


def source_plan(profile: dict, image_id: str) -> dict:
    rows = {row["id"]: row for row in profile["metadata"]["sources"]}
    _require(image_id in rows, f"unknown metadata image id: {image_id}")
    return rows[image_id]


def _debugfs_environment() -> dict[str, str]:
    environment = dict(os.environ)
    environment["LC_ALL"] = "C"
    return environment


def _run_debugfs_text(image: Path, command: str) -> str:
    try:
        result = subprocess.run(
            ["debugfs", "-R", command, str(image)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="surrogateescape",
            env=_debugfs_environment(),
            check=False,
        )
    except OSError as exc:
        raise MetadataError(f"cannot execute debugfs: {exc}") from exc
    _require(result.returncode == 0, f"debugfs command failed: {command}")
    return result.stdout


def _entry_kind(mode: int) -> str:
    kind = stat.S_IFMT(mode)
    names = {
        stat.S_IFDIR: "directory",
        stat.S_IFREG: "regular",
        stat.S_IFLNK: "symlink",
    }
    _require(kind in names, f"unsupported ext4 file type: {mode:06o}")
    return names[kind]


def parse_ls_output(output: str) -> list[dict]:
    rows: list[dict] = []
    for raw_line in output.splitlines():
        line = raw_line.rstrip("\r")
        if not line or line.startswith("debugfs "):
            continue
        match = LS_RECORD.fullmatch(line)
        _require(match is not None, f"unrecognized debugfs ls output: {line}")
        assert match is not None
        name = match.group("name")
        _require(name and "\x00" not in name and "\n" not in name, "unsafe ext4 entry name")
        mode = int(match.group("mode"), 8)
        rows.append(
            {
                "inode": int(match.group("inode")),
                "type": _entry_kind(mode),
                "mode_octal": f"{mode:06o}",
                "permissions_octal": f"{stat.S_IMODE(mode):04o}",
                "uid": int(match.group("uid")),
                "gid": int(match.group("gid")),
                "name": name,
                "size": int(match.group("size") or "0"),
            }
        )
    _require(rows, "debugfs directory listing is empty")
    return rows


def _list_directory(image: Path, path: str) -> list[dict]:
    output = _run_debugfs_text(image, f"ls -p -l {path}")
    _require("ls: " not in output and "File not found" not in output, f"cannot list ext4 path: {path}")
    return parse_ls_output(output)


def _join_path(parent: str, name: str) -> str:
    value = "/" + name if parent == "/" else parent + "/" + name
    _require(str(PurePosixPath(value)) == value, f"unsafe discovered ext4 path: {value}")
    return value


def scan_entries(image: Path, roots: list[str]) -> list[dict]:
    roots = _safe_roots(roots)
    _require(roots, "snapshot source has no roots")
    discovered: dict[str, dict] = {}
    directory_queue: deque[tuple[str, int]] = deque()
    queued_directories: set[str] = set()
    directory_inodes: dict[int, str] = {}
    preloaded: dict[str, list[dict]] = {}

    def add(path: str, row: dict) -> None:
        entry = {key: value for key, value in row.items() if key != "name"}
        entry["path"] = path
        previous = discovered.get(path)
        if previous is not None:
            _require(previous == entry, f"metadata drift while revisiting path: {path}")
            return
        discovered[path] = entry
        if entry["type"] == "directory":
            previous_path = directory_inodes.get(entry["inode"])
            _require(previous_path in (None, path), f"hard-linked directory is unsafe: {path}")
            directory_inodes[entry["inode"]] = path
            if path not in queued_directories:
                queued_directories.add(path)
                directory_queue.append((path, entry["inode"]))

    for root in roots:
        if root == "/":
            rows = _list_directory(image, root)
            current = next((row for row in rows if row["name"] == "."), None)
            _require(current is not None, "root directory self-entry is missing")
            assert current is not None
            add(root, current)
            preloaded[root] = rows
            continue
        logical = PurePosixPath(root)
        parent = str(logical.parent)
        rows = _list_directory(image, parent)
        current = next((row for row in rows if row["name"] == logical.name), None)
        _require(current is not None, f"metadata root is missing from image: {root}")
        assert current is not None
        add(root, current)

    while directory_queue:
        parent, parent_inode = directory_queue.popleft()
        rows = preloaded.pop(parent, None) or _list_directory(image, f"<{parent_inode}>")
        current = next((row for row in rows if row["name"] == "."), None)
        _require(current is not None, f"directory self-entry is missing: {parent}")
        assert current is not None
        add(parent, current)
        for row in sorted(rows, key=lambda item: item["name"]):
            name = row["name"]
            if name in {".", ".."}:
                continue
            add(_join_path(parent, name), row)

    return [discovered[path] for path in sorted(discovered)]


def _decode_quoted_bytes(value: str) -> bytes:
    _require(len(value) >= 2 and value[0] == '"' and value[-1] == '"', "invalid quoted xattr")
    body = value[1:-1]
    result = bytearray()
    index = 0
    escapes = {
        "a": 0x07,
        "b": 0x08,
        "t": 0x09,
        "n": 0x0A,
        "v": 0x0B,
        "f": 0x0C,
        "r": 0x0D,
        "e": 0x1B,
        "\\": 0x5C,
        '"': 0x22,
    }
    while index < len(body):
        character = body[index]
        if character != "\\":
            result.extend(character.encode("utf-8", errors="surrogateescape"))
            index += 1
            continue
        index += 1
        _require(index < len(body), "trailing xattr escape")
        character = body[index]
        if character in "01234567":
            end = index
            while end < min(index + 3, len(body)) and body[end] in "01234567":
                end += 1
            result.append(int(body[index:end], 8))
            index = end
            continue
        _require(character in escapes, f"unknown xattr escape: \\{character}")
        result.append(escapes[character])
        index += 1
    return bytes(result)


def decode_xattr_value(value: str, expected_size: int) -> bytes:
    value = value.strip()
    if value.startswith('"'):
        decoded = _decode_quoted_bytes(value)
    else:
        _require(
            re.fullmatch(r"(?:[0-9A-Fa-f]{2}(?:\s+|$))+", value) is not None,
            f"unrecognized binary xattr value: {value}",
        )
        decoded = bytes.fromhex(value)
    _require(len(decoded) == expected_size, f"xattr size mismatch: expected {expected_size}, got {len(decoded)}")
    return decoded


def parse_ea_batch(output: str, expected_inodes: list[int]) -> dict[int, dict[str, bytes]]:
    expected = set(expected_inodes)
    result: dict[int, dict[str, bytes]] = {}
    current_inode: int | None = None
    current_attribute: tuple[str, int, list[str]] | None = None

    def finish_attribute() -> None:
        nonlocal current_attribute
        if current_attribute is None:
            return
        _require(current_inode is not None, "xattr appeared before an inode command")
        name, size, fragments = current_attribute
        value = decode_xattr_value(" ".join(fragments), size)
        _require(name not in result[current_inode], f"duplicate xattr {name} on inode {current_inode}")
        result[current_inode][name] = value
        current_attribute = None

    for raw_line in output.splitlines():
        line = raw_line.rstrip("\r")
        command = EA_COMMAND.fullmatch(line)
        if command:
            finish_attribute()
            current_inode = int(command.group("inode"))
            _require(current_inode in expected, f"unexpected xattr inode: {current_inode}")
            _require(current_inode not in result, f"duplicate xattr command: {current_inode}")
            result[current_inode] = {}
            continue
        record = EA_RECORD.fullmatch(line)
        if record:
            finish_attribute()
            _require(current_inode is not None, "xattr appeared before an inode command")
            current_attribute = (
                record.group("name"),
                int(record.group("size")),
                [record.group("value")],
            )
            continue
        if current_attribute is not None and line.startswith("    "):
            current_attribute[2].append(line.strip())
            continue
        if "ea_list:" in line or "Filesystem not open" in line:
            raise MetadataError(f"debugfs xattr failure: {line}")
    finish_attribute()
    _require(set(result) == expected, "debugfs omitted one or more xattr commands")
    return result


def read_xattrs(image: Path, inodes: list[int]) -> dict[int, dict[str, bytes]]:
    unique = sorted(set(inodes))
    result: dict[int, dict[str, bytes]] = {}
    for offset in range(0, len(unique), DEBUGFS_BATCH_SIZE):
        batch = unique[offset : offset + DEBUGFS_BATCH_SIZE]
        commands = "".join(f"ea_list <{inode}>\n" for inode in batch)
        try:
            process = subprocess.run(
                ["debugfs", "-f", "-", str(image)],
                input=commands,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="surrogateescape",
                env=_debugfs_environment(),
                check=False,
            )
        except OSError as exc:
            raise MetadataError(f"cannot execute debugfs: {exc}") from exc
        _require(process.returncode == 0, "debugfs xattr batch failed")
        result.update(parse_ea_batch(process.stdout, batch))
    return result


def read_symlink(image: Path, inode: int, expected_size: int) -> bytes:
    try:
        with tempfile.TemporaryDirectory(prefix="xos-symlink-") as temporary:
            destination_root = Path(temporary)
            process = subprocess.run(
                ["debugfs", "-R", f"rdump <{inode}> {destination_root}", str(image)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=_debugfs_environment(),
                check=False,
            )
            stderr = process.stderr.decode("utf-8", errors="surrogateescape")
            outputs = list(destination_root.iterdir())
            _require(
                process.returncode == 0
                and "rdump: " not in stderr
                and len(outputs) == 1
                and outputs[0].is_symlink(),
                f"cannot read symlink inode {inode}",
            )
            destination = outputs[0]
            target = os.fsencode(os.readlink(destination))
    except OSError as exc:
        raise MetadataError(f"cannot execute debugfs for symlink inode {inode}: {exc}") from exc
    _require(len(target) == expected_size, f"symlink size mismatch for inode {inode}")
    return target


def capture_entries(image: Path, roots: list[str]) -> list[dict]:
    entries = scan_entries(image, roots)
    xattrs = read_xattrs(image, [entry["inode"] for entry in entries])
    symlinks: dict[int, bytes] = {}
    for entry in entries:
        encoded_attributes = {
            name: base64.b64encode(value).decode("ascii")
            for name, value in sorted(xattrs[entry["inode"]].items())
        }
        entry["xattrs_b64"] = encoded_attributes
        if entry["type"] == "symlink":
            if entry["inode"] not in symlinks:
                symlinks[entry["inode"]] = read_symlink(image, entry["inode"], entry["size"])
            target = symlinks[entry["inode"]]
            entry["symlink_target_b64"] = base64.b64encode(target).decode("ascii")
            try:
                entry["symlink_target"] = target.decode("utf-8")
            except UnicodeDecodeError:
                pass
    return entries


def _snapshot_summary(entries: list[dict], label_xattr: str, capability_xattr: str) -> dict:
    types = Counter(entry["type"] for entry in entries)
    attribute_names = Counter(name for entry in entries for name in entry["xattrs_b64"])
    inode_paths: dict[int, int] = Counter(entry["inode"] for entry in entries)
    return {
        "entries": len(entries),
        "directories": types["directory"],
        "regular_files": types["regular"],
        "symbolic_links": types["symlink"],
        "unique_inodes": len(inode_paths),
        "hardlinked_inodes": sum(1 for count in inode_paths.values() if count > 1),
        "extended_attributes": sum(attribute_names.values()),
        "xattr_names": dict(sorted(attribute_names.items())),
        "selinux_labels": attribute_names[label_xattr],
        "file_capabilities": attribute_names[capability_xattr],
    }


def build_snapshot(
    image_id: str,
    image_identity: dict,
    purpose: str,
    roots: list[str],
    entries: list[dict],
    label_xattr: str,
    capability_xattr: str,
) -> dict:
    summary = _snapshot_summary(entries, label_xattr, capability_xattr)
    _require(summary["selinux_labels"] > 0, f"no SELinux labels captured from {image_id}")
    return {
        "schema": SNAPSHOT_SCHEMA,
        "status": "verified",
        "image": {
            key: image_identity[key]
            for key in ("id", "size", "sha256", "block_count", "free_blocks", "block_size", "used_bytes")
        },
        "purpose": purpose,
        "roots": roots,
        "metadata_sha256": compatctl.canonical_digest(entries),
        "summary": summary,
        "entries": entries,
    }


def _atomic_report(path: Path, value: dict) -> None:
    _require(path.is_absolute(), "snapshot output must be absolute")
    _require(not path.is_symlink(), f"refusing symbolic-link snapshot: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".partial", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(value, output, indent=2, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_snapshot(path: Path) -> dict:
    _require(path.is_file() and not path.is_symlink(), f"snapshot is not a regular file: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise MetadataError(f"cannot read metadata snapshot {path}: {exc}") from exc
    _require(isinstance(value, dict) and value.get("schema") == SNAPSHOT_SCHEMA, "snapshot schema drift")
    _require(value.get("status") == "verified", "snapshot is not verified")
    image = value.get("image")
    _require(isinstance(image, dict) and image.get("id"), "snapshot image identity is missing")
    roots = _safe_roots(value.get("roots"))
    _require(roots, "snapshot roots are empty")
    entries = value.get("entries")
    _require(isinstance(entries, list) and entries, "snapshot entries are empty")
    paths: list[str] = []
    allowed_types = {"directory", "regular", "symlink"}
    for entry in entries:
        _require(isinstance(entry, dict), "invalid snapshot entry")
        path_value = entry.get("path")
        _require(
            isinstance(path_value, str) and path_value.startswith("/") and str(PurePosixPath(path_value)) == path_value,
            "invalid snapshot entry path",
        )
        _require(entry.get("type") in allowed_types, f"invalid snapshot entry type: {path_value}")
        _require(re.fullmatch(r"[0-7]{6}", str(entry.get("mode_octal", ""))) is not None, "invalid mode")
        _require(re.fullmatch(r"[0-7]{4}", str(entry.get("permissions_octal", ""))) is not None, "invalid permissions")
        mode = int(entry["mode_octal"], 8)
        _require(_entry_kind(mode) == entry["type"], f"mode/type drift: {path_value}")
        _require(f"{stat.S_IMODE(mode):04o}" == entry["permissions_octal"], f"mode/permissions drift: {path_value}")
        for number in ("inode", "uid", "gid", "size"):
            _require(isinstance(entry.get(number), int) and entry[number] >= 0, f"invalid {number}: {path_value}")
        _require(
            any(root == "/" or path_value == root or path_value.startswith(root + "/") for root in roots),
            f"snapshot entry lies outside its roots: {path_value}",
        )
        attributes = entry.get("xattrs_b64")
        _require(isinstance(attributes, dict), f"missing xattrs: {path_value}")
        for name, encoded in attributes.items():
            _require(re.fullmatch(r"[A-Za-z0-9_.-]+", name) is not None, "invalid xattr name")
            _require(isinstance(encoded, str), f"invalid encoded xattr: {path_value} {name}")
            try:
                base64.b64decode(encoded, validate=True)
            except (TypeError, ValueError) as exc:
                raise MetadataError(f"invalid encoded xattr: {path_value} {name}") from exc
        if entry["type"] == "symlink":
            encoded_target = entry.get("symlink_target_b64")
            try:
                target = base64.b64decode(encoded_target, validate=True)
            except (TypeError, ValueError) as exc:
                raise MetadataError(f"invalid encoded symlink: {path_value}") from exc
            _require(len(target) == entry["size"], f"symlink size drift: {path_value}")
            if "symlink_target" in entry:
                try:
                    _require(entry["symlink_target"] == target.decode("utf-8"), f"symlink text drift: {path_value}")
                except UnicodeDecodeError as exc:
                    raise MetadataError(f"non-UTF-8 symlink may not have a text target: {path_value}") from exc
        paths.append(path_value)
    _require(paths == sorted(paths) and len(paths) == len(set(paths)), "snapshot paths are not sorted and unique")
    _require(all(root in paths for root in roots), "snapshot root entry is missing")
    _require(
        value.get("metadata_sha256") == compatctl.canonical_digest(entries),
        "snapshot metadata digest mismatch",
    )
    profile, _compatibility, _port, _pipeline, _summary = load_and_validate()
    expected_summary = _snapshot_summary(
        entries,
        profile["metadata"]["required_label_xattr"],
        profile["metadata"]["capability_xattr"],
    )
    _require(value.get("summary") == expected_summary, "snapshot summary drift")
    _require(expected_summary["selinux_labels"] > 0, "snapshot has no SELinux labels")
    return {
        "status": "verified",
        "snapshot": str(path),
        "snapshot_sha256": _sha256_file(path),
        "image": image,
        "roots": roots,
        "metadata_sha256": value["metadata_sha256"],
        "summary": expected_summary,
    }


def command_check(_profile: dict, _compatibility: dict, _summary: dict, args: argparse.Namespace) -> None:
    print(json.dumps(args.contract_summary, indent=2, sort_keys=True))


def command_snapshot(profile: dict, compatibility: dict, _summary: dict, args: argparse.Namespace) -> None:
    plan = source_plan(profile, args.id)
    _require(plan["mode"] == "snapshot", f"image is preserved byte-exact and must not be snapshotted: {args.id}")
    expected_images = {row["id"]: row for row in compatibility["images"]}
    image = args.image.absolute()
    try:
        image_identity = compatctl.verify_image(image, expected_images[args.id])
    except compatctl.CompatibilityError as exc:
        raise MetadataError(str(exc)) from exc
    output = args.output.absolute()
    if output.exists() or output.is_symlink():
        report = verify_snapshot(output)
        _require(report["image"]["id"] == args.id, "reused snapshot image id drift")
        _require(report["image"]["sha256"] == image_identity["sha256"], "reused snapshot image hash drift")
        _require(report["roots"] == plan["roots"], "reused snapshot roots drift")
        report["mode"] = "reused"
        print(json.dumps(report, indent=2, sort_keys=True))
        return
    entries = capture_entries(image, plan["roots"])
    snapshot = build_snapshot(
        args.id,
        image_identity,
        plan["purpose"],
        plan["roots"],
        entries,
        profile["metadata"]["required_label_xattr"],
        profile["metadata"]["capability_xattr"],
    )
    _atomic_report(output, snapshot)
    report = verify_snapshot(output)
    report["mode"] = "captured"
    print(json.dumps(report, indent=2, sort_keys=True))


def command_verify(_profile: dict, _compatibility: dict, _summary: dict, args: argparse.Namespace) -> None:
    print(json.dumps(verify_snapshot(args.snapshot.absolute()), indent=2, sort_keys=True))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    parser.add_argument("--compatibility-profile", type=Path, default=DEFAULT_COMPATIBILITY_PROFILE)
    parser.add_argument("--port-profile", type=Path, default=DEFAULT_PORT_PROFILE)
    parser.add_argument("--pipeline-profile", type=Path, default=DEFAULT_PIPELINE_PROFILE)
    subparsers = parser.add_subparsers(dest="command", required=True)

    check = subparsers.add_parser("check", help="validate the locked Case 5.1 metadata contract")
    check.set_defaults(handler=command_check)

    snapshot = subparsers.add_parser("snapshot", help="capture one locked ext4 metadata source")
    snapshot.add_argument("--id", required=True)
    snapshot.add_argument("--image", type=Path, required=True)
    snapshot.add_argument("--output", type=Path, required=True)
    snapshot.set_defaults(handler=command_snapshot)

    verify = subparsers.add_parser("verify", help="verify a completed metadata snapshot")
    verify.add_argument("snapshot", type=Path)
    verify.set_defaults(handler=command_verify)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        profile, compatibility, _port, _pipeline, summary = load_and_validate(
            args.profile,
            args.compatibility_profile,
            args.port_profile,
            args.pipeline_profile,
        )
        args.contract_summary = summary
        args.handler(profile, compatibility, summary, args)
    except MetadataError as exc:
        parser.exit(1, f"ERROR: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
