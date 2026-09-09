#!/usr/bin/env python3
"""Run the Case 5.1 local recovery pipeline as a durable, resumable job."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import traceback
from typing import Callable
from datetime import datetime, timezone


TOOLS_DIRECTORY = Path(__file__).resolve().parent
if str(TOOLS_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIRECTORY))

import buildctl  # noqa: E402
import compatctl  # noqa: E402
import metactl  # noqa: E402
import portctl  # noqa: E402


REPOSITORY_ROOT = TOOLS_DIRECTORY.parent.resolve()
SCRIPT_PATH = Path(__file__).resolve()
STATE_SCHEMA = "xos-lavender-case5-local-v1"
REPORT_SCHEMA = "xos-lavender-case5-checkpoint-v1"
PATH_PATTERN = re.compile(r"/[A-Za-z0-9._/+-]+")
STAGES = (
    "preflight",
    "development_key",
    "base_images",
    "donor_images",
    "case4_inputs",
    "development_root",
    "output_verification",
    "metadata_base_system",
    "metadata_donor_system",
    "metadata_donor_product",
    "metadata_donor_system_ext",
    "checkpoint",
)
TOOLING_FILES = (
    "config/case5.toml",
    "config/compatibility.toml",
    "config/pipeline.toml",
    "config/port.toml",
    "scripts/extract-case3-selection.sh",
    "scripts/extract-case4-roots.sh",
    "scripts/materialize-case4-images.sh",
    "tools/apksign.py",
    "tools/buildctl.py",
    "tools/case5ctl.py",
    "tools/compatctl.py",
    "tools/imagectl.py",
    "tools/metactl.py",
    "tools/portctl.py",
)


class Case5Error(RuntimeError):
    """The durable Case 5.1 runner encountered an unsafe or invalid state."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise Case5Error(message)


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _log(message: str) -> None:
    print(f"[{_now()}] {message}", flush=True)


def _safe_absolute(path: Path, label: str, *, must_exist: bool = False) -> Path:
    _require(path.is_absolute(), f"{label} must be absolute")
    _require(PATH_PATTERN.fullmatch(str(path)) is not None, f"{label} must be whitespace-free: {path}")
    _require(Path(os.path.normpath(str(path))) == path, f"{label} is not normalized: {path}")
    if must_exist:
        _require(path.is_dir() and not path.is_symlink(), f"{label} is not a regular directory: {path}")
        _require(path.resolve() == path, f"{label} contains a symbolic-link component: {path}")
    else:
        existing = path
        while not existing.exists() and existing != existing.parent:
            existing = existing.parent
        _require(existing.is_dir() and existing.resolve() == existing, f"unsafe parent for {label}: {existing}")
        _require(not path.exists() or (path.is_dir() and not path.is_symlink()), f"unsafe {label}: {path}")
    return path


def _outside_repository(path: Path) -> bool:
    try:
        path.relative_to(REPOSITORY_ROOT)
    except ValueError:
        return True
    return False


def default_data_directory(source_directory: Path, repository_root: Path = REPOSITORY_ROOT) -> Path:
    candidate = source_directory / "case5-local"
    try:
        candidate.relative_to(repository_root)
    except ValueError:
        return candidate
    return repository_root.parent / "xos-lavender-case5-local"


@dataclass(frozen=True)
class Layout:
    source: Path
    data: Path
    work: Path
    materialized: Path
    case4: Path
    private: Path
    key: Path
    reports: Path
    metadata: Path
    state_directory: Path
    state: Path
    lock: Path
    log: Path
    checkpoint: Path

    @property
    def output_root(self) -> Path:
        return self.case4 / "output" / "dev-root"

    @property
    def private_key(self) -> Path:
        return self.key / "platform-development.pem"

    @property
    def certificate(self) -> Path:
        return self.key / "platform-development.der"

    def image(self, identifier: str) -> Path:
        return self.materialized / "images" / f"{identifier}.img"

    def snapshot(self, identifier: str) -> Path:
        return self.metadata / f"{identifier}.json"


def resolve_layout(source: Path, data: Path | None = None, *, create: bool = False) -> Layout:
    source = _safe_absolute(source, "source directory", must_exist=True)
    data = data or default_data_directory(source)
    data = _safe_absolute(data, "data directory")
    _require(_outside_repository(data), f"Case 5 data must remain outside the repository: {data}")
    _require(data != source, "data directory may not replace the source directory")
    layout = Layout(
        source=source,
        data=data,
        work=data / "work",
        materialized=data / "work" / "materialized",
        case4=data / "work" / "case4",
        private=data / "private",
        key=data / "private" / "development-key",
        reports=data / "reports",
        metadata=data / "reports" / "metadata",
        state_directory=data / "state",
        state=data / "state" / "case5-1.json",
        lock=data / "state" / "case5-1.lock",
        log=data / "logs" / "case5-1.log",
        checkpoint=data / "reports" / "case5-1-checkpoint.json",
    )
    if create:
        for directory in (
            layout.data,
            layout.work,
            layout.private,
            layout.key,
            layout.reports,
            layout.metadata,
            layout.state_directory,
            layout.log.parent,
        ):
            _require(not directory.is_symlink(), f"refusing symbolic-link directory: {directory}")
            directory.mkdir(parents=True, exist_ok=True)
        layout.private.chmod(0o700)
        layout.key.chmod(0o700)
    return layout


def _atomic_json(path: Path, value: dict, *, mode: int = 0o644) -> None:
    _require(not path.is_symlink(), f"refusing symbolic-link JSON output: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".partial", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(value, output, indent=2, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        temporary.chmod(mode)
        os.replace(temporary, path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def _read_json(path: Path, label: str) -> dict:
    _require(path.is_file() and not path.is_symlink(), f"{label} is not a regular file: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise Case5Error(f"cannot read {label} {path}: {exc}") from exc
    _require(isinstance(value, dict), f"{label} is not a JSON object: {path}")
    return value


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tooling_identity() -> dict:
    files: list[dict] = []
    for relative in TOOLING_FILES:
        path = REPOSITORY_ROOT / relative
        _require(path.is_file() and not path.is_symlink(), f"tooling file is missing: {relative}")
        files.append({"path": relative, "sha256": _sha256_file(path)})
    return {"sha256": compatctl.canonical_digest(files), "files": files}


def _state_paths(layout: Layout) -> dict:
    return {
        "source": str(layout.source),
        "data": str(layout.data),
        "materialized": str(layout.materialized),
        "case4": str(layout.case4),
        "key": str(layout.key),
        "output_root": str(layout.output_root),
        "checkpoint": str(layout.checkpoint),
        "log": str(layout.log),
    }


def initial_state(layout: Layout, contract: dict) -> dict:
    now = _now()
    identity = tooling_identity()
    return {
        "schema": STATE_SCHEMA,
        "case": "5.1",
        "status": "initialized",
        "active_stage": None,
        "completed_stages": [],
        "stage_results": {},
        "attempts": 0,
        "pid": None,
        "paths": _state_paths(layout),
        "contract_sha256": contract["profile_sha256"],
        "tooling_history": [identity["sha256"]],
        "created_at": now,
        "updated_at": now,
    }


def load_state(layout: Layout, contract: dict, *, allow_missing: bool = False) -> dict | None:
    if not layout.state.exists() and not layout.state.is_symlink():
        if allow_missing:
            return None
        raise Case5Error(f"Case 5.1 state does not exist: {layout.state}")
    state = _read_json(layout.state, "Case 5.1 state")
    _require(state.get("schema") == STATE_SCHEMA and state.get("case") == "5.1", "state schema drift")
    _require(state.get("contract_sha256") == contract["profile_sha256"], "state contract drift")
    _require(state.get("paths") == _state_paths(layout), "state path drift")
    _require(
        state.get("status") in {"initialized", "starting", "queued", "running", "failed", "complete"},
        "invalid state status",
    )
    completed = state.get("completed_stages")
    _require(isinstance(completed, list) and len(completed) == len(set(completed)), "invalid completed stages")
    _require(all(stage in STAGES for stage in completed), "unknown completed stage")
    expected_prefix = list(STAGES[: len(completed)])
    _require(completed == expected_prefix, "completed stages are out of order")
    results = state.get("stage_results")
    _require(isinstance(results, dict) and set(results) == set(completed), "stage results do not match completed stages")
    active = state.get("active_stage")
    _require(active is None or (active in STAGES and active not in completed), "invalid active stage")
    _require(isinstance(state.get("attempts"), int) and state["attempts"] >= 0, "invalid attempt count")
    return state


def _process_is_live(state: dict | None) -> bool:
    if not state or not isinstance(state.get("pid"), int) or state["pid"] <= 0:
        return False
    process = Path("/proc") / str(state["pid"])
    command_line = process / "cmdline"
    try:
        command = command_line.read_bytes()
    except OSError:
        return False
    data = state.get("paths", {}).get("data")
    return (
        isinstance(data, str)
        and b"case5ctl.py" in command
        and b"run" in command
        and os.fsencode(data) in command
    )


def _record_tooling(state: dict) -> dict:
    identity = tooling_identity()
    history = state.setdefault("tooling_history", [])
    if identity["sha256"] not in history:
        history.append(identity["sha256"])
    state["current_tooling_sha256"] = identity["sha256"]
    return identity


def execute_stage(
    layout: Layout,
    state: dict,
    stage: str,
    action: Callable[[], dict],
) -> dict:
    _require(stage in STAGES, f"unknown stage: {stage}")
    completed: list[str] = state["completed_stages"]
    if stage in completed:
        return state["stage_results"][stage]
    expected_index = len(completed)
    _require(expected_index < len(STAGES), "all Case 5.1 stages are already complete")
    _require(STAGES[expected_index] == stage, f"stage order violation: expected {STAGES[expected_index]}, got {stage}")
    state["status"] = "running"
    state["active_stage"] = stage
    state["updated_at"] = _now()
    state.pop("failure", None)
    _atomic_json(layout.state, state)
    _log(f"START stage={stage}")
    try:
        result = action()
        _require(isinstance(result, dict), f"stage returned no structured result: {stage}")
    except Exception as exc:
        state["status"] = "failed"
        state["failure"] = {"stage": stage, "error": str(exc), "at": _now()}
        state["updated_at"] = _now()
        _atomic_json(layout.state, state)
        _log(f"FAILED stage={stage} error={exc}")
        raise
    state["stage_results"][stage] = result
    state["completed_stages"].append(stage)
    state["active_stage"] = None
    state["updated_at"] = _now()
    _atomic_json(layout.state, state)
    _log(f"COMPLETE stage={stage}")
    return result


def _run(command: list[str], *, capture_json: bool = False) -> dict | None:
    _log("RUN " + shlex.join(command))
    environment = dict(os.environ)
    environment["LC_ALL"] = "C"
    if capture_json:
        process = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=environment,
            check=False,
        )
        if process.stderr:
            print(process.stderr, file=sys.stderr, end="", flush=True)
        if process.stdout:
            print(process.stdout, end="", flush=True)
        _require(process.returncode == 0, f"command failed with exit code {process.returncode}: {command[0]}")
        try:
            value = json.loads(process.stdout)
        except json.JSONDecodeError as exc:
            raise Case5Error(f"command did not return JSON: {command[0]}") from exc
        _require(isinstance(value, dict), f"command returned invalid JSON: {command[0]}")
        return value
    process = subprocess.run(command, env=environment, check=False)
    _require(process.returncode == 0, f"command failed with exit code {process.returncode}: {command[0]}")
    return None


def _required_commands() -> list[str]:
    return [
        "awk",
        "bash",
        "debugfs",
        "df",
        "dirname",
        "e2fsck",
        "find",
        "flock",
        "mkdir",
        "mktemp",
        "mv",
        "openssl",
        "python3",
        "readlink",
        "rm",
        "rmdir",
        "sha256sum",
        "sort",
        "stat",
        "sync",
        "tail",
        "tr",
        "wc",
    ]


def runtime_space_check(layout: Layout, profile: dict, state: dict) -> dict:
    completed = set(state["completed_stages"])
    if "donor_images" not in completed:
        phase = "image-materialization"
        required = profile["local"]["minimum_fresh_free_bytes"]
    elif "case4_inputs" not in completed:
        phase = "root-extraction"
        required = 6 * 1024**3
    elif "development_root" not in completed:
        phase = "development-build"
        required = 4 * 1024**3
    elif "metadata_donor_system_ext" not in completed:
        phase = "verification-and-metadata"
        required = 1024**3
    else:
        phase = "checkpoint"
        required = 512 * 1024**2
    free_bytes = shutil.disk_usage(layout.data).free
    _require(
        free_bytes >= required,
        f"insufficient free space for {phase}: need {required} bytes, have {free_bytes}",
    )
    return {"status": "verified", "phase": phase, "free_bytes": free_bytes, "required_free_bytes": required}


def preflight(layout: Layout, profile: dict, port: dict, state: dict) -> dict:
    missing = [name for name in _required_commands() if shutil.which(name) is None]
    _require(not missing, "required commands are missing: " + ", ".join(missing))
    sources: list[dict] = []
    for role in ("base", "donor"):
        expected = port[role]
        path = layout.source / expected["filename"]
        _require(path.is_file() and not path.is_symlink(), f"source ZIP is missing or unsafe: {path}")
        file_stat = path.stat()
        _require(file_stat.st_size == expected["size"], f"source ZIP size mismatch: {path.name}")
        sources.append(
            {
                "role": role,
                "path": str(path),
                "filename": path.name,
                "size": file_stat.st_size,
                "expected_sha256": expected["sha256"],
            }
        )
    space = runtime_space_check(layout, profile, state)
    return {
        "status": "verified",
        "sources": sources,
        "space": space,
        "commands": len(_required_commands()),
    }


def initialize_key(layout: Layout, profile: dict) -> dict:
    layout.private.chmod(int(profile["signing"]["private_directory_mode"], 8))
    layout.key.chmod(int(profile["signing"]["private_directory_mode"], 8))
    if layout.private_key.exists() and not layout.private_key.is_symlink():
        layout.private_key.chmod(int(profile["signing"]["private_key_mode"], 8))
    report = _run(
        [
            sys.executable,
            str(REPOSITORY_ROOT / "tools" / "buildctl.py"),
            "init-dev-key",
            "--key-dir",
            str(layout.key),
        ],
        capture_json=True,
    )
    assert report is not None
    _require(stat.S_IMODE(layout.key.stat().st_mode) == 0o700, "development key directory mode drift")
    _require(stat.S_IMODE(layout.private_key.stat().st_mode) == 0o600, "development private-key mode drift")
    _require(report.get("private_key_committed") is False, "private-key boundary drift")
    _atomic_json(layout.reports / "development-key.json", report, mode=0o600)
    return {
        "status": "verified",
        "mode": report["mode"],
        "certificate_sha256": report["certificate_sha256"],
        "public_key_sha256": report["public_key_sha256"],
        "private_key_mode": "0600",
        "private_key_committed": False,
    }


def _source_identity(layout: Layout, port: dict, role: str) -> dict:
    expected = port[role]
    source = layout.source / expected["filename"]
    manifest_path = layout.materialized / "extracted" / role / "extraction-manifest.json"
    verified_by = "extraction-manifest"
    if manifest_path.is_file() and not manifest_path.is_symlink():
        manifest = _read_json(manifest_path, f"{role} extraction manifest")
        _require(manifest.get("source_filename") == expected["filename"], f"{role} source filename drift")
        _require(manifest.get("source_size") == expected["size"], f"{role} source size drift")
        _require(manifest.get("source_sha256") == expected["sha256"], f"{role} source SHA-256 drift")
    else:
        _run(
            [
                sys.executable,
                str(REPOSITORY_ROOT / "tools" / "portctl.py"),
                "verify-source",
                role,
                str(source),
            ]
        )
        verified_by = "direct-source-verification"
    _require(source.is_file() and not source.is_symlink(), f"source ZIP was not preserved: {source}")
    source_stat = source.stat()
    _require(source_stat.st_size == expected["size"], f"preserved source ZIP size drift: {source.name}")
    return {
        "status": "verified",
        "role": role,
        "filename": expected["filename"],
        "size": expected["size"],
        "sha256": expected["sha256"],
        "path": str(source),
        "preserved": True,
        "verified_by": verified_by,
        "stat": {
            "device": source_stat.st_dev,
            "inode": source_stat.st_ino,
            "mtime_ns": source_stat.st_mtime_ns,
        },
    }


def _e2fsck(layout: Layout, identifier: str) -> None:
    image = layout.image(identifier)
    log = layout.reports / f"e2fsck-{identifier}.log"
    _require(not log.is_symlink(), f"refusing symbolic-link e2fsck log: {log}")
    with log.open("wb") as output:
        process = subprocess.run(["e2fsck", "-fn", str(image)], stdout=output, stderr=subprocess.STDOUT, check=False)
    _require(process.returncode == 0, f"read-only e2fsck failed for {identifier}; see {log}")


def _verify_existing_images(layout: Layout, compatibility: dict, identifiers: list[str]) -> list[dict]:
    expected = {row["id"]: row for row in compatibility["images"]}
    reports: list[dict] = []
    for identifier in identifiers:
        image = layout.image(identifier)
        _require(image.is_file() and not image.is_symlink(), f"image is missing or unsafe: {image}")
        _e2fsck(layout, identifier)
        try:
            reports.append(compatctl.verify_image(image, expected[identifier]))
        except compatctl.CompatibilityError as exc:
            raise Case5Error(str(exc)) from exc
    return reports


def materialize_images(layout: Layout, compatibility: dict, port: dict, role: str) -> dict:
    identifiers = ["base_system", "base_vendor"] if role == "base" else [
        "donor_system",
        "donor_product",
        "donor_system_ext",
    ]
    reused = all(layout.image(identifier).is_file() and not layout.image(identifier).is_symlink() for identifier in identifiers)
    if reused:
        _log(f"REUSE candidate images role={role}; validating exact hashes and e2fsck")
        image_reports = _verify_existing_images(layout, compatibility, identifiers)
    else:
        source = layout.source / port[role]["filename"]
        _run(
            [
                str(REPOSITORY_ROOT / "scripts" / "materialize-case4-images.sh"),
                role,
                str(source),
                str(layout.materialized),
            ]
        )
        image_reports = [
            {
                key: row[key]
                for key in ("id", "size", "sha256", "block_count", "free_blocks", "block_size")
            }
            for row in compatibility["images"]
            if row["id"] in identifiers
        ]
    return {
        "status": "verified",
        "mode": "reused" if reused else "materialized",
        "source": _source_identity(layout, port, role),
        "images": image_reports,
    }


def _verify_all_images(layout: Layout, compatibility: dict) -> dict:
    report_path = layout.materialized / "reports" / "generated" / "images.json"
    if not report_path.is_file() or report_path.is_symlink():
        _run(
            [
                sys.executable,
                str(REPOSITORY_ROOT / "tools" / "compatctl.py"),
                "verify-images",
                "--base-system",
                str(layout.image("base_system")),
                "--base-vendor",
                str(layout.image("base_vendor")),
                "--donor-system",
                str(layout.image("donor_system")),
                "--donor-product",
                str(layout.image("donor_product")),
                "--donor-system-ext",
                str(layout.image("donor_system_ext")),
                "--report",
                str(report_path),
            ]
        )
    report = _read_json(report_path, "five-image report")
    _require(report.get("status") == "verified", "five-image report is not verified")
    expected = {row["id"]: row for row in compatibility["images"]}
    actual = {row.get("id"): row for row in report.get("images", [])}
    _require(set(actual) == set(expected), "five-image report set drift")
    for identifier, row in expected.items():
        for field in ("size", "sha256", "block_count", "free_blocks", "block_size"):
            _require(actual[identifier].get(field) == row[field], f"five-image report drift: {identifier} {field}")
    return report


def extract_case4_inputs(layout: Layout) -> dict:
    _run(
        [
            str(REPOSITORY_ROOT / "scripts" / "extract-case4-roots.sh"),
            str(layout.materialized),
            str(layout.case4),
        ]
    )
    report_path = layout.case4 / "reports" / "generated" / "case4-inputs.json"
    report = _read_json(report_path, "Case 4 input report")
    _require(report.get("status") == "verified", "Case 4 input gate did not pass")
    return {
        "status": "verified",
        "report": str(report_path),
        "input_apks": sum(row["apk_count"] for row in report["inventories"].values()),
        "selected_packages": len(report["selected_packages"]),
        "runtime_dependencies": len(report["runtime_dependencies"]),
        "classpath_providers": len(report["classpath_providers"]),
    }


def build_development_root(layout: Layout) -> dict:
    report_path = layout.reports / "development-root.json"
    _run(
        [
            sys.executable,
            str(REPOSITORY_ROOT / "tools" / "buildctl.py"),
            "build",
            "--base-root",
            str(layout.case4 / "roots" / "base"),
            "--donor-system-root",
            str(layout.case4 / "roots" / "donor-system"),
            "--donor-product-root",
            str(layout.case4 / "selection" / "donor" / "product"),
            "--donor-system-ext-root",
            str(layout.case4 / "selection" / "donor" / "system_ext"),
            "--output-root",
            str(layout.output_root),
            "--development-key",
            str(layout.private_key),
            "--development-cert",
            str(layout.certificate),
            "--report",
            str(report_path),
        ]
    )
    report = _read_json(report_path, "development-root build report")
    _require(report.get("status") == "verified", "development root build did not pass")
    return {
        "status": "verified",
        "mode": report["mode"],
        "report": str(report_path),
        "certificate_sha256": report["development_key"]["certificate_sha256"],
        "tree_manifest": report["output"]["tree_manifest"],
    }


def verify_development_root(layout: Layout) -> dict:
    report_path = layout.reports / "development-root-verified.json"
    _run(
        [
            sys.executable,
            str(REPOSITORY_ROOT / "tools" / "buildctl.py"),
            "verify-output",
            "--output-root",
            str(layout.output_root),
            "--development-cert",
            str(layout.certificate),
            "--report",
            str(report_path),
        ]
    )
    report = _read_json(report_path, "development-root verification report")
    _require(report.get("status") == "verified", "development-root verification did not pass")
    return {
        "status": "verified",
        "report": str(report_path),
        "certificate_sha256": report["development_certificate_sha256"],
        "apk_inventory": report["apk_inventory"],
        "tree_manifest": report["tree_manifest"],
    }


def capture_metadata(layout: Layout, identifier: str) -> dict:
    output = layout.snapshot(identifier)
    _run(
        [
            sys.executable,
            str(REPOSITORY_ROOT / "tools" / "metactl.py"),
            "snapshot",
            "--id",
            identifier,
            "--image",
            str(layout.image(identifier)),
            "--output",
            str(output),
        ]
    )
    try:
        report = metactl.verify_snapshot(output)
    except metactl.MetadataError as exc:
        raise Case5Error(str(exc)) from exc
    return {
        "status": "verified",
        "snapshot": str(output),
        "snapshot_sha256": report["snapshot_sha256"],
        "image_sha256": report["image"]["sha256"],
        "metadata_sha256": report["metadata_sha256"],
        "roots": report["roots"],
        "summary": report["summary"],
    }


def _validate_source_result(value: dict, port: dict, role: str) -> None:
    expected = port[role]
    _require(value.get("status") == "verified" and value.get("preserved") is True, f"{role} source not preserved")
    for field in ("filename", "size", "sha256"):
        _require(value.get(field) == expected[field], f"{role} source result drift: {field}")


def create_checkpoint(
    layout: Layout,
    profile: dict,
    compatibility: dict,
    port: dict,
    state: dict,
    identity: dict,
) -> dict:
    if layout.checkpoint.exists() or layout.checkpoint.is_symlink():
        return verify_checkpoint(layout, profile, compatibility, port)
    image_report = _verify_all_images(layout, compatibility)
    expected_images = {row["id"]: row for row in compatibility["images"]}
    try:
        retained_vendor = compatctl.verify_image(
            layout.image("base_vendor"),
            expected_images["base_vendor"],
        )
    except compatctl.CompatibilityError as exc:
        raise Case5Error(str(exc)) from exc
    build_report = _read_json(layout.reports / "development-root-verified.json", "output verification report")
    key_report = _read_json(layout.reports / "development-key.json", "development key report")
    try:
        verified_key = buildctl.apksign.verify_key_pair(layout.private_key, layout.certificate)
    except buildctl.apksign.ApkSignError as exc:
        raise Case5Error(str(exc)) from exc
    _require(verified_key["certificate_sha256"] == key_report["certificate_sha256"], "development key report drift")
    _require(stat.S_IMODE(layout.private_key.stat().st_mode) == 0o600, "private key is not mode 0600")

    base_source = state["stage_results"]["base_images"]["source"]
    donor_source = state["stage_results"]["donor_images"]["source"]
    _validate_source_result(base_source, port, "base")
    _validate_source_result(donor_source, port, "donor")

    snapshots: list[dict] = []
    for identifier in ("base_system", "donor_system", "donor_product", "donor_system_ext"):
        result = state["stage_results"][f"metadata_{identifier}"]
        try:
            verified = metactl.verify_snapshot(Path(result["snapshot"]))
        except metactl.MetadataError as exc:
            raise Case5Error(str(exc)) from exc
        _require(verified["snapshot_sha256"] == result["snapshot_sha256"], f"snapshot drift: {identifier}")
        snapshots.append(
            {
                "id": identifier,
                "path": result["snapshot"],
                "snapshot_sha256": verified["snapshot_sha256"],
                "image_sha256": verified["image"]["sha256"],
                "metadata_sha256": verified["metadata_sha256"],
                "roots": verified["roots"],
                "summary": verified["summary"],
            }
        )

    checkpoint = {
        "schema": REPORT_SCHEMA,
        "status": "verified",
        "case": "5.1",
        "generated_at": _now(),
        "pipeline_profile_sha256": profile["project"]["pipeline_profile_sha256"],
        "case5_profile_sha256": metactl.LOCKED_PROFILE_SHA256,
        "tooling": identity,
        "paths": {
            "data": str(layout.data),
            "state": str(layout.state),
            "log": str(layout.log),
            "development_root": str(layout.output_root),
        },
        "source_archives": [base_source, donor_source],
        "images": image_report["images"],
        "development_signing": {
            "mode": "project-development",
            "certificate_sha256": verified_key["certificate_sha256"],
            "public_key_sha256": verified_key["public_key_sha256"],
            "private_key_mode": "0600",
            "private_key_committed": False,
            "production_key": False,
        },
        "development_root": {
            "status": build_report["status"],
            "apk_inventory": build_report["apk_inventory"],
            "preopt_residue": build_report["preopt_residue"],
            "tree_manifest": build_report["tree_manifest"],
        },
        "metadata": {
            "schema": profile["metadata"]["schema"],
            "snapshots": snapshots,
            "preserved_image": {
                "id": "base_vendor",
                "sha256": retained_vendor["sha256"],
                "reason": "lavender vendor is retained byte-exact; no metadata reconstruction is permitted",
            },
        },
        "guards": {
            "source_archives_preserved": True,
            "development_signing_only": True,
            "production_signing": False,
            "image_repack": False,
            "automatic_flash": False,
        },
        "boundary": {
            "completed": "Case 5.1 durable local rebuild and source metadata capture",
            "next_allowed": "Case 5.2 metadata reconstruction and system-image repack",
            "device_flash_requires_manual_approval": True,
        },
    }
    _atomic_json(layout.checkpoint, checkpoint)
    return verify_checkpoint(layout, profile, compatibility, port)


def verify_checkpoint(layout: Layout, profile: dict, compatibility: dict, port: dict) -> dict:
    checkpoint = _read_json(layout.checkpoint, "Case 5.1 checkpoint")
    _require(checkpoint.get("schema") == REPORT_SCHEMA and checkpoint.get("status") == "verified", "checkpoint drift")
    _require(checkpoint.get("case") == "5.1", "checkpoint case drift")
    _require(
        checkpoint.get("pipeline_profile_sha256") == profile["project"]["pipeline_profile_sha256"],
        "checkpoint pipeline-profile drift",
    )
    _require(checkpoint.get("case5_profile_sha256") == metactl.LOCKED_PROFILE_SHA256, "checkpoint Case 5 profile drift")
    guards = checkpoint.get("guards", {})
    _require(guards == {
        "source_archives_preserved": True,
        "development_signing_only": True,
        "production_signing": False,
        "image_repack": False,
        "automatic_flash": False,
    }, "checkpoint guard drift")
    source_archives = checkpoint.get("source_archives")
    _require(isinstance(source_archives, list) and len(source_archives) == 2, "checkpoint source archive count drift")
    for role, value in zip(("base", "donor"), source_archives, strict=True):
        _validate_source_result(value, port, role)
        source = Path(value["path"])
        _require(source.is_file() and not source.is_symlink() and source.stat().st_size == value["size"], f"source drift: {role}")
        source_stat = source.stat()
        expected_stat = value.get("stat", {})
        actual_stat = {
            "device": source_stat.st_dev,
            "inode": source_stat.st_ino,
            "mtime_ns": source_stat.st_mtime_ns,
        }
        if expected_stat != actual_stat:
            try:
                portctl.verify_source(source, port[role])
            except portctl.PortError as exc:
                raise Case5Error(f"source file identity drift: {role}: {exc}") from exc
    expected_images = {row["id"]: row for row in compatibility["images"]}
    actual_images = {row.get("id"): row for row in checkpoint.get("images", [])}
    _require(set(actual_images) == set(expected_images), "checkpoint image set drift")
    for identifier, expected in expected_images.items():
        for field in ("size", "sha256", "block_count", "free_blocks", "block_size"):
            _require(actual_images[identifier].get(field) == expected[field], f"checkpoint image drift: {identifier} {field}")
    preserved = checkpoint.get("metadata", {}).get("preserved_image", {})
    _require(
        preserved.get("id") == "base_vendor" and preserved.get("sha256") == expected_images["base_vendor"]["sha256"],
        "checkpoint preserved-vendor drift",
    )
    signing = checkpoint.get("development_signing", {})
    _require(signing.get("production_key") is False and signing.get("private_key_committed") is False, "signing boundary drift")
    try:
        key = buildctl.apksign.verify_key_pair(layout.private_key, layout.certificate)
    except buildctl.apksign.ApkSignError as exc:
        raise Case5Error(str(exc)) from exc
    _require(key["certificate_sha256"] == signing.get("certificate_sha256"), "checkpoint certificate drift")
    snapshots = checkpoint.get("metadata", {}).get("snapshots", [])
    _require(len(snapshots) == 4, "checkpoint metadata snapshot count drift")
    for snapshot in snapshots:
        try:
            verified = metactl.verify_snapshot(Path(snapshot["path"]))
        except metactl.MetadataError as exc:
            raise Case5Error(str(exc)) from exc
        for field in ("snapshot_sha256", "metadata_sha256"):
            _require(snapshot.get(field) == verified[field], f"checkpoint snapshot drift: {snapshot.get('id')} {field}")
    return {
        "status": "verified",
        "case": "5.1",
        "checkpoint": str(layout.checkpoint),
        "checkpoint_sha256": _sha256_file(layout.checkpoint),
        "development_certificate_sha256": signing["certificate_sha256"],
        "tree_manifest": checkpoint["development_root"]["tree_manifest"],
        "metadata_snapshots": len(snapshots),
        "next_allowed": checkpoint["boundary"]["next_allowed"],
    }


def run_pipeline(layout: Layout, *, wait_lock: bool = False) -> dict:
    profile, compatibility, port, _pipeline, contract = metactl.load_and_validate()
    layout = resolve_layout(layout.source, layout.data, create=True)
    _require(not layout.lock.is_symlink(), f"refusing symbolic-link run lock: {layout.lock}")
    with layout.lock.open("a+", encoding="utf-8") as lock:
        operation = fcntl.LOCK_EX if wait_lock else fcntl.LOCK_EX | fcntl.LOCK_NB
        try:
            fcntl.flock(lock.fileno(), operation)
        except BlockingIOError as exc:
            raise Case5Error(f"another Case 5.1 worker owns {layout.lock}") from exc
        state = load_state(layout, contract, allow_missing=True) or initial_state(layout, contract)
        identity = _record_tooling(state)
        state["attempts"] += 1
        state["pid"] = os.getpid()
        state["status"] = "running"
        state["updated_at"] = _now()
        _atomic_json(layout.state, state)
        _log(f"Case 5.1 attempt={state['attempts']} data={layout.data}")
        try:
            state["last_space_check"] = runtime_space_check(layout, profile, state)
            state["updated_at"] = _now()
            _atomic_json(layout.state, state)
            if "preflight" not in state["completed_stages"]:
                execute_stage(layout, state, "preflight", lambda: preflight(layout, profile, port, state))
            if "development_key" not in state["completed_stages"]:
                execute_stage(layout, state, "development_key", lambda: initialize_key(layout, profile))
            if "base_images" not in state["completed_stages"]:
                execute_stage(
                    layout,
                    state,
                    "base_images",
                    lambda: materialize_images(layout, compatibility, port, "base"),
                )
            if "donor_images" not in state["completed_stages"]:
                execute_stage(
                    layout,
                    state,
                    "donor_images",
                    lambda: materialize_images(layout, compatibility, port, "donor"),
                )
            if "case4_inputs" not in state["completed_stages"]:
                execute_stage(layout, state, "case4_inputs", lambda: extract_case4_inputs(layout))
            if "development_root" not in state["completed_stages"]:
                execute_stage(layout, state, "development_root", lambda: build_development_root(layout))
            if "output_verification" not in state["completed_stages"]:
                execute_stage(layout, state, "output_verification", lambda: verify_development_root(layout))
            for identifier in ("base_system", "donor_system", "donor_product", "donor_system_ext"):
                stage = f"metadata_{identifier}"
                if stage not in state["completed_stages"]:
                    execute_stage(layout, state, stage, lambda identifier=identifier: capture_metadata(layout, identifier))
            if "checkpoint" not in state["completed_stages"]:
                execute_stage(
                    layout,
                    state,
                    "checkpoint",
                    lambda: create_checkpoint(layout, profile, compatibility, port, state, identity),
                )
            state["status"] = "complete"
            state["active_stage"] = None
            state["pid"] = None
            state["updated_at"] = _now()
            _atomic_json(layout.state, state)
            report = verify_checkpoint(layout, profile, compatibility, port)
            _log(f"VERIFIED checkpoint={layout.checkpoint}")
            return report
        except Exception as exc:
            state["status"] = "failed"
            state["pid"] = None
            state["failure"] = {
                "stage": state.get("active_stage"),
                "error": str(exc),
                "at": _now(),
            }
            state["updated_at"] = _now()
            _atomic_json(layout.state, state)
            raise


def start(layout: Layout) -> dict:
    profile, _compatibility, _port, _pipeline, contract = metactl.load_and_validate()
    layout = resolve_layout(layout.source, layout.data, create=True)
    _require(not layout.lock.is_symlink(), f"refusing symbolic-link run lock: {layout.lock}")
    with layout.lock.open("a+", encoding="utf-8") as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise Case5Error(f"Case 5.1 is already starting or running: {layout.lock}") from exc
        state = load_state(layout, contract, allow_missing=True)
        if state and _process_is_live(state):
            return {
                "status": "running",
                "pid": state["pid"],
                "active_stage": state.get("active_stage"),
                "state": str(layout.state),
                "log": str(layout.log),
            }
        if state and state.get("status") == "complete":
            return verify_checkpoint(layout, profile, _compatibility, _port)
        state = state or initial_state(layout, contract)
        state["status"] = "starting"
        state["active_stage"] = None
        state["pid"] = None
        state["updated_at"] = _now()
        _atomic_json(layout.state, state)
        _require(not layout.log.is_symlink(), f"refusing symbolic-link log: {layout.log}")
        with layout.log.open("ab") as log_output:
            log_output.write(f"\n[{_now()}] LAUNCH Case 5.1\n".encode())
            log_output.flush()
            command = [
                sys.executable,
                str(SCRIPT_PATH),
                "run",
                str(layout.source),
                "--data-dir",
                str(layout.data),
                "--wait-lock",
            ]
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=log_output,
                stderr=subprocess.STDOUT,
                close_fds=True,
                start_new_session=True,
            )
        state["status"] = "queued"
        state["pid"] = process.pid
        state["updated_at"] = _now()
        _atomic_json(layout.state, state)
    return {
        "status": "started",
        "pid": process.pid,
        "data": str(layout.data),
        "state": str(layout.state),
        "log": str(layout.log),
        "checkpoint": str(layout.checkpoint),
        "source_archives_consumed": False,
        "production_signing": False,
        "automatic_flash": False,
    }


def status(layout: Layout, contract: dict, lines: int) -> dict:
    state = load_state(layout, contract, allow_missing=True)
    if state is None:
        return {"status": "not-started", "data": str(layout.data)}
    result = {
        "status": state["status"],
        "pid": state.get("pid"),
        "process_live": _process_is_live(state),
        "active_stage": state.get("active_stage"),
        "completed_stages": state["completed_stages"],
        "next_stage": STAGES[len(state["completed_stages"])] if len(state["completed_stages"]) < len(STAGES) else None,
        "attempts": state["attempts"],
        "state": str(layout.state),
        "log": str(layout.log),
        "checkpoint": str(layout.checkpoint) if layout.checkpoint.exists() else None,
    }
    if state.get("failure"):
        result["failure"] = state["failure"]
    if lines and layout.log.is_file() and not layout.log.is_symlink():
        result["log_tail"] = layout.log.read_text(encoding="utf-8", errors="replace").splitlines()[-lines:]
    return result


def _layout_from_args(args: argparse.Namespace, *, create: bool = False) -> Layout:
    source = args.source_dir.absolute()
    data = args.data_dir.absolute() if args.data_dir else None
    return resolve_layout(source, data, create=create)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("check", help="validate the Case 5.1 local-runner contract")

    for name, help_text in (
        ("start", "start or resume Case 5.1 as a detached local job"),
        ("run", "run or resume Case 5.1 in the foreground"),
        ("status", "show durable Case 5.1 state and recent log lines"),
        ("verify", "verify an existing Case 5.1 checkpoint"),
    ):
        command = subparsers.add_parser(name, help=help_text)
        command.add_argument("source_dir", type=Path)
        command.add_argument("--data-dir", type=Path)
        if name == "run":
            command.add_argument("--wait-lock", action="store_true", help=argparse.SUPPRESS)
        if name == "status":
            command.add_argument("--lines", type=int, default=60)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        profile, compatibility, port, _pipeline, contract = metactl.load_and_validate()
        if args.command == "check":
            print(
                json.dumps(
                    {
                        "status": "verified",
                        "case": "5.1",
                        "profile_sha256": contract["profile_sha256"],
                        "stages": list(STAGES),
                        "detached": True,
                        "resumable": True,
                        "source_archives_consumed": False,
                        "production_signing": False,
                        "repack": False,
                        "automatic_flash": False,
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0
        layout = _layout_from_args(args, create=args.command in {"start", "run"})
        if args.command == "start":
            result = start(layout)
        elif args.command == "run":
            result = run_pipeline(layout, wait_lock=args.wait_lock)
        elif args.command == "status":
            _require(0 <= args.lines <= 200, "status --lines must be between 0 and 200")
            result = status(layout, contract, args.lines)
        else:
            result = verify_checkpoint(layout, profile, compatibility, port)
        print(json.dumps(result, indent=2, sort_keys=True))
    except (Case5Error, metactl.MetadataError) as exc:
        if args.command == "run":
            traceback.print_exc()
        parser.exit(1, f"ERROR: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
