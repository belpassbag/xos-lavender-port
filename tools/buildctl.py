#!/usr/bin/env python3
"""Plan and build the locked Case 4 XOS core development tree."""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import fcntl
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
import xml.etree.ElementTree as ElementTree
import zipfile


TOOLS_DIRECTORY = Path(__file__).resolve().parent
if str(TOOLS_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIRECTORY))

import compatctl  # noqa: E402
import apksign  # noqa: E402


REPOSITORY_ROOT = TOOLS_DIRECTORY.parent
DEFAULT_PROFILE = REPOSITORY_ROOT / "config" / "pipeline.toml"
DEFAULT_COMPATIBILITY_PROFILE = REPOSITORY_ROOT / "config" / "compatibility.toml"
DEFAULT_PORT_PROFILE = REPOSITORY_ROOT / "config" / "port.toml"
LOCKED_PIPELINE_SHA256 = "6cffdd3beda43710d71d40e59c08a38c2fcf127c34307353c8b28237d012bf5a"
DEVELOPMENT_KEY_NAME = "platform-development.pem"
DEVELOPMENT_CERTIFICATE_NAME = "platform-development.der"
PRIVAPP_OUTPUT_PATH = "/system/system_ext/etc/permissions/privapp-permissions-xos-lavender.xml"
LOCKED_REMOVALS = (
    {
        "path": "/system/priv-app/SecondaryDisplayLauncher/SecondaryDisplayLauncher.apk",
        "sha256": "4d1879ddccfceb56e726878cb58bea2c0b69719d33a02bfe14ec6b868274d325",
        "certificate_sha256": "a7e2e584fd1e865551aeca7a4110d8b9c0ba9b1fe6c3b7807d564a45557a5e71",
        "package": "com.android.launcher3",
    },
)
PREOPT_SUFFIXES = (".art", ".odex", ".vdex")
PHASES = ("initializing", "staged", "transplanted", "patched", "signed", "complete")
EXPECTED_INPUT_APKS = 311
EXPECTED_OUTPUT_APKS = 227
EXPECTED_DEVELOPMENT_APKS = 90
EXPECTED_STANDALONE_APKS = 137
EXPECTED_SHARED_UID_GROUPS = 11


class BuildError(RuntimeError):
    """The Case 4 policy or an input tree is invalid."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise BuildError(message)


def _read_toml(path: Path) -> dict:
    if path.is_symlink() or not path.is_file():
        raise BuildError(f"profile is not a regular file: {path}")
    try:
        with path.open("rb") as source:
            return tomllib.load(source)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise BuildError(f"cannot read profile {path}: {exc}") from exc


def _locked_path(value: object, label: str) -> str:
    _require(isinstance(value, str) and value.startswith("/"), f"{label} must be absolute")
    path = PurePosixPath(value)
    _require(str(path) == value, f"{label} is not normalized: {value}")
    _require(".." not in path.parts and "." not in path.parts, f"unsafe {label}: {value}")
    return value


def _unique_strings(value: object, label: str) -> list[str]:
    _require(isinstance(value, list) and value, f"{label} must be a non-empty list")
    _require(all(isinstance(item, str) and item for item in value), f"invalid {label}")
    _require(len(value) == len(set(value)), f"duplicate {label}")
    return value


def validate_profile(profile: dict, compatibility: dict, port: dict, enforce_lock: bool = True) -> dict:
    digest = compatctl.canonical_digest(profile)
    if enforce_lock:
        _require(digest == LOCKED_PIPELINE_SHA256, "pipeline profile digest is not locked")

    _require(profile.get("schema_version") == 1, "unsupported pipeline schema")
    project = profile.get("project", {})
    compatibility_project = compatibility.get("project", {})
    port_project = port.get("project", {})
    base = port.get("base", {})
    donor = port.get("donor", {})
    _require(project.get("device") == compatibility_project.get("device") == base.get("device") == "lavender", "target drift")
    _require(project.get("donor") == compatibility_project.get("donor") == donor.get("device"), "donor drift")
    for key in ("android_version", "sdk", "architecture"):
        _require(project.get(key) == compatibility_project.get(key) == port_project.get(key), f"project {key} drift")
    _require(project.get("mode") == "development", "Case 4 must use development mode")
    compatibility_digest = compatctl.canonical_digest(compatibility)
    _require(
        project.get("compatibility_profile_sha256") == compatibility_digest,
        "compatibility profile reference drift",
    )

    layout = profile.get("layout", {})
    expected_layout = {
        "base_root": "/",
        "donor_system_source": "/system",
        "output_system": "/system",
        "output_product": "/system/product",
        "output_system_ext": "/system/system_ext",
        "strategy": "donor-system-on-base-system-as-root",
    }
    for key, expected in expected_layout.items():
        _require(layout.get(key) == expected, f"layout drift: {key}")
    protected_paths = _unique_strings(layout.get("protected_base_paths"), "protected base path")
    protected_paths = [_locked_path(path, "protected base path") for path in protected_paths]
    required_protected = {
        "/system/product",
        "/system/system_ext",
        "/system/etc/init",
        "/system/etc/vintf",
        "/system/etc/selinux",
        "/system/etc/permissions",
        "/system/etc/selinux/plat_mac_permissions.xml",
        "/system/framework/org.ifaa.android.manager.jar",
        "/system/framework/telephony-ext.jar",
    }
    _require(set(protected_paths) == required_protected, "protected base path set drift")

    packages = profile.get("packages", {})
    retain_uids = _unique_strings(packages.get("retain_base_shared_uids"), "retained shared UID")
    _require(set(retain_uids) == {"android.uid.bluetooth", "android.uid.phone"}, "retained shared UID drift")
    replace_names = _unique_strings(packages.get("replace_package_names"), "replacement package")
    _require(
        set(replace_names)
        == {"com.android.settings", "com.android.settings.intelligence", "com.android.systemui"},
        "replacement package set drift",
    )
    product_paths = [_locked_path(path, "product selection") for path in _unique_strings(packages.get("product_paths"), "product selection")]
    system_ext_paths = [
        _locked_path(path, "system_ext selection")
        for path in _unique_strings(packages.get("system_ext_paths"), "system_ext selection")
    ]
    _require(product_paths == compatibility["selection"]["product_paths"], "product selection drift")
    _require(system_ext_paths == compatibility["selection"]["system_ext_paths"], "system_ext selection drift")

    cleanup = profile.get("cleanup", {})
    _require(cleanup.get("directory_names") == ["oat"], "preopt directory policy drift")
    _require(cleanup.get("file_suffixes") == [".art", ".odex", ".vdex"], "preopt suffix policy drift")
    _require(cleanup.get("discard_all_preopt") is True, "preopt cleanup must remain enabled")

    permissions = profile.get("permissions", {})
    _require(permissions.get("package") == "com.android.systemui", "permission target drift")
    _require(permissions.get("destination_partition") == "system_ext", "permission partition drift")
    _require(
        permissions.get("required_grants")
        == [
            "android.permission.KILL_UID",
            "android.permission.READ_PHONE_STATE",
            "android.permission.SEND_SMS",
        ],
        "privileged permission set drift",
    )
    _require(permissions.get("copy_donor_privapp_file") is False, "donor permission file must not be copied")

    selinux = profile.get("selinux", {})
    _require(selinux.get("preserve_base_policy") is True, "base SELinux policy must be preserved")
    _require(selinux.get("allow_new_types") is False, "new SELinux types are forbidden")
    _require(
        selinux.get("service_contexts_destination")
        == "/system/system_ext/etc/selinux/system_ext_service_contexts",
        "service-context destination drift",
    )
    _require(len(compatibility.get("service_types", {})) == 9, "Case 3 service map is incomplete")

    signing = profile.get("signing", {})
    _require(signing.get("mode") == "project-development", "signing mode drift")
    _require(signing.get("strategy") == compatibility["shared_uid_audit"]["case4_strategy"], "signing strategy drift")
    expected_certificates = {
        compatibility["signers"]["base_platform_sha256"],
        compatibility["signers"]["xos_platform_sha256"],
    }
    certificate_inputs = _unique_strings(signing.get("resign_certificate_sha256"), "re-sign certificate")
    _require(set(certificate_inputs) == expected_certificates, "re-sign certificate set drift")
    for key in (
        "preserve_standalone_apks",
        "preserve_apex",
        "update_mac_permissions",
        "require_one_certificate_per_shared_uid",
        "clean_data_required_for_device_test",
    ):
        _require(signing.get(key) is True, f"signing guard missing: {key}")
    for key in ("allow_public_aosp_testkey", "allow_production_key", "commit_private_key"):
        _require(signing.get(key) is False, f"unsafe signing policy enabled: {key}")

    guards = profile.get("guards", {})
    for key in (
        "forbid_donor_hardware_images",
        "forbid_donor_vendor_tree",
        "forbid_shared_uid_removal",
        "forbid_package_manager_signature_bypass",
        "forbid_repartition",
        "forbid_automatic_flash",
    ):
        _require(guards.get(key) is True, f"pipeline guard missing: {key}")

    return {
        "status": "verified",
        "profile_sha256": digest,
        "compatibility_profile_sha256": compatibility_digest,
        "protected_base_paths": len(protected_paths),
        "product_paths": len(product_paths),
        "system_ext_paths": len(system_ext_paths),
        "retained_shared_uids": len(retain_uids),
        "replacement_packages": len(replace_names),
        "permission_grants": len(permissions["required_grants"]),
        "service_mappings": len(compatibility["service_types"]),
        "signing_mode": signing["mode"],
    }


def load_and_validate(
    profile_path: Path = DEFAULT_PROFILE,
    compatibility_path: Path = DEFAULT_COMPATIBILITY_PROFILE,
    port_path: Path = DEFAULT_PORT_PROFILE,
    enforce_lock: bool = True,
) -> tuple[dict, dict, dict, dict]:
    profile = _read_toml(profile_path)
    try:
        compatibility, port, _ = compatctl.load_and_validate(compatibility_path, port_path)
    except compatctl.CompatibilityError as exc:
        raise BuildError(str(exc)) from exc
    summary = validate_profile(profile, compatibility, port, enforce_lock=enforce_lock)
    return profile, compatibility, port, summary


def _validate_root(root: Path, label: str) -> Path:
    _require(root.is_absolute(), f"{label} must be absolute")
    _require(not root.is_symlink() and root.is_dir(), f"{label} is not a regular directory: {root}")
    return root


def source_path(root: Path, locked_path: str, partition: str | None = None) -> Path:
    root = _validate_root(root, "source root")
    logical = PurePosixPath(_locked_path(locked_path, "source path"))
    parts = list(logical.parts[1:])
    if partition is not None:
        _require(parts and parts[0] == partition, f"source path is not in {partition}: {locked_path}")
        parts = parts[1:]
    candidate = root.joinpath(*parts)
    current = root
    for part in parts[:-1]:
        current = current / part
        _require(not current.is_symlink(), f"symbolic-link source parent is forbidden: {current}")
    return candidate


def _verify_file(path: Path, expected: dict, label: str) -> dict:
    _require(path.is_file() and not path.is_symlink(), f"{label} is not a regular file: {path}")
    size = path.stat().st_size
    _require(size == expected["size"], f"{label} size mismatch")
    digest = compatctl.sha256_file(path)
    _require(digest == expected["sha256"], f"{label} SHA-256 mismatch")
    return {"path": str(path), "size": size, "sha256": digest}


def _inventory_apks(root: Path, label: str) -> dict:
    root = _validate_root(root, label)
    rows = []
    for directory, directory_names, file_names in os.walk(root, followlinks=False):
        directory_names[:] = sorted(
            name for name in directory_names if not (Path(directory) / name).is_symlink()
        )
        for name in sorted(file_names):
            if not name.endswith(".apk"):
                continue
            path = Path(directory) / name
            _require(not path.is_symlink(), f"symbolic-link APK is forbidden: {path}")
            try:
                report = compatctl.apk_report(path)
            except compatctl.CompatibilityError as exc:
                raise BuildError(f"cannot inspect APK {path}: {exc}") from exc
            rows.append(
                {
                    "path": "/" + path.relative_to(root).as_posix(),
                    "package": report["package"],
                    "shared_uid": report["shared_uid"],
                    "certificate_sha256": report["certificate_sha256"],
                }
            )

    certificate_counts = Counter(row["certificate_sha256"] for row in rows)
    shared_groups: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
    for row in rows:
        if row["shared_uid"]:
            shared_groups[row["shared_uid"]][row["certificate_sha256"]].append(row["package"])
    normalized_groups = {
        uid: {certificate: sorted(packages) for certificate, packages in sorted(certificates.items())}
        for uid, certificates in sorted(shared_groups.items())
    }
    return {
        "apk_count": len(rows),
        "shared_uid_packages": sum(bool(row["shared_uid"]) for row in rows),
        "certificate_counts": dict(sorted(certificate_counts.items())),
        "shared_uid_groups": normalized_groups,
    }


def inspect_inputs(
    profile: dict,
    compatibility: dict,
    summary: dict,
    base_root: Path,
    donor_system_root: Path,
    donor_product_root: Path,
    donor_system_ext_root: Path,
) -> dict:
    roots = {
        "base_system": _validate_root(base_root, "base system root"),
        "donor_system": _validate_root(donor_system_root, "donor system root"),
        "donor_product": _validate_root(donor_product_root, "donor product root"),
        "donor_system_ext": _validate_root(donor_system_ext_root, "donor system_ext root"),
    }
    _require((base_root / "system").is_dir(), "base system-as-root /system is missing")
    _require((donor_system_root / "system").is_dir(), "donor TSSI /system is missing")

    protected = []
    for locked_path in profile["layout"]["protected_base_paths"]:
        path = source_path(base_root, locked_path)
        _require(path.exists() and not path.is_symlink(), f"protected base input is missing: {locked_path}")
        protected.append(locked_path)

    selected_packages = []
    for expected in compatibility["packages"]:
        locked_path = expected["path"]
        if locked_path.startswith("/product/"):
            path = source_path(donor_product_root, locked_path, "product")
        elif locked_path.startswith("/system_ext/"):
            path = source_path(donor_system_ext_root, locked_path, "system_ext")
        else:
            raise BuildError(f"selected package is outside allowlisted partitions: {locked_path}")
        try:
            actual = compatctl.apk_report(path)
        except compatctl.CompatibilityError as exc:
            raise BuildError(f"cannot inspect selected package {expected['id']}: {exc}") from exc
        for field in ("size", "sha256", "package", "shared_uid", "certificate_sha256"):
            _require(actual[field] == expected[field], f"selected package drift: {expected['id']} {field}")
        selected_packages.append({"id": expected["id"], "path": str(path), "sha256": actual["sha256"]})

    runtime_dependencies = []
    for expected in compatibility["runtime_dependencies"]:
        locked_path = expected["path"]
        if locked_path.startswith("/system_ext/"):
            path = source_path(donor_system_ext_root, locked_path, "system_ext")
        elif locked_path.startswith("/system/"):
            path = source_path(donor_system_root, locked_path)
        else:
            raise BuildError(f"runtime dependency is outside donor system partitions: {locked_path}")
        runtime_dependencies.append({"id": expected["id"], **_verify_file(path, expected, expected["id"])})

    classpath_providers = []
    for expected in compatibility["classpath_providers"]:
        root = roots["base_system"] if expected["source"] == "base-system" else roots["donor_system"]
        path = source_path(root, expected["path"])
        classpath_providers.append({"id": expected["id"], **_verify_file(path, expected, expected["id"])})

    inventories = {
        "base_system": _inventory_apks(base_root, "base system root"),
        "donor_system": _inventory_apks(donor_system_root, "donor system root"),
        "donor_product": _inventory_apks(donor_product_root, "donor product root"),
        "donor_system_ext": _inventory_apks(donor_system_ext_root, "donor system_ext root"),
    }
    total_apks = sum(inventory["apk_count"] for inventory in inventories.values())
    _require(total_apks == EXPECTED_INPUT_APKS, "input APK inventory count drift")

    return {
        "status": "verified",
        "profile_sha256": summary["profile_sha256"],
        "compatibility_profile_sha256": summary["compatibility_profile_sha256"],
        "protected_base_paths": protected,
        "selected_packages": selected_packages,
        "runtime_dependencies": runtime_dependencies,
        "classpath_providers": classpath_providers,
        "inventories": inventories,
        "total_apks_scanned": total_apks,
    }


def _output_path(root: Path, logical_path: str) -> Path:
    root = _validate_root(root, "output root")
    logical = PurePosixPath(_locked_path(logical_path, "output path"))
    candidate = root.joinpath(*logical.parts[1:])
    current = root
    for part in logical.parts[1:-1]:
        current = current / part
        _require(not current.is_symlink(), f"symbolic-link output parent is forbidden: {current}")
    return candidate


def _atomic_bytes(path: Path, data: bytes, mode: int | None = None) -> None:
    _require(not path.is_symlink(), f"refusing symbolic-link output: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    if mode is None:
        mode = stat.S_IMODE(path.stat().st_mode) if path.exists() else 0o644
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".partial", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def _remove_path(path: Path) -> None:
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.is_dir():
        shutil.rmtree(path)


def _hardlink_copy(source: str, destination: str) -> str:
    os.link(source, destination, follow_symlinks=False)
    return destination


def _copy_path(source: Path, destination: Path) -> None:
    _require(source.exists() or source.is_symlink(), f"copy source is missing: {source}")
    _remove_path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if source.is_symlink():
        destination.symlink_to(os.readlink(source), target_is_directory=source.is_dir())
    elif source.is_dir():
        shutil.copytree(source, destination, symlinks=True, copy_function=_hardlink_copy)
    elif source.is_file():
        os.link(source, destination, follow_symlinks=False)
    else:
        raise BuildError(f"unsupported copy source: {source}")


def _stage_base(base_root: Path, output_root: Path) -> None:
    _validate_root(base_root, "base system root")
    _require(output_root.is_absolute(), "output root must be absolute")
    _require(not output_root.exists() and not output_root.is_symlink(), f"output root already exists: {output_root}")
    output_root.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{output_root.name}.staging.", dir=output_root.parent))
    temporary.rmdir()
    try:
        shutil.copytree(base_root, temporary, symlinks=True, copy_function=_hardlink_copy)
        os.replace(temporary, output_root)
    except Exception:
        if temporary.exists():
            shutil.rmtree(temporary)
        raise


def _apk_rows(root: Path) -> list[dict]:
    root = _validate_root(root, "APK root")
    rows: list[dict] = []
    for directory, directory_names, file_names in os.walk(root, followlinks=False):
        directory_names[:] = sorted(
            name for name in directory_names if not (Path(directory) / name).is_symlink()
        )
        for name in sorted(file_names):
            if not name.endswith(".apk"):
                continue
            path = Path(directory) / name
            _require(path.is_file() and not path.is_symlink(), f"unsafe APK path: {path}")
            try:
                report = compatctl.apk_report(path)
            except compatctl.CompatibilityError as exc:
                raise BuildError(f"cannot inspect APK {path}: {exc}") from exc
            rows.append(
                {
                    "path": "/" + path.relative_to(root).as_posix(),
                    "directory": "/" + path.parent.relative_to(root).as_posix(),
                    **report,
                }
            )
    return rows


def _cross_directory_duplicates(rows: list[dict]) -> dict[str, list[str]]:
    packages: dict[str, set[str]] = defaultdict(set)
    for row in rows:
        packages[row["package"]].add(row["directory"])
    return {
        package: sorted(directories)
        for package, directories in sorted(packages.items())
        if package and len(directories) > 1
    }


def _remove_locked_duplicates(root: Path) -> list[dict]:
    removed: list[dict] = []
    for expected in LOCKED_REMOVALS:
        apk = _output_path(root, expected["path"])
        if not apk.exists() and not apk.is_symlink():
            continue
        _require(apk.is_file() and not apk.is_symlink(), f"locked removal is not a regular APK: {apk}")
        try:
            actual = compatctl.apk_report(apk)
        except compatctl.CompatibilityError as exc:
            raise BuildError(f"cannot validate locked removal {apk}: {exc}") from exc
        for field in ("sha256", "certificate_sha256", "package"):
            _require(actual[field] == expected[field], f"locked removal identity drift: {expected['path']} {field}")
        directory = apk.parent
        _remove_path(directory)
        removed.append(dict(expected))
    return removed


def _cleanup_preopt(root: Path) -> dict:
    root = _validate_root(root, "preopt cleanup root")
    removed_entries = 0
    removed_regular_files = 0
    removed_regular_bytes = 0
    for directory, directory_names, file_names in os.walk(root, topdown=False, followlinks=False):
        parent = Path(directory)
        for name in file_names:
            path = parent / name
            if name == "oat" and path.is_symlink():
                path.unlink()
                removed_entries += 1
                continue
            if not name.endswith(PREOPT_SUFFIXES):
                continue
            if path.is_symlink():
                path.unlink()
                removed_entries += 1
            elif path.is_file():
                removed_regular_bytes += path.stat().st_size
                path.unlink()
                removed_entries += 1
                removed_regular_files += 1
        for name in directory_names:
            path = parent / name
            if name != "oat":
                continue
            if path.is_symlink():
                path.unlink()
                removed_entries += 1
                continue
            if path.is_dir():
                for child_directory, child_dirs, child_files in os.walk(path, topdown=False, followlinks=False):
                    child_parent = Path(child_directory)
                    for child_name in child_files:
                        child = child_parent / child_name
                        if child.is_symlink():
                            removed_entries += 1
                        elif child.is_file():
                            removed_regular_bytes += child.stat().st_size
                            removed_regular_files += 1
                            removed_entries += 1
                    for child_name in child_dirs:
                        child = child_parent / child_name
                        if child.is_symlink():
                            removed_entries += 1
                shutil.rmtree(path)
    return {
        "removed_entries": removed_entries,
        "removed_regular_files": removed_regular_files,
        "removed_regular_bytes": removed_regular_bytes,
    }


def _preopt_residue(root: Path) -> list[str]:
    residue: list[str] = []
    for directory, directory_names, file_names in os.walk(root, followlinks=False):
        parent = Path(directory)
        for name in directory_names:
            if name == "oat":
                residue.append("/" + (parent / name).relative_to(root).as_posix())
        for name in file_names:
            if name == "oat" or name.endswith(PREOPT_SUFFIXES):
                residue.append("/" + (parent / name).relative_to(root).as_posix())
    return sorted(residue)


def _tree_manifest(root: Path) -> dict:
    root = _validate_root(root, "manifest root")
    digest = hashlib.sha256()
    regular_files = 0
    symbolic_links = 0
    regular_bytes = 0
    for directory, directory_names, file_names in os.walk(root, followlinks=False):
        parent = Path(directory)
        symlink_directories = [name for name in directory_names if (parent / name).is_symlink()]
        directory_names[:] = sorted(name for name in directory_names if name not in symlink_directories)
        entries = [(name, parent / name) for name in file_names]
        entries.extend((name, parent / name) for name in symlink_directories)
        for _name, path in sorted(entries):
            relative = "/" + path.relative_to(root).as_posix()
            if path.is_symlink():
                target = os.readlink(path)
                record = f"l\t{relative}\t{target}\n".encode("utf-8", errors="surrogateescape")
                symbolic_links += 1
            elif path.is_file():
                size = path.stat().st_size
                file_digest = compatctl.sha256_file(path)
                mode = stat.S_IMODE(path.stat().st_mode)
                record = f"f\t{relative}\t{mode:04o}\t{size}\t{file_digest}\n".encode()
                regular_files += 1
                regular_bytes += size
            else:
                raise BuildError(f"unsupported filesystem entry: {path}")
            digest.update(record)
    return {
        "sha256": digest.hexdigest(),
        "regular_files": regular_files,
        "symbolic_links": symbolic_links,
        "regular_bytes": regular_bytes,
    }


def _logical_output_path(path: str) -> str:
    _locked_path(path, "logical package path")
    if path.startswith("/product/") or path.startswith("/system_ext/"):
        return "/system" + path
    return path


def _transplant(
    profile: dict,
    compatibility: dict,
    base_root: Path,
    donor_system_root: Path,
    donor_product_root: Path,
    donor_system_ext_root: Path,
    output_root: Path,
) -> dict:
    donor_system = source_path(donor_system_root, "/system")
    _require(donor_system.is_dir() and not donor_system.is_symlink(), "donor /system tree is missing")
    _copy_path(donor_system, _output_path(output_root, "/system"))

    restored: list[str] = []
    for locked_path in profile["layout"]["protected_base_paths"]:
        _copy_path(source_path(base_root, locked_path), _output_path(output_root, locked_path))
        restored.append(locked_path)

    retained_uids = set(profile["packages"]["retain_base_shared_uids"])
    base_rows = [row for row in _apk_rows(base_root) if row["shared_uid"] in retained_uids]
    output_rows = [row for row in _apk_rows(output_root) if row["shared_uid"] in retained_uids]
    removed_directories: list[str] = []
    for directory in sorted({row["directory"] for row in output_rows}):
        _remove_path(_output_path(output_root, directory))
        removed_directories.append(directory)
    retained_directories: list[str] = []
    for directory in sorted({row["directory"] for row in base_rows}):
        _copy_path(source_path(base_root, directory), _output_path(output_root, directory))
        retained_directories.append(directory)

    selected: list[str] = []
    for expected in compatibility["packages"]:
        logical = expected["path"]
        directory = str(PurePosixPath(logical).parent)
        if logical.startswith("/product/"):
            source = source_path(donor_product_root, directory, "product")
        elif logical.startswith("/system_ext/"):
            source = source_path(donor_system_ext_root, directory, "system_ext")
        else:
            raise BuildError(f"selected package is outside allowed partitions: {logical}")
        destination = _output_path(output_root, _logical_output_path(directory))
        _copy_path(source, destination)
        selected.append(expected["id"])

    runtimes: list[str] = []
    for expected in compatibility["runtime_dependencies"]:
        logical = expected["path"]
        if logical.startswith("/system_ext/"):
            source = source_path(donor_system_ext_root, logical, "system_ext")
        elif logical.startswith("/system/"):
            source = source_path(donor_system_root, logical)
        else:
            raise BuildError(f"runtime dependency is outside donor partitions: {logical}")
        _copy_path(source, _output_path(output_root, _logical_output_path(logical)))
        runtimes.append(expected["id"])

    removed = _remove_locked_duplicates(output_root)
    _require(removed == list(LOCKED_REMOVALS), "locked duplicate removal was not applied exactly once")
    cleanup = _cleanup_preopt(output_root)
    duplicates = _cross_directory_duplicates(_apk_rows(output_root))
    _require(not duplicates, f"cross-directory duplicate packages remain: {', '.join(duplicates)}")
    return {
        "restored_base_paths": sorted(restored),
        "retained_shared_uid_directories": retained_directories,
        "removed_donor_shared_uid_directories": removed_directories,
        "selected_packages": selected,
        "runtime_dependencies": runtimes,
        "locked_removals": removed,
        "cross_directory_duplicate_packages": 0,
        "preopt_cleanup": cleanup,
    }


def _permission_document(profile: dict) -> bytes:
    package = profile["permissions"]["package"]
    grants = profile["permissions"]["required_grants"]
    lines = [
        '<?xml version="1.0" encoding="utf-8"?>',
        "<!-- Generated by the locked Case 4 development pipeline. -->",
        "<permissions>",
        f'    <privapp-permissions package="{package}">',
    ]
    lines.extend(f'        <permission name="{grant}" />' for grant in grants)
    lines.extend(["    </privapp-permissions>", "</permissions>", ""])
    return "\n".join(lines).encode("utf-8")


def _patch_privapp_permissions(profile: dict, output_root: Path) -> dict:
    path = _output_path(output_root, PRIVAPP_OUTPUT_PATH)
    content = _permission_document(profile)
    _atomic_bytes(path, content)
    return {"path": PRIVAPP_OUTPUT_PATH, "sha256": hashlib.sha256(content).hexdigest()}


def _service_context_map(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    if not path.exists():
        return result
    _require(path.is_file() and not path.is_symlink(), f"service contexts is not a regular file: {path}")
    for number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        fields = line.split()
        _require(len(fields) == 2, f"invalid service-context line {number}: {path}")
        service, context = fields
        _require(service not in result or result[service] == context, f"conflicting service context: {service}")
        result[service] = context
    return result


def _patch_service_contexts(profile: dict, compatibility: dict, output_root: Path) -> dict:
    logical = profile["selinux"]["service_contexts_destination"]
    path = _output_path(output_root, logical)
    existing = _service_context_map(path)
    additions: list[str] = []
    for service, se_type in sorted(compatibility["service_types"].items()):
        context = f"u:object_r:{se_type}:s0"
        _require(service not in existing or existing[service] == context, f"service-context type drift: {service}")
        if service not in existing:
            additions.append(f"{service} {context}")
    original = path.read_text(encoding="utf-8") if path.exists() else ""
    if original and not original.endswith("\n"):
        original += "\n"
    if additions:
        original += "# XOS Lavender Case 4 mappings\n" + "\n".join(additions) + "\n"
    _atomic_bytes(path, original.encode("utf-8"))
    return {
        "path": logical,
        "mappings": len(compatibility["service_types"]),
        "added": len(additions),
        "sha256": compatctl.sha256_file(path),
    }


SIGNER_ATTRIBUTE = re.compile(
    rb"(<signer\b[^>]*?\bsignature\s*=\s*['\"])([0-9A-Fa-f]+)(['\"])",
    re.IGNORECASE,
)


def _patch_mac_permissions(profile: dict, compatibility: dict, output_root: Path, certificate: Path) -> dict:
    logical = "/system/etc/selinux/plat_mac_permissions.xml"
    path = _output_path(output_root, logical)
    _require(path.is_file() and not path.is_symlink(), f"platform mac permissions is missing: {path}")
    development_certificate = certificate.read_bytes()
    development_hex = development_certificate.hex().encode("ascii")
    platform_fingerprints = {
        compatibility["signers"]["base_platform_sha256"],
        compatibility["signers"]["xos_platform_sha256"],
    }
    replacements = 0

    def replace(match: re.Match[bytes]) -> bytes:
        nonlocal replacements
        try:
            encoded = bytes.fromhex(match.group(2).decode("ascii"))
        except ValueError:
            return match.group(0)
        if hashlib.sha256(encoded).hexdigest() not in platform_fingerprints:
            return match.group(0)
        replacements += 1
        return match.group(1) + development_hex + match.group(3)

    original = path.read_bytes()
    patched = SIGNER_ATTRIBUTE.sub(replace, original)
    resumed = replacements == 0 and development_hex in [
        match.group(2).lower() for match in SIGNER_ATTRIBUTE.finditer(original)
    ]
    _require(replacements > 0 or resumed, "base or development signer was not found in plat_mac_permissions.xml")
    _atomic_bytes(path, patched)
    return {
        "path": logical,
        "replacements": replacements,
        "resumed": resumed,
        "certificate_sha256": apksign.certificate_fingerprint(certificate),
        "sha256": hashlib.sha256(patched).hexdigest(),
    }


def _patch_tree(profile: dict, compatibility: dict, output_root: Path, certificate: Path) -> dict:
    return {
        "privapp_permissions": _patch_privapp_permissions(profile, output_root),
        "service_contexts": _patch_service_contexts(profile, compatibility, output_root),
        "mac_permissions": _patch_mac_permissions(profile, compatibility, output_root, certificate),
    }


def _sign_output_apks(
    profile: dict,
    compatibility: dict,
    output_root: Path,
    private_key: Path,
    certificate: Path,
) -> dict:
    key_report = apksign.verify_key_pair(private_key, certificate)
    development_fingerprint = key_report["certificate_sha256"]
    platform_fingerprints = set(profile["signing"]["resign_certificate_sha256"])
    _require(
        platform_fingerprints
        == {
            compatibility["signers"]["base_platform_sha256"],
            compatibility["signers"]["xos_platform_sha256"],
        },
        "platform signing set drift",
    )
    results: list[dict] = []
    signed = 0
    resumed = 0
    preserved = 0
    for row in _apk_rows(output_root):
        path = _output_path(output_root, row["path"])
        before_sha256 = row["sha256"]
        source_certificate = row["certificate_sha256"]
        if source_certificate in platform_fingerprints:
            temporary = path.with_name(f".{path.name}.case4-signed.partial")
            if temporary.exists() or temporary.is_symlink():
                _require(
                    temporary.is_file() and not temporary.is_symlink(),
                    f"unsafe signing temporary: {temporary}",
                )
                recovered = apksign.verify_apk(temporary.resolve())
                _require(
                    recovered["certificate_sha256"] == development_fingerprint,
                    f"stale signing temporary has wrong certificate: {temporary}",
                )
                action = "recovered-atomic-signature"
                resumed += 1
            else:
                apksign.sign_apk(path.resolve(), temporary.resolve(), private_key, certificate)
                action = "signed"
                signed += 1
            os.replace(temporary, path)
        elif source_certificate == development_fingerprint:
            apksign.verify_apk(path.resolve())
            action = "resumed-development-signature"
            resumed += 1
        else:
            action = "preserved-standalone"
            preserved += 1
        after_sha256 = compatctl.sha256_file(path)
        results.append(
            {
                "path": row["path"],
                "package": row["package"],
                "shared_uid": row["shared_uid"],
                "action": action,
                "source_certificate_sha256": source_certificate,
                "before_sha256": before_sha256,
                "after_sha256": after_sha256,
            }
        )
    _require(signed + resumed > 0, "no platform APK was development-signed")
    return {
        "certificate_sha256": development_fingerprint,
        "signed": signed,
        "resumed": resumed,
        "development_signed_total": signed + resumed,
        "preserved_standalone": preserved,
        "apk_total": len(results),
        "apks": results,
    }


def _verify_zip(path: Path) -> None:
    try:
        with zipfile.ZipFile(path) as archive:
            _require(len(archive.infolist()) == len(set(archive.namelist())), f"duplicate ZIP member: {path}")
            damaged = archive.testzip()
            _require(damaged is None, f"damaged APK member {damaged}: {path}")
    except (OSError, zipfile.BadZipFile) as exc:
        raise BuildError(f"cannot validate APK ZIP {path}: {exc}") from exc


def _verify_permissions(profile: dict, root: Path) -> dict:
    path = _output_path(root, PRIVAPP_OUTPUT_PATH)
    _require(path.is_file() and not path.is_symlink(), f"generated privileged permissions are missing: {path}")
    try:
        document = ElementTree.parse(path).getroot()
    except (OSError, ElementTree.ParseError) as exc:
        raise BuildError(f"cannot parse privileged permissions {path}: {exc}") from exc
    package = profile["permissions"]["package"]
    entries = [element for element in document.findall("privapp-permissions") if element.get("package") == package]
    _require(len(entries) == 1, "generated SystemUI privileged-permission group is not unique")
    grants = sorted(element.get("name", "") for element in entries[0].findall("permission"))
    _require(grants == sorted(profile["permissions"]["required_grants"]), "generated privileged-permission grants drift")
    return {"path": PRIVAPP_OUTPUT_PATH, "package": package, "grants": grants, "sha256": compatctl.sha256_file(path)}


def _verify_service_contexts(profile: dict, compatibility: dict, root: Path) -> dict:
    logical = profile["selinux"]["service_contexts_destination"]
    path = _output_path(root, logical)
    contexts = _service_context_map(path)
    for service, se_type in compatibility["service_types"].items():
        _require(contexts.get(service) == f"u:object_r:{se_type}:s0", f"service mapping mismatch: {service}")
    return {"path": logical, "mappings": len(compatibility["service_types"]), "sha256": compatctl.sha256_file(path)}


def _verify_mac_permissions(root: Path, certificate: Path) -> dict:
    logical = "/system/etc/selinux/plat_mac_permissions.xml"
    path = _output_path(root, logical)
    _require(path.is_file() and not path.is_symlink(), f"platform mac permissions are missing: {path}")
    signatures = [match.group(2).lower() for match in SIGNER_ATTRIBUTE.finditer(path.read_bytes())]
    certificate_hex = certificate.read_bytes().hex().encode("ascii")
    _require(certificate_hex in signatures, "development signer is missing from platform mac permissions")
    return {
        "path": logical,
        "certificate_sha256": apksign.certificate_fingerprint(certificate),
        "sha256": compatctl.sha256_file(path),
    }


def _verify_hardware_guard(port: dict, root: Path) -> dict:
    forbidden = set(port["policy"]["forbidden_donor_output_images"])
    hits: list[str] = []
    for directory, directory_names, file_names in os.walk(root, followlinks=False):
        parent = Path(directory)
        directory_names[:] = [name for name in directory_names if not (parent / name).is_symlink()]
        for name in file_names:
            path = parent / name
            if name in forbidden and not path.is_symlink():
                hits.append("/" + path.relative_to(root).as_posix())
    vendor_paths = (root / "vendor", root / "system" / "vendor")
    _require(
        all(not path.is_dir() or path.is_symlink() for path in vendor_paths),
        "a vendor directory was packaged into the system root",
    )
    _require(not hits, f"forbidden donor hardware output found: {', '.join(sorted(hits))}")
    return {"forbidden_image_hits": [], "vendor_tree_packaged": False}


def _verify_static_identities(compatibility: dict, root: Path, development_fingerprint: str) -> dict:
    selected: list[dict] = []
    for expected in compatibility["packages"]:
        logical = _logical_output_path(expected["path"])
        path = _output_path(root, logical)
        try:
            actual = compatctl.apk_report(path)
        except compatctl.CompatibilityError as exc:
            raise BuildError(f"cannot inspect selected output {expected['id']}: {exc}") from exc
        for field in ("package", "shared_uid"):
            _require(actual[field] == expected[field], f"selected output drift: {expected['id']} {field}")
        expected_certificate = (
            development_fingerprint if expected["signer"] == "xos-platform" else expected["certificate_sha256"]
        )
        _require(actual["certificate_sha256"] == expected_certificate, f"selected output signer drift: {expected['id']}")
        selected.append(
            {
                "id": expected["id"],
                "path": logical,
                "package": actual["package"],
                "certificate_sha256": actual["certificate_sha256"],
                "sha256": actual["sha256"],
            }
        )

    runtimes: list[dict] = []
    for expected in compatibility["runtime_dependencies"]:
        logical = _logical_output_path(expected["path"])
        path = _output_path(root, logical)
        if expected["id"] == "transsion_resources":
            try:
                actual = compatctl.apk_report(path)
            except compatctl.CompatibilityError as exc:
                raise BuildError(f"cannot inspect transformed runtime {path}: {exc}") from exc
            _require(actual["package"] == expected["package"], "transsion resource package drift")
            _require(actual["certificate_sha256"] == development_fingerprint, "transsion resource signer drift")
            runtimes.append({"id": expected["id"], "path": logical, "sha256": actual["sha256"], "preserved": False})
        else:
            verified = _verify_file(path, expected, expected["id"])
            runtimes.append({"id": expected["id"], **verified, "preserved": True})

    providers: list[dict] = []
    for expected in compatibility["classpath_providers"]:
        path = _output_path(root, expected["path"])
        providers.append({"id": expected["id"], **_verify_file(path, expected, expected["id"])})

    matrix = _output_path(root, "/system/etc/vintf/compatibility_matrix.3.xml")
    _require(matrix.is_file() and not matrix.is_symlink(), "base VINTF level-3 matrix is missing")
    matrix_sha256 = compatctl.sha256_file(matrix)
    _require(matrix_sha256 == compatibility["vintf"]["matrix_level_3_sha256"], "base VINTF level-3 matrix drift")

    marker_paths = {
        "plat": "/system/etc/selinux/plat_sepolicy_and_mapping.sha256",
        "product": "/system/product/etc/selinux/product_sepolicy_and_mapping.sha256",
        "system_ext": "/system/system_ext/etc/selinux/system_ext_sepolicy_and_mapping.sha256",
    }
    markers: dict[str, dict] = {}
    for identifier, logical in marker_paths.items():
        path = _output_path(root, logical)
        digest = compatctl.sha256_file(path)
        expected = compatibility["selinux"][f"{identifier}_precompiled_sha256"]
        _require(digest == expected, f"base {identifier} SELinux marker drift")
        markers[identifier] = {"path": logical, "sha256": digest}
    return {
        "selected_packages": selected,
        "runtime_dependencies": runtimes,
        "classpath_providers": providers,
        "vintf": {"path": "/system/etc/vintf/compatibility_matrix.3.xml", "sha256": matrix_sha256},
        "selinux_markers": markers,
    }


def verify_output(
    profile: dict,
    compatibility: dict,
    port: dict,
    summary: dict,
    output_root: Path,
    certificate: Path,
    standalone_sha256: dict[str, str] | None = None,
) -> dict:
    output_root = _validate_root(output_root, "output root")
    development_fingerprint = apksign.certificate_fingerprint(certificate)
    rows = _apk_rows(output_root)
    _require(rows, "output APK inventory is empty")
    development_signed = 0
    preserved = 0
    shared_groups: dict[str, set[str]] = defaultdict(set)
    for row in rows:
        path = _output_path(output_root, row["path"])
        _verify_zip(path)
        if row["certificate_sha256"] == development_fingerprint:
            apksign.verify_apk(path.resolve())
            development_signed += 1
        else:
            _require(
                row["certificate_sha256"] not in set(profile["signing"]["resign_certificate_sha256"]),
                f"original platform-signed APK was not re-signed: {row['path']}",
            )
            preserved += 1
            if standalone_sha256 is not None:
                _require(
                    standalone_sha256.get(row["path"]) == row["sha256"],
                    f"preserved standalone APK drift: {row['path']}",
                )
        if row["shared_uid"]:
            shared_groups[row["shared_uid"]].add(row["certificate_sha256"])
    mixed = {uid: sorted(values) for uid, values in shared_groups.items() if len(values) != 1}
    _require(not mixed, f"mixed signer in shared UID groups: {', '.join(sorted(mixed))}")
    _require(len(rows) == EXPECTED_OUTPUT_APKS, "output APK inventory count drift")
    _require(development_signed == EXPECTED_DEVELOPMENT_APKS, "development-signed APK count drift")
    _require(preserved == EXPECTED_STANDALONE_APKS, "preserved standalone APK count drift")
    _require(len(shared_groups) == EXPECTED_SHARED_UID_GROUPS, "shared UID group count drift")
    duplicates = _cross_directory_duplicates(rows)
    _require(not duplicates, f"cross-directory duplicate packages remain: {', '.join(duplicates)}")
    for removal in LOCKED_REMOVALS:
        _require(not _output_path(output_root, removal["path"]).exists(), f"locked duplicate removal still exists: {removal['path']}")
    residue = _preopt_residue(output_root)
    _require(not residue, f"preopt residue remains: {residue[0]}")
    patches = {
        "privapp_permissions": _verify_permissions(profile, output_root),
        "service_contexts": _verify_service_contexts(profile, compatibility, output_root),
        "mac_permissions": _verify_mac_permissions(output_root, certificate),
    }
    identities = _verify_static_identities(compatibility, output_root, development_fingerprint)
    hardware = _verify_hardware_guard(port, output_root)
    manifest = _tree_manifest(output_root)
    _require(
        manifest["regular_bytes"] <= compatibility["capacity"]["target_filesystem_data_size"],
        "output regular-file bytes exceed target filesystem capacity",
    )
    return {
        "status": "verified",
        "profile_sha256": summary["profile_sha256"],
        "compatibility_profile_sha256": summary["compatibility_profile_sha256"],
        "development_certificate_sha256": development_fingerprint,
        "apk_inventory": {
            "total": len(rows),
            "development_signed": development_signed,
            "preserved_standalone": preserved,
            "shared_uid_groups": len(shared_groups),
            "mixed_shared_uid_groups": 0,
            "cross_directory_duplicate_packages": 0,
            "zip_failures": 0,
        },
        "preopt_residue": 0,
        "patches": patches,
        "identities": identities,
        "hardware_guard": hardware,
        "tree_manifest": manifest,
    }


def _input_identity(report: dict) -> str:
    payload = {
        "profile_sha256": report["profile_sha256"],
        "compatibility_profile_sha256": report["compatibility_profile_sha256"],
        "protected_base_paths": report["protected_base_paths"],
        "selected_packages": [
            {"id": row["id"], "sha256": row["sha256"]} for row in report["selected_packages"]
        ],
        "runtime_dependencies": [
            {"id": row["id"], "size": row["size"], "sha256": row["sha256"]}
            for row in report["runtime_dependencies"]
        ],
        "classpath_providers": [
            {"id": row["id"], "size": row["size"], "sha256": row["sha256"]}
            for row in report["classpath_providers"]
        ],
        "inventories": {
            name: {
                "apk_count": inventory["apk_count"],
                "shared_uid_packages": inventory["shared_uid_packages"],
                "certificate_counts": inventory["certificate_counts"],
                "shared_uid_groups": inventory["shared_uid_groups"],
            }
            for name, inventory in sorted(report["inventories"].items())
        },
    }
    return compatctl.canonical_digest(payload)


def _state_path(output_root: Path) -> Path:
    return output_root.parent / f".{output_root.name}.case4-state.json"


def _lock_path(output_root: Path) -> Path:
    return output_root.parent / f".{output_root.name}.case4.lock"


def _read_state(path: Path) -> dict | None:
    if not path.exists() and not path.is_symlink():
        return None
    _require(path.is_file() and not path.is_symlink(), f"build state is not a regular file: {path}")
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BuildError(f"cannot read build state {path}: {exc}") from exc
    _require(isinstance(state, dict) and state.get("schema_version") == 1, "unsupported build state")
    _require(state.get("phase") in PHASES, "invalid build state phase")
    return state


def _write_state(path: Path, state: dict) -> None:
    _atomic_report(path, state)


def _phase_at_least(state: dict, phase: str) -> bool:
    return PHASES.index(state["phase"]) >= PHASES.index(phase)


def build_tree(
    profile: dict,
    compatibility: dict,
    port: dict,
    summary: dict,
    base_root: Path,
    donor_system_root: Path,
    donor_product_root: Path,
    donor_system_ext_root: Path,
    output_root: Path,
    private_key: Path,
    certificate: Path,
) -> dict:
    for root, label in (
        (base_root, "base system root"),
        (donor_system_root, "donor system root"),
        (donor_product_root, "donor product root"),
        (donor_system_ext_root, "donor system_ext root"),
    ):
        _validate_root(root, label)
    _require(output_root.is_absolute(), "output root must be absolute")
    _require(not output_root.is_symlink(), f"output root may not be a symbolic link: {output_root}")
    key_report = apksign.verify_key_pair(private_key, certificate)
    _require(
        key_report["certificate_sha256"] not in set(profile["signing"]["resign_certificate_sha256"]),
        "development certificate must be project-specific",
    )
    input_report = inspect_inputs(
        profile,
        compatibility,
        summary,
        base_root,
        donor_system_root,
        donor_product_root,
        donor_system_ext_root,
    )
    identity = _input_identity(input_report)
    paths = {
        "base_root": str(base_root),
        "donor_system_root": str(donor_system_root),
        "donor_product_root": str(donor_product_root),
        "donor_system_ext_root": str(donor_system_ext_root),
        "output_root": str(output_root),
    }
    output_root.parent.mkdir(parents=True, exist_ok=True)
    state_path = _state_path(output_root)
    lock_path = _lock_path(output_root)
    _require(not lock_path.is_symlink(), f"build lock may not be a symbolic link: {lock_path}")
    with lock_path.open("a+", encoding="utf-8") as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise BuildError(f"another Case 4 build owns {lock_path}") from exc
        state = _read_state(state_path)
        if state is None:
            _require(not output_root.exists(), f"untracked output root already exists: {output_root}")
            state = {
                "schema_version": 1,
                "phase": "initializing",
                "input_identity_sha256": identity,
                "development_certificate_sha256": key_report["certificate_sha256"],
                "paths": paths,
            }
            _write_state(state_path, state)
        else:
            _require(state["input_identity_sha256"] == identity, "build input identity drift")
            _require(
                state["development_certificate_sha256"] == key_report["certificate_sha256"],
                "development certificate drift",
            )
            _require(state.get("paths") == paths, "build path drift")

        if state["phase"] == "initializing":
            if not output_root.exists():
                _stage_base(base_root, output_root)
            else:
                _validate_root(output_root, "resumed staged output root")
                _require((output_root / "system").is_dir(), "resumed base stage is incomplete")
            state["phase"] = "staged"
            _write_state(state_path, state)

        if state["phase"] == "staged":
            state["transplant"] = _transplant(
                profile,
                compatibility,
                base_root,
                donor_system_root,
                donor_product_root,
                donor_system_ext_root,
                output_root,
            )
            state["phase"] = "transplanted"
            _write_state(state_path, state)

        if state["phase"] == "transplanted":
            state["patches"] = _patch_tree(profile, compatibility, output_root, certificate)
            state["phase"] = "patched"
            _write_state(state_path, state)

        if state["phase"] == "patched":
            signing = _sign_output_apks(profile, compatibility, output_root, private_key, certificate)
            state["signing"] = signing
            state["standalone_sha256"] = {
                row["path"]: row["after_sha256"]
                for row in signing["apks"]
                if row["action"] == "preserved-standalone"
            }
            state["phase"] = "signed"
            _write_state(state_path, state)

        standalone = state.get("standalone_sha256")
        _require(isinstance(standalone, dict), "standalone APK identity state is missing")
        output_report = verify_output(
            profile,
            compatibility,
            port,
            summary,
            output_root,
            certificate,
            standalone,
        )
        resumed_complete = state["phase"] == "complete"
        state["verification"] = output_report
        state["phase"] = "complete"
        _write_state(state_path, state)
        return {
            "status": "verified",
            "mode": "complete" if resumed_complete else "built",
            "input_identity_sha256": identity,
            "state_path": str(state_path),
            "development_key": {
                "certificate_sha256": key_report["certificate_sha256"],
                "private_key_committed": False,
            },
            "transplant": state.get("transplant"),
            "patches": state.get("patches"),
            "signing": {
                key: value for key, value in state["signing"].items() if key != "apks"
            },
            "output": output_report,
        }


def _atomic_report(path: Path, report: dict) -> None:
    if path.is_symlink():
        raise BuildError(f"refusing symbolic-link report: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".partial", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(report, output, indent=2, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def command_check(_profile: dict, _compatibility: dict, _port: dict, summary: dict, _args: argparse.Namespace) -> None:
    print(json.dumps(summary, indent=2, sort_keys=True))


def command_inspect(profile: dict, compatibility: dict, _port: dict, summary: dict, args: argparse.Namespace) -> None:
    report = inspect_inputs(
        profile,
        compatibility,
        summary,
        args.base_root,
        args.donor_system_root,
        args.donor_product_root,
        args.donor_system_ext_root,
    )
    if args.report:
        _atomic_report(args.report, report)
    print(json.dumps(report, indent=2, sort_keys=True))


def command_init_key(_profile: dict, _compatibility: dict, _port: dict, _summary: dict, args: argparse.Namespace) -> None:
    key_directory = args.key_dir.absolute()
    _require(key_directory.is_absolute(), "development key directory must be absolute")
    try:
        inside_repository = key_directory.is_relative_to(REPOSITORY_ROOT.resolve())
    except ValueError:
        inside_repository = False
    _require(not inside_repository, "development keys must remain outside the repository")
    private_key = key_directory / DEVELOPMENT_KEY_NAME
    certificate = key_directory / DEVELOPMENT_CERTIFICATE_NAME
    if private_key.exists() or certificate.exists():
        _require(private_key.exists() and certificate.exists(), "development key pair is incomplete")
        report = apksign.verify_key_pair(private_key, certificate)
        report["mode"] = "existing"
    else:
        report = apksign.initialize_key(private_key, certificate, args.subject)
        report["mode"] = "created"
    report.update(
        {
            "private_key": str(private_key),
            "certificate": str(certificate),
            "private_key_committed": False,
        }
    )
    print(json.dumps(report, indent=2, sort_keys=True))


def command_build(profile: dict, compatibility: dict, port: dict, summary: dict, args: argparse.Namespace) -> None:
    report = build_tree(
        profile,
        compatibility,
        port,
        summary,
        args.base_root.absolute(),
        args.donor_system_root.absolute(),
        args.donor_product_root.absolute(),
        args.donor_system_ext_root.absolute(),
        args.output_root.absolute(),
        args.development_key.absolute(),
        args.development_cert.absolute(),
    )
    if args.report:
        _atomic_report(args.report.absolute(), report)
    print(json.dumps(report, indent=2, sort_keys=True))


def command_verify_output(profile: dict, compatibility: dict, port: dict, summary: dict, args: argparse.Namespace) -> None:
    output_root = args.output_root.absolute()
    state_path = args.state.absolute() if args.state else _state_path(output_root)
    state = _read_state(state_path)
    _require(state is not None and state.get("phase") == "complete", "a complete Case 4 state is required")
    certificate = args.development_cert.absolute()
    _require(
        state.get("development_certificate_sha256") == apksign.certificate_fingerprint(certificate),
        "verification certificate does not match build state",
    )
    _require(state.get("paths", {}).get("output_root") == str(output_root), "verification output path drift")
    standalone = state.get("standalone_sha256")
    _require(isinstance(standalone, dict), "standalone APK identity state is missing")
    report = verify_output(
        profile,
        compatibility,
        port,
        summary,
        output_root,
        certificate,
        standalone,
    )
    if args.report:
        _atomic_report(args.report.absolute(), report)
    print(json.dumps(report, indent=2, sort_keys=True))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    parser.add_argument("--compatibility-profile", type=Path, default=DEFAULT_COMPATIBILITY_PROFILE)
    parser.add_argument("--port-profile", type=Path, default=DEFAULT_PORT_PROFILE)
    subparsers = parser.add_subparsers(dest="command", required=True)

    check_parser = subparsers.add_parser("check", help="validate the locked Case 4 pipeline profile")
    check_parser.set_defaults(handler=command_check)

    inspect_parser = subparsers.add_parser("inspect-inputs", help="verify and inventory all Case 4 input roots")
    inspect_parser.add_argument("--base-root", type=Path, required=True)
    inspect_parser.add_argument("--donor-system-root", type=Path, required=True)
    inspect_parser.add_argument("--donor-product-root", type=Path, required=True)
    inspect_parser.add_argument("--donor-system-ext-root", type=Path, required=True)
    inspect_parser.add_argument("--report", type=Path)
    inspect_parser.set_defaults(handler=command_inspect)

    key_parser = subparsers.add_parser("init-dev-key", help="create or verify the local Case 4 development key")
    key_parser.add_argument("--key-dir", type=Path, required=True)
    key_parser.add_argument("--subject", default="/CN=XOS Lavender Development/O=Local Porting/")
    key_parser.set_defaults(handler=command_init_key)

    build_command = subparsers.add_parser("build", help="build or resume the development-signed Case 4 root")
    build_command.add_argument("--base-root", type=Path, required=True)
    build_command.add_argument("--donor-system-root", type=Path, required=True)
    build_command.add_argument("--donor-product-root", type=Path, required=True)
    build_command.add_argument("--donor-system-ext-root", type=Path, required=True)
    build_command.add_argument("--output-root", type=Path, required=True)
    build_command.add_argument("--development-key", type=Path, required=True)
    build_command.add_argument("--development-cert", type=Path, required=True)
    build_command.add_argument("--report", type=Path)
    build_command.set_defaults(handler=command_build)

    verify_parser = subparsers.add_parser("verify-output", help="re-verify a completed Case 4 output root")
    verify_parser.add_argument("--output-root", type=Path, required=True)
    verify_parser.add_argument("--development-cert", type=Path, required=True)
    verify_parser.add_argument("--state", type=Path)
    verify_parser.add_argument("--report", type=Path)
    verify_parser.set_defaults(handler=command_verify_output)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        profile, compatibility, port, summary = load_and_validate(
            args.profile,
            args.compatibility_profile,
            args.port_profile,
        )
        args.handler(profile, compatibility, port, summary, args)
    except (BuildError, apksign.ApkSignError) as exc:
        parser.exit(1, f"ERROR: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
