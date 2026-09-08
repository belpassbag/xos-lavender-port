#!/usr/bin/env python3
"""Plan and build the locked Case 4 XOS core development tree."""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import json
import os
from pathlib import Path, PurePosixPath
import sys
import tempfile
import tomllib


TOOLS_DIRECTORY = Path(__file__).resolve().parent
if str(TOOLS_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIRECTORY))

import compatctl  # noqa: E402


REPOSITORY_ROOT = TOOLS_DIRECTORY.parent
DEFAULT_PROFILE = REPOSITORY_ROOT / "config" / "pipeline.toml"
DEFAULT_COMPATIBILITY_PROFILE = REPOSITORY_ROOT / "config" / "compatibility.toml"
DEFAULT_PORT_PROFILE = REPOSITORY_ROOT / "config" / "port.toml"
LOCKED_PIPELINE_SHA256 = "6cffdd3beda43710d71d40e59c08a38c2fcf127c34307353c8b28237d012bf5a"


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
    _require(total_apks > 0, "input APK inventory is empty")

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
    except BuildError as exc:
        parser.exit(1, f"ERROR: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
