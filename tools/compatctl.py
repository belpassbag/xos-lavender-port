#!/usr/bin/env python3
"""Validate the locked Case 3 compatibility profile and recovered payloads."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import struct
import sys
import tempfile
import tomllib
import zipfile
import zlib


DEFAULT_PROFILE = Path(__file__).resolve().parents[1] / "config" / "compatibility.toml"
DEFAULT_PORT_PROFILE = Path(__file__).resolve().parents[1] / "config" / "port.toml"
LOCKED_PROFILE_SHA256 = "03c5553149b49aba127534a96a8420d2a2682590e79c3b40b9fedd43509847bd"
BUFFER_SIZE = 4 * 1024 * 1024
SHA256_LENGTH = 64

RES_STRING_POOL_TYPE = 0x0001
RES_XML_START_ELEMENT_TYPE = 0x0102
UTF8_FLAG = 1 << 8
NO_INDEX = 0xFFFFFFFF
TYPE_STRING = 0x03
TYPE_INT_DEC = 0x10
TYPE_INT_BOOLEAN = 0x12

APK_SIG_MAGIC = b"APK Sig Block 42"
APK_SIG_V2 = 0x7109871A
APK_SIG_V3 = 0xF05368C0
DEX_HEADER_SIZE = 0x70
DEX_ENDIAN_CONSTANT = 0x12345678
DEX_ARCHIVE_MEMBER = re.compile(r"^classes(?:[2-9][0-9]*)?\.dex$")
SAFE_INPUT_ID = re.compile(r"^[A-Za-z0-9_.-]+$")


class CompatibilityError(RuntimeError):
    """The compatibility evidence is malformed or does not match the lock."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise CompatibilityError(message)


def _read_toml(path: Path) -> dict:
    if path.is_symlink() or not path.is_file():
        raise CompatibilityError(f"profile is not a regular file: {path}")
    try:
        with path.open("rb") as source:
            return tomllib.load(source)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise CompatibilityError(f"cannot read profile {path}: {exc}") from exc


def canonical_digest(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(BUFFER_SIZE), b""):
                digest.update(chunk)
    except OSError as exc:
        raise CompatibilityError(f"cannot hash {path}: {exc}") from exc
    return digest.hexdigest()


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == SHA256_LENGTH
        and all(character in "0123456789abcdef" for character in value)
    )


def _locked_absolute_path(value: object, label: str) -> str:
    _require(isinstance(value, str) and value.startswith("/"), f"{label} must be absolute")
    path = PurePosixPath(value)
    _require(str(path) == value, f"{label} is not normalized: {value}")
    _require(".." not in path.parts and "." not in path.parts, f"unsafe {label}: {value}")
    return value


def _unique_table(rows: object, key: str, label: str) -> dict[str, dict]:
    _require(isinstance(rows, list) and rows, f"{label} must be a non-empty table array")
    result: dict[str, dict] = {}
    for row in rows:
        _require(isinstance(row, dict), f"invalid {label} row")
        identifier = row.get(key)
        _require(isinstance(identifier, str) and identifier, f"invalid {label} {key}")
        _require(identifier not in result, f"duplicate {label} {key}: {identifier}")
        result[identifier] = row
    return result


def validate_profile(profile: dict, port_profile: dict, enforce_lock: bool = True) -> dict:
    digest = canonical_digest(profile)
    if enforce_lock:
        _require(digest == LOCKED_PROFILE_SHA256, "compatibility profile digest is not locked")

    _require(profile.get("schema_version") == 1, "unsupported compatibility schema")
    _require(port_profile.get("schema_version") == 1, "unsupported port schema")
    project = profile.get("project", {})
    port_project = port_profile.get("project", {})
    base = port_profile.get("base", {})
    donor = port_profile.get("donor", {})
    _require(project.get("device") == base.get("device") == "lavender", "target mismatch")
    _require(project.get("donor") == donor.get("device"), "donor mismatch")
    for key in ("android_version", "sdk", "architecture"):
        _require(project.get(key) == port_project.get(key), f"project {key} mismatch")
    _require(
        project.get("port_profile_canonical_sha256") == canonical_digest(port_profile),
        "port profile digest mismatch",
    )

    images = _unique_table(profile.get("images"), "id", "image")
    expected_image_ids = {"base_system", "base_vendor", "donor_system", "donor_product", "donor_system_ext"}
    _require(set(images) == expected_image_ids, "image identity set mismatch")
    for identifier, image in images.items():
        for field in ("size", "block_count", "free_blocks", "block_size"):
            _require(isinstance(image.get(field), int) and image[field] > 0, f"invalid {identifier} {field}")
        _require(image["free_blocks"] < image["block_count"], f"invalid {identifier} free blocks")
        _require(image["block_size"] == 4096, f"unexpected {identifier} block size")
        _require(_is_sha256(image.get("sha256")), f"invalid {identifier} SHA-256")
    _require(images["base_system"]["size"] == base.get("system_partition_size"), "base system size mismatch")
    _require(images["base_vendor"]["size"] == base.get("vendor_partition_size"), "base vendor size mismatch")

    capacity = profile.get("capacity", {})
    used = {
        identifier: (image["block_count"] - image["free_blocks"]) * image["block_size"]
        for identifier, image in images.items()
    }
    _require(capacity.get("base_system_used") == used["base_system"], "base used-byte mismatch")
    _require(capacity.get("donor_system_used") == used["donor_system"], "donor used-byte mismatch")
    _require(capacity.get("target_filesystem_data_size") == base.get("system_filesystem_data_size"), "target data size mismatch")
    for partition in ("product", "system_ext"):
        measured = capacity.get(f"selected_{partition}_measured")
        upper = capacity.get(f"selected_{partition}_upper")
        _require(isinstance(measured, int) and measured > 0, f"invalid selected {partition} measurement")
        _require(isinstance(upper, int) and upper >= measured, f"selected {partition} exceeds upper bound")
    runtime_upper = capacity.get("selected_system_ext_runtime_upper")
    _require(isinstance(runtime_upper, int) and runtime_upper > 0, "invalid system_ext runtime upper bound")
    conservative = (
        capacity.get("base_system_used", -1)
        + capacity.get("donor_system_used", -1)
        + capacity.get("selected_product_upper", -1)
        + capacity.get("selected_system_ext_upper", -1)
        + runtime_upper
    )
    _require(capacity.get("conservative_total") == conservative, "capacity total mismatch")
    headroom = capacity["target_filesystem_data_size"] - conservative
    _require(capacity.get("headroom") == headroom, "capacity headroom mismatch")
    _require(headroom >= capacity.get("minimum_reserve", headroom + 1), "capacity reserve is not met")

    android = profile.get("android_compatibility", {})
    expected_abis = ["arm64-v8a", "armeabi-v7a", "armeabi"]
    _require(android.get("base_release") == android.get("donor_release") == 11, "Android release mismatch")
    _require(android.get("base_sdk") == android.get("donor_sdk") == 30, "Android SDK mismatch")
    _require(android.get("base_vendor_sdk") == 30, "base vendor SDK mismatch")
    _require(android.get("base_vendor_first_api_level") == 28, "base vendor first API mismatch")
    _require(android.get("base_abis") == expected_abis, "base ABI list mismatch")
    _require(android.get("donor_abis") == expected_abis, "donor ABI list mismatch")
    for key in ("base_system_build_prop_sha256", "donor_system_build_prop_sha256", "base_vendor_build_prop_sha256"):
        _require(_is_sha256(android.get(key)), f"invalid Android evidence hash: {key}")

    super_profile = profile.get("super", {})
    _require(super_profile.get("expanded_size") > super_profile.get("sparse_size", 0), "invalid super sizes")
    _require(_is_sha256(super_profile.get("sha256")), "invalid super SHA-256")
    _require(super_profile.get("logical_block_size") == 4096, "invalid LP block size")
    _require(super_profile.get("metadata_slots") == 3, "invalid LP metadata slot count")
    _require(super_profile.get("selected_b_partitions_are_empty") is True, "selected B partitions must be empty")

    vintf = profile.get("vintf", {})
    _require(vintf.get("preserve") == "base", "VINTF source must remain base")
    _require(vintf.get("target_manifest_level") == 3, "VINTF target level mismatch")
    _require(_is_sha256(vintf.get("matrix_level_3_sha256")), "invalid VINTF matrix hash")
    _require(vintf.get("base_and_donor_matrix_match") is True, "VINTF matrix equality not locked")

    selinux = profile.get("selinux", {})
    _require(selinux.get("preserve_base_cil_and_mappings") is True, "base SELinux policy must be preserved")
    _require(selinux.get("allow_new_policy_types") is False, "new SELinux types are forbidden")
    for key in ("plat_precompiled_sha256", "product_precompiled_sha256", "system_ext_precompiled_sha256"):
        _require(_is_sha256(selinux.get(key)), f"invalid SELinux hash: {key}")

    signers = profile.get("signers", {})
    _require(_is_sha256(signers.get("base_platform_sha256")), "invalid base signer hash")
    _require(_is_sha256(signers.get("xos_platform_sha256")), "invalid XOS signer hash")
    _require(signers.get("mixed_shared_uid_signers_forbidden") is True, "shared-UID signer guard missing")

    shared_uid_audit = profile.get("shared_uid_audit", {})
    expected_shared_uid_counts = {
        "base_apks_scanned": 107,
        "base_shared_uid_packages": 44,
        "donor_apks_scanned": 237,
        "donor_shared_uid_packages": 83,
        "parse_failures": 0,
    }
    for key, expected in expected_shared_uid_counts.items():
        _require(shared_uid_audit.get(key) == expected, f"shared-UID audit drift: {key}")
    _require(
        shared_uid_audit.get("selected_shared_uids") == ["android.uid.system", "android.uid.systemui"],
        "selected shared-UID set drift",
    )
    _require(
        shared_uid_audit.get("retained_conflicting_shared_uids") == ["android.uid.system"],
        "retained shared-UID conflict drift",
    )
    _require(
        shared_uid_audit.get("case4_strategy") == "unified-port-platform-signing",
        "shared-UID strategy drift",
    )
    for key in (
        "resign_included_platform_apks",
        "preserve_standalone_apk_signers",
        "preserve_apex_signers",
        "update_mac_permissions_signer",
        "verify_single_certificate_per_shared_uid",
        "remove_shared_uid_forbidden",
        "global_signature_bypass_forbidden",
        "key_selection_requires_approval",
    ):
        _require(shared_uid_audit.get(key) is True, f"shared-UID guard missing: {key}")

    layout = profile.get("layout", {})
    for key in ("preserve_base_system_as_root", "preserve_base_init", "preserve_base_fstab"):
        _require(layout.get(key) is True, f"layout guard missing: {key}")
    _require(layout.get("base_product_target") == "/system/product", "base product target mismatch")
    _require(layout.get("base_system_ext_target") == "/system/system_ext", "base system_ext target mismatch")
    for key in ("base_init_path", "base_fstab_path"):
        _locked_absolute_path(layout.get(key), key.replace("_", " "))
    for key in ("base_init_sha256", "base_fstab_sha256"):
        _require(_is_sha256(layout.get(key)), f"invalid layout evidence hash: {key}")

    selection = profile.get("selection", {})
    _require(selection.get("product_mode") == "allowlist-only", "product selection is not allowlist-only")
    _require(selection.get("system_ext_mode") == "allowlist-only", "system_ext selection is not allowlist-only")
    _require(selection.get("discard_preopt") is True, "preopt discard is not locked")
    product_paths = [_locked_absolute_path(path, "product path") for path in selection.get("product_paths", [])]
    system_ext_paths = [_locked_absolute_path(path, "system_ext path") for path in selection.get("system_ext_paths", [])]
    policy = port_profile.get("policy", {})
    _require(product_paths == policy.get("donor_product_package_allowlist"), "product allowlist drift")
    _require(system_ext_paths == policy.get("donor_system_ext_package_allowlist"), "system_ext allowlist drift")
    _require(selection.get("product_mode") == policy.get("donor_product_selection"), "product mode drift")
    _require(selection.get("system_ext_mode") == policy.get("donor_system_ext_selection"), "system_ext mode drift")

    exclusion = profile.get("exclusions", {})
    for key in (
        "retain_base_phone_shared_uid_group", "retain_base_qti_system_ext", "retain_base_bluetooth",
        "exclude_donor_phone_shared_uid_group", "exclude_donor_mtk_bluetooth",
        "exclude_donor_hardware_services", "exclude_donor_generated_rros",
    ):
        _require(exclusion.get(key) is True, f"exclusion guard missing: {key}")
    exclusion_paths = [_locked_absolute_path(path, "exclusion path") for path in exclusion.get("paths", [])]
    _require(exclusion_paths == policy.get("first_boot_exclusions"), "first-boot exclusion drift")

    expected_services = {
        "kolun": "activity_service", "gamemode_helper": "activity_service", "sand_accessor": "activity_service",
        "os_audio_change": "audio_service", "tran_appm": "system_config_service",
        "tran_resmonitor": "system_config_service", "tran_tranlog": "system_config_service",
        "tranlog_sub": "system_config_service", "tran_pwhub": "power_service",
    }
    _require(profile.get("service_types") == expected_services, "service-type map drift")

    required_kernel = {
        "CONFIG_BLK_DEV_LOOP=y", "CONFIG_DM_VERITY=y", "CONFIG_DM_VERITY_FEC=y",
        "CONFIG_EXT4_FS=y", "CONFIG_SECURITY_SELINUX=y",
    }
    kernel = profile.get("kernel", {})
    _require(set(kernel.get("required_builtins", [])) == required_kernel, "kernel requirement drift")
    _require(kernel.get("packaged_apex_payload_filesystem") == "ext4", "APEX filesystem mismatch")
    for key in ("base_boot_sha256", "compressed_kernel_sha256", "ikconfig_sha256"):
        _require(_is_sha256(kernel.get(key)), f"invalid kernel hash: {key}")
    _require(isinstance(kernel.get("compressed_kernel_size"), int) and kernel["compressed_kernel_size"] > 0, "invalid kernel size")

    apex_payloads = _unique_table(profile.get("apex_payloads"), "id", "APEX payload")
    _require(set(apex_payloads) == {"os_framework_apex", "kolun_apex"}, "APEX payload set drift")
    for identifier, payload in apex_payloads.items():
        for field in ("size", "block_count", "free_blocks", "block_size"):
            _require(isinstance(payload.get(field), int) and payload[field] > 0, f"invalid {identifier} {field}")
        _require(payload["free_blocks"] < payload["block_count"], f"invalid {identifier} free blocks")
        _require(payload["block_size"] == 4096, f"unexpected {identifier} block size")
        _require(_is_sha256(payload.get("sha256")), f"invalid {identifier} SHA-256")

    classpaths = profile.get("classpaths", {})
    _require(classpaths.get("strategy") == "donor-xos-runtime-plus-base-qti", "classpath strategy drift")
    _require(
        classpaths.get("custom_prefixes") == ["Lcom/mediatek/", "Lcom/transsion/", "Ltranssion/"],
        "custom DEX prefix drift",
    )
    required_donor = classpaths.get("required_donor_jars", [])
    required_base = classpaths.get("required_base_jars", [])
    _require(len(required_donor) == len(set(required_donor)), "duplicate donor classpath JAR")
    _require(len(required_base) == len(set(required_base)), "duplicate base classpath JAR")
    classpath_providers = _unique_table(profile.get("classpath_providers"), "id", "classpath provider")
    external_donor = {identifier for identifier, row in classpath_providers.items() if row.get("source") == "donor-system"}
    external_base = {identifier for identifier, row in classpath_providers.items() if row.get("source") == "base-system"}
    _require(external_donor == set(required_donor[:7]), "donor classpath provider set drift")
    _require(external_base == set(required_base), "base classpath provider set drift")
    for identifier, provider in classpath_providers.items():
        path = _locked_absolute_path(provider.get("path"), f"{identifier} provider path")
        _require(path.startswith("/system/framework/"), f"unsafe classpath provider path: {identifier}")
        _require(isinstance(provider.get("size"), int) and provider["size"] > 0, f"invalid provider size: {identifier}")
        _require(isinstance(provider.get("defined_classes"), int) and provider["defined_classes"] > 0, f"invalid provider class count: {identifier}")
        _require(_is_sha256(provider.get("sha256")), f"invalid provider SHA-256: {identifier}")

    packages = _unique_table(profile.get("packages"), "id", "package")
    expected_packages = set(policy.get("core_xos_packages", [])) | {
        item for item in policy.get("core_xos_dependencies", []) if item != "com.transsion.mi.os.framework"
    }
    _require(set(packages) == expected_packages, "selected package set drift")
    _require(sum(row.get("size", -1) for row in packages.values()) == selection.get("selected_apk_bytes"), "selected APK byte total mismatch")
    shared_uid_signers: dict[str, set[str]] = {}
    for identifier, package in packages.items():
        path = _locked_absolute_path(package.get("path"), f"{identifier} path")
        _require(path.startswith(("/product/", "/system_ext/")), f"unsafe package partition: {path}")
        _require(isinstance(package.get("package"), str) and package["package"], f"missing package name: {identifier}")
        _require(isinstance(package.get("size"), int) and package["size"] > 0, f"invalid package size: {identifier}")
        _require(_is_sha256(package.get("sha256")), f"invalid package SHA-256: {identifier}")
        _require(_is_sha256(package.get("certificate_sha256")), f"invalid package certificate: {identifier}")
        _require(package.get("signer") in {"xos-platform", "standalone"}, f"invalid signer class: {identifier}")
        if package["signer"] == "xos-platform":
            _require(package["certificate_sha256"] == signers["xos_platform_sha256"], f"XOS signer drift: {identifier}")
        else:
            _require(package["certificate_sha256"] != signers["xos_platform_sha256"], f"standalone signer drift: {identifier}")
        _require(isinstance(package.get("dex_scan"), bool), f"missing DEX scan policy: {identifier}")
        _require(package.get("custom_external_classes") == package.get("resolved_external_classes"), f"unresolved classes: {identifier}")
        shared_uid = package.get("shared_uid", "")
        _require(isinstance(shared_uid, str), f"invalid shared UID: {identifier}")
        if shared_uid:
            shared_uid_signers.setdefault(shared_uid, set()).add(package["signer"])
    _require(all(len(values) == 1 for values in shared_uid_signers.values()), "mixed selected shared-UID signers")

    runtimes = _unique_table(profile.get("runtime_dependencies"), "id", "runtime dependency")
    _require(set(runtimes) == {"os_framework_apex", "kolun_apex", "transsion_resources"}, "runtime dependency set drift")
    for identifier, runtime in runtimes.items():
        _locked_absolute_path(runtime.get("path"), f"{identifier} path")
        _require(isinstance(runtime.get("size"), int) and runtime["size"] > 0, f"invalid runtime size: {identifier}")
        state = runtime.get("identity_state")
        _require(state in {"pending-fresh-verification", "verified"}, f"invalid runtime state: {identifier}")
        if state == "verified":
            _require(_is_sha256(runtime.get("sha256")), f"missing verified runtime hash: {identifier}")
            _require(isinstance(runtime.get("package"), str) and runtime["package"], f"missing runtime package: {identifier}")
            _require(_is_sha256(runtime.get("certificate_sha256")), f"missing runtime certificate: {identifier}")

    providers = _unique_table(profile.get("embedded_providers"), "id", "embedded provider")
    expected_embedded = {"os-framework.jar", "os-services.jar", "kolun.jar", "kolunlibrary.jar", "proxy.jar", "proxy_sprd.jar"}
    _require(set(providers) == expected_embedded, "embedded provider set drift")
    for identifier, provider in providers.items():
        _require(provider.get("container") in runtimes, f"unknown provider container: {identifier}")
        path = _locked_absolute_path(provider.get("path"), f"{identifier} embedded path")
        _require(path.startswith("/javalib/"), f"unsafe embedded provider path: {identifier}")
        _require(isinstance(provider.get("size"), int) and provider["size"] > 0, f"invalid provider size: {identifier}")
        _require(isinstance(provider.get("defined_classes"), int) and provider["defined_classes"] > 0, f"invalid provider class count: {identifier}")
        _require(isinstance(provider.get("classpath_required"), bool), f"invalid classpath requirement: {identifier}")
        state = provider.get("identity_state")
        _require(state in {"pending-fresh-verification", "verified"}, f"invalid provider state: {identifier}")
        if state == "verified":
            _require(_is_sha256(provider.get("sha256")), f"missing verified provider hash: {identifier}")
    embedded_required = {identifier for identifier, row in providers.items() if row["classpath_required"]}
    _require(embedded_required == set(required_donor[7:]), "embedded classpath provider set drift")

    native_libraries = _unique_table(profile.get("native_libraries"), "id", "native library")
    _require(len(native_libraries) == 5, "native library set drift")
    for identifier, library in native_libraries.items():
        _require(library.get("package") in packages, f"unknown native package: {identifier}")
        member = library.get("member")
        _require(isinstance(member, str) and re.fullmatch(r"lib/[^/]+/[^/]+\.so", member), f"invalid native member: {identifier}")
        _require(library.get("elf_class") in {32, 64}, f"invalid ELF class: {identifier}")
        _require(library.get("machine") in {"ARM", "AArch64"}, f"invalid ELF machine: {identifier}")
        _require(isinstance(library.get("size"), int) and library["size"] > 0, f"invalid native size: {identifier}")
        _require(_is_sha256(library.get("sha256")), f"invalid native SHA-256: {identifier}")
        needed = library.get("needed")
        _require(isinstance(needed, list) and needed == sorted(set(needed)) and needed, f"invalid DT_NEEDED set: {identifier}")

    native = profile.get("native_compatibility", {})
    _require(native.get("base_abis") == expected_abis, "native base ABI drift")
    provided = native.get("base_system_provides")
    _require(isinstance(provided, list) and provided == sorted(set(provided)), "invalid native provider set")
    _require(native.get("all_needed_present_in_base_32_and_64") is True, "native base coverage is not locked")
    _require(
        {name for row in native_libraries.values() for name in row["needed"]} <= set(provided),
        "native dependency missing from base provider set",
    )

    pending_runtimes = sum(row.get("identity_state") != "verified" for row in runtimes.values())
    pending_providers = sum(row.get("identity_state") != "verified" for row in providers.values())
    return {
        "profile_sha256": digest,
        "images": len(images),
        "packages": len(packages),
        "runtime_dependencies": len(runtimes),
        "embedded_providers": len(providers),
        "classpath_providers": len(classpath_providers),
        "native_libraries": len(native_libraries),
        "pending_identities": pending_runtimes + pending_providers,
        "base_apks_scanned": shared_uid_audit["base_apks_scanned"],
        "donor_apks_scanned": shared_uid_audit["donor_apks_scanned"],
        "shared_uid_conflicts": len(shared_uid_audit["retained_conflicting_shared_uids"]),
        "headroom": headroom,
        "minimum_reserve": capacity["minimum_reserve"],
    }


def load_and_validate(profile_path: Path, port_path: Path, enforce_lock: bool = True) -> tuple[dict, dict, dict]:
    profile = _read_toml(profile_path)
    port_profile = _read_toml(port_path)
    summary = validate_profile(profile, port_profile, enforce_lock=enforce_lock)
    return profile, port_profile, summary


def ext4_metrics(path: Path) -> dict:
    if path.is_symlink() or not path.is_file():
        raise CompatibilityError(f"image is not a regular file: {path}")
    try:
        with path.open("rb") as source:
            source.seek(1024)
            superblock = source.read(1024)
    except OSError as exc:
        raise CompatibilityError(f"cannot read ext4 superblock from {path}: {exc}") from exc
    _require(len(superblock) == 1024, f"truncated ext4 superblock: {path}")
    _require(struct.unpack_from("<H", superblock, 0x38)[0] == 0xEF53, f"not an ext filesystem: {path}")
    blocks = struct.unpack_from("<I", superblock, 0x04)[0]
    free_blocks = struct.unpack_from("<I", superblock, 0x0C)[0]
    log_block_size = struct.unpack_from("<I", superblock, 0x18)[0]
    incompat = struct.unpack_from("<I", superblock, 0x60)[0]
    if incompat & 0x80:
        blocks |= struct.unpack_from("<I", superblock, 0x150)[0] << 32
        free_blocks |= struct.unpack_from("<I", superblock, 0x158)[0] << 32
    block_size = 1024 << log_block_size
    _require(block_size in {1024, 2048, 4096, 8192, 16384, 32768, 65536}, f"invalid ext block size: {path}")
    _require(0 < free_blocks < blocks, f"invalid ext block counts: {path}")
    return {
        "block_count": blocks,
        "free_blocks": free_blocks,
        "block_size": block_size,
        "used_bytes": (blocks - free_blocks) * block_size,
    }


def verify_image(path: Path, expected: dict) -> dict:
    actual = {
        "path": str(path),
        "size": path.stat().st_size if path.is_file() else -1,
        "sha256": sha256_file(path),
        **ext4_metrics(path),
    }
    for field in ("size", "sha256", "block_count", "free_blocks", "block_size"):
        _require(actual[field] == expected[field], f"{expected['id']} {field} mismatch")
    actual["id"] = expected["id"]
    actual["status"] = "verified"
    return actual


def _decode_length8(data: bytes, offset: int) -> tuple[int, int]:
    _require(offset < len(data), "truncated UTF-8 string length")
    first = data[offset]
    if first & 0x80:
        _require(offset + 1 < len(data), "truncated UTF-8 string length")
        return ((first & 0x7F) << 8) | data[offset + 1], offset + 2
    return first, offset + 1


def _decode_length16(data: bytes, offset: int) -> tuple[int, int]:
    _require(offset + 2 <= len(data), "truncated UTF-16 string length")
    first = struct.unpack_from("<H", data, offset)[0]
    if first & 0x8000:
        _require(offset + 4 <= len(data), "truncated UTF-16 string length")
        second = struct.unpack_from("<H", data, offset + 2)[0]
        return ((first & 0x7FFF) << 16) | second, offset + 4
    return first, offset + 2


def _string_pool(chunk: bytes) -> list[str]:
    _require(len(chunk) >= 28, "truncated Android string pool")
    chunk_type, header_size, chunk_size = struct.unpack_from("<HHI", chunk, 0)
    _require(chunk_type == RES_STRING_POOL_TYPE and chunk_size == len(chunk), "invalid Android string pool")
    string_count, style_count, flags, strings_start, styles_start = struct.unpack_from("<IIIII", chunk, 8)
    del style_count, styles_start
    _require(header_size >= 28 and header_size + string_count * 4 <= len(chunk), "invalid string-pool header")
    result: list[str] = []
    for index in range(string_count):
        relative = struct.unpack_from("<I", chunk, header_size + index * 4)[0]
        offset = strings_start + relative
        _require(offset < len(chunk), "string-pool offset exceeds chunk")
        if flags & UTF8_FLAG:
            _, offset = _decode_length8(chunk, offset)
            byte_length, offset = _decode_length8(chunk, offset)
            _require(offset + byte_length < len(chunk), "truncated UTF-8 string")
            result.append(chunk[offset : offset + byte_length].decode("utf-8"))
        else:
            char_length, offset = _decode_length16(chunk, offset)
            byte_length = char_length * 2
            _require(offset + byte_length + 2 <= len(chunk), "truncated UTF-16 string")
            result.append(chunk[offset : offset + byte_length].decode("utf-16le"))
    return result


def _string(strings: list[str], index: int) -> str | None:
    if index == NO_INDEX:
        return None
    _require(0 <= index < len(strings), "Android XML string index exceeds pool")
    return strings[index]


def parse_android_manifest(data: bytes) -> dict:
    _require(len(data) >= 8, "truncated Android binary XML")
    xml_type, header_size, xml_size = struct.unpack_from("<HHI", data, 0)
    _require(xml_type == 0x0003 and header_size >= 8 and xml_size <= len(data), "invalid Android binary XML")
    strings: list[str] | None = None
    elements: list[tuple[str, dict[str, object]]] = []
    offset = header_size
    while offset < xml_size:
        _require(offset + 8 <= xml_size, "truncated Android XML chunk")
        chunk_type, chunk_header, chunk_size = struct.unpack_from("<HHI", data, offset)
        _require(chunk_header >= 8 and chunk_size >= chunk_header and offset + chunk_size <= xml_size, "invalid Android XML chunk")
        chunk = data[offset : offset + chunk_size]
        if chunk_type == RES_STRING_POOL_TYPE:
            _require(strings is None, "duplicate Android XML string pool")
            strings = _string_pool(chunk)
        elif chunk_type == RES_XML_START_ELEMENT_TYPE:
            _require(strings is not None, "start element precedes string pool")
            _require(chunk_header >= 16 and len(chunk) >= 36, "truncated Android XML start element")
            name_index = struct.unpack_from("<I", chunk, 20)[0]
            attribute_start, attribute_size, attribute_count = struct.unpack_from("<HHH", chunk, 24)
            _require(attribute_size >= 20, "invalid Android XML attribute size")
            base = 16 + attribute_start
            _require(base + attribute_count * attribute_size <= len(chunk), "attributes exceed Android XML chunk")
            attributes: dict[str, object] = {}
            for index in range(attribute_count):
                item = base + index * attribute_size
                name = _string(strings, struct.unpack_from("<I", chunk, item + 4)[0])
                raw_index = struct.unpack_from("<I", chunk, item + 8)[0]
                value_type = chunk[item + 15]
                value_data = struct.unpack_from("<I", chunk, item + 16)[0]
                raw_value = _string(strings, raw_index)
                if raw_value is not None:
                    value: object = raw_value
                elif value_type == TYPE_STRING:
                    value = _string(strings, value_data)
                elif value_type == TYPE_INT_BOOLEAN:
                    value = bool(value_data)
                elif value_type == TYPE_INT_DEC:
                    value = value_data
                else:
                    value = value_data
                _require(name is not None, "Android XML attribute has no name")
                attributes[name] = value
            element_name = _string(strings, name_index)
            _require(element_name is not None, "Android XML element has no name")
            elements.append((element_name, attributes))
        offset += chunk_size
    _require(strings is not None, "Android XML has no string pool")
    manifests = [attrs for name, attrs in elements if name == "manifest"]
    _require(len(manifests) == 1, "Android manifest root count is not one")
    root = manifests[0]
    uses_libraries = sorted(
        str(attrs["name"])
        for name, attrs in elements
        if name == "uses-library" and "name" in attrs
    )
    uses_permissions = sorted(
        {
            str(attrs["name"])
            for name, attrs in elements
            if name in {"uses-permission", "uses-permission-sdk-23"} and "name" in attrs
        }
    )
    overlays = [attrs for name, attrs in elements if name == "overlay"]
    _require(len(overlays) <= 1, "multiple overlay elements are unsupported")
    overlay = overlays[0] if overlays else {}
    return {
        "package": root.get("package", ""),
        "shared_uid": root.get("sharedUserId", ""),
        "uses_libraries": uses_libraries,
        "uses_permissions": uses_permissions,
        "overlay_target": overlay.get("targetPackage"),
        "overlay_priority": overlay.get("priority"),
        "overlay_is_static": overlay.get("isStatic"),
    }


def _lp(data: bytes, offset: int) -> tuple[bytes, int]:
    _require(offset + 4 <= len(data), "truncated APK signing length")
    length = struct.unpack_from("<I", data, offset)[0]
    start = offset + 4
    end = start + length
    _require(end <= len(data), "APK signing value exceeds block")
    return data[start:end], end


def _apk_signing_certificate(apk: bytes) -> bytes | None:
    eocd = apk.rfind(b"PK\x05\x06", max(0, len(apk) - 65557))
    if eocd < 0 or eocd + 22 > len(apk):
        return None
    central_offset = struct.unpack_from("<I", apk, eocd + 16)[0]
    if central_offset < 24 or apk[central_offset - 16 : central_offset] != APK_SIG_MAGIC:
        return None
    size = struct.unpack_from("<Q", apk, central_offset - 24)[0]
    block_start = central_offset - (size + 8)
    _require(0 <= block_start < central_offset - 24, "invalid APK signing-block offset")
    _require(struct.unpack_from("<Q", apk, block_start)[0] == size, "APK signing-block size mismatch")
    cursor = block_start + 8
    end = central_offset - 24
    while cursor < end:
        _require(cursor + 8 <= end, "truncated APK signing pair")
        pair_size = struct.unpack_from("<Q", apk, cursor)[0]
        cursor += 8
        _require(pair_size >= 4 and cursor + pair_size <= end, "invalid APK signing pair")
        pair_id = struct.unpack_from("<I", apk, cursor)[0]
        value = apk[cursor + 4 : cursor + pair_size]
        cursor += pair_size
        if pair_id not in {APK_SIG_V2, APK_SIG_V3}:
            continue
        signers, _ = _lp(value, 0)
        signer, _ = _lp(signers, 0)
        signed_data, _ = _lp(signer, 0)
        _, position = _lp(signed_data, 0)
        certificates, _ = _lp(signed_data, position)
        certificate, _ = _lp(certificates, 0)
        _require(certificate.startswith(b"0"), "APK signer certificate is not DER")
        return certificate
    return None


def _der_length(data: bytes, offset: int) -> tuple[int, int]:
    _require(offset < len(data), "truncated DER length")
    first = data[offset]
    if first < 0x80:
        return first, offset + 1
    count = first & 0x7F
    _require(0 < count <= 4 and offset + 1 + count <= len(data), "invalid DER length")
    value = int.from_bytes(data[offset + 1 : offset + 1 + count], "big")
    return value, offset + 1 + count


def _der_tlv(data: bytes, offset: int) -> tuple[int, int, int, int]:
    _require(offset < len(data), "truncated DER tag")
    tag = data[offset]
    length, content_start = _der_length(data, offset + 1)
    end = content_start + length
    _require(end <= len(data), "DER value exceeds container")
    return tag, content_start, end, end


def _pkcs7_certificate(data: bytes) -> bytes | None:
    try:
        tag, outer_start, outer_end, _ = _der_tlv(data, 0)
        _require(tag == 0x30 and outer_end == len(data), "invalid PKCS#7 wrapper")
        _, _, _, cursor = _der_tlv(data, outer_start)
        tag, explicit_start, explicit_end, _ = _der_tlv(data, cursor)
        _require(tag == 0xA0, "PKCS#7 signedData wrapper missing")
        tag, signed_start, signed_end, _ = _der_tlv(data, explicit_start)
        _require(tag == 0x30 and signed_end == explicit_end, "invalid PKCS#7 signedData")
        cursor = signed_start
        for _ in range(3):
            _, _, _, cursor = _der_tlv(data, cursor)
        tag, certs_start, certs_end, _ = _der_tlv(data, cursor)
        _require(tag == 0xA0, "PKCS#7 certificate set missing")
        cert_tag, _, _, cert_end = _der_tlv(data, certs_start)
        _require(cert_tag == 0x30 and cert_end <= certs_end, "invalid PKCS#7 certificate")
        return data[certs_start:cert_end]
    except CompatibilityError:
        return None


def apk_report(path: Path) -> dict:
    if path.is_symlink() or not path.is_file():
        raise CompatibilityError(f"APK is not a regular file: {path}")
    try:
        apk_bytes = path.read_bytes()
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()
            _require(len(names) == len(set(names)), f"duplicate APK member: {path}")
            _require("AndroidManifest.xml" in names, f"APK manifest missing: {path}")
            manifest = parse_android_manifest(archive.read("AndroidManifest.xml"))
            abis = sorted({name.split("/", 2)[1] for name in names if name.startswith("lib/") and name.count("/") >= 2})
            certificate = _apk_signing_certificate(apk_bytes)
            if certificate is None:
                signature_names = sorted(
                    name for name in names
                    if name.upper().startswith("META-INF/") and name.upper().endswith((".RSA", ".DSA", ".EC"))
                )
                _require(signature_names, f"APK signer certificate missing: {path}")
                certificate = _pkcs7_certificate(archive.read(signature_names[0]))
            _require(certificate is not None, f"APK signer certificate cannot be parsed: {path}")
    except (OSError, zipfile.BadZipFile, UnicodeDecodeError) as exc:
        raise CompatibilityError(f"cannot inspect APK {path}: {exc}") from exc
    return {
        "path": str(path),
        "size": path.stat().st_size,
        "sha256": hashlib.sha256(apk_bytes).hexdigest(),
        "certificate_sha256": hashlib.sha256(certificate).hexdigest(),
        "abis": abis,
        **manifest,
    }


def _nul_terminated_string(data: bytes, offset: int, label: str) -> str:
    _require(0 <= offset < len(data), f"{label} offset exceeds string table")
    end = data.find(b"\0", offset)
    _require(end >= 0, f"unterminated {label}")
    try:
        return data[offset:end].decode("ascii")
    except UnicodeDecodeError as exc:
        raise CompatibilityError(f"non-ASCII {label}") from exc


def elf_report(data: bytes) -> dict:
    _require(len(data) >= 52 and data[:4] == b"\x7fELF", "invalid ELF header")
    elf_class = data[4]
    _require(elf_class in {1, 2}, "unsupported ELF class")
    _require(data[5] == 1, "unsupported ELF byte order")
    _require(data[6] == 1, "unsupported ELF version")
    machine_value = struct.unpack_from("<H", data, 18)[0]
    machines = {40: "ARM", 183: "AArch64"}
    _require(machine_value in machines, "unsupported ELF machine")

    if elf_class == 1:
        section_offset = struct.unpack_from("<I", data, 32)[0]
        header_size = struct.unpack_from("<H", data, 40)[0]
        section_entry_size = struct.unpack_from("<H", data, 46)[0]
        section_count = struct.unpack_from("<H", data, 48)[0]
        section_format = "<IIIIIIIIII"
        minimum_section_size = 40
        dynamic_format = "<iI"
        minimum_dynamic_size = 8
        reported_class = 32
    else:
        _require(len(data) >= 64, "truncated ELF64 header")
        section_offset = struct.unpack_from("<Q", data, 40)[0]
        header_size = struct.unpack_from("<H", data, 52)[0]
        section_entry_size = struct.unpack_from("<H", data, 58)[0]
        section_count = struct.unpack_from("<H", data, 60)[0]
        section_format = "<IIQQQQIIQQ"
        minimum_section_size = 64
        dynamic_format = "<qQ"
        minimum_dynamic_size = 16
        reported_class = 64

    _require(header_size >= (52 if elf_class == 1 else 64), "invalid ELF header size")
    _require(section_count > 0, "ELF extended section counts are unsupported")
    _require(section_entry_size >= minimum_section_size, "invalid ELF section-header size")
    _require(section_offset + section_count * section_entry_size <= len(data), "ELF section table exceeds file")
    sections = []
    for index in range(section_count):
        fields = struct.unpack_from(section_format, data, section_offset + index * section_entry_size)
        section = {
            "type": fields[1],
            "offset": fields[4],
            "size": fields[5],
            "link": fields[6],
            "entry_size": fields[9],
        }
        if section["type"] != 8:  # SHT_NOBITS occupies memory but has no file payload.
            _require(section["offset"] + section["size"] <= len(data), "ELF section exceeds file")
        sections.append(section)

    dynamic_sections = [section for section in sections if section["type"] == 6]
    _require(len(dynamic_sections) == 1, "ELF dynamic section count is not one")
    dynamic = dynamic_sections[0]
    _require(dynamic["link"] < len(sections), "ELF dynamic string-table link exceeds sections")
    strings_section = sections[dynamic["link"]]
    _require(strings_section["type"] == 3, "ELF dynamic section does not link to a string table")
    strings = data[strings_section["offset"] : strings_section["offset"] + strings_section["size"]]
    entry_size = dynamic["entry_size"] or minimum_dynamic_size
    _require(entry_size >= minimum_dynamic_size and dynamic["size"] % entry_size == 0, "invalid ELF dynamic entry size")
    needed = []
    saw_null = False
    for offset in range(dynamic["offset"], dynamic["offset"] + dynamic["size"], entry_size):
        tag, value = struct.unpack_from(dynamic_format, data, offset)
        if tag == 0:
            saw_null = True
            break
        if tag == 1:
            needed.append(_nul_terminated_string(strings, value, "ELF DT_NEEDED name"))
    _require(saw_null, "ELF dynamic section has no terminator")
    _require(needed, "ELF contains no DT_NEEDED entries")
    _require(len(needed) == len(set(needed)), "duplicate ELF DT_NEEDED entry")
    return {"elf_class": reported_class, "machine": machines[machine_value], "needed": sorted(needed)}


def apk_native_report(path: Path) -> list[dict]:
    if path.is_symlink() or not path.is_file():
        raise CompatibilityError(f"APK is not a regular file: {path}")
    try:
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()
            _require(len(names) == len(set(names)), f"duplicate APK member: {path}")
            native_names = sorted(
                name for name in names
                if re.fullmatch(r"lib/[^/]+/[^/]+\.so", name) is not None
            )
            result = []
            for name in native_names:
                payload = archive.read(name)
                result.append(
                    {
                        "member": name,
                        "size": len(payload),
                        "sha256": hashlib.sha256(payload).hexdigest(),
                        **elf_report(payload),
                    }
                )
            return result
    except (OSError, zipfile.BadZipFile) as exc:
        raise CompatibilityError(f"cannot inspect native APK payload {path}: {exc}") from exc


def _uleb128(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    for index in range(5):
        _require(offset < len(data), "truncated DEX ULEB128")
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << (index * 7)
        if not byte & 0x80:
            _require(index < 4 or byte <= 0x0F, "DEX ULEB128 exceeds 32 bits")
            return value, offset
    raise CompatibilityError("DEX ULEB128 exceeds five bytes")


def _dex_table(data: bytes, size_offset: int, item_size: int, label: str) -> tuple[int, int]:
    size, offset = struct.unpack_from("<II", data, size_offset)
    _require(size == 0 or offset >= DEX_HEADER_SIZE, f"invalid DEX {label} offset")
    _require(offset + size * item_size <= len(data), f"DEX {label} exceeds file")
    return size, offset


def _decode_dex_mutf8(data: bytes) -> tuple[str, int]:
    units: list[int] = []
    cursor = 0
    while cursor < len(data):
        first = data[cursor]
        cursor += 1
        if 0 < first < 0x80:
            units.append(first)
            continue
        if 0xC0 <= first <= 0xDF:
            _require(cursor < len(data), "truncated DEX MUTF-8 sequence")
            second = data[cursor]
            cursor += 1
            _require(second & 0xC0 == 0x80, "invalid DEX MUTF-8 continuation")
            unit = ((first & 0x1F) << 6) | (second & 0x3F)
            _require(unit >= 0x80 or (first == 0xC0 and second == 0x80), "overlong DEX MUTF-8 sequence")
            units.append(unit)
            continue
        if 0xE0 <= first <= 0xEF:
            _require(cursor + 1 < len(data), "truncated DEX MUTF-8 sequence")
            second, third = data[cursor], data[cursor + 1]
            cursor += 2
            _require(
                second & 0xC0 == 0x80 and third & 0xC0 == 0x80,
                "invalid DEX MUTF-8 continuation",
            )
            unit = ((first & 0x0F) << 12) | ((second & 0x3F) << 6) | (third & 0x3F)
            _require(unit >= 0x800, "overlong DEX MUTF-8 sequence")
            units.append(unit)
            continue
        raise CompatibilityError("invalid DEX MUTF-8 leading byte")

    encoded_units = b"".join(struct.pack("<H", unit) for unit in units)
    return encoded_units.decode("utf-16-le", errors="surrogatepass"), len(units)


def _dex_string(data: bytes, offset: int) -> str:
    utf16_size, cursor = _uleb128(data, offset)
    end = data.find(b"\0", cursor)
    _require(end >= 0, "unterminated DEX string")
    try:
        value, decoded_units = _decode_dex_mutf8(data[cursor:end])
    except UnicodeDecodeError as exc:
        raise CompatibilityError("invalid DEX MUTF-8 surrogate sequence") from exc
    _require(decoded_units == utf16_size, "DEX string UTF-16 size mismatch")
    return value


def _object_descriptor(descriptor: str) -> str | None:
    while descriptor.startswith("["):
        descriptor = descriptor[1:]
    if descriptor.startswith("L") and descriptor.endswith(";") and len(descriptor) > 2:
        return descriptor
    return None


def dex_inventory(data: bytes) -> dict[str, set[str]]:
    _require(len(data) >= DEX_HEADER_SIZE, "truncated DEX header")
    _require(data[:4] == b"dex\n" and data[7] == 0, "invalid DEX magic")
    _require(data[4:7].isdigit(), "invalid DEX version")
    file_size, header_size, endian_tag = struct.unpack_from("<III", data, 0x20)
    _require(file_size == len(data), "DEX file-size field mismatch")
    _require(header_size == DEX_HEADER_SIZE, "unsupported DEX header size")
    _require(endian_tag == DEX_ENDIAN_CONSTANT, "unsupported DEX endian tag")

    string_count, string_offset = _dex_table(data, 0x38, 4, "string IDs")
    type_count, type_offset = _dex_table(data, 0x40, 4, "type IDs")
    class_count, class_offset = _dex_table(data, 0x60, 32, "class definitions")

    strings = []
    for index in range(string_count):
        value_offset = struct.unpack_from("<I", data, string_offset + index * 4)[0]
        _require(0 < value_offset < len(data), "DEX string-data offset exceeds file")
        strings.append(_dex_string(data, value_offset))

    descriptors = []
    for index in range(type_count):
        string_index = struct.unpack_from("<I", data, type_offset + index * 4)[0]
        _require(string_index < len(strings), "DEX type descriptor index exceeds strings")
        descriptors.append(strings[string_index])

    defined: set[str] = set()
    for index in range(class_count):
        type_index = struct.unpack_from("<I", data, class_offset + index * 32)[0]
        _require(type_index < len(descriptors), "DEX class index exceeds types")
        descriptor = _object_descriptor(descriptors[type_index])
        _require(descriptor is not None, "DEX class definition is not an object type")
        _require(descriptor not in defined, f"duplicate DEX class definition: {descriptor}")
        defined.add(descriptor)

    referenced = {
        normalized
        for descriptor in descriptors
        if (normalized := _object_descriptor(descriptor)) is not None
    }
    return {"defined": defined, "referenced": referenced}


def archive_dex_inventory(path: Path) -> dict[str, set[str]]:
    if path.is_symlink() or not path.is_file():
        raise CompatibilityError(f"DEX archive is not a regular file: {path}")
    try:
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()
            _require(len(names) == len(set(names)), f"duplicate DEX archive member: {path}")
            dex_names = sorted(name for name in names if DEX_ARCHIVE_MEMBER.fullmatch(name))
            _require(dex_names, f"DEX archive contains no classes*.dex: {path}")
            defined: set[str] = set()
            referenced: set[str] = set()
            for name in dex_names:
                inventory = dex_inventory(archive.read(name))
                duplicates = defined & inventory["defined"]
                if duplicates:
                    raise CompatibilityError(
                        f"duplicate class across DEX members in {path}: {sorted(duplicates)[0]}"
                    )
                defined.update(inventory["defined"])
                referenced.update(inventory["referenced"])
    except (OSError, zipfile.BadZipFile) as exc:
        raise CompatibilityError(f"cannot inspect DEX archive {path}: {exc}") from exc
    return {"defined": defined, "referenced": referenced}


def _named_paths(values: list[str], label: str) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for value in values:
        identifier, separator, raw_path = value.partition("=")
        _require(separator == "=" and SAFE_INPUT_ID.fullmatch(identifier) is not None, f"invalid {label}: {value}")
        _require(identifier not in result, f"duplicate {label} identifier: {identifier}")
        _require(bool(raw_path), f"missing {label} path: {identifier}")
        result[identifier] = Path(raw_path)
    _require(result, f"at least one {label} is required")
    return result


def dex_resolution_report(
    packages: dict[str, Path],
    providers: dict[str, Path],
    custom_prefixes: list[str],
) -> dict:
    _require(custom_prefixes, "at least one custom DEX descriptor prefix is required")
    _require(
        all(prefix.startswith("L") and "/" in prefix and not prefix.endswith(";") for prefix in custom_prefixes),
        "invalid custom DEX descriptor prefix",
    )
    _require(len(custom_prefixes) == len(set(custom_prefixes)), "duplicate custom DEX descriptor prefix")

    provider_classes: dict[str, set[str]] = {}
    class_providers: dict[str, list[str]] = {}
    for identifier, path in sorted(providers.items()):
        classes = archive_dex_inventory(path)["defined"]
        provider_classes[identifier] = classes
        for descriptor in classes:
            class_providers.setdefault(descriptor, []).append(identifier)

    package_reports = []
    unresolved_total = 0
    for identifier, path in sorted(packages.items()):
        inventory = archive_dex_inventory(path)
        external = inventory["referenced"] - inventory["defined"]
        custom = sorted(
            descriptor for descriptor in external
            if any(descriptor.startswith(prefix) for prefix in custom_prefixes)
        )
        resolved = {
            descriptor: class_providers[descriptor]
            for descriptor in custom
            if descriptor in class_providers
        }
        unresolved = [descriptor for descriptor in custom if descriptor not in class_providers]
        unresolved_total += len(unresolved)
        package_reports.append(
            {
                "id": identifier,
                "path": str(path),
                "defined_classes": len(inventory["defined"]),
                "referenced_classes": len(inventory["referenced"]),
                "custom_external_classes": custom,
                "resolved_external_classes": resolved,
                "unresolved_external_classes": unresolved,
            }
        )

    return {
        "status": "verified" if unresolved_total == 0 else "unresolved",
        "custom_prefixes": sorted(custom_prefixes),
        "providers": [
            {"id": identifier, "path": str(providers[identifier]), "defined_classes": len(provider_classes[identifier])}
            for identifier in sorted(providers)
        ],
        "packages": package_reports,
        "unresolved_external_classes": unresolved_total,
    }


def boot_kernel_report(path: Path) -> dict:
    if path.is_symlink() or not path.is_file():
        raise CompatibilityError(f"boot image is not a regular file: {path}")
    try:
        boot = path.read_bytes()
    except OSError as exc:
        raise CompatibilityError(f"cannot read boot image {path}: {exc}") from exc
    _require(len(boot) >= 44 and boot[:8] == b"ANDROID!", "invalid Android boot image")
    kernel_size = struct.unpack_from("<I", boot, 8)[0]
    page_size = struct.unpack_from("<I", boot, 36)[0]
    _require(page_size in {2048, 4096, 8192, 16384, 32768, 65536}, "invalid boot page size")
    _require(kernel_size > 0 and page_size + kernel_size <= len(boot), "boot kernel exceeds image")
    kernel = boot[page_size : page_size + kernel_size]
    _require(kernel.startswith(b"\x1f\x8b"), "boot kernel is not gzip-compressed")
    try:
        decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
        expanded = decompressor.decompress(kernel) + decompressor.flush()
    except zlib.error as exc:
        raise CompatibilityError(f"cannot decompress boot kernel: {exc}") from exc
    _require(decompressor.eof, "truncated gzip kernel")
    start = expanded.find(b"IKCFG_ST")
    end = expanded.find(b"IKCFG_ED", start + 8)
    _require(start >= 0 and end > start and expanded.find(b"IKCFG_ST", start + 1) < 0, "kernel IKCONFIG markers invalid")
    packed_config = expanded[start + 8 : end]
    try:
        config_bytes = zlib.decompress(packed_config, 16 + zlib.MAX_WBITS)
        config_text = config_bytes.decode("utf-8")
    except (zlib.error, UnicodeDecodeError) as exc:
        raise CompatibilityError(f"cannot decode kernel IKCONFIG: {exc}") from exc
    return {
        "path": str(path),
        "boot_sha256": hashlib.sha256(boot).hexdigest(),
        "kernel_size": kernel_size,
        "kernel_sha256": hashlib.sha256(kernel).hexdigest(),
        "expanded_kernel_size": len(expanded),
        "appended_dtb_size": len(decompressor.unused_data),
        "ikconfig_sha256": hashlib.sha256(config_bytes).hexdigest(),
        "config_lines": set(config_text.splitlines()),
    }


def _property_file(path: Path) -> dict[str, str]:
    if path.is_symlink() or not path.is_file():
        raise CompatibilityError(f"property file is not regular: {path}")
    result: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise CompatibilityError(f"cannot read property file {path}: {exc}") from exc
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        _require(separator == "=" and key, f"invalid property in {path}: {key}")
        if key in result:
            _require(result[key] == value, f"conflicting duplicate property in {path}: {key}")
        result[key] = value
    return result


def _service_contexts(paths: list[Path]) -> dict[str, str]:
    result: dict[str, str] = {}
    for path in paths:
        if not path.exists():
            continue
        _require(path.is_file() and not path.is_symlink(), f"invalid service-context file: {path}")
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError) as exc:
            raise CompatibilityError(f"cannot read service contexts {path}: {exc}") from exc
        for raw in lines:
            line = raw.partition("#")[0].strip()
            if not line:
                continue
            fields = line.split()
            _require(len(fields) == 2, f"invalid service-context row in {path}")
            service, context = fields
            if service in result:
                _require(result[service] == context, f"conflicting service context: {service}")
            result[service] = context
    return result


def _partition_file(roots: dict[str, Path], locked_path: str) -> Path:
    parts = PurePosixPath(locked_path).parts
    _require(len(parts) >= 3, f"partition path is too short: {locked_path}")
    partition = parts[1]
    _require(partition in roots, f"no root supplied for partition: {partition}")
    root = roots[partition]
    _require(root.is_dir() and not root.is_symlink(), f"invalid partition root: {root}")
    candidate = root.joinpath(*parts[2:])
    try:
        candidate.resolve(strict=False).relative_to(root.resolve(strict=True))
    except (OSError, ValueError) as exc:
        raise CompatibilityError(f"partition path escapes root: {locked_path}") from exc
    return candidate


def tree_block_upper(path: Path, block_size: int = 4096) -> int:
    _require(path.is_dir() and not path.is_symlink(), f"package directory missing: {path}")
    total = block_size
    for item in path.rglob("*"):
        _require(not item.is_symlink(), f"symbolic link is forbidden in selected tree: {item}")
        if item.is_dir():
            total += block_size
        elif item.is_file():
            size = item.stat().st_size
            total += ((size + block_size - 1) // block_size) * block_size
        else:
            raise CompatibilityError(f"unsupported selected-tree entry: {item}")
    return total


def _atomic_report(path: Path, report: dict) -> None:
    if path.is_symlink():
        raise CompatibilityError(f"refusing symbolic-link report: {path}")
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


def command_check(profile: dict, _port: dict, summary: dict, _args: argparse.Namespace) -> None:
    status = "verified" if summary["pending_identities"] == 0 else "profile-valid-pending-identities"
    print(json.dumps({"status": status, **summary}, indent=2, sort_keys=True))


def command_verify_images(profile: dict, _port: dict, summary: dict, args: argparse.Namespace) -> None:
    images = _unique_table(profile["images"], "id", "image")
    paths = {
        "base_system": args.base_system,
        "base_vendor": args.base_vendor,
        "donor_system": args.donor_system,
        "donor_product": args.donor_product,
        "donor_system_ext": args.donor_system_ext,
    }
    results = [verify_image(paths[identifier], images[identifier]) for identifier in sorted(paths)]
    report = {"status": "verified", "profile_sha256": summary["profile_sha256"], "images": results}
    if args.report:
        _atomic_report(args.report, report)
    print(json.dumps(report, indent=2, sort_keys=True))


def command_verify_image(profile: dict, _port: dict, summary: dict, args: argparse.Namespace) -> None:
    images = _unique_table(profile["images"], "id", "image")
    _require(args.id in images, f"unknown image ID: {args.id}")
    report = {
        "status": "verified",
        "profile_sha256": summary["profile_sha256"],
        "image": verify_image(args.image, images[args.id]),
    }
    if args.report:
        _atomic_report(args.report, report)
    print(json.dumps(report, indent=2, sort_keys=True))


def command_verify_selection(profile: dict, _port: dict, summary: dict, args: argparse.Namespace) -> None:
    roots = {"system": args.system_root, "product": args.product_root, "system_ext": args.system_ext_root}
    expected_packages = _unique_table(profile["packages"], "id", "package")
    expected_native = _unique_table(profile["native_libraries"], "id", "native library")
    package_reports = []
    native_reports = []
    for expected in expected_packages.values():
        path = _partition_file(roots, expected["path"])
        actual = apk_report(path)
        for field in ("size", "sha256", "certificate_sha256", "package", "shared_uid", "uses_libraries"):
            _require(actual[field] == expected[field], f"{expected['id']} {field} mismatch")
        _require(actual["abis"] == sorted(expected["abis"]), f"{expected['id']} ABI mismatch")
        if "overlay_target" in expected:
            _require(actual["overlay_target"] == expected["overlay_target"], f"{expected['id']} overlay target mismatch")
            _require(actual["overlay_priority"] == expected["overlay_priority"], f"{expected['id']} overlay priority mismatch")
            _require(actual["overlay_is_static"] is True, f"{expected['id']} overlay is not static")
        actual["id"] = expected["id"]
        actual["status"] = "verified"
        package_reports.append(actual)

        package_native = apk_native_report(path)
        locked_native = {
            row["member"]: row for row in expected_native.values() if row["package"] == expected["id"]
        }
        _require({row["member"] for row in package_native} == set(locked_native), f"{expected['id']} native member set mismatch")
        for row in package_native:
            locked = locked_native[row["member"]]
            for field in ("size", "sha256", "elf_class", "machine", "needed"):
                _require(row[field] == locked[field], f"{locked['id']} {field} mismatch")
            native_reports.append({"id": locked["id"], "package": expected["id"], "status": "verified", **row})

    runtime_reports = []
    identities_to_lock = []
    for expected in profile["runtime_dependencies"]:
        path = _partition_file(roots, expected["path"])
        _require(path.is_file() and not path.is_symlink(), f"runtime dependency missing: {path}")
        actual = {"id": expected["id"], **apk_report(path)}
        for field in ("size", "package", "certificate_sha256"):
            _require(actual[field] == expected[field], f"{expected['id']} runtime {field} mismatch")
        if expected.get("identity_state") == "verified":
            _require(actual["sha256"] == expected["sha256"], f"{expected['id']} runtime hash mismatch")
            actual["status"] = "verified"
        else:
            actual["status"] = "measured-needs-lock"
            identities_to_lock.append({"table": "runtime_dependencies", "id": expected["id"], "sha256": actual["sha256"]})
        runtime_reports.append(actual)

    supplied_providers = _named_paths(args.embedded_provider, "embedded provider")
    expected_providers = _unique_table(profile["embedded_providers"], "id", "embedded provider")
    _require(set(supplied_providers) == set(expected_providers), "embedded provider input set mismatch")
    provider_reports = []
    for identifier, path in sorted(supplied_providers.items()):
        expected = expected_providers[identifier]
        inventory = archive_dex_inventory(path)
        actual = {
            "id": identifier,
            "path": str(path),
            "size": path.stat().st_size if path.is_file() else -1,
            "sha256": sha256_file(path),
            "defined_classes": len(inventory["defined"]),
        }
        for field in ("size", "sha256", "defined_classes"):
            _require(actual[field] == expected[field], f"{identifier} embedded provider {field} mismatch")
        actual["status"] = "verified"
        provider_reports.append(actual)

    supplied_payloads = _named_paths(args.apex_payload, "APEX payload")
    expected_payloads = _unique_table(profile["apex_payloads"], "id", "APEX payload")
    _require(set(supplied_payloads) == set(expected_payloads), "APEX payload input set mismatch")
    payload_reports = [
        verify_image(supplied_payloads[identifier], expected_payloads[identifier])
        for identifier in sorted(supplied_payloads)
    ]

    selection = profile["selection"]
    product_measured = sum(tree_block_upper(_partition_file(roots, path)) for path in selection["product_paths"])
    system_ext_measured = sum(tree_block_upper(_partition_file(roots, path)) for path in selection["system_ext_paths"])
    capacity = profile["capacity"]
    _require(product_measured == capacity["selected_product_measured"], "selected product measurement mismatch")
    _require(system_ext_measured == capacity["selected_system_ext_measured"], "selected system_ext measurement mismatch")
    _require(product_measured <= capacity["selected_product_upper"], "selected product exceeds upper bound")
    _require(system_ext_measured <= capacity["selected_system_ext_upper"], "selected system_ext exceeds upper bound")
    runtime_upper = sum(
        ((row["size"] + 4095) // 4096) * 4096
        for row in runtime_reports if next(item for item in profile["runtime_dependencies"] if item["id"] == row["id"])["path"].startswith("/system_ext/")
    )
    _require(runtime_upper == capacity["selected_system_ext_runtime_upper"], "system_ext runtime upper bound mismatch")

    status = "verified" if not identities_to_lock else "measured-needs-identity-lock"
    report = {
        "status": status,
        "profile_sha256": summary["profile_sha256"],
        "packages": package_reports,
        "runtime_dependencies": runtime_reports,
        "embedded_providers": provider_reports,
        "apex_payloads": payload_reports,
        "native_libraries": native_reports,
        "identities_to_lock": identities_to_lock,
        "selected_product_measured": product_measured,
        "selected_product_upper": capacity["selected_product_upper"],
        "selected_system_ext_measured": system_ext_measured,
        "selected_system_ext_upper": capacity["selected_system_ext_upper"],
        "selected_system_ext_runtime_upper": runtime_upper,
    }
    if args.report:
        _atomic_report(args.report, report)
    print(json.dumps(report, indent=2, sort_keys=True))


def command_verify_dex(profile: dict, _port: dict, summary: dict, args: argparse.Namespace) -> None:
    packages = _named_paths(args.package, "package")
    providers = _named_paths(args.provider, "provider")
    expected_packages = _unique_table(profile["packages"], "id", "package")
    scanned_packages = {identifier for identifier, row in expected_packages.items() if row["dex_scan"]}
    _require(set(packages) == scanned_packages, "DEX package input set mismatch")
    expected_providers = {
        **_unique_table(profile["classpath_providers"], "id", "classpath provider"),
        **_unique_table(profile["embedded_providers"], "id", "embedded provider"),
    }
    _require(set(providers) == set(expected_providers), "DEX provider input set mismatch")
    _require(sorted(args.custom_prefix) == sorted(profile["classpaths"]["custom_prefixes"]), "DEX prefix input set mismatch")
    for identifier, path in providers.items():
        expected = expected_providers[identifier]
        _require(path.is_file() and not path.is_symlink(), f"DEX provider is not regular: {path}")
        _require(path.stat().st_size == expected["size"], f"{identifier} DEX provider size mismatch")
        _require(sha256_file(path) == expected["sha256"], f"{identifier} DEX provider hash mismatch")
    report = {
        "profile_sha256": summary["profile_sha256"],
        **dex_resolution_report(packages, providers, args.custom_prefix),
    }
    package_reports = {row["id"]: row for row in report["packages"]}
    for identifier in sorted(scanned_packages):
        actual = package_reports[identifier]
        expected = expected_packages[identifier]
        _require(
            len(actual["custom_external_classes"]) == expected["custom_external_classes"],
            f"{identifier} custom DEX class count mismatch",
        )
        _require(
            len(actual["resolved_external_classes"]) == expected["resolved_external_classes"],
            f"{identifier} resolved DEX class count mismatch",
        )
    if args.report:
        _atomic_report(args.report, report)
    print(json.dumps(report, indent=2, sort_keys=True))
    _require(
        report["unresolved_external_classes"] == 0,
        f"{report['unresolved_external_classes']} custom external DEX classes are unresolved",
    )


def command_verify_static(profile: dict, _port: dict, summary: dict, args: argparse.Namespace) -> None:
    base_roots = {
        "system": args.base_system_root,
        "product": args.base_product_root,
        "system_ext": args.base_system_ext_root,
        "vendor": args.base_vendor_root,
    }
    donor_roots = {"system": args.donor_system_root, "system_ext": args.donor_system_ext_root}
    android = profile["android_compatibility"]
    property_inputs = {
        "base_system": (_partition_file(base_roots, "/system/build.prop"), android["base_system_build_prop_sha256"]),
        "base_vendor": (_partition_file(base_roots, "/vendor/build.prop"), android["base_vendor_build_prop_sha256"]),
        "donor_system": (_partition_file(donor_roots, "/system/build.prop"), android["donor_system_build_prop_sha256"]),
    }
    properties = {}
    for identifier, (path, expected_hash) in property_inputs.items():
        actual_hash = sha256_file(path)
        _require(actual_hash == expected_hash, f"{identifier} build.prop hash mismatch")
        properties[identifier] = _property_file(path)
    for identifier, prefix in (("base_system", "base"), ("donor_system", "donor")):
        values = properties[identifier]
        _require(int(values.get("ro.build.version.release", -1)) == android[f"{prefix}_release"], f"{identifier} release mismatch")
        _require(int(values.get("ro.build.version.sdk", -1)) == android[f"{prefix}_sdk"], f"{identifier} SDK mismatch")
        _require(values.get("ro.product.cpu.abilist", "").split(",") == android[f"{prefix}_abis"], f"{identifier} ABI list mismatch")
    _require(
        int(properties["base_vendor"].get("ro.vendor.build.version.sdk", -1)) == android["base_vendor_sdk"],
        "base vendor SDK mismatch",
    )
    _require(
        int(properties["base_vendor"].get("ro.product.first_api_level", -1)) == android["base_vendor_first_api_level"],
        "base vendor first API mismatch",
    )
    android_report = {
        "base_release": android["base_release"],
        "donor_release": android["donor_release"],
        "base_sdk": android["base_sdk"],
        "donor_sdk": android["donor_sdk"],
        "base_vendor_sdk": android["base_vendor_sdk"],
        "base_vendor_first_api_level": android["base_vendor_first_api_level"],
        "abis": android["base_abis"],
        "build_prop_sha256": {key: expected for key, (_, expected) in property_inputs.items()},
    }

    matrix_paths = {
        "base": _partition_file(base_roots, "/system/etc/vintf/compatibility_matrix.3.xml"),
        "donor": _partition_file(donor_roots, "/system/etc/vintf/compatibility_matrix.3.xml"),
    }
    matrix_hashes = {identifier: sha256_file(path) for identifier, path in matrix_paths.items()}
    expected_matrix = profile["vintf"]["matrix_level_3_sha256"]
    _require(set(matrix_hashes.values()) == {expected_matrix}, "VINTF level-3 matrix mismatch")
    manifest_path = _partition_file(base_roots, "/vendor/etc/vintf/manifest.xml")
    try:
        manifest_text = manifest_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise CompatibilityError(f"cannot read VINTF manifest {manifest_path}: {exc}") from exc
    level_match = re.search(r"\btarget-level\s*=\s*[\"']([0-9]+)[\"']", manifest_text)
    _require(level_match is not None, "base VINTF target level missing")
    target_level = int(level_match.group(1))
    _require(target_level == profile["vintf"]["target_manifest_level"], "base VINTF target level mismatch")
    vintf_report = {"target_manifest_level": target_level, "matrix_level_3_sha256": matrix_hashes}

    policy_inputs = {
        "plat": (
            _partition_file(base_roots, "/system/etc/selinux/plat_sepolicy_and_mapping.sha256"),
            _partition_file(base_roots, "/vendor/etc/selinux/precompiled_sepolicy.plat_sepolicy_and_mapping.sha256"),
            profile["selinux"]["plat_precompiled_sha256"],
        ),
        "product": (
            _partition_file(base_roots, "/product/etc/selinux/product_sepolicy_and_mapping.sha256"),
            _partition_file(base_roots, "/vendor/etc/selinux/precompiled_sepolicy.product_sepolicy_and_mapping.sha256"),
            profile["selinux"]["product_precompiled_sha256"],
        ),
        "system_ext": (
            _partition_file(base_roots, "/system_ext/etc/selinux/system_ext_sepolicy_and_mapping.sha256"),
            _partition_file(base_roots, "/vendor/etc/selinux/precompiled_sepolicy.system_ext_sepolicy_and_mapping.sha256"),
            profile["selinux"]["system_ext_precompiled_sha256"],
        ),
    }
    policy_hashes = {}
    for identifier, (source_path, vendor_path, expected) in policy_inputs.items():
        try:
            source_value = source_path.read_text(encoding="ascii").strip()
            vendor_value = vendor_path.read_text(encoding="ascii").strip()
        except (OSError, UnicodeDecodeError) as exc:
            raise CompatibilityError(f"cannot read SELinux hash evidence for {identifier}: {exc}") from exc
        _require(source_value == vendor_value == expected, f"SELinux precompiled hash mismatch: {identifier}")
        policy_hashes[identifier] = expected

    donor_contexts = _service_contexts(
        [
            _partition_file(donor_roots, "/system/etc/selinux/plat_service_contexts"),
            _partition_file(donor_roots, "/system_ext/etc/selinux/system_ext_service_contexts"),
        ]
    )
    base_contexts = _service_contexts(
        [
            _partition_file(base_roots, "/system/etc/selinux/plat_service_contexts"),
            _partition_file(base_roots, "/product/etc/selinux/product_service_contexts"),
            _partition_file(base_roots, "/system_ext/etc/selinux/system_ext_service_contexts"),
        ]
    )
    service_reports = []
    base_values = set(base_contexts.values())
    for service, target_type in sorted(profile["service_types"].items()):
        _require(service in donor_contexts, f"donor service context missing: {service}")
        target_context = f"u:object_r:{target_type}:s0"
        _require(target_context in base_values, f"base service type missing: {target_type}")
        service_reports.append(
            {"service": service, "donor_context": donor_contexts[service], "mapped_base_context": target_context}
        )
    selinux_report = {
        "precompiled_hashes": policy_hashes,
        "allow_new_policy_types": False,
        "service_mappings": service_reports,
    }

    layout = profile["layout"]
    layout_paths = {
        "base_init": _partition_file(base_roots, layout["base_init_path"]),
        "base_fstab": _partition_file(base_roots, layout["base_fstab_path"]),
    }
    layout_report = {}
    for identifier, path in layout_paths.items():
        actual_hash = sha256_file(path)
        _require(actual_hash == layout[f"{identifier}_sha256"], f"{identifier} hash mismatch")
        layout_report[identifier] = {"locked_path": layout[f"{identifier}_path"], "sha256": actual_hash}

    kernel = profile["kernel"]
    kernel_report = boot_kernel_report(args.base_boot)
    for actual_key, expected_key in (
        ("boot_sha256", "base_boot_sha256"),
        ("kernel_sha256", "compressed_kernel_sha256"),
        ("kernel_size", "compressed_kernel_size"),
        ("ikconfig_sha256", "ikconfig_sha256"),
    ):
        _require(kernel_report[actual_key] == kernel[expected_key], f"kernel {actual_key} mismatch")
    missing_configs = sorted(set(kernel["required_builtins"]) - kernel_report["config_lines"])
    _require(not missing_configs, f"required kernel config missing: {missing_configs[0] if missing_configs else ''}")
    del kernel_report["config_lines"]
    kernel_report["required_builtins"] = sorted(kernel["required_builtins"])
    kernel_report["status"] = "verified"

    report = {
        "status": "verified",
        "profile_sha256": summary["profile_sha256"],
        "android": android_report,
        "vintf": vintf_report,
        "selinux": selinux_report,
        "layout": layout_report,
        "kernel": kernel_report,
    }
    if args.report:
        _atomic_report(args.report, report)
    print(json.dumps(report, indent=2, sort_keys=True))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    parser.add_argument("--port-profile", type=Path, default=DEFAULT_PORT_PROFILE)
    subparsers = parser.add_subparsers(dest="command", required=True)

    check_parser = subparsers.add_parser("check", help="validate the locked compatibility profile")
    check_parser.set_defaults(handler=command_check)

    image_parser = subparsers.add_parser("verify-images", help="verify all five recovered ext filesystems")
    image_parser.add_argument("--base-system", type=Path, required=True)
    image_parser.add_argument("--base-vendor", type=Path, required=True)
    image_parser.add_argument("--donor-system", type=Path, required=True)
    image_parser.add_argument("--donor-product", type=Path, required=True)
    image_parser.add_argument("--donor-system-ext", type=Path, required=True)
    image_parser.add_argument("--report", type=Path)
    image_parser.set_defaults(handler=command_verify_images)

    single_image_parser = subparsers.add_parser(
        "verify-image", help="verify one recovered ext filesystem by locked ID"
    )
    single_image_parser.add_argument("--id", required=True)
    single_image_parser.add_argument("--image", type=Path, required=True)
    single_image_parser.add_argument("--report", type=Path)
    single_image_parser.set_defaults(handler=command_verify_image)

    selection_parser = subparsers.add_parser("verify-selection", help="verify selected APKs and runtime files")
    selection_parser.add_argument("--system-root", type=Path, required=True)
    selection_parser.add_argument("--product-root", type=Path, required=True)
    selection_parser.add_argument("--system-ext-root", type=Path, required=True)
    selection_parser.add_argument("--embedded-provider", action="append", required=True, metavar="ID=PATH")
    selection_parser.add_argument("--apex-payload", action="append", required=True, metavar="ID=PATH")
    selection_parser.add_argument("--report", type=Path)
    selection_parser.set_defaults(handler=command_verify_selection)

    dex_parser = subparsers.add_parser("verify-dex", help="verify custom DEX references against provider archives")
    dex_parser.add_argument("--package", action="append", required=True, metavar="ID=PATH")
    dex_parser.add_argument("--provider", action="append", required=True, metavar="ID=PATH")
    dex_parser.add_argument("--custom-prefix", action="append", required=True, metavar="LDESCRIPTOR/PREFIX/")
    dex_parser.add_argument("--report", type=Path)
    dex_parser.set_defaults(handler=command_verify_dex)

    static_parser = subparsers.add_parser("verify-static", help="verify Android, VINTF, SELinux, layout, and kernel evidence")
    static_parser.add_argument("--base-system-root", type=Path, required=True)
    static_parser.add_argument("--base-product-root", type=Path, required=True)
    static_parser.add_argument("--base-system-ext-root", type=Path, required=True)
    static_parser.add_argument("--base-vendor-root", type=Path, required=True)
    static_parser.add_argument("--donor-system-root", type=Path, required=True)
    static_parser.add_argument("--donor-system-ext-root", type=Path, required=True)
    static_parser.add_argument("--base-boot", type=Path, required=True)
    static_parser.add_argument("--report", type=Path)
    static_parser.set_defaults(handler=command_verify_static)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        profile, port_profile, summary = load_and_validate(args.profile, args.port_profile)
        args.handler(profile, port_profile, summary, args)
    except CompatibilityError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
