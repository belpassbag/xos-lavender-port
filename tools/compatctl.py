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


DEFAULT_PROFILE = Path(__file__).resolve().parents[1] / "config" / "compatibility.toml"
DEFAULT_PORT_PROFILE = Path(__file__).resolve().parents[1] / "config" / "port.toml"
LOCKED_PROFILE_SHA256 = "209161ed6a5fe7a1f72fa1884c452963a62b78f62b67631ec6af94996c889b59"
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
    expected_image_ids = {
        "base_system",
        "base_vendor",
        "donor_system",
        "donor_product",
        "donor_system_ext",
    }
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
    conservative = (
        capacity.get("base_system_used", -1)
        + capacity.get("donor_system_used", -1)
        + capacity.get("selected_product_upper", -1)
        + capacity.get("selected_system_ext_upper", -1)
    )
    _require(capacity.get("conservative_total") == conservative, "capacity total mismatch")
    headroom = capacity["target_filesystem_data_size"] - conservative
    _require(capacity.get("headroom") == headroom, "capacity headroom mismatch")
    _require(headroom >= capacity.get("minimum_reserve", headroom + 1), "capacity reserve is not met")

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

    layout = profile.get("layout", {})
    for key in ("preserve_base_system_as_root", "preserve_base_init", "preserve_base_fstab"):
        _require(layout.get(key) is True, f"layout guard missing: {key}")
    _require(layout.get("base_product_target") == "/system/product", "base product target mismatch")
    _require(layout.get("base_system_ext_target") == "/system/system_ext", "base system_ext target mismatch")

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
        "retain_base_phone_shared_uid_group",
        "retain_base_qti_system_ext",
        "retain_base_bluetooth",
        "exclude_donor_phone_shared_uid_group",
        "exclude_donor_mtk_bluetooth",
        "exclude_donor_hardware_services",
        "exclude_donor_generated_rros",
    ):
        _require(exclusion.get(key) is True, f"exclusion guard missing: {key}")
    exclusion_paths = [_locked_absolute_path(path, "exclusion path") for path in exclusion.get("paths", [])]
    _require(exclusion_paths == policy.get("first_boot_exclusions"), "first-boot exclusion drift")

    expected_services = {
        "kolun": "activity_service",
        "gamemode_helper": "activity_service",
        "sand_accessor": "activity_service",
        "os_audio_change": "audio_service",
        "tran_appm": "system_config_service",
        "tran_resmonitor": "system_config_service",
        "tran_tranlog": "system_config_service",
        "tranlog_sub": "system_config_service",
        "tran_pwhub": "power_service",
    }
    _require(profile.get("service_types") == expected_services, "service-type map drift")

    required_kernel = {
        "CONFIG_BLK_DEV_LOOP=y",
        "CONFIG_DM_VERITY=y",
        "CONFIG_DM_VERITY_FEC=y",
        "CONFIG_EXT4_FS=y",
        "CONFIG_SECURITY_SELINUX=y",
    }
    kernel = profile.get("kernel", {})
    _require(set(kernel.get("required_builtins", [])) == required_kernel, "kernel requirement drift")
    _require(kernel.get("packaged_apex_payload_filesystem") == "ext4", "APEX filesystem mismatch")

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
        _require(package.get("signer") in {"xos-platform", "standalone"}, f"invalid signer class: {identifier}")
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

    providers = _unique_table(profile.get("embedded_providers"), "id", "embedded provider")
    _require(set(providers) == {"os-framework.jar", "os-services.jar", "kolun.jar", "kolunlibrary.jar"}, "embedded provider set drift")
    for identifier, provider in providers.items():
        _require(provider.get("container") in runtimes, f"unknown provider container: {identifier}")
        _require(isinstance(provider.get("size"), int) and provider["size"] > 0, f"invalid provider size: {identifier}")
        state = provider.get("identity_state")
        _require(state in {"pending-fresh-verification", "verified"}, f"invalid provider state: {identifier}")
        if state == "verified":
            _require(_is_sha256(provider.get("sha256")), f"missing verified provider hash: {identifier}")

    return {
        "profile_sha256": digest,
        "images": len(images),
        "packages": len(packages),
        "runtime_dependencies": len(runtimes),
        "embedded_providers": len(providers),
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
            _require(strings is not None and chunk_header >= 36, "start element precedes string pool")
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
    overlays = [attrs for name, attrs in elements if name == "overlay"]
    _require(len(overlays) <= 1, "multiple overlay elements are unsupported")
    overlay = overlays[0] if overlays else {}
    return {
        "package": root.get("package", ""),
        "shared_uid": root.get("sharedUserId", ""),
        "uses_libraries": uses_libraries,
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


def _dex_string(data: bytes, offset: int) -> str:
    _, cursor = _uleb128(data, offset)
    end = data.find(b"\0", cursor)
    _require(end >= 0, "unterminated DEX string")
    try:
        return data[cursor:end].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CompatibilityError("DEX descriptor string is not UTF-8") from exc


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
    total = 0
    for item in path.rglob("*"):
        _require(not item.is_symlink(), f"symbolic link is forbidden in selected tree: {item}")
        if item.is_file():
            size = item.stat().st_size
            total += ((size + block_size - 1) // block_size) * block_size
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
    print(json.dumps({"status": "verified", **summary}, indent=2, sort_keys=True))


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


def command_verify_selection(profile: dict, _port: dict, summary: dict, args: argparse.Namespace) -> None:
    roots = {"system": args.system_root, "product": args.product_root, "system_ext": args.system_ext_root}
    signers = profile["signers"]
    package_reports = []
    for expected in profile["packages"]:
        path = _partition_file(roots, expected["path"])
        actual = apk_report(path)
        for field in ("size", "package", "shared_uid", "uses_libraries"):
            _require(actual[field] == expected[field], f"{expected['id']} {field} mismatch")
        _require(actual["abis"] == sorted(expected["abis"]), f"{expected['id']} ABI mismatch")
        if "overlay_target" in expected:
            _require(actual["overlay_target"] == expected["overlay_target"], f"{expected['id']} overlay target mismatch")
            _require(actual["overlay_priority"] == expected["overlay_priority"], f"{expected['id']} overlay priority mismatch")
            _require(actual["overlay_is_static"] is True, f"{expected['id']} overlay is not static")
        if expected["signer"] == "xos-platform":
            _require(actual["certificate_sha256"] == signers["xos_platform_sha256"], f"{expected['id']} signer mismatch")
        actual["id"] = expected["id"]
        actual["status"] = "verified"
        package_reports.append(actual)

    runtime_reports = []
    identities_to_lock = []
    for expected in profile["runtime_dependencies"]:
        path = _partition_file(roots, expected["path"])
        _require(path.is_file() and not path.is_symlink(), f"runtime dependency missing: {path}")
        actual = {"id": expected["id"], "path": str(path), "size": path.stat().st_size, "sha256": sha256_file(path)}
        _require(actual["size"] == expected["size"], f"{expected['id']} runtime size mismatch")
        if expected.get("identity_state") == "verified":
            _require(actual["sha256"] == expected["sha256"], f"{expected['id']} runtime hash mismatch")
            actual["status"] = "verified"
        else:
            actual["status"] = "measured-needs-lock"
            identities_to_lock.append({"table": "runtime_dependencies", "id": expected["id"], "sha256": actual["sha256"]})
        runtime_reports.append(actual)

    selection = profile["selection"]
    product_upper = sum(tree_block_upper(_partition_file(roots, path)) for path in selection["product_paths"])
    system_ext_upper = sum(tree_block_upper(_partition_file(roots, path)) for path in selection["system_ext_paths"])
    _require(product_upper == profile["capacity"]["selected_product_upper"], "selected product tree upper bound mismatch")
    _require(system_ext_upper == profile["capacity"]["selected_system_ext_upper"], "selected system_ext tree upper bound mismatch")

    status = "verified" if not identities_to_lock else "measured-needs-identity-lock"
    report = {
        "status": status,
        "profile_sha256": summary["profile_sha256"],
        "packages": package_reports,
        "runtime_dependencies": runtime_reports,
        "identities_to_lock": identities_to_lock,
        "selected_product_upper": product_upper,
        "selected_system_ext_upper": system_ext_upper,
    }
    if args.report:
        _atomic_report(args.report, report)
    print(json.dumps(report, indent=2, sort_keys=True))


def command_verify_dex(_profile: dict, _port: dict, summary: dict, args: argparse.Namespace) -> None:
    packages = _named_paths(args.package, "package")
    providers = _named_paths(args.provider, "provider")
    report = {
        "profile_sha256": summary["profile_sha256"],
        **dex_resolution_report(packages, providers, args.custom_prefix),
    }
    if args.report:
        _atomic_report(args.report, report)
    print(json.dumps(report, indent=2, sort_keys=True))
    _require(
        report["unresolved_external_classes"] == 0,
        f"{report['unresolved_external_classes']} custom external DEX classes are unresolved",
    )


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

    selection_parser = subparsers.add_parser("verify-selection", help="verify selected APKs and runtime files")
    selection_parser.add_argument("--system-root", type=Path, required=True)
    selection_parser.add_argument("--product-root", type=Path, required=True)
    selection_parser.add_argument("--system-ext-root", type=Path, required=True)
    selection_parser.add_argument("--report", type=Path)
    selection_parser.set_defaults(handler=command_verify_selection)

    dex_parser = subparsers.add_parser("verify-dex", help="verify custom DEX references against provider archives")
    dex_parser.add_argument("--package", action="append", required=True, metavar="ID=PATH")
    dex_parser.add_argument("--provider", action="append", required=True, metavar="ID=PATH")
    dex_parser.add_argument("--custom-prefix", action="append", required=True, metavar="LDESCRIPTOR/PREFIX/")
    dex_parser.add_argument("--report", type=Path)
    dex_parser.set_defaults(handler=command_verify_dex)
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
