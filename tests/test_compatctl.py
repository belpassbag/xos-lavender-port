from __future__ import annotations

from copy import deepcopy
import gzip
import importlib.util
from pathlib import Path
import struct
import sys
import tempfile
import unittest
import zipfile


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("compatctl", REPOSITORY_ROOT / "tools" / "compatctl.py")
assert SPEC is not None and SPEC.loader is not None
compatctl = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = compatctl
SPEC.loader.exec_module(compatctl)


def utf8_length(value: int) -> bytes:
    if value < 0x80:
        return bytes([value])
    return bytes([0x80 | (value >> 8), value & 0xFF])


def string_pool(strings: list[str]) -> bytes:
    offsets: list[int] = []
    payload = bytearray()
    for value in strings:
        encoded = value.encode("utf-8")
        offsets.append(len(payload))
        payload.extend(utf8_length(len(value)))
        payload.extend(utf8_length(len(encoded)))
        payload.extend(encoded)
        payload.append(0)
    while len(payload) % 4:
        payload.append(0)
    header_size = 28
    strings_start = header_size + 4 * len(strings)
    chunk_size = strings_start + len(payload)
    header = struct.pack(
        "<HHIIIIII",
        compatctl.RES_STRING_POOL_TYPE,
        header_size,
        chunk_size,
        len(strings),
        0,
        compatctl.UTF8_FLAG,
        strings_start,
        0,
    )
    return header + b"".join(struct.pack("<I", value) for value in offsets) + payload


def start_element(strings: list[str], name: str, attributes: list[tuple[str, object]]) -> bytes:
    encoded_attributes = bytearray()
    for attribute_name, value in attributes:
        if isinstance(value, bool):
            raw = compatctl.NO_INDEX
            value_type = compatctl.TYPE_INT_BOOLEAN
            data = int(value)
        elif isinstance(value, int):
            raw = compatctl.NO_INDEX
            value_type = compatctl.TYPE_INT_DEC
            data = value
        else:
            raw = strings.index(value)
            value_type = compatctl.TYPE_STRING
            data = raw
        encoded_attributes.extend(
            struct.pack(
                "<IIIHBBI",
                compatctl.NO_INDEX,
                strings.index(attribute_name),
                raw,
                8,
                0,
                value_type,
                data,
            )
        )
    chunk_size = 36 + len(encoded_attributes)
    return (
        struct.pack("<HHI", compatctl.RES_XML_START_ELEMENT_TYPE, 16, chunk_size)
        + struct.pack("<II", 1, compatctl.NO_INDEX)
        + struct.pack(
            "<IIHHHHHH",
            compatctl.NO_INDEX,
            strings.index(name),
            20,
            20,
            len(attributes),
            0,
            0,
            0,
        )
        + encoded_attributes
    )


def binary_manifest() -> bytes:
    strings = [
        "manifest",
        "package",
        "sharedUserId",
        "com.example.settings",
        "android.uid.system",
        "uses-library",
        "name",
        "org.apache.http.legacy",
        "overlay",
        "targetPackage",
        "com.android.settings",
        "priority",
        "isStatic",
    ]
    chunks = [
        string_pool(strings),
        start_element(
            strings,
            "manifest",
            [("package", "com.example.settings"), ("sharedUserId", "android.uid.system")],
        ),
        start_element(strings, "uses-library", [("name", "org.apache.http.legacy")]),
        start_element(
            strings,
            "overlay",
            [("targetPackage", "com.android.settings"), ("priority", 2), ("isStatic", True)],
        ),
    ]
    size = 8 + sum(len(chunk) for chunk in chunks)
    return struct.pack("<HHI", 0x0003, 8, size) + b"".join(chunks)


def der(tag: int, content: bytes) -> bytes:
    length = len(content)
    if length < 0x80:
        encoded_length = bytes([length])
    else:
        raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
        encoded_length = bytes([0x80 | len(raw)]) + raw
    return bytes([tag]) + encoded_length + content


def uleb128(value: int) -> bytes:
    result = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        result.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(result)


def dex_fixture(descriptors: list[str], defined: list[str]) -> bytes:
    strings = list(dict.fromkeys(descriptors))
    types = list(dict.fromkeys(descriptors))
    string_ids_offset = compatctl.DEX_HEADER_SIZE
    type_ids_offset = string_ids_offset + len(strings) * 4
    class_defs_offset = type_ids_offset + len(types) * 4
    data_offset = class_defs_offset + len(defined) * 32

    string_data = bytearray()
    string_offsets = []
    for value in strings:
        encoded = value.encode("utf-8")
        string_offsets.append(data_offset + len(string_data))
        string_data.extend(uleb128(len(value)))
        string_data.extend(encoded)
        string_data.append(0)

    file_size = data_offset + len(string_data)
    result = bytearray(file_size)
    result[:8] = b"dex\n035\0"
    struct.pack_into("<III", result, 0x20, file_size, compatctl.DEX_HEADER_SIZE, compatctl.DEX_ENDIAN_CONSTANT)
    struct.pack_into("<II", result, 0x38, len(strings), string_ids_offset)
    struct.pack_into("<II", result, 0x40, len(types), type_ids_offset)
    struct.pack_into("<II", result, 0x60, len(defined), class_defs_offset)
    for index, offset in enumerate(string_offsets):
        struct.pack_into("<I", result, string_ids_offset + index * 4, offset)
    for index, descriptor in enumerate(types):
        struct.pack_into("<I", result, type_ids_offset + index * 4, strings.index(descriptor))
    for index, descriptor in enumerate(defined):
        struct.pack_into("<I", result, class_defs_offset + index * 32, types.index(descriptor))
    result[data_offset:] = string_data
    return bytes(result)


def dex_archive(path: Path, descriptors: list[str], defined: list[str]) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("classes.dex", dex_fixture(descriptors, defined))


def elf64_fixture(needed: list[str]) -> bytes:
    strings = bytearray(b"\0")
    string_offsets = []
    for name in needed:
        string_offsets.append(len(strings))
        strings.extend(name.encode("ascii") + b"\0")
    dynamic = b"".join(struct.pack("<qQ", 1, offset) for offset in string_offsets)
    dynamic += struct.pack("<qQ", 0, 0)
    string_offset = 64
    dynamic_offset = string_offset + len(strings)
    section_offset = dynamic_offset + len(dynamic)
    result = bytearray(section_offset + 3 * 64)
    result[:16] = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    struct.pack_into(
        "<HHIQQQIHHHHHH",
        result,
        16,
        3,
        183,
        1,
        0,
        0,
        section_offset,
        0,
        64,
        0,
        0,
        64,
        3,
        0,
    )
    result[string_offset : string_offset + len(strings)] = strings
    result[dynamic_offset : dynamic_offset + len(dynamic)] = dynamic
    struct.pack_into("<IIQQQQIIQQ", result, section_offset + 64, 0, 3, 0, 0, string_offset, len(strings), 0, 0, 1, 0)
    struct.pack_into("<IIQQQQIIQQ", result, section_offset + 128, 0, 6, 0, 0, dynamic_offset, len(dynamic), 1, 0, 8, 16)
    return bytes(result)


def boot_fixture(config: bytes) -> bytes:
    packed_config = gzip.compress(config, mtime=0)
    expanded_kernel = b"kernel-prefix" + b"IKCFG_ST" + packed_config + b"IKCFG_ED" + b"kernel-suffix"
    compressed_kernel = gzip.compress(expanded_kernel, mtime=0) + b"appended-dtb"
    page_size = 4096
    result = bytearray(page_size + len(compressed_kernel))
    result[:8] = b"ANDROID!"
    struct.pack_into("<I", result, 8, len(compressed_kernel))
    struct.pack_into("<I", result, 36, page_size)
    result[page_size:] = compressed_kernel
    return bytes(result)


class CompatibilityProfileTests(unittest.TestCase):
    def load(self) -> tuple[dict, dict]:
        return (
            compatctl._read_toml(REPOSITORY_ROOT / "config" / "compatibility.toml"),
            compatctl._read_toml(REPOSITORY_ROOT / "config" / "port.toml"),
        )

    def test_repository_profile_is_locked_and_valid(self) -> None:
        profile, port = self.load()
        summary = compatctl.validate_profile(profile, port)
        self.assertEqual(summary["headroom"], 558_571_520)
        self.assertEqual(summary["packages"], 8)
        self.assertEqual(summary["pending_identities"], 0)
        self.assertEqual(summary["base_apks_scanned"], 107)
        self.assertEqual(summary["donor_apks_scanned"], 237)
        self.assertEqual(summary["shared_uid_conflicts"], 1)

    def test_rejects_semantic_profile_mutations(self) -> None:
        profile, port = self.load()
        mutations = {
            "capacity": lambda value: value["capacity"].__setitem__("headroom", 1),
            "service map": lambda value: value["service_types"].pop("kolun"),
            "product path": lambda value: value["selection"]["product_paths"].append("/product/app/Extra"),
            "shared UID signer": lambda value: value["packages"][4].__setitem__("signer", "standalone"),
            "shared UID strategy": lambda value: value["shared_uid_audit"].__setitem__(
                "global_signature_bypass_forbidden", False
            ),
            "runtime identity": lambda value: value["runtime_dependencies"][0].pop("sha256"),
            "SELinux types": lambda value: value["selinux"].__setitem__("allow_new_policy_types", True),
        }
        for label, mutation in mutations.items():
            with self.subTest(label=label):
                candidate = deepcopy(profile)
                mutation(candidate)
                with self.assertRaises(compatctl.CompatibilityError):
                    compatctl.validate_profile(candidate, port, enforce_lock=False)

    def test_rejects_any_locked_profile_byte_semantic_change(self) -> None:
        profile, port = self.load()
        candidate = deepcopy(profile)
        candidate["capacity"]["minimum_reserve"] += 1
        with self.assertRaisesRegex(compatctl.CompatibilityError, "digest"):
            compatctl.validate_profile(candidate, port)


class ParserTests(unittest.TestCase):
    def test_reads_ext4_metrics(self) -> None:
        image = bytearray(2048)
        superblock = memoryview(image)[1024:2048]
        struct.pack_into("<I", superblock, 0x04, 100)
        struct.pack_into("<I", superblock, 0x0C, 25)
        struct.pack_into("<I", superblock, 0x18, 2)
        struct.pack_into("<H", superblock, 0x38, 0xEF53)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "system.img"
            path.write_bytes(image)
            metrics = compatctl.ext4_metrics(path)
        self.assertEqual(metrics["block_count"], 100)
        self.assertEqual(metrics["free_blocks"], 25)
        self.assertEqual(metrics["block_size"], 4096)
        self.assertEqual(metrics["used_bytes"], 75 * 4096)

    def test_parses_binary_android_manifest(self) -> None:
        report = compatctl.parse_android_manifest(binary_manifest())
        self.assertEqual(report["package"], "com.example.settings")
        self.assertEqual(report["shared_uid"], "android.uid.system")
        self.assertEqual(report["uses_libraries"], ["org.apache.http.legacy"])
        self.assertEqual(report["overlay_target"], "com.android.settings")
        self.assertEqual(report["overlay_priority"], 2)
        self.assertIs(report["overlay_is_static"], True)

    def test_extracts_first_pkcs7_certificate(self) -> None:
        certificate = der(0x30, der(0x30, b"fixture"))
        signed_data = der(
            0x30,
            der(0x02, b"\x01")
            + der(0x31, b"")
            + der(0x30, der(0x06, b"\x2a\x03"))
            + der(0xA0, certificate)
            + der(0x31, b""),
        )
        pkcs7 = der(0x30, der(0x06, b"\x2a\x03") + der(0xA0, signed_data))
        self.assertEqual(compatctl._pkcs7_certificate(pkcs7), certificate)

    def test_parses_dex_class_inventory(self) -> None:
        data = dex_fixture(
            ["Lapp/Main;", "Lvendor/runtime/Api;", "[Lvendor/runtime/Api;", "I"],
            ["Lapp/Main;"],
        )
        inventory = compatctl.dex_inventory(data)
        self.assertEqual(inventory["defined"], {"Lapp/Main;"})
        self.assertEqual(
            inventory["referenced"],
            {"Lapp/Main;", "Lvendor/runtime/Api;"},
        )

    def test_decodes_dex_modified_utf8(self) -> None:
        encoded = uleb128(4) + b"A\xc0\x80\xed\xa0\xbd\xed\xb8\x80\0"
        self.assertEqual(compatctl._dex_string(encoded, 0), "A\0\U0001f600")

    def test_rejects_dex_modified_utf8_size_mismatch(self) -> None:
        encoded = uleb128(2) + b"A\0"
        with self.assertRaisesRegex(compatctl.CompatibilityError, "UTF-16 size"):
            compatctl._dex_string(encoded, 0)

    def test_resolves_custom_dex_classes_to_exact_provider(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = root / "ui.apk"
            provider = root / "runtime.jar"
            dex_archive(
                package,
                ["Lapp/Main;", "Lvendor/runtime/Api;", "Ljava/lang/Object;"],
                ["Lapp/Main;"],
            )
            dex_archive(
                provider,
                ["Lvendor/runtime/Api;", "Ljava/lang/Object;"],
                ["Lvendor/runtime/Api;"],
            )
            report = compatctl.dex_resolution_report(
                {"ui": package},
                {"runtime": provider},
                ["Lvendor/"],
            )
        self.assertEqual(report["status"], "verified")
        self.assertEqual(report["unresolved_external_classes"], 0)
        self.assertEqual(
            report["packages"][0]["resolved_external_classes"],
            {"Lvendor/runtime/Api;": ["runtime"]},
        )

    def test_reports_unresolved_custom_dex_class(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = root / "ui.apk"
            provider = root / "runtime.jar"
            dex_archive(package, ["Lapp/Main;", "Lvendor/missing/Api;"], ["Lapp/Main;"])
            dex_archive(provider, ["Lvendor/other/Api;"], ["Lvendor/other/Api;"])
            report = compatctl.dex_resolution_report(
                {"ui": package},
                {"runtime": provider},
                ["Lvendor/"],
            )
        self.assertEqual(report["status"], "unresolved")
        self.assertEqual(
            report["packages"][0]["unresolved_external_classes"],
            ["Lvendor/missing/Api;"],
        )

    def test_rejects_malformed_dex_table(self) -> None:
        data = bytearray(dex_fixture(["Lapp/Main;"], ["Lapp/Main;"]))
        struct.pack_into("<I", data, 0x3C, len(data) + 4)
        with self.assertRaises(compatctl.CompatibilityError):
            compatctl.dex_inventory(bytes(data))

    def test_reads_elf_needed_libraries(self) -> None:
        report = compatctl.elf_report(elf64_fixture(["liblog.so", "libc.so"]))
        self.assertEqual(report["elf_class"], 64)
        self.assertEqual(report["machine"], "AArch64")
        self.assertEqual(report["needed"], ["libc.so", "liblog.so"])

    def test_extracts_boot_ikconfig(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "boot.img"
            path.write_bytes(boot_fixture(b"CONFIG_EXT4_FS=y\n"))
            report = compatctl.boot_kernel_report(path)
        self.assertIn("CONFIG_EXT4_FS=y", report["config_lines"])
        self.assertEqual(report["appended_dtb_size"], len(b"appended-dtb"))

    def test_allows_identical_but_rejects_conflicting_properties(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "build.prop"
            path.write_text("ro.example=value\nro.example=value\n", encoding="utf-8")
            self.assertEqual(compatctl._property_file(path), {"ro.example": "value"})
            path.write_text("ro.example=one\nro.example=two\n", encoding="utf-8")
            with self.assertRaisesRegex(compatctl.CompatibilityError, "conflicting duplicate"):
                compatctl._property_file(path)

    def test_tree_upper_bound_and_symlink_guard(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "one").write_bytes(b"x")
            (root / "two").write_bytes(b"x" * 4097)
            self.assertEqual(compatctl.tree_block_upper(root), 16_384)
            (root / "escape").symlink_to(root / "one")
            with self.assertRaises(compatctl.CompatibilityError):
                compatctl.tree_block_upper(root)

    def test_partition_path_cannot_escape_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            roots = {"product": root}
            with self.assertRaises(compatctl.CompatibilityError):
                compatctl._partition_file(roots, "/product/../outside")


if __name__ == "__main__":
    unittest.main()
