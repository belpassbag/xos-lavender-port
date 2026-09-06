from __future__ import annotations

from copy import deepcopy
import importlib.util
from pathlib import Path
import struct
import sys
import tempfile
import unittest


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
        struct.pack("<HHI", compatctl.RES_XML_START_ELEMENT_TYPE, 36, chunk_size)
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


class CompatibilityProfileTests(unittest.TestCase):
    def load(self) -> tuple[dict, dict]:
        return (
            compatctl._read_toml(REPOSITORY_ROOT / "config" / "compatibility.toml"),
            compatctl._read_toml(REPOSITORY_ROOT / "config" / "port.toml"),
        )

    def test_repository_profile_is_locked_and_valid(self) -> None:
        profile, port = self.load()
        summary = compatctl.validate_profile(profile, port)
        self.assertEqual(summary["headroom"], 559_411_200)
        self.assertEqual(summary["packages"], 8)

    def test_rejects_semantic_profile_mutations(self) -> None:
        profile, port = self.load()
        mutations = {
            "capacity": lambda value: value["capacity"].__setitem__("headroom", 1),
            "service map": lambda value: value["service_types"].pop("kolun"),
            "product path": lambda value: value["selection"]["product_paths"].append("/product/app/Extra"),
            "shared UID signer": lambda value: value["packages"][4].__setitem__("signer", "standalone"),
            "runtime identity": lambda value: value["runtime_dependencies"][0].__setitem__("identity_state", "verified"),
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

    def test_tree_upper_bound_and_symlink_guard(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "one").write_bytes(b"x")
            (root / "two").write_bytes(b"x" * 4097)
            self.assertEqual(compatctl.tree_block_upper(root), 12_288)
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
