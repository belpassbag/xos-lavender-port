from __future__ import annotations

from copy import deepcopy
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest
import zipfile


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("portctl", REPOSITORY_ROOT / "tools" / "portctl.py")
assert SPEC is not None and SPEC.loader is not None
portctl = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(portctl)


class PortCtlTests(unittest.TestCase):
    @staticmethod
    def zip_source(path: Path, entries: dict[str, bytes], extract_entries: list[str]) -> dict:
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, payload in entries.items():
                archive.writestr(name, payload)
        return {
            "filename": path.name,
            "parts_prefix": "fixture.part-",
            "size": path.stat().st_size,
            "sha256": portctl.sha256_file(path),
            "required_zip_entries": list(entries),
            "extract_entries": extract_entries,
            "expected_entry_sizes": {name: len(payload) for name, payload in entries.items()},
        }

    def test_repository_configuration_is_valid(self) -> None:
        config = portctl.load_config(REPOSITORY_ROOT / "config" / "port.toml")
        self.assertEqual(config["base"]["device"], "lavender")
        self.assertEqual(config["donor"]["platform"], "mt6768")

    def test_rejects_every_locked_profile_mutation(self) -> None:
        config = portctl.load_config(REPOSITORY_ROOT / "config" / "port.toml")
        mutations = {
            "source checksum": lambda value: value["base"].__setitem__("sha256", "0" * 64),
            "partition size": lambda value: value["base"].__setitem__(
                "system_partition_size", 99_999_999_999
            ),
            "base hardware policy": lambda value: value["policy"].__setitem__(
                "keep_from_base", []
            ),
            "donor modem policy": lambda value: value["policy"].__setitem__(
                "forbidden_donor_output_images",
                [
                    name
                    for name in value["policy"]["forbidden_donor_output_images"]
                    if name != "md1img.img"
                ],
            ),
            "core package scope": lambda value: value["policy"].__setitem__(
                "core_xos_packages", []
            ),
            "first boot exclusions": lambda value: value["policy"].__setitem__(
                "first_boot_exclusions", []
            ),
            "donor boot extraction": lambda value: value["donor"]["extract_entries"].append(
                "boot.img"
            ),
            "product allowlist": lambda value: value["policy"].__setitem__(
                "donor_product_package_allowlist", []
            ),
        }
        for label, mutation in mutations.items():
            with self.subTest(label=label):
                candidate = deepcopy(config)
                mutation(candidate)
                with self.assertRaises(portctl.PortError):
                    portctl.validate_config(candidate)

    def test_separates_analysis_inputs_from_final_output_policy(self) -> None:
        config = portctl.load_config(REPOSITORY_ROOT / "config" / "port.toml")
        donor_extract = set(config["donor"]["extract_entries"])
        forbidden_output = set(config["policy"]["forbidden_donor_output_images"])
        self.assertNotIn("boot.img", donor_extract)
        self.assertNotIn("dtbo.img", donor_extract)
        self.assertIn("vbmeta.img", donor_extract)
        self.assertIn("vbmeta.img", forbidden_output)

    def test_product_package_selection_keeps_only_verified_xos_dependencies(self) -> None:
        policy = portctl.load_config(REPOSITORY_ROOT / "config" / "port.toml")["policy"]
        self.assertEqual(policy["donor_product_selection"], "allowlist-only")
        self.assertEqual(
            set(policy["donor_product_package_allowlist"]),
            {
                "/product/app/SystemUIOverlay",
                "/product/app/SettingsOverlay",
                "/product/priv-app/XOSLauncher_res",
            },
        )
        self.assertNotIn("/product/app", policy["first_boot_exclusions"])
        self.assertNotIn("/product/priv-app", policy["first_boot_exclusions"])

    def test_discovers_numeric_parts_in_order(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            for name in ("source.part-002", "source.part-000", "source.part-001"):
                (root / name).write_bytes(name.encode())
            parts = portctl.discover_parts(root, "source.part-")
            self.assertEqual([part.name for part in parts], [
                "source.part-000",
                "source.part-001",
                "source.part-002",
            ])

    def test_rejects_missing_part_number(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "source.part-000").write_bytes(b"a")
            (root / "source.part-002").write_bytes(b"b")
            with self.assertRaises(portctl.PortError):
                portctl.discover_parts(root, "source.part-")

    def test_rejects_sequence_that_does_not_start_at_zero(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "source.part-001").write_bytes(b"a")
            (root / "source.part-002").write_bytes(b"b")
            with self.assertRaises(portctl.PortError):
                portctl.discover_parts(root, "source.part-")

    def test_assembles_and_verifies_source(self) -> None:
        payload = b"lavender-xos-test-payload"
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            parts_dir = root / "parts"
            output_dir = root / "out"
            parts_dir.mkdir()
            part_payloads = (payload[:9], payload[9:18], payload[18:])
            manifest_lines = []
            for index, part_payload in enumerate(part_payloads):
                name = f"fixture.part-{index:03d}"
                (parts_dir / name).write_bytes(part_payload)
                manifest_lines.append(f"{hashlib.sha256(part_payload).hexdigest()}  {name}\n")
            (parts_dir / "SHA256SUMS-parts.txt").write_text("".join(manifest_lines), encoding="utf-8")
            source = {
                "parts_prefix": "fixture.part-",
                "filename": "fixture.zip",
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }

            output = portctl.assemble_source(parts_dir, output_dir, source)

            self.assertEqual(output.read_bytes(), payload)
            self.assertFalse(any(output_dir.glob("*.partial")))

    def test_rejects_bad_part_checksum_without_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            parts_dir = root / "parts"
            output_dir = root / "out"
            parts_dir.mkdir()
            (parts_dir / "fixture.part-000").write_bytes(b"changed")
            (parts_dir / "SHA256SUMS-parts.txt").write_text(
                f"{'0' * 64}  fixture.part-000\n", encoding="utf-8"
            )
            source = {
                "parts_prefix": "fixture.part-",
                "filename": "fixture.zip",
                "size": 7,
                "sha256": hashlib.sha256(b"changed").hexdigest(),
            }

            with self.assertRaises(portctl.PortError):
                portctl.assemble_source(parts_dir, output_dir, source)
            self.assertFalse((output_dir / "fixture.zip").exists())

    def test_rejects_unsafe_checksum_manifest_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            manifest = Path(temporary_directory) / "SHA256SUMS-parts.txt"
            manifest.write_text(f"{'0' * 64}  ../outside.part-000\n", encoding="utf-8")
            with self.assertRaises(portctl.PortError):
                portctl.parse_checksum_manifest(manifest)

    def test_audits_and_extracts_allowlisted_zip_entries(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            archive_path = root / "fixture.zip"
            entries = {
                "system.new.dat.br": b"system-payload",
                "META-INF/com/android/metadata": b"metadata",
            }
            source = self.zip_source(archive_path, entries, ["system.new.dat.br"])

            report = portctl.audit_zip(archive_path, source)
            destination = portctl.extract_source(archive_path, root / "out", "base", source)

            self.assertEqual(report["entry_count"], 2)
            self.assertEqual((destination / "system.new.dat.br").read_bytes(), b"system-payload")
            self.assertFalse((destination / "META-INF/com/android/metadata").exists())
            self.assertTrue((destination / "extraction-manifest.json").is_file())

    def test_rejects_unsafe_zip_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            archive_path = root / "unsafe.zip"
            entries = {"safe.txt": b"safe", "../escape.txt": b"escape"}
            source = self.zip_source(archive_path, entries, ["safe.txt"])

            with self.assertRaises(portctl.PortError):
                portctl.audit_zip(archive_path, source)

    def test_rejects_unexpected_zip_entry_size(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            archive_path = root / "fixture.zip"
            source = self.zip_source(archive_path, {"required.txt": b"data"}, ["required.txt"])
            source["expected_entry_sizes"]["required.txt"] = 99

            with self.assertRaises(portctl.PortError):
                portctl.audit_zip(archive_path, source)

    def test_rejects_symlink_in_extraction_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            archive_path = root / "fixture.zip"
            source = self.zip_source(archive_path, {"nested/file.txt": b"data"}, ["nested/file.txt"])
            destination_root = root / "out" / "base"
            destination_root.mkdir(parents=True)
            (destination_root / "nested").symlink_to(root)

            with self.assertRaises(portctl.PortError):
                portctl.extract_source(archive_path, root / "out", "base", source)


if __name__ == "__main__":
    unittest.main()
