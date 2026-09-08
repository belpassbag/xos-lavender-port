from __future__ import annotations

from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("buildctl", REPOSITORY_ROOT / "tools" / "buildctl.py")
assert SPEC is not None and SPEC.loader is not None
buildctl = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = buildctl
SPEC.loader.exec_module(buildctl)


class PipelineProfileTests(unittest.TestCase):
    def load(self) -> tuple[dict, dict, dict]:
        profile = buildctl._read_toml(REPOSITORY_ROOT / "config" / "pipeline.toml")
        compatibility, port, _ = buildctl.compatctl.load_and_validate(
            REPOSITORY_ROOT / "config" / "compatibility.toml",
            REPOSITORY_ROOT / "config" / "port.toml",
        )
        return profile, compatibility, port

    def test_repository_pipeline_profile_is_locked(self) -> None:
        profile, compatibility, port = self.load()
        summary = buildctl.validate_profile(profile, compatibility, port)
        self.assertEqual(summary["status"], "verified")
        self.assertEqual(summary["product_paths"], 3)
        self.assertEqual(summary["system_ext_paths"], 5)
        self.assertEqual(summary["permission_grants"], 3)
        self.assertEqual(summary["service_mappings"], 9)
        self.assertEqual(summary["signing_mode"], "project-development")
        self.assertIn(
            "/system/etc/selinux/plat_mac_permissions.xml",
            profile["layout"]["protected_base_paths"],
        )

    def test_rejects_pipeline_policy_mutations(self) -> None:
        profile, compatibility, port = self.load()
        mutations = {
            "production signing": lambda value: value["signing"].__setitem__("allow_production_key", True),
            "shared UID bypass": lambda value: value["guards"].__setitem__(
                "forbid_package_manager_signature_bypass", False
            ),
            "donor permissions": lambda value: value["permissions"].__setitem__(
                "copy_donor_privapp_file", True
            ),
            "base init": lambda value: value["layout"]["protected_base_paths"].remove(
                "/system/etc/init"
            ),
            "extra package": lambda value: value["packages"]["system_ext_paths"].append(
                "/system_ext/app/Unexpected"
            ),
        }
        for label, mutation in mutations.items():
            with self.subTest(label=label):
                candidate = deepcopy(profile)
                mutation(candidate)
                with self.assertRaises(buildctl.BuildError):
                    buildctl.validate_profile(candidate, compatibility, port, enforce_lock=False)

    def test_rejects_any_locked_profile_change(self) -> None:
        profile, compatibility, port = self.load()
        candidate = deepcopy(profile)
        candidate["signing"]["clean_data_required_for_device_test"] = False
        with self.assertRaisesRegex(buildctl.BuildError, "digest"):
            buildctl.validate_profile(candidate, compatibility, port)


class InputSafetyTests(unittest.TestCase):
    def test_maps_partition_path_without_host_escape(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            expected = root / "app" / "Selected" / "Selected.apk"
            expected.parent.mkdir(parents=True)
            expected.write_bytes(b"apk")
            actual = buildctl.source_path(
                root,
                "/system_ext/app/Selected/Selected.apk",
                "system_ext",
            )
            self.assertEqual(actual, expected)

    def test_rejects_cross_partition_and_parent_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaises(buildctl.BuildError):
                buildctl.source_path(root, "/product/app/Selected.apk", "system_ext")
            with self.assertRaises(buildctl.BuildError):
                buildctl.source_path(root, "/system_ext/../outside", "system_ext")

    def test_rejects_symbolic_link_source_parent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            outside = root / "outside"
            outside.mkdir()
            (root / "app").symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(buildctl.BuildError, "symbolic-link"):
                buildctl.source_path(root, "/product/app/Selected.apk", "product")

    def test_apk_inventory_groups_certificates_per_shared_uid(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = root / "app" / "One" / "One.apk"
            second = root / "priv-app" / "Two" / "Two.apk"
            first.parent.mkdir(parents=True)
            second.parent.mkdir(parents=True)
            first.write_bytes(b"one")
            second.write_bytes(b"two")

            reports = {
                "One.apk": {
                    "package": "com.example.one",
                    "shared_uid": "android.uid.system",
                    "certificate_sha256": "1" * 64,
                },
                "Two.apk": {
                    "package": "com.example.two",
                    "shared_uid": "android.uid.system",
                    "certificate_sha256": "2" * 64,
                },
            }
            with mock.patch.object(
                buildctl.compatctl,
                "apk_report",
                side_effect=lambda path: reports[path.name],
            ):
                inventory = buildctl._inventory_apks(root, "fixture")

            self.assertEqual(inventory["apk_count"], 2)
            self.assertEqual(inventory["shared_uid_packages"], 2)
            self.assertEqual(
                set(inventory["shared_uid_groups"]["android.uid.system"]),
                {"1" * 64, "2" * 64},
            )

    def test_report_write_is_atomic_and_rejects_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report_path = root / "reports" / "case4.json"
            buildctl._atomic_report(report_path, {"status": "verified"})
            self.assertEqual(json.loads(report_path.read_text(encoding="utf-8"))["status"], "verified")
            report_path.unlink()
            report_path.symlink_to(root / "outside.json")
            with self.assertRaises(buildctl.BuildError):
                buildctl._atomic_report(report_path, {"status": "unsafe"})


if __name__ == "__main__":
    unittest.main()
