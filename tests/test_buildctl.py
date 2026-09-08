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


class OutputPipelineTests(unittest.TestCase):
    def profiles(self) -> tuple[dict, dict, dict, dict]:
        return buildctl.load_and_validate()

    def test_generates_only_locked_systemui_privileged_grants(self) -> None:
        profile, _compatibility, _port, _summary = self.profiles()
        document = buildctl.ElementTree.fromstring(buildctl._permission_document(profile))
        group = document.find("privapp-permissions")
        self.assertIsNotNone(group)
        assert group is not None
        self.assertEqual(group.get("package"), "com.android.systemui")
        self.assertEqual(
            sorted(item.get("name") for item in group.findall("permission")),
            sorted(profile["permissions"]["required_grants"]),
        )

    def test_service_context_patch_is_idempotent_and_rejects_conflict(self) -> None:
        profile, compatibility, _port, _summary = self.profiles()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            path = root / "system" / "system_ext" / "etc" / "selinux" / "system_ext_service_contexts"
            path.parent.mkdir(parents=True)
            path.write_text("gamemode_helper u:object_r:activity_service:s0\n", encoding="utf-8")
            first = buildctl._patch_service_contexts(profile, compatibility, root)
            second = buildctl._patch_service_contexts(profile, compatibility, root)
            self.assertEqual(first["added"], 8)
            self.assertEqual(second["added"], 0)
            self.assertEqual(len(buildctl._service_context_map(path)), 9)
            path.write_text("gamemode_helper u:object_r:wrong_type:s0\n", encoding="utf-8")
            with self.assertRaisesRegex(buildctl.BuildError, "drift"):
                buildctl._patch_service_contexts(profile, compatibility, root)

    def test_preopt_cleanup_removes_regular_and_symbolic_link_residue(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            regular = root / "system" / "app" / "One" / "oat" / "arm64" / "One.odex"
            regular.parent.mkdir(parents=True)
            regular.write_bytes(b"preopt")
            linked = root / "system" / "app" / "Two" / "Two.vdex"
            linked.parent.mkdir(parents=True)
            linked.symlink_to("missing.vdex")
            linked_oat = root / "system" / "app" / "Three" / "oat"
            linked_oat.parent.mkdir(parents=True)
            linked_oat.symlink_to("missing-oat", target_is_directory=True)
            report = buildctl._cleanup_preopt(root)
            self.assertGreaterEqual(report["removed_entries"], 3)
            self.assertEqual(report["removed_regular_files"], 1)
            self.assertEqual(report["removed_regular_bytes"], 6)
            self.assertEqual(buildctl._preopt_residue(root), [])

    def test_duplicate_package_guard_allows_splits_only_in_one_directory(self) -> None:
        rows = [
            {"package": "com.example.split", "directory": "/system/app/Split"},
            {"package": "com.example.split", "directory": "/system/app/Split"},
            {"package": "com.example.duplicate", "directory": "/system/app/One"},
            {"package": "com.example.duplicate", "directory": "/system/priv-app/Two"},
        ]
        self.assertEqual(
            buildctl._cross_directory_duplicates(rows),
            {"com.example.duplicate": ["/system/app/One", "/system/priv-app/Two"]},
        )

    def test_locked_launcher_removal_requires_exact_identity(self) -> None:
        expected = buildctl.LOCKED_REMOVALS[0]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            apk = root.joinpath(*Path(expected["path"]).parts[1:])
            apk.parent.mkdir(parents=True)
            apk.write_bytes(b"fixture")
            report = {
                "sha256": expected["sha256"],
                "certificate_sha256": expected["certificate_sha256"],
                "package": expected["package"],
            }
            with mock.patch.object(buildctl.compatctl, "apk_report", return_value=report):
                self.assertEqual(buildctl._remove_locked_duplicates(root), [expected])
            self.assertFalse(apk.parent.exists())
            apk.parent.mkdir(parents=True)
            apk.write_bytes(b"drift")
            with mock.patch.object(
                buildctl.compatctl,
                "apk_report",
                return_value={**report, "sha256": "0" * 64},
            ):
                with self.assertRaisesRegex(buildctl.BuildError, "identity drift"):
                    buildctl._remove_locked_duplicates(root)

    def test_tree_manifest_is_deterministic_and_content_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            file_path = root / "system" / "framework" / "fixture.jar"
            file_path.parent.mkdir(parents=True)
            file_path.write_bytes(b"one")
            link = root / "system" / "bin" / "fixture"
            link.parent.mkdir(parents=True)
            link.symlink_to("../framework/fixture.jar")
            first = buildctl._tree_manifest(root)
            second = buildctl._tree_manifest(root)
            self.assertEqual(first, second)
            self.assertEqual(first["regular_files"], 1)
            self.assertEqual(first["symbolic_links"], 1)
            file_path.write_bytes(b"two")
            self.assertNotEqual(first["sha256"], buildctl._tree_manifest(root)["sha256"])


if __name__ == "__main__":
    unittest.main()
