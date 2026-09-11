from __future__ import annotations

import base64
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("metactl", REPOSITORY_ROOT / "tools" / "metactl.py")
assert SPEC is not None and SPEC.loader is not None
metactl = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = metactl
SPEC.loader.exec_module(metactl)


class MetadataProfileTests(unittest.TestCase):
    def test_repository_case5_profile_is_locked_and_development_only(self) -> None:
        profile, _compatibility, _port, _pipeline, summary = metactl.load_and_validate()
        self.assertEqual(summary["status"], "verified")
        self.assertEqual(summary["snapshot_sources"], 4)
        self.assertEqual(summary["preserved_images"], 1)
        self.assertFalse(summary["production_signing"])
        self.assertFalse(summary["repack"])
        self.assertFalse(summary["automatic_flash"])
        self.assertEqual(profile["metadata"]["sources"], metactl.EXPECTED_SOURCE_PLAN)

    def test_rejects_repack_production_signing_and_source_plan_mutations(self) -> None:
        profile, compatibility, port, pipeline, _summary = metactl.load_and_validate()
        mutations = (
            lambda value: value["guards"].__setitem__("allow_repack", True),
            lambda value: value["guards"].__setitem__("allow_production_key", True),
            lambda value: value["metadata"]["sources"][2]["roots"].append("/vendor"),
        )
        for mutation in mutations:
            candidate = deepcopy(profile)
            mutation(candidate)
            with self.assertRaises(metactl.MetadataError):
                metactl.validate_profile(
                    candidate,
                    compatibility,
                    port,
                    pipeline,
                    enforce_lock=False,
                )

    def test_rejects_any_locked_case5_profile_change(self) -> None:
        profile, compatibility, port, pipeline, _summary = metactl.load_and_validate()
        candidate = deepcopy(profile)
        candidate["local"]["minimum_fresh_free_bytes"] += 1
        with self.assertRaisesRegex(metactl.MetadataError, "digest"):
            metactl.validate_profile(candidate, compatibility, port, pipeline)

    def test_metadata_roots_reject_overlap_and_traversal(self) -> None:
        with self.assertRaisesRegex(metactl.MetadataError, "overlapping"):
            metactl._safe_roots(["/system", "/system/app"])
        with self.assertRaisesRegex(metactl.MetadataError, "normalized|unsafe"):
            metactl._safe_roots(["/system/../vendor"])


class DebugfsParserTests(unittest.TestCase):
    def test_parses_uid_gid_mode_and_types(self) -> None:
        rows = metactl.parse_ls_output(
            """debugfs 1.47.0 (5-Feb-2023)
/12/040755/0/0/.//
/2/040755/0/0/..//
/13/100755/1000/2000/file/13/
/14/120777/0/0/link/4/
"""
        )
        file_row = next(row for row in rows if row["name"] == "file")
        link_row = next(row for row in rows if row["name"] == "link")
        self.assertEqual(file_row["type"], "regular")
        self.assertEqual(file_row["permissions_octal"], "0755")
        self.assertEqual((file_row["uid"], file_row["gid"]), (1000, 2000))
        self.assertEqual(link_row["type"], "symlink")

    def test_skips_debugfs_inode_zero_unused_directory_records(self) -> None:
        rows = metactl.parse_ls_output(
            """debugfs 1.47.0 (5-Feb-2023)
/12/040755/0/0/.//
/2/040755/0/0/..//
/0/000000/0/0//0/
/13/100644/0/0/live-file/7/
"""
        )
        self.assertEqual([row["name"] for row in rows], [".", "..", "live-file"])
        self.assertNotIn(0, [row["inode"] for row in rows])

    def test_rejects_malformed_inode_zero_debugfs_record(self) -> None:
        with self.assertRaisesRegex(metactl.MetadataError, "malformed unused ext4 directory entry"):
            metactl.parse_ls_output(
                """debugfs 1.47.0 (5-Feb-2023)
/0/100644/1000/2000//7/
"""
            )

    def test_directory_listing_error_reports_the_scanned_ext4_path(self) -> None:
        with mock.patch.object(
            metactl,
            "_run_debugfs_text",
            return_value="/13/100644/0/0//7/\n",
        ):
            with self.assertRaisesRegex(metactl.MetadataError, "ext4 directory: /system"):
                metactl._list_directory(Path("/fixture.img"), "/system")

    def test_parses_text_and_binary_extended_attributes(self) -> None:
        output = """debugfs 1.47.0 (5-Feb-2023)
debugfs: ea_list <13>
Extended attributes:
  security.selinux (25) = "u:object_r:system_file:s0"
  security.capability (4) = 00 01 fe ff
debugfs: ea_list <14>
"""
        attributes = metactl.parse_ea_batch(output, [13, 14])
        self.assertEqual(attributes[13]["security.selinux"], b"u:object_r:system_file:s0")
        self.assertEqual(attributes[13]["security.capability"], b"\x00\x01\xfe\xff")
        self.assertEqual(attributes[14], {})


@unittest.skipUnless(shutil.which("debugfs") and shutil.which("mke2fs"), "e2fsprogs is required")
class Ext4MetadataIntegrationTests(unittest.TestCase):
    def debugfs_write(self, image: Path, command: str) -> None:
        result = subprocess.run(
            ["debugfs", "-w", "-R", command, str(image)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout.decode(errors="replace"))
        self.assertNotIn(b"Command not found", result.stdout)

    def test_captures_exact_ext4_metadata_and_symlink_target(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            image = root / "fixture.img"
            payload = root / "payload.bin"
            capability = root / "capability.bin"
            payload.write_bytes(b"fixture-data")
            capability.write_bytes(bytes(range(20)))
            with image.open("wb") as output:
                output.truncate(16 * 1024 * 1024)
            subprocess.run(["mke2fs", "-q", "-t", "ext4", "-F", str(image)], check=True)
            self.debugfs_write(image, "mkdir /system")
            self.debugfs_write(image, f"write {payload} /system/file")
            self.debugfs_write(image, "symlink /system/link file")
            self.debugfs_write(image, "set_inode_field /system/file uid 1000")
            self.debugfs_write(image, "set_inode_field /system/file gid 2000")
            self.debugfs_write(image, "set_inode_field /system/file mode 0100755")
            self.debugfs_write(
                image,
                "ea_set /system/file security.selinux u:object_r:system_file:s0",
            )
            self.debugfs_write(
                image,
                f"ea_set -f {capability} /system/file security.capability",
            )

            entries = metactl.capture_entries(image, ["/system"])
            by_path = {entry["path"]: entry for entry in entries}
            self.assertEqual(sorted(by_path), ["/system", "/system/file", "/system/link"])
            self.assertEqual(by_path["/system/file"]["uid"], 1000)
            self.assertEqual(by_path["/system/file"]["gid"], 2000)
            self.assertEqual(by_path["/system/file"]["permissions_octal"], "0755")
            self.assertEqual(
                base64.b64decode(by_path["/system/file"]["xattrs_b64"]["security.selinux"]),
                b"u:object_r:system_file:s0",
            )
            self.assertEqual(
                base64.b64decode(by_path["/system/file"]["xattrs_b64"]["security.capability"]),
                bytes(range(20)),
            )
            self.assertEqual(by_path["/system/link"]["symlink_target"], "file")
            self.assertEqual(base64.b64decode(by_path["/system/link"]["symlink_target_b64"]), b"file")

            snapshot = metactl.build_snapshot(
                "fixture",
                {
                    "id": "fixture",
                    "size": image.stat().st_size,
                    "sha256": "0" * 64,
                    "block_count": 1,
                    "free_blocks": 1,
                    "block_size": 4096,
                    "used_bytes": 0,
                },
                "integration fixture",
                ["/system"],
                entries,
                "security.selinux",
                "security.capability",
            )
            output = (root / "metadata.json").resolve()
            metactl._atomic_report(output, snapshot)
            verified = metactl.verify_snapshot(output)
            self.assertEqual(verified["metadata_sha256"], snapshot["metadata_sha256"])

            tampered = json.loads(output.read_text(encoding="utf-8"))
            tampered["entries"][1]["uid"] += 1
            output.write_text(json.dumps(tampered), encoding="utf-8")
            with self.assertRaisesRegex(metactl.MetadataError, "digest"):
                metactl.verify_snapshot(output)

            malformed = deepcopy(snapshot)
            malformed["entries"][0]["inode"] = 0
            malformed["metadata_sha256"] = metactl.compatctl.canonical_digest(malformed["entries"])
            malformed["summary"] = metactl._snapshot_summary(
                malformed["entries"],
                "security.selinux",
                "security.capability",
            )
            output.write_text(json.dumps(malformed), encoding="utf-8")
            with self.assertRaisesRegex(metactl.MetadataError, "invalid inode"):
                metactl.verify_snapshot(output)


if __name__ == "__main__":
    unittest.main()
