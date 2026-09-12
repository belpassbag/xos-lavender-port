from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("case5ctl", REPOSITORY_ROOT / "tools" / "case5ctl.py")
assert SPEC is not None and SPEC.loader is not None
case5ctl = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = case5ctl
SPEC.loader.exec_module(case5ctl)


class Case5ContractTests(unittest.TestCase):
    def test_status_default_includes_subprocess_error_context(self) -> None:
        args = case5ctl.build_parser().parse_args(["status", "/tmp/source"])
        self.assertEqual(args.lines, 60)

    def test_stage_order_stops_before_repack_and_flash(self) -> None:
        _profile, _compatibility, _port, _pipeline, contract = case5ctl.metactl.load_and_validate()
        self.assertEqual(contract["status"], "verified")
        self.assertEqual(case5ctl.STAGES[-1], "checkpoint")
        self.assertNotIn("repack", case5ctl.STAGES)
        self.assertNotIn("flash", case5ctl.STAGES)

    def test_default_data_directory_is_outside_repo_when_sources_are_in_repo(self) -> None:
        repository = Path("/tmp/project/repository")
        self.assertEqual(
            case5ctl.default_data_directory(repository, repository),
            Path("/tmp/project/xos-lavender-case5-local"),
        )
        source = Path("/tmp/project/sources")
        self.assertEqual(
            case5ctl.default_data_directory(source, repository),
            source / "case5-local",
        )

    def test_explicit_data_directory_inside_repository_is_rejected(self) -> None:
        with self.assertRaisesRegex(case5ctl.Case5Error, "outside the repository"):
            case5ctl.resolve_layout(
                REPOSITORY_ROOT,
                REPOSITORY_ROOT / "work" / "case5-local",
            )

    def test_local_acceptance_evidence_closes_exact_stage_boundary(self) -> None:
        evidence = json.loads(
            (REPOSITORY_ROOT / "docs" / "CASE-5-1-EVIDENCE.json").read_text(encoding="utf-8")
        )
        self.assertEqual(evidence["schema_version"], 1)
        self.assertEqual(evidence["case"], "5.1")
        self.assertEqual(evidence["status"], "accepted-local")
        self.assertEqual(evidence["state"]["status"], "complete")
        self.assertIsNone(evidence["state"]["active_stage"])
        self.assertFalse(evidence["state"]["process_live"])
        self.assertEqual(evidence["state"]["completed_stages"], list(case5ctl.STAGES))
        self.assertEqual(evidence["checkpoint"]["status"], "verified")
        self.assertRegex(evidence["checkpoint"]["sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(evidence["metadata"], {"snapshots": 4, "status": "verified"})
        self.assertTrue(evidence["boundary"]["case_5_1_complete"])
        self.assertIn("Case 5.2", evidence["boundary"]["next_allowed"])
        self.assertEqual(
            evidence["guards"],
            {
                "automatic_flash": False,
                "image_repack": False,
                "production_signing": False,
                "source_archives_preserved": True,
            },
        )

    def test_local_acceptance_evidence_matches_locked_payload_identities(self) -> None:
        evidence = json.loads(
            (REPOSITORY_ROOT / "docs" / "CASE-5-1-EVIDENCE.json").read_text(encoding="utf-8")
        )
        _profile, compatibility, port, _pipeline, _contract = case5ctl.metactl.load_and_validate()
        expected_sources = [
            {
                "filename": port[role]["filename"],
                "role": role,
                "sha256": port[role]["sha256"],
                "size": port[role]["size"],
            }
            for role in ("base", "donor")
        ]
        expected_images = [
            {field: image[field] for field in ("id", "sha256", "size")}
            for image in compatibility["images"]
        ]
        self.assertEqual(evidence["source_archives"], expected_sources)
        self.assertEqual(evidence["images"], expected_images)
        self.assertEqual(
            evidence["evidence_source"]["tooling_git_commit"],
            "d762ce62c9bb8e913fb8e244f8d1be6711c64dd3",
        )
        self.assertEqual(evidence["evidence_source"]["attempt"], 7)
        self.assertEqual(evidence["development_signing"]["mode"], "project-development")
        self.assertFalse(evidence["development_signing"]["private_key_committed"])
        self.assertFalse(evidence["development_signing"]["production_signing"])


class DurableStateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.profile, _compatibility, _port, _pipeline, self.contract = case5ctl.metactl.load_and_validate()

    def layout(self, temporary: str) -> case5ctl.Layout:
        root = Path(temporary)
        source = root / "sources"
        source.mkdir()
        return case5ctl.resolve_layout(source, root / "case5-data", create=True)

    def test_stage_completion_is_atomic_and_reusable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            layout = self.layout(temporary)
            state = case5ctl.initial_state(layout, self.contract)
            result = case5ctl.execute_stage(
                layout,
                state,
                "preflight",
                lambda: {"status": "verified", "fixture": 1},
            )
            self.assertEqual(result["fixture"], 1)
            restored = case5ctl.load_state(layout, self.contract)
            assert restored is not None
            self.assertEqual(restored["completed_stages"], ["preflight"])
            reused = case5ctl.execute_stage(
                layout,
                restored,
                "preflight",
                lambda: self.fail("completed stage must not execute again"),
            )
            self.assertEqual(reused["fixture"], 1)

    def test_space_floor_tracks_the_next_heavy_resume_stage(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            layout = self.layout(temporary)
            cases = (
                ([], "image-materialization", 24 * 1024**3),
                (list(case5ctl.STAGES[:4]), "root-extraction", 6 * 1024**3),
                (list(case5ctl.STAGES[:5]), "development-build", 4 * 1024**3),
                (list(case5ctl.STAGES[:7]), "verification-and-metadata", 1024**3),
            )
            with mock.patch.object(
                case5ctl.shutil,
                "disk_usage",
                return_value=SimpleNamespace(free=100 * 1024**3),
            ):
                for completed, phase, required in cases:
                    report = case5ctl.runtime_space_check(
                        layout,
                        self.profile,
                        {"completed_stages": completed},
                    )
                    self.assertEqual(report["phase"], phase)
                    self.assertEqual(report["required_free_bytes"], required)

    def test_failed_stage_stays_at_same_resume_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            layout = self.layout(temporary)
            state = case5ctl.initial_state(layout, self.contract)

            def fail() -> dict:
                raise case5ctl.Case5Error("fixture interruption")

            with self.assertRaisesRegex(case5ctl.Case5Error, "interruption"):
                case5ctl.execute_stage(layout, state, "preflight", fail)
            restored = case5ctl.load_state(layout, self.contract)
            assert restored is not None
            self.assertEqual(restored["completed_stages"], [])
            self.assertEqual(restored["status"], "failed")
            self.assertEqual(restored["failure"]["stage"], "preflight")
            case5ctl.execute_stage(
                layout,
                restored,
                "preflight",
                lambda: {"status": "verified"},
            )
            final = case5ctl.load_state(layout, self.contract)
            assert final is not None
            self.assertEqual(final["completed_stages"], ["preflight"])

    def test_start_uses_a_detached_child_and_records_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            layout = self.layout(temporary)
            fake_process = mock.Mock(pid=43210)
            with mock.patch.object(case5ctl.subprocess, "Popen", return_value=fake_process) as popen:
                report = case5ctl.start(layout)
            self.assertEqual(report["status"], "started")
            self.assertFalse(report["source_archives_consumed"])
            call = popen.call_args
            self.assertTrue(call.kwargs["start_new_session"])
            self.assertIn("--wait-lock", call.args[0])
            state = json.loads(layout.state.read_text(encoding="utf-8"))
            self.assertEqual(state["status"], "queued")
            self.assertEqual(state["pid"], 43210)
            self.assertEqual(state["completed_stages"], [])

    def test_checkpoint_locks_dev_signing_metadata_and_no_flash_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            layout = self.layout(temporary)
            base = layout.source / "base.zip"
            donor = layout.source / "donor.zip"
            base.write_bytes(b"base")
            donor.write_bytes(b"donor")
            layout.private_key.write_bytes(b"private")
            layout.private_key.chmod(0o600)
            layout.certificate.write_bytes(b"certificate")
            certificate_sha256 = "a" * 64
            key_report = {
                "certificate_sha256": certificate_sha256,
                "public_key_sha256": "b" * 64,
            }
            case5ctl._atomic_json(layout.reports / "development-key.json", key_report)
            case5ctl._atomic_json(
                layout.reports / "development-root-verified.json",
                {
                    "status": "verified",
                    "apk_inventory": {"total": 227},
                    "preopt_residue": 0,
                    "tree_manifest": {"sha256": "c" * 64},
                },
            )
            port = {
                "base": {"filename": base.name, "size": 4, "sha256": "1" * 64},
                "donor": {"filename": donor.name, "size": 5, "sha256": "2" * 64},
            }

            def source_result(role: str, path: Path) -> dict:
                file_stat = path.stat()
                expected = port[role]
                return {
                    "status": "verified",
                    "role": role,
                    "filename": expected["filename"],
                    "size": expected["size"],
                    "sha256": expected["sha256"],
                    "path": str(path),
                    "preserved": True,
                    "verified_by": "fixture",
                    "stat": {
                        "device": file_stat.st_dev,
                        "inode": file_stat.st_ino,
                        "mtime_ns": file_stat.st_mtime_ns,
                    },
                }

            image_ids = ["base_system", "base_vendor", "donor_system", "donor_product", "donor_system_ext"]
            images = [
                {
                    "id": identifier,
                    "size": index + 1,
                    "sha256": str(index) * 64,
                    "block_count": 10,
                    "free_blocks": 1,
                    "block_size": 4096,
                }
                for index, identifier in enumerate(image_ids, 1)
            ]
            compatibility = {"images": images}
            state = {
                "stage_results": {
                    "base_images": {"source": source_result("base", base)},
                    "donor_images": {"source": source_result("donor", donor)},
                }
            }
            metadata_reports = {}
            for identifier in ("base_system", "donor_system", "donor_product", "donor_system_ext"):
                snapshot = layout.snapshot(identifier)
                snapshot.write_text("fixture", encoding="utf-8")
                report = {
                    "status": "verified",
                    "snapshot": str(snapshot),
                    "snapshot_sha256": identifier[0] * 64,
                    "image": {"sha256": next(row["sha256"] for row in images if row["id"] == identifier)},
                    "roots": ["/"],
                    "metadata_sha256": identifier[-1] * 64,
                    "summary": {"entries": 1},
                }
                metadata_reports[str(snapshot)] = report
                state["stage_results"][f"metadata_{identifier}"] = {
                    "snapshot": str(snapshot),
                    "snapshot_sha256": report["snapshot_sha256"],
                }

            profile = self.profile
            with (
                mock.patch.object(case5ctl, "_verify_all_images", return_value={"images": images}),
                mock.patch.object(
                    case5ctl.compatctl,
                    "verify_image",
                    return_value={**next(row for row in images if row["id"] == "base_vendor")},
                ),
                mock.patch.object(case5ctl.buildctl.apksign, "verify_key_pair", return_value=key_report),
                mock.patch.object(
                    case5ctl.metactl,
                    "verify_snapshot",
                    side_effect=lambda path: metadata_reports[str(path)],
                ),
            ):
                result = case5ctl.create_checkpoint(
                    layout,
                    profile,
                    compatibility,
                    port,
                    state,
                    {"sha256": "d" * 64, "files": []},
                )
            self.assertEqual(result["status"], "verified")
            checkpoint = json.loads(layout.checkpoint.read_text(encoding="utf-8"))
            self.assertTrue(checkpoint["guards"]["development_signing_only"])
            self.assertFalse(checkpoint["guards"]["production_signing"])
            self.assertFalse(checkpoint["guards"]["image_repack"])
            self.assertFalse(checkpoint["guards"]["automatic_flash"])
            self.assertEqual(checkpoint["metadata"]["preserved_image"]["id"], "base_vendor")
            self.assertIn("Case 5.2", checkpoint["boundary"]["next_allowed"])


if __name__ == "__main__":
    unittest.main()
