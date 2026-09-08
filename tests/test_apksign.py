from __future__ import annotations

import importlib.util
import hashlib
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
import zipfile


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT / "tools"))
import compatctl  # noqa: E402

SPEC = importlib.util.spec_from_file_location("apksign", REPOSITORY_ROOT / "tools" / "apksign.py")
assert SPEC is not None and SPEC.loader is not None
apksign = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = apksign
SPEC.loader.exec_module(apksign)


class ApkV2SigningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temporary.name)
        cls.key = cls.root / "development.pem"
        cls.cert = cls.root / "development.der"
        cls.key_report = apksign.initialize_key(
            cls.key.resolve(),
            cls.cert.resolve(),
            "/CN=Case 4 Unit Test/O=XOS Lavender/",
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    def fixture(self, name: str) -> Path:
        path = self.root / name
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("classes.dex", b"dex\n035\0" + b"fixture" * 4096)
            archive.writestr("res/raw/value.txt", b"payload")
            archive.writestr("META-INF/MANIFEST.MF", b"stale")
            archive.writestr("META-INF/OLD.SF", b"stale")
            archive.writestr("META-INF/OLD.RSA", b"stale")
        return path

    def test_initializes_private_local_key_with_restricted_permissions(self) -> None:
        self.assertEqual(stat.S_IMODE(self.key.stat().st_mode), 0o600)
        self.assertEqual(len(self.key_report["certificate_sha256"]), 64)
        self.assertEqual(apksign.verify_key_pair(self.key.resolve(), self.cert.resolve()), self.key_report)

    def test_sign_and_verify_v2_content(self) -> None:
        source = self.fixture("roundtrip-unsigned.apk")
        output = self.root / "roundtrip-signed.apk"
        signed = apksign.sign_apk(source.resolve(), output.resolve(), self.key.resolve(), self.cert.resolve())
        verified = apksign.verify_apk(output.resolve())
        self.assertEqual(signed, verified)
        self.assertEqual(verified["status"], "verified")
        self.assertEqual(verified["scheme"], "v2")
        self.assertEqual(verified["certificate_sha256"], self.key_report["certificate_sha256"])
        embedded_certificate = compatctl._apk_signing_certificate(output.read_bytes())
        self.assertIsNotNone(embedded_certificate)
        assert embedded_certificate is not None
        self.assertEqual(
            hashlib.sha256(embedded_certificate).hexdigest(),
            self.key_report["certificate_sha256"],
        )
        with zipfile.ZipFile(output) as archive:
            self.assertEqual(archive.testzip(), None)

    def test_removes_v1_signature_records_from_directory(self) -> None:
        source = self.fixture("v1-unsigned.apk")
        output = self.root / "v1-signed.apk"
        apksign.sign_apk(source.resolve(), output.resolve(), self.key.resolve(), self.cert.resolve())
        with zipfile.ZipFile(output) as archive:
            self.assertEqual(sorted(archive.namelist()), ["classes.dex", "res/raw/value.txt"])

    def test_rejects_content_tampering(self) -> None:
        source = self.fixture("tamper-unsigned.apk")
        output = self.root / "tamper-signed.apk"
        apksign.sign_apk(source.resolve(), output.resolve(), self.key.resolve(), self.cert.resolve())
        data = bytearray(output.read_bytes())
        data[48] ^= 0x01
        output.write_bytes(data)
        with self.assertRaisesRegex(apksign.ApkSignError, "digest"):
            apksign.verify_apk(output.resolve())

    def test_rejects_group_readable_private_key(self) -> None:
        source = self.fixture("mode-unsigned.apk")
        output = self.root / "mode-signed.apk"
        os.chmod(self.key, 0o640)
        try:
            with self.assertRaisesRegex(apksign.ApkSignError, "permissions"):
                apksign.sign_apk(source.resolve(), output.resolve(), self.key.resolve(), self.cert.resolve())
        finally:
            os.chmod(self.key, 0o600)


if __name__ == "__main__":
    unittest.main()
