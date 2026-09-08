#!/usr/bin/env python3
"""Minimal fail-closed APK Signature Scheme v2 development signer.

The implementation intentionally supports one conservative signing profile:
RSA PKCS#1 v1.5 with SHA-256 (algorithm ID 0x0103), one signer, no v3/v4
metadata, and no key storage.  OpenSSL performs every private-key operation;
Python only constructs and validates the APK v2 container.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import tempfile


APK_SIG_MAGIC = b"APK Sig Block 42"
APK_SIG_V2 = 0x7109871A
RSA_PKCS1_SHA256 = 0x0103
CHUNK_SIZE = 1024 * 1024
EOCD_MAGIC = b"PK\x05\x06"
CD_MAGIC = b"PK\x01\x02"


class ApkSignError(RuntimeError):
    """The APK or signing material is invalid."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ApkSignError(message)


def _run(command: list[str], *, input_data: bytes | None = None) -> bytes:
    try:
        result = subprocess.run(
            command,
            input=input_data,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as exc:
        raise ApkSignError(f"cannot execute {command[0]}: {exc}") from exc
    if result.returncode:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise ApkSignError(f"{command[0]} failed: {detail or 'no diagnostic'}")
    return result.stdout


def _lp(value: bytes) -> bytes:
    _require(len(value) <= 0xFFFFFFFF, "length-prefixed value is too large")
    return struct.pack("<I", len(value)) + value


def _read_lp(value: bytes, offset: int, label: str) -> tuple[bytes, int]:
    _require(offset + 4 <= len(value), f"truncated {label} length")
    size = struct.unpack_from("<I", value, offset)[0]
    start = offset + 4
    end = start + size
    _require(end <= len(value), f"truncated {label}")
    return value[start:end], end


def _single_lp(value: bytes, label: str) -> bytes:
    item, end = _read_lp(value, 0, label)
    _require(end == len(value), f"unexpected trailing data in {label}")
    return item


def _regular_file(path: Path, label: str) -> None:
    _require(path.is_absolute(), f"{label} must be absolute")
    _require(path.is_file() and not path.is_symlink(), f"{label} is not a regular file: {path}")


def _private_key(path: Path) -> None:
    _regular_file(path, "private key")
    mode = stat.S_IMODE(path.stat().st_mode)
    _require(mode & 0o077 == 0, f"private key permissions must exclude group/other access: {path}")


def certificate_fingerprint(certificate: Path) -> str:
    _regular_file(certificate, "certificate")
    data = certificate.read_bytes()
    _require(data.startswith(b"0"), "certificate must be DER encoded")
    return hashlib.sha256(data).hexdigest()


def _public_key_from_private(private_key: Path) -> bytes:
    return _run(["openssl", "pkey", "-in", str(private_key), "-pubout", "-outform", "DER"])


def _public_key_from_certificate(certificate: Path) -> bytes:
    pem = _run(["openssl", "x509", "-inform", "DER", "-in", str(certificate), "-pubkey", "-noout"])
    return _run(["openssl", "pkey", "-pubin", "-outform", "DER"], input_data=pem)


def verify_key_pair(private_key: Path, certificate: Path) -> dict:
    _private_key(private_key)
    _regular_file(certificate, "certificate")
    private_public = _public_key_from_private(private_key)
    certificate_public = _public_key_from_certificate(certificate)
    _require(private_public == certificate_public, "private key does not match certificate")
    return {
        "algorithm": "RSA-PKCS1-SHA256",
        "certificate_sha256": certificate_fingerprint(certificate),
        "public_key_sha256": hashlib.sha256(private_public).hexdigest(),
    }


def initialize_key(private_key: Path, certificate: Path, subject: str) -> dict:
    _require(private_key.is_absolute() and certificate.is_absolute(), "key paths must be absolute")
    _require(not private_key.exists() and not private_key.is_symlink(), f"private key already exists: {private_key}")
    _require(not certificate.exists() and not certificate.is_symlink(), f"certificate already exists: {certificate}")
    _require(subject.startswith("/") and "\n" not in subject, "OpenSSL subject must be an absolute one-line DN")
    private_key.parent.mkdir(parents=True, exist_ok=True)
    certificate.parent.mkdir(parents=True, exist_ok=True)
    _require(private_key.parent.resolve() == certificate.parent.resolve(), "key and certificate must share a directory")
    directory = private_key.parent
    key_fd, key_name = tempfile.mkstemp(prefix=".development-key.", suffix=".partial", dir=directory)
    cert_fd, cert_name = tempfile.mkstemp(prefix=".development-cert.", suffix=".partial", dir=directory)
    os.close(key_fd)
    os.close(cert_fd)
    key_temporary = Path(key_name)
    cert_temporary = Path(cert_name)
    try:
        key_temporary.chmod(0o600)
        _run(
            [
                "openssl",
                "req",
                "-new",
                "-x509",
                "-newkey",
                "rsa:3072",
                "-sha256",
                "-nodes",
                "-days",
                "3650",
                "-subj",
                subject,
                "-keyout",
                str(key_temporary),
                "-outform",
                "DER",
                "-out",
                str(cert_temporary),
            ]
        )
        key_temporary.chmod(0o600)
        cert_temporary.chmod(0o644)
        verify_key_pair(key_temporary.resolve(), cert_temporary.resolve())
        os.replace(key_temporary, private_key)
        os.replace(cert_temporary, certificate)
    except Exception:
        key_temporary.unlink(missing_ok=True)
        cert_temporary.unlink(missing_ok=True)
        raise
    return verify_key_pair(private_key, certificate)


def _find_eocd(data: bytes) -> int:
    start = max(0, len(data) - (0xFFFF + 22))
    offset = data.rfind(EOCD_MAGIC, start)
    _require(offset >= 0 and offset + 22 <= len(data), "ZIP end-of-central-directory record is missing")
    comment_length = struct.unpack_from("<H", data, offset + 20)[0]
    _require(offset + 22 + comment_length == len(data), "ZIP has trailing or truncated data")
    disk, cd_disk, disk_entries, total_entries = struct.unpack_from("<HHHH", data, offset + 4)
    _require(disk == cd_disk == 0, "multi-disk ZIP is unsupported")
    _require(disk_entries == total_entries != 0xFFFF, "ZIP64 or inconsistent entry counts are unsupported")
    cd_size, cd_offset = struct.unpack_from("<II", data, offset + 12)
    _require(cd_size != 0xFFFFFFFF and cd_offset != 0xFFFFFFFF, "ZIP64 APK is unsupported")
    _require(cd_offset + cd_size == offset, "central directory bounds are inconsistent")
    return offset


def _signing_block_start(data: bytes, central_offset: int) -> int | None:
    if central_offset < 24 or data[central_offset - 16 : central_offset] != APK_SIG_MAGIC:
        return None
    size = struct.unpack_from("<Q", data, central_offset - 24)[0]
    _require(size >= 24 and size <= central_offset - 8, "invalid APK signing-block size")
    start = central_offset - size - 8
    _require(struct.unpack_from("<Q", data, start)[0] == size, "APK signing-block size mismatch")
    return start


def _v1_signature_name(raw_name: bytes) -> bool:
    try:
        name = raw_name.decode("utf-8").upper()
    except UnicodeDecodeError:
        return False
    if not name.startswith("META-INF/") or "/" in name[len("META-INF/") :]:
        return False
    leaf = name[len("META-INF/") :]
    return leaf == "MANIFEST.MF" or leaf.startswith("SIG-") or leaf.endswith((".SF", ".RSA", ".DSA", ".EC"))


def _unsigned_sections(data: bytes) -> tuple[bytes, bytes, bytes, int]:
    """Remove an old v2/v3 block and v1 directory records without moving payloads."""
    eocd_offset = _find_eocd(data)
    central_size, central_offset = struct.unpack_from("<II", data, eocd_offset + 12)
    block_start = _signing_block_start(data, central_offset)
    payload_end = block_start if block_start is not None else central_offset
    central = data[central_offset : central_offset + central_size]
    kept: list[bytes] = []
    cursor = 0
    seen: set[bytes] = set()
    while cursor < len(central):
        _require(central[cursor : cursor + 4] == CD_MAGIC, "invalid central-directory entry")
        _require(cursor + 46 <= len(central), "truncated central-directory entry")
        name_length, extra_length, comment_length = struct.unpack_from("<HHH", central, cursor + 28)
        end = cursor + 46 + name_length + extra_length + comment_length
        _require(end <= len(central), "central-directory entry exceeds directory")
        name = central[cursor + 46 : cursor + 46 + name_length]
        _require(name not in seen, "duplicate ZIP member")
        seen.add(name)
        if not _v1_signature_name(name):
            kept.append(central[cursor:end])
        cursor = end
    _require(cursor == len(central), "central-directory length mismatch")
    new_central = b"".join(kept)
    eocd = bytearray(data[eocd_offset:])
    struct.pack_into("<HH", eocd, 8, len(kept), len(kept))
    struct.pack_into("<II", eocd, 12, len(new_central), payload_end)
    return data[:payload_end], new_central, bytes(eocd), payload_end


def _chunked_digest(sections: tuple[bytes, ...]) -> bytes:
    chunks: list[bytes] = []
    for section in sections:
        for start in range(0, len(section), CHUNK_SIZE):
            chunk = section[start : start + CHUNK_SIZE]
            chunks.append(hashlib.sha256(b"\xa5" + struct.pack("<I", len(chunk)) + chunk).digest())
    _require(chunks, "APK content has no digest chunks")
    return hashlib.sha256(b"\x5a" + struct.pack("<I", len(chunks)) + b"".join(chunks)).digest()


def _build_signing_block(signed_data: bytes, signature: bytes, certificate: bytes, public_key: bytes) -> bytes:
    signature_record = struct.pack("<I", RSA_PKCS1_SHA256) + _lp(signature)
    signer = _lp(signed_data) + _lp(_lp(signature_record)) + _lp(public_key)
    value = _lp(_lp(signer))
    pair_value = struct.pack("<I", APK_SIG_V2) + value
    pairs = struct.pack("<Q", len(pair_value)) + pair_value
    size = len(pairs) + 24
    return struct.pack("<Q", size) + pairs + struct.pack("<Q", size) + APK_SIG_MAGIC


def sign_apk(source: Path, output: Path, private_key: Path, certificate: Path) -> dict:
    _regular_file(source, "source APK")
    _require(source != output, "source and output APK must differ")
    _require(output.is_absolute(), "output APK must be absolute")
    _require(not output.is_symlink(), f"refusing symbolic-link output: {output}")
    if output.exists():
        _require(output.is_file(), f"output APK is not a regular file: {output}")
        _require(not os.path.samefile(source, output), "source and output APK share one inode")
    key_report = verify_key_pair(private_key, certificate)
    data = source.read_bytes()
    payload, central, eocd, block_start = _unsigned_sections(data)
    digest = _chunked_digest((payload, central, eocd))
    digest_record = struct.pack("<I", RSA_PKCS1_SHA256) + _lp(digest)
    certificate_bytes = certificate.read_bytes()
    signed_data = _lp(_lp(digest_record)) + _lp(_lp(certificate_bytes)) + _lp(b"")
    with tempfile.TemporaryDirectory(prefix="apksign-") as temporary:
        signed_path = Path(temporary) / "signed-data.bin"
        signature_path = Path(temporary) / "signature.bin"
        signed_path.write_bytes(signed_data)
        _run(
            [
                "openssl",
                "dgst",
                "-sha256",
                "-sign",
                str(private_key),
                "-out",
                str(signature_path),
                str(signed_path),
            ]
        )
        signature = signature_path.read_bytes()
    public_key = _public_key_from_private(private_key)
    block = _build_signing_block(signed_data, signature, certificate_bytes, public_key)
    patched_eocd = bytearray(eocd)
    struct.pack_into("<I", patched_eocd, 16, block_start + len(block))
    result = payload + block + central + bytes(patched_eocd)
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{output.name}.", suffix=".partial", dir=output.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as target:
            target.write(result)
            target.flush()
            os.fsync(target.fileno())
        os.chmod(temporary, stat.S_IMODE(source.stat().st_mode))
        os.replace(temporary, output)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    report = verify_apk(output)
    _require(report["certificate_sha256"] == key_report["certificate_sha256"], "signed APK certificate drift")
    return report


def _parse_v2(data: bytes, block_start: int, central_offset: int) -> tuple[bytes, bytes, bytes, bytes]:
    cursor = block_start + 8
    end = central_offset - 24
    v2_values: list[bytes] = []
    while cursor < end:
        _require(cursor + 8 <= end, "truncated APK signing pair")
        pair_size = struct.unpack_from("<Q", data, cursor)[0]
        cursor += 8
        _require(pair_size >= 4 and cursor + pair_size <= end, "invalid APK signing pair")
        pair_id = struct.unpack_from("<I", data, cursor)[0]
        if pair_id == APK_SIG_V2:
            v2_values.append(data[cursor + 4 : cursor + pair_size])
        cursor += pair_size
    _require(cursor == end and len(v2_values) == 1, "APK must contain exactly one v2 signer block")
    signers = _single_lp(v2_values[0], "v2 signers")
    signer = _single_lp(signers, "v2 signer")
    signed_data, offset = _read_lp(signer, 0, "signed data")
    signatures, offset = _read_lp(signer, offset, "signatures")
    public_key, offset = _read_lp(signer, offset, "public key")
    _require(offset == len(signer), "trailing signer data")
    signature_record = _single_lp(signatures, "signature record")
    _require(len(signature_record) >= 8, "truncated signature record")
    algorithm = struct.unpack_from("<I", signature_record, 0)[0]
    signature, signature_end = _read_lp(signature_record, 4, "signature")
    _require(signature_end == len(signature_record) and algorithm == RSA_PKCS1_SHA256, "unsupported signature algorithm")
    digests, position = _read_lp(signed_data, 0, "digests")
    certificates, position = _read_lp(signed_data, position, "certificates")
    attributes, position = _read_lp(signed_data, position, "attributes")
    _require(position == len(signed_data) and attributes == b"", "unsupported signed-data attributes")
    digest_record = _single_lp(digests, "digest record")
    _require(len(digest_record) >= 8 and struct.unpack_from("<I", digest_record, 0)[0] == algorithm, "digest algorithm mismatch")
    digest, digest_end = _read_lp(digest_record, 4, "content digest")
    _require(digest_end == len(digest_record) and len(digest) == 32, "invalid content digest")
    certificate = _single_lp(certificates, "certificate")
    return signed_data, signature, certificate, public_key


def verify_apk(path: Path) -> dict:
    _regular_file(path, "APK")
    data = path.read_bytes()
    eocd_offset = _find_eocd(data)
    central_size, central_offset = struct.unpack_from("<II", data, eocd_offset + 12)
    block_start = _signing_block_start(data, central_offset)
    _require(block_start is not None, "APK v2 signing block is missing")
    signed_data, signature, certificate, public_key = _parse_v2(data, block_start, central_offset)
    with tempfile.TemporaryDirectory(prefix="apkverify-") as temporary:
        root = Path(temporary)
        cert_path = root / "certificate.der"
        signed_path = root / "signed-data.bin"
        signature_path = root / "signature.bin"
        public_path = root / "public.der"
        public_pem = root / "public.pem"
        cert_path.write_bytes(certificate)
        signed_path.write_bytes(signed_data)
        signature_path.write_bytes(signature)
        public_path.write_bytes(public_key)
        certificate_public = _public_key_from_certificate(cert_path.resolve())
        _require(certificate_public == public_key, "signer public key does not match certificate")
        public_pem.write_bytes(_run(["openssl", "pkey", "-pubin", "-inform", "DER", "-in", str(public_path), "-outform", "PEM"]))
        _run(
            [
                "openssl",
                "dgst",
                "-sha256",
                "-verify",
                str(public_pem),
                "-signature",
                str(signature_path),
                str(signed_path),
            ]
        )
    digests, _ = _read_lp(signed_data, 0, "digests")
    digest_record = _single_lp(digests, "digest record")
    expected_digest, _ = _read_lp(digest_record, 4, "content digest")
    eocd = bytearray(data[eocd_offset:])
    struct.pack_into("<I", eocd, 16, block_start)
    actual_digest = _chunked_digest((data[:block_start], data[central_offset : central_offset + central_size], bytes(eocd)))
    _require(actual_digest == expected_digest, "APK content digest mismatch")
    return {
        "status": "verified",
        "scheme": "v2",
        "algorithm_id": f"0x{RSA_PKCS1_SHA256:04x}",
        "certificate_sha256": hashlib.sha256(certificate).hexdigest(),
        "content_digest_sha256": actual_digest.hex(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    initialize = subparsers.add_parser("init-key", help="create a local project development key")
    initialize.add_argument("--key", type=Path, required=True)
    initialize.add_argument("--cert", type=Path, required=True)
    initialize.add_argument("--subject", default="/CN=XOS Lavender Development/O=Local Porting/")
    sign = subparsers.add_parser("sign", help="sign one APK atomically")
    sign.add_argument("--input", type=Path, required=True)
    sign.add_argument("--output", type=Path, required=True)
    sign.add_argument("--key", type=Path, required=True)
    sign.add_argument("--cert", type=Path, required=True)
    verify = subparsers.add_parser("verify", help="verify one APK v2 signature and content digest")
    verify.add_argument("apk", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "init-key":
            report = initialize_key(args.key.absolute(), args.cert.absolute(), args.subject)
        elif args.command == "sign":
            report = sign_apk(
                args.input.absolute(),
                args.output.absolute(),
                args.key.absolute(),
                args.cert.absolute(),
            )
        else:
            report = verify_apk(args.apk.absolute())
    except ApkSignError as exc:
        parser.exit(1, f"ERROR: {exc}\n")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
