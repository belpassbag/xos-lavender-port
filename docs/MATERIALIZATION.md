# Case 2 — Source materialization report

Status: **accepted on 2026-09-06**.

No proprietary ROM payload is committed to this repository. The source files
were materialized in temporary build storage from the user-provided
`XOS-Lavender-Parts` Drive folder.

## Uploaded-part verification

| Source | Parts | Full-size parts | Final part | Result |
|---|---:|---:|---:|---|
| LineageOS base | 5 | 4 × 209,715,200 bytes | 12,200,545 bytes | All SHA-256 checks passed |
| XOS donor | 19 | 18 × 209,715,200 bytes | 164,485,466 bytes | All SHA-256 checks passed |

The uploaded `SHA256SUMS-parts.txt` contained one unique checksum for every
part. Both numeric sequences started at `000`, were contiguous, and contained
no extra matching part names. Verification was repeated with
`portctl.py verify-parts` after download.

## Reconstructed-source verification

| Role | File | Bytes | SHA-256 | Result |
|---|---|---:|---|---|
| Target/base | `lineage-18.1-20221025-nightly-lavender-signed.zip` | 851,061,345 | `4845c4910593a6b8a612c5ea9af1b6752fe8ab2514f62e062abe759e760b82ba` | Match |
| Framework donor | `X6812B-H6912KL-R-OP-231009V922.zip` | 3,939,359,066 | `5066e7b7e397bad14b81d91f42a1d79e05c150e37c7b047f7b52e5b4b8a178b0` | Match |

Reconstruction used a new temporary file, an `fsync`, complete size and
SHA-256 validation, and an atomic rename. An existing output can only be reused
after the same locked size and hash checks pass.

## ZIP audit

| Source | Entries | Total uncompressed bytes | Approved extraction bytes | Result |
|---|---:|---:|---:|---|
| LineageOS base | 14 | 906,178,204 | 904,168,980 | Pass |
| XOS donor | 40 | 6,979,505,485 | 6,808,689,800 | Pass |

Both archives passed checks for their locked source identity, safe relative
paths, unique entry names, absence of encrypted entries and ZIP symlinks,
required entries, and exact expected entry sizes. The extraction allowlist does
not include donor `boot.img`, `dtbo.img`, preloader, modem, vendor, or firmware
images.

## Acceptance

Case 2 passes. Case 3 may consume only the verified allowlisted payloads and
must continue to preserve the `lavender` boot, kernel, vendor, DTBO, vbmeta,
modem, firmware, fstab, and init stack.
