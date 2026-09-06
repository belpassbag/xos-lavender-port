# Case 2 source revalidation

Status: **accepted on 2026-09-06 after full re-download and verification**.

This recovery confirms that Case 2 remains reproducible after its original
temporary build workspace was cleared. No proprietary source part or ROM ZIP is
committed to this repository.

## Problem

The original Case 2 evidence was committed, but the ignored temporary source
workspace no longer existed. Case 3 could not safely resume until the Drive
inputs and both reconstructed archives were verified again.

## Cause

ROM sources and expanded images are intentionally excluded from Git. Temporary
workspace cleanup therefore removes the local materialization while leaving
the accepted evidence and the user-owned Drive uploads intact.

## Solution

- Re-list the exact `XOS-Lavender-Parts` Drive folder.
- Require exactly 24 source parts and one checksum manifest.
- Re-download every part into ignored build storage.
- Verify every part against `SHA256SUMS-parts.txt`.
- Reconstruct each source atomically and verify its complete locked identity.
- Repeat the ZIP structure and extraction-allowlist audit.

## Verification

| Check | Base | Donor | Result |
|---|---:|---:|---|
| Drive parts | 5 | 19 | Pass |
| Full-size parts | 4 × 209,715,200 | 18 × 209,715,200 | Pass |
| Final part | 12,200,545 | 164,485,466 | Pass |
| ZIP entries | 14 | 40 | Pass |

The Drive folder contained exactly 25 expected items, with no missing, extra,
or wrong-sized file. All 25 were downloadable. The 24-line manifest had
SHA-256 `8a6967217ed7758acd480bbb35a6c92151b60f3bc35f89cce6a0efccc07c2c9a`.

The reconstructed source identities were:

| Role | Bytes | SHA-256 |
|---|---:|---|
| LineageOS base | 851,061,345 | `4845c4910593a6b8a612c5ea9af1b6752fe8ab2514f62e062abe759e760b82ba` |
| XOS donor | 3,939,359,066 | `5066e7b7e397bad14b81d91f42a1d79e05c150e37c7b047f7b52e5b4b8a178b0` |

The base audit approved 904,168,980 extraction bytes. The donor audit approved
6,808,689,800 extraction bytes. Standalone donor boot, DTBO, preloader, modem,
and firmware remain outside normal ZIP extraction. The donor vendor logical
partition remains outside approved LP extraction and final output. Donor vbmeta
remains analysis-only and forbidden from final output.

Case 3 may start only after this report passes pull-request CI and the resulting
`main` commit passes post-merge CI.
