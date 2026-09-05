# XOS Lavender Port

Reproducible tooling and documentation for an experimental, debloated XOS 7.6
Android 11 framework port to Xiaomi Redmi Note 7 (`lavender`).

## Locked profile

- Target/base: LineageOS 18.1 Android 11 for `lavender` (Qualcomm SDM660).
- Donor: Infinix HOT 11S NFC X6812B XOS 7.6 (MediaTek MT6768).
- First boot scope: XOS core UI, Settings, Launcher, and required framework/overlays.
- Hardware stack: always inherited from the `lavender` base.
- First boot excludes donor GMS/SetupWizard, operator apps, camera, FaceID, NFC,
  calibration tools, and MediaTek hardware services.

This repository intentionally contains no proprietary ROM payloads and no
automatic flashing command.

## Safety invariants

The build pipeline must never package donor `boot`, `dtbo`, `vendor`, `vbmeta`,
preloader, modem, or other MediaTek firmware images for `lavender`. It must also
remain inside the stock `lavender` partition sizes; repartitioning is outside the
project scope.

## Current workflow

1. Validate the immutable source profile:

   ```bash
   make check
   ```

2. On the machine holding the original ZIP files, create Drive-safe chunks:

   ```bash
   scripts/prepare-parts.sh \
     lineage-18.1-20221025-nightly-lavender-signed.zip \
     X6812B-H6912KL-R-OP-231009V922.zip
   ```

3. Place all chunks and `SHA256SUMS-parts.txt` in `incoming/`, then reconstruct
   and verify without overwriting an existing source:

   ```bash
   python3 tools/portctl.py assemble base --parts-dir incoming --output-dir work/sources
   python3 tools/portctl.py assemble donor --parts-dir incoming --output-dir work/sources
   ```

See [docs/AUDIT-1.md](docs/AUDIT-1.md) for the verified feasibility baseline and
[docs/ROADMAP.md](docs/ROADMAP.md) for the case-by-case execution plan.

## Status

Case 1 is repository/source-intake foundation. No ROM has been built or flashed.
