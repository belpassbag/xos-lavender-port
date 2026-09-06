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

4. Audit the reconstructed archives and extract only the case-approved payloads:

   ```bash
   python3 tools/portctl.py audit-zip base work/sources/lineage-18.1-20221025-nightly-lavender-signed.zip
   python3 tools/portctl.py audit-zip donor work/sources/X6812B-H6912KL-R-OP-231009V922.zip
   python3 tools/portctl.py extract base work/sources/lineage-18.1-20221025-nightly-lavender-signed.zip --output-dir work/extracted
   python3 tools/portctl.py extract donor work/sources/X6812B-H6912KL-R-OP-231009V922.zip --output-dir work/extracted
   ```

Extraction is atomic, validates ZIP paths and expected entry sizes, and never
extracts donor boot/DTBO/preloader/modem images.

Donor vbmeta files are read-only analysis inputs. The locked output policy
forbids packaging or flashing them on `lavender`.

See [docs/AUDIT-1.md](docs/AUDIT-1.md) for the verified feasibility baseline,
[docs/MATERIALIZATION.md](docs/MATERIALIZATION.md) for the accepted source
materialization evidence, [docs/RECOVERY-1.md](docs/RECOVERY-1.md) for the
safety hardening evidence, [docs/RECOVERY-2.md](docs/RECOVERY-2.md) for the
full source revalidation, and [docs/ROADMAP.md](docs/ROADMAP.md) for the
case-by-case execution plan.

## Status

Cases 1 and 2 are accepted: the immutable safety profile, source intake,
uploaded-part verification, byte-exact reconstruction, and ZIP audit all pass
after recovery. Case 3 has not been accepted. No ROM has been built or flashed.
