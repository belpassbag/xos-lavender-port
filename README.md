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

   For a shared Google Drive folder, first create a two-column local ID map
   (`DRIVE_FILE_ID PART_FILENAME`) from the authenticated folder listing. The
   downloader resumes at verified part boundaries, uses an exclusive lock, and
   publishes each part only after its SHA-256 matches:

   ```bash
   scripts/download-drive-parts.sh SHA256SUMS-parts.txt drive-ids.txt incoming lineage.zip.part-
   scripts/download-drive-parts.sh SHA256SUMS-parts.txt drive-ids.txt incoming xos.zip.part-
   ```

   Drive IDs remain runtime inputs and are not committed to this repository.

4. Audit the reconstructed archives and extract only the case-approved payloads:

   ```bash
   python3 tools/portctl.py audit-zip base work/sources/lineage-18.1-20221025-nightly-lavender-signed.zip
   python3 tools/portctl.py audit-zip donor work/sources/X6812B-H6912KL-R-OP-231009V922.zip
   python3 tools/portctl.py extract base work/sources/lineage-18.1-20221025-nightly-lavender-signed.zip --output-dir work/extracted
   python3 tools/portctl.py extract donor work/sources/X6812B-H6912KL-R-OP-231009V922.zip --output-dir work/extracted
   ```

Extraction is atomic, validates ZIP paths and expected entry sizes, and never
extracts donor boot/DTBO/preloader/modem images.

Case 4 source recovery can resume direct Drive downloads and materialize base
and donor images in separate disk-bounded stages:

```bash
scripts/download-drive-file.sh DRIVE_ID EXPECTED_BYTES EXPECTED_SHA256 /absolute/work/source.zip
scripts/materialize-case4-images.sh base /absolute/work/base.zip /absolute/work --consume-source
scripts/materialize-case4-images.sh donor /absolute/work/donor.zip /absolute/work --consume-source
```

Only a downloaded source located inside the selected work root can be consumed.
Every image must pass its locked identity and read-only filesystem check before
the next regenerable layer is pruned.

5. Extract/reuse the two full roots plus the minimum audited selection, then
   run the exact Case 4 input gate:

   ```bash
   scripts/extract-case4-roots.sh /absolute/image-work /absolute/case4-work
   ```

6. Create a project-specific development key outside this repository and build
   the resumable development root:

   ```bash
   python3 tools/buildctl.py init-dev-key --key-dir /absolute/private-key-dir
   python3 tools/buildctl.py build \
     --base-root /absolute/case4-work/roots/base \
     --donor-system-root /absolute/case4-work/roots/donor-system \
     --donor-product-root /absolute/case4-work/selection/donor/product \
     --donor-system-ext-root /absolute/case4-work/selection/donor/system_ext \
     --output-root /absolute/case4-work/output/dev-root \
     --development-key /absolute/private-key-dir/platform-development.pem \
     --development-cert /absolute/private-key-dir/platform-development.der \
     --report /absolute/case4-work/reports/output.json
   ```

The private key must remain mode `0600` and outside Git. Platform-domain APKs
are signed with APK Signature Scheme v2; standalone APK and APEX signatures are
preserved. The completed tree is re-verifiable with `buildctl.py verify-output`.

Donor vbmeta files are read-only analysis inputs. The locked output policy
forbids packaging or flashing them on `lavender`.

See [docs/AUDIT-1.md](docs/AUDIT-1.md) for the verified feasibility baseline,
[docs/MATERIALIZATION.md](docs/MATERIALIZATION.md) for the accepted source
materialization evidence, [docs/RECOVERY-1.md](docs/RECOVERY-1.md) for the
safety hardening evidence, [docs/RECOVERY-2.md](docs/RECOVERY-2.md) for the
full source revalidation,
[docs/RECOVERY-3-CHECKPOINT.md](docs/RECOVERY-3-CHECKPOINT.md) for the durable
Case 3 restart point, [docs/CASE-3-REPORT.md](docs/CASE-3-REPORT.md) for the
accepted compatibility evidence and keep/remove/patch matrix, and
[docs/CASE-4-CHECKPOINT.md](docs/CASE-4-CHECKPOINT.md) for the Case 4 recovery
history. The accepted static build evidence and remaining boundary are in
[docs/CASE-4-REPORT.md](docs/CASE-4-REPORT.md) and
[docs/CASE-4-EVIDENCE.json](docs/CASE-4-EVIDENCE.json). See
[docs/ROADMAP.md](docs/ROADMAP.md) for the case-by-case execution plan.

## Status

Cases 1 through 4 are accepted. Source intake/reconstruction is byte-exact, the
resumable extraction path is verified, and the selected XOS core development
root passes the locked signing, shared-UID, dependency, capacity, and static
compatibility gates. Production signing remains deferred until physical boot
and functional stability. No flashable ROM image has been built or flashed;
Case 5 has not started.
