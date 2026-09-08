# Port roadmap

Each case follows analysis → implementation → verification. A later case may not
start until the current case passes its acceptance checks.

## Case 1 — Repository and source intake

Status: **accepted; safety profile recovered and re-verified on 2026-09-06**.

- Record exact source names, sizes, and SHA-256 hashes.
- Encode immutable hardware/partition safety policy.
- Implement deterministic split-source reconstruction.
- Add unit tests and local checks.

Acceptance: configuration validation and all source-intake tests pass.

The recovery evidence is recorded in [RECOVERY-1.md](RECOVERY-1.md).

## Case 2 — Source materialization

Status: **accepted; sources fully revalidated on 2026-09-06**.

- Verify every uploaded part against its manifest.
- Reconstruct both source ZIPs atomically.
- Verify reconstructed size and SHA-256 against the locked profile.
- Audit ZIP paths and required entries.

Acceptance: both exact source archives are available locally and verified.

The recovery evidence is recorded in [RECOVERY-2.md](RECOVERY-2.md).

## Case 3 — Partition extraction and compatibility audit

Status: **accepted on 2026-09-07; static compatibility gates pass**.

- Convert Lineage block OTA payloads to target system/vendor images.
- Convert sparse donor `super.img` and extract logical partitions.
- Measure filesystem use and partition headroom.
- Compare Android/VNDK, VINTF, init, SELinux, framework, native-library, and APK
  dependencies.

Acceptance: a fact-backed keep/remove/patch matrix exists and the selected XOS
core payload fits the stock `lavender` system partition.

The recovery boundary is recorded in
[RECOVERY-3-CHECKPOINT.md](RECOVERY-3-CHECKPOINT.md). The final measured
evidence, drift corrections, signing decision, and keep/remove/patch matrix are
recorded in [CASE-3-REPORT.md](CASE-3-REPORT.md).

## Case 4 — XOS Core port pipeline

Status: **accepted for static development on 2026-09-08**.

- Preserve the Lineage system-as-root bootstrap and Qualcomm hardware stack.
- Transplant the donor TSSI framework and selected XOS core components.
- Remove donor hardware services and first-boot exclusions.
- Patch properties, permissions, overlays, VINTF, init references, and SELinux
  labels with the smallest verified change set.

Acceptance: the generated root tree passes policy, dependency, and size checks.

The recovery history is recorded in
[CASE-4-CHECKPOINT.md](CASE-4-CHECKPOINT.md). Final measured evidence, drift
fixes, development-signing result, and the Case 5 boundary are recorded in
[CASE-4-REPORT.md](CASE-4-REPORT.md) and
[CASE-4-EVIDENCE.json](CASE-4-EVIDENCE.json).

## Case 5 — Repack and static validation

Status: **in progress; Case 5.1 implementation verified, local payload
execution pending**.

### Case 5.1 — Durable rebuild and source metadata

- Run the exact Case 4 regeneration as a detached, single-worker, resumable
  local job.
- Persist one project development key outside Git and record its public
  identity.
- Capture UID/GID, modes, symlinks, SELinux labels, capabilities, and all other
  xattrs directly from the locked source ext4 images.
- Publish an atomic machine-readable checkpoint without repacking or flashing.

Acceptance: `reports/case5-1-checkpoint.json` passes on the payload-holding
machine. Tooling and synthetic-ext4 verification are complete; the local
payload run is still required. See
[CASE-5-1-CHECKPOINT.md](CASE-5-1-CHECKPOINT.md).

### Case 5.2 — Metadata reconstruction and image repack

- Rebuild the target system image reproducibly within the stock size.
- Apply source-proven metadata to every final path and verify there are no
  unmapped entries.

This subcase is blocked until Case 5.1 local acceptance.

### Case 5.3 — Recovery test package

- Generate a recovery-installable test package from the Lineage base layout.
- Retain target boot/vendor and target-compatible AVB handling.

### Case 5.4 — Artifact validation

- Run ZIP, image, path, architecture, policy, and checksum validation.

Acceptance: a versioned test artifact and verification report pass locally.

## Case 6 — Device test and log-driven fixes

- Require verified backups and an explicit manual flashing checkpoint.
- Test first boot without donor GMS/SetupWizard.
- Collect recovery, kernel, logcat, tombstone, and service diagnostics.
- Apply one evidence-backed fix per iteration.

Acceptance: stable boot and agreed essential functions pass on the physical
device. Flashing remains manual.

## Final closure

- Audit the complete diff and generated reports.
- Document known limitations and recovery procedure.
- Tag the verified source/tooling state and publish checksums for any release
  artifact.
