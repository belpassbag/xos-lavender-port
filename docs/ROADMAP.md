# Port roadmap

Each case follows analysis → implementation → verification. A later case may not
start until the current case passes its acceptance checks.

## Case 1 — Repository and source intake

- Record exact source names, sizes, and SHA-256 hashes.
- Encode immutable hardware/partition safety policy.
- Implement deterministic split-source reconstruction.
- Add unit tests and local checks.

Acceptance: configuration validation and all source-intake tests pass.

## Case 2 — Source materialization

Status: **accepted on 2026-09-06**.

- Verify every uploaded part against its manifest.
- Reconstruct both source ZIPs atomically.
- Verify reconstructed size and SHA-256 against the locked profile.
- Audit ZIP paths and required entries.

Acceptance: both exact source archives are available locally and verified.

## Case 3 — Partition extraction and compatibility audit

- Convert Lineage block OTA payloads to target system/vendor images.
- Convert sparse donor `super.img` and extract logical partitions.
- Measure filesystem use and partition headroom.
- Compare Android/VNDK, VINTF, init, SELinux, framework, native-library, and APK
  dependencies.

Acceptance: a fact-backed keep/remove/patch matrix exists and the selected XOS
core payload fits the stock `lavender` system partition.

## Case 4 — XOS Core port pipeline

- Preserve the Lineage system-as-root bootstrap and Qualcomm hardware stack.
- Transplant the donor TSSI framework and selected XOS core components.
- Remove donor hardware services and first-boot exclusions.
- Patch properties, permissions, overlays, VINTF, init references, and SELinux
  labels with the smallest verified change set.

Acceptance: the generated root tree passes policy, dependency, and size checks.

## Case 5 — Repack and static validation

- Rebuild the target system image reproducibly within the stock size.
- Generate a recovery-installable test package from the Lineage base layout.
- Retain target boot/vendor and target-compatible AVB handling.
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
