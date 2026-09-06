# Case 3 recovery checkpoint

Status: **in progress; not yet accepted**.

This file is the durable restart point for the partition extraction and
compatibility audit. It records only facts already measured from the locked
LineageOS and XOS source identities. Generated images and proprietary payloads
remain excluded from Git.

## Problem

Case 3 reached filesystem and dependency analysis more than once, but its
expanded images lived only in ignored temporary storage. Workspace resets and
transaction sidecars removed or exhausted that storage before the audit tools,
profile, report, and pull request were committed.

## Cause

The source ROMs expand to substantially more than the workspace quota when the
source parts, reconstructed ZIPs, `super.img`, raw logical partitions, audit
trees, and transactional sidecars coexist. The earlier workflow kept too many
regenerable layers at once and did not commit a small checkpoint before the
large-file stages.

## Recovery rule

Case 3 is now split into durable checkpoints. Each checkpoint is tested and
pushed before another large-file stage starts. At most one regenerable large
layer may be retained after its consumer has verified the output hash.

## Locked source identities

| Role | Bytes | SHA-256 |
|---|---:|---|
| LineageOS target/base | 851,061,345 | `4845c4910593a6b8a612c5ea9af1b6752fe8ab2514f62e062abe759e760b82ba` |
| XOS framework donor | 3,939,359,066 | `5066e7b7e397bad14b81d91f42a1d79e05c150e37c7b047f7b52e5b4b8a178b0` |

The Drive split-source manifest contains five LineageOS parts and nineteen XOS
parts. Case 2 already verifies every part and reconstructs both ZIPs atomically.

## Verified image identities

All five filesystems passed read-only `e2fsck -fn`.

| Image | Bytes | SHA-256 |
|---|---:|---|
| Base `system.img` | 3,640,619,008 | `3536fa28745278ecbd38cc0a0f09329a1c19cf1f959aeb189ee71c1c9f904501` |
| Base `vendor.img` | 2,080,305,152 | `967a4b560b774e869a5ce16f6b5ee6b73dedfdfde7fa4ef641b3b9cdce4f8f60` |
| Donor `system_a.img` | 1,121,648,640 | `2fb5bf44091b6ddd9d63799351c38f75c26499809f6db832e24ced3f5700313d` |
| Donor `product_a.img` | 3,206,438,912 | `a3e760d683423b419f2b859fbf3ac24cfd41276939291e819cbeb05e9db6fcbb` |
| Donor `system_ext_a.img` | 1,706,311,680 | `7de9ac35bd7c51e683b86546278e2c630024e9f8c9a01c9d4b99f1836324b002` |

The sparse donor `super.img` expands to 7,345,774,592 bytes and has SHA-256
`7b622c6fa90c909f2bdde39d0344dcadfb576662a33b447a9d6b0808d362a383`.
LP metadata uses 4,096-byte blocks and three metadata slots. The measured
`vendor_a` logical partition is 853,602,304 bytes; all selected `_b` partitions
are zero-sized.

## Filesystem capacity evidence

| Filesystem | Blocks | Free blocks | Block size | Used bytes |
|---|---:|---:|---:|---:|
| Base system | 874,777 | 477,417 | 4,096 | 1,627,586,560 |
| Base vendor | 499,853 | 369,676 | 4,096 | 533,204,992 |
| Donor system | 269,498 | 816 | 4,096 | 1,100,521,472 |
| Donor product | 770,449 | 2,305 | 4,096 | 3,146,317,824 |
| Donor system_ext | 409,986 | 1,240 | 4,096 | 1,674,223,616 |

The selected product tree has a conservative 4 KiB-rounded upper bound of
13,475,840 bytes. The selected system_ext tree upper bound is 282,091,520
bytes. Counting the full base system and full donor system additively, before
crediting any replaced files, gives a deliberately conservative total of
3,023,675,392 bytes. Against the 3,583,086,592-byte target filesystem data
area, the resulting headroom is **559,411,200 bytes**. The minimum locked
reserve is 268,435,456 bytes.

## Compatibility decisions already established

- Preserve the complete LineageOS system-as-root bootstrap, Qualcomm kernel,
  vendor, DTBO, vbmeta, fstab, init, modem, and firmware stack.
- Never emit donor boot, DTBO, vendor, vbmeta, preloader, modem, firmware, or
  MediaTek hardware-service payloads.
- Preserve base VINTF. The target device manifest is level 3, and the base and
  donor level-3 compatibility matrices have identical SHA-256
  `67edd789de4bd35d47e14c2365de082b9ee64ade0c1ca77e2842f3a2015af8b5`.
- Preserve the exact base SELinux CIL and mappings. Their precompiled hashes
  match the base vendor expectations: platform
  `23f3b45bb1932c664d94cf157f2a9cda8d6415321383b97cd59da17321e80e9c`,
  product `5e7d483f16bc3b339e9dc63ce0a0f4a35263ee48e340bafe47fb10464368f653`,
  and system_ext
  `d2a9ddfc73981f04a363623b1ade22849abf9288cf94118c6ebb13c8d5ba4f7f`.
- The base platform signer SHA-256 is
  `59988fff31e2f85fbaddc5b37704be97d1c5b7db72a4fb2ed5f07b58ccf20ccf`;
  the XOS platform signer SHA-256 is
  `a2f1535b2e2e6b707412f8732a08d7911c0cb7b81d061504eba75da32ca3492f`.
  Shared-UID groups must never mix those signers.
- Keep the complete base phone shared-UID/QTI group and base Bluetooth. Exclude
  donor phone shared-UID packages and donor `MtkBluetooth`.
- Product and system_ext remain allowlist-only. Donor GMS, SetupWizard,
  auto-generated MediaTek RROs, camera, FaceID, NFC-ST, calibration, and other
  first-boot extras remain excluded.
- Required XOS runtime includes `com.transsion.mi.os.framework`,
  `com.transsion.kolun`, and `transsion-res.apk`. Both packaged APEX payloads
  use ext4, which the base kernel supports together with loop, dm-verity, FEC,
  ext4, and SELinux built in.
- Map the nine observed XOS Binder service names only to existing base service
  types; do not introduce new SELinux types.

## Selected XOS UI payload

The locked UI selection is `TranSystemUI`, `TranSettings`,
`TranSettingsIntelligence`, `XLauncher`, `OSSettingsExt`, `SystemUIOverlay`,
`SettingsOverlay`, and `XOSLauncher_res`. Their APK bytes total 286,326,703;
their package directories including discarded preopt artifacts total
287,141,584 bytes.

DEX inspection found no unresolved custom external classes after adding the
verified providers. `TranSystemUI` resolves through `framework.jar` and
`os-framework.jar`. `TranSettings` additionally resolves through
`mediatek-common.jar`, `mediatek-ims-common.jar`,
`mediatek-telephony-base.jar`, and `mediatek-telephony-common.jar`. Native
libraries in SystemUI and Launcher require only standard Android 32-bit and
64-bit libraries already present in the base.

The repository now includes `compatctl.py verify-dex`, which parses every
`classes*.dex` member directly, inventories defined and referenced object
descriptors, and maps each custom external reference to the exact supplied
provider archive. The earlier result above remains evidence, but Case 3 is not
accepted until a fresh run against the rematerialized payload produces the
durable report.

## Durable checkpoints

1. Image conversion and LP extraction tool plus unit tests: pushed on branch
   `case/3-compatibility-audit`.
2. Locked compatibility profile, static validator, and unit tests: included in
   this branch checkpoint.
3. Fresh payload verification report and final Case 3 documentation: pending.
4. Pull-request CI, merge, and post-merge CI: pending.

Case 4 must not start until checkpoints 2 through 4 pass.
