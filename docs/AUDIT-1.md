# Audit 1 — Feasibility baseline

This report records only facts verified from the source ZIP listings, selected
images, AVB metadata, transfer lists, and the LineageOS 18.1 `lavender` device
configuration. It does not claim that the port boots.

## Source identity

| Role | File | Bytes | SHA-256 |
|---|---|---:|---|
| Target/base | `lineage-18.1-20221025-nightly-lavender-signed.zip` | 851,061,345 | `4845c4910593a6b8a612c5ea9af1b6752fe8ab2514f62e062abe759e760b82ba` |
| Framework donor | `X6812B-H6912KL-R-OP-231009V922.zip` | 3,939,359,066 | `5066e7b7e397bad14b81d91f42a1d79e05c150e37c7b047f7b52e5b4b8a178b0` |

The audit bundle itself was 35,720,630 bytes with SHA-256
`bdf620904d360add8a87c96c4723955603596ff85757f8544f63bd413ed1babe`.
All 21 extracted-file checksums in that bundle passed.

## Verified compatibility facts

| Property | Target/base | Donor | Consequence |
|---|---|---|---|
| Android API | Android 11 / SDK 30 | Android 11 / SDK 30 | Framework generation matches. |
| ABI | arm64 with arm secondary ABI | arm64 with arm secondary ABI | Java and architecture-compatible userspace is possible. |
| Platform | Qualcomm SDM660 | MediaTek MT6768 | Hardware stack is not interchangeable. |
| Kernel | Linux 4.4.302 LineageOS | Linux 4.14.186 MTK | Donor kernel cannot be used. |
| Layout | non-A/B, static, system-as-root | A/B, dynamic logical partitions | Donor partitions must be flattened into the target layout. |
| Treble/VNDK | full Treble, Android 11 current VNDK | VNDK 30 | A TSSI-style framework experiment is plausible, not proven. |

The donor AVB descriptors label `system`, `product`, and `system_ext` as
`Infinix/TSSI/FULL-64`, which is the strongest positive feasibility signal. The
donor vendor remains device-specific and is excluded.

## Boot and AVB

| Image | Header | Page | Kernel | Ramdisk | Verified platform signal |
|---|---:|---:|---:|---:|---|
| Base `boot.img` | v0 | 4,096 | 13,573,602 bytes | none | `androidboot.hardware=qcom`, SDM660 strings |
| Donor `boot.img` | v2 | 2,048 | 9,719,129 bytes | 12,956,293 bytes | MT6768 fstab/init and MediaTek strings |

The donor ramdisk mounts `system`, `system_ext`, `product`, and `vendor` with
`slotselect`, `logical`, and donor AVB chains. The target instead mounts its
static `system` partition as `/` and is system-as-root. Therefore target boot,
root init/fstab, DTBO, vendor, and firmware must be preserved.

The Lineage base `vbmeta.img` has flags `3` (verification and hashtree disabled),
while the donor AVB images have flags `0` and signed chains for donor logical
partitions. Donor vbmeta images cannot describe the target layout.

## Size gate

AVB hashtree descriptors expose the following filesystem data sizes:

| Filesystem | Donor bytes | Donor GiB |
|---|---:|---:|
| `system` | 1,103,863,808 | 1.028 |
| `product` | 3,155,759,104 | 2.939 |
| `system_ext` | 1,679,302,656 | 1.564 |
| Total framework-side payload | 5,938,925,568 | 5.531 |

The target physical `system` partition is 3,640,619,008 bytes (3.391 GiB). Its
Lineage AVB layout allocates 3,583,086,592 bytes (3.337 GiB) to filesystem data.
An untouched donor framework therefore exceeds the usable target area by
2,355,838,976 bytes (2.194 GiB).

The donor installed-file reports independently show 4,824,730,445 bytes in
`product` plus `system_ext` alone, already 1,241,643,853 bytes beyond the target
filesystem area before `system` is included. `/product/operator` accounts for
1,368,970,767 bytes and is an immediate first-boot exclusion.

## Locked first-boot decision

The first test build prioritizes stable boot and includes only:

- `TranSystemUI`
- `TranSettings`
- `XLauncher`
- `OSSettingsExt`
- dependencies and overlays proven necessary by static analysis

It excludes donor GMS/SetupWizard, all operator applications, and donor
hardware-specific camera, FaceID, NFC, calibration, kernel, vendor, firmware,
and boot components. Google provisioning is deliberately deferred until after
a stable non-GMS boot is verified.

## Version mapping note

The outer donor package is named `V922`. Its boot/vendor properties report
`231009V566`, while AVB properties for the TSSI `system`, `product`, and
`system_ext` report `231009V473`. The source checksum passes, so the pipeline
records these as component versions and does not silently rewrite them.

