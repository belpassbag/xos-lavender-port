# Case 4 — XOS core pipeline checkpoint

Status: **in progress from `main` commit `cd8b63b`; Case 4 input recovery and
inspection are complete, and staging/patch/signing implementation is next**.

This is the durable restart point for the XOS core port pipeline. Case 3 is
closed and must not be repeated. Proprietary inputs and generated trees remain
outside Git.

## Approved signing sequence

The development phase uses one project-specific development platform-signing
domain. Public AOSP test keys and production keys are both excluded from this
phase. Production signing begins only after boot and functional stability.

The locked sequence is:

1. transplant and patch the selected XOS core;
2. generate/use a local project development key;
3. re-sign included APKs from the original base/XOS platform domains;
4. verify boot, SystemUI, Settings, framework, priv-app, and permissions;
5. fix evidence-backed signature or runtime failures;
6. declare the development ROM stable;
7. generate private production keys;
8. perform the final full re-sign, OTA/AVB verification, and release build.

Private keys, keystores, public AOSP test keys, PackageManager signature bypass,
and `sharedUserId` removal are forbidden by `config/pipeline.toml`. A device test
after changing the platform signing domain requires clean data.

## Case 4.1 contract

`tools/buildctl.py check` now locks:

- the accepted Case 3 compatibility-profile digest;
- donor-system-on-base-system-as-root layout;
- nine base paths that must be restored after the donor TSSI transplant;
- base phone and Bluetooth shared-UID retention;
- exact product/system-ext package allowlists;
- complete preopt removal;
- the three verified SystemUI privileged-permission additions;
- nine service mappings to existing base SELinux types;
- unified project development signing and post-build shared-UID validation;
- no donor hardware image, donor vendor tree, repartitioning, or automatic flash.

`tools/buildctl.py inspect-inputs` validates all selected APK, runtime, and
classpath-provider identities and inventories APK certificates/shared UIDs in
all four source roots. It writes reports atomically when `--report` is supplied.

## Locked source recovery

The two Drive source files were rematerialized directly into ignored work
storage with resumable `.partial` downloads. A file was published only after
size and SHA-256 matched:

| Role | Bytes | SHA-256 |
|---|---:|---|
| LineageOS base | 851,061,345 | `4845c4910593a6b8a612c5ea9af1b6752fe8ab2514f62e062abe759e760b82ba` |
| XOS donor | 3,939,359,066 | `5066e7b7e397bad14b81d91f42a1d79e05c150e37c7b047f7b52e5b4b8a178b0` |

The 35,720,630-byte audit bundle also passed its outer SHA-256
`bdf620904d360add8a87c96c4723955603596ff85757f8544f63bd413ed1babe`
and all 21 inner checksums. A tar ownership warning was isolated to host UID/GID
metadata; file bytes were independently verified.

## ENOSPC recovery

The first five-image rematerialization attempt verified the base system and
vendor images, then stopped safely while extracting donor logical partitions
because the temporary filesystem reached 100% use. Atomic output publication
prevented a partial donor image from being accepted. The large temporary layer
was reclaimed after its verified or regenerable role was identified; no source
identity or accepted Case 3 evidence changed.

Two committed scripts now make that boundary repeatable:

- `download-drive-file.sh` resumes a direct Drive ZIP at its existing byte
  offset and publishes it only after exact size and SHA-256 verification;
- `materialize-case4-images.sh` handles base and donor separately, verifies
  each image by its locked Case 3 ID, runs read-only `e2fsck`, and removes only
  the exact intermediate source layer after all dependent outputs pass.

The donor partitions are extracted one at a time, so a later run reuses each
already verified image rather than restarting all three. Full five-image
verification atomically writes `reports/generated/images.json`.

## Recovered image and input gate

All five outputs now match the locked Case 3 size and SHA-256 contracts and
pass read-only `e2fsck`:

| Image | Bytes | SHA-256 |
|---|---:|---|
| `base_system` | 3,640,619,008 | `3536fa28745278ecbd38cc0a0f09329a1c19cf1f959aeb189ee71c1c9f904501` |
| `base_vendor` | 2,080,305,152 | `967a4b560b774e869a5ce16f6b5ee6b73dedfdfde7fa4ef641b3b9cdce4f8f60` |
| `donor_system` | 1,121,648,640 | `2fb5bf44091b6ddd9d63799351c38f75c26499809f6db832e24ced3f5700313d` |
| `donor_product` | 3,206,438,912 | `a3e760d683423b419f2b859fbf3ac24cfd41276939291e819cbeb05e9db6fcbb` |
| `donor_system_ext` | 1,706,311,680 | `7de9ac35bd7c51e683b86546278e2c630024e9f8c9a01c9d4b99f1836324b002` |

The base and donor system roots were extracted once. Product and system-ext
use the already audited Case 3 minimum selection instead of duplicating both
full partitions. The selection contains 481 files and 350,727,209 bytes.

The first real `inspect-inputs` run exposed one contract drift: Android 11 uses
`/system/etc/selinux/plat_mac_permissions.xml`, while the initial Case 4
profile named the nonexistent legacy path
`/system/etc/security/mac_permissions.xml`. The profile and its lock now use
the source-proven Android 11 path. After that correction, the input gate passed
with 311 APKs inventoried, eight exact selected packages, three exact runtime
dependencies, nine exact classpath providers, and all nine protected base
paths present.

## Exact restart boundary

1. Case 4.1 profile, input inspector, and safety tests: committed and verified.
2. Disk-bounded, resumable five-image recovery: complete and verified.
3. Real root extraction and `inspect-inputs`: complete; the sole measured path
   drift is corrected and all input contracts pass.
4. Implement and test resumable staging, patching, development signing, and
   output verification.
5. Generate and verify the real development root tree.
6. Publish the final Case 4 report, run complete CI, and merge.

Do not start Case 5 or produce a flashable package until all Case 4 gates pass.
