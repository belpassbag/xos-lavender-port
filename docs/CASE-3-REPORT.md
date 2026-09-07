# Case 3 — Partition extraction and compatibility audit

Status: **accepted on 2026-09-07 for static compatibility**.

This report closes Case 3. It proves that the locked XOS core selection fits
the `lavender` system filesystem and that its measured Java, native, APEX,
Android, VINTF, SELinux, layout, kernel, package, and signing inputs are
internally consistent. It does **not** claim that a ROM has been built, booted,
or flashed.

The machine-readable evidence is `config/compatibility.toml`, locked by
canonical SHA-256
`03c5553149b49aba127534a96a8420d2a2682590e79c3b40b9fedd43509847bd`.
Any semantic change makes `compatctl.py check` fail until it is deliberately
reviewed and relocked.

## Problem

Case 3 repeatedly reached payload analysis but large ignored artifacts were
removed when the temporary Work workspace was reclaimed. Some early measured
values also drifted as the verifier learned to parse real Android binary XML,
DEX Modified UTF-8, embedded APEX filesystems, directory allocation, and APK
signatures.

## Cause

The original flow kept reconstructed ZIPs, sparse and raw images, extracted
trees, and reports together in temporary storage. That exceeded the useful
lifetime of the workspace and left the repository checkpoint behind the actual
analysis. The earlier profile also treated a few inferred paths, class counts,
and signer classes as facts before byte-level verification.

## Solution

- Recover source parts and selected files at verified boundaries with exclusive
  locks, atomic publication, and reuse of already verified outputs.
- Extract only the minimum Case 3 payload and write a sorted SHA-256 inventory.
- Parse APK manifests, APK signing blocks, DEX files, ELF dependencies, ext4
  metadata, Android properties, and the base boot kernel directly.
- Replace inferred identities with exact sizes and SHA-256 values.
- Lock the complete compatibility profile and reject semantic drift in tests.
- Audit all base and donor APKs for `sharedUserId` before choosing the Case 4
  signing strategy.

## Recovery and source identity

| Role | Bytes | SHA-256 |
|---|---:|---|
| LineageOS target/base ZIP | 851,061,345 | `4845c4910593a6b8a612c5ea9af1b6752fe8ab2514f62e062abe759e760b82ba` |
| XOS framework donor ZIP | 3,939,359,066 | `5066e7b7e397bad14b81d91f42a1d79e05c150e37c7b047f7b52e5b4b8a178b0` |
| Donor sparse `super.img` | 6,808,452,712 | `7b622c6fa90c909f2bdde39d0344dcadfb576662a33b447a9d6b0808d362a383` |

All five recovered ext filesystems passed read-only `e2fsck -fn` and exact
identity verification:

| Image | Bytes | SHA-256 |
|---|---:|---|
| Base `system.img` | 3,640,619,008 | `3536fa28745278ecbd38cc0a0f09329a1c19cf1f959aeb189ee71c1c9f904501` |
| Base `vendor.img` | 2,080,305,152 | `967a4b560b774e869a5ce16f6b5ee6b73dedfdfde7fa4ef641b3b9cdce4f8f60` |
| Donor `system_a.img` | 1,121,648,640 | `2fb5bf44091b6ddd9d63799351c38f75c26499809f6db832e24ced3f5700313d` |
| Donor `product_a.img` | 3,206,438,912 | `a3e760d683423b419f2b859fbf3ac24cfd41276939291e819cbeb05e9db6fcbb` |
| Donor `system_ext_a.img` | 1,706,311,680 | `7de9ac35bd7c51e683b86546278e2c630024e9f8c9a01c9d4b99f1836324b002` |

The resumable minimum extraction completed with 481 files and 350,727,209
bytes. A resumed run reused the prior 480 files and added only the missing base
vendor `build.prop`, proving that recovery does not restart the whole payload.
Proprietary source files, expanded images, APKs, and private Drive IDs remain
outside Git.

## Corrected drift

| Evidence | Earlier assumption | Verified value |
|---|---|---|
| XOS framework APEX path | `/system_ext/apex/...` | `/system/apex/com.transsion.mi.os.framework.apex` |
| Base IFAA provider | `org.ifaa.jar` | `org.ifaa.android.manager.jar` |
| Embedded APEX providers | 4 | 6, including `proxy.jar` and `proxy_sprd.jar` |
| `TranSettings` custom references | 22 | 23, including `Ltranssion/log/Athena;` |
| Resource/overlay signer class | Standalone | XOS platform for all three selected resource APKs |
| Tree accounting | Files only | Files plus one 4 KiB block per directory |
| Conservative total | Omitted system-ext runtime allocation | 3,024,515,072 bytes |
| Remaining headroom | 559,411,200 bytes | 558,571,520 bytes |
| Android XML handling | Fixture-compatible header assumptions | Real variable-size node headers |
| DEX strings | Plain UTF-8 | DEX Modified UTF-8 with UTF-16 length checks |

## Verification results

| Gate | Verified result |
|---|---|
| Profile | 5 images, 8 packages, 3 runtime dependencies, 6 embedded providers, 9 external classpath providers, 5 native libraries; 0 pending identities |
| Selection | Exact APK/package/certificate/native/APEX identities; product measured 6,787,072 bytes and system-ext measured 280,444,928 bytes |
| DEX | 5 packages against 15 providers; 0 unresolved custom external classes |
| Static | Android 11 / SDK 30 on both sides; base vendor SDK 30 and first API 28; matching ABI lists |
| VINTF | Base target level 3; base and donor level-3 matrix hash both `67edd789de4bd35d47e14c2365de082b9ee64ade0c1ca77e2842f3a2015af8b5` |
| SELinux | Base platform, product, and system-ext precompiled-policy hashes match vendor expectations; 9 donor services map to existing base types |
| Kernel/APEX | Base boot and IKCONFIG identities match; loop, dm-verity, FEC, ext4, and SELinux are built in; both APEX payloads are verified ext4 |
| Native | All 5 selected ELF files are ARM/AArch64; every `DT_NEEDED` entry exists in the base 32-bit and 64-bit system libraries |

DEX resolution by selected code package:

| Package | Custom external | Resolved | Unresolved |
|---|---:|---:|---:|
| `TranSystemUI` | 3 | 3 | 0 |
| `TranSettings` | 23 | 23 | 0 |
| `TranSettingsIntelligence` | 0 | 0 | 0 |
| `XLauncher` | 0 | 0 | 0 |
| `OSSettingsExt` | 0 | 0 | 0 |

### Capacity proof

The conservative calculation counts the complete used base system and donor
system, the allowlisted product and system-ext upper bounds, and the separate
system-ext runtime allocation without crediting replaced files:

```text
1,627,586,560 + 1,100,521,472 + 13,475,840 + 282,091,520 + 839,680
= 3,024,515,072 bytes

3,583,086,592 - 3,024,515,072
= 558,571,520 bytes headroom
```

The result exceeds the locked 268,435,456-byte reserve by 290,136,064 bytes.

## Shared-UID and signing decision

The complete APK inventory was parsed successfully, not sampled:

| Source | APKs scanned | Packages declaring a shared UID | Parse failures |
|---|---:|---:|---:|
| Base system | 107 | 44 | 0 |
| Donor system/product/system-ext | 237 | 83 | 0 |

The base platform certificate is
`59988fff31e2f85fbaddc5b37704be97d1c5b7db72a4fb2ed5f07b58ccf20ccf`;
the XOS platform certificate is
`a2f1535b2e2e6b707412f8732a08d7911c0cb7b81d061504eba75da32ca3492f`.
Selected `TranSettings` and `OSSettingsExt` declare `android.uid.system` with
the XOS certificate, while retained base members of that UID use the base
certificate. Android therefore cannot accept the unmodified mixed group.

`TranSystemUI` declares `android.uid.systemui` and replaces base SystemUI. The
donor FaceID member of that UID is excluded, but the output group must still be
checked after assembly.

| Candidate response | Decision | Reason |
|---|---|---|
| Merge privileged permissions only | Reject | Permissions cannot satisfy shared-UID signature equality. |
| Remove `sharedUserId` from XOS packages | Reject | It changes process identity, data ownership, and framework assumptions. |
| Globally bypass PackageManager signature checks | Reject | It weakens platform security and hides future signing mistakes. |
| Use one port platform-signing domain | Required for Case 4 | Re-sign included APKs from both original platform domains, update the relevant `mac_permissions.xml` signer mapping, and verify one certificate per shared UID in the assembled output. |

Standalone APK signers and APEX signing are preserved unless a later explicit
trust-chain test proves a narrower change necessary. Preoptimized artifacts are
discarded. No private signing material may be committed.

The only approval gate carried into Case 4 is signing-key selection: use a
public test key for experimental builds or a user-supplied private production
key. Case 4 must not silently choose or publish a private key.

## Permission delta

The selected XOS SystemUI requests 149 permissions. The base privileged grant
file grants 52 of them and the donor grants 60. Only three requested permissions
exist in the donor grant but not the base grant:

- `android.permission.KILL_UID`
- `android.permission.READ_PHONE_STATE`
- `android.permission.SEND_SMS`

Seven other donor-only grant entries are not requested by this APK and must not
be copied. Selected Settings and Settings Intelligence have no requested
donor-only privileged-grant gap. Case 4 should therefore merge only the three
SystemUI entries, subject to output validation.

## Keep/remove/patch matrix

| Area | Decision | Case 4 constraint |
|---|---|---|
| Base boot, kernel, DTBO, vendor, vbmeta, modem, firmware, persist | Keep | Never replace with MT6768 output. |
| Base system-as-root init/fstab, VINTF, and SELinux policy | Keep | Verify their locked hashes after assembly. |
| Donor TSSI system framework | Patch/transplant | Retain the base bootstrap and remove MediaTek hardware coupling. |
| Eight selected XOS UI/resource APKs and three required runtimes | Keep from allowlist | Verify exact identity before transformation; discard preopt. |
| Donor product and system-ext outside the allowlist | Remove | Do not copy implicitly. |
| Donor phone shared-UID group, `MtkBluetooth`, GMS/SetupWizard, operator, camera, FaceID, NFC-ST, and calibration tools | Remove | Preserve the corresponding base Qualcomm functionality where present. |
| Nine XOS Binder service labels | Patch | Map only to the existing locked base service types; add no SELinux type. |
| Privileged permissions | Patch | Add only the three verified SystemUI grants. |
| Platform-signed APKs and `mac_permissions.xml` | Patch | Use one approved port platform key and verify every shared-UID group. |

## Reproduction boundary

After exact images are rematerialized, minimum extraction is resumable:

```bash
scripts/extract-case3-selection.sh \
  /absolute/base-system.img \
  /absolute/base-vendor.img \
  /absolute/donor-system.img \
  /absolute/donor-product.img \
  /absolute/donor-system-ext.img \
  /absolute/case3-selection
```

`tools/compatctl.py` exposes `verify-images`, `verify-selection`, `verify-dex`,
and `verify-static`; each accepts `--report` and atomically writes sorted JSON.
The exact required IDs, paths, sizes, hashes, certificates, class counts, and
upper bounds are the locked profile rather than undocumented command history.

Repository-only acceptance is reproduced with:

```bash
make check
```

Case 4 may begin only after this report, pull-request CI, merge, and post-merge
CI all pass.
