# Case 4 — XOS core pipeline checkpoint

Status: **in progress from `main` commit `cd8b63b`; Case 4.1 contract implemented**.

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

## Exact restart boundary

1. Case 4.1 profile, input inspector, and safety tests: implemented locally.
2. Reconstruct the five exact filesystem images and extract Case 4 roots.
3. Run `buildctl.py inspect-inputs` and resolve only measured pipeline drift.
4. Implement and test resumable staging, patching, development signing, and
   output verification.
5. Generate and verify the real development root tree.
6. Publish the final Case 4 report, run complete CI, and merge.

Do not start Case 5 or produce a flashable package until all Case 4 gates pass.
