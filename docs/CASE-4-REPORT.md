# Case 4 — XOS core development-root report

Status: **accepted for static development on 2026-09-08**.

Case 4 produced and verified a development-signed root tree from the exact
Case 3 inputs. It did not create a flashable image, alter boot/vendor firmware,
flash a device, or begin production signing. Machine-readable evidence is in
[`CASE-4-EVIDENCE.json`](CASE-4-EVIDENCE.json).

## Acceptance result

| Gate | Measured result |
|---|---:|
| Input APKs inventoried | 311 |
| Exact selected XOS package directories | 8 |
| Exact runtime dependencies | 3 |
| Exact classpath providers | 9 |
| Protected base paths restored | 9 |
| Output APKs | 227 |
| APKs signed by the project development certificate | 90 |
| Standalone APK signatures preserved | 137 |
| Shared-UID groups | 11 |
| Mixed-certificate shared-UID groups | 0 |
| Cross-directory duplicate packages | 0 |
| APK ZIP failures | 0 |
| Preopt residue | 0 |
| Regular files | 3,089 |
| Symbolic links | 262 |
| Regular-file bytes | 1,761,769,184 |

The deterministic file/symlink manifest digest was
`a7129dee724a75058617087dca2b688f348e06af452b593f64df33c563a13c0b`.
This is below the locked 3,583,086,592-byte target filesystem data capacity.

Every transformed APK passed RSA PKCS#1 SHA-256 signature verification and
APK v2 chunked-content-digest verification. Every one of the 227 APK ZIP
directories and members also passed integrity testing. The signer inserts the
v2 block immediately before the ZIP central directory and signs all content
outside that block, matching the Android v2 layout.

## Development signing boundary

The measured tree used a project-specific development certificate with SHA-256
fingerprint
`afd733ea357012987f9d4e70d6a425f15027fe2b424906a879a1399f624826c1`.
The private key was mode `0600`, remained outside Git, and is not present in
this repository. This phase forbids public AOSP test keys, production keys,
signature bypasses, and removal of `sharedUserId` declarations.

The signer re-signed only APKs from the locked Lineage/XOS platform-signing
domains. It preserved standalone APKs and both selected APEX signatures. The
post-build verifier independently re-opened every development-signed APK,
verified its certificate/public-key relationship, signature, and content
digest, then enforced one certificate per shared UID.

Changing this development certificate later requires a clean-data device test.
Production keys remain deferred until the ROM passes physical boot and agreed
functional tests.

## Exact runtime and selected results

The two preserved APEX files remained byte-exact:

| Runtime | SHA-256 |
|---|---|
| `com.transsion.mi.os.framework.apex` | `a2b648e722552065cd2e06ee9a90c6796384f6154bcdbd5ed1af5ca611a46cc9` |
| `com.transsion.kolun.apex` | `e97e6533e4423a7062f18c52f26a593d2dc24e365ceefcfd07dbd5f3ca684ab9` |

Selected output identities were:

| Component | Final SHA-256 | Action |
|---|---|---|
| `TranSystemUI` | `2bd3d1201daae3e0f167082ba8ffde5837ee6a2685106704099160e9cfa3a6aa` | development-signed |
| `TranSettings` | `e44483b30a0726606407c354a7409997dfe377574d10ba5253a9247669289451` | development-signed |
| `TranSettingsIntelligence` | `d5cb1bc537223c32ba277bec726ab1102299a8d72f80e1409048ad0a9b858bbd` | standalone preserved |
| `XLauncher` | `220b345611e97833068efbe48f88e79e5ab276f744a1cd88bf8683018816b02a` | standalone preserved |
| `OSSettingsExt` | `4ec84df888279569b98ce9cfc5db080481e80bde09411239b4bfd3ae2d38c478` | development-signed |
| `SystemUIOverlay` | `101055b31a422a4463f1a353729c147606fa97f3ab2d1f2d7d79eacfa700205e` | development-signed |
| `SettingsOverlay` | `bb9e6f4bf53b720e2dead85f31a8d113ca4e606bd9617119b23754ac8d3fa581` | development-signed |
| `XOSLauncher_res` | `aff40047341f27e6f554881ab34ec47962ece3ed3a614249822c2d47fe011310` | development-signed |
| `transsion-res.apk` | `d2884d9c688bb99fa5bfd3bb4ae150970f74d9108a0bd88df04f3b4419805835` | development-signed |

All nine external classpath providers matched their Case 3 size/SHA-256
contracts. The base VINTF level-3 matrix remained
`67edd789de4bd35d47e14c2365de082b9ee64ade0c1ca77e2842f3a2015af8b5`.
The base SELinux mapping markers remained:

- platform: `23f3b45bb1932c664d94cf157f2a9cda8d6415321383b97cd59da17321e80e9c`;
- product: `5e7d483f16bc3b339e9dc63ce0a0f4a35263ee48e340bafe47fb10464368f653`;
- system-ext: `d2a9ddfc73981f04a363623b1ade22849abf9288cf94118c6ebb13c8d5ba4f7f`.

## Applied compatibility patches

The generated SystemUI privileged-permission file grants exactly:

- `android.permission.KILL_UID`;
- `android.permission.READ_PHONE_STATE`;
- `android.permission.SEND_SMS`.

Nine donor service names were mapped to already-existing base SELinux types;
no new policy type or allow rule was introduced. The base platform MAC signer
entry was changed to the project development certificate. Resulting hashes
were:

| Patch | SHA-256 |
|---|---|
| privileged-permission XML | `1ae6e5b3f6846536ac5fa312cbeee2fb6b94aace34bb6fa0b448410674d89439` |
| system-ext service contexts | `a0007a02a4faeeadbe3db3d72f679ed98990e6928eb1ea7e1f6804ef5438888f` |
| platform MAC permissions | `1437fdbdda068632626df347e2f735c7ce5681e9ac3c5c653594367bc92563be` |

## Measured drift and fixes

1. The first donor extraction exhausted temporary storage. Atomic publication
   correctly withheld incomplete images. Recovery was split by partition and
   made resumable, so verified images are reused.
2. The first pipeline contract named legacy
   `/system/etc/security/mac_permissions.xml`. The Android 11 input proved that
   the real path is `/system/etc/selinux/plat_mac_permissions.xml`; the profile
   and digest lock were corrected before staging.
3. Initial preopt cleanup missed symbolic-link `.vdex` and symbolic-link `oat`
   entries. Cleanup now operates on regular files and symlinks without following
   them. The measured run removed 450 regular files (64,038,471 bytes) plus 26
   symlink entries, leaving zero residue.
4. Package `com.android.launcher3` appeared in the donor
   `SecondaryDisplayLauncher` directory and the retained base Trebuchet
   directory. Four other repeated names were legitimate split APKs in one
   directory. The duplicate guard is now split-aware, and removes only this
   exact donor APK identity:
   - path: `/system/priv-app/SecondaryDisplayLauncher/SecondaryDisplayLauncher.apk`;
   - SHA-256: `4d1879ddccfceb56e726878cb58bea2c0b69719d33a02bfe14ec6b868274d325`;
   - certificate: `a7e2e584fd1e865551aeca7a4110d8b9c0ba9b1fe6c3b7807d564a45557a5e71`.

Any drift in that path, package, signer, or file hash fails instead of deleting
an unknown APK.

## Resumability and usage

`extract-case4-roots.sh` verifies all five image identities before extraction.
Each full root is atomically published with an image-bound completion marker;
the Case 3 minimum selection and `inspect-inputs` gate run afterward.

```bash
scripts/extract-case4-roots.sh /absolute/image-work /absolute/case4-work

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

The builder locks one output root, stages through hard links, records each
completed phase atomically, and resumes signing without re-signing an already
verified development APK. A completed invocation re-runs all output verifiers
instead of mutating the tree.

## Repository verification

`make check` passes 59 unit tests plus Python compilation, every locked profile
check, shell syntax checks, evidence JSON parsing, and the private-key guard.
The tests include APK v2 round-trip/tamper cases and regressions for every
measured Case 4 drift above.

## Boundary before Case 5

The extracted host trees do not preserve trustworthy Android numeric UID/GID
or SELinux labels: `debugfs` may be unable to apply those metadata values as an
unprivileged host user. Case 5 must rebuild ownership, modes, capabilities, and
SELinux labels from the source ext4 metadata/configuration; it must not infer
them from host `root:root` ownership.

The measured development tree and private key were intentionally transient and
were never Git artifacts. If local workspace maintenance has removed them,
Case 5 must regenerate the tree with a newly persisted local development key
and record the new certificate/tree hashes. No device was flashed with the
measured key, so this rotation does not create an on-device upgrade conflict.

Case 5 has not started. Packaging, filesystem-metadata reconstruction, AVB/OTA
validation, and any manual device test remain later gates.
