# Case 5.1 — durable local rebuild and metadata checkpoint

Status: **accepted locally on 2026-09-11; attempt 7 checkpoint verified**.

Cases 1 through 4 remain closed. This subcase does not repeat their audits and
does not build a flashable image. It provides one durable local entry point for
regenerating the accepted Case 4 development root from the two original ZIPs,
then captures filesystem metadata directly from the verified ext4 images.

## One-command local start

Run this from an up-to-date repository checkout on the machine that already
holds the two source ZIPs:

```bash
./scripts/case5-local.sh start /home/zirex/XOS-Lavender-Port
```

The command returns after starting a detached process session. Closing the
terminal does not terminate the worker. Its default data directory is
`/home/zirex/XOS-Lavender-Port/case5-local`; if the source directory is itself
the Git repository, the runner selects an adjacent directory outside Git.

Inspect progress without restarting work:

```bash
./scripts/case5-local.sh status /home/zirex/XOS-Lavender-Port
```

Running `start` again is also safe: an active worker is not duplicated, and a
stopped worker resumes at the first incomplete stage. For interactive
diagnostics only, `run` executes the same pipeline in the foreground.

## Ordered resume contract

The locked order is:

1. check both exact source filenames/sizes, required host commands, and free
   space;
2. create or verify one persistent project development key outside Git;
3. materialize or verify the two base images;
4. materialize or verify the three donor logical-partition images;
5. regenerate/reuse the Case 4 roots and minimum selection;
6. build/resume the development-signed Case 4 root;
7. independently run the complete Case 4 output verifier;
8. snapshot `base_system` metadata;
9. snapshot `donor_system` metadata;
10. snapshot the selected `donor_product` paths;
11. snapshot the selected `donor_system_ext` paths;
12. verify and atomically publish the Case 5.1 checkpoint.

Each completed stage is recorded in `state/case5-1.json`. A single-worker
`flock` prevents overlap. State files, reports, and metadata snapshots are
written through a temporary file plus `fsync` and atomic rename. If power,
terminal, or a subprocess interrupts a stage, only that uncommitted stage is
repeated.

The fresh-workspace floor is 24 GiB. Existing exact images and completed roots
are reused after their locked identities pass. Neither source ZIP is consumed
or deleted.

## Metadata captured from ext4

Host extraction ownership is not trusted. `tools/metactl.py` walks the original
ext4 inode trees with `debugfs` and records, per path:

- inode number and entry type;
- full mode plus permission bits;
- numeric UID and GID;
- file size;
- exact symbolic-link target;
- every extended attribute as lossless base64, including
  `security.selinux` and `security.capability` when present.

The capture scope follows actual Case 4 provenance:

| Image | Capture scope | Reason |
|---|---|---|
| `base_system` | `/` | system-as-root shell, restored base paths, retained shared-UID groups |
| `donor_system` | `/system` | transplanted donor TSSI system |
| `donor_product` | three selected package directories | selected XOS overlays only |
| `donor_system_ext` | five selected package directories and two runtime files | selected XOS core only |
| `base_vendor` | no metadata export | vendor image remains byte-exact and is never reconstructed |

Snapshots contain both an exact source-image hash and a canonical metadata
digest. The final checkpoint re-verifies every snapshot and separately hashes
the preserved base vendor image.

## Development-signing boundary

The key directory is mode `0700`; the private key is mode `0600`. Only the
project-specific development signing domain is allowed. The generated
checkpoint records the new certificate/public-key hashes but never the private
key material.

Public AOSP test keys, production keys, PackageManager signature bypasses,
shared-UID removal, source deletion, repartitioning, image repack, and automatic
flashing all remain forbidden in this subcase.

## Fresh-rebuild drift correction

The first durable local rebuild on 2026-09-09 stopped safely at
`development_root` after all five source images and the Case 4 input gate had
passed. It exposed one missing encoded action: the three locked
`replace_package_names` were validated by the profile but their pre-existing
base/donor package directories were not removed before the selected XOS
replacements were installed. That left duplicate `Settings`,
`SettingsIntelligence`, and `SystemUI` package names.

The transplant now removes only APK directories whose parsed manifest package
matches one of those three locked names. It rejects a directory containing any
collateral package, records every removed APK identity, installs the selected
XOS replacements, and verifies that each replacement exists only at its locked
donor destination. A failed `development_root` remains resumable: the inner
Case 4 stage is reconstructed from its last atomic boundary while the five
already completed Case 5.1 stages are reused.

The next retry exposed a path-namespace collision in the shared APK inventory:
the absolute host path returned by the APK parser overwrote the intended
logical Android path. Replacement cleanup therefore found its package by
logical directory but could not associate the same row by path. The inventory
now validates the parser's host path and then publishes only normalized logical
paths to transplant, signing, and output verification. A regression test locks
that boundary. The default status view also retains 60 log lines so a child
process error remains visible alongside the wrapper traceback.

The third retry reached final output verification with no preoptimized residue,
but the success path eagerly formatted an error message using the first element
of the empty residue list. The verifier now enters the error path only when a
real residue exists. Regression coverage locks both the clean-tree success case
and the diagnostic path for actual residue; all completed outer stages and the
inner signed tree remain reusable on resume.

The fourth retry passed the APK inventory, signer, duplicate-package, preopt,
permission, service-context, MAC-permission, selected-runtime, classpath, and
VINTF gates. It then exposed a semantic mismatch shared by all three SELinux
marker checks: the compatibility contract stores the 64-digit hash contained
inside each marker, while output verification hashed the marker file itself and
compared that unrelated digest to its contents. Output verification now reads
and compares the marker value exactly as the original compatibility verifier
does for `plat`, `product`, and `system_ext`, while separately reporting the
marker file digest. Regression coverage proves that valid marker contents pass
even though their file digests differ, and that real marker drift still fails.

The only gates after these markers were audited in the same correction. The
hardware guard had clean-tree, forbidden-image, and vendor-tree regression
coverage, but its clean fixture omitted the system-as-root `/vendor`
mountpoint. The deterministic manifest test remains active, and the locked
capacity plan retains 558,571,520 bytes of conservative headroom.

The fifth retry passed all three corrected SELinux marker gates, proving their
fix against the real tree, then stopped at the hardware guard because it treated
the required `/vendor` directory itself as a packaged vendor payload. This is a
false positive: AOSP's system-as-root layout explicitly includes `/vendor` as a
mountpoint and `/system/vendor` as its compatibility link, while lavender's
LineageOS 18.1 fstab mounts the separate vendor partition at `/vendor`. The
guard now verifies that `/vendor` is an empty mountpoint and that
`/system/vendor` is absent, empty, or resolves to `/vendor`; it rejects any
payload entry, regular file, divergent link, or forbidden hardware image. The
root cause, sources, pipeline provenance, and corrected invariant are recorded
in `docs/CASE-5-1-VENDOR-GUARD-AUDIT.md`. No payload, selection, signing
policy, source archive, repack, or flash boundary changed.

The sixth retry completed both `development_root` and the independent
`output_verification`, then stopped at `metadata_base_system` with
`unsafe ext4 entry name`. The failing row was not a live Android path.
`debugfs` 1.47.0 always walks directories with
`DIRENT_FLAG_INCLUDE_EMPTY`; its parse format consequently emits inode-zero
records for unused ext4 directory slots and htree bookkeeping. The parser
accepted the record grammar but checked its intentionally empty name before
classifying inode zero, producing a false positive on the real system image.

Metadata parsing now discards only inode-zero records after verifying that the
mode, UID, GID, and size fields that `debugfs` synthesizes for them are all
zero. Live inodes still require a nonempty safe name, and a malformed inode-zero
record remains fatal. The kernel ext4 format, matching e2fsprogs 1.47.0 source,
the exact failure path, corrected invariant, and downstream audit are recorded
in `docs/CASE-5-1-EXT4-DIRENT-AUDIT.md`. The seven completed outer stages stay
reusable; the next run starts at `metadata_base_system`.

## Local acceptance output

The attempt 7 payload run ended with:

- state `status` equal to `complete`;
- a re-verified development root and its tree-manifest digest;
- four verified metadata snapshots;
- `reports/case5-1-checkpoint.json` with `status: verified`;
- a durable log at `logs/case5-1.log`.

The resulting checkpoint SHA-256 is
`4ed6e387f32113a77b59112464f001e46215bbbc2109bb95d9809d194377050c`.
Its development-tree manifest SHA-256 is
`f99262b7402f885024564815da8df042a5aa939159512efbc0fedf6573bf277a`;
the tree contains 3,089 regular files, 262 symbolic links, and 1,761,713,439
regular-file bytes. All four metadata snapshots passed, the state is
`complete`, and no worker remains active. The complete closure and
machine-readable evidence are recorded in
[`CASE-5-1-REPORT.md`](CASE-5-1-REPORT.md) and
[`CASE-5-1-EVIDENCE.json`](CASE-5-1-EVIDENCE.json).

The payload cannot be executed in repository CI because proprietary images are
not committed. CI verifies the orchestration, safety contract, interruption
recovery, metadata parsers, and a real synthetic ext4 round trip. The current
repository check runs 87 tests.

The local `verified` gate is now satisfied. Case 5.2 may map the captured source
metadata onto the transformed tree and repack it; it must not infer Android
ownership or labels from host filesystem values. This closure does not start
Case 5.2.
