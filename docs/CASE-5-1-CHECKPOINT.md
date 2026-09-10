# Case 5.1 — durable local rebuild and metadata checkpoint

Status: **implementation verified; local payload execution pending**.

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

## Local acceptance output

A successful run ends with:

- state `status` equal to `complete`;
- a re-verified development root and its tree-manifest digest;
- four verified metadata snapshots;
- `reports/case5-1-checkpoint.json` with `status: verified`;
- a durable log at `logs/case5-1.log`.

The payload cannot be executed in repository CI because proprietary images are
not committed. CI verifies the orchestration, safety contract, interruption
recovery, metadata parsers, and a real synthetic ext4 round trip. The current
repository check runs 79 tests.

Case 5.2 may begin only after the user's local checkpoint reports `verified`.
That later subcase will map the captured source metadata onto the transformed
tree and repack it; it must not infer Android ownership or labels from host
filesystem values.
