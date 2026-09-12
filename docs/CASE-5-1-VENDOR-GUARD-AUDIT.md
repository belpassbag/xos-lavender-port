# Case 5.1 vendor-boundary failure audit

Status: **resolved; repository tests and the final attempt 7 payload checkpoint
verified the correction**.

## Observed failure

Attempt 5 resumed the existing signed development tree and passed every prior
output gate, including all three corrected SELinux markers. It stopped at
`development_root` with:

```text
ERROR: a vendor directory was packaged into the system root
```

The failing condition rejected either `/vendor` or `/system/vendor` merely for
being a real directory. It did not inspect whether the directory contained a
vendor payload.

## Authoritative layout evidence

Android's system-as-root partition layout explicitly places `vendor/` in the
system image root as a **mountpoint** and shows `system/vendor -> /vendor` as a
compatibility link:

- https://source.android.com/docs/core/architecture/partitions/system-as-root

The LineageOS 18.1 lavender device tree independently confirms the exact target
layout. Its fstab mounts the system partition at `/`, states that vendor is
early-mounted, and mounts the separate vendor partition at `/vendor`:

- https://github.com/LineageOS/android_device_xiaomi_lavender/blob/8d0e035cb03683baba0a54b86f5c8977890721c4/rootdir/etc/fstab.qcom

A directory used as a mountpoint is therefore required structure, not evidence
that vendor binaries were copied into `system`.

## Pipeline provenance

The Case 5.1 pipeline materializes and preserves lavender `base_vendor.img`
byte-for-byte. It never materializes an X6812B vendor image. During the Case 4
tree build it:

1. stages the complete lavender system-as-root tree;
2. copies only the donor `/system` subtree to output `/system`;
3. restores locked lavender system/product/system-ext paths;
4. refuses every named donor hardware image.

Consequently, the root `/vendor` directory comes from the lavender
system-as-root image and serves as the mountpoint for the separately preserved
lavender vendor partition. The old guard conflated that directory entry with a
nonempty vendor payload tree.

## Correct invariant

The corrected guard distinguishes topology from content:

- `/vendor` must exist as an empty real directory mountpoint;
- `/system/vendor` may be absent, an empty compatibility directory, or a
  symbolic link that resolves exactly to `/vendor`;
- any entry beneath either real directory is rejected;
- a regular file at either boundary is rejected;
- a compatibility link resolving anywhere except `/vendor` is rejected;
- all forbidden boot, vendor, firmware, modem, and related image filenames
  remain rejected anywhere in the output tree.

This preserves the Android/Lineage mount topology without allowing donor vendor
content into the system image.

## Verification contract

Regression coverage constructs the real system-as-root topology and proves:

1. empty `/vendor` plus `/system/vendor -> /vendor` passes;
2. adding even one directory under `/vendor` fails;
3. redirecting `/system/vendor` away from `/vendor` fails;
4. a forbidden `boot.img` anywhere in the output fails.

The patch changes only verifier semantics and reporting. It does not alter the
signed tree, source archives, package selection, SELinux policy, development
key, partition images, repack boundary, or flashing boundary.

Attempt 6 subsequently passed this hardware guard and completed both the
development-root build and its independent output verification. Attempt 7 then
completed all remaining metadata stages and published the verified Case 5.1
checkpoint, closing the real-payload verification requirement.
