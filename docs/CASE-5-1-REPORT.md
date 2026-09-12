# Case 5.1 — final local acceptance report

Status: **accepted on the payload-holding machine on 2026-09-11**.

Case 5.1 is closed. Attempt 7 resumed at the first incomplete stage, completed
all 12 ordered stages, and atomically published a checkpoint that its final
verification pass reported as `verified`. Machine-readable non-secret evidence
is recorded in [`CASE-5-1-EVIDENCE.json`](CASE-5-1-EVIDENCE.json).

This acceptance does not claim a repacked image or a bootable ROM. It authorizes
only the next static subcase, Case 5.2 metadata reconstruction and system-image
repack. Production signing and device flashing remain forbidden here.

## Acceptance result

| Gate | Measured result |
|---|---:|
| Payload attempt | 7 |
| Pipeline stages completed | 12 of 12 |
| Durable state | `complete` |
| Worker still live | no |
| Checkpoint status | `verified` |
| Metadata snapshots verified | 4 |
| Development-root regular files | 3,089 |
| Development-root symbolic links | 262 |
| Development-root regular bytes | 1,761,713,439 |
| Image repack performed | no |
| Production signing performed | no |
| Automatic flashing performed | no |

The accepted checkpoint SHA-256 is
`4ed6e387f32113a77b59112464f001e46215bbbc2109bb95d9809d194377050c`.
The deterministic development-tree manifest SHA-256 is
`f99262b7402f885024564815da8df042a5aa939159512efbc0fedf6573bf277a`.
The project development certificate SHA-256 is
`0d3704757d2faf719a06e07046152571a331c119cf78371349a7523cf689b623`.
The private key remains outside Git.

## Ordered completion

The final state records every stage exactly once and in the locked order:

1. `preflight`;
2. `development_key`;
3. `base_images`;
4. `donor_images`;
5. `case4_inputs`;
6. `development_root`;
7. `output_verification`;
8. `metadata_base_system`;
9. `metadata_donor_system`;
10. `metadata_donor_product`;
11. `metadata_donor_system_ext`;
12. `checkpoint`.

The terminal status reported `active_stage: null`, `process_live: false`, and
`next_stage: null`. No stage is still running and the pipeline must not be
started again merely to close this case.

## Problem, cause, solution, verification

| Attempt | Problem | Established cause | Correction | Real-payload verification |
|---:|---|---|---|---|
| 1 | Three cross-directory duplicate packages | Locked replacement names were validated but their old package directories were not removed | Remove only directories whose parsed package identity matches the locked replacement | Later attempts passed the duplicate-package gate |
| 2 | Replacement directory reported collateral content | Host APK path overwrote the logical Android path in inventory rows | Validate the host path, then retain a normalized logical path for matching | Attempt 3 advanced through replacement cleanup |
| 3 | `IndexError` after zero preopt residue | The success path eagerly evaluated `residue[0]` | Enter the diagnostic branch only when residue exists | Attempt 4 passed the preopt gate |
| 4 | Base platform SELinux marker drift | Verifier compared the marker file digest with the hash stored inside it | Compare the stored marker value and report the file digest separately | Attempt 5 passed all three marker gates |
| 5 | Vendor directory rejected | Required empty system-as-root `/vendor` mountpoint was confused with packaged vendor content | Permit only the correct empty mountpoint/compatibility-link topology | Attempt 6 completed both development-root verification passes |
| 6 | `unsafe ext4 entry name` | `debugfs` exposed a valid inode-zero unused directory record | Validate its synthesized zero fields, discard only inode-zero non-objects, retain strict live-inode checks | Attempt 7 captured all four snapshots and verified the checkpoint |
| 7 | None | All prior corrections composed successfully | No payload mutation required | 12 of 12 stages complete; checkpoint verified |

The failures were independent fail-closed verifier/parser defects exposed in
sequence. Resumability worked as designed: previously completed outer stages
were reused and only the incomplete boundary was retried.

## Evidence provenance and limits

The acceptance values come from the final output of
`./scripts/case5-local.sh status /home/zirex/XOS-Lavender-Port`, executed on the
machine holding the two proprietary source archives at tooling commit
`d762ce62c9bb8e913fb8e244f8d1be6711c64dd3`. The full checkpoint and metadata
snapshots remain on that machine. This repository records their public hashes,
counts, state, and safety boundary; it does not copy source payloads or private
key material into Git.

Repository CI locks the recorded source/image identities, exact stage order,
checkpoint fields, development-only signing boundary, and the absence of
repack or automatic flashing. Physical boot behavior remains unverified and is
outside Case 5.1.

## Closure boundary

Case 5.1 acceptance unlocks planning and implementation of Case 5.2. Case 5.2
must consume the verified metadata snapshots, map every final path without
falling back to host ownership or labels, build within the lavender system
capacity, and verify the rebuilt image. It must remain development-signed and
must stop before recovery packaging or any device flash.
