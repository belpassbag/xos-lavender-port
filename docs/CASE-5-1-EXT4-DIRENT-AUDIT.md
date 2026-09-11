# Case 5.1 ext4 directory-entry parser audit

Status: **root cause established; correction verified by repository tests;
local metadata resume pending**.

## Problem

Case 5.1 attempt 6 completed the development root and the independent output
verification. The first source-metadata stage then stopped with:

```text
ERROR: unsafe ext4 entry name
```

The exception can only arise after a line has matched the complete
`debugfs ls -p -l` record grammar and its name field is empty or contains an
embedded NUL/newline. Because the parser splits on newlines and ext4 forbids
NUL in a live filename, the observed empty field identifies an inode-zero
directory record rather than a live file.

## Authoritative format evidence

Linux's ext4 documentation states that inode zero marks an unused directory
entry. It also documents that hash-tree interior nodes deliberately masquerade
as empty inode-zero directory entries:

- https://docs.kernel.org/filesystems/ext4/directory.html

The exact e2fsprogs 1.47.0 implementation used by the local run establishes the
producer behavior. `debugfs` initializes `ls` traversal with
`DIRENT_FLAG_INCLUDE_EMPTY`. In parse mode it emits every selected directory
record, and when its inode is zero it clears the synthetic inode structure
before printing the mode, UID, GID, name, and size fields:

- https://github.com/tytso/e2fsprogs/blob/v1.47.0/debugfs/ls.c
- https://github.com/tytso/e2fsprogs/blob/v1.47.0/lib/ext2fs/dir_iterate.c

Therefore a record such as this is valid tool output but does not describe a
filesystem object:

```text
/0/000000/0/0//0/
```

## Root cause

`parse_ls_output()` validated `name` before interpreting `inode`. It rejected
the empty name even when `inode == 0`, despite the producer and filesystem
format defining that record as unused. The synthetic integration image did not
contain an exposed unused/htree record, so the earlier fixture failed to cover
the real-image condition.

This was a parser-classification defect. It was not corrupt Android metadata,
a damaged source image, a path traversal attempt, or a failure of the completed
development root.

## Correct invariant

The parser now separates non-objects from live objects:

1. Parse inode, mode, UID, GID, name, and size from the complete record.
2. If inode is zero, require mode, UID, GID, and size to be zero, then omit the
   record from the metadata tree.
3. If inode is nonzero, continue to require a nonempty name without NUL or
   newline and validate its file type before publishing it.
4. Reject an inode-zero record carrying nonzero synthetic inode metadata.

No live inode, ownership, mode, SELinux label, capability, xattr, symlink, or
path is discarded by this rule.

## Downstream audit

All four snapshot stages use the same `scan_entries()` and
`parse_ls_output()` path, so the corrected classification applies uniformly to
`base_system`, `donor_system`, `donor_product`, and `donor_system_ext`.
Snapshots remain atomic and image-hash-bound. The final checkpoint still
re-verifies each snapshot's schema, sorted unique paths, root containment,
metadata digest, summary, source image identity, and SELinux-label presence.

Regression coverage proves that:

- a canonical inode-zero empty record between live entries is ignored;
- no inode-zero record reaches captured metadata;
- a malformed inode-zero record is rejected;
- any remaining parser failure reports the exact ext4 directory being scanned;
- normal UID/GID/mode/type parsing still passes;
- the real synthetic-ext4 metadata and symlink round trip still passes;
- snapshot tampering still fails digest verification.

The patch changes only read-only metadata interpretation. It does not modify
any source image, development root, package selection, signing key, SELinux
policy, repack behavior, production signing, or flashing boundary.
