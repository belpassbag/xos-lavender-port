# Case 1 safety recovery

Status: **accepted on 2026-09-06 after local and GitHub CI verification**.

This recovery reopens only the Case 1 safety foundation. It does not extract,
port, package, or flash a ROM.

## Problem

The original configuration validator checked the shape of the profile, but it
did not lock every safety-critical value. A syntactically valid edit could
replace a source checksum, enlarge the target partition, remove target hardware
preservation, weaken donor-image exclusions, or empty the first-boot scope and
still pass `make check`.

The first-boot policy also excluded all of `/product/app` and
`/product/priv-app`. That broad rule conflicted with the verified XOS core
dependencies `SystemUIOverlay`, `SettingsOverlay`, and `XOSLauncher_res`.

## Cause

`validate_config()` enforced Android/API/device invariants and a minimum set of
forbidden images, but the canonical source, partition, and selection profiles
were not independently encoded in the validator. Product selection used a
directory-wide exclusion instead of an explicit allowlist.

## Solution

- Lock the complete project, base, donor, and policy profiles in the validator.
- Reject missing, unexpected, reordered, or changed locked fields.
- Keep donor `boot.img` and `dtbo.img` outside normal extraction.
- Allow donor AVB metadata to be inspected while continuing to forbid every
  donor vbmeta image from final output.
- Replace broad product exclusions with allowlist-only package selection.
- Record the five selected `system_ext` packages and the three selected product
  packages separately from the remaining first-boot exclusions.

The locked product allowlist is:

- `/product/app/SystemUIOverlay`
- `/product/app/SettingsOverlay`
- `/product/priv-app/XOSLauncher_res`

All other donor product application directories remain excluded implicitly by
the allowlist-only mode. This includes donor GMS and SetupWizard payloads.

## Verification

The recovery adds negative tests proving that the validator rejects changes to:

- source SHA-256 identity;
- target system partition size;
- target hardware preservation;
- donor modem/firmware exclusion;
- XOS core scope;
- first-boot exclusions;
- donor boot extraction; and
- the donor product allowlist.

`make check` passes 14 tests, Python compilation, locked-profile validation, and
shell syntax validation. Acceptance requires the same checks to pass in the
pull request and again on the resulting `main` commit.
