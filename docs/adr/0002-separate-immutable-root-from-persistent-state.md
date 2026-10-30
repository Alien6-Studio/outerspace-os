# ADR 0002: Separate the immutable root from persistent worker state

Status: implemented decision, recorded retrospectively on 2026-10-30.

## Context

The worker must boot a known host configuration while preserving container data,
node identity and logs across cold starts. Kubernetes and CNI components need
writable state, but should not require modifying installed host software.

## Decision

Ship a read-only ext4 root with a dm-verity hash partition. Embed the expected
root hash in the UKI. Keep persistent state in a separate `/var` partition;
`/etc` remains static and `/run` and `/tmp` are volatile. Route CNI installation
through `/opt/cni` to `/var/lib/cni` instead of making the root writable.

Host configuration and kernel modules change through image assembly, not package
installation at node startup. The development layout has one root slot and
unsigned boot assets. It supplies no in-place updater or rollback transaction.

## Alternatives and tradeoffs

- A writable root would accommodate arbitrary installers, but allow host state
  to drift away from the built image.
- An entirely ephemeral disk would simplify replacement, but discard node
  credentials, runtime data and logs on every boot.
- An A/B layout would provide update slots, but slots alone do not implement
  authenticated metadata, boot confirmation, state migration or rollback.

## Consequences

Host changes are reviewable as image inputs, and worker state survives reboot.
Integrations must use explicit writable locations. Persistent state still needs
its own access, retention and recovery policies; dm-verity does not protect it.

Verity detects root corruption only when the expected hash is trusted. Unsigned
development boot assets therefore do not establish boot authenticity. A future
update mechanism must switch matching root and UKI together and define failure
recovery; [#19](https://github.com/Alien6-Studio/outerspace-os/issues/19) owns that
work and requires a successor decision before changing this layout.

Implementation: [partition definitions](../../src/image/mkosi.repart/),
[image assembly](../../src/image/mkosi.postinst),
[mount configuration](../../src/image/mkosi.extra/etc/fstab) and
[cold-boot harness](../../tests/harness/boot-uefi.py).
