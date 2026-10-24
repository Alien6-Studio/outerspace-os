# Security policy

## Report a vulnerability privately

Use GitHub's [Report a vulnerability](https://github.com/Alien6-Studio/outerspace-os/security/advisories/new)
form. Private vulnerability reporting is enabled. Do not put exploit details,
credentials or sensitive logs in a public issue or discussion.

Include the affected commit/version, architecture, image checksum if available,
configuration, impact and a minimal reproduction. A sanitized boot or audit log
can help. Maintainers will assess the report privately and coordinate a fix and
disclosure with the reporter. Response is best effort during development; there
is no response-time SLA.

## Supported versions and scope

Only the current development branch is being maintained. There is no supported
production release or published support window yet. Development images are for
disposable test environments. Before stable, the project must publish a tested
hardware/version matrix, update and rollback procedure, and support dates.

Scope includes the image recipe, host services, bootstrap/config-drive handling,
component installation, build and release tooling and the website. Upstream Linux,
Ubuntu and runtime components retain their upstream security processes; report
an integration impact here so the distribution can be assessed and rebuilt.

## Security posture and its limits

The image uses a read-only verity root, locked accounts, AppArmor, container
seccomp defaults and conservative host configuration. Development UKIs are
unsigned. Secure Boot, authenticated A/B updates, complete SBOM/vulnerability
review and independent hardening evidence remain release gates.

The [CIS security target](src/docs/security.md) describes intended controls and
exceptions. It is not a certification or a completed compliance audit. Likewise,
checksums verify file integrity; they do not authenticate a publisher.

Repository protections, private reporting, secret push protection, Dependabot and
native GitHub CodeQL complement review. They do not replace image-level auditing,
runtime tests or the [release qualification policy](build/release/README.md).
