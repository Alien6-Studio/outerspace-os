# Repository automation

| Workflow | Purpose |
| --- | --- |
| `ci.yml` | Unit checks, native Agent/Inference image qualification and the aggregate `ci` check |
| `candidate.yml` | Build and package an existing candidate tag for both architectures |
| `cpu-serving.yml` | Manually run the real CPU model-serving qualification |
| `release.yml` | Validate evidence and prepare a draft release from existing candidate bytes |

The CI classifier skips image builds only for an explicit documentation/community
allowlist. Runtime, build, test and unknown paths require the full image matrix.
Candidate and release workflows are manually dispatched. Release preparation
downloads the qualified candidate and does not rebuild it.

[repository/](repository/) contains the repository settings and branch/tag
ruleset definitions. The distribution check is `ci`; the website branch uses
`site-quality`. Workflow tokens default to read-only. The draft-release job
requests the permissions needed to create its draft.

Third-party Actions are pinned to full commit hashes. Dependabot groups Actions
updates and checks the [builder image](../build/Dockerfile), keeping Ubuntu on
the selected LTS. Runtime locks and kernel updates are reviewed separately.

See [contributing](../CONTRIBUTING.md) and the
[release process](../build/release/README.md) for validation and promotion.
