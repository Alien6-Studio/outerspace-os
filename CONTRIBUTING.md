# Contributing to OuterSpace OS

Start with the [README](README.md), [architecture decisions](docs/adr/) and
[release gates](build/release/README.md). The current channel is development; use
disposable infrastructure and describe what you actually tested.

Distribution sources live in `src/`, build and release tooling in `build/`, and
qualification code in `tests/`. The root Makefile exposes their commands;
generated artifacts belong in the ignored `out/` directory.

## Choose the right branch

- Distribution, runtime, tests, release tooling and repository policies: branch
  from `main` and open a pull request targeting `main`.
- Website sources and generated HTML: branch from `gh-pages` and target
  `gh-pages`. Follow that branch's README; do not add the website to `main`.

Group a complete ticket or a coherent set of tickets on one branch. Keep the PR
in draft while implementing and fixing it locally. Mark it ready only when the
acceptance criteria are implemented and local checks pass. If CI exposes a code
defect, return the PR to draft, fix the cause locally and push the complete fix.
Squash merge once, close the implemented issues and delete the merged branch.
Use version tags only for release candidates and releases.

## Validate your change

Run the fast checks with Python 3.11+ and Make:

```sh
make check
```

Run tests for the behavior changed while developing. Before marking an image,
runtime, bootstrap or build PR ready, qualify the affected native profiles once
using the [build guide](build/README.md):

```sh
make PROFILE=agent builder build smoke package
make PROFILE=inference build smoke package
```

Draft PRs do not run distribution jobs. Ready PRs run contract tests; known
documentation-only changes skip image builds. Runtime and unknown changes run
the full native qualification on both architectures. Weekly and manual runs
retain the full campaign; a protected merge does not launch it again. Do not
rerun a passing campaign unless the code, inputs or an unresolved failure require
it. Use a failed-job retry only for an identified infrastructure failure.

Keep status and acceptance criteria in GitHub issues and milestones. Attach
generated evidence to the relevant run or release; do not add progress diaries
or duplicate roadmaps to the repository. Keep PR validation concise, with the
commit, image checksum and tested scope. A kind network lab does not qualify an
OuterSpace OS node; native VM evidence does not qualify physical hardware.

Record durable architectural choices in `docs/adr/`: context, decision,
alternatives, consequences and implementation references. An ADR explains why a
choice was made; operational instructions stay with the source, build or test
guide. Supersede an obsolete decision with a new ADR rather than rewriting its
history. Record existing choices as retrospective records, without inventing a
past approval or decision date.

## Review expectations

Explain the problem, resulting behavior, validation and any state or upgrade
impact. Keep dependency changes pinned to official sources and verify checksums.
Update documentation and release notes when behavior or compatibility changes.
Add regression tests where they exercise a meaningful failure or security boundary.

Do not include bootstrap tokens, kubeconfigs, private keys, model credentials or
config-drive images. Sanitize logs before attaching them. Report vulnerabilities
through the [private security channel](SECURITY.md).

Protected branches require a pull request, passing checks and resolved review
threads. CODEOWNERS requests maintainer review for outside contributions. The
repository currently has one owner, so a second-person approval and signed commits
are not mandatory. Release tags cannot be overwritten or deleted.

Contributions are licensed under Apache-2.0. Keep upstream notices and licenses
intact. Participation follows the [Code of Conduct](CODE_OF_CONDUCT.md).
