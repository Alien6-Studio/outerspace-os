# Contributing to OuterSpace OS

Start with the [README](README.md), [architecture](design/architecture.md) and
[release gates](design/roadmap.md). The current channel is development; use
disposable infrastructure and describe what you actually tested.

## Choose the right branch

- Distribution, runtime, tests, release tooling and repository policies: branch
  from `main` and open a pull request targeting `main`.
- Website sources and generated HTML: branch from `gh-pages` and target
  `gh-pages`. Follow that branch's README; do not add the website to `main`.

Use a focused branch and a descriptive commit, for example
`fix: preserve worker identity after reboot`. Squash merging keeps one coherent
change on the target branch. Link the issue when one exists.

## Validate your change

Run the fast checks with Python 3.11+ and Make:

```sh
make check
```

For image, runtime, bootstrap or build changes, also use the [build guide](design/building.md):

```sh
make builder build smoke package
```

CI runs contract tests on every pull request. Known documentation-only changes
skip image builds; unknown paths, runtime changes, scheduled runs and manual runs
build and smoke-test both architectures. A successful kind network lab does not
qualify an OuterSpace OS node. Hardware reports should include the commit, image
checksum, architecture, machine/firmware and commands used.

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
