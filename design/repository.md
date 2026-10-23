# Repository maintenance

The baseline follows the OuterSpace Apizr repositories: concise README, honest
workflow/status badges, CODEOWNERS, private security reporting, focused pull
requests and separate distribution/website branches. It is adapted to OS image
qualification rather than Python package publication.

## GitHub settings

The desired state is recorded in [.github/repository](../.github/repository).
Use the authenticated GitHub CLI as a repository administrator, after reviewing
the JSON files:

```sh
gh api --method PATCH repos/Alien6-Studio/outerspace-os --input .github/repository/settings.json
gh api --method PUT repos/Alien6-Studio/outerspace-os/topics --input .github/repository/topics.json
gh api --method PUT repos/Alien6-Studio/outerspace-os/actions/permissions/workflow --input .github/repository/workflow-permissions.json
gh api --method PATCH repos/Alien6-Studio/outerspace-os/code-scanning/default-setup --input .github/repository/codeql.json
gh api --method PUT repos/Alien6-Studio/outerspace-os/automated-security-fixes
gh api --method PUT repos/Alien6-Studio/outerspace-os/private-vulnerability-reporting
```

Secret scanning and secret push protection must remain enabled. CodeQL's native
default setup scans Python and Actions; there is no duplicate custom workflow.
Dependabot proposes pinned Actions and Docker base-image updates. The custom
runtime lock and Ubuntu security updates still need maintainer review.

The default workflow token is read-only and cannot approve pull requests. The
draft-release job alone requests the write access it needs. Third-party actions
are pinned to full commit SHAs, with version comments for review.

## Branch and tag rules

`main` requires the aggregate **ci** check; `gh-pages` requires **site-quality**.
Both require a PR, resolved review threads and an up-to-date branch, and prohibit
deletion and force pushes. Checks always report on PRs; there is no top-level
documentation path filter that could leave a required check pending forever.
Version tags `v*` cannot be deleted or moved. No bypass actor is configured.

To reconcile rulesets, first list existing IDs:

```sh
gh api repos/Alien6-Studio/outerspace-os/rulesets --jq '.[] | {id, name}'
```

For a missing rule, POST its JSON to `/repos/Alien6-Studio/outerspace-os/rulesets`.
For an existing rule, PUT the reviewed JSON to that endpoint plus its ID. Do not
POST duplicate rulesets. Install workflow changes and confirm the named checks
exist before enforcing a new required check.

There is currently one maintainer. CODEOWNERS requests review, with zero required
approvals so the maintainer can merge their own checked work. Unlike Apizr,
verified commit signatures are not required yet: the current development history
is unsigned. Add signing and second-person approval only with a tested maintainer
workflow and recovery procedure. This is separate from image/release signing.

## CI cost and evidence

Every distribution PR runs `make check`. A conservative, tested allowlist lets
documentation/community-only changes skip the image matrix. Unknown paths,
comparison failures, runtime/build changes, schedules and manual dispatches run
both native architecture builds, QEMU smoke tests and packaging. The aggregate
check rejects failures, cancellation and unexpected skips.

Website changes use a separate strict MkDocs build. Candidate/release workflows
remain manually dispatched and evidence-gated; no push publishes a Linux release.
See [release maintenance](../release/README.md) for the wider qualification policy.
