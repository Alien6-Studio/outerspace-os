# Focused serving recovery qualification, 2026-10-29

The OuterSpace arm completed all five serving phases: initial requests, sustained
load, Pod replacement, drain recovery and cold-node recovery. It served 46 requests
and 368 generated tokens, with nine admission refusals and two actual invalid-model
refusals. The corrected cold-recovery loop observed the old terminated container,
then a new running container with the same Pod UID and exactly one restart. It
required token-producing readiness before accepting the recovered server.

Harness: `3aae7a5509bd83835143eb2421aef4ec9ffe5219`.
Immutable Inference image source: `c80dc98d492b4cd228b20ca8d0602427fa2977b6`.
Raw disk SHA256: `d37e550741e85d65a3b72d402fd9762391743be2973ac6ccbdd7b62579c9678b`.
The independent verification retains 28 source-input hashes, all original logs
and observations, eight startup waits, exact boot/container identities and
recomputed request summaries. Run `python3 verify-focused.py` to check this archive.
`SHA256SUMS` covers every archived file except itself.

The enclosing comparison later timed out waiting for the Ubuntu worker. Its
exit code is 2: this is **not a new passing matched comparison**. The separate
cleanup record verifies removal of all four inventoried kind volumes and owned
containers, network and temporary state. Prior complete matched evidence remains
at commit `5d23cd066a07cac0b099cfc3e2c495705a11fcf9`, under
`evidence/cpu-serving-20261027`.

These are development observations on an emulated arm64 worker. They establish
no physical efficiency, energy saving, other-architecture result or release
approval. Disks, model weights, kubeconfigs and bootstrap credentials are absent.
