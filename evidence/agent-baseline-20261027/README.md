# Agent density evidence — 2026-10-27

Raw, paired OuterSpace/Ubuntu arm64 QEMU TCG observations for issue #11 and PR #40.
The parent commit is the exact clean harness snapshot used by this run. This
branch archives evidence separately from the distribution source on main.

`worker-comparison.json` contains the 32 raw samples, summaries, health checks,
source and image identities, Ubuntu provenance and hashes of the eight supporting
files. Its SHA256 is `6b1fc656b97f5bdcbd585fd19fb06e27b5f715416198e622bacdc1ad720c9430`.
`SHA256SUMS` covers it and the original observations, boot logs, QEMU commands and
DHCP logs for both subjects. Bootstrap credentials, kubeconfigs, private keys,
config-drive images and VM disks are excluded.

Each worker ran from a fresh overlay, serially, with four vCPUs and 4096 MiB.
Kernel/build notes, runtime binary hashes and policy/configuration hashes match.
Stages contain zero, one, two and four idle BusyBox Agents; no agent framework
or model is loaded. Health, enforced limits, unchanged Agent identities and
complete teardown pass. Both disposable laboratories were removed after the run.

These observations include the read-only probe and qualification workloads.
They establish no useful-agent throughput, physical performance, higher-density
capacity or CPU-efficiency advantage. Density 10/100 and an amd64 Ubuntu
comparison remain untested. The source PR documents numeric results and limits.
