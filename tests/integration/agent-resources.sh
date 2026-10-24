#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
# Disposable, admitted BusyBox workload. The external harness always deletes the
# entire pod; no cleanup command needs to fork inside an exhausted PID budget.
set -eu
mode=$1
test ! -e /workspace/previous-workspace
test ! -e /scratch/previous-workspace
printf 'fresh\n' > /workspace/ready
while [ ! -e /workspace/go ]; do sleep 1; done
printf 'private\n' > /workspace/previous-workspace
printf 'private\n' > /scratch/previous-workspace
case "$mode" in
    cpu)
        for worker in 1 2 3 4; do
            (while :; do :; done) &
        done
        wait
        ;;
    fork)
        # The parent survives a child's fork failure so the observer can read
        # pids.events at the enforced limit before teardown.
        (i=0; while [ "$i" -lt 512 ]; do sleep 300 & i=$((i + 1)); done; wait) &
        wait || :
        while :; do :; done
        ;;
    scratch)
        if dd if=/dev/zero of=/scratch/flood bs=1048576 count=32 2>/workspace/dd-error; then
            exit 91
        fi
        grep -q 'No space left on device' /workspace/dd-error
        printf 'scratch-full\n' > /workspace/result
        ;;
    oom)
        set +e
        awk 'BEGIN { for (i=0;;i++) a[i]=sprintf("%01024d",i) }'
        status=$?
        set -e
        test "$status" -eq 137
        printf 'oom-killed\n' > /workspace/result
        ;;
    logs)
        # A finite burst exposes rotation overshoot; rotation is not a hard
        # per-write filesystem quota. Do not advertise 2 MiB as a hard cap.
        line=$(printf '%01024d' 1)
        yes "$line" | head -c 20971520
        printf 'logs-written\n' > /workspace/result
        ;;
    *) exit 92 ;;
esac
while :; do sleep 1; done
