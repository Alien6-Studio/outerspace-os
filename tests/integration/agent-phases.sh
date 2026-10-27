#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
# Finite synthetic tools. Boundaries come from the authenticated external
# gateway, never from this untrusted program or its stdout.
set -eu
case "$1" in
    cpu-burst)
        dd if=/dev/zero bs=4096 count=8192 2>/dev/null | sha256sum >/dev/null
        ;;
    memory-spike)
        awk 'BEGIN { for (i=0;i<16384;i++) a[i]=sprintf("%01024d",i); system("sleep 2"); if(length(a[100])!=1024) exit 1 }'
        ;;
    io)
        i=0
        while [ "$i" -lt 16 ]; do
            dd if=/bin/busybox of=/dev/null bs=131072 count=4 iflag=direct 2>/dev/null
            i=$((i + 1))
        done
        ;;
    remote-llm-wait)
        # A private delayed HTTP fixture models provider waiting. It does not
        # execute an LLM, and remote CPU/memory/tokens remain unknown.
        test "$(wget -T 20 -qO- "$2")" = synthetic-provider-response
        ;;
    cached-read)
        dd if=/bin/busybox of=/dev/null bs=131072 count=4 2>/dev/null
        ;;
    shared-memory)
        dd if=/dev/zero of=/workspace/shared bs=1048576 count=16 2>/dev/null
        ;;
    reuse-shared-memory)
        test -s /workspace/shared
        dd if=/workspace/shared of=/dev/null bs=1048576 2>/dev/null
        ;;
    background)
        (sleep 3; dd if=/dev/zero bs=4096 count=8192 2>/dev/null | sha256sum >/dev/null; sleep 120) >/dev/null 2>&1 &
        ;;
    oom-restart)
        awk 'BEGIN { for(i=0;;i++) a[i]=sprintf("%01024d",i) }'
        ;;
    cancellation)
        exec sleep 300
        ;;
    *) exit 92 ;;
esac
