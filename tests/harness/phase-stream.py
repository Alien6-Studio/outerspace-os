# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
"""Bounded request/response transport over one authenticated Kubernetes exec."""
import json
import os
import select
import subprocess
import tempfile
import threading
import time

SCHEMA = 'outerspace.phase-probe.v1'
MAX_REQUEST_BYTES = 16384
MAX_RESPONSE_BYTES = 262144


class ProbeStream:
    def __init__(self, command, *, startup_timeout=180, request_timeout=60):
        self.process = None
        self.stderr = tempfile.TemporaryFile()
        self.buffer = b''
        self.sequence = 0
        self.closed = False
        self.lock = threading.Lock()
        self.request_timeout = request_timeout
        started = time.monotonic()
        try:
            self.process = subprocess.Popen(list(map(str, command)), stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=self.stderr, bufsize=0)
            ready = self.read(started + startup_timeout)
            if ready != {'schema': SCHEMA, 'status': 'ready'}:
                raise ValueError('Unexpected phase collector handshake')
            self.startup_wall_seconds = time.monotonic() - started
        except Exception:
            self.close()
            raise

    def read(self, deadline):
        while b'\n' not in self.buffer:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([self.process.stdout], [], [], remaining)[0]:
                raise TimeoutError('Phase collector response deadline exceeded')
            chunk = os.read(self.process.stdout.fileno(), 4096)
            if not chunk:
                raise RuntimeError('Phase collector connection lost')
            self.buffer += chunk
            if len(self.buffer) > MAX_RESPONSE_BYTES:
                raise ValueError('Phase collector response budget exceeded')
        line, self.buffer = self.buffer.split(b'\n', 1)
        return json.loads(line)

    def request(self, request):
        with self.lock:
            if self.closed:
                raise RuntimeError('Phase collector is closed; refusing reconnect')
            try:
                sequence = self.sequence + 1
                data = json.dumps({'sequence': sequence, 'request': request},
                                  separators=(',', ':'), allow_nan=False).encode() + b'\n'
                if len(data) > MAX_REQUEST_BYTES:
                    raise ValueError('Phase collector request budget exceeded')
                deadline = time.monotonic() + self.request_timeout
                # One bounded request is in flight. Nonblocking writes keep the
                # same deadline even if a failed peer stops reading its input.
                descriptor = self.process.stdin.fileno()
                os.set_blocking(descriptor, False)
                while data:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or not select.select([], [descriptor], [], remaining)[1]:
                        raise TimeoutError('Phase collector request deadline exceeded')
                    try:
                        data = data[os.write(descriptor, data):]
                    except BlockingIOError:
                        continue
                result = self.read(deadline)
                if (set(result) != {'sequence', 'observation'} or type(result['sequence']) is not int
                        or result['sequence'] != sequence):
                    raise ValueError('Replayed or mismatched phase collector response')
                self.sequence = sequence
                return result['observation']
            except Exception:
                self.close()
                raise

    def close(self):
        if self.closed:
            return
        self.closed = True
        if self.process is not None:
            self.process.stdin.close()
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.terminate()
                try:
                    self.process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait()
            self.process.stdout.close()
        self.stderr.close()
