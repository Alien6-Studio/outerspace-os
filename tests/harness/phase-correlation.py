# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
"""Versioned trusted gateway contract; performance evidence, not authorization.

The caller owns the authenticated Kubernetes API connection and resolves every
scope from API-observed OCI identities. An agent cannot register scopes or obtain
the per-run MAC key. No prompt, tool arguments, filesystem path or credential is
accepted by this contract. This reference implementation runs outside the host.
"""
import hashlib
import hmac
import json
import math
import re
import time
import uuid

SCHEMA = 'outerspace.phase.v1'
MAX_EVENTS, MAX_SCOPES, MAX_SAMPLES, MAX_BYTES = 1024, 32, 256, 8 * 1024 * 1024
UUID = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')
HEX64 = re.compile(r'[0-9a-f]{64}')
EVENT_FIELDS = {'schema', 'run_id', 'issuer_id', 'sequence', 'policy_sha256', 'event',
                'operation_id', 'agent_id', 'parent_agent_id', 'tool_id', 'trace_id',
                'span_id', 'parent_span_id', 'scope_id', 'wall_time_unix_ns',
                'monotonic_ns', 'outcome'}
SCOPE_FIELDS = {'pod_uid', 'node_uid', 'container_id', 'image_id', 'boot_id', 'restart_count'}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def identifier(value):
    return isinstance(value, str) and UUID.fullmatch(value) is not None


def quantiles(values):
    if not values or any(type(v) not in (int, float) or not math.isfinite(v) or v < 0 for v in values):
        raise ValueError('Invalid observation distribution')
    ordered = sorted(values)
    return {'samples': len(values), 'p50': ordered[math.ceil(.5 * len(values)) - 1],
            'p95': ordered[math.ceil(.95 * len(values)) - 1], 'min': ordered[0], 'max': ordered[-1]}


class Session:
    def __init__(self, key, run_id, issuer_id, policy_sha256):
        if (not isinstance(key, bytes) or len(key) != 32 or not identifier(run_id)
                or not identifier(issuer_id) or not HEX64.fullmatch(policy_sha256)):
            raise ValueError('Invalid trusted session')
        self.key, self.run_id, self.issuer_id, self.policy = key, run_id, issuer_id, policy_sha256
        self.events, self.scopes, self.samples, self.operations = [], {}, {}, {}
        self.sequence, self.bytes = 0, 0
        self.failed = False

    def reserve(self, value):
        if self.failed:
            raise ValueError('Measurement session has failed closed')
        size = len(canonical(value))
        if self.bytes + size > MAX_BYTES:
            self.failed = True
            raise ValueError('Measurement buffer budget exceeded; cancel pending benchmark work')
        self.bytes += size

    def register(self, metadata):
        if (set(metadata) != SCOPE_FIELDS
                or any(not identifier(metadata[k]) for k in ['pod_uid', 'node_uid', 'boot_id'])
                or any(not HEX64.fullmatch(metadata[k]) for k in ['container_id', 'image_id'])
                or type(metadata['restart_count']) is not int or metadata['restart_count'] < 0):
            raise ValueError('Invalid authenticated execution scope')
        # Do not allow two aliases to duplicate the same measured OCI scope.
        if any((s['pod_uid'], s['container_id']) == (metadata['pod_uid'], metadata['container_id'])
               for s in self.scopes.values()):
            raise ValueError('Execution scope is already registered')
        if len(self.scopes) >= MAX_SCOPES:
            self.failed = True
            raise ValueError('Execution scope buffer budget exceeded; cancel pending benchmark work')
        self.reserve(metadata)
        scope = str(uuid.uuid4())
        self.scopes[scope], self.samples[scope] = dict(metadata), []
        return scope

    def sign(self, event):
        encoded = canonical(event)
        if len(encoded) > 4096:
            raise ValueError('Unbounded boundary event')
        return {'event': event, 'mac': hmac.new(self.key, encoded, hashlib.sha256).hexdigest()}

    def accept(self, envelope):
        if set(envelope) != {'event', 'mac'}:
            raise ValueError('Invalid boundary envelope')
        event = envelope['event']
        encoded = canonical(event)
        if (len(encoded) > 4096 or not isinstance(envelope['mac'], str)
                or not hmac.compare_digest(envelope['mac'], hmac.new(self.key, encoded, hashlib.sha256).hexdigest())):
            raise ValueError('Unauthenticated phase boundary')
        if (set(event) != EVENT_FIELDS or event['schema'] != SCHEMA or event['run_id'] != self.run_id
                or event['issuer_id'] != self.issuer_id or event['policy_sha256'] != self.policy
                or type(event['sequence']) is not int or event['sequence'] != self.sequence + 1
                or event['event'] not in ['start', 'end']
                or any(not identifier(event[k]) for k in ['operation_id', 'agent_id', 'tool_id'])
                or event['parent_agent_id'] is not None and not identifier(event['parent_agent_id'])
                or event['scope_id'] is not None and event['scope_id'] not in self.scopes
                or not re.fullmatch(r'[0-9a-f]{32}', event['trace_id']) or event['trace_id'] == '0' * 32
                or not re.fullmatch(r'[0-9a-f]{16}', event['span_id']) or event['span_id'] == '0' * 16
                or event['parent_span_id'] is not None and not re.fullmatch(r'[0-9a-f]{16}', event['parent_span_id'])
                or any(type(event[k]) is not int or event[k] <= 0 for k in ['wall_time_unix_ns', 'monotonic_ns'])
                or self.events and event['monotonic_ns'] < self.events[-1]['event']['monotonic_ns']):
            raise ValueError('Invalid, replayed or cross-run boundary')
        operation = event['operation_id']
        if event['event'] == 'start':
            if operation in self.operations or event['outcome'] != 'running':
                raise ValueError('Duplicate or invalid operation start')
        else:
            start = self.operations.get(operation, {}).get('start')
            if (not start or 'end' in self.operations[operation] or event['outcome'] not in ['ok', 'cancelled', 'error']
                    or any(event[k] != start[k] for k in ['agent_id', 'parent_agent_id', 'tool_id',
                                                         'trace_id', 'span_id', 'parent_span_id', 'scope_id'])):
                raise ValueError('Unmatched operation end')
        if len(self.events) >= MAX_EVENTS:
            self.failed = True
            raise ValueError('Boundary buffer budget exceeded; cancel pending benchmark work')
        self.reserve(envelope)
        self.events.append(json.loads(canonical(envelope)))
        self.operations.setdefault(operation, {})[event['event']] = dict(event)
        self.sequence += 1

    def boundary(self, event, operation=None, *, agent_id=None, tool_id=None, scope_id=None,
                 parent_agent_id=None, outcome=None):
        if event == 'start':
            payload = {'schema': SCHEMA, 'run_id': self.run_id, 'issuer_id': self.issuer_id,
                       'policy_sha256': self.policy, 'operation_id': str(uuid.uuid4()),
                       'agent_id': agent_id, 'parent_agent_id': parent_agent_id, 'tool_id': tool_id,
                       'scope_id': scope_id, 'trace_id': uuid.uuid4().hex, 'span_id': uuid.uuid4().hex[:16],
                       'parent_span_id': None}
        else:
            payload = dict(self.operations[operation]['start'])
        payload.update(event=event, sequence=self.sequence + 1, wall_time_unix_ns=time.time_ns(),
                       monotonic_ns=time.monotonic_ns(), outcome=outcome or ('running' if event == 'start' else 'ok'))
        self.accept(self.sign(payload))
        return payload['operation_id']

    def sample(self, scope, observation, before_ns, after_ns):
        if scope not in self.scopes or len(self.samples[scope]) >= MAX_SAMPLES:
            self.failed = True
            raise ValueError('Unknown scope or exhausted sample buffer; cancel pending benchmark work')
        identity = self.scopes[scope]
        if (observation['pod_uid'] != identity['pod_uid'] or observation['container_id'] != identity['container_id']
                or type(before_ns) is not int or type(after_ns) is not int or not 0 < before_ns <= after_ns):
            raise ValueError('Snapshot is not bound to the authenticated scope')
        value = {'gateway_before_ns': before_ns, 'gateway_after_ns': after_ns, 'observation': observation}
        self.reserve(value)
        self.samples[scope].append(json.loads(canonical(value)))

    def report(self):
        scopes = {}
        for scope, samples in self.samples.items():
            reasons = set()
            data = [s['observation'] for s in samples]
            if len(data) < 2:
                reasons.add('missing-samples')
            if any(s['status'] != 'observed' for s in data):
                reasons.add('missing-or-lost-scope')
            if len({(s.get('scope_instance'), s['boot_id']) for s in data}) > 1:
                reasons.add('scope-restart-or-node-reboot')
            if any(s.get('detached_processes') for s in data):
                reasons.add('observed-detached-process')
            if any(s.get('gaps') for s in data):
                reasons.add('collector-observation-gap')
            intervals = []
            for first, last in zip(data, data[1:]):
                if (first['status'] != 'observed' or last['status'] != 'observed'
                        or first.get('scope_instance') != last.get('scope_instance')
                        or first['boot_id'] != last['boot_id']):
                    continue
                elapsed = (last['started_monotonic_ns'] - first['started_monotonic_ns']) / 1e9
                cpu = last['cpu_usec']['usage_usec'] - first['cpu_usec']['usage_usec']
                io = {}
                for device in first['io'].keys() | last['io'].keys():
                    io[device] = {k: last['io'].get(device, {}).get(k, 0) - first['io'].get(device, {}).get(k, 0)
                                  for k in ['rbytes', 'wbytes', 'rios', 'wios']}
                if elapsed <= 0 or cpu < 0 or any(v < 0 for device in io.values() for v in device.values()):
                    reasons.add('counter-regression-or-clock-gap')
                    continue
                intervals.append({'wall_seconds': elapsed, 'cpu_seconds': cpu / 1e6, 'io': io})
            operations = [k for k, op in self.operations.items() if op['start']['scope_id'] == scope]
            if any('end' not in self.operations[k] for k in operations):
                reasons.add('unfinished-operation')
            scopes[scope] = {'identity': self.scopes[scope], 'status': 'partial' if reasons else 'observed',
                'reasons': sorted(reasons), 'intervals': intervals, 'operation_ids': operations,
                'samples': samples, 'attribution': 'scope-only',
                'memory_semantics': 'current gauges and lifetime peaks; shared/page-cache charges are not private RSS',
                'coverage': 'cgroup descendants; unobserved escaped or external processes are unknown'}
        spans = []
        for operation, bounds in self.operations.items():
            start, end = bounds['start'], bounds.get('end')
            spans.append({'traceId': start['trace_id'], 'spanId': start['span_id'],
                'parentSpanId': start['parent_span_id'], 'startTimeUnixNano': str(start['wall_time_unix_ns']),
                'endTimeUnixNano': str(end['wall_time_unix_ns']) if end else None,
                'attributes': {'outerspace.operation.id': operation, 'outerspace.run.id': self.run_id,
                    'outerspace.agent.id': start['agent_id'], 'outerspace.agent.parent_id': start['parent_agent_id'],
                    'outerspace.tool.id': start['tool_id'], 'outerspace.policy.sha256': self.policy,
                    'outerspace.scope.id': start['scope_id'], 'outerspace.outcome': end['outcome'] if end else 'unfinished'},
                'tool_metrics': None,
                'attribution_status': 'unknown',
                'attribution': 'scope-only; no per-tool allocation' if start['scope_id'] else 'external-provider-unknown'})
        return {'schema': SCHEMA, 'run_id': self.run_id, 'issuer_id': self.issuer_id,
                'policy_sha256': self.policy, 'status': 'failed' if self.failed else 'recorded',
                'authentication': 'Per-run HMAC verified before acceptance; key excluded from export',
                'events': self.events, 'scopes': scopes, 'spans': spans,
                'buffer_bytes': self.bytes,
                'aggregation': 'Each scope interval occurs once; never sum per-tool or memory peaks',
                'failure_behavior': 'Reject unauthenticated boundaries; cancel pending benchmark work on lost collection or buffer failure; retain partial traces'}
