# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
"""Exercise a real, lab-isolated llama.cpp server; emit raw, bounded samples."""
import argparse
import json
import time
import urllib.request

parser = argparse.ArgumentParser()
parser.add_argument('--requests', type=int, default=4)
parser.add_argument('--min-seconds', type=int, default=0)
args = parser.parse_args()
assert 1 <= args.requests <= 128 and 0 <= args.min_seconds <= 600
samples, started = [], time.monotonic()
for index in range(1024):
    if len(samples) >= args.requests and time.monotonic() - started >= args.min_seconds:
        break
    assert time.monotonic() - started < 1800, 'Serving observation exceeded its bounded duration'
    payload = {'prompt': 'The capital of France is', 'n_predict': 8, 'temperature': 0,
               'seed': 42, 'cache_prompt': False, 'stream': True}
    start = time.monotonic()
    request = urllib.request.Request('http://inference.outerspace-inference-v1:8080/completion',
                                     data=json.dumps(payload).encode(),
                                     headers={'Content-Type': 'application/json'})
    chunks, first_token, result, size = [], None, None, 0
    with urllib.request.urlopen(request, timeout=300) as response:
        for line in response:
            size += len(line)
            assert size < 65536, 'Unbounded server response'
            if not line.startswith(b'data: '):
                continue
            data = line[6:].strip()
            if data == b'[DONE]':
                continue
            event = json.loads(data)
            if event.get('content'):
                if first_token is None:
                    first_token = time.monotonic() - start
                chunks.append(event['content'])
            if event.get('stop'):
                result = {**event, 'content': ''.join(chunks)}
    elapsed = time.monotonic() - start
    assert result and first_token is not None, 'No completed streaming generation observed'
    assert isinstance(result.get('content'), str) and result['content'].strip(), 'Empty inference output'
    assert 0 < result['tokens_predicted'] <= 8, 'No bounded model generation observed'
    assert result['tokens_evaluated'] > 0, 'Prompt was not evaluated'
    assert result.get('timings', {}).get('predicted_n', 0) > 0, 'Missing token timing evidence'
    samples.append({'index': index, 'wall_seconds': elapsed, 'first_token_seconds': first_token, 'response': result})
elapsed = time.monotonic() - started
assert len(samples) >= args.requests and elapsed >= args.min_seconds, 'Incomplete sustained serving interval'
print(json.dumps({'schema': 1, 'concurrency': 1, 'requested_samples': args.requests,
                  'minimum_duration_seconds': args.min_seconds, 'wall_seconds': elapsed,
                  'prompt': 'The capital of France is', 'output_token_limit': 8,
                  'temperature': 0, 'seed': 42, 'cache_prompt': False, 'samples': samples}))
