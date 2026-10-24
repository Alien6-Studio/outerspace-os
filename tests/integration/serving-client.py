# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
"""Exercise a real, lab-isolated llama.cpp server; emit raw, bounded samples."""
import json
import time
import urllib.request

samples = []
for index in range(4):
    payload = {'prompt': 'The capital of France is', 'n_predict': 8, 'temperature': 0,
               'seed': 42, 'cache_prompt': False, 'stream': True}
    start = time.monotonic()
    request = urllib.request.Request('http://inference:8080/completion',
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
print(json.dumps({'schema': 1, 'concurrency': 1, 'samples': samples}))
