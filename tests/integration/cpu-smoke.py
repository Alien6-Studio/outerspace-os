# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
"""Deterministic nearest-centroid classifier; enrollment smoke, not serving qualification."""
from http.server import BaseHTTPRequestHandler, HTTPServer


def predict(point):
    centroids = ((0, 0), (3, 3))
    distances = [sum((x - y) ** 2 for x, y in zip(point, center)) for center in centroids]
    return min(range(len(centroids)), key=distances.__getitem__)


assert [predict(p) for p in ((0, 1), (2, 3), (3, 2), (1, 0))] == [0, 1, 1, 0]
result = sum(predict((i % 4, (i // 4) % 4)) for i in range(4096))
assert result == 1536
RESPONSE = b'outerspace-cpu-ok:1536\n'


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(RESPONSE)


HTTPServer(('0.0.0.0', 8080), Handler).serve_forever()
