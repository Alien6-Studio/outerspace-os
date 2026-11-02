#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
# Run inside the pinned Linux Go builder against the fully staged containerd tree.
set -euo pipefail
source_dir=${1:?Provide the fully staged containerd source directory}
fixture=$(cd "$(dirname "$0")" && pwd)/containerd_oci_user_bounds_test.go
source_dir=$(cd "$source_dir" && pwd)
tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT
python3 - "$source_dir/pkg/oci/outerspace_user_bounds_test.go" "$fixture" "$tmp_dir/overlay.json" <<'PY'
import json, sys
from pathlib import Path
Path(sys.argv[3]).write_text(json.dumps({'Replace': {sys.argv[1]: sys.argv[2]}}))
PY
cd "$source_dir"
case "$(go version)" in
  "go version go1.26.10 linux/amd64"|"go version go1.26.10 linux/arm64") ;;
  *) echo 'The pinned Linux Go 1.26.10 toolchain is required.' >&2; exit 1 ;;
esac
# The upstream test expects a 10 MiB group line to parse; v0.4.1 deliberately
# rejects lines >= 1 MiB. Run every other OCI test plus the replacement bounds.
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off CGO_ENABLED=0 go test -count=1 -mod=vendor \
  -overlay "$tmp_dir/overlay.json" -skip '^TestOpenUserFileCapsReads$' \
  -tags urfave_cli_no_docs,osusergo,netgo,static_build ./pkg/oci
