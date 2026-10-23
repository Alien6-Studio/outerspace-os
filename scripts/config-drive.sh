#!/bin/bash
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
config_dir=$(cd "${1:-$repo/node-config}" && pwd)
mkdir -p "$repo/build"
exec docker run --rm --cap-drop=ALL \
    --mount "type=bind,src=$config_dir,dst=/config,readonly" \
    --mount "type=bind,src=$repo/build,dst=/out" \
    "${OUTERSPACE_BUILDER:-outerspace-builder:dev}" \
    bash -euc 'umask 077; test ! -e /out/node-config.raw; truncate -s 16M /out/node-config.raw; mkfs.vfat -n OOS_CONFIG /out/node-config.raw; mcopy -s -i /out/node-config.raw /config/* ::/'
