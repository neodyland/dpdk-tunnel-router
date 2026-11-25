#!/usr/bin/env bash
# Run the router without a NIC, using DPDK's net_null PMD.  Useful for control
# plane work and CI.  Requires `make`.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
mkdir -p "$ROOT/run" "$ROOT/tmp"
chmod 700 "$ROOT/run"
export XDG_RUNTIME_DIR="$ROOT/run"
export TMPDIR="$ROOT/tmp"
exec "$ROOT/build/core/dpdk-tunnel-router" \
    --no-huge --no-pci --vdev=net_null0 -l 0-1 -m 512 -- \
    --workers 1 \
    --config "${ROUTER_CONFIG:-$ROOT/run/running.conf}" \
    --ctl-sock "${ROUTER_SOCKET:-$ROOT/run/ctl.sock}" \
    "${@}"
