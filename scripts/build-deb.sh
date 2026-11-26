#!/usr/bin/env bash
# Build a Debian package from the current build artifacts.
#
#   VERSION=1.2.3 ./scripts/build-deb.sh
#   SKIP_BUILD=1 ./scripts/build-deb.sh
#
# The package expects the Ubuntu/Debian DPDK runtime (librte-meta-all).
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
VERSION=${VERSION:-${1:-1.0.0}}
VERSION=${VERSION#v}
DEB_VERSION=${DEB_VERSION:-${VERSION}-1}
ARCH=${DEB_ARCH:-amd64}
MARCH=${DEB_MARCH:-x86-64-v2}
DEPENDS=${DEB_DEPENDS:-"libc6 (>= 2.39), librte-meta-all (>= 23.11), libnuma1"}
OUTDIR=${OUTDIR:-"$ROOT/dist"}
SKIP_BUILD=${SKIP_BUILD:-0}
STAGE="$ROOT/build/deb/dpdk-tunnel-router_${DEB_VERSION}_${ARCH}"

if ! command -v dpkg-deb >/dev/null 2>&1; then
    echo "build-deb: dpkg-deb is required" >&2
    exit 1
fi
if ! command -v pkg-config >/dev/null 2>&1; then
    echo "build-deb: pkg-config is required" >&2
    exit 1
fi
if ! pkg-config --exists libdpdk; then
    echo "build-deb: libdpdk development files are required (pkg-config libdpdk)" >&2
    exit 1
fi

if [[ "$SKIP_BUILD" != "1" ]]; then
    # DPDK's pkg-config normally requests -march=native.  A package built on
    # one CI runner must not require that exact CPU, so use a conservative
    # x86-64 baseline by default.
    DPDK_CFLAGS=$(pkg-config --cflags libdpdk)
    if [[ "$DPDK_CFLAGS" == *-march=* ]]; then
        DPDK_CFLAGS=$(printf '%s\n' "$DPDK_CFLAGS" | sed -E "s/-march=[^ ]+/-march=${MARCH}/g")
    else
        DPDK_CFLAGS="$DPDK_CFLAGS -march=${MARCH}"
    fi
    echo "build-deb: clean build (VERSION=$VERSION, march=$MARCH)"
    make -C "$ROOT" clean
    make -C "$ROOT" -j"${JOBS:-$(nproc)}" \
        VERSION="$VERSION" DPDK_CFLAGS="$DPDK_CFLAGS" all
fi

for f in \
    "$ROOT/build/core/dpdk-tunnel-router" \
    "$ROOT/build/rust/release/routerctl" \
    "$ROOT/build/rust/release/libtunnel_driver.so" \
    "$ROOT/config/example.conf"; do
    if [[ ! -e "$f" ]]; then
        echo "build-deb: missing build artifact: $f" >&2
        exit 1
    fi
done

rm -rf "$STAGE"
mkdir -p \
    "$STAGE/DEBIAN" \
    "$STAGE/usr/bin" \
    "$STAGE/usr/sbin" \
    "$STAGE/usr/lib/dpdk-tunnel-router" \
    "$STAGE/usr/share/doc/dpdk-tunnel-router/examples" \
    "$STAGE/etc/dpdk-tunnel-router"

install -m 0755 "$ROOT/build/rust/release/routerctl" \
    "$STAGE/usr/bin/routerctl"
install -m 0755 "$ROOT/build/core/dpdk-tunnel-router" \
    "$STAGE/usr/sbin/dpdk-tunnel-router"
install -m 0755 "$ROOT/build/rust/release/libtunnel_driver.so" \
    "$STAGE/usr/lib/dpdk-tunnel-router/libtunnel_driver.so"
install -m 0644 "$ROOT/config/example.conf" \
    "$STAGE/usr/share/doc/dpdk-tunnel-router/examples/example.conf"
install -m 0644 "$ROOT/config/example.conf" \
    "$STAGE/etc/dpdk-tunnel-router/main.conf"
install -m 0644 "$ROOT/README.md" \
    "$STAGE/usr/share/doc/dpdk-tunnel-router/README.md"
install -m 0644 "$ROOT/LICENSE" \
    "$STAGE/usr/share/doc/dpdk-tunnel-router/copyright"

cat >"$STAGE/usr/share/doc/dpdk-tunnel-router/README.Debian" <<'DEBREADME'
dpdk-tunnel-router for Debian/Ubuntu
=====================================

Installed files:
  /usr/sbin/dpdk-tunnel-router
  /usr/bin/routerctl
  /usr/lib/dpdk-tunnel-router/libtunnel_driver.so
  /etc/dpdk-tunnel-router/main.conf
  /usr/share/doc/dpdk-tunnel-router/examples/example.conf

DPDK ports must be bound to a userspace driver (for example vfio-pci) before
starting the core.  See README.md for dpdk-devbind.py and hugepage setup.

Example:
  sudo dpdk-tunnel-router -l 0-3 -a 0000:00:06.0 -a 0000:00:07.0 -- \
      --workers 3 \
      --config /etc/dpdk-tunnel-router/main.conf \
      --ctl-sock /run/dpdk-tunnel-router.sock

  sudo routerctl --socket /run/dpdk-tunnel-router.sock show interfaces

The Rust transport plugin is optional and is loaded explicitly:
  --plugin /usr/lib/dpdk-tunnel-router/libtunnel_driver.so
DEBREADME

printf '/etc/dpdk-tunnel-router/main.conf\n' >"$STAGE/DEBIAN/conffiles"
chmod -R go-w "$STAGE"
SIZE=$(du -sk "$STAGE" | awk '{print $1}')
cat >"$STAGE/DEBIAN/control" <<EOF
Package: dpdk-tunnel-router
Version: ${DEB_VERSION}
Section: net
Priority: optional
Architecture: ${ARCH}
Maintainer: tuna2134 <m-kikuchi@neody.ad.jp>
Homepage: https://github.com/neodyland/dpdk-tunnel-router
Depends: ${DEPENDS}
Recommends: dpdk
Installed-Size: ${SIZE}
Description: DPDK-based Ethernet tunnel router
 A small DPDK router with EtherIP (RFC 3378) tunnel drivers, VLANs,
 bridging, IPv4/IPv6 forwarding, ARP/NDP, SLAAC, packet capture and a
 routerctl command-line client.  The Rust tunnel-driver plugin is included.
EOF

mkdir -p "$OUTDIR"
DEB="$OUTDIR/dpdk-tunnel-router_${DEB_VERSION}_${ARCH}.deb"
dpkg-deb --build --root-owner-group "$STAGE" "$DEB" >/dev/null
echo "build-deb: wrote $DEB"
echo "build-deb: install with: sudo apt install $DEB"
