#!/bin/bash
# Build the project on the host, package the test binaries and their runtime
# libraries into an initramfs, boot the host kernel in QEMU, and execute every
# test inside the guest.  No host network, rootfs image, or KVM is required;
# QEMU uses TCG when /dev/kvm is unavailable.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
BUILD=${VM_BUILD_DIR:-$ROOT/vmtest}
STAGE=$BUILD/root
KVER=${KVER:-$(uname -r)}
KERNEL=${KERNEL:-/boot/vmlinuz-$KVER}
LOG=$BUILD/console.log
TIMEOUT=${VM_TIMEOUT:-1800}
QEMU=${QEMU:-qemu-system-x86_64}

say() { printf '>>> %s\n' "$*"; }

for cmd in "$QEMU" cpio gzip ldd make tar; do
    command -v "$cmd" >/dev/null 2>&1 || {
        echo "missing required command: $cmd" >&2
        exit 1
    }
done
if [ ! -r "$KERNEL" ]; then
    # /boot images are often mode 0600.  Fetch the matching distribution
    # package as an unprivileged user and extract it inside the workspace.
    say "kernel $KERNEL is not readable; fetching linux-image-$KVER"
    command -v dpkg-deb >/dev/null 2>&1 && command -v apt-get >/dev/null 2>&1 || {
        echo "need dpkg-deb and apt-get to obtain a readable kernel" >&2
        exit 1
    }
    mkdir -p "$BUILD/pkg" "$BUILD/kernel-root"
    deb=$(find "$BUILD/pkg" -maxdepth 1 -name "linux-image-${KVER}_*.deb" | head -1)
    if [ -z "$deb" ]; then
        (cd "$BUILD/pkg" && apt-get download "linux-image-$KVER")
        deb=$(find "$BUILD/pkg" -maxdepth 1 -name "linux-image-${KVER}_*.deb" | head -1)
    fi
    [ -n "$deb" ] || {
        echo "cannot obtain linux-image-$KVER" >&2
        exit 1
    }
    rm -rf "$BUILD/kernel-root"
    mkdir -p "$BUILD/kernel-root"
    dpkg-deb -x "$deb" "$BUILD/kernel-root"
    KERNEL="$BUILD/kernel-root/boot/vmlinuz-$KVER"
fi
[ -r "$KERNEL" ] || {
    echo "kernel not readable: $KERNEL" >&2
    exit 1
}

say "building core, CLI, plugin and tests"
make -C "$ROOT" all
make -C "$ROOT/core" tests
"$ROOT/scripts/cargo.sh" test --workspace --no-run

RUST_TUNNEL_TEST=$(find "$ROOT/build/rust/debug/build" -type f -perm -111 \
    -name 'tunnel_driver-*' | sort | tail -1)
RUST_CTL_TEST=$(find "$ROOT/build/rust/debug/build" -type f -perm -111 \
    -name 'routerctl-*' | sort | tail -1)
[ -n "$RUST_TUNNEL_TEST" ] && [ -x "$RUST_TUNNEL_TEST" ] || {
    echo "Rust tunnel-driver test binary not found" >&2
    exit 1
}
[ -n "$RUST_CTL_TEST" ] && [ -x "$RUST_CTL_TEST" ] || {
    echo "Rust routerctl test binary not found" >&2
    exit 1
}

say "preparing initramfs"
rm -rf "$STAGE" "$LOG"
mkdir -p "$STAGE"/{bin,sbin,lib,lib64,proc,sys,dev,tmp,run,etc,usr/bin,usr/sbin}
mkdir -p "$STAGE"/usr/lib/x86_64-linux-gnu
mkdir -p "$STAGE"/usr/local/lib/x86_64-linux-gnu
mkdir -p "$STAGE"/project/build/core
mkdir -p "$STAGE"/project/build/rust/release
mkdir -p "$STAGE"/project/build/rust/tests
mkdir -p "$STAGE"/project/scripts

# Minimal userland.
cp /bin/busybox "$STAGE/bin/busybox"
for applet in sh mount umount mkdir chmod rm cp mv ln cat grep od tr seq \
              sleep kill head tail awk sed cut uname date wc sort \
              dirname basename true false sync poweroff ls echo; do
    ln -sf /bin/busybox "$STAGE/bin/$applet"
done
cp /bin/bash "$STAGE/bin/bash"
cp /usr/bin/od "$STAGE/usr/bin/od"

# Project artifacts under test.
cp "$ROOT"/build/core/test_* "$STAGE/project/build/core/"
cp "$ROOT"/build/core/dpdk-tunnel-router "$STAGE/project/build/core/"
cp "$ROOT"/build/rust/release/routerctl "$STAGE/project/build/rust/release/"
cp "$ROOT"/build/rust/release/libtunnel_driver.so "$STAGE/project/build/rust/release/"
cp "$RUST_TUNNEL_TEST" "$STAGE/project/build/rust/tests/tunnel_driver"
cp "$RUST_CTL_TEST" "$STAGE/project/build/rust/tests/routerctl"
cp "$ROOT"/scripts/smoke-test.sh "$STAGE/project/scripts/"
cp "$ROOT"/tests/vm/init "$STAGE/init"
chmod +x "$STAGE/init"

# Runtime configuration and DPDK PMDs.  DPDK's compiled-in PMD path is
# /usr/local/lib/x86_64-linux-gnu/dpdk/pmds-25.0; keep the same path.
cp -a /usr/local/lib/x86_64-linux-gnu/librte_*.so* \
    "$STAGE/usr/local/lib/x86_64-linux-gnu/" 2>/dev/null || true
if [ -d /usr/local/lib/x86_64-linux-gnu/dpdk/pmds-25.0 ]; then
    mkdir -p "$STAGE/usr/local/lib/x86_64-linux-gnu/dpdk"
    cp -a /usr/local/lib/x86_64-linux-gnu/dpdk/pmds-25.0 \
        "$STAGE/usr/local/lib/x86_64-linux-gnu/dpdk/"
fi

cp /etc/protocols /etc/services "$STAGE/etc/" 2>/dev/null || true
printf 'hosts: files\n' > "$STAGE/etc/nsswitch.conf"
printf '127.0.0.1 localhost\n::1 localhost\n' > "$STAGE/etc/hosts"
printf 'root:x:0:0:root:/root:/bin/sh\n' > "$STAGE/etc/passwd"
printf 'root:x:0:\n' > "$STAGE/etc/group"
: > "$STAGE/etc/resolv.conf"

# Recursively copy shared libraries required by every executable and plugin.
declare -A seen=()
queue=()
enqueue() { [ -e "$1" ] && queue+=("$1"); }
parse_ldd() {
    ldd "$1" 2>/dev/null | awk '
        $2 == "=>" && $3 ~ /^\// { print $3 }
        $1 ~ /^\// { print $1 }
    '
}
enqueue "$STAGE/bin/bash"
enqueue "$STAGE/usr/bin/od"
for f in "$STAGE"/project/build/core/* "$STAGE"/project/build/rust/release/routerctl \
         "$STAGE"/project/build/rust/release/libtunnel_driver.so \
         "$STAGE"/project/build/rust/tests/*; do
    [ -f "$f" ] && [ -x "$f" ] && enqueue "$f"
done
for f in "$STAGE"/usr/local/lib/x86_64-linux-gnu/librte_*.so.*; do
    [ -f "$f" ] && enqueue "$f"
done
if [ -d "$STAGE/usr/local/lib/x86_64-linux-gnu/dpdk" ]; then
    while IFS= read -r f; do enqueue "$f"; done < <(
        find "$STAGE/usr/local/lib/x86_64-linux-gnu/dpdk" -type f -name '*.so*'
    )
fi

while [ "${#queue[@]}" -gt 0 ]; do
    elf=${queue[0]}
    queue=("${queue[@]:1}")
    while IFS= read -r lib; do
        [ -n "$lib" ] || continue
        [ -f "$lib" ] || {
            echo "missing runtime library: $lib (needed by $elf)" >&2
            exit 1
        }
        if [ -z "${seen[$lib]:-}" ]; then
            seen[$lib]=1
            mkdir -p "$STAGE$(dirname "$lib")"
            cp -L "$lib" "$STAGE$lib"
            queue+=("$lib")
        fi
    done < <(parse_ldd "$elf")
done

say "creating compressed initramfs"
(
    cd "$STAGE"
    find . -print0 | cpio --null -o -H newc --quiet
) | gzip -6 > "$BUILD/initramfs.cpio.gz"
ls -lh "$BUILD/initramfs.cpio.gz"

say "booting QEMU VM (TCG)"
set +e
timeout "$TIMEOUT" "$QEMU" \
    -kernel "$KERNEL" \
    -initrd "$BUILD/initramfs.cpio.gz" \
    -append "console=ttyS0,115200 rdinit=/init panic=-1 loglevel=4" \
    -nographic -no-reboot -m 2048 -smp 2 \
    -accel tcg,thread=multi -cpu max \
    2>&1 | tee "$LOG"
qemu_rc=${PIPESTATUS[0]}
set -e

say "checking VM test results"
if ! grep -q 'VM_TESTS_PASS' "$LOG"; then
    echo "VM TEST FAILED (no VM_TESTS_PASS marker, qemu rc=$qemu_rc)" >&2
    tail -120 "$LOG" >&2
    exit 1
fi
if grep -q 'TEST_FAIL' "$LOG"; then
    echo "VM TEST FAILED (TEST_FAIL present)" >&2
    grep -E 'TEST_FAIL|TEST_OK|VM_TESTS' "$LOG" >&2
    exit 1
fi

say "all tests passed inside the VM"
grep -E 'TEST_OK|VM_TESTS_PASS|test_(capture|config|engine|fib|plugin|reasm):|smoke:' "$LOG" | tail -40
