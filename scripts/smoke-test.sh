#!/usr/bin/env bash
# Live control-plane smoke test using DPDK's net_null PMD.
#
# It starts the real data plane, drives it through routerctl, checks
# persistence across a restart, and loads the Rust tunnel-driver plugin.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CORE="$ROOT/build/core/dpdk-tunnel-router"
CLI="$ROOT/build/rust/release/routerctl"
PLUGIN="$ROOT/build/rust/release/libtunnel_driver.so"
RUN="$ROOT/run"
XDG="$RUN/smoke-xdg"
SOCK="$RUN/smoke.sock"
CONF="$RUN/smoke.conf"
LOG="$RUN/smoke.log"
PID=""

mkdir -p "$RUN" "$ROOT/tmp" "$XDG"
chmod 700 "$XDG"
rm -f "$SOCK" "$CONF" "$LOG"

cleanup() {
    if [[ -n "$PID" ]] && kill -0 "$PID" 2>/dev/null; then
        kill "$PID" 2>/dev/null || true
        wait "$PID" 2>/dev/null || true
    fi
    rm -f "$SOCK"
}
trap cleanup EXIT

start_core() {
    local extra=("$@")
    XDG_RUNTIME_DIR="$XDG" TMPDIR="$ROOT/tmp" \
        "$CORE" --no-huge --no-pci --vdev=net_null0 --vdev=net_null1 -l 0-1 -m 512 \
        --file-prefix=tr-smoke -- --workers 1 --config "$CONF" \
        --ctl-sock "$SOCK" "${extra[@]}" >>"$LOG" 2>&1 &
    PID=$!
    for _ in $(seq 1 100); do
        [[ -S "$SOCK" ]] && return 0
        if ! kill -0 "$PID" 2>/dev/null; then
            cat "$LOG" >&2
            return 1
        fi
        sleep 0.05
    done
    echo "control socket did not appear" >&2
    cat "$LOG" >&2
    return 1
}

stop_core() {
    if [[ -n "$PID" ]] && kill -0 "$PID" 2>/dev/null; then
        kill "$PID"
        wait "$PID" 2>/dev/null || true
    fi
    PID=""
}

ctl() { "$CLI" --socket "$SOCK" "$@"; }

expect_contains() {
    local haystack="$1" needle="$2" what="$3"
    if [[ "$haystack" != *"$needle"* ]]; then
        echo "smoke: $what: expected '$needle'" >&2
        echo "$haystack" >&2
        exit 1
    fi
}

[[ -x "$CORE" && -x "$CLI" ]] || {
    echo "build first: make" >&2
    exit 1
}

start_core
ctl set interfaces ethernet eth0 mtu 9000 >/dev/null
ctl set interfaces ethernet eth0 address 192.0.2.1/24 >/dev/null
ctl set interfaces ethernet eth0 address 2001:db8:1::1/64 >/dev/null
ctl set interfaces ethernet eth0 vlan-id 10 address 192.168.10.1/24 >/dev/null
ctl set interfaces ethernet eth0.30 address 203.0.113.30/24 >/dev/null
ctl set interfaces ethernet eth0.30 address ipv6 autoconf >/dev/null
ctl set interfaces tunnel tun0 encapsulation etherip6 >/dev/null
ctl set interfaces tunnel tun0 remote 2001:db8:2::2 >/dev/null
ctl set interfaces tunnel tun0 local-address 2001:db8:2::1 >/dev/null
ctl set interfaces tunnel tun0 local-interface eth0 >/dev/null
ctl set interfaces tunnel tun0 mtu 9000 >/dev/null
ctl set interfaces tunnel tun0 tcp-mss auto >/dev/null
ctl set interfaces tunnel tun0 address 10.0.0.1/30 >/dev/null
ctl set interfaces ethernet eth0 vlan-id 20 >/dev/null
ctl set interfaces bridge br0 children eth0.20 >/dev/null
ctl set interfaces bridge br0 mtu 1400 >/dev/null
ctl set protocols static route 0.0.0.0/0 via 192.0.2.254 >/dev/null

show=$(ctl show interfaces)
expect_contains "$show" "192.0.2.1/24" "host address"
expect_contains "$show" "192.168.10.1/24" "VLAN address"
expect_contains "$show" "tcp-mss 0" "tunnel MSS"
expect_contains "$show" "eth0.30" "VLAN alias"
expect_contains "$show" "address ipv6 autoconf" "VLAN autoconf"

routes=$(ctl show routes)
expect_contains "$routes" "192.0.2.0/24" "connected IPv4 route"
expect_contains "$routes" "0.0.0.0/0" "default route"
all_routes=$(ctl show route)
expect_contains "$all_routes" "192.0.2.0/24" "show route all connected"
expect_contains "$all_routes" "0.0.0.0/0" "show route all default"
route_lookup=$(ctl show route 8.8.8.8)
expect_contains "$route_lookup" "Matched prefix: 0.0.0.0/0" "show route default"
expect_contains "$route_lookup" "Next-hop: 192.0.2.254" "show route next-hop"

conf=$(ctl show configuration)
expect_contains "$conf" "set interfaces tunnel tun0 remote 2001:db8:2::2" "configuration"
expect_contains "$conf" "set interfaces bridge br0 children eth0.20" "bridge child"

status=$(ctl show status)
expect_contains "$status" "workers 1" "status"

# Context-sensitive help.
help_root=$(ctl '?')
expect_contains "$help_root" "command help" "root help"
help_eth=$(ctl set interfaces ethernet eth1 '?')
expect_contains "$help_eth" "Ethernet eth1" "ethernet context help"
expect_contains "$help_eth" "vlan-id" "ethernet property help"
help_show=$(ctl show '?')
expect_contains "$help_show" "show configuration" "show help"

# A rejected command must return non-zero and leave the configuration intact.
if ctl set interfaces ethernet eth0 mtu 20 >/dev/null 2>&1; then
    echo "smoke: invalid MTU was accepted" >&2
    exit 1
fi
if grep -q 'mtu 20' "$CONF"; then
    echo "smoke: invalid command was persisted" >&2
    exit 1
fi

# Read mode must reject set/del.
if printf 'set interfaces ethernet eth0 mtu 1400\n' |
    "$CLI" --socket "$SOCK" --quiet >/dev/null 2>&1; then
    echo "smoke: read mode accepted set" >&2
    exit 1
fi
if ctl show interfaces | grep -q 'eth0 (ethernet, mtu 1400'; then
    echo "smoke: read-mode set changed the router" >&2
    exit 1
fi

# save without commit must be rejected and must not touch the data plane.
if printf 'configure\nset interfaces ethernet eth0 address 203.0.113.1/24\nsave\n' |
    "$CLI" --socket "$SOCK" --quiet >/dev/null 2>&1; then
    echo "smoke: save without commit succeeded" >&2
    exit 1
fi
if ctl show interfaces | grep -q '203.0.113.1/24'; then
    echo "smoke: uncommitted candidate was applied" >&2
    exit 1
fi

# Configuration mode: commit applies, save persists.
printf 'configure\nset interfaces ethernet eth0 address 203.0.113.1/24\ncommit\nsave\nread\n' |
    "$CLI" --socket "$SOCK" --quiet
ctl show interfaces | grep -q '203.0.113.1/24' || {
    echo "smoke: committed candidate was not applied" >&2
    exit 1
}

# Data-plane ping and the enhanced neighbor/MAC table.
ping_out=$(ctl ping 203.0.113.254 count 1 timeout 100)
expect_contains "$ping_out" "packets transmitted" "ping statistics"
neigh_out=$(ctl show neighbors)
expect_contains "$neigh_out" "MAC table (bridge forwarding)" "MAC table"

# commit reflects the running data plane but must not write the config file.
if printf 'configure\nset interfaces ethernet eth0 address 203.0.113.5/24\ncommit\n' |
    "$CLI" --socket "$SOCK" --quiet >/dev/null 2>&1; then
    echo "smoke: commit-only exit succeeded" >&2
    exit 1
fi
ctl show interfaces | grep -q '203.0.113.5/24' || {
    echo "smoke: commit did not reach running state" >&2
    exit 1
}
if grep -q '203.0.113.5/24' "$CONF"; then
    echo "smoke: commit wrote the configuration file" >&2
    exit 1
fi
printf 'configure\nsave\nexit\n' | "$CLI" --socket "$SOCK" --quiet
grep -q '203.0.113.5/24' "$CONF" || {
    echo "smoke: save did not persist running configuration" >&2
    exit 1
}

# Configuration mode: discard must not apply.
printf 'configure\nset interfaces ethernet eth0 address 203.0.113.2/24\ndiscard\nexit\n' |
    "$CLI" --socket "$SOCK" --quiet
if ctl show interfaces | grep -q '203.0.113.2/24'; then
    echo "smoke: discarded candidate was applied" >&2
    exit 1
fi

# Leaving configuration mode with uncommitted changes must fail.
if printf 'configure\nset interfaces ethernet eth0 address 203.0.113.3/24\nexit\n' |
    "$CLI" --socket "$SOCK" --quiet >/dev/null 2>&1; then
    echo "smoke: dirty candidate exit succeeded" >&2
    exit 1
fi
if ctl show interfaces | grep -q '203.0.113.3/24'; then
    echo "smoke: dirty candidate was applied" >&2
    exit 1
fi

# --file is one configure/commit/save transaction.
cat >"$RUN/smoke-batch.conf" <<'BATCH'
set interfaces ethernet eth0 address 203.0.113.4/24
BATCH
"$CLI" --socket "$SOCK" --quiet --file "$RUN/smoke-batch.conf"
ctl show interfaces | grep -q '203.0.113.4/24' || {
    echo "smoke: --file transaction did not apply" >&2
    exit 1
}

# tcpdump-style debug capture: net_null produces frames continuously, so a
# count-limited capture completes quickly.
CAP="$RUN/smoke-capture.pcap"
rm -f "$CAP"
ctl tcpdump -i eth0 -w "$CAP" -c 20 >/dev/null
for _ in $(seq 1 100); do
    cap_status=$(ctl tcpdump status)
    [[ "$cap_status" == *"packets: 20"* ]] && break
    sleep 0.05
done
expect_contains "$cap_status" "packets: 20" "capture packet count"
magic=$(od -An -tx1 -N4 "$CAP" | tr -d ' \n')
[[ "$magic" == "d4c3b2a1" ]] || {
    echo "smoke: capture file is not a little-endian pcap" >&2
    exit 1
}
ctl tcpdump stop >/dev/null

# Restart and verify persistence.
stop_core
start_core
restarted=$(ctl show tunnels)
expect_contains "$restarted" "tun0" "tunnel after restart"
expect_contains "$restarted" "state up" "tunnel state after restart"
stop_core

# Hot-add a logical Ethernet interface on a port that was initialized at
# startup but was previously unbound.
start_core
ctl delete interfaces ethernet eth1 >/dev/null
ctl set interfaces ethernet wan1 port 1 >/dev/null
ifaces=$(ctl show interfaces)
expect_contains "$ifaces" "wan1 (ethernet, mtu 1500" "hot-added ethernet"
stop_core

# An existing but Ethernet-less config file must still auto-assign all DPDK
# ports as eth0, eth1, ...
printf '# no interfaces configured yet\n' >"$CONF"
start_core
auto_ifaces=$(ctl show interfaces)
expect_contains "$auto_ifaces" "eth0 (ethernet" "automatic port 0 assignment"
expect_contains "$auto_ifaces" "eth1 (ethernet" "automatic port 1 assignment"
stop_core

# Load the Rust cdylib and confirm its two drivers are visible.
if [[ -f "$PLUGIN" ]]; then
    start_core --plugin "$PLUGIN"
    drivers=$(ctl show drivers)
    expect_contains "$drivers" "etherip6-rs" "Rust plugin driver"
    expect_contains "$drivers" "etherip-rs" "Rust plugin driver"
    # Select the plugin implementation for a tunnel.
    ctl set interfaces tunnel tun1 encapsulation etherip6-rs >/dev/null
    ctl set interfaces tunnel tun1 remote 2001:db8:9::2 >/dev/null
    ctl set interfaces tunnel tun1 local-address 2001:db8:9::1 >/dev/null
    ctl set interfaces tunnel tun1 local-interface eth0 >/dev/null
    plugin_show=$(ctl show tunnels)
    expect_contains "$plugin_show" "encap etherip6-rs" "plugin tunnel"
    stop_core
fi

echo "smoke: ok"
