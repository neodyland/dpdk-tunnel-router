#!/usr/bin/env bash
# Locate a Rust toolchain without assuming it is on PATH.
#
# Set CARGO_REAL=/path/to/cargo to force a toolchain.  CARGO_HOME and the
# target directory stay inside the repository so builds work in sandboxes
# where $HOME is read-only.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
export CARGO_HOME=${CARGO_HOME:-$ROOT/.cargo-home}
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-$ROOT/build/rust}
export CARGO_NET_OFFLINE=${CARGO_NET_OFFLINE:-true}

find_cargo() {
    if [[ -n "${CARGO_REAL:-}" && -x "$CARGO_REAL" ]]; then
        printf '%s\n' "$CARGO_REAL"; return 0
    fi
    if command -v cargo >/dev/null 2>&1; then
        command -v cargo; return 0
    fi
    local candidates=(
        "$HOME/.cargo/bin/cargo"
        /usr/local/cargo/bin/cargo
        /opt/rust/bin/cargo
    )
    local c
    for c in "${candidates[@]}"; do
        [[ -x "$c" ]] && { printf '%s\n' "$c"; return 0; }
    done
    # A toolchain unpacked by rustup in a neighbouring project (seen in
    # appliance-style build images).
    c=$(find "$HOME" /opt /usr/local -maxdepth 7 -type f -path '*/bin/cargo' 2>/dev/null | head -n1 || true)
    if [[ -n "$c" ]]; then printf '%s\n' "$c"; return 0; fi
    return 1
}

CARGO_BIN=$(find_cargo) || {
    cat >&2 <<'EOF'
error: cargo was not found.

Install Rust (https://rustup.rs) or point CARGO_REAL at a cargo binary:

    CARGO_REAL=/path/to/cargo make
EOF
    exit 1
}

# Cargo invokes rustc from PATH in several situations; keep the sibling
# rustc reachable when using an unpacked toolchain.
export PATH="$(dirname "$CARGO_BIN"):$PATH"
export RUSTC=${RUSTC:-$(dirname "$CARGO_BIN")/rustc}
cd "$ROOT/rust"
unset MAKEFLAGS MFLAGS
exec "$CARGO_BIN" "$@"
