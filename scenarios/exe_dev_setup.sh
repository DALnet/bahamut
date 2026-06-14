#!/usr/bin/env bash
# exe_dev_setup.sh — Provision an exe.dev VM, build bahamut, run topology tests.
#
# Usage (from your local machine):
#
#   # Create VM:
#   ssh exe.dev new bahamut-test
#
#   # Copy this repo:
#   scp -r . bahamut-test:~/bahamut/
#
#   # Run this script inside the VM:
#   ssh bahamut-test bash ~/bahamut/scenarios/exe_dev_setup.sh
#
#   # When done, delete the VM:
#   ssh exe.dev rm bahamut-test
#
# Or run locally (no VM needed):
#   bash scenarios/exe_dev_setup.sh
#
set -euo pipefail

REPO_DIR="${REPO_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"
cd "$REPO_DIR"

# ---------------------------------------------------------------------------
# 1. Install system dependencies (skip if already present)
# ---------------------------------------------------------------------------
install_deps() {
    if command -v meson &>/dev/null && command -v ninja &>/dev/null && command -v gcc &>/dev/null; then
        echo "[deps] Build tools already installed, skipping."
        return
    fi
    echo "[deps] Installing build dependencies..."
    if command -v apt-get &>/dev/null; then
        sudo apt-get update -qq
        sudo apt-get install -y -qq \
            gcc make autoconf automake libtool \
            meson ninja-build pkg-config \
            libssl-dev zlib1g-dev \
            python3 python3-pip python3-venv \
            git openssl
    elif command -v dnf &>/dev/null; then
        sudo dnf install -y \
            gcc make autoconf automake libtool \
            meson ninja-build pkg-config \
            openssl-devel zlib-devel \
            python3 python3-pip \
            git openssl
    else
        echo "[deps] ERROR: Unsupported package manager. Install manually:"
        echo "  gcc, make, autoconf, automake, libtool, meson, ninja, libssl-dev, zlib1g-dev, python3, pip"
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# 2. Build new bahamut (bahamut-mods-gossip)
# ---------------------------------------------------------------------------
build_new() {
    echo "[build-new] Building new bahamut..."
    if [ ! -d "build" ]; then
        meson setup build -Dhookmodules=true
    fi
    ninja -C build
    echo "[build-new] Done. Binary: build/src/ircd"
}

# ---------------------------------------------------------------------------
# 3. Build old bahamut (master branch) for Scenario B
# ---------------------------------------------------------------------------
build_old() {
    local OLD_BIN="build-master/src/ircd"
    if [ -f "$OLD_BIN" ]; then
        echo "[build-old] Old binary already exists at $OLD_BIN, skipping."
        return
    fi

    echo "[build-old] Building old bahamut from master branch..."
    local WORKTREE_DIR
    WORKTREE_DIR=$(mktemp -d)

    git worktree add "$WORKTREE_DIR" master 2>/dev/null || {
        echo "[build-old] WARNING: Could not create worktree for master branch."
        echo "[build-old] Scenario B will be skipped."
        return
    }

    (
        cd "$WORKTREE_DIR"
        # Old bahamut uses autotools
        if [ -f configure ]; then
            ./configure
        elif [ -f configure.in ]; then
            autoreconf -vfi
            ./configure
        else
            echo "[build-old] ERROR: No configure script found in master branch."
            exit 1
        fi
        make -j"$(nproc)" 2>/dev/null || make
    )

    mkdir -p build-master/src
    cp "$WORKTREE_DIR/src/ircd" "$OLD_BIN"
    chmod +x "$OLD_BIN"

    git worktree remove "$WORKTREE_DIR" --force 2>/dev/null || rm -rf "$WORKTREE_DIR"
    echo "[build-old] Done. Binary: $OLD_BIN"
}

# ---------------------------------------------------------------------------
# 4. Install Python test deps
# ---------------------------------------------------------------------------
install_pytest() {
    if python3 -c "import pytest" 2>/dev/null; then
        echo "[pytest] Already installed."
        return
    fi
    echo "[pytest] Installing pytest..."
    pip3 install --user pytest 2>/dev/null || pip3 install pytest
}

# ---------------------------------------------------------------------------
# 5. Run scenarios
# ---------------------------------------------------------------------------
run_scenarios() {
    local rc=0

    echo ""
    echo "============================================================"
    echo "  Running Scenario A: All-gossip cluster (2 hubs + 2 leafs)"
    echo "============================================================"
    if python3 scenarios/scenario_a_gossip_cluster.py; then
        echo "[scenario-a] PASSED"
    else
        echo "[scenario-a] FAILED"
        rc=1
    fi

    echo ""
    echo "============================================================"
    echo "  Running Scenario B: Mixed old+new cluster (TS5 bridge)"
    echo "============================================================"
    if [ -f "build-master/src/ircd" ]; then
        if python3 scenarios/scenario_b_mixed_cluster.py --old-binary build-master/src/ircd; then
            echo "[scenario-b] PASSED"
        else
            echo "[scenario-b] FAILED"
            rc=1
        fi
    else
        echo "[scenario-b] SKIPPED (old binary not available)"
    fi

    return $rc
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    echo "=== Bahamut Topology Test Setup ==="
    echo "Repo: $REPO_DIR"
    echo ""

    install_deps
    build_new
    build_old
    install_pytest

    echo ""
    run_scenarios
    local rc=$?

    echo ""
    if [ $rc -eq 0 ]; then
        echo "All scenarios passed!"
    else
        echo "Some scenarios failed (exit code $rc)"
    fi

    echo ""
    echo "To delete the exe.dev VM when done:"
    echo "  ssh exe.dev rm bahamut-test"

    exit $rc
}

main "$@"
