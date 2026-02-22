#!/usr/bin/env bash
# =============================================================
# Local Elements Node Recovery Launcher
# =============================================================
# Syncs Liquid blockchain locally, then brute-forces using RPC.
# No API rate limits — thousands of checks per second.
#
# Usage:
#   ./run-local.sh              # Liquid testnet (default)
#   ./run-local.sh mainnet      # Liquid mainnet
# =============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

MODE="${1:-testnet}"

# Check for .env
if [ ! -f .env ]; then
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  No .env file found. Creating from template..."
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    cp .env.example .env
    echo "  Edit .env and set your KNOWN_WORDS, then re-run."
    exit 1
fi

# Parse KNOWN_WORDS safely
KNOWN_WORDS="$(grep -E '^KNOWN_WORDS=' .env | head -1 | sed 's/^KNOWN_WORDS=//' | sed 's/^"//' | sed 's/"$//' | xargs)"

if [ -z "${KNOWN_WORDS:-}" ] || [ "$KNOWN_WORDS" = "word1 word2 word3 word4 word5 word6 word7 word8 word9 word10" ]; then
    echo "ERROR: KNOWN_WORDS not set in .env"
    exit 1
fi

# Set chain based on mode
if [ "$MODE" = "mainnet" ]; then
    CHAIN="liquidv1"
    NETWORKS="liquid"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  BIP39 Recovery — LIQUID MAINNET (local node)"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
else
    CHAIN="liquidtestnet"
    NETWORKS="liquid_testnet"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  BIP39 Recovery — LIQUID TESTNET (local node)"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
fi

echo "  Mode:        Local Elements node (no API rate limits)"
echo "  Chain:       $CHAIN"
echo "  Networks:    $NETWORKS"
echo ""
echo "  The node will sync first. This may take a few minutes"
echo "  for testnet or ~10-30 min for mainnet on first run."
echo "  Subsequent runs use cached chain data."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Export for docker-compose variable substitution
export ELEMENTS_CHAIN="$CHAIN"
export NETWORKS="$NETWORKS"
export CHECK_MODE="rpc"

docker compose -f docker-compose.local.yml up --build

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Done. Check ./output/ for results."
echo "  Look for found_wallets.json"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
