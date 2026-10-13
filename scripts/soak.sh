#!/bin/sh
# 24h soak test with leak detection.
# Usage: scripts/soak.sh [duration_secs]   (default: 86400 = 24h)
set -e
cd "$(dirname "$0")/.."
DURATION="${1:-86400}"
echo "Building release soak harness..."
cargo build --release --example soak_load
echo "Starting ${DURATION}s soak at $(date) ..."
./target/release/examples/soak_load "$DURATION"
echo "Soak finished at $(date)"
