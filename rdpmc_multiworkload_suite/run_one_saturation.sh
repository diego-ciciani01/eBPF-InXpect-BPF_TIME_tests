#!/usr/bin/env bash
set -euo pipefail
WORKLOAD="${1:?Usage: $0 drop|nat|routing|tunnel [repo-root]}"
ROOT="${2:-$(pwd)}"
SUITE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
case "$WORKLOAD" in drop|nat|routing|tunnel) ;; *) echo "bad workload" >&2; exit 2;; esac
exec "$SUITE_DIR/run_saturation_suite.sh" "$ROOT" "$WORKLOAD"
