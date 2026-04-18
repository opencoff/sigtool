#!/usr/bin/env bash
#
# run-fuzz.sh -- run every FuzzXxx target in this package sequentially.
#
# Usage:
#   ./run-fuzz.sh                 # default 30s per fuzzer
#   FUZZTIME=5m ./run-fuzz.sh     # override per-fuzzer duration
#   FUZZTIME=1h ./run-fuzz.sh     # long soak
#
# Go's -fuzz flag accepts only one target per invocation, so we enumerate
# them and loop. Any discovered crash is written under testdata/fuzz/<name>/
# and the script aborts on first failure.

set -euo pipefail

FUZZTIME="${FUZZTIME:-30s}"

cd "$(dirname "$0")"

fuzzers=$(go test -list='^Fuzz' . | grep ^Fuzz || true)
if [ -z "$fuzzers" ]; then
    echo "no fuzz targets found" >&2
    exit 1
fi

echo "running fuzzers ($FUZZTIME each):"
echo "$fuzzers" | sed 's/^/  - /'
echo

for f in $fuzzers; do
    echo "=== $f ==="
    go test -run=xxx -fuzz="^${f}\$" -fuzztime="$FUZZTIME" .
done
