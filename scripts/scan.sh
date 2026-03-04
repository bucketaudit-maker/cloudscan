#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
# CloudScan — Run a Discovery Scan
#
# Usage:
#   ./scripts/scan.sh -k "backup,credentials,secret" -c "acme-corp" -p "aws,gcp"
#   ./scripts/scan.sh --keywords "database,config" --max-names 2000
# ═══════════════════════════════════════════════════════════════════
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

# Parse args
KEYWORDS=""
COMPANIES=""
PROVIDERS=""
MAX_NAMES=500

while [[ $# -gt 0 ]]; do
    case $1 in
        -k|--keywords)  KEYWORDS="$2"; shift 2;;
        -c|--companies) COMPANIES="$2"; shift 2;;
        -p|--providers) PROVIDERS="$2"; shift 2;;
        -n|--max-names) MAX_NAMES="$2"; shift 2;;
        -h|--help)
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  -k, --keywords    Comma-separated keywords (required)"
            echo "  -c, --companies   Comma-separated company names"
            echo "  -p, --providers   Comma-separated providers (aws,azure,gcp,digitalocean,alibaba)"
            echo "  -n, --max-names   Maximum bucket names to generate (default: 500)"
            echo ""
            echo "Examples:"
            echo "  $0 -k 'backup,secret,credentials'"
            echo "  $0 -k 'database' -c 'acme-corp' -p 'aws,gcp' -n 2000"
            exit 0;;
        *) echo "Unknown option: $1. Use -h for help."; exit 1;;
    esac
done

if [ -z "$KEYWORDS" ] && [ -z "$COMPANIES" ]; then
    echo "Error: At least --keywords or --companies required. Use -h for help."
    exit 1
fi

# Activate venv if exists
if [ -d "backend/venv" ]; then
    source backend/venv/bin/activate
fi

echo "☁  CloudScan — Discovery Scan"
echo ""
echo "  Keywords:   ${KEYWORDS:-none}"
echo "  Companies:  ${COMPANIES:-none}"
echo "  Providers:  ${PROVIDERS:-all}"
echo "  Max names:  $MAX_NAMES"
echo ""

# Build CLI args
CMD="PYTHONPATH=$ROOT_DIR python3 -m backend.app.scanners.engine"
[ -n "$KEYWORDS" ]  && CMD="$CMD -k $(echo $KEYWORDS | tr ',' ' ')"
[ -n "$COMPANIES" ] && CMD="$CMD -c $(echo $COMPANIES | tr ',' ' ')"
[ -n "$PROVIDERS" ] && CMD="$CMD -p $(echo $PROVIDERS | tr ',' ' ')"
CMD="$CMD -n $MAX_NAMES"

echo "Running: $CMD"
echo ""
eval "$CMD"
