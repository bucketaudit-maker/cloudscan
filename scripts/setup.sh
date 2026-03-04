#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
# CloudScan — Local Development Setup
# Run: ./scripts/setup.sh
# ═══════════════════════════════════════════════════════════════════
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[✗]${NC} $1"; exit 1; }
step() { echo -e "\n${CYAN}═══ $1 ═══${NC}"; }

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

echo -e "${CYAN}"
echo "   ☁  CloudScan — Setup"
echo -e "${NC}"

# ── Preflight ──────────────────────────────────────────────────
step "Checking prerequisites"

command -v python3 >/dev/null 2>&1 || err "Python 3.11+ required. Install: https://python.org"
PYVER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
log "Python $PYVER found"

command -v node >/dev/null 2>&1 || err "Node.js 18+ required. Install: https://nodejs.org"
NVER=$(node -v)
log "Node $NVER found"

command -v npm >/dev/null 2>&1 || err "npm required"
log "npm $(npm -v) found"

# ── Environment ────────────────────────────────────────────────
step "Setting up environment"

if [ ! -f .env ]; then
    cp .env.example .env
    # Generate a real secret key
    SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    if [[ "$OSTYPE" == "darwin"* ]]; then
        sed -i '' "s/change-me-to-a-random-64-char-string/$SECRET/" .env
    else
        sed -i "s/change-me-to-a-random-64-char-string/$SECRET/" .env
    fi
    log "Created .env with generated SECRET_KEY"
else
    log ".env already exists, skipping"
fi

# ── Backend ────────────────────────────────────────────────────
step "Setting up backend"

cd "$ROOT_DIR/backend"

if [ ! -d "venv" ]; then
    python3 -m venv venv
    log "Created Python virtual environment"
else
    log "Virtual environment already exists"
fi

source venv/bin/activate
pip install -r requirements.txt --quiet
log "Installed Python dependencies"

cd "$ROOT_DIR"

# Initialize DB and seed
PYTHONPATH="$ROOT_DIR" python3 -m backend.app.seed
log "Database initialized and seeded"

# ── Frontend ───────────────────────────────────────────────────
step "Setting up frontend"

cd "$ROOT_DIR/frontend"

if [ ! -d "node_modules" ]; then
    npm install --silent
    log "Installed Node.js dependencies"
else
    log "node_modules already exists, skipping npm install"
fi

# ── Done ───────────────────────────────────────────────────────
cd "$ROOT_DIR"

echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Setup complete!${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
echo ""
echo "  Start the backend (Terminal 1):"
echo -e "    ${CYAN}cd backend && source venv/bin/activate && cd .. && python -m backend.app.main${NC}"
echo ""
echo "  Start the frontend (Terminal 2):"
echo -e "    ${CYAN}cd frontend && npm run dev${NC}"
echo ""
echo "  Open in browser:"
echo -e "    ${CYAN}http://localhost:5173${NC}"
echo ""
echo "  Demo credentials:"
echo -e "    Email:    ${YELLOW}demo@cloudscan.io${NC}"
echo -e "    Password: ${YELLOW}demo1234${NC}"
echo -e "    API Key:  ${YELLOW}cs_demo_key_for_testing_purposes_only${NC}"
echo ""
