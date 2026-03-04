#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
# CloudScan — Start Development Servers
# Launches backend and frontend in parallel with colored output.
# Run: ./scripts/dev.sh
# ═══════════════════════════════════════════════════════════════════
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${CYAN}"
echo "   ☁  CloudScan — Development Servers"
echo -e "${NC}"

# Check if .env exists
if [ ! -f .env ]; then
    echo -e "${YELLOW}[!] No .env found. Run ./scripts/setup.sh first.${NC}"
    exit 1
fi

# Cleanup on exit
cleanup() {
    echo ""
    echo -e "${YELLOW}Shutting down...${NC}"
    kill 0 2>/dev/null
    exit
}
trap cleanup SIGINT SIGTERM EXIT

# Start backend
echo -e "${GREEN}[API]${NC} Starting backend on http://localhost:8000"
(
    cd "$ROOT_DIR"
    if [ -d "backend/venv" ]; then
        source backend/venv/bin/activate
    fi
    PYTHONPATH="$ROOT_DIR" python3 -m backend.app.main 2>&1 | sed "s/^/[API] /"
) &
BACKEND_PID=$!

# Wait for backend to be ready
echo -e "${GREEN}[API]${NC} Waiting for backend..."
for i in {1..30}; do
    if curl -s http://localhost:8000/api/v1/health > /dev/null 2>&1; then
        echo -e "${GREEN}[API]${NC} Backend ready!"
        break
    fi
    sleep 1
done

# Start frontend
echo -e "${GREEN}[UI]${NC}  Starting frontend on http://localhost:5173"
(
    cd "$ROOT_DIR/frontend"
    npm run dev 2>&1 | sed "s/^/[UI]  /"
) &
FRONTEND_PID=$!

echo ""
echo -e "${GREEN}═══════════════════════════════════════════════${NC}"
echo -e "  ${CYAN}Backend:${NC}  http://localhost:8000"
echo -e "  ${CYAN}Frontend:${NC} http://localhost:5173"
echo -e "  ${YELLOW}Press Ctrl+C to stop${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════${NC}"
echo ""

# Wait for both
wait
