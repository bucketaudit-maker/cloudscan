#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
# CloudScan — Database Management
#
# Usage:
#   ./scripts/db.sh init          Initialize fresh database
#   ./scripts/db.sh seed          Seed demo data
#   ./scripts/db.sh reset         Drop and recreate (WARNING: destroys data)
#   ./scripts/db.sh stats         Show database statistics
#   ./scripts/db.sh backup        Create a timestamped backup
# ═══════════════════════════════════════════════════════════════════
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

DB_PATH="${ROOT_DIR}/backend/data/cloudscan.db"

if [ -d "backend/venv" ]; then
    source backend/venv/bin/activate
fi

case "${1:-help}" in
    init)
        echo -e "${GREEN}Initializing database...${NC}"
        PYTHONPATH="$ROOT_DIR" python3 -c "
from backend.app.models.database import init_db
path = init_db()
print(f'Database initialized at {path}')
"
        ;;

    seed)
        echo -e "${GREEN}Seeding demo data...${NC}"
        PYTHONPATH="$ROOT_DIR" python3 -m backend.app.seed
        ;;

    reset)
        echo -e "${RED}WARNING: This will destroy all data!${NC}"
        read -p "Type 'yes' to confirm: " confirm
        if [ "$confirm" = "yes" ]; then
            rm -f "$DB_PATH"
            echo "Database deleted."
            PYTHONPATH="$ROOT_DIR" python3 -c "
from backend.app.models.database import init_db
init_db()
print('Fresh database created.')
"
            echo -e "${GREEN}Database reset complete.${NC}"
        else
            echo "Cancelled."
        fi
        ;;

    stats)
        if [ ! -f "$DB_PATH" ]; then
            echo -e "${YELLOW}No database found. Run: $0 init${NC}"
            exit 1
        fi
        PYTHONPATH="$ROOT_DIR" python3 -c "
from backend.app.models.database import init_db, FileStore
init_db()
s = FileStore.get_stats()
print(f'''
CloudScan Database Statistics
{'═' * 40}
  Files:        {s['total_files']:>10,}
  Buckets:      {s['total_buckets']:>10,}
  Open buckets: {s['open_buckets']:>10,}
  Total size:   {s['total_size_bytes']:>10,} bytes

  Providers:''')
for p in s['providers']:
    print(f\"    {p['display_name']:<25} {p['bucket_count']:>5} buckets  {p['file_count']:>8} files\")
print(f'''
  Top extensions:''')
for e in s['top_extensions'][:10]:
    print(f\"    .{e['extension']:<10} {e['count']:>8,} files\")
"
        ;;

    backup)
        if [ ! -f "$DB_PATH" ]; then
            echo -e "${YELLOW}No database found.${NC}"
            exit 1
        fi
        BACKUP_DIR="${ROOT_DIR}/backend/data/backups"
        mkdir -p "$BACKUP_DIR"
        TIMESTAMP=$(date +%Y%m%d_%H%M%S)
        BACKUP_PATH="${BACKUP_DIR}/cloudscan_${TIMESTAMP}.db"
        cp "$DB_PATH" "$BACKUP_PATH"
        echo -e "${GREEN}Backup created: ${BACKUP_PATH}${NC}"
        echo "Size: $(du -h "$BACKUP_PATH" | cut -f1)"
        ;;

    help|*)
        echo "CloudScan Database Management"
        echo ""
        echo "Usage: $0 <command>"
        echo ""
        echo "Commands:"
        echo "  init     Initialize fresh database with schema"
        echo "  seed     Seed demo data (buckets + files + demo user)"
        echo "  reset    Drop and recreate database (destroys all data)"
        echo "  stats    Show database statistics"
        echo "  backup   Create a timestamped backup"
        ;;
esac
