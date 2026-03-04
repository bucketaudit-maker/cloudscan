.PHONY: help install dev seed scan test docker-up docker-down clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-18s\033[0m %s\n", $$1, $$2}'

# ── Development ──────────────────────────────────────────────

install: ## Install all dependencies
	cd backend && pip install -r requirements.txt
	cd frontend && npm install

dev-backend: ## Start backend dev server
	cd backend && python -m backend.app.main

dev-frontend: ## Start frontend dev server
	cd frontend && npm run dev

dev: ## Start both backend and frontend (requires 2 terminals)
	@echo "Terminal 1: make dev-backend"
	@echo "Terminal 2: make dev-frontend"
	@echo ""
	@echo "Or use: make dev-backend & make dev-frontend"

seed: ## Seed database with demo data
	python -m backend.app.seed

scan: ## Run a discovery scan (use KEYWORDS="backup,secret" COMPANIES="acme")
	python -m backend.app.scanners.engine -k $(shell echo $(KEYWORDS) | tr ',' ' ') \
		$(if $(COMPANIES),-c $(shell echo $(COMPANIES) | tr ',' ' '),) \
		$(if $(PROVIDERS),-p $(shell echo $(PROVIDERS) | tr ',' ' '),) \
		-n $(or $(MAX_NAMES),500)

# ── Testing ──────────────────────────────────────────────────

test: ## Run backend tests
	cd backend && python -m pytest tests/ -v

# ── Docker ───────────────────────────────────────────────────

docker-up: ## Start all services with Docker Compose
	docker compose up -d --build

docker-down: ## Stop all services
	docker compose down

docker-logs: ## View logs
	docker compose logs -f

# ── Maintenance ──────────────────────────────────────────────

clean: ## Remove generated files
	rm -rf backend/data/ frontend/dist/ frontend/node_modules/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
