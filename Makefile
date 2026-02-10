.PHONY: help demo test lint clean

help:
	@echo "SignalForge - Security Detection Platform"
	@echo ""
	@echo "Available commands:"
	@echo "  make demo        - Generate demo logs, start services, and ingest data"
	@echo "  make test        - Run pytest with coverage"
	@echo "  make lint        - Run ruff linting"
	@echo "  make format      - Format code with ruff"
	@echo "  make clean       - Remove database and generated files"
	@echo "  make frontend    - Install frontend dependencies"
	@echo "  make backend     - Install backend dependencies"

demo:
	@echo "🔨 Generating demo logs..."
	python examples/generators/generate_demo_logs.py
	@echo ""
	@echo "✅ Demo logs generated!"
	@echo ""
	@echo "📝 Next steps:"
	@echo "  1. Start backend: make run-backend"
	@echo "  2. In another terminal, start frontend: make run-frontend"
	@echo "  3. Ingest logs: make ingest-demo"
	@echo "  4. Run detections: make detect"
	@echo "  5. Open http://localhost:3000"

run-backend:
	uvicorn backend.app.main:app --reload

run-frontend:
	cd frontend && npm run dev

ingest-demo:
	@echo "📥 Ingesting demo logs..."
	curl -X POST http://localhost:8000/api/v1/ingest \
		-H "Content-Type: application/x-ndjson" \
		--data-binary @examples/sample_logs/demo_logs.jsonl
	@echo ""
	@echo "✅ Logs ingested!"

detect:
	@echo "🔍 Running detections..."
	curl -X POST http://localhost:8000/api/v1/detections/run
	@echo ""
	@echo "✅ Detections complete!"

test:
	pytest backend/tests/ -v --cov=backend/app --cov-report=term-missing

lint:
	ruff check backend/

format:
	ruff format backend/

clean:
	@echo "🧹 Cleaning up..."
	rm -f signalforge.db
	rm -f examples/sample_logs/demo_logs.jsonl
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	@echo "✅ Cleanup complete!"

frontend:
	cd frontend && npm install

backend:
	pip install -e ".[dev]"

all: backend frontend demo
	@echo "✅ All setup complete!"
	@echo ""
	@echo "Run 'make run-backend' and 'make run-frontend' to start services"
