.PHONY: frontend-install frontend-dev frontend-lint frontend-test backend-install backend-dev backend-test backend-e2e backend-export-schema

frontend-install:
	cd frontend && npm ci

frontend-dev:
	cd frontend && npm run dev

frontend-lint:
	cd frontend && npm run lint

frontend-test:
	cd frontend && npm run test

backend-install:
	python -m pip install -r backend/requirements.txt

backend-dev:
	uvicorn app.main:app --reload --port 8001 --app-dir backend

backend-test:
	cd backend && pytest -q

backend-e2e:
	cd backend && pytest -q tests/test_e2e_flow.py
