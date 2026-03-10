# Testlogon dev stack — run `just` to see available commands.
# Install: curl -fsSL https://just.systems/install.sh | bash -s -- --to /usr/local/bin

# Show available commands
default:
    @just --list

# ── First-time setup ──────────────────────────────────────────────────────────

# Install all dependencies and generate secrets (run once after cloning)
setup *args:
    bash scripts/setup_ubuntu.sh {{args}}

# ── Dev stack ─────────────────────────────────────────────────────────────────

# Start the dev stack and seed E2E sessions (use this instead of `start` normally)
up *args:
    scripts/dev.sh start {{args}}
    python3 e2e_session_setup.py
    python3 e2e_admin_session_setup.py

# Start the dev stack only (no E2E session seeding)
start *args:
    scripts/dev.sh start {{args}}

# Stop the dev stack
stop:
    scripts/dev.sh stop

# Restart the dev stack and re-seed E2E sessions
restart *args:
    scripts/dev.sh restart {{args}}
    python3 e2e_session_setup.py
    python3 e2e_admin_session_setup.py

# Show health of all dev services
status:
    scripts/dev.sh status

# ── Tests ─────────────────────────────────────────────────────────────────────

# Run all E2E tests
e2e *args:
    cd frontend && npx playwright test {{args}}

# Run backend unit tests
test *args:
    .venv/bin/pytest {{args}}

# Run a quick smoke test against the running stack
smoke:
    python3 smoke_test.py

# ── Logs ──────────────────────────────────────────────────────────────────────

# Tail backend log (Ctrl-C to exit)
logs-backend:
    tail -f .logs/dev/backend.log

# Tail frontend log (Ctrl-C to exit)
logs-frontend:
    tail -f .logs/dev/frontend.log
