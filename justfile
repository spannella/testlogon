# Testlogon dev stack — run `just` to see available commands.
# Install just: https://github.com/casey/just

# Show available commands
default:
    @just --list

# ── Dev stack ────────────────────────────────────────────────────────────────

# Dev stack control: just dev [start|stop|restart|status] [--no-clean]
dev *args:
    scripts/dev.sh {{if args == "" { "start" } else { args }}}

# Alias: just start [--no-clean]
start *args:
    scripts/dev.sh start {{args}}

# Stop the dev stack
stop:
    scripts/dev.sh stop

# Restart the dev stack
restart *args:
    scripts/dev.sh restart {{args}}

# Show health of all dev services
status:
    scripts/dev.sh status

# ── Logs ─────────────────────────────────────────────────────────────────────

# Tail backend log (Ctrl-C to exit)
logs-backend:
    tail -f .logs/dev/backend.log

# Tail frontend log (Ctrl-C to exit)
logs-frontend:
    tail -f .logs/dev/frontend.log

# ── Tests ────────────────────────────────────────────────────────────────────

# Run backend tests
test *args:
    .venv/bin/pytest {{args}}

# Run a quick smoke test against the running stack
smoke:
    python3 smoke_test.py
