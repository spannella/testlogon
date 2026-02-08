#!/usr/bin/env bash
# =============================================================================
# start.sh — Launch backend + frontend for local development
# Usage:  ./start.sh          (both servers)
#         ./start.sh backend  (backend only)
#         ./start.sh frontend (frontend only)
#         ./start.sh stop     (kill both)
# =============================================================================
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

log()  { echo -e "${GREEN}[start]${NC} $*"; }
warn() { echo -e "${YELLOW}[start]${NC} $*"; }
err()  { echo -e "${RED}[start]${NC} $*" >&2; }

BACKEND_PORT=8000
FRONTEND_PORT=3000
BACKEND_PID_FILE="$ROOT/.backend.pid"
FRONTEND_PID_FILE="$ROOT/.frontend.pid"
BACKEND_LOG="$ROOT/logs/backend.log"
FRONTEND_LOG="$ROOT/logs/frontend.log"

mkdir -p "$ROOT/logs"

# ---------------------------------------------------------------------------
# Load .env if present
# ---------------------------------------------------------------------------
if [ -f "$ROOT/.env" ]; then
    log "Loading .env"
    set -a; source "$ROOT/.env"; set +a
else
    warn "No .env file found — using defaults (DEV_MODE=1)"
    export DEV_MODE=1
fi

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
kill_pid_file() {
    local pf="$1" name="$2"
    if [ -f "$pf" ]; then
        local pid; pid=$(cat "$pf")
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null && log "Stopped $name (PID $pid)" || true
            sleep 1
            kill -0 "$pid" 2>/dev/null && kill -9 "$pid" 2>/dev/null || true
        fi
        rm -f "$pf"
    fi
}

wait_for_port() {
    local port="$1" name="$2" max=30 i=0
    while ! curl -s -o /dev/null "http://localhost:$port" 2>/dev/null; do
        i=$((i + 1))
        if [ "$i" -ge "$max" ]; then
            err "$name did not start within ${max}s — check $3"
            return 1
        fi
        sleep 1
    done
    log "$name is ready on http://localhost:$port"
}

# ---------------------------------------------------------------------------
# Stop
# ---------------------------------------------------------------------------
do_stop() {
    kill_pid_file "$BACKEND_PID_FILE" "backend"
    kill_pid_file "$FRONTEND_PID_FILE" "frontend"
    # Also clean up any orphan processes on the ports
    lsof -ti ":$BACKEND_PORT" 2>/dev/null | xargs -r kill 2>/dev/null || true
    lsof -ti ":$FRONTEND_PORT" 2>/dev/null | xargs -r kill 2>/dev/null || true
    log "All servers stopped"
}

# ---------------------------------------------------------------------------
# Backend
# ---------------------------------------------------------------------------
start_backend() {
    kill_pid_file "$BACKEND_PID_FILE" "old backend"

    log "Checking Python dependencies..."
    if ! python -c "import fastapi" 2>/dev/null; then
        log "Installing Python dependencies..."
        pip install --ignore-installed -r "$ROOT/requirements.txt" -q
    fi

    log "Verifying backend loads..."
    if ! python -c "from app.main import create_app; create_app()" 2>/dev/null; then
        err "Backend failed to load — check Python errors above"
        return 1
    fi

    log "Starting backend on :$BACKEND_PORT..."
    nohup uvicorn app.main:create_app \
        --host 0.0.0.0 \
        --port "$BACKEND_PORT" \
        --factory \
        --reload \
        > "$BACKEND_LOG" 2>&1 &
    echo $! > "$BACKEND_PID_FILE"

    wait_for_port "$BACKEND_PORT" "Backend" "$BACKEND_LOG"
}

# ---------------------------------------------------------------------------
# Frontend
# ---------------------------------------------------------------------------
start_frontend() {
    kill_pid_file "$FRONTEND_PID_FILE" "old frontend"

    if [ ! -d "$ROOT/frontend/node_modules" ]; then
        log "Installing frontend dependencies..."
        (cd "$ROOT/frontend" && npm install)
    fi

    log "Starting frontend on :$FRONTEND_PORT..."
    nohup npx --prefix "$ROOT/frontend" vite \
        --host 0.0.0.0 \
        --port "$FRONTEND_PORT" \
        > "$FRONTEND_LOG" 2>&1 &
    echo $! > "$FRONTEND_PID_FILE"

    wait_for_port "$FRONTEND_PORT" "Frontend" "$FRONTEND_LOG"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
MODE="${1:-all}"

case "$MODE" in
    stop)
        do_stop
        ;;
    backend)
        start_backend
        log "Backend log: tail -f $BACKEND_LOG"
        ;;
    frontend)
        start_frontend
        log "Frontend log: tail -f $FRONTEND_LOG"
        ;;
    all|"")
        log "=== Starting development servers ==="
        start_backend
        start_frontend
        echo ""
        log "=== All servers running ==="
        log "  Backend:  http://localhost:$BACKEND_PORT  (API docs: http://localhost:$BACKEND_PORT/docs)"
        log "  Frontend: http://localhost:$FRONTEND_PORT"
        log ""
        log "  Backend log:  tail -f $BACKEND_LOG"
        log "  Frontend log: tail -f $FRONTEND_LOG"
        log "  Stop all:     ./start.sh stop"
        ;;
    *)
        echo "Usage: ./start.sh [all|backend|frontend|stop]"
        exit 1
        ;;
esac
