#!/usr/bin/env bash
# Run the Python test suite against its own temporary database.
#
#   scripts/run_tests.sh [pytest arguments]      e.g. scripts/run_tests.sh -q
#
# Starts a test API server on 127.0.0.1:8000 (the address the integration
# tests use), with FLOP_DATABASE_URL pointing at a database in a temporary
# directory, runs pytest with the same environment, and removes the server and
# the directory on exit, Ctrl+C or termination. The repository's proofs.db is
# never opened.
#
# FLOP_TEST_LOG_DIR: directory for the server log (flop-uvicorn.log); default
# is the temporary directory, which is removed on exit.
# PYTHON: interpreter to use; default "python".

set -u

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${PYTHON:-python}"
HOST=127.0.0.1
PORT=8000

# Pre-check: the tests talk to 127.0.0.1:8000 directly. A server already
# listening there (e.g. a development server on the real proofs.db) would
# receive the test traffic, so refuse to run.
if (exec 3<>"/dev/tcp/$HOST/$PORT") 2>/dev/null; then
    echo "run_tests.sh: $HOST:$PORT is already in use." >&2
    echo "The tests send requests to $HOST:$PORT; a server already running there" >&2
    echo "(for example a development server using proofs.db) would get the test" >&2
    echo "writes. Stop it and run again." >&2
    exit 2
fi

TMP="$(mktemp -d "${TMPDIR:-/tmp}/flop-tests.XXXXXX")"
LOG_DIR="${FLOP_TEST_LOG_DIR:-$TMP}"
LOG="$LOG_DIR/flop-uvicorn.log"
SERVER_PID=""

cleanup() {
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID" 2>/dev/null
        wait "$SERVER_PID" 2>/dev/null
    fi
    SERVER_PID=""
    rm -rf "$TMP"
}
trap cleanup EXIT
trap 'echo "run_tests.sh: interrupted" >&2; exit 130' INT
trap 'echo "run_tests.sh: terminated" >&2; exit 143' TERM

mkdir -p "$LOG_DIR"
cd "$REPO_ROOT" || exit 1

# Server and pytest must see the same values.
export FLOP_DATABASE_URL="sqlite:///$TMP/test.db"
export FLOP_API_KEY=flop-test-key-2026
export FLOP_RATE_LIMIT_ENABLED=false

"$PYTHON" - <<'PY' || exit 1
import os

from app.database import DATABASE_URL

assert DATABASE_URL == os.environ["FLOP_DATABASE_URL"], DATABASE_URL
print(f"run_tests.sh: test database {DATABASE_URL}")
PY

# The schema comes from the migrations, as for any other database
# (test_migrations.py checks that it equals app/models.py).
"$PYTHON" -m alembic upgrade head > "$LOG_DIR/alembic.log" 2>&1 || {
    echo "run_tests.sh: alembic upgrade head failed:" >&2
    cat "$LOG_DIR/alembic.log" >&2
    exit 1
}

"$PYTHON" -m uvicorn app.main:app --host "$HOST" --port "$PORT" > "$LOG" 2>&1 &
SERVER_PID=$!

ready=""
for _ in $(seq 1 30); do
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        echo "run_tests.sh: the API server exited before becoming ready. Log ($LOG):" >&2
        cat "$LOG" >&2
        exit 1
    fi
    if curl -fsS "http://$HOST:$PORT/health" > /dev/null 2>&1; then
        ready=1
        break
    fi
    sleep 1
done

if [ -z "$ready" ]; then
    echo "run_tests.sh: the API server did not become ready within 30 seconds. Log ($LOG):" >&2
    cat "$LOG" >&2
    exit 1
fi
echo "run_tests.sh: API server ready on $HOST:$PORT (log: $LOG)"

"$PYTHON" -m pytest "$@"
status=$?

if [ "$status" -ne 0 ]; then
    echo "run_tests.sh: pytest exited with $status. Last lines of the server log ($LOG):" >&2
    tail -n 50 "$LOG" >&2
fi

exit "$status"
