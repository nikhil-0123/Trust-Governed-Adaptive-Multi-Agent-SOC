#!/usr/bin/env bash
# ==============================================================================
# TGAM-SOC Ubuntu Telemetry Agent Controller
# Controls local Ubuntu Telemetry collection, detection, and outbox delivery.
# Usage: ./agent.sh {start | stop | status | run}
# ==============================================================================

set -o errexit
set -o nounset
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_FILE="$SCRIPT_DIR/.agent.pid"
LOG_FILE="$SCRIPT_DIR/agent.log"
MAIN_PY="$SCRIPT_DIR/main.py"
PYTHON_BIN="${PYTHON_BIN:-python3}"

get_agent_pid() {
    if [[ -f "$PID_FILE" ]]; then
        local pid
        pid=$(cat "$PID_FILE" 2>/dev/null || true)
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            echo "$pid"
            return 0
        fi
    fi
    return 1
}

get_agent_info() {
    "$PYTHON_BIN" - << 'EOF' 2>/dev/null || true
import json, os, sqlite3
try:
    from config.settings import config
    outbox_count = 0
    if os.path.exists(config.outbox_db_path):
        conn = sqlite3.connect(config.outbox_db_path)
        cur = conn.cursor()
        cur.execute("SELECT count(*) FROM outbox WHERE status='pending'")
        outbox_count = cur.fetchone()[0]
        conn.close()

    agent_id = 'Unknown'
    id_file = os.path.join(config.data_dir, 'agent_identity.json')
    if os.path.exists(id_file):
        with open(id_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
            agent_id = data.get('agent_id', 'Unknown')

    print(json.dumps({
        'agent_id': agent_id,
        'soc_url': config.soc_api_url,
        'pending_outbox': outbox_count,
        'data_dir': config.data_dir
    }))
except Exception as e:
    print(json.dumps({'error': str(e)}))
EOF
}

cmd_start() {
    local pid
    if pid=$(get_agent_pid); then
        echo "[ALREADY RUNNING] Ubuntu Telemetry Agent is already active (PID: $pid)."
        exit 0
    fi

    # Clear stale pid file
    rm -f "$PID_FILE"

    echo "Starting Ubuntu Telemetry Agent in background..."
    nohup "$PYTHON_BIN" "$MAIN_PY" >> "$LOG_FILE" 2>&1 &
    local new_pid=$!
    echo "$new_pid" > "$PID_FILE"

    sleep 1

    if kill -0 "$new_pid" 2>/dev/null; then
        echo "[SUCCESS] Ubuntu Telemetry Agent started."
        echo "  PID:         $new_pid"
        echo "  Log File:    $LOG_FILE"
    else
        echo "[ERROR] Agent process failed to start. Recent log output:"
        tail -n 15 "$LOG_FILE" 2>/dev/null || true
        rm -f "$PID_FILE"
        exit 1
    fi
}

cmd_stop() {
    local pid
    if ! pid=$(get_agent_pid); then
        echo "[NOT RUNNING] Ubuntu Telemetry Agent is not currently running."
        rm -f "$PID_FILE"
        exit 0
    fi

    echo "Stopping Ubuntu Telemetry Agent (PID: $pid)..."
    kill -TERM "$pid" 2>/dev/null || true

    # Wait up to 5 seconds for clean exit and outbox flush
    local count=0
    while kill -0 "$pid" 2>/dev/null && [[ $count -lt 10 ]]; do
        sleep 0.5
        count=$((count + 1))
    done

    if kill -0 "$pid" 2>/dev/null; then
        echo "Agent did not terminate gracefully, sending SIGKILL..."
        kill -KILL "$pid" 2>/dev/null || true
    fi

    rm -f "$PID_FILE"
    echo "[SUCCESS] Ubuntu Telemetry Agent stopped cleanly."
}

cmd_status() {
    local pid
    local running=false
    if pid=$(get_agent_pid); then
        running=true
    fi

    local info_json
    info_json=$(cd "$SCRIPT_DIR" && get_agent_info)

    echo "=================================================="
    echo "TGAM-SOC Ubuntu Telemetry Agent Status"
    echo "=================================================="
    if [[ "$running" == "true" ]]; then
        echo "  Process State:     RUNNING"
        echo "  PID:               $pid"
    else
        echo "  Process State:     STOPPED"
    fi

    local agent_id soc_url pending_outbox
    agent_id=$("$PYTHON_BIN" -c "import json; print(json.loads('''$info_json''').get('agent_id', 'Unknown'))" 2>/dev/null || echo "Unknown")
    soc_url=$("$PYTHON_BIN" -c "import json; print(json.loads('''$info_json''').get('soc_url', 'Unknown'))" 2>/dev/null || echo "Unknown")
    pending_outbox=$("$PYTHON_BIN" -c "import json; print(json.loads('''$info_json''').get('pending_outbox', 0))" 2>/dev/null || echo "0")

    echo "  Agent ID:          $agent_id"
    echo "  Hostname:          $(hostname 2>/dev/null || echo 'unknown')"
    echo "  Operating System:  Linux / Ubuntu"
    echo "  Central SOC URL:   $soc_url"
    echo "  Pending Outbox:    $pending_outbox events"
    echo "  Log Path:          $LOG_FILE"

    if [[ -f "$LOG_FILE" ]]; then
        echo ""
        echo "Recent Log Entries:"
        tail -n 5 "$LOG_FILE" 2>/dev/null | sed 's/^/    /' || true
    fi
    echo "=================================================="
}

cmd_run() {
    local pid
    if pid=$(get_agent_pid); then
        echo "[WARNING] A background agent is already running (PID: $pid)."
        echo "Stopping the background agent before interactive run is recommended."
    fi
    echo "Running Ubuntu Telemetry Agent in foreground (Ctrl+C to terminate)..."
    exec "$PYTHON_BIN" "$MAIN_PY"
}

case "${1:-status}" in
    start)
        cmd_start
        ;;
    stop)
        cmd_stop
        ;;
    status)
        cmd_status
        ;;
    run)
        cmd_run
        ;;
    *)
        echo "Usage: $0 {start | stop | status | run}"
        exit 1
        ;;
esac
