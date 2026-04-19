#!/usr/bin/env bash
set -euo pipefail

DASHBOARD_PORT=8501
BUILD=false
WITH_WORKERS=false
WITH_PGADMIN=false
PREPARE_VENV=false
SKIP_PIP_UPGRADE=false

write_step() {
  echo "[setup] $*"
}

write_warn() {
  echo "[warning] $*"
}

fail() {
  echo "[error] $*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Usage: ./run.sh [options]

Options:
  --dashboard-port <port>   Host port for Streamlit dashboard (default: 8501)
  --build                   Rebuild images before starting services
  --with-workers            Start producer and consumer services (workers profile)
  --with-pgadmin            Start pgAdmin service (tools profile)
  --prepare-venv            Create/update local .venv and install requirements
  --skip-pip-upgrade        Skip pip upgrade when --prepare-venv is used
  -h, --help                Show this help message

Examples:
  ./run.sh
  ./run.sh --build
  ./run.sh --with-workers --with-pgadmin
  ./run.sh --prepare-venv
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dashboard-port)
      [[ $# -lt 2 ]] && fail "--dashboard-port requires a value"
      DASHBOARD_PORT="$2"
      shift 2
      ;;
    --build)
      BUILD=true
      shift
      ;;
    --with-workers)
      WITH_WORKERS=true
      shift
      ;;
    --with-pgadmin)
      WITH_PGADMIN=true
      shift
      ;;
    --prepare-venv)
      PREPARE_VENV=true
      shift
      ;;
    --skip-pip-upgrade)
      SKIP_PIP_UPGRADE=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "Unknown option: $1"
      ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

require_command() {
  local cmd="$1"
  command -v "$cmd" >/dev/null 2>&1 || fail "Required command not found: $cmd"
}

invoke_checked_command() {
  local step_name="$1"
  shift
  write_step "$step_name"
  if ! "$@"; then
    fail "$step_name failed."
  fi
}

ensure_env_file() {
  if [[ -f ".env" ]]; then
    return
  fi

  if [[ -f ".env.example" ]]; then
    cp ".env.example" ".env"
    write_step "Created .env from .env.example"
  else
    : > ".env"
    write_step "Created empty .env"
  fi
}

setup_local_venv() {
  local python_cmd
  if command -v python3 >/dev/null 2>&1; then
    python_cmd="python3"
  elif command -v python >/dev/null 2>&1; then
    python_cmd="python"
  else
    fail "Python 3 was not found. Install Python 3 to create a local .venv."
  fi

  if [[ ! -x ".venv/bin/python" ]]; then
    invoke_checked_command "Creating local virtual environment (.venv)" "$python_cmd" -m venv .venv
  else
    write_step "Using existing local virtual environment (.venv)"
  fi

  if [[ ! -x ".venv/bin/python" ]]; then
    fail "Virtual environment creation failed. Missing .venv/bin/python"
  fi

  if [[ "$SKIP_PIP_UPGRADE" == false ]]; then
    invoke_checked_command "Upgrading local pip" .venv/bin/python -m pip install --upgrade pip
  else
    write_step "Skipping local pip upgrade"
  fi

  invoke_checked_command "Installing local Python dependencies" .venv/bin/python -m pip install -r my-ai-soc-agent/requirements.txt
}

wait_for_container() {
  local container_name="$1"
  local timeout_seconds="${2:-180}"
  local start_ts
  start_ts="$(date +%s)"

  while true; do
    local status
    status="$(docker inspect --format='{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$container_name" 2>/dev/null || true)"

    if [[ "$status" == "healthy" || "$status" == "running" ]]; then
      write_step "$container_name is $status"
      return 0
    fi

    local now_ts
    now_ts="$(date +%s)"
    if (( now_ts - start_ts >= timeout_seconds )); then
      docker compose logs --tail=120 || true
      fail "Timeout waiting for container: $container_name"
    fi

    if [[ -z "$status" ]]; then
      write_step "Waiting for $container_name to be created..."
    else
      write_step "Waiting for $container_name (status: $status)..."
    fi

    sleep 2
  done
}

get_listening_pids() {
  local port="$1"
  if command -v lsof >/dev/null 2>&1; then
    lsof -tiTCP:"$port" -sTCP:LISTEN 2>/dev/null || true
  else
    echo ""
  fi
}

stop_docker_containers_on_host_port() {
  local port="$1"
  local rows
  rows="$(docker ps --format '{{.ID}}|{{.Names}}|{{.Ports}}' || true)"

  while IFS='|' read -r container_id container_name ports; do
    [[ -z "${container_id:-}" ]] && continue

    if [[ "${ports:-}" == *"0.0.0.0:${port}->"* || "${ports:-}" == *"[::]:${port}->"* ]]; then
      write_step "Stopping container '$container_name' using host port $port"
      docker stop "$container_id" >/dev/null || fail "Failed to stop container '$container_name'"
    fi
  done <<< "$rows"
}

stop_processes_on_port() {
  local port="$1"
  write_step "Ensuring host port $port is available"

  stop_docker_containers_on_host_port "$port"

  local pids
  pids="$(get_listening_pids "$port")"
  if [[ -z "$pids" ]]; then
    write_step "Port $port is already free"
    return 0
  fi

  while read -r pid; do
    [[ -z "${pid:-}" ]] && continue
    [[ "$pid" == "$$" ]] && continue

    local proc_name
    proc_name="$(ps -p "$pid" -o comm= 2>/dev/null || true)"
    if [[ "$proc_name" == *"com.docker.backend"* ]]; then
      continue
    fi

    if [[ -n "$proc_name" ]]; then
      write_step "Stopping process $proc_name (PID $pid) on port $port"
    else
      write_step "Stopping PID $pid on port $port"
    fi

    kill -9 "$pid" 2>/dev/null || fail "Unable to stop PID $pid on port $port"
  done <<< "$pids"

  local deadline=$(( $(date +%s) + 10 ))
  while (( $(date +%s) < deadline )); do
    local remaining
    remaining="$(get_listening_pids "$port")"
    if [[ -z "$remaining" ]]; then
      write_step "Port $port is now free"
      return 0
    fi
    sleep 1
  done

  fail "Port $port is still in use after attempting to stop conflicting processes"
}

wait_for_http_endpoint() {
  local url="$1"
  local timeout_seconds="${2:-90}"
  local start_ts
  start_ts="$(date +%s)"

  while true; do
    local http_code
    http_code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 8 "$url" || true)"
    if [[ "$http_code" =~ ^[0-9]{3}$ ]] && (( http_code >= 200 && http_code < 500 )); then
      return 0
    fi

    local now_ts
    now_ts="$(date +%s)"
    if (( now_ts - start_ts >= timeout_seconds )); then
      return 1
    fi

    sleep 2
  done
}

require_command docker

docker compose version >/dev/null 2>&1 || fail "Docker Compose plugin is required (docker compose)."

ensure_env_file

if [[ "$PREPARE_VENV" == true ]]; then
  setup_local_venv
fi

export DASHBOARD_PORT

stop_processes_on_port "$DASHBOARD_PORT"

up_core_cmd=(docker compose up -d)
if [[ "$BUILD" == true ]]; then
  up_core_cmd+=(--build)
fi
up_core_cmd+=(postgres redis)
invoke_checked_command "Starting PostgreSQL and Redis" "${up_core_cmd[@]}"

wait_for_container "soc-postgres" 180
wait_for_container "soc-redis" 120

init_db_cmd=(docker compose run --rm)
if [[ "$BUILD" == true ]]; then
  init_db_cmd+=(--build)
fi
init_db_cmd+=(init-db)
invoke_checked_command "Initializing PostgreSQL schema and pgvector" "${init_db_cmd[@]}"

dashboard_cmd=(docker compose up -d)
if [[ "$BUILD" == true ]]; then
  dashboard_cmd+=(--build)
fi
dashboard_cmd+=(dashboard)
invoke_checked_command "Starting Streamlit dashboard container" "${dashboard_cmd[@]}"

wait_for_container "soc-dashboard" 240

if [[ "$WITH_WORKERS" == true ]]; then
  workers_cmd=(docker compose --profile workers up -d)
  if [[ "$BUILD" == true ]]; then
    workers_cmd+=(--build)
  fi
  workers_cmd+=(producer consumer)
  invoke_checked_command "Starting producer and consumer workers" "${workers_cmd[@]}"
fi

if [[ "$WITH_PGADMIN" == true ]]; then
  invoke_checked_command "Starting pgAdmin" docker compose --profile tools up -d pgadmin
fi

APP_URL="http://localhost:${DASHBOARD_PORT}"
if ! wait_for_http_endpoint "$APP_URL" 90; then
  write_warn "Dashboard container is running but HTTP health check timed out for $APP_URL"
fi

echo
echo "[success] Full SOC stack is running in Docker."
echo "[success] Dashboard: $APP_URL"
echo "[info] Core services: postgres, redis, init-db, dashboard"
if [[ "$WITH_WORKERS" == true ]]; then
  echo "[info] Worker services: producer, consumer"
fi
if [[ "$WITH_PGADMIN" == true ]]; then
  echo "[info] pgAdmin: http://localhost:5050"
fi
echo
echo "Useful commands:"
echo "  docker compose logs -f dashboard"
echo "  docker compose --profile workers logs -f producer consumer"
echo "  docker compose down"
echo
