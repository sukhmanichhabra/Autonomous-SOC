# Docker-First Setup and Run Guide

This project now supports a full Docker runtime for the SOC stack.

## What runs in Docker

- PostgreSQL with pgvector (`soc-postgres`)
- Redis (`soc-redis`)
- DB initialization job (`init-db`)
- Streamlit dashboard (`soc-dashboard`)

Optional profiles:
- Workers (`producer`, `consumer`) via profile `workers`
- pgAdmin via profile `tools`

## One-command startup

From the repository root:

macOS / Linux:

./run.sh

Windows PowerShell:

powershell -NoProfile -ExecutionPolicy Bypass -File .\run.ps1

This script will:
1. Ensure dashboard host port is available (default 8501)
2. Start PostgreSQL + Redis containers
3. Run database initialization in Docker (`init-db`)
4. Start Streamlit dashboard container
5. Wait for healthy status and print the dashboard URL

Open: http://localhost:8501

## First run with image rebuild

macOS / Linux:

./run.sh --build

Windows PowerShell:

powershell -NoProfile -ExecutionPolicy Bypass -File .\run.ps1 -Build

## Enable optional worker services

macOS / Linux:

./run.sh --with-workers

Windows PowerShell:

powershell -NoProfile -ExecutionPolicy Bypass -File .\run.ps1 -WithWorkers

## Enable pgAdmin

macOS / Linux:

./run.sh --with-pgadmin

Windows PowerShell:

powershell -NoProfile -ExecutionPolicy Bypass -File .\run.ps1 -WithPgAdmin

Then open: http://localhost:5050

## Optional local venv prep (for tests/dev scripts)

If you still want local Python dependencies installed in `.venv`:

macOS / Linux:

./run.sh --prepare-venv

Windows PowerShell:

powershell -NoProfile -ExecutionPolicy Bypass -File .\run.ps1 -PrepareVenv

## Port customization

Set dashboard host port via `.env`:

DASHBOARD_PORT=8501

Or override at runtime:

macOS / Linux:

./run.sh --dashboard-port 8502

Windows PowerShell:

powershell -NoProfile -ExecutionPolicy Bypass -File .\run.ps1 -DashboardPort 8502

## Useful Docker commands

See running services:

docker compose ps

Tail dashboard logs:

docker compose logs -f dashboard

Tail worker logs:

docker compose --profile workers logs -f producer consumer

Stop everything:

docker compose down

Stop and remove volumes (resets PostgreSQL data):

docker compose down -v
