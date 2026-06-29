#!/usr/bin/env bash
# deploy.sh: Deploy Trap House to a Hetzner VPS.
# Run this script ON the VPS after harden.sh has been executed.
#
# Prerequisites:
# - harden.sh has been run
# - Docker is installed
# - This repo is cloned to /opt/trap-house
# - .env.hetzner is configured with real SESSION_SECRET and GRAFANA_ADMIN_PASSWORD
#
# Usage: bash deploy.sh

set -euo pipefail

PROJECT_DIR="/opt/trap-house"
ENV_FILE="${PROJECT_DIR}/.env.hetzner"

echo "=== Trap House Deployment ==="

# Check prerequisites
if [ ! -f "$ENV_FILE" ]; then
  echo "ERROR: ${ENV_FILE} not found."
  echo "Copy .env.hetzner.example to .env.hetzner and configure it:"
  echo "  cp ${PROJECT_DIR}/.env.hetzner.example ${ENV_FILE}"
  echo "  # Edit SESSION_SECRET and GRAFANA_ADMIN_PASSWORD"
  exit 1
fi

# Validate env file has real values
if grep -q "REPLACE_WITH" "$ENV_FILE"; then
  echo "ERROR: .env.hetzner contains placeholder values."
  echo "Replace REPLACE_WITH_* with real values before deploying."
  exit 1
fi

cd "$PROJECT_DIR"

# Create data directories with correct permissions
echo "[1/4] Creating data directories..."
mkdir -p data/{logs/cowrie,logs/deception-gw,db,loki,grafana}
chown -R 999:999 data/logs/cowrie
chown -R 1000:1000 data/logs/deception-gw data/db
chown -R 10001:10001 data/loki
chown -R 472:472 data/grafana

# Build custom images
echo "[2/4] Building Docker images..."
docker compose -f docker-compose.yml -f docker-compose.prod.yml --env-file "$ENV_FILE" build

# Start the stack
echo "[3/4] Starting Trap House stack..."
docker compose -f docker-compose.yml -f docker-compose.prod.yml --env-file "$ENV_FILE" up -d

# Wait for services to start
echo "[4/4] Verifying services..."
sleep 10

PASS=0
FAIL=0

check_port() {
  local port=$1
  local name=$2
  if ss -tlnp | grep -q ":${port}\b"; then
    echo "  PASS: ${name} listening on port ${port}"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: ${name} not listening on port ${port}"
    FAIL=$((FAIL + 1))
  fi
}

check_container() {
  local container=$1
  local name=$2
  local status=$(docker inspect -f '{{.State.Status}}' "$container" 2>/dev/null || echo "missing")
  if [ "$status" = "running" ]; then
    echo "  PASS: ${name} container is running"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: ${name} container is ${status}"
    FAIL=$((FAIL + 1))
  fi
}

echo ""
echo "Container status:"
check_container "trap-endlessh" "Endlessh"
check_container "trap-cowrie" "Cowrie"
check_container "trap-deception-gw" "Deception-gw"
check_container "trap-log-shipper" "Log-shipper"
check_container "trap-mitre-mapper" "MITRE-mapper"
check_container "trap-frontend" "Frontend"
check_container "trap-loki" "Loki"
check_container "trap-grafana" "Grafana"

echo ""
echo "Port bindings:"
check_port 22 "Endlessh tarpit"
check_port 2222 "Cowrie SSH"
check_port 2223 "Cowrie Telnet"
check_port 80 "Deception-gw HTTP"

echo ""
echo "=== Deployment Results: ${PASS} passed, ${FAIL} failed ==="

if [ "$FAIL" -gt 0 ]; then
  echo ""
  echo "Some checks failed. Check logs:"
  echo "  docker compose -f docker-compose.yml -f docker-compose.prod.yml logs"
  exit 1
fi

echo ""
echo "Trap House is live."
echo ""
echo "External honeypot services:"
echo "  Port 22:   Endlessh SSH tarpit"
echo "  Port 2222: Cowrie SSH honeypot"
echo "  Port 2223: Cowrie Telnet honeypot"
echo "  Port 80:   Deception-gw (fake NordTech Solutions web app)"
echo ""
echo "Internal dashboards (access via SSH tunnel):"
echo "  ssh -p 65022 -L 8001:localhost:8001 -L 3000:localhost:3000 user@$(hostname -I | awk '{print $1}')"
echo "  http://localhost:8001  (SOC Dashboard)"
echo "  http://localhost:3000  (Grafana)"