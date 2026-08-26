#!/usr/bin/env bash
# RAPTOR demo launcher — credential-free, offline, synthetic data.
#
#   ./demo/run_demo.sh
#
# Brings up MongoDB, seeds synthetic "Northwind Securities" data, and starts the
# app on http://localhost:10004  (login: admin / demo).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$HERE"

echo "==> Starting MongoDB (docker compose)…"
docker compose up -d

echo "==> Loading demo environment…"
set -a
# shellcheck disable=SC1091
source demo/demo.env
set +a

echo "==> Waiting for MongoDB…"
for i in $(seq 1 30); do
  if docker compose exec -T mongodb mongosh --quiet --eval 'db.adminCommand("ping").ok' >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

echo "==> Seeding synthetic demo data…"
python demo/seed_demo.py

echo "==> Launching RAPTOR on http://localhost:10004  (login: admin / demo)"
exec uvicorn app.main:app --host 0.0.0.0 --port 10004
