#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/home/sswfb/feedback"
SERVER_DIR="/home/sswfb/feedback/server"
PM2_NAME="feedback"             

echo "==> Deploy started: $(date)"
cd "$APP_DIR"

echo "==> Pulling latest code..."

git pull

cd "$SERVER_DIR"

echo "==> Installing production dependencies..."
npm ci --omit=dev

echo "==> Restarting pm2 process: $PM2_NAME"
pm2 restart "$PM2_NAME"

echo "==> Deploy complete: $(date)"
