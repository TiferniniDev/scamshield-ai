#!/usr/bin/env bash
# ScamShield AI - One-Command Local Launcher
# Starts:
#   1. FastAPI Core + Abu Dhabi Police Command Dashboard (http://127.0.0.1:8000)
#   2. Mobile Private DNS Shield (UDP port 5353 local, or set DNS_PORT=53 with sudo for phones)
#   3. Citizen Telegram "Share-to-Check" Bot (@ScamShieldAD_bot)

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [ ! -d "venv" ]; then
  echo "[ScamShield] Creating Python virtual environment..."
  python3 -m venv venv
  ./venv/bin/pip install --upgrade pip
  ./venv/bin/pip install -r requirements.txt
fi

if [ ! -f "ml/scam_model.joblib" ]; then
  echo "[ScamShield] Training local ML scam detection model..."
  ./venv/bin/python -m ml.train_model
fi

echo "[ScamShield] Running initial proactive Abu Dhabi patrol sweep..."
./venv/bin/python -m patrol.patrol_worker

cleanup() {
  echo ""
  echo "[ScamShield] Shutting down all services..."
  kill $API_PID $DNS_PID $BOT_PID 2>/dev/null || true
  exit 0
}
trap cleanup INT TERM

echo "[ScamShield] Starting FastAPI + ScamShield Command Center on http://127.0.0.1:8000 ..."
./venv/bin/uvicorn backend.main:app --host 0.0.0.0 --port 8000 &
API_PID=$!

echo "[ScamShield] Starting Mobile DNS Shield (#2) on port ${DNS_PORT:-1053} ..."
./venv/bin/python -m dns_shield.dns_server --port "${DNS_PORT:-1053}" &
DNS_PID=$!

if [ -f ".env" ] && grep -q "TELEGRAM_BOT_TOKEN=" .env && ! grep -q "your_telegram_bot_token_here" .env; then
  echo "[ScamShield] Starting Citizen Telegram Bot (#3) ..."
  ./venv/bin/python -m bot.telegram_bot &
  BOT_PID=$!
else
  echo "[ScamShield] Telegram bot token not configured in .env — skipping bot."
  BOT_PID=""
fi

echo ""
echo "================================================================"
echo "  🛡️  SCAMSHIELD AI IS LIVE!"
echo "  • ScamShield Command Center : http://127.0.0.1:8000"
echo "  • Mobile DNS Block Page     : http://127.0.0.1:8000/blocked"
echo "  • Safe Demo Scam Page       : http://127.0.0.1:8000/demo-scam"
echo "  • Press Ctrl+C to stop all services cleanly."
echo "================================================================"
echo ""

wait
