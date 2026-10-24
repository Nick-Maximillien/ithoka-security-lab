#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
exec python3 -m streamlit run gui/streamlit_app.py \
  --server.address 127.0.0.1 \
  --server.port "${LAB_GUI_PORT:-8501}" \
  --server.headless true \
  --server.enableCORS false \
  --server.enableXsrfProtection true \
  --browser.gatherUsageStats false
