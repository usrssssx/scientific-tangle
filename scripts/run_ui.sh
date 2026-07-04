#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
streamlit run ui/streamlit_app.py --server.port 8501
