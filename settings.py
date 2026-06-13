"""
config/settings.py
──────────────────
Central configuration. Loads .env and exposes all app-wide
paths, constants, and API credentials as module-level names.
"""
import os
from pathlib import Path
from dotenv import load_dotenv

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR    = Path(__file__).resolve().parent.parent
DATA_DIR    = BASE_DIR / "data"
EXPORTS_DIR = BASE_DIR / "exports"

# Ensure runtime directories exist
DATA_DIR.mkdir(exist_ok=True)
EXPORTS_DIR.mkdir(exist_ok=True)

# ── Load .env ─────────────────────────────────────────────────────────────────
load_dotenv(BASE_DIR / ".env")

# ── API Keys ──────────────────────────────────────────────────────────────────
VIRUSTOTAL_API_KEY: str = os.getenv("VT_API_KEY", "")

# ── Database ──────────────────────────────────────────────────────────────────
DB_PATH = DATA_DIR / "toolkit.db"

# ── VirusTotal rate-limit (free tier = 4 req / min) ──────────────────────────
VT_REQUEST_DELAY: float = 16.0   # seconds between requests (safe margin)

# ── Web server ────────────────────────────────────────────────────────────────
FLASK_PORT:  int  = int(os.getenv("FLASK_PORT", 5000))
FLASK_DEBUG: bool = os.getenv("FLASK_DEBUG", "false").lower() == "true"
