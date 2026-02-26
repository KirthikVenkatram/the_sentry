import os
import json
import logging
from dotenv import load_dotenv

# Load .env file from project root
load_dotenv()

# --- ⚙️ CONFIGURATION (all values from environment) ---

# 1. SLACK
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")

# 2. GITHUB
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
GITHUB_REPO = os.getenv("GITHUB_REPO", "")

# 3. ELASTIC
ELASTIC_URL     = os.getenv("ELASTIC_URL", "")
ELASTIC_API_KEY = os.getenv("ELASTIC_API_KEY", "")

# 4. FILE PERSISTENCE (local JSON state)
STATE_STORE_PATH = os.path.join(os.path.dirname(__file__), "state_store.json")
ALLOWLIST_PATH   = os.path.join(os.path.dirname(__file__), "allowlist.json")
AUDIT_LOG_PATH   = os.path.join(os.path.dirname(__file__), "sentry_audit.log")

# 5. LOGGING
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("Sentry-Grid")

# --- HELPERS ---
def load_json_file(filepath, default=None):
    if default is None:
        default = []
    try:
        with open(filepath, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return default

def save_json_file(filepath, data):
    with open(filepath, "w") as f:
        json.dump(data, f, indent=2)