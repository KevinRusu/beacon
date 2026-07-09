import os
import sys

# main.py uses flat imports (from schemas import ...), so the api/ directory
# itself must be importable.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# These must be set BEFORE main is imported: its module-level
# _validate_config() eagerly builds the provider, and the rate-limit string is
# captured when the route decorator runs. load_dotenv() does not override
# variables that are already set, so these win over api/.env.
os.environ["USE_MOCK"] = "true"
os.environ["RATE_LIMIT"] = "1000/minute"
os.environ.pop("ALLOWED_EXTENSION_ORIGINS", None)