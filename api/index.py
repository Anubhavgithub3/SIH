import sys
from pathlib import Path

# Add workspace root to sys.path so 'app' module can be found by Vercel Serverless Python
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from app.main import app

# Export app for Vercel
__all__ = ["app"]
