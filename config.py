import os

# Admin authentication token for dashboard and admin API
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "admin123")

# Server host and port
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", 8000))

# Database file path
DB_PATH = os.path.join(os.path.dirname(__file__), "keys.db")
