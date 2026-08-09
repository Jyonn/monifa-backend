import os
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent


def env_list(name, default=""):
    return [value.strip() for value in os.getenv(name, default).split(",") if value.strip()]


SECRET_KEY = os.getenv("DJANGO_SECRET_KEY", "development-only-secret-change-before-production")
DEBUG = os.getenv("DJANGO_DEBUG", "false").lower() == "true"
ALLOWED_HOSTS = env_list("DJANGO_ALLOWED_HOSTS", "localhost,127.0.0.1,testserver")
APPEND_SLASH = False

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.staticfiles",
    "corsheaders",
    "core",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "monifa.urls"
WSGI_APPLICATION = "monifa.wsgi.application"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

MYSQL_CONFIG_FILE = BASE_DIR / "mysql.local.conf"

if MYSQL_CONFIG_FILE.exists():
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.mysql",
            "OPTIONS": {
                "charset": "utf8mb4",
                "read_default_file": str(MYSQL_CONFIG_FILE),
            },
        }
    }
else:
    DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": BASE_DIR / "db.sqlite3"}}

CORS_ALLOWED_ORIGINS = env_list("CORS_ALLOWED_ORIGINS", "http://localhost:5173")
CORS_ALLOW_CREDENTIALS = False
CORS_ALLOW_HEADERS = ["accept", "authorization", "content-type", "origin", "user-agent"]
CSRF_TRUSTED_ORIGINS = []

LANGUAGE_CODE = "zh-hans"
TIME_ZONE = "Asia/Shanghai"
USE_I18N = True
USE_TZ = True
STATIC_URL = "static/"

FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:5173").rstrip("/")
ACCESS_TOKEN_TTL_SECONDS = 15 * 60
REFRESH_TOKEN_TTL_SECONDS = 30 * 24 * 60 * 60
LOGIN_TICKET_TTL_SECONDS = 60
OAUTH_STATE_TTL_SECONDS = 10 * 60

QITIAN_CLIENT_ID = os.getenv("QITIAN_CLIENT_ID", "")
QITIAN_CLIENT_SECRET = os.getenv("QITIAN_CLIENT_SECRET", "")
QITIAN_AUTHORIZE_URL = os.getenv("QITIAN_AUTHORIZE_URL", "https://sso.6-79.cn/oauth/")
QITIAN_TOKEN_URL = os.getenv("QITIAN_TOKEN_URL", "https://sso.6-79.cn/oauth/token")
QITIAN_USER_URL = os.getenv("QITIAN_USER_URL", "https://sso.6-79.cn/user/")
GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID", "")
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET", "")
