import os
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

# Automatically load .env file if present
env_path = BASE_DIR / '.env'
if env_path.exists():
    with open(env_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, val = line.split('=', 1)
                key = key.strip()
                val = val.strip().strip("'\"")
                if key and key not in os.environ:
                    os.environ[key] = val

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'sentinel-api-sec-key-production-098f6bcd4621d373cade4e832627b4f6')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', f"sqlite:///{BASE_DIR / 'database' / 'sentinelapi.db'}")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Session & Security
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', '0') == '1'
    PERMANENT_SESSION_LIFETIME = 86400  # 24 hours
    
    # File upload limits
    MAX_CONTENT_LENGTH = 10 * 1024 * 1024  # 10 MB limit
    ALLOWED_EXTENSIONS = {'json', 'yaml', 'yml'}
    
    # Scanner / SSRF Protection Configuration
    SSRF_REQUEST_TIMEOUT = 10  # seconds
    MAX_REMOTE_SPEC_SIZE = 5 * 1024 * 1024  # 5 MB
    SCAN_MAX_CONCURRENT_CHECKS = 5
    DEFAULT_SCAN_PROFILE = 'standard'
    
    # Enterprise / App info
    APP_NAME = "SentinelAPI"
    APP_VERSION = "2.4.0-enterprise"
    PLATFORM_STATUS = "OPERATIONAL"

class DevelopmentConfig(Config):
    DEBUG = True
    SESSION_COOKIE_SECURE = False

class ProductionConfig(Config):
    DEBUG = False
    SESSION_COOKIE_SECURE = False  # Set to True when SSL terminated in production

class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False
    SECRET_KEY = 'test-secret-key'

config_by_name = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}
