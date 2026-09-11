import os
from dotenv import load_dotenv

# Carrega arquivo .env caso exista
load_dotenv()

class Config:
    FLASK_ENV = os.getenv("FLASK_ENV", "production")
    SECRET_KEY = os.getenv("SECRET_KEY", "givova_fallback_secret_key_change_in_prod")
    
    # Token de autenticação exigido dos agentes no header 'X-Agent-Token'
    AGENT_SECRET_TOKEN = os.getenv("AGENT_SECRET_TOKEN", "givova_agent_token_dev_2026")
    
    # URL do Banco de dados (adequa URLs do Postgres legadas ex: postgres:// -> postgresql://)
    _db_url = os.getenv("DATABASE_URL", "sqlite:///monitoramento.db")
    if _db_url.startswith("postgres://"):
        _db_url = _db_url.replace("postgres://", "postgresql://", 1)
    SQLALCHEMY_DATABASE_URI = _db_url
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Regras de Status e Alertas
    OFFLINE_THRESHOLD_SECONDS = int(os.getenv("OFFLINE_THRESHOLD_SECONDS", "30"))
    CPU_ALERT_PERCENT = float(os.getenv("CPU_ALERT_PERCENT", "90.0"))
    RAM_ALERT_PERCENT = float(os.getenv("RAM_ALERT_PERCENT", "90.0"))
    DISK_ALERT_PERCENT = float(os.getenv("DISK_ALERT_PERCENT", "90.0"))
    
    # Retenção de dados históricos (em dias)
    METRICS_RETENTION_DAYS = int(os.getenv("METRICS_RETENTION_DAYS", "7"))
    
    # Credenciais do Administrador inicial
    ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
    ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin")
    
    # Servidor
    HOST = os.getenv("HOST", "0.0.0.0")
    PORT = int(os.getenv("PORT", "5000"))
