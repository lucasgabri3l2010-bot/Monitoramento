import os
from dotenv import load_dotenv

# Carrega arquivo .env caso exista
load_dotenv()

class Config:
    FLASK_ENV = os.getenv("FLASK_ENV", "production")
    SECRET_KEY = os.getenv("SECRET_KEY", "givova_fallback_secret_key_change_in_prod")
    
    # Token de autenticação exigido dos agentes no header 'X-Agent-Token'
    # NUNCA utilizar token hardcoded ou fallback fixo. Deve ser fornecido via variável de ambiente.
    AGENT_SECRET_TOKEN = os.getenv("AGENT_SECRET_TOKEN", "").strip()
    
    # Conexão com o Banco de dados (adequa URLs do Postgres legadas ex: postgres:// -> postgresql://)
    _db_url = os.getenv("DATABASE_URL", "sqlite:///monitoramento.db").strip()
    if _db_url.startswith("postgres://"):
        _db_url = _db_url.replace("postgres://", "postgresql://", 1)
    SQLALCHEMY_DATABASE_URI = _db_url
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Opções do mecanismo SQLAlchemy (essenciais para PostgreSQL serverless como Neon)
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_pre_ping": True,
        "pool_recycle": 300,
    }

    # Cookies de Sessão Seguros para Produção (HTTPS no Render)
    SESSION_COOKIE_SECURE = os.getenv(
        "SESSION_COOKIE_SECURE",
        "true" if FLASK_ENV == "production" else "false"
    ).lower() in ("true", "1", "yes")
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"

    # Regras de Status e Alertas
    OFFLINE_THRESHOLD_SECONDS = int(os.getenv("OFFLINE_THRESHOLD_SECONDS", "30"))
    CPU_ALERT_PERCENT = float(os.getenv("CPU_ALERT_PERCENT", "90.0"))
    RAM_ALERT_PERCENT = float(os.getenv("RAM_ALERT_PERCENT", "90.0"))
    DISK_ALERT_PERCENT = float(os.getenv("DISK_ALERT_PERCENT", "90.0"))

    # Retenção de dados históricos (em dias)
    METRICS_RETENTION_DAYS = int(os.getenv("METRICS_RETENTION_DAYS", "7"))

    # Credenciais do Administrador inicial (criado no 1º boot se inexistente)
    ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin").strip()
    ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "GivovaAdmin@2026!").strip()

    # Monitoramento de Atividade Atual (janela em primeiro plano e domínio ativo)
    ACTIVITY_MONITORING_ENABLED = os.getenv("ACTIVITY_MONITORING_ENABLED", "true").lower() in ("true", "1", "yes")

    # Modo de Demonstração Opcional (dados fictícios em memória com badge DEMO, padrão: false)
    DEMO_MODE = os.getenv("DEMO_MODE", "false").lower() in ("true", "1", "yes")

    # Fuso Horário Corporativo (para cálculo correto de indicadores diários/KPIs)
    APP_TIMEZONE = os.getenv("APP_TIMEZONE", "America/Sao_Paulo").strip()
    APP_TIMEZONE_OFFSET_HOURS = int(os.getenv("APP_TIMEZONE_OFFSET_HOURS", "-3"))

    # Políticas de Uso Corporativo (bloqueios, detecções, alertas)
    POLICY_MONITORING_ENABLED = os.getenv("POLICY_MONITORING_ENABLED", "true").lower() in ("true", "1", "yes")
    ADMIN_NOTIFICATIONS_ENABLED = os.getenv("ADMIN_NOTIFICATIONS_ENABLED", "true").lower() in ("true", "1", "yes")
    POLICY_EVENT_RETENTION_DAYS = int(os.getenv("POLICY_EVENT_RETENTION_DAYS", "90"))
    POLICY_ALERT_COOLDOWN_MINUTES = int(os.getenv("POLICY_ALERT_COOLDOWN_MINUTES", "30"))
    ADMIN_NOTIFICATION_MIN_SEVERITY = os.getenv("ADMIN_NOTIFICATION_MIN_SEVERITY", "warning").strip().lower()

    # Classificação Automática de Domínios
    DOMAIN_CLASSIFICATION_ENABLED = os.getenv("DOMAIN_CLASSIFICATION_ENABLED", "true").lower() in ("true", "1", "yes")
    DOMAIN_CLASSIFICATION_PROVIDER = os.getenv("DOMAIN_CLASSIFICATION_PROVIDER", "internal").strip().lower()
    DOMAIN_CLASSIFICATION_API_KEY = os.getenv("DOMAIN_CLASSIFICATION_API_KEY", "").strip()
    DOMAIN_CLASSIFICATION_TTL_DAYS = int(os.getenv("DOMAIN_CLASSIFICATION_TTL_DAYS", "30"))
    DOMAIN_CLASSIFICATION_MIN_CONFIDENCE = float(os.getenv("DOMAIN_CLASSIFICATION_MIN_CONFIDENCE", "0.80"))

    # Auto-Update do Agente e Gestão de Versões
    AGENT_AUTO_UPDATE_ENABLED = os.getenv("AGENT_AUTO_UPDATE_ENABLED", "true").lower() in ("true", "1", "yes")
    AGENT_UPDATE_CHECK_HOURS = int(os.getenv("AGENT_UPDATE_CHECK_HOURS", "6"))
    LATEST_AGENT_VERSION = os.getenv("LATEST_AGENT_VERSION", "1.5.0")
    RELEASES_DIR = os.getenv("RELEASES_DIR", os.path.join(os.path.dirname(os.path.abspath(__file__)), "releases"))

    # Rastreamento de Tempo de Uso Real e Ociosidade (v1.5.0)
    IDLE_THRESHOLD_SECONDS = int(os.getenv("IDLE_THRESHOLD_SECONDS", "300"))
    MAX_USAGE_GAP_SECONDS = int(os.getenv("MAX_USAGE_GAP_SECONDS", "120"))
    USAGE_SESSION_RETENTION_DAYS = int(os.getenv("USAGE_SESSION_RETENTION_DAYS", "90"))
    USAGE_SUMMARY_RETENTION_DAYS = int(os.getenv("USAGE_SUMMARY_RETENTION_DAYS", "365"))

    # Servidor e Porta (Render define dinamicamente a variável de ambiente PORT)
    HOST = os.getenv("HOST", "0.0.0.0")
    PORT = int(os.getenv("PORT", "5000"))

    # Cloudflare R2 Object Storage (Armazenamento de Binários de Releases)
    R2_ENDPOINT_URL = os.getenv("R2_ENDPOINT_URL", "").strip()
    R2_ACCESS_KEY_ID = os.getenv("R2_ACCESS_KEY_ID", "").strip()
    R2_SECRET_ACCESS_KEY = os.getenv("R2_SECRET_ACCESS_KEY", "").strip()
    R2_BUCKET_NAME = os.getenv("R2_BUCKET_NAME", "givova-monitor-releases").strip()
    R2_REGION = os.getenv("R2_REGION", "auto").strip()
    R2_DOWNLOAD_STRATEGY = os.getenv("R2_DOWNLOAD_STRATEGY", "redirect").strip().lower()  # "redirect" | "stream"
    R2_PRESIGNED_URL_EXPIRES_SECONDS = int(os.getenv("R2_PRESIGNED_URL_EXPIRES_SECONDS", "180"))
    R2_FALLBACK_TO_DATABASE = os.getenv("R2_FALLBACK_TO_DATABASE", "true").lower() in ("true", "1", "yes")


