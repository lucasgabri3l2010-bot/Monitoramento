# =================================================================
# Givova Transportes - Monitoramento de Computadores
# Dockerfile para Produção (Render, Railway, Fly.io, VPS)
# =================================================================

FROM python:3.12-slim

# Evita geração de bytecode .pyc e força flush imediato de stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=5000 \
    FLASK_ENV=production

WORKDIR /app

# Instala curl para verificação de health check
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

# Instalação de dependências do Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn

# Cópia do código fonte da aplicação
COPY . .

# Expõe a porta da aplicação
EXPOSE 5000

# Checagem periódica de saúde do container
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:${PORT}/health || exit 1

# Inicialização com migração isolada seguida de Gunicorn (multi-worker com threads assíncronas)
CMD ["sh", "-c", "python migrate.py && gunicorn --bind 0.0.0.0:${PORT} --workers 2 --threads 4 --access-logfile - --error-logfile - servidor:app"]
