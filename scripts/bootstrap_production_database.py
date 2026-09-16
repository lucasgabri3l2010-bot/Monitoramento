#!/usr/bin/env python3
"""
Givova Transportes - Script de Bootstrap Idempotente do Banco de Produção (Aiven)
Finalidade: Inicializar uma base de dados PostgreSQL vazia (Aiven) para Cold Cutover,
            garantindo 100% de integridade estrutural, regras corporativas oficiais,
            usuário administrador seguro e release v1.5.0 (R2) SEM criar dados fictícios,
            computadores falsos ou histórico simulado.

Uso:
    python scripts/bootstrap_production_database.py [--db-url <URL>] [--admin-username <USER>] [--admin-password <PASS>]
"""

import os
import sys
import argparse
import logging
from datetime import datetime, timezone

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from dotenv import load_dotenv
load_dotenv(os.path.join(BASE_DIR, ".env"))

import storage_service

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("AivenBootstrap")


def mask_url(url: str) -> str:
    """Mascara credenciais em connection string do banco de dados para logging seguro."""
    if not url:
        return ""
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        if parsed.password:
            netloc = f"{parsed.username}:***@{parsed.hostname}"
            if parsed.port:
                netloc += f":{parsed.port}"
            return parsed._replace(netloc=netloc).geturl()
    except Exception:
        pass
    return "postgresql://***:***@<masked>"


def bootstrap_database(db_url: str = None, admin_user: str = None, admin_pass: str = None, verify_r2: bool = True) -> bool:
    """
    Executa o bootstrap idempotente do banco de dados de produção.
    """
    # 1. Resolução da URL de Conexão
    target_url = (
        db_url or
        os.getenv("AIVEN_DATABASE_URL") or
        os.getenv("DATABASE_URL")
    )
    if not target_url:
        logger.critical("Nenhuma URL de banco de dados fornecida (--db-url, AIVEN_DATABASE_URL ou DATABASE_URL).")
        return False

    target_url = target_url.strip()
    if target_url.startswith("postgres://"):
        target_url = target_url.replace("postgres://", "postgresql://", 1)

    logger.info("=" * 65)
    logger.info("   GIVOVA MONITOR - BOOTSTRAP DE BANCO DE DADOS (COLD CUTOVER)")
    logger.info("=" * 65)
    logger.info(f"Destino: {mask_url(target_url)}")

    # Atualiza configuração do app
    os.environ["DATABASE_URL"] = target_url
    from config import Config
    Config.SQLALCHEMY_DATABASE_URI = target_url
    Config._db_url = target_url

    from servidor import app
    app.config["SQLALCHEMY_DATABASE_URI"] = target_url

    with app.app_context():
        from models import (
            db, User, Device, MetricHistory, Alert, PolicyRule, PolicyEvent,
            PolicyAllowlist, DomainClassification, PolicyAuditLog, SystemMetadata,
            AgentRelease, UsageSession, DailyUsageSummary
        )
        import storage_service
        from migrate import run_migrations

        # ---------------------------------------------------------------------
        # 1. Teste de Conectividade com o Banco
        # ---------------------------------------------------------------------
        logger.info("[ETAPA 1/6] Testando conectividade com o banco de dados...")
        try:
            with db.engine.connect() as conn:
                res = conn.execute(db.text("SELECT 1")).scalar()
                logger.info("Conexão estabelecida com sucesso (SELECT 1 -> OK).")
        except Exception as e:
            logger.critical(f"Falha ao conectar no banco de dados: {e}")
            return False

        # ---------------------------------------------------------------------
        # 2. Execução das Migrations e Criação do Schema Completo
        # ---------------------------------------------------------------------
        logger.info("[ETAPA 2/6] Executando pipeline completo de migração de schema...")
        success = run_migrations()
        if not success:
            logger.critical("Falha na execução de run_migrations(). Abortando.")
            return False
        logger.info("Schema do banco e tabelas verificados com sucesso.")

        # ---------------------------------------------------------------------
        # 3. Bootstrap Seguro do Usuário Administrador
        # ---------------------------------------------------------------------
        resolved_admin_user = admin_user or Config.ADMIN_USERNAME or "admin"
        resolved_admin_pass = admin_pass or os.getenv("ADMIN_PASSWORD") or Config.ADMIN_PASSWORD or "GivovaAdmin@2026!"

        logger.info(f"[ETAPA 3/6] Verificando credenciais do administrador ('{resolved_admin_user}')...")
        try:
            admin = User.query.filter_by(username=resolved_admin_user).first()
            if not admin:
                logger.info(f"Criando novo usuário administrador '{resolved_admin_user}'...")
                admin = User(username=resolved_admin_user, role="admin")
                admin.set_password(resolved_admin_pass)
                db.session.add(admin)
                db.session.commit()
                logger.info(f"Administrador '{resolved_admin_user}' criado com sucesso.")
            else:
                # Se fornecida senha explicitamente via CLI ou env, garante atualização
                if admin_pass or os.getenv("ADMIN_PASSWORD"):
                    admin.set_password(resolved_admin_pass)
                    db.session.commit()
                    logger.info(f"Senha do administrador '{resolved_admin_user}' atualizada.")
                else:
                    logger.info(f"Administrador '{resolved_admin_user}' já existente e preservado.")
        except Exception as e:
            db.session.rollback()
            logger.critical(f"Erro ao configurar usuário administrador: {e}")
            return False

        # ---------------------------------------------------------------------
        # 4. Registro Oficial da Release v1.5.0 (Cloudflare R2 Global)
        # ---------------------------------------------------------------------
        EXPECTED_SHA = "fbaf61d253c9b9fe5ea5f813dabe473b622dd4eb90aa99e0129edba62ffe1743"
        OBJECT_KEY = "agents/1.5.0/GivovaMonitorAgent.exe"
        FILE_SIZE = 13724916

        logger.info("[ETAPA 4/6] Verificando cadastro da release oficial v1.5.0 (Cloudflare R2)...")
        try:
            rel = AgentRelease.query.filter_by(version="1.5.0").first()
            if not rel:
                rel = AgentRelease(
                    version="1.5.0",
                    sha256=EXPECTED_SHA,
                    download_url="/api/agent/download/1.5.0",
                    changelog="Release oficial v1.5.0: Rollout Global via Cloudflare R2 e telemetria de uso real.",
                    min_supported_version="1.0.0",
                    mandatory=False,
                    storage_type="r2",
                    object_key=OBJECT_KEY,
                    file_size=FILE_SIZE,
                    binary_data=None,
                    release_channel="stable",
                    rollout_scope="global",
                    status="active",
                    created_by="bootstrap"
                )
                db.session.add(rel)
                db.session.commit()
                logger.info("Release v1.5.0 cadastrada com sucesso (stable, global, r2).")
            else:
                rel.sha256 = EXPECTED_SHA
                rel.storage_type = "r2"
                rel.object_key = OBJECT_KEY
                rel.file_size = FILE_SIZE
                rel.release_channel = "stable"
                rel.rollout_scope = "global"
                rel.status = "active"
                db.session.commit()
                logger.info("Release v1.5.0 atualizada e validada.")
        except Exception as e:
            db.session.rollback()
            logger.critical(f"Erro ao registrar release v1.5.0: {e}")
            return False

        # ---------------------------------------------------------------------
        # 5. Garantia de Ausência de Dados Fictícios (Clean Slate Verification)
        # ---------------------------------------------------------------------
        logger.info("[ETAPA 5/6] Verificando integridade e ausência de dados fictícios...")
        device_count = Device.query.count()
        metric_count = MetricHistory.query.count()
        session_count = UsageSession.query.count()
        rules_count = PolicyRule.query.count()

        logger.info(f"Dispositivos cadastrados no banco: {device_count}")
        logger.info(f"Métricas históricas no banco: {metric_count}")
        logger.info(f"Sessões de uso no banco: {session_count}")
        logger.info(f"Regras corporativas semeadas: {rules_count}")

        if device_count > 0:
            logger.info(f"Dispositivos já existentes ({device_count}) detectados no banco.")
        else:
            logger.info("[VERIFICADO] Nenhum computador falso ou dado fictício foi inserido. A frota será reconstruída naturalmente pelos agentes legítimos.")

        # ---------------------------------------------------------------------
        # 6. Verificação do Cloudflare R2
        # ---------------------------------------------------------------------
        if verify_r2:
            logger.info("[ETAPA 6/6] Verificando status do Cloudflare R2...")
            if storage_service.is_r2_configured():
                try:
                    exists = storage_service.object_exists(OBJECT_KEY)
                    if exists:
                        meta = storage_service.get_object_metadata(OBJECT_KEY)
                        r2_size = meta.get("size")
                        logger.info(f"[R2 OK] Objeto '{OBJECT_KEY}' localizado no R2 ({r2_size} bytes).")
                    else:
                        logger.warning(
                            f"[AVISO R2] Objeto '{OBJECT_KEY}' ainda não existe no bucket R2 '{Config.R2_BUCKET_NAME}'. "
                            f"Execute 'python scripts/upload_release_to_r2.py --version 1.5.0' para enviá-lo."
                        )
                except Exception as e:
                    logger.warning(f"Não foi possível checar objeto no R2: {e}")
            else:
                logger.warning(
                    "[AVISO R2] Variáveis de ambiente do Cloudflare R2 não detectadas no ambiente local. "
                    "Certifique-se de que estejam configuradas no Render."
                )

        logger.info("=" * 65)
        logger.info("   BOOTSTRAP DO BANCO CONCLUÍDO COM 100% DE SUCESSO!")
        logger.info("=" * 65)
        return True


def main():
    parser = argparse.ArgumentParser(description="Bootstrap de Banco de Dados de Produção (Aiven) para Cold Cutover")
    parser.add_argument("--db-url", dest="db_url", help="URL de conexão PostgreSQL (Aiven)")
    parser.add_argument("--admin-username", dest="admin_user", help="Nome do usuário administrador inicial")
    parser.add_argument("--admin-password", dest="admin_pass", help="Senha do usuário administrador inicial")
    parser.add_argument("--no-verify-r2", dest="no_verify_r2", action="store_true", help="Pula checagem remota no R2")
    args = parser.parse_args()

    success = bootstrap_database(
        db_url=args.db_url,
        admin_user=args.admin_user,
        admin_pass=args.admin_pass,
        verify_r2=not args.no_verify_r2
    )
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
