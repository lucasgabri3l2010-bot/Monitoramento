"""
Givova Transportes - Script de Migracao e Inicializacao do Banco de Dados
Executado como etapa pre-boot antes de subir o Gunicorn (Render, Docker, Local).
Garante:
1. Execucao serializada via PostgreSQL Advisory Lock (multi-process) e Threading Lock (in-process).
2. Separacao estrita entre DDL (Schema) e DML (Bootstrap de Regras e Admin).
3. Transacoes atomicas com rollback explicito e logging detalhado sem vazamento de segredos.
4. Idempotencia absoluta em multiplos boots/restarts consecutivos.
"""

import sys
import logging
import threading
from config import Config
from models import (
    db, User, Device, MetricHistory, Alert, PolicyRule, PolicyEvent,
    PolicyAuditLog, SystemMetadata, AgentRelease, UsageSession, DailyUsageSummary,
    normalize_domain
)
from corporate_rules_data import CORPORATE_DEFAULT_RULES
from servidor import app

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("GivovaMigration")

GIVOVA_MIGRATION_ADVISORY_LOCK_ID = 482019472910472
_migration_thread_lock = threading.Lock()


def seed_default_policy_rules(force: bool = False) -> int:
    """
    Semeia a base corporativa oficial (> 100 regras) de forma estritamente idempotente.
    1. Verifica versao de seed em SystemMetadata ('corporate_rules_seed_version' = '2').
    2. Se versao ja aplicada e nao for force, pula sem tocar em regras existentes.
    3. Para cada regra do catalogo oficial:
       - Se o dominio normalizado ja existir no banco: NAO duplica, NAO sobrescreve severidade/status customizados.
       - Se for novo: insere com source_provider='seed'.
    4. Seta a versao de seed para '2' e comita.
    Retorna a quantidade de novas regras inseridas.
    """
    seed_ver = SystemMetadata.get_value("corporate_rules_seed_version", "0")
    if not force and seed_ver == "2":
        count = PolicyRule.query.count()
        logger.info(f"[MIGRATION] Base corporativa v2 ja semeada ({count} regras registradas). Pulando seed.")
        return 0

    existing_domain_rules = PolicyRule.query.filter_by(rule_type="domain").all()
    existing_patterns = {normalize_domain(r.pattern) for r in existing_domain_rules}

    existing_app_rules = PolicyRule.query.filter_by(rule_type="application").all()
    existing_apps = {r.pattern.strip().lower() for r in existing_app_rules}

    inserted_count = 0

    # Aplicacoes padrao basicas (caso banco esteja vazio)
    default_apps = [
        {"name": "Jogos Steam", "pattern": "steam.exe", "category": "games", "severity": "warning"},
        {"name": "Jogos Valorant", "pattern": "valorant.exe", "category": "games", "severity": "critical"},
        {"name": "Jogos Roblox", "pattern": "robloxplayerbeta.exe", "category": "games", "severity": "warning"},
    ]
    for app_item in default_apps:
        if app_item["pattern"].lower() not in existing_apps:
            rule = PolicyRule(
                name=app_item["name"],
                rule_type="application",
                pattern=app_item["pattern"],
                category=app_item["category"],
                severity=app_item["severity"],
                scope_type="global",
                scope_target="Todos",
                action="alert",
                enabled=True,
                source_provider="seed"
            )
            db.session.add(rule)
            existing_apps.add(app_item["pattern"].lower())
            inserted_count += 1

    for def_rule in CORPORATE_DEFAULT_RULES:
        clean_pat = normalize_domain(def_rule["pattern"])
        if clean_pat in existing_patterns:
            continue

        rule = PolicyRule(
            name=def_rule["name"],
            rule_type="domain",
            pattern=clean_pat,
            category=def_rule["category"],
            severity=def_rule["severity"],
            scope_type="global",
            scope_target="Todos",
            action="alert",
            enabled=True,
            source_provider="seed"
        )
        db.session.add(rule)
        existing_patterns.add(clean_pat)
        inserted_count += 1

    SystemMetadata.set_value("corporate_rules_seed_version", "2")
    db.session.commit()
    logger.info(f"[MIGRATION] Base corporativa v2 semeada com sucesso ({inserted_count} novas regras inseridas).")
    return inserted_count


def run_migrations() -> bool:
    """
    Executa o pipeline completo e idempotente de migracao e inicializacao.
    Retorna True se concluido com sucesso, ou levanta excecao / retorna False em caso de falha.
    """
    with _migration_thread_lock:
        logger.info("=" * 65)
        logger.info("   GIVOVA MONITOR - PROCESSO DE MIGRACAO DE BANCO DE DADOS")
        logger.info("=" * 65)
        logger.info("[MIGRATION] Starting database migration process...")

        with app.app_context():
            engine_str = str(db.engine.url).lower()
            is_postgres = "postgres" in engine_str

            # -----------------------------------------------------------------
            # Bloqueio de Concorrencia (PostgreSQL Advisory Lock)
            # -----------------------------------------------------------------
            lock_conn = None
            if is_postgres:
                try:
                    lock_conn = db.engine.connect()
                    lock_conn.execute(
                        db.text("SELECT pg_advisory_lock(:lock_id)"),
                        {"lock_id": GIVOVA_MIGRATION_ADVISORY_LOCK_ID}
                    )
                    logger.info("[MIGRATION] PostgreSQL Advisory Lock adquirido com sucesso.")
                except Exception as e:
                    logger.warning(f"[MIGRATION] Aviso ao obter Advisory Lock: {e}")
                    if lock_conn:
                        try:
                            lock_conn.close()
                        except Exception:
                            pass
                    lock_conn = None

            try:
                # -----------------------------------------------------------------
                # FASE A: DDL / Schema Migration (Tabelas e Colunas)
                # -----------------------------------------------------------------
                logger.info("[MIGRATION] Fase A: Verificando tabelas (db.create_all)...")
                db.create_all()
                logger.info("[MIGRATION] Tabelas base verificadas com sucesso.")

                logger.info("[MIGRATION] Checking table columns for devices, policy_rules, policy_events...")
                with db.engine.begin() as conn:
                    table_migrations = [
                        (
                            "devices",
                            [
                                ("active_app", "VARCHAR(120)", "VARCHAR(120)"),
                                ("active_domain", "VARCHAR(150)", "VARCHAR(150)"),
                                ("activity_updated_at", "TIMESTAMP", "DATETIME"),
                                ("is_admin_device", "BOOLEAN DEFAULT FALSE", "BOOLEAN DEFAULT 0"),
                                ("device_token", "VARCHAR(64)", "VARCHAR(64)"),
                                ("update_status", "VARCHAR(50) DEFAULT 'up_to_date'", "VARCHAR(50) DEFAULT 'up_to_date'"),
                                ("last_update_check", "TIMESTAMP", "DATETIME"),
                                ("current_session_state", "VARCHAR(30) DEFAULT 'unknown'", "VARCHAR(30) DEFAULT 'unknown'"),
                                ("last_input_at", "TIMESTAMP", "DATETIME"),
                                ("last_idle_seconds", "FLOAT DEFAULT 0.0", "FLOAT DEFAULT 0.0"),
                                ("user_active", "BOOLEAN DEFAULT FALSE", "BOOLEAN DEFAULT 0"),
                                ("windows_session_id", "INTEGER", "INTEGER")
                            ]
                        ),
                        (
                            "policy_rules",
                            [
                                ("is_automatic", "BOOLEAN DEFAULT FALSE", "BOOLEAN DEFAULT 0"),
                                ("source_provider", "VARCHAR(50)", "VARCHAR(50)")
                            ]
                        ),
                        (
                            "policy_events",
                            [
                                ("source", "VARCHAR(50) DEFAULT 'manual_rule'", "VARCHAR(50) DEFAULT 'manual_rule'"),
                                ("last_notification_sent_at", "TIMESTAMP", "DATETIME"),
                                ("resolved_by", "VARCHAR(80)", "VARCHAR(80)")
                            ]
                        )
                    ]

                    for table_name, columns in table_migrations:
                        logger.info(f"[MIGRATION] Checking table: {table_name}")
                        if is_postgres:
                            res = conn.execute(db.text(
                                "SELECT column_name FROM information_schema.columns WHERE table_name = :tbl"
                            ), {"tbl": table_name}).fetchall()
                            existing_cols = {r[0].lower() for r in res}

                            for col_name, pg_type, _ in columns:
                                logger.info(f"[MIGRATION] Checking {table_name}.{col_name}")
                                if col_name in existing_cols:
                                    logger.info(f"[MIGRATION] {table_name}.{col_name}: Already exists")
                                else:
                                    conn.execute(db.text(
                                        f"ALTER TABLE {table_name} ADD COLUMN IF NOT EXISTS {col_name} {pg_type}"
                                    ))
                                    logger.info(f"[MIGRATION] {table_name}.{col_name}: Added successfully")
                        else:
                            # SQLite
                            res = conn.execute(db.text(f"PRAGMA table_info({table_name})")).fetchall()
                            existing_cols = {r[1].lower() for r in res} if res else set()

                            for col_name, _, sqlite_type in columns:
                                logger.info(f"[MIGRATION] Checking {table_name}.{col_name}")
                                if col_name in existing_cols:
                                    logger.info(f"[MIGRATION] {table_name}.{col_name}: Already exists")
                                else:
                                    conn.execute(db.text(f"ALTER TABLE {table_name} ADD COLUMN {col_name} {sqlite_type}"))
                                    logger.info(f"[MIGRATION] {table_name}.{col_name}: Added successfully")

                logger.info("[MIGRATION] Fase A (Schema/DDL) concluida com sucesso.")

                # -----------------------------------------------------------------
                # FASE B: DML / Regras Corporativas Padrao em Nova Transacao
                # -----------------------------------------------------------------
                logger.info("[MIGRATION] Fase B: Verificando regras corporativas de politicas...")
                try:
                    db.session.rollback()
                    inserted = seed_default_policy_rules()
                    logger.info(f"[MIGRATION] Fase B concluida ({inserted} regras semeadas nesta execucao).")
                except Exception as e:
                    db.session.rollback()
                    logger.error(f"[MIGRATION ERROR] Falha na Fase B (PolicyRule): {e}")
                    raise
                finally:
                    db.session.remove()

                # -----------------------------------------------------------------
                # FASE C: DML / Bootstrap do Administrador em Nova Transacao
                # -----------------------------------------------------------------
                logger.info(f"[MIGRATION] Fase C: Verificando usuario administrador '{Config.ADMIN_USERNAME}'...")
                try:
                    db.session.rollback()
                    admin = User.query.filter_by(username=Config.ADMIN_USERNAME).first()
                    if not admin:
                        logger.info(f"[MIGRATION] Criando usuario administrador inicial '{Config.ADMIN_USERNAME}'...")
                        admin = User(username=Config.ADMIN_USERNAME, role="admin")
                        admin.set_password(Config.ADMIN_PASSWORD)
                        db.session.add(admin)
                        db.session.commit()
                        logger.info(f"[MIGRATION] Usuario administrador '{Config.ADMIN_USERNAME}' inicializado com sucesso.")
                    else:
                        logger.info(f"[MIGRATION] Usuario administrador '{Config.ADMIN_USERNAME}' ja existe.")
                except Exception as e:
                    db.session.rollback()
                    logger.error(f"[MIGRATION ERROR] Falha na Fase C (Admin User): {e}")
                    raise
                finally:
                    db.session.remove()

                # -----------------------------------------------------------------
                # FASE D: Verificacao de Segredos em Producao
                # -----------------------------------------------------------------
                if Config.FLASK_ENV == "production":
                    if "change_in_prod" in Config.SECRET_KEY or "fallback" in Config.SECRET_KEY:
                        logger.warning("[MIGRATION SECURITY WARNING] SECRET_KEY padrao em uso. Defina SECRET_KEY no Render!")
                    if "dev" in Config.AGENT_SECRET_TOKEN:
                        logger.warning("[MIGRATION SECURITY WARNING] AGENT_SECRET_TOKEN padrao em uso. Defina AGENT_SECRET_TOKEN no Render!")

                logger.info("[MIGRATION] Todas as fases de migracao concluidas com 100% de sucesso.")
                return True

            except Exception as err:
                logger.error(f"[MIGRATION ERROR] Processo de migracao falhou: {err}")
                return False

            finally:
                if lock_conn is not None:
                    try:
                        lock_conn.execute(
                            db.text("SELECT pg_advisory_unlock(:lock_id)"),
                            {"lock_id": GIVOVA_MIGRATION_ADVISORY_LOCK_ID}
                        )
                        lock_conn.close()
                        logger.info("[MIGRATION] PostgreSQL Advisory Lock liberado com sucesso.")
                    except Exception as e:
                        logger.warning(f"[MIGRATION] Aviso ao liberar Advisory Lock: {e}")


if __name__ == "__main__":
    success = run_migrations()
    sys.exit(0 if success else 1)
