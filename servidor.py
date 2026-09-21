import os
import json
import secrets
import logging
from datetime import datetime, timezone, timedelta
from functools import wraps
from flask import Flask, g, request, jsonify, render_template, redirect, url_for, session, flash, send_file, Response
from werkzeug.security import generate_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix

import io
from sqlalchemy.orm import undefer

import storage_service
from telemetry import (
    install_sql_query_counter,
    response_size_bytes,
    telemetry,
    track_release_stream,
)
from config import Config
from datetime_utils import (
    utc_now, ensure_utc, to_app_timezone, format_iso_utc,
    format_local_datetime, format_local_time, start_of_local_day_utc,
    start_of_next_local_day_utc, get_local_day_range_utc,
    get_app_timezone as get_corporate_timezone, get_local_date
)
from models import (
    db, User, Device, MetricHistory, Alert, PolicyRule, PolicyEvent,
    PolicyAuditLog, SystemMetadata, AgentRelease, ReleaseTargetDevice, PolicyAllowlist,
    DomainClassification, DailyUsageSummary, compare_versions, parse_semver, normalize_domain
)
from services import process_agent_payload, get_dashboard_stats, invalidate_policy_rules_cache
from usage_service import get_device_usage_data

# Configuração de Logging Profissional
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("GivovaMonitor")


def get_r2_download_strategy():
    """Reads the download strategy from the current process environment."""
    return os.getenv("R2_DOWNLOAD_STRATEGY", "redirect").strip().lower()


logger.info("R2 download strategy: %s", get_r2_download_strategy())

app = Flask(__name__)
app.config.from_object(Config)
app.permanent_session_lifetime = timedelta(days=7)

# Middleware para Proxy Reverso (Render, Nginx, Docker) garantindo HTTPS e IPs reais
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

db.init_app(app)
install_sql_query_counter()


@app.before_request
def start_request_telemetry():
    """Starts aggregate-only request accounting without retaining sensitive data."""
    import time
    g.telemetry_started_at = time.perf_counter()
    g.telemetry_sql_queries = 0


@app.after_request
def record_request_telemetry(response):
    import time
    started_at = getattr(g, "telemetry_started_at", time.perf_counter())
    endpoint = request.url_rule.rule if request.url_rule else "unmatched"
    telemetry.record_request(
        method=request.method,
        endpoint=endpoint,
        status_code=response.status_code,
        request_bytes=request.content_length or 0,
        response_bytes=response_size_bytes(response),
        duration_ms=(time.perf_counter() - started_at) * 1000.0,
        sql_queries=getattr(g, "telemetry_sql_queries", 0),
    )
    telemetry.maybe_emit(logger)
    return response


@app.after_request
def add_cache_headers(response):
    """
    Desativa cache do navegador para HTML do painel e APIs de administração.
    Garante que atualizações na interface e status de rollout sejam imediatamente visíveis aos administradores.
    """
    if request.path == "/" or request.path.startswith("/api/admin/") or (response.mimetype and response.mimetype == "text/html"):
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response


# =====================================================================
# Middleware & Decorators
# =====================================================================

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            if request.path.startswith("/api/"):
                return jsonify({"error": "Não autenticado", "code": "UNAUTHORIZED"}), 401
            return redirect(url_for("login_page", next=request.path))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """
    Exige autenticação e papel administrativo (role == 'admin') para operações sensíveis.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            if request.path.startswith("/api/"):
                return jsonify({"error": "Não autenticado", "code": "UNAUTHORIZED"}), 401
            return redirect(url_for("login_page", next=request.path))
        if session.get("role") != "admin":
            return jsonify({"error": "Acesso restrito a administradores", "code": "FORBIDDEN"}), 403
        return f(*args, **kwargs)
    return decorated_function


def get_app_timezone():
    """
    Retorna o fuso horário corporativo via ZoneInfo (Config.APP_TIMEZONE).
    Elimina dependência de APP_TIMEZONE_OFFSET_HOURS (deprecated).
    """
    return get_corporate_timezone(Config.APP_TIMEZONE)


def get_start_of_day_app_tz() -> datetime:
    """
    Calcula o início do dia local da empresa (00:00:00) convertido para UTC ingênuo (naive).
    Garante precisão independente do fuso horário em que o servidor estiver hospedado.
    """
    return start_of_local_day_utc(tz_name=Config.APP_TIMEZONE)


def require_agent_token(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # 1. Extração estruturada de tokens por cabeçalho e payload JSON
        sent_agent_token = request.headers.get("X-Agent-Token")
        sent_device_token = request.headers.get("X-Device-Token")
        auth = request.headers.get("Authorization")
        if auth and auth.startswith("Bearer "):
            auth = auth.replace("Bearer ", "", 1).strip()

        payload_data = request.get_json(silent=True) or {}
        payload_token = payload_data.get("token") or payload_data.get("agent_token")
        payload_device_token = payload_data.get("device_token")
        device_uuid = request.headers.get("X-Device-UUID") or payload_data.get("uuid")

        effective_agent_token = sent_agent_token or payload_token or auth
        effective_device_token = sent_device_token or payload_device_token

        request.authenticated_device = None

        # 2. Se informado device_uuid, localiza o dispositivo no banco
        if device_uuid:
            dev = Device.query.filter_by(uuid=device_uuid).first()
            if dev:
                request.authenticated_device = dev
                # Proteção anti-spoofing: se o dispositivo tem device_token cadastrado
                if dev.device_token:
                    if effective_device_token:
                        if effective_device_token.strip() == dev.device_token.strip():
                            return f(*args, **kwargs)
                        else:
                            logger.warning(f"Tentativa de spoofing/token divergente para UUID '{device_uuid}' de {request.remote_addr}")
                            return jsonify({"error": "Token individual do dispositivo inválido"}), 401

        # 3. Validação pelo AGENT_SECRET_TOKEN corporativo compartilhado
        expected_token = Config.AGENT_SECRET_TOKEN
        if expected_token:
            candidate = effective_agent_token or effective_device_token
            if not candidate or candidate.strip() != expected_token.strip():
                logger.warning(f"Tentativa de acesso ao agente com token inválido de {request.remote_addr}")
                return jsonify({"error": "Token de autenticação do agente inválido ou ausente"}), 401
        else:
            logger.error(f"Tentativa de acesso ao agente rejeitada: AGENT_SECRET_TOKEN não configurado no servidor ({request.remote_addr})")
            return jsonify({"error": "Autenticação do agente não configurada no servidor"}), 401

        return f(*args, **kwargs)
    return decorated_function


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response


@app.teardown_appcontext
def shutdown_session(exception=None):
    """
    Garante limpeza e rollback automático da sessão SQLAlchemy em caso de exceção,
    evitando transações PostgreSQL abortadas residuais entre requisições.
    """
    if exception:
        try:
            db.session.rollback()
        except Exception:
            pass
    try:
        db.session.remove()
    except Exception:
        pass


# =====================================================================
# Rotas de Health Check & Diagnóstico
# =====================================================================

@app.route("/health")
def health_check():
    """
    Endpoint de checagem de integridade para monitoramento de infraestrutura e orquestradores de nuvem.
    Utiliza conexão direta de engine para não poluir nem abortar a sessão ORM.
    """
    db_ok = False
    try:
        with db.engine.connect() as conn:
            conn.execute(db.text("SELECT 1"))
            db_ok = True
    except Exception as e:
        logger.error(f"Health check falhou no banco de dados: {e}")

    status_code = 200 if db_ok else 503
    return jsonify({
        "status": "ok" if db_ok else "unhealthy",
        "service": "Givova Transportes - Monitoramento de PCs",
        "database": "connected" if db_ok else "disconnected",
        "timestamp": format_iso_utc(utc_now())
    }), status_code


@app.route("/health/db")
def health_db_check():
    """
    Endpoint dedicado para diagnóstico da conexão com o banco de dados sem expor credenciais.
    """
    db_ok = False
    engine_dialect = "unknown"
    try:
        with db.engine.connect() as conn:
            conn.execute(db.text("SELECT 1"))
            db_ok = True
        engine_dialect = db.engine.dialect.name
    except Exception as e:
        logger.error(f"Health check DB falhou: {e}")

    status_code = 200 if db_ok else 503
    return jsonify({
        "status": "ok" if db_ok else "unhealthy",
        "database": "connected" if db_ok else "disconnected",
        "engine": engine_dialect,
        "timestamp": format_iso_utc(utc_now())
    }), status_code


# =====================================================================
# Rotas de Autenticação Web
# =====================================================================

@app.route("/login", methods=["GET", "POST"])
def login_page():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session.permanent = True
            session["user_id"] = user.id
            session["username"] = user.username
            session["role"] = user.role
            user.last_login = datetime.now(timezone.utc)
            db.session.commit()
            logger.info(f"Usuário {username} realizou login com sucesso de {request.remote_addr}")
            next_url = request.args.get("next") or url_for("painel")
            return redirect(next_url)
        else:
            logger.warning(f"Tentativa de login inválida para '{username}' de {request.remote_addr}")
            flash("Usuário ou senha incorretos.", "danger")

    return render_template("login.html")


@app.route("/logout", methods=["GET", "POST"])
def logout():
    username = session.get("username")
    session.clear()
    logger.info(f"Usuário {username} deslogou do sistema")
    return redirect(url_for("login_page"))


# =====================================================================
# Rotas de Páginas Administrativas (HTML)
# =====================================================================

@app.route("/")
@login_required
def painel():
    return render_template("index.html", user=session.get("username"))


# =====================================================================
# Rotas de Ingestão de Métricas (Agente)
# =====================================================================

@app.route("/monitoramento", methods=["POST"])
@app.route("/api/agent/report", methods=["POST"])
@require_agent_token
def receber_dados_agente():
    """
    Endpoint autenticado de recepção periódica de métricas dos computadores.
    """
    dados = request.get_json(silent=True)
    if not dados:
        return jsonify({"error": "Payload JSON inválido ou vazio"}), 400

    try:
        device = process_agent_payload(dados)
        logger.info(f"Métricas recebidas com sucesso de {device.hostname} ({device.ip_address}) - CPU: {device.last_cpu}% | RAM: {device.last_ram}%")
        idle_threshold = int(SystemMetadata.get_value("idle_threshold_seconds", str(Config.IDLE_THRESHOLD_SECONDS)))
        return jsonify({
            "status": "ok",
            "message": "Dados processados com sucesso",
            "device_id": device.id,
            "status_computed": device.get_status(Config.OFFLINE_THRESHOLD_SECONDS),
            "idle_threshold_seconds": idle_threshold
        })
    except ValueError as ve:
        logger.warning(f"Erro de validação em payload de {request.remote_addr}: {ve}")
        return jsonify({"error": str(ve)}), 422
    except Exception as e:
        db.session.rollback()
        logger.error(f"Erro ao processar dados do agente: {e}", exc_info=True)
        return jsonify({"error": "Erro interno ao processar dados"}), 500


# =====================================================================
# Rotas de API para o Painel Web (Protegidas)
# =====================================================================

@app.route("/dados")
@login_required
def dados_retrocomp():
    """
    Mantém compatibilidade com a rota legada /dados, retornando o dicionário indexado pelo hostname.
    """
    devices = Device.query.all()
    resultado = {}
    for d in devices:
        resultado[d.hostname] = d.to_dict(Config.OFFLINE_THRESHOLD_SECONDS)
    return jsonify(resultado)


@app.route("/api/devices")
@login_required
def listar_dispositivos():
    """
    Lista todos os computadores monitorados com suporte a busca, filtro por setor e status.
    Suporta DEMO_MODE opcional com computadores virtuais em memória identificados com is_demo=True.
    """
    search = request.args.get("search", "").strip().lower()
    department = request.args.get("department", "").strip()
    status_filter = request.args.get("status", "").strip()

    # 1. Dispositivos reais cadastrados no banco
    real_devices = Device.query.order_by(Device.updated_at.desc()).all()
    all_items = [d.to_dict(Config.OFFLINE_THRESHOLD_SECONDS) for d in real_devices]

    today_date = get_local_date()
    today_summaries = {
        s.device_id: s.to_dict()
        for s in DailyUsageSummary.query.filter(DailyUsageSummary.date == today_date).all()
    }
    for item in all_items:
        item["today_usage"] = today_summaries.get(item["id"])

    # 2. Se DEMO_MODE estiver ativo, anexa os dispositivos virtuais de demonstração
    if Config.DEMO_MODE:
        from demo_data import get_demo_devices
        all_items.extend(get_demo_devices())

    # 3. Aplica filtros de busca, departamento e status
    filtered = []
    for item in all_items:
        if search:
            match = (
                search in str(item.get("hostname", "")).lower() or
                search in str(item.get("display_name", "")).lower() or
                search in str(item.get("user_name", "")).lower() or
                search in str(item.get("ip_address", "")).lower()
            )
            if not match:
                continue

        if department and department != "Todos":
            if item.get("department") != department:
                continue

        if status_filter and status_filter != "Todos":
            if str(item.get("status", "")).lower() != status_filter.lower():
                continue

        filtered.append(item)

    return jsonify(filtered)


@app.route("/api/devices/<int:device_id>")
@login_required
def detalhes_dispositivo(device_id):
    """
    Retorna os detalhes completos de um computador específico, incluindo métricas recentes e alertas.
    """
    # Se for dispositivo virtual de demonstração
    if Config.DEMO_MODE and device_id >= 90000:
        from demo_data import get_demo_device
        demo_data = get_demo_device(device_id)
        if demo_data:
            return jsonify(demo_data)

    device = db.get_or_404(Device, device_id)

    # Busca últimas 60 métricas históricas para o gráfico temporal
    metrics = MetricHistory.query.filter_by(device_id=device.id)\
        .order_by(MetricHistory.timestamp.asc())\
        .limit(60).all()

    alerts = Alert.query.filter_by(device_id=device.id)\
        .order_by(Alert.created_at.desc())\
        .limit(10).all()

    # Cálculo de métricas de Políticas e Segurança para a modal do dispositivo
    now = datetime.now(timezone.utc)
    twenty_four_h = now - timedelta(hours=24)
    seven_d = now - timedelta(days=7)

    policy_events_24h = PolicyEvent.query.filter(PolicyEvent.device_id == device.id, PolicyEvent.last_seen >= twenty_four_h).count()
    policy_events_7d = PolicyEvent.query.filter(PolicyEvent.device_id == device.id, PolicyEvent.last_seen >= seven_d).count()
    critical_events = PolicyEvent.query.filter(PolicyEvent.device_id == device.id, PolicyEvent.severity == "critical").count()
    warning_events = PolicyEvent.query.filter(PolicyEvent.device_id == device.id, PolicyEvent.severity == "warning").count()
    last_event = PolicyEvent.query.filter_by(device_id=device.id).order_by(PolicyEvent.last_seen.desc()).first()

    policy_summary = {
        "events_24h": policy_events_24h,
        "events_7d": policy_events_7d,
        "critical_count": critical_events,
        "warning_count": warning_events,
        "last_event": last_event.to_dict() if last_event else None,
        "last_classified_domain": device.active_domain or "—"
    }

    return jsonify({
        "device": device.to_dict(Config.OFFLINE_THRESHOLD_SECONDS),
        "metrics": [m.to_dict() for m in metrics],
        "alerts": [a.to_dict() for a in alerts],
        "policy_summary": policy_summary
    })


@app.route("/api/devices/<int:device_id>/metrics")
@login_required
def historico_metricas_dispositivo(device_id):
    """
    Retorna o histórico de métricas para gráficos com limite configurável.
    """
    limit = min(int(request.args.get("limit", 60)), 300)

    # Se for dispositivo virtual de demonstração
    if Config.DEMO_MODE and device_id >= 90000:
        from demo_data import get_demo_metrics_history
        return jsonify(get_demo_metrics_history(device_id, limit))

    metrics = MetricHistory.query.filter_by(device_id=device_id)\
        .order_by(MetricHistory.timestamp.desc())\
        .limit(limit).all()
    # Inverte para ordem cronológica crescente para renderização no gráfico
    metrics.reverse()
    return jsonify([m.to_dict() for m in metrics])


@app.route("/api/devices/<int:device_id>/edit", methods=["POST"])
@login_required
def editar_dispositivo(device_id):
    """
    Permite atualizar o nome amigável e o setor do computador.
    Dispositivos de demonstração são protegidos contra edição.
    """
    if device_id >= 90000:
        return jsonify({
            "error": "Dispositivos do Modo de Demonstração são somente leitura e não podem ser editados.",
            "code": "DEMO_DEVICE_READONLY"
        }), 400

    device = db.get_or_404(Device, device_id)
    data = request.get_json(silent=True) or request.form

    display_name = data.get("display_name")
    department = data.get("department")
    is_admin = data.get("is_admin_device")
    gen_token = data.get("generate_token")

    if display_name is not None:
        device.display_name = display_name.strip()
    if department is not None:
        device.department = department.strip()
    if is_admin is not None:
        device.is_admin_device = bool(is_admin)
    if gen_token:
        device.device_token = secrets.token_hex(24)

    db.session.commit()
    logger.info(f"Dispositivo {device.hostname} atualizado: nome='{device.display_name}', setor='{device.department}', admin={device.is_admin_device}")
    return jsonify({"status": "ok", "device": device.to_dict(Config.OFFLINE_THRESHOLD_SECONDS, Config.LATEST_AGENT_VERSION)})


@app.route("/api/devices/<int:device_id>", methods=["DELETE"])
@login_required
def remover_dispositivo(device_id):
    """
    Remove o computador e seu histórico do sistema.
    Dispositivos de demonstração são protegidos contra remoção.
    """
    if device_id >= 90000:
        return jsonify({
            "error": "Dispositivos do Modo de Demonstração são somente leitura e não podem ser removidos.",
            "code": "DEMO_DEVICE_READONLY"
        }), 400

    device = db.get_or_404(Device, device_id)
    hostname = device.hostname
    db.session.delete(device)
    db.session.commit()
    logger.info(f"Dispositivo {hostname} (id {device_id}) removido pelo usuário {session.get('username')}")
    return jsonify({"status": "ok", "message": f"Computador {hostname} removido com sucesso."})


@app.route("/api/devices/<int:device_id>/usage")
@login_required
def obter_uso_dispositivo(device_id):
    """
    Retorna o histórico de tempo de uso real, ociosidade e timeline de um computador.
    """
    if device_id >= 90000:
        from demo_data import get_demo_device_usage
        return jsonify(get_demo_device_usage(device_id))

    device = db.get_or_404(Device, device_id)
    date_str = request.args.get("date")
    start_date_str = request.args.get("start_date")
    end_date_str = request.args.get("end_date")
    data = get_device_usage_data(device.id, date_str, start_date_str, end_date_str)
    return jsonify(data)


@app.route("/api/settings/idle-threshold", methods=["GET"])
@login_required
def obter_idle_threshold():
    """
    Retorna o limite de tempo configurado para considerar um computador ocioso.
    """
    val = int(SystemMetadata.get_value("idle_threshold_seconds", str(Config.IDLE_THRESHOLD_SECONDS)))
    return jsonify({"idle_threshold_seconds": val})


@app.route("/api/settings/idle-threshold", methods=["POST"])
@admin_required
def salvar_idle_threshold():
    """
    Atualiza o limite corporativo de tempo para ociosidade (30 a 3600 segundos).
    Sincronizado automaticamente com os agentes no próximo report.
    """
    body = request.get_json(silent=True) or {}
    val = body.get("idle_threshold_seconds")
    try:
        val = int(val)
        if val < 30 or val > 3600:
            return jsonify({"error": "O limite de ociosidade deve estar entre 30 e 3600 segundos."}), 400
        SystemMetadata.set_value("idle_threshold_seconds", str(val))
        logger.info(f"Limite corporativo de ociosidade atualizado para {val}s por {session.get('username')}")
        return jsonify({"status": "ok", "idle_threshold_seconds": val})
    except (TypeError, ValueError):
        return jsonify({"error": "Valor numérico inválido."}), 400


@app.route("/api/stats")
@login_required
def estatisticas_dashboard():
    """
    Retorna métricas agregadas do dashboard geral.
    """
    stats = get_dashboard_stats()
    return jsonify(stats)


@app.route("/api/alerts")
@login_required
def listar_alertas():
    """
    Lista alertas recentes com opção de filtrar por status (ativos/resolvidos).
    Suporta DEMO_MODE com alertas virtuais em memória.
    """
    status = request.args.get("status", "active")
    query = Alert.query

    if status == "active":
        query = query.filter_by(is_resolved=False)
    elif status == "resolved":
        query = query.filter_by(is_resolved=True)

    alerts = query.order_by(Alert.created_at.desc()).limit(100).all()
    result = [a.to_dict() for a in alerts]

    # Se DEMO_MODE estiver ativo e buscando alertas ativos, anexa os alertas virtuais
    if Config.DEMO_MODE and status != "resolved":
        from demo_data import get_demo_alerts
        result = get_demo_alerts() + result

    return jsonify(result)


@app.route("/api/alerts/<int:alert_id>/resolve", methods=["POST"])
@login_required
def resolver_alerta(alert_id):
    """
    Marca um alerta como resolvido manualmente.
    """
    if alert_id >= 9000:
        return jsonify({
            "status": "ok",
            "message": "Alerta de demonstração marcado como resolvido (simulação)."
        })

    alert = db.get_or_404(Alert, alert_id)
    alert.is_resolved = True
    alert.resolved_at = datetime.now(timezone.utc)
    db.session.commit()
    return jsonify({"status": "ok", "alert": alert.to_dict()})



@app.route("/api/alerts/resolve-all", methods=["POST"])
@login_required
def resolver_todos_alertas():
    """
    Marca todos os alertas ativos como resolvidos.
    """
    now = datetime.now(timezone.utc)
    Alert.query.filter_by(is_resolved=False).update({"is_resolved": True, "resolved_at": now})
    db.session.commit()
    return jsonify({"status": "ok", "message": "Todos os alertas foram marcados como resolvidos."})


# =====================================================================
# Rotas de Auto-Update do Agente & Gestão de Releases
# =====================================================================

# =====================================================================
# Rotas de Auto-Update do Agente & Gestão de Releases (Rollout Canary)
# =====================================================================

@app.route("/api/agent/update", methods=["GET", "POST"])
@require_agent_token
def checar_atualizacao_agente():
    """
    Endpoint autenticado para consulta periódica de atualização pelo agente.
    Suporta Rollout Progressivo (Canary e Stable Global) com seleção SemVer determinística.
    Compatível com GET (query string) e POST (JSON) do Agent 1.4.1.
    """
    import functools

    body = request.get_json(silent=True) or {}
    current_version = (
        request.args.get("current_version") or request.args.get("agent_version") or request.args.get("version") or
        body.get("current_version") or body.get("agent_version") or body.get("version") or "1.0.0"
    ).strip()
    device_uuid = (
        request.args.get("uuid") or request.args.get("device_uuid") or
        body.get("uuid") or body.get("device_uuid") or
        request.headers.get("X-Device-UUID")
    )

    device = getattr(request, "authenticated_device", None)
    if not device and device_uuid:
        device = Device.query.filter_by(uuid=device_uuid).first()

    now = datetime.now(timezone.utc)
    if device:
        device.last_update_check = now

    # Tokens enviados pelo cliente para autenticação estrita
    sent_device_token = request.headers.get("X-Device-Token")
    sent_agent_token = request.headers.get("X-Agent-Token") or request.headers.get("Authorization") or ""
    if sent_agent_token.startswith("Bearer "):
        sent_agent_token = sent_agent_token.replace("Bearer ", "", 1).strip()

    # 1. Verifica se existem releases cadastradas no banco de dados
    has_any_release_in_db = db.session.query(AgentRelease.id).first() is not None
    if not has_any_release_in_db:
        # Fallback de compatibilidade quando nenhuma release foi cadastrada em banco ainda
        manifest_path = os.path.join(Config.RELEASES_DIR, "manifest.json")
        manifest = {
            "version": Config.LATEST_AGENT_VERSION,
            "minimum_supported_version": "1.0.0",
            "required": False,
            "sha256": "",
            "release_notes": "Atualização de estabilidade e suporte a políticas corporativas.",
            "download_url": f"/api/agent/download/{Config.LATEST_AGENT_VERSION}",
            "release_channel": "stable",
            "rollout_scope": "global"
        }
        if os.path.exists(manifest_path):
            try:
                with open(manifest_path, "r", encoding="utf-8") as f:
                    saved_m = json.load(f)
                    if isinstance(saved_m, dict):
                        manifest.update(saved_m)
            except Exception as e:
                logger.warning(f"Erro ao ler manifesto de release {manifest_path}: {e}")

        latest_version = manifest.get("version", Config.LATEST_AGENT_VERSION)
        has_update = compare_versions(latest_version, current_version) > 0
        target_sha256 = manifest.get("sha256", "")
        download_url = manifest.get("download_url", f"/api/agent/download/{latest_version}")

        if device:
            device.update_status = "update_available" if has_update else "up_to_date"
            db.session.commit()

        return jsonify({
            "update_available": has_update,
            "version": latest_version,
            "latest_version": latest_version,
            "target_version": latest_version,
            "current_version": current_version,
            "download_url": download_url,
            "sha256": target_sha256,
            "update_id": f"{latest_version}-{int(now.timestamp())}",
            "required": manifest.get("required", False),
            "release_notes": manifest.get("release_notes", ""),
            "release_channel": manifest.get("release_channel", "stable"),
            "rollout_scope": manifest.get("rollout_scope", "global"),
            "server_time": format_iso_utc(now)
        })

    active_releases = AgentRelease.query.filter_by(status="active").all()
    eligible = []

    for rel in active_releases:
        # A versão deve ser estritamente mais nova que a versão corrente do agente
        if compare_versions(rel.version, current_version) <= 0:
            continue

        # Deve satisfazer a versão mínima suportada pela release
        if rel.min_supported_version and compare_versions(current_version, rel.min_supported_version) < 0:
            continue

        # 2. Avaliação de Escopo e Canal de Rollout
        if rel.release_channel == "stable" and rel.rollout_scope == "global":
            # Release Global estável: elegível para qualquer dispositivo autenticado
            eligible.append(rel)

        elif rel.release_channel == "canary" and rel.rollout_scope == "devices":
            # Release Canary: elegível SOMENTE para dispositivos explicitamente autorizados
            if not device or not device_uuid or device.uuid != device_uuid:
                continue

            # Verifica se o dispositivo está na lista de alvos da release
            is_targeted = any(td.id == device.id for td in rel.target_devices)
            if not is_targeted:
                continue

            # Proteção 1: Autenticação Forte do Device Canary
            if sent_device_token:
                if not device.device_token or sent_device_token.strip() != device.device_token.strip():
                    logger.warning(
                        f"[CANARY SECURITY] Tentativa de obter release Canary v{rel.version} para {device.hostname} "
                        f"rejeitada: device_token divergente do token individual do dispositivo."
                    )
                    continue
            else:
                # Fallback para Agent 1.4.1 (sem device_token no config): valida contra AGENT_SECRET_TOKEN
                if not sent_agent_token or sent_agent_token.strip() != (Config.AGENT_SECRET_TOKEN or "").strip():
                    logger.warning(
                        f"[CANARY SECURITY] Tentativa de obter release Canary v{rel.version} para {device.hostname} "
                        f"rejeitada: token compartilhado ausente ou inválido."
                    )
                    continue

            # Dispositivo autenticado e autorizado para Canary
            eligible.append(rel)

    # 3. Seleção SemVer Determinística: escolhe a maior versão elegível (ex: 1.10.0 > 1.9.0)
    chosen_release = None
    if eligible:
        eligible.sort(key=functools.cmp_to_key(lambda a, b: compare_versions(a.version, b.version)), reverse=True)
        chosen_release = eligible[0]

    if chosen_release:
        has_update = True
        latest_version = chosen_release.version
        target_sha256 = chosen_release.sha256
        download_url = chosen_release.download_url or f"/api/agent/download/{chosen_release.version}"
        manifest = {
            "version": chosen_release.version,
            "minimum_supported_version": chosen_release.min_supported_version or "1.0.0",
            "required": chosen_release.mandatory,
            "sha256": target_sha256,
            "release_notes": chosen_release.changelog or "Atualização de estabilidade e suporte a políticas corporativas.",
            "download_url": download_url,
            "release_channel": chosen_release.release_channel,
            "rollout_scope": chosen_release.rollout_scope
        }
    else:
        has_update = False
        latest_version = current_version
        target_sha256 = ""
        download_url = ""
        manifest = {
            "version": current_version,
            "minimum_supported_version": "1.0.0",
            "required": False,
            "sha256": "",
            "release_notes": "",
            "download_url": "",
            "release_channel": "stable",
            "rollout_scope": "global"
        }

    if device:
        device.update_status = "update_available" if has_update else "up_to_date"
        db.session.commit()

    return jsonify({
        "update_available": has_update,
        "version": latest_version,
        "latest_version": latest_version,
        "target_version": latest_version,
        "current_version": current_version,
        "download_url": download_url,
        "sha256": target_sha256,
        "update_id": f"{latest_version}-{int(now.timestamp())}",
        "required": manifest.get("required", False),
        "release_notes": manifest.get("release_notes", ""),
        "release_channel": manifest.get("release_channel", "stable"),
        "rollout_scope": manifest.get("rollout_scope", "global"),
        "server_time": format_iso_utc(now)
    })


@app.route("/api/agent/download/<path:version>", methods=["GET"])
@app.route("/api/agent/update/download/<path:version>", methods=["GET"])
@require_agent_token
def baixar_versao_agente(version):
    """
    Entrega o binário executável autenticado para o agente.
    Protegido contra directory traversal e restrito a dispositivos autorizados em releases Canary.
    Prioriza binário no banco de dados com hash SHA-256 verificado.
    """
    clean_version = version.strip().lstrip("vV")
    if not all(c.isalnum() or c == "." for c in clean_version) or ".." in clean_version:
        return jsonify({"error": "Formato de versão inválido", "code": "INVALID_VERSION"}), 400

    # 1. Localiza a release no banco de dados (sem carregar o BLOB pesado preventivamente)
    rel = AgentRelease.query.filter_by(version=clean_version).first()
    if not rel:
        # Fallback para filesystem se release não estiver em banco
        exe_path = os.path.join(Config.RELEASES_DIR, clean_version, "GivovaMonitorAgent.exe")
        if not os.path.exists(exe_path):
            exe_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dist", "GivovaMonitorAgent.exe")
        if not os.path.exists(exe_path):
            return jsonify({"error": f"Executável da versão {clean_version} não encontrado no servidor."}), 404

        return send_file(
            exe_path,
            as_attachment=True,
            download_name=f"GivovaMonitorAgent-v{clean_version}.exe",
            mimetype="application/octet-stream"
        )

    # 2. Se a release estiver pausada ou draft, proíbe download
    if rel.status in ("paused", "draft"):
        return jsonify({"error": f"A release v{clean_version} está com status '{rel.status}' e não está disponível para download."}), 403

    # 3. Se a release for Canary, valida que o dispositivo requisitante está expressamente autorizado
    if rel.release_channel == "canary" and rel.rollout_scope == "devices":
        device_uuid = request.headers.get("X-Device-UUID") or request.args.get("uuid")
        device = getattr(request, "authenticated_device", None)
        if not device and device_uuid:
            device = Device.query.filter_by(uuid=device_uuid).first()

        if not device or not any(td.id == device.id for td in rel.target_devices):
            logger.warning(f"[SECURITY] Tentativa de download não autorizada da release Canary v{clean_version} por {request.remote_addr} (UUID: {device_uuid}).")
            return jsonify({"error": "Dispositivo não autorizado para download desta release Canary.", "code": "CANARY_UNAUTHORIZED"}), 403

    download_filename = f"GivovaMonitorAgent-v{clean_version}.exe"

    # 4. Resolução de Armazenamento
    # 4.1. Cloudflare R2 (Armazenamento Principal de Alta Performance)
    if rel.storage_type == "r2" and rel.object_key:
        if storage_service.is_r2_configured():
            try:
                if get_r2_download_strategy() == "stream":
                    # Modo Streaming através do Render (opcional)
                    telemetry.record_release_attempt("r2_stream")
                    return Response(
                        track_release_stream(
                            storage_service.download_stream(rel.object_key),
                            mode="r2_stream",
                        ),
                        mimetype="application/octet-stream",
                        headers={
                            "Content-Disposition": f'attachment; filename="{download_filename}"',
                            **({"Content-Length": str(rel.file_size)} if rel.file_size is not None else {})
                        }
                    )
                else:
                    # Padrão: Redirecionamento 302 para Presigned URL de curta duração no Cloudflare R2
                    # O Agent 1.4.1 (requests) segue o redirect automaticamente de forma transparente.
                    presigned_url = storage_service.generate_presigned_download_url(
                        rel.object_key,
                        expires_in=Config.R2_PRESIGNED_URL_EXPIRES_SECONDS,
                        filename=download_filename
                    )
                    telemetry.record_release_attempt("r2_redirect")
                    return redirect(presigned_url, code=302)
            except Exception as e:
                logger.warning(f"Falha ao gerar download via Cloudflare R2 para v{clean_version}: {e}")

        # Fallback controlado para banco de dados caso R2 falhe temporariamente
        if Config.R2_FALLBACK_TO_DATABASE and rel.binary_data:
            logger.warning("R2 unavailable; using temporary database fallback")
            telemetry.record_release_attempt("database_fallback")
            telemetry.record_release_bytes("database_fallback", len(rel.binary_data))
            return send_file(
                io.BytesIO(rel.binary_data),
                as_attachment=True,
                download_name=download_filename,
                mimetype="application/octet-stream"
            )
        else:
            return jsonify({
                "error": f"Armazenamento da release v{clean_version} temporariamente indisponível.",
                "code": "STORAGE_UNAVAILABLE"
            }), 503

    # 4.2. Armazenamento Legado no Banco de Dados
    if rel.binary_data:
        telemetry.record_release_attempt("database")
        telemetry.record_release_bytes("database", len(rel.binary_data))
        return send_file(
            io.BytesIO(rel.binary_data),
            as_attachment=True,
            download_name=download_filename,
            mimetype="application/octet-stream"
        )
    elif rel.download_url and rel.download_url.startswith(("http://", "https://")):
        telemetry.record_release_attempt("external_redirect")
        return redirect(rel.download_url)

    # 5. Fallback para arquivo em disco local
    exe_candidates = [
        os.path.join(Config.RELEASES_DIR, clean_version, "GivovaMonitorAgent.exe"),
        os.path.join(Config.RELEASES_DIR, f"v{clean_version}", "GivovaMonitorAgent.exe"),
        os.path.join(Config.RELEASES_DIR, "GivovaMonitorAgent.exe"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "dist", "GivovaMonitorDeploy", "GivovaMonitorAgent.exe"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "dist", "GivovaMonitorAgent.exe")
    ]
    target_exe = None
    for cand in exe_candidates:
        if os.path.exists(cand):
            target_exe = cand
            break

    if not target_exe:
        logger.warning(f"Executável da versão {clean_version} não encontrado no repositório de releases.")
        return jsonify({"error": f"Executável da versão {clean_version} não disponível para download no servidor."}), 404

    telemetry.record_release_attempt("filesystem")
    telemetry.record_release_bytes("filesystem", os.path.getsize(target_exe))
    return send_file(
        target_exe,
        as_attachment=True,
        download_name=f"GivovaMonitorAgent-v{clean_version}.exe",
        mimetype="application/octet-stream"
    )


@app.route("/api/admin/releases", methods=["GET"])
@admin_required
def listar_releases_agente():
    """
    Lista todas as releases de agentes com canal, escopo, status e alvos Canary.
    """
    releases = AgentRelease.query.order_by(AgentRelease.created_at.desc()).all()
    return jsonify({
        "success": True,
        "releases": [r.to_dict() for r in releases]
    })


@app.route("/api/admin/releases/publish", methods=["POST"])
@admin_required
def publicar_release_agente():
    """
    Endpoint administrativo para registrar ou atualizar release com suporte a Rollout Canary.
    Valida invariantes rígidas (canary+devices ou stable+global), calcula SHA-256 no servidor
    e protege contra modificações em releases ativas (imutabilidade).
    """
    data = request.form if request.form else (request.get_json(silent=True) or {})
    version = data.get("version")
    provided_sha256 = (data.get("sha256") or "").strip().lower()
    release_notes = data.get("release_notes", "")
    required = str(data.get("required", "")).lower() in ("true", "1", "yes")
    external_url = data.get("download_url")

    raw_channel = str(data.get("release_channel", "stable")).strip().lower()
    raw_scope = str(data.get("rollout_scope", "global")).strip().lower()
    raw_status = str(data.get("status", "active")).strip().lower()

    if not version:
        return jsonify({"error": "O campo 'version' é obrigatório."}), 400

    clean_version = version.strip().lstrip("vV")

    # Invariantes Rígidas de Release
    if raw_channel not in ("canary", "stable"):
        return jsonify({"error": "Canal inválido. Valores permitidos: 'canary', 'stable'."}), 400
    if raw_scope not in ("devices", "global"):
        return jsonify({"error": "Escopo inválido. Valores permitidos: 'devices', 'global'."}), 400
    if raw_status not in ("draft", "active", "paused", "superseded"):
        return jsonify({"error": "Status inválido. Valores permitidos: 'draft', 'active', 'paused', 'superseded'."}), 400

    if raw_channel == "canary" and raw_scope != "devices":
        return jsonify({"error": "Releases Canary devem possuir escopo 'devices'."}), 400
    if raw_channel == "stable" and raw_scope != "global":
        return jsonify({"error": "Releases Stable devem possuir escopo 'global'."}), 400

    # Imutabilidade de Release Ativa (User Protection 6)
    existing_rel = AgentRelease.query.filter_by(version=clean_version).first()
    has_uploaded_file = ("executable" in request.files) or ("file" in request.files)
    if existing_rel and existing_rel.status == "active":
        if has_uploaded_file or (external_url and external_url != existing_rel.download_url):
            return jsonify({
                "error": f"A release v{clean_version} já está ativa e é imutável. Para publicar novo código, lance uma nova versão (ex: 1.5.1)."
            }), 400

    # Leitura e cálculo de SHA-256 dos bytes efetivos pelo servidor (User Protection 2)
    file_bytes = None
    target_dir = os.path.join(Config.RELEASES_DIR, clean_version)
    os.makedirs(target_dir, exist_ok=True)

    uploaded_file = request.files.get("executable") or request.files.get("file")
    if uploaded_file and uploaded_file.filename:
        file_bytes = uploaded_file.read()
        dest_path = os.path.join(target_dir, "GivovaMonitorAgent.exe")
        with open(dest_path, "wb") as f:
            f.write(file_bytes)

    if not file_bytes:
        # Se não enviou arquivo no multipart, tenta buscar de dist/GivovaMonitorDeploy local
        deploy_exe = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dist", "GivovaMonitorDeploy", "GivovaMonitorAgent.exe")
        if os.path.exists(deploy_exe):
            with open(deploy_exe, "rb") as f:
                file_bytes = f.read()

    server_calculated_sha = None
    if file_bytes:
        import hashlib
        server_calculated_sha = hashlib.sha256(file_bytes).hexdigest().lower()
        if provided_sha256 and provided_sha256 != server_calculated_sha:
            return jsonify({
                "error": f"SHA-256 fornecido ({provided_sha256}) diverge do hash calculado pelo servidor ({server_calculated_sha}). Publicação abortada."
            }), 400

    sha256_final = server_calculated_sha or provided_sha256 or (existing_rel.sha256 if existing_rel else "")

    rel = existing_rel
    if not rel:
        rel = AgentRelease(version=clean_version)
        db.session.add(rel)

    rel.sha256 = sha256_final
    rel.download_url = external_url or f"/api/agent/download/{clean_version}"
    rel.changelog = release_notes
    rel.mandatory = bool(required)
    rel.release_channel = raw_channel
    rel.rollout_scope = raw_scope
    rel.status = raw_status
    rel.created_by = session.get("username", "admin")
    if file_bytes:
        rel.file_size = len(file_bytes)
        if storage_service.is_r2_configured():
            try:
                object_key = f"agents/{clean_version}/GivovaMonitorAgent.exe"
                upload_source = dest_path if ('dest_path' in locals() and os.path.exists(dest_path)) else None
                if not upload_source:
                    import tempfile
                    with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tf:
                        tf.write(file_bytes)
                        upload_source = tf.name

                storage_service.upload_file(
                    local_path=upload_source,
                    object_key=object_key,
                    metadata={"version": clean_version, "sha256": sha256_final}
                )
                rel.storage_type = "r2"
                rel.object_key = object_key
                rel.binary_data = file_bytes  # Preserva binary_data para fallback de segurança
                logger.info(f"Release v{clean_version} enviada e registrada no Cloudflare R2 ({object_key}).")
            except Exception as e:
                logger.warning(f"Falha no upload para R2 durante publicação, mantendo fallback de banco: {e}")
                rel.storage_type = "database"
                rel.binary_data = file_bytes
        else:
            rel.storage_type = "database"
            rel.binary_data = file_bytes
    elif external_url:
        rel.storage_type = "external"

    # Alvos Canary (se fornecido device_ids)
    target_ids = data.get("target_device_ids")
    if target_ids:
        if isinstance(target_ids, str):
            try:
                target_ids = json.loads(target_ids)
            except Exception:
                target_ids = [int(x.strip()) for x in target_ids.split(",") if x.strip().isdigit()]
        if isinstance(target_ids, list):
            target_devices = Device.query.filter(Device.id.in_(target_ids)).all()
            rel.target_devices = target_devices

    manifest_data = {
        "version": clean_version,
        "sha256": sha256_final,
        "required": bool(required),
        "release_notes": release_notes,
        "download_url": rel.download_url,
        "release_channel": rel.release_channel,
        "rollout_scope": rel.rollout_scope,
        "status": rel.status,
        "published_at": format_iso_utc(utc_now()),
        "published_by": session.get("username", "admin")
    }

    manifest_root = os.path.join(Config.RELEASES_DIR, "manifest.json")
    try:
        with open(manifest_root, "w", encoding="utf-8") as f:
            json.dump(manifest_data, f, indent=2)
    except Exception:
        pass

    action_label = "agent_release_canary_enabled" if raw_channel == "canary" else "agent_release_published"
    audit = PolicyAuditLog(
        user_name=session.get("username", "admin"),
        action=action_label,
        details=f"Publicada release v{clean_version} | Canal: {raw_channel} | Escopo: {raw_scope} | SHA-256: {sha256_final}."
    )
    db.session.add(audit)
    db.session.commit()

    logger.info(f"Release v{clean_version} publicada com sucesso (Canal: {raw_channel}, Escopo: {raw_scope}).")
    return jsonify({"status": "ok", "release": rel.to_dict(), "manifest": manifest_data})


@app.route("/api/admin/releases/<int:release_id>/promote", methods=["POST"])
@admin_required
def promover_release_agente(release_id):
    """
    Promove uma release Canary para Stable/Global.
    Preserva rigorosamente o binário, URL e hash SHA-256 sem necessidade de recompilação.
    """
    rel = db.get_or_404(AgentRelease, release_id)

    if rel.release_channel != "canary":
        return jsonify({"error": f"Apenas releases no canal 'canary' podem ser promovidas. Release v{rel.version} está em '{rel.release_channel}'."}), 400

    old_sha = rel.sha256
    rel.release_channel = "stable"
    rel.rollout_scope = "global"
    rel.status = "active"
    rel.updated_at = datetime.now(timezone.utc)

    # Invariante: SHA-256 e binário permanecem rigorosamente idênticos
    assert rel.sha256 == old_sha, "Violação crítica: o hash SHA-256 da release foi corrompido durante a promoção!"

    audit = PolicyAuditLog(
        user_name=session.get("username", "admin"),
        action="agent_release_promoted_global",
        details=f"Release v{rel.version} promovida com sucesso de Canary para Stable/Global. SHA-256 preservado: {rel.sha256}."
    )
    db.session.add(audit)
    db.session.commit()

    logger.info(f"[PROMOÇÃO GLOBAL] Release v{rel.version} promovida para Stable/Global por {session.get('username')}.")
    return jsonify({
        "status": "ok",
        "message": f"Release v{rel.version} promovida com sucesso para toda a frota.",
        "release": rel.to_dict()
    })


@app.route("/api/admin/releases/<int:release_id>/pause", methods=["POST"])
@admin_required
def pausar_release_agente(release_id):
    """
    Pausa a distribuição de uma release para novos computadores sem causar downgrade em máquinas já atualizadas.
    """
    rel = db.get_or_404(AgentRelease, release_id)
    rel.status = "paused"
    rel.updated_at = datetime.now(timezone.utc)

    audit = PolicyAuditLog(
        user_name=session.get("username", "admin"),
        action="agent_release_paused",
        details=f"Rollout da release v{rel.version} pausado pelo administrador."
    )
    db.session.add(audit)
    db.session.commit()

    logger.info(f"Rollout da release v{rel.version} pausado por {session.get('username')}.")
    return jsonify({"status": "ok", "message": f"Rollout da versão v{rel.version} pausado com sucesso.", "release": rel.to_dict()})


@app.route("/api/admin/releases/<int:release_id>/resume", methods=["POST"])
@admin_required
def retomar_release_agente(release_id):
    """
    Retoma o rollout de uma release que estava pausada.
    """
    rel = db.get_or_404(AgentRelease, release_id)
    rel.status = "active"
    rel.updated_at = datetime.now(timezone.utc)

    audit = PolicyAuditLog(
        user_name=session.get("username", "admin"),
        action="agent_release_resumed",
        details=f"Rollout da release v{rel.version} retomado com status 'active'."
    )
    db.session.add(audit)
    db.session.commit()

    logger.info(f"Rollout da release v{rel.version} retomado por {session.get('username')}.")
    return jsonify({"status": "ok", "message": f"Rollout da versão v{rel.version} retomado.", "release": rel.to_dict()})


@app.route("/api/admin/releases/<int:release_id>/targets", methods=["POST"])
@admin_required
def atualizar_alvos_release(release_id):
    """
    Adiciona ou remove computadores de teste da lista de alvos de uma release Canary.
    """
    rel = db.get_or_404(AgentRelease, release_id)
    if rel.release_channel != "canary":
        return jsonify({"error": "Alvos de teste só podem ser definidos para releases no canal 'canary'."}), 400

    data = request.get_json(silent=True) or {}
    device_ids = data.get("device_ids", [])
    if not isinstance(device_ids, list):
        return jsonify({"error": "O campo 'device_ids' deve ser uma lista de IDs de computadores."}), 400

    target_devices = Device.query.filter(Device.id.in_(device_ids)).all()
    rel.target_devices = target_devices
    rel.updated_at = datetime.now(timezone.utc)

    target_names = ", ".join(d.hostname for d in target_devices)
    audit = PolicyAuditLog(
        user_name=session.get("username", "admin"),
        action="agent_release_targets_updated",
        details=f"Alvos Canary da release v{rel.version} atualizados: {len(target_devices)} computadores ({target_names or 'Nenhum'})."
    )
    db.session.add(audit)
    db.session.commit()

    logger.info(f"Alvos da release Canary v{rel.version} atualizados por {session.get('username')}: {target_names}")
    return jsonify({
        "status": "ok",
        "message": f"Alvos atualizados com sucesso ({len(target_devices)} computadores autorizados).",
        "release": rel.to_dict()
    })


@app.route("/api/admin/releases/<int:release_id>/rollout-progress", methods=["GET"])
@admin_required
def obter_progresso_rollout(release_id):
    """
    Retorna o progresso factual e comprovável do rollout da release na frota de computadores.
    Não inventa status: distingue estritamente entre Atualizado, Aguardando, Offline e Não Elegível.
    """
    rel = db.get_or_404(AgentRelease, release_id)
    target_ids = {td.id for td in rel.target_devices}

    # Dispositivos reais cadastrados no sistema
    real_devices = Device.query.filter(Device.id < 90000).order_by(Device.hostname.asc()).all()

    devices_list = []
    updated_count = 0
    pending_count = 0
    offline_count = 0
    not_targeted_count = 0

    for d in real_devices:
        is_targeted = (d.id in target_ids)
        is_eligible = (rel.rollout_scope == "global") or is_targeted
        status_computed = d.get_status(Config.OFFLINE_THRESHOLD_SECONDS)
        is_updated = (compare_versions(d.agent_version or "1.0.0", rel.version) >= 0)

        if is_updated:
            item_status = "updated"
            item_label = "Atualizado"
            updated_count += 1
        elif status_computed == "offline":
            item_status = "offline"
            item_label = "Offline"
            offline_count += 1
        elif is_eligible:
            item_status = "pending"
            item_label = "Aguardando"
            pending_count += 1
        else:
            item_status = "not_targeted"
            item_label = "Fora do Rollout"
            not_targeted_count += 1

        devices_list.append({
            "id": d.id,
            "hostname": d.hostname,
            "display_name": d.display_name or d.hostname,
            "user_name": d.user_name or "—",
            "department": d.department or "—",
            "current_version": d.agent_version or "1.0.0",
            "target_version": rel.version,
            "status": item_status,
            "status_label": item_label,
            "is_targeted": is_targeted,
            "is_eligible": is_eligible,
            "last_contact_iso": format_iso_utc(d.updated_at),
            "last_contact": format_local_datetime(d.updated_at)
        })

    # Ordenação Determinística Estável: departamento ASC, display_name ASC, hostname ASC, id ASC
    devices_list.sort(key=lambda x: (
        (x.get("department") or "").lower(),
        (x.get("display_name") or x.get("hostname") or "").lower(),
        (x.get("hostname") or "").lower(),
        x.get("id") or 0
    ))

    online_eligible_count = updated_count + pending_count
    progress_pct = round((updated_count / online_eligible_count * 100.0), 1) if online_eligible_count > 0 else 0.0

    # summary é a fonte de verdade canônica oficial; counts é mantido como alias de compatibilidade
    summary_data = {
        "total_devices": len(real_devices),
        "updated_count": updated_count,
        "pending_count": pending_count,
        "offline_count": offline_count,
        "not_targeted_count": not_targeted_count,
        "online_eligible_count": online_eligible_count,
        "progress_percent": progress_pct
    }
    counts_alias = {
        "total_devices": len(real_devices),
        "updated": updated_count,
        "pending_update": pending_count,
        "offline": offline_count,
        "not_targeted": not_targeted_count,
        "online_eligible": online_eligible_count,
        "online_eligible_count": online_eligible_count,
        "progress_percent": progress_pct,
        "progress_pct": progress_pct
    }

    return jsonify({
        "success": True,
        "release": rel.to_dict(),
        "summary": summary_data,
        "counts": counts_alias,
        "devices": devices_list
    })


# =====================================================================
# Rotas de Políticas de Uso Corporativo (Regras & Ocorrências)
# =====================================================================

@app.route("/api/policies/rules", methods=["GET"])
@login_required
def listar_regras_politicas():
    """
    Lista todas as regras corporativas configuradas com suporte a DEMO_MODE.
    """
    rules = PolicyRule.query.order_by(PolicyRule.created_at.desc()).all()
    result = [r.to_dict() for r in rules]

    if Config.DEMO_MODE:
        from demo_data import get_demo_policy_rules
        result = get_demo_policy_rules() + result

    return jsonify(result)


@app.route("/api/policies/rules", methods=["POST"])
@login_required
def criar_regra_politica():
    """
    Cadastra nova regra corporativa de site ou aplicativo.
    Invalida o cache em memória imediatamente.
    """
    data = request.get_json(silent=True) or request.form
    name = (data.get("name") or "").strip()
    rule_type = (data.get("rule_type") or "domain").strip().lower()
    pattern = (data.get("pattern") or "").strip()
    category = (data.get("category") or "Outro").strip()
    severity = (data.get("severity") or "warning").strip().lower()
    scope_type = (data.get("scope_type") or "global").strip().lower()
    scope_target = (data.get("scope_target") or "Todos").strip()
    action = (data.get("action") or "alert").strip().lower()

    if not name or not pattern:
        return jsonify({"error": "Nome e padrão (domínio ou executável) são obrigatórios."}), 400

    if rule_type not in ("domain", "application"):
        return jsonify({"error": "Tipo de regra deve ser 'domain' ou 'application'."}), 400

    if severity not in ("info", "warning", "critical"):
        severity = "warning"

    if scope_type not in ("global", "department", "device"):
        scope_type = "global"

    rule = PolicyRule(
        name=name,
        rule_type=rule_type,
        pattern=pattern,
        category=category,
        severity=severity,
        scope_type=scope_type,
        scope_target=scope_target if scope_type != "global" else "Todos",
        action=action,
        enabled=True
    )
    db.session.add(rule)

    audit = PolicyAuditLog(
        user_name=session.get("username", "admin"),
        action="RULE_CREATED",
        details=f"Criada regra '{name}' [{rule_type}: {pattern}] Categoria: {category} ({severity})"
    )
    db.session.add(audit)
    db.session.commit()

    invalidate_policy_rules_cache()
    logger.info(f"Nova regra de política '{name}' criada pelo usuário {session.get('username')}.")
    return jsonify({"status": "ok", "rule": rule.to_dict()}), 201


@app.route("/api/policies/rules/<int:rule_id>/edit", methods=["POST"])
@login_required
def editar_regra_politica(rule_id):
    """
    Atualiza os parâmetros de uma regra existente.
    """
    if rule_id >= 9000:
        return jsonify({"error": "Regras de demonstração são somente leitura.", "code": "DEMO_RULE_READONLY"}), 400

    rule = db.get_or_404(PolicyRule, rule_id)
    data = request.get_json(silent=True) or request.form

    if data.get("name"):
        rule.name = data["name"].strip()
    if data.get("pattern"):
        rule.pattern = data["pattern"].strip()
    if data.get("category"):
        rule.category = data["category"].strip()
    if data.get("severity") in ("info", "warning", "critical"):
        rule.severity = data["severity"].strip()
    if data.get("scope_type") in ("global", "department", "device"):
        rule.scope_type = data["scope_type"].strip()
        rule.scope_target = data.get("scope_target", "Todos").strip()
    if data.get("enabled") is not None:
        rule.enabled = bool(data["enabled"])

    rule.updated_at = datetime.now(timezone.utc)

    audit = PolicyAuditLog(
        user_name=session.get("username", "admin"),
        action="RULE_UPDATED",
        details=f"Regra {rule.id} ('{rule.name}') atualizada."
    )
    db.session.add(audit)
    db.session.commit()

    invalidate_policy_rules_cache()
    return jsonify({"status": "ok", "rule": rule.to_dict()})


@app.route("/api/policies/rules/<int:rule_id>/toggle", methods=["POST"])
@login_required
def alternar_regra_politica(rule_id):
    """
    Ativa ou desativa rapidamente uma regra corporativa.
    """
    if rule_id >= 9000:
        return jsonify({"error": "Regras de demonstração não podem ser alteradas.", "code": "DEMO_RULE_READONLY"}), 400

    rule = db.get_or_404(PolicyRule, rule_id)
    rule.enabled = not rule.enabled
    rule.updated_at = datetime.now(timezone.utc)

    audit = PolicyAuditLog(
        user_name=session.get("username", "admin"),
        action="RULE_UPDATED",
        details=f"Regra {rule.id} ('{rule.name}') alterada para {'habilitada' if rule.enabled else 'desabilitada'}."
    )
    db.session.add(audit)
    db.session.commit()

    invalidate_policy_rules_cache()
    return jsonify({"status": "ok", "enabled": rule.enabled, "rule": rule.to_dict()})


@app.route("/api/policies/rules/<int:rule_id>", methods=["DELETE"])
@login_required
def excluir_regra_politica(rule_id):
    """
    Remove uma regra corporativa do sistema.
    """
    if rule_id >= 9000:
        return jsonify({"error": "Regras de demonstração não podem ser excluídas.", "code": "DEMO_RULE_READONLY"}), 400

    rule = db.get_or_404(PolicyRule, rule_id)
    name = rule.name
    db.session.delete(rule)

    audit = PolicyAuditLog(
        user_name=session.get("username", "admin"),
        action="RULE_DELETED",
        details=f"Regra '{name}' (id {rule_id}) removida."
    )
    db.session.add(audit)
    db.session.commit()

    invalidate_policy_rules_cache()
    logger.info(f"Regra de política '{name}' (id {rule_id}) removida por {session.get('username')}.")
    return jsonify({"status": "ok", "message": f"Regra '{name}' removida com sucesso."})


@app.route("/api/policies/rules/bulk-action", methods=["POST"])
@login_required
def acao_em_massa_regras_politicas():
    """
    Executa ações em lote sobre regras de políticas:
    - activate: habilita regras selecionadas
    - deactivate: desabilita regras selecionadas
    - set_severity: altera severidade (info, warning, critical)
    - set_category: altera categoria
    - delete: remove regras selecionadas
    Somente administradores. Ignora IDs de demo (>= 9000).
    """
    if session.get("role") != "admin":
        return jsonify({"error": "Acesso negado: apenas administradores podem executar ações em lote."}), 403

    data = request.get_json(silent=True) or {}
    action = (data.get("action") or "").strip().lower()
    rule_ids = data.get("rule_ids") or []

    if not isinstance(rule_ids, list) or len(rule_ids) == 0:
        return jsonify({"error": "Nenhuma regra selecionada para a ação."}), 400

    # Filtra IDs de demonstração e inválidos
    has_demo = any(str(rid).isdigit() and int(rid) >= 9000 for rid in rule_ids)
    valid_ids = [int(rid) for rid in rule_ids if str(rid).isdigit() and int(rid) < 9000]
    if has_demo and not valid_ids:
        return jsonify({"error": "Regras de demonstração são protegidas e não podem ser alteradas ou excluídas."}), 403
    if not valid_ids:
        return jsonify({"error": "Nenhuma regra válida selecionada."}), 400

    rules = PolicyRule.query.filter(PolicyRule.id.in_(valid_ids)).all()
    if not rules:
        return jsonify({"error": "Nenhuma regra encontrada no banco de dados para os IDs informados."}), 404

    count_affected = len(rules)
    user = session.get("username", "admin")

    if action == "activate":
        for r in rules:
            r.enabled = True
            r.updated_at = datetime.now(timezone.utc)
        audit_msg = f"Ativação em massa de {count_affected} regras de política."
    elif action == "deactivate":
        for r in rules:
            r.enabled = False
            r.updated_at = datetime.now(timezone.utc)
        audit_msg = f"Desativação em massa de {count_affected} regras de política."
    elif action == "set_severity":
        new_sev = (data.get("severity") or data.get("value") or "").strip().lower()
        if new_sev not in ("info", "warning", "critical"):
            return jsonify({"error": "Severidade inválida. Deve ser 'info', 'warning' ou 'critical'."}), 400
        for r in rules:
            r.severity = new_sev
            r.updated_at = datetime.now(timezone.utc)
        audit_msg = f"Alteração de severidade para '{new_sev}' em {count_affected} regras de política."
    elif action == "set_category":
        new_cat = (data.get("category") or data.get("value") or "").strip()
        if not new_cat:
            return jsonify({"error": "Categoria não informada."}), 400
        for r in rules:
            r.category = new_cat
            r.updated_at = datetime.now(timezone.utc)
        audit_msg = f"Alteração de categoria para '{new_cat}' em {count_affected} regras de política."
    elif action == "delete":
        for r in rules:
            db.session.delete(r)
        audit_msg = f"Exclusão em massa de {count_affected} regras de política."
    else:
        return jsonify({"error": f"Ação desconhecida: '{action}'."}), 400

    audit = PolicyAuditLog(
        user_name=user,
        action="RULES_BULK_ACTION",
        details=audit_msg
    )
    db.session.add(audit)
    db.session.commit()

    invalidate_policy_rules_cache()
    logger.info(f"{audit_msg} Executado por {user}.")
    return jsonify({
        "status": "ok",
        "action": action,
        "affected": count_affected,
        "message": audit_msg
    })


@app.route("/api/policies/rules/import-csv", methods=["POST"])
@login_required
def importar_regras_csv():
    """
    Importa regras de políticas a partir de arquivo CSV ou texto CSV.
    Formato esperado:
    domain,category,severity,action,scope
    Exemplo:
    example.com,games,warning,alert,global
    """
    if session.get("role") != "admin":
        return jsonify({"error": "Acesso negado: apenas administradores podem importar regras."}), 403

    import csv

    csv_text = ""
    if "file" in request.files:
        file = request.files["file"]
        if file and file.filename:
            csv_text = file.read().decode("utf-8-sig", errors="ignore")
    else:
        data = request.get_json(silent=True) or request.form
        csv_text = data.get("csv_content") or ""

    if not csv_text.strip():
        return jsonify({"error": "Conteúdo CSV não fornecido."}), 400

    reader = csv.reader(io.StringIO(csv_text.strip()))
    header = None
    imported_count = 0
    skipped_duplicates = 0
    invalid_count = 0
    errors = []

    existing_domain_rules = PolicyRule.query.filter_by(rule_type="domain").all()
    existing_patterns = {normalize_domain(r.pattern) for r in existing_domain_rules}

    row_num = 0
    for row in reader:
        row_num += 1
        if not row or all(c.strip() == "" for c in row):
            continue

        clean_row = [c.strip() for c in row]

        # Detecta cabeçalho
        if header is None:
            first_col = clean_row[0].lower()
            if first_col in ("domain", "dominio", "pattern", "padrao", "url"):
                header = [c.lower() for c in clean_row]
                continue
            else:
                header = ["domain", "category", "severity", "action", "scope"]

        dom = clean_row[0] if len(clean_row) > 0 else ""
        cat = "other"
        sev = "warning"
        act = "alert"
        sc = "global"

        if "domain" in header:
            idx = header.index("domain")
            if idx < len(clean_row): dom = clean_row[idx]
        elif len(clean_row) > 0:
            dom = clean_row[0]

        if "category" in header:
            idx = header.index("category")
            if idx < len(clean_row) and clean_row[idx]: cat = clean_row[idx].lower()
        elif len(clean_row) > 1 and clean_row[1]:
            cat = clean_row[1].lower()

        if "severity" in header:
            idx = header.index("severity")
            if idx < len(clean_row) and clean_row[idx]: sev = clean_row[idx].lower()
        elif len(clean_row) > 2 and clean_row[2]:
            sev = clean_row[2].lower()

        if "action" in header:
            idx = header.index("action")
            if idx < len(clean_row) and clean_row[idx]: act = clean_row[idx].lower()
        elif len(clean_row) > 3 and clean_row[3]:
            act = clean_row[3].lower()

        if "scope" in header:
            idx = header.index("scope")
            if idx < len(clean_row) and clean_row[idx]: sc = clean_row[idx].lower()
        elif len(clean_row) > 4 and clean_row[4]:
            sc = clean_row[4].lower()

        # Validação do domínio
        clean_dom = normalize_domain(dom)
        if not clean_dom or "." not in clean_dom or len(clean_dom) < 4 or " " in clean_dom or "/" in clean_dom:
            errors.append(f"Linha {row_num}: Domínio inválido '{dom}'.")
            invalid_count += 1
            continue

        if clean_dom in existing_patterns:
            skipped_duplicates += 1
            continue

        if sev not in ("info", "warning", "critical"):
            sev = "warning"
        if act not in ("alert", "log", "allow"):
            act = "alert"
        if sc not in ("global", "department", "device"):
            sc = "global"

        rule = PolicyRule(
            name=f"[{cat}] {clean_dom}",
            rule_type="domain",
            pattern=clean_dom,
            category=cat,
            severity=sev,
            scope_type=sc,
            scope_target="Todos" if sc == "global" else "",
            action=act,
            enabled=True,
            source_provider="import"
        )
        db.session.add(rule)
        existing_patterns.add(clean_dom)
        imported_count += 1

    total_skipped = skipped_duplicates + invalid_count

    if imported_count > 0:
        audit = PolicyAuditLog(
            user_name=session.get("username", "admin"),
            action="RULES_IMPORTED_CSV",
            details=f"Importação CSV: {imported_count} regras inseridas, {skipped_duplicates} duplicadas ignoradas, {invalid_count} inválidas."
        )
        db.session.add(audit)
        db.session.commit()
        invalidate_policy_rules_cache()
        logger.info(f"Importação CSV concluída: {imported_count} inseridas, {skipped_duplicates} duplicadas, {invalid_count} inválidas por {session.get('username')}.")

    return jsonify({
        "status": "ok",
        "imported": imported_count,
        "import_count": imported_count,
        "skipped": total_skipped,
        "skipped_duplicates": skipped_duplicates,
        "invalid_count": invalid_count,
        "errors": errors[:10]
    })


@app.route("/api/policies/events", methods=["GET"])
@login_required
def listar_eventos_politicas():
    """
    Lista ocorrências de violação de políticas com filtros avançados, ordenação (first_seen DESC) e paginação server-side.
    Suporta DEMO_MODE com dados virtuais em memória.
    """
    status_filter = request.args.get("status", "all").strip().lower()
    severity_filter = request.args.get("severity", "").strip()
    dept_filter = request.args.get("department", "").strip()
    category_filter = request.args.get("category", "").strip()
    source_filter = request.args.get("source", "").strip()
    period_filter = request.args.get("period", "").strip().lower()
    search_query = request.args.get("search", request.args.get("q", "")).strip()
    format_opt = request.args.get("format", "").strip().lower()

    try:
        page = max(1, int(request.args.get("page", 1)))
    except (ValueError, TypeError):
        page = 1

    try:
        per_page = min(max(1, int(request.args.get("per_page", 25))), 100)
    except (ValueError, TypeError):
        per_page = 25

    query = PolicyEvent.query.join(Device, isouter=True)

    # 1. Filtro por Status / Aba
    if status_filter == "active":
        query = query.filter(PolicyEvent.status == "active")
    elif status_filter == "closed":
        query = query.filter(PolicyEvent.status == "closed")
    elif status_filter == "recognized":
        query = query.filter(PolicyEvent.acknowledged == True)
    elif status_filter == "critical":
        query = query.filter(PolicyEvent.severity == "critical")
    # 'all' ou vazio: não filtra por status, retorna histórico completo

    # 2. Filtro por Severidade
    if severity_filter and severity_filter != "Todos":
        query = query.filter(PolicyEvent.severity == severity_filter.lower())

    # 3. Filtro por Departamento / Setor
    if dept_filter and dept_filter != "Todos":
        query = query.filter(Device.department == dept_filter)

    # 4. Filtro por Categoria
    if category_filter and category_filter != "Todos":
        query = query.filter(PolicyEvent.category == category_filter)

    # 5. Filtro por Origem
    if source_filter and source_filter != "Todos":
        query = query.filter(PolicyEvent.source == source_filter)

    # 6. Filtro por Período
    now_utc = datetime.now(timezone.utc)
    if period_filter == "today":
        start_today, next_start = get_local_day_range_utc()
        query = query.filter(PolicyEvent.first_seen >= start_today, PolicyEvent.first_seen < next_start)
    elif period_filter == "7d":
        cutoff_7d = (now_utc - timedelta(days=7)).replace(tzinfo=None)
        query = query.filter(PolicyEvent.first_seen >= cutoff_7d)
    elif period_filter == "30d":
        cutoff_30d = (now_utc - timedelta(days=30)).replace(tzinfo=None)
        query = query.filter(PolicyEvent.first_seen >= cutoff_30d)

    # 7. Busca Textual
    if search_query:
        term = f"%{search_query.lower()}%"
        query = query.filter(db.or_(
            db.func.lower(Device.hostname).like(term),
            db.func.lower(Device.display_name).like(term),
            db.func.lower(Device.user_name).like(term),
            db.func.lower(Device.department).like(term),
            db.func.lower(PolicyEvent.domain).like(term),
            db.func.lower(PolicyEvent.application).like(term),
            db.func.lower(PolicyEvent.category).like(term)
        ))

    # Ordenação padrão: mais recentes primeiro (first_seen DESC)
    query = query.order_by(PolicyEvent.first_seen.desc(), PolicyEvent.id.desc())

    total = query.count()
    events = query.offset((page - 1) * per_page).limit(per_page).all()
    result = [e.to_dict() for e in events]

    if Config.DEMO_MODE and page == 1 and status_filter in ("all", "active"):
        from demo_data import get_demo_policy_events
        demo_events = get_demo_policy_events()
        if status_filter == "active":
            demo_events = [d for d in demo_events if d.get("status") == "active"]
        result = demo_events + result
        total += len(demo_events)

    has_page_param = "page" in request.args or request.args.get("paginate") == "true" or format_opt == "paginated"
    if has_page_param and format_opt != "list":
        pages = max(1, (total + per_page - 1) // per_page)
        return jsonify({
            "items": result,
            "total": total,
            "page": page,
            "per_page": per_page,
            "pages": pages
        })

    return jsonify(result)


@app.route("/api/policies/events/<int:event_id>/acknowledge", methods=["POST"])
@login_required
def reconhecer_evento_politica(event_id):
    """
    Marca uma ocorrência de política como reconhecida pelo operador de TI.
    """
    if event_id >= 9000:
        return jsonify({"status": "ok", "message": "Ocorrência de demonstração reconhecida (simulação)."})

    event = db.get_or_404(PolicyEvent, event_id)
    event.acknowledged = True
    event.acknowledged_at = datetime.now(timezone.utc)
    event.acknowledged_by = session.get("username", "admin")

    audit = PolicyAuditLog(
        user_name=session.get("username", "admin"),
        action="EVENT_ACKNOWLEDGED",
        details=f"Ocorrência {event_id} ({event.category} em {event.device.hostname if event.device else '—'}) reconhecida."
    )
    db.session.add(audit)
    db.session.commit()
    return jsonify({"status": "ok", "event": event.to_dict()})


@app.route("/api/policies/events/<int:event_id>/resolve", methods=["POST"])
@login_required
def resolver_evento_politica(event_id):
    """
    Marca uma ocorrência de política como tratada/resolvida manualmente por um administrador de TI.
    Preserva a distinção entre encerramento automático da atividade (status='closed') e resolução manual.
    """
    if event_id >= 9000:
        return jsonify({"status": "ok", "message": "Ocorrência de demonstração resolvida (simulação)."})

    event = db.get_or_404(PolicyEvent, event_id)
    now = datetime.now(timezone.utc)
    event.resolved_at = now
    event.resolved_by = session.get("username", "admin")

    audit = PolicyAuditLog(
        user_name=session.get("username", "admin"),
        action="EVENT_RESOLVED",
        details=f"Ocorrência {event_id} ({event.category} em {event.device.hostname if event.device else '—'}) marcada como resolvida por {session.get('username', 'admin')}."
    )
    db.session.add(audit)
    db.session.commit()
    return jsonify({"status": "ok", "event": event.to_dict()})


@app.route("/api/policies/events/<int:event_id>", methods=["DELETE"])
@admin_required
def excluir_evento_politica(event_id):
    """
    Exclui manualmente uma ocorrência do histórico operacional.
    Exige papel de administrador e gera registro de auditoria em PolicyAuditLog.
    """
    if event_id >= 9000:
        return jsonify({"status": "ok", "message": "Ocorrência de demonstração excluída (simulação)."})

    event = db.get_or_404(PolicyEvent, event_id)
    dev_name = event.device.hostname if event.device else "—"
    target = event.domain or event.application or "—"
    category = event.category

    audit = PolicyAuditLog(
        user_name=session.get("username", "admin"),
        action="policy_event_deleted",
        details=f"Ocorrência {event.id} ({category} - {target} em {dev_name}) excluída manualmente por {session.get('username', 'admin')}."
    )
    db.session.add(audit)
    db.session.delete(event)
    db.session.commit()

    logger.info(f"Ocorrência de política {event_id} excluída por {session.get('username', 'admin')}.")
    return jsonify({"status": "ok", "message": f"Ocorrência {event_id} removida com sucesso."})


@app.route("/api/policies/events/bulk-delete", methods=["POST"])
@admin_required
def excluir_eventos_em_massa():
    """
    Exclusão em massa de ocorrências de políticas corporativas.
    Modos estritos:
    - 'selected_ids': Exclui lista de event_ids especificados. Exige confirm_active=True se houver ativas.
    - 'cleanup_older_than': Limpa ocorrências encerradas (closed) com mais de N dias.
    Rejeita combinações ambíguas com status 400.
    """
    data = request.get_json(silent=True) or {}
    mode = str(data.get("mode", "")).strip().lower()

    if mode == "selected_ids":
        event_ids = data.get("event_ids")
        if not isinstance(event_ids, list) or len(event_ids) == 0:
            return jsonify({
                "error": "Parâmetro 'event_ids' deve ser uma lista não vazia de identificadores.",
                "code": "INVALID_EVENT_IDS"
            }), 400

        if "days" in data or "filter_closed_older_than_days" in data:
            return jsonify({
                "error": "Não misture o modo 'selected_ids' com filtros de dias.",
                "code": "AMBIGUOUS_BULK_PAYLOAD"
            }), 400

        # Filtra apenas IDs válidos de inteiros
        valid_ids = [int(i) for i in event_ids if str(i).isdigit()]
        real_ids = [i for i in valid_ids if i < 9000]

        # Verifica se existem ocorrências ativas entre as selecionadas
        active_count = PolicyEvent.query.filter(PolicyEvent.id.in_(real_ids), PolicyEvent.status == "active").count()
        if active_count > 0 and not data.get("confirm_active"):
            return jsonify({
                "error": f"Existem {active_count} ocorrências ativas selecionadas. Confirme explicitamente a exclusão de ocorrências ativas.",
                "code": "CONFIRM_ACTIVE_REQUIRED",
                "active_count": active_count
            }), 400

        targets = PolicyEvent.query.filter(PolicyEvent.id.in_(real_ids)).all()
        deleted_count = len(targets)

        audit = PolicyAuditLog(
            user_name=session.get("username", "admin"),
            action="policy_event_deleted",
            details=f"Exclusão em massa de {deleted_count} ocorrências selecionadas realizada por {session.get('username', 'admin')}."
        )
        db.session.add(audit)

        for event in targets:
            db.session.delete(event)

        db.session.commit()
        logger.info(f"Exclusão em massa de {deleted_count} ocorrências de políticas realizada por {session.get('username')}.")
        return jsonify({
            "status": "ok",
            "deleted_count": deleted_count,
            "mode": "selected_ids"
        })

    elif mode == "cleanup_older_than":
        if "event_ids" in data:
            return jsonify({
                "error": "Não misture o modo 'cleanup_older_than' com lista de 'event_ids'.",
                "code": "AMBIGUOUS_BULK_PAYLOAD"
            }), 400

        days_val = data.get("days") or data.get("filter_closed_older_than_days")
        try:
            days_int = int(days_val)
            if days_int <= 0:
                raise ValueError()
        except (ValueError, TypeError):
            return jsonify({
                "error": "Parâmetro 'days' deve ser um número inteiro positivo.",
                "code": "INVALID_DAYS"
            }), 400

        cutoff_utc = datetime.now(timezone.utc) - timedelta(days=days_int)
        cutoff_naive = cutoff_utc.replace(tzinfo=None)

        # Remove apenas ocorrências que estejam estritamente ENCERRADAS (closed)
        closed_targets = PolicyEvent.query.filter(
            PolicyEvent.status == "closed",
            PolicyEvent.first_seen < cutoff_naive
        ).all()
        deleted_count = len(closed_targets)

        audit = PolicyAuditLog(
            user_name=session.get("username", "admin"),
            action="policy_event_deleted",
            details=f"Limpeza de {deleted_count} ocorrências encerradas há mais de {days_int} dias realizada por {session.get('username', 'admin')}."
        )
        db.session.add(audit)

        for event in closed_targets:
            db.session.delete(event)

        db.session.commit()
        logger.info(f"Limpeza de {deleted_count} ocorrências encerradas (> {days_int} dias) realizada por {session.get('username')}.")
        return jsonify({
            "status": "ok",
            "deleted_count": deleted_count,
            "mode": "cleanup_older_than",
            "days": days_int
        })

    else:
        return jsonify({
            "error": "Modo de exclusão em massa inválido. Especifique 'mode': 'selected_ids' ou 'mode': 'cleanup_older_than'.",
            "code": "INVALID_BULK_MODE"
        }), 400


@app.route("/api/policies/stats", methods=["GET"])
@login_required
def estatisticas_politicas():
    """
    Relatório consolidado de violações de políticas para gestão de risco e conformidade.
    Calcula indicadores temporais (como ocorrências hoje) respeitando o fuso horário da empresa.
    """
    start_today, next_start = get_local_day_range_utc()

    active_rules_count = PolicyRule.query.filter_by(enabled=True).count()
    active_violations_count = PolicyEvent.query.filter_by(status="active").count()
    today_violations_count = PolicyEvent.query.filter(PolicyEvent.first_seen >= start_today, PolicyEvent.first_seen < next_start).count()
    critical_active_count = PolicyEvent.query.filter(PolicyEvent.severity == "critical", PolicyEvent.status == "active").count()

    all_events = PolicyEvent.query.all()
    events_dicts = [e.to_dict() for e in all_events]

    if Config.DEMO_MODE:
        from demo_data import get_demo_policy_events
        demo_events = get_demo_policy_events()
        events_dicts = demo_events + events_dicts
        active_violations_count += sum(1 for d in demo_events if d.get("status") == "active")
        today_violations_count += len(demo_events)
        critical_active_count += sum(1 for d in demo_events if d.get("severity") == "critical" and d.get("status") == "active")

    categories_count = {}
    departments_count = {}
    severity_count = {"critical": 0, "warning": 0, "info": 0}

    for e in events_dicts:
        cat = e.get("category") or "Outro"
        categories_count[cat] = categories_count.get(cat, 0) + 1

        dept = e.get("department") or "Outro"
        departments_count[dept] = departments_count.get(dept, 0) + 1

        sev = e.get("severity", "warning").lower()
        if sev in severity_count:
            severity_count[sev] += 1

    return jsonify({
        "app_timezone": Config.APP_TIMEZONE,
        "server_time_iso": format_iso_utc(utc_now()),
        "active_rules": active_rules_count,
        "active_violations": active_violations_count,
        "today_violations": today_violations_count,
        "critical_violations": critical_active_count,
        "total_events": len(events_dicts),
        "active_events": active_violations_count,
        "by_category": categories_count,
        "by_department": departments_count,
        "by_severity": severity_count
    })


@app.route("/api/policies/allowlist", methods=["GET"])
@login_required
def listar_allowlists():
    """
    Lista todas as liberações corporativas (Allowlist).
    """
    allowlists = PolicyAllowlist.query.order_by(PolicyAllowlist.created_at.desc()).all()
    return jsonify([al.to_dict() for al in allowlists])


@app.route("/api/policies/allowlist", methods=["POST"])
@login_required
def criar_allowlist():
    """
    Cadastra uma nova liberação de site ou aplicativo (Allowlist).
    """
    data = request.get_json(silent=True) or request.form
    pattern = (data.get("pattern") or "").strip()
    target_type = (data.get("target_type") or "domain").strip().lower()
    scope_type = (data.get("scope_type") or "global").strip().lower()
    scope_target = (data.get("scope_target") or "Todos").strip()
    reason = (data.get("reason") or "").strip()

    if not pattern:
        return jsonify({"error": "O padrão (domínio ou executável) é obrigatório."}), 400

    al = PolicyAllowlist(
        pattern=pattern,
        target_type=target_type if target_type in ("domain", "application") else "domain",
        scope_type=scope_type if scope_type in ("global", "department", "device") else "global",
        scope_target=scope_target if scope_type != "global" else "Todos",
        reason=reason,
        enabled=True,
        created_by=session.get("username", "admin")
    )
    db.session.add(al)

    audit = PolicyAuditLog(
        user_name=session.get("username", "admin"),
        action="ALLOWLIST_CREATED",
        details=f"Criada liberação para '{pattern}' [{target_type}] Escopo: {scope_type} ({scope_target})"
    )
    db.session.add(audit)
    db.session.commit()

    invalidate_policy_rules_cache()
    return jsonify({"status": "ok", "allowlist": al.to_dict()}), 201


@app.route("/api/policies/allowlist/<int:allow_id>", methods=["DELETE"])
@login_required
def excluir_allowlist(allow_id):
    """
    Remove uma liberação corporativa.
    """
    al = db.get_or_404(PolicyAllowlist, allow_id)
    pat = al.pattern
    db.session.delete(al)

    audit = PolicyAuditLog(
        user_name=session.get("username", "admin"),
        action="ALLOWLIST_DELETED",
        details=f"Removida liberação para '{pat}' (id {allow_id})."
    )
    db.session.add(audit)
    db.session.commit()

    invalidate_policy_rules_cache()
    return jsonify({"status": "ok", "message": f"Liberação para '{pat}' removida com sucesso."})


@app.route("/api/policies/classification/status", methods=["GET"])
@login_required
def status_classificacao_automatica():
    """
    Retorna métricas de transparência e integridade da classificação automática de domínios.
    NUNCA exibe API Keys completas ou segredos no frontend.
    """
    has_api_key = bool(Config.DOMAIN_CLASSIFICATION_API_KEY)
    provider_name = "External" if has_api_key else "Internal"
    coverage = "reputação global" if has_api_key else "regras/listas locais"

    total_classified = DomainClassification.query.count()
    recent_classifications = DomainClassification.query.order_by(DomainClassification.classified_at.desc()).limit(20).all()

    return jsonify({
        "enabled": Config.DOMAIN_CLASSIFICATION_ENABLED,
        "provider": provider_name,
        "coverage": coverage,
        "provider_label": f"Provider: {provider_name}",
        "coverage_label": f"Cobertura: {coverage}",
        "ttl_days": Config.DOMAIN_CLASSIFICATION_TTL_DAYS,
        "min_confidence": Config.DOMAIN_CLASSIFICATION_MIN_CONFIDENCE,
        "total_classified_domains": total_classified,
        "recent_classifications": [c.to_dict() for c in recent_classifications]
    })


# =====================================================================
# Rotas de Notificações Windows de TI (Alertas Administrativos)
# =====================================================================

@app.route("/api/agent/admin-alerts", methods=["GET"])
def consultar_alertas_admin():
    """
    Endpoint autenticado e restrito para dispositivos de TI/Administração
    consultarem novos alertas de políticas para exibição em Windows Toast.
    Usuários comuns e computadores não autorizados recebem HTTP 403 Forbidden.
    """
    is_authorized = False

    # 1. Permite acesso se operador estiver logado na sessão web
    if session.get("role") == "admin":
        is_authorized = True

    # 2. Permite acesso se o agente autenticado tiver a flag is_admin_device no banco de dados
    if not is_authorized:
        token = request.headers.get("X-Agent-Token") or request.headers.get("X-Device-Token") or request.headers.get("Authorization")
        if token and token.startswith("Bearer "):
            token = token.replace("Bearer ", "", 1).strip()

        device_uuid = request.headers.get("X-Device-UUID") or request.args.get("uuid")

        if device_uuid and token:
            dev = Device.query.filter_by(uuid=device_uuid).first()
            if dev:
                token_valid = (dev.device_token and dev.device_token.strip() == token.strip()) or (token.strip() == Config.AGENT_SECRET_TOKEN.strip())
                if token_valid and dev.is_admin_device:
                    is_authorized = True

    if not is_authorized:
        logger.warning(f"Tentativa de acesso não autorizado a /api/agent/admin-alerts de {request.remote_addr}")
        return jsonify({
            "error": "Acesso negado: Este computador não está autorizado como dispositivo administrativo de TI.",
            "code": "ADMIN_DEVICE_UNAUTHORIZED"
        }), 403

    since_id = int(request.args.get("since_id", 0))
    fifteen_mins_ago = datetime.now(timezone.utc) - timedelta(minutes=15)

    query = PolicyEvent.query.filter(
        PolicyEvent.status == "active",
        PolicyEvent.severity.in_(["warning", "critical"]),
        PolicyEvent.last_seen >= fifteen_mins_ago
    )

    if since_id > 0:
        query = query.filter(PolicyEvent.id > since_id)

    events = query.order_by(PolicyEvent.id.asc()).limit(15).all()

    toasts = []
    for ev in events:
        dev_name = ev.device.display_name or ev.device.hostname if ev.device else "PC Desconhecido"
        toasts.append({
            "id": ev.id,
            "title": f"🚨 Alerta de Política — {ev.category}",
            "message": f"{dev_name} ({ev.device.department if ev.device else '—'}): {ev.domain or ev.application}",
            "device": dev_name,
            "department": ev.device.department if ev.device else "—",
            "category": ev.category,
            "severity": ev.severity,
            "target": ev.domain or ev.application or "—",
            "duration": ev.format_duration(),
            "time_iso": format_iso_utc(ev.last_seen),
            "time": format_local_time(ev.last_seen)  # LEGACY
        })

    return jsonify({
        "alerts": toasts,
        "count": len(toasts),
        "timestamp": format_iso_utc(utc_now())
    })


# =====================================================================
# Tratamento Centralizado de Erros (Segurança em Produção)
# =====================================================================

@app.errorhandler(404)
def handle_not_found(error):
    if request.path.startswith("/api/"):
        return jsonify({"error": "Recurso não encontrado", "code": "NOT_FOUND"}), 404
    return render_template("login.html", error="Página não encontrada (404)"), 404


@app.errorhandler(500)
def handle_internal_server_error(error):
    logger.error(f"Erro interno 500: {error}", exc_info=True)
    if request.path.startswith("/api/"):
        return jsonify({"error": "Erro interno do servidor", "code": "INTERNAL_SERVER_ERROR"}), 500
    return "<h3>Erro interno do servidor. Entre em contato com a equipe de TI da Givova Transportes.</h3>", 500


# =====================================================================
# Inicialização e Execução Direta
# =====================================================================

def init_db():
    """
    Função de compatibilidade. Delega para migrate.run_migrations().
    NOTA DE ARQUITETURA: Esta função NÃO é mais chamada automaticamente no import
    deste módulo, eliminando concorrência e transações abortadas no Gunicorn.
    """
    from migrate import run_migrations
    return run_migrations()


if __name__ == "__main__":
    logger.info(f"Iniciando Givova Monitor Server em {Config.HOST}:{Config.PORT}...")
    from migrate import run_migrations
    run_migrations()
    # Em execução direta de desenvolvimento
    app.run(host=Config.HOST, port=Config.PORT, debug=(Config.FLASK_ENV == "development"))
