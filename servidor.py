import os
import json
import secrets
import logging
from datetime import datetime, timezone, timedelta
from functools import wraps
from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash, send_file
from werkzeug.security import generate_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix

import io

from config import Config
from models import db, User, Device, MetricHistory, Alert, PolicyRule, PolicyEvent, PolicyAuditLog, SystemMetadata, AgentRelease, PolicyAllowlist, DomainClassification, compare_versions, parse_semver
from services import process_agent_payload, get_dashboard_stats, invalidate_policy_rules_cache

# Configuração de Logging Profissional
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("GivovaMonitor")

app = Flask(__name__)
app.config.from_object(Config)
app.permanent_session_lifetime = timedelta(days=7)

# Middleware para Proxy Reverso (Render, Nginx, Docker) garantindo HTTPS e IPs reais
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

db.init_app(app)



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


def require_agent_token(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # 1. Permite token via header 'X-Agent-Token', 'X-Device-Token', 'Authorization' ou via payload JSON
        token = request.headers.get("X-Agent-Token") or request.headers.get("X-Device-Token") or request.headers.get("Authorization")
        if token and token.startswith("Bearer "):
            token = token.replace("Bearer ", "", 1).strip()

        payload_token = None
        device_uuid = request.headers.get("X-Device-UUID")
        if request.is_json and request.json:
            payload_token = request.json.get("token") or request.json.get("agent_token") or request.json.get("device_token")
            if not device_uuid:
                device_uuid = request.json.get("uuid")

        sent_token = token or payload_token
        request.authenticated_device = None

        # 2. Se informado device_uuid e device_token individual, autentica especificamente aquele computador
        if device_uuid and sent_token:
            dev = Device.query.filter_by(uuid=device_uuid).first()
            if dev:
                request.authenticated_device = dev
                if dev.device_token and dev.device_token.strip() == sent_token.strip():
                    return f(*args, **kwargs)

        # 3. Fallback retrocompatível: validação contra o AGENT_SECRET_TOKEN compartilhado da empresa
        expected_token = Config.AGENT_SECRET_TOKEN
        if expected_token:
            if not sent_token or sent_token.strip() != expected_token.strip():
                logger.warning(f"Tentativa de acesso ao agente com token inválido de {request.remote_addr}")
                return jsonify({"error": "Token de autenticação do agente inválido ou ausente"}), 401

        # Vincula o dispositivo à requisição se já localizado por UUID
        if not request.authenticated_device and device_uuid:
            request.authenticated_device = Device.query.filter_by(uuid=device_uuid).first()

        return f(*args, **kwargs)
    return decorated_function


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response


# =====================================================================
# Rotas de Health Check & Diagnóstico
# =====================================================================

@app.route("/health")
def health_check():
    """
    Endpoint de checagem de integridade para monitoramento de infraestrutura e orquestradores de nuvem.
    """
    db_ok = False
    try:
        db.session.execute(db.text("SELECT 1"))
        db_ok = True
    except Exception as e:
        logger.error(f"Health check falhou no banco de dados: {e}")

    status_code = 200 if db_ok else 503
    return jsonify({
        "status": "ok" if db_ok else "unhealthy",
        "service": "Givova Transportes - Monitoramento de PCs",
        "database": "connected" if db_ok else "disconnected",
        "timestamp": datetime.now(timezone.utc).isoformat()
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
        return jsonify({
            "status": "ok",
            "message": "Dados processados com sucesso",
            "device_id": device.id,
            "status_computed": device.get_status(Config.OFFLINE_THRESHOLD_SECONDS)
        })
    except ValueError as ve:
        logger.warning(f"Erro de validação em payload de {request.remote_addr}: {ve}")
        return jsonify({"error": str(ve)}), 422
    except Exception as e:
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

@app.route("/api/agent/update", methods=["GET"])
@require_agent_token
def checar_atualizacao_agente():
    """
    Endpoint autenticado para consulta periódica de atualização pelo agente.
    Responde com manifesto oficial de release e hash SHA-256 para integridade.
    Compatível com os parâmetros 'current_version' e 'agent_version'.
    """
    current_version = (request.args.get("current_version") or request.args.get("agent_version") or "1.0.0").strip()
    device_uuid = request.args.get("uuid") or request.args.get("device_uuid")

    device = getattr(request, "authenticated_device", None)
    if not device and device_uuid:
        device = Device.query.filter_by(uuid=device_uuid).first()

    now = datetime.now(timezone.utc)
    if device:
        device.last_update_check = now

    # Carrega manifesto de release oficial (prioriza AgentRelease persistido no banco)
    latest_release = AgentRelease.query.order_by(AgentRelease.created_at.desc()).first()
    if latest_release:
        latest_version = latest_release.version
        manifest = {
            "version": latest_release.version,
            "minimum_supported_version": latest_release.min_supported_version or "1.0.0",
            "required": latest_release.mandatory,
            "sha256": latest_release.sha256,
            "release_notes": latest_release.changelog or "Atualização de estabilidade e suporte a políticas corporativas.",
            "download_url": latest_release.download_url or f"/api/agent/download/{latest_release.version}"
        }
    else:
        manifest_path = os.path.join(Config.RELEASES_DIR, "manifest.json")
        manifest = {
            "version": Config.LATEST_AGENT_VERSION,
            "minimum_supported_version": "1.0.0",
            "required": False,
            "sha256": "",
            "release_notes": "Atualização de estabilidade e suporte a políticas corporativas.",
            "download_url": f"/api/agent/download/{Config.LATEST_AGENT_VERSION}"
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

    if device:
        device.update_status = "update_available" if has_update else "up_to_date"
        db.session.commit()

    return jsonify({
        "update_available": has_update,
        "latest_version": latest_version,
        "target_version": latest_version,
        "current_version": current_version,
        "download_url": manifest.get("download_url", f"/api/agent/download/{latest_version}"),
        "sha256": manifest.get("sha256", ""),
        "required": manifest.get("required", False),
        "release_notes": manifest.get("release_notes", ""),
        "server_time": now.isoformat()
    })


@app.route("/api/agent/download/<path:version>", methods=["GET"])
@require_agent_token
def baixar_versao_agente(version):
    """
    Entrega o binário executável autenticado para o agente.
    Protegido contra directory traversal através de sanitização da versão.
    Prioriza binário no banco PostgreSQL (AgentRelease) antes do filesystem do Render.
    """
    clean_version = version.strip().lstrip("vV")
    if not all(c.isalnum() or c == "." for c in clean_version) or ".." in clean_version:
        return jsonify({"error": "Formato de versão inválido", "code": "INVALID_VERSION"}), 400

    # 1. Verifica se a release está cadastrada no banco de dados (Neon / PostgreSQL)
    rel = AgentRelease.query.filter_by(version=clean_version).first()
    if rel:
        if rel.binary_data:
            return send_file(
                io.BytesIO(rel.binary_data),
                as_attachment=True,
                download_name=f"GivovaMonitorAgent-v{clean_version}.exe",
                mimetype="application/octet-stream"
            )
        elif rel.download_url and rel.download_url.startswith(("http://", "https://")):
            return redirect(rel.download_url)

    # 2. Fallback para arquivos em disco local
    exe_candidates = [
        os.path.join(Config.RELEASES_DIR, clean_version, "GivovaMonitorAgent.exe"),
        os.path.join(Config.RELEASES_DIR, f"v{clean_version}", "GivovaMonitorAgent.exe"),
        os.path.join(Config.RELEASES_DIR, "GivovaMonitorAgent.exe"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "dist", "releases", clean_version, "GivovaMonitorAgent.exe"),
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

    return send_file(
        target_exe,
        as_attachment=True,
        download_name=f"GivovaMonitorAgent-v{clean_version}.exe",
        mimetype="application/octet-stream"
    )


@app.route("/api/admin/releases/publish", methods=["POST"])
@login_required
def publicar_release_agente():
    """
    Endpoint administrativo para registrar ou atualizar manifesto de release.
    Persiste o binário na tabela AgentRelease no banco e/ou registra link externo
    (GitHub Releases / S3) para não depender do filesystem efêmero do Render.
    """
    data = request.form if request.form else (request.get_json(silent=True) or {})
    version = data.get("version")
    sha256_hash = data.get("sha256", "")
    release_notes = data.get("release_notes", "")
    required = str(data.get("required", "")).lower() in ("true", "1", "yes")
    external_url = data.get("download_url")

    if not version:
        return jsonify({"error": "O campo 'version' é obrigatório."}), 400

    clean_version = version.strip().lstrip("vV")
    target_dir = os.path.join(Config.RELEASES_DIR, clean_version)
    os.makedirs(target_dir, exist_ok=True)

    file_bytes = None
    if "executable" in request.files:
        file = request.files["executable"]
        if file.filename.endswith(".exe"):
            file_bytes = file.read()
            dest_path = os.path.join(target_dir, "GivovaMonitorAgent.exe")
            with open(dest_path, "wb") as f:
                f.write(file_bytes)
            if not sha256_hash:
                import hashlib
                sha256_hash = hashlib.sha256(file_bytes).hexdigest()

    manifest_data = {
        "version": clean_version,
        "sha256": sha256_hash,
        "required": bool(required),
        "release_notes": release_notes,
        "download_url": external_url or f"/api/agent/download/{clean_version}",
        "published_at": datetime.now(timezone.utc).isoformat(),
        "published_by": session.get("username", "admin")
    }

    # Persiste na tabela AgentRelease para garantir sobrevivência no Render/Neon
    rel = AgentRelease.query.filter_by(version=clean_version).first()
    if not rel:
        rel = AgentRelease(version=clean_version)
        db.session.add(rel)
    rel.sha256 = sha256_hash or "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    rel.download_url = external_url or f"/api/agent/download/{clean_version}"
    rel.changelog = release_notes
    rel.mandatory = bool(required)
    rel.created_by = session.get("username", "admin")
    if file_bytes:
        rel.storage_type = "database"
        rel.binary_data = file_bytes
    elif external_url:
        rel.storage_type = "external"

    os.makedirs(Config.RELEASES_DIR, exist_ok=True)
    manifest_root = os.path.join(Config.RELEASES_DIR, "manifest.json")
    with open(manifest_root, "w", encoding="utf-8") as f:
        json.dump(manifest_data, f, indent=2)

    manifest_version_path = os.path.join(target_dir, "manifest.json")
    with open(manifest_version_path, "w", encoding="utf-8") as f:
        json.dump(manifest_data, f, indent=2)

    audit = PolicyAuditLog(
        user_name=session.get("username", "admin"),
        action="RELEASE_PUBLISHED",
        details=f"Publicada versão {clean_version} com hash SHA-256 {sha256_hash[:16] if sha256_hash else '—'}..."
    )
    db.session.add(audit)
    db.session.commit()

    logger.info(f"Release v{clean_version} do agente publicada pelo administrador {session.get('username')}.")
    return jsonify({"status": "ok", "manifest": manifest_data})


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


@app.route("/api/policies/events", methods=["GET"])
@login_required
def listar_eventos_politicas():
    """
    Lista ocorrências de violação de políticas com filtros por status, severidade e departamento.
    Suporta DEMO_MODE com dados virtuais em memória.
    """
    status_filter = request.args.get("status", "all").strip()
    severity_filter = request.args.get("severity", "").strip()
    dept_filter = request.args.get("department", "").strip()
    limit = min(int(request.args.get("limit", 100)), 300)

    query = PolicyEvent.query

    if status_filter == "active":
        query = query.filter_by(status="active")
    elif status_filter == "closed":
        query = query.filter_by(status="closed")

    if severity_filter and severity_filter != "Todos":
        query = query.filter_by(severity=severity_filter.lower())

    if dept_filter and dept_filter != "Todos":
        query = query.join(Device).filter(Device.department == dept_filter)

    events = query.order_by(PolicyEvent.last_seen.desc()).limit(limit).all()
    result = [e.to_dict() for e in events]

    if Config.DEMO_MODE and status_filter != "closed":
        from demo_data import get_demo_policy_events
        result = get_demo_policy_events() + result

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
    Marca uma ocorrência de política como resolvida/fechada manualmente.
    """
    if event_id >= 9000:
        return jsonify({"status": "ok", "message": "Ocorrência de demonstração resolvida (simulação)."})

    event = db.get_or_404(PolicyEvent, event_id)
    now = datetime.now(timezone.utc)
    event.status = "closed"
    event.resolved_at = now
    if event.first_seen:
        f_seen = event.first_seen
        if f_seen.tzinfo is None:
            f_seen = f_seen.replace(tzinfo=timezone.utc)
        event.duration_seconds = max(0, int((now - f_seen).total_seconds()))

    audit = PolicyAuditLog(
        user_name=session.get("username", "admin"),
        action="EVENT_RESOLVED",
        details=f"Ocorrência {event_id} encerrada manualmente."
    )
    db.session.add(audit)
    db.session.commit()
    return jsonify({"status": "ok", "event": event.to_dict()})


@app.route("/api/policies/stats", methods=["GET"])
@login_required
def estatisticas_politicas():
    """
    Relatório consolidado de violações de políticas para gestão de risco e conformidade.
    """
    all_events = PolicyEvent.query.all()
    events_dicts = [e.to_dict() for e in all_events]

    if Config.DEMO_MODE:
        from demo_data import get_demo_policy_events
        events_dicts = get_demo_policy_events() + events_dicts

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
        "total_events": len(events_dicts),
        "active_events": sum(1 for e in events_dicts if e.get("status") == "active"),
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
            "time": ev.last_seen.strftime("%H:%M:%S") if ev.last_seen else ""
        })

    return jsonify({
        "alerts": toasts,
        "count": len(toasts),
        "timestamp": datetime.now(timezone.utc).isoformat()
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
# Inicialização da Base de Dados e Usuário Inicial
# =====================================================================

def init_db():
    with app.app_context():
        db.create_all()
        # Migração idempotente para bases existentes (adiciona colunas de atividade se ausentes)
        try:
            with db.engine.connect() as conn:
                engine_str = str(db.engine.url).lower()
                if "sqlite" in engine_str:
                    result = conn.execute(db.text("PRAGMA table_info(devices)")).fetchall()
                    cols = [r[1] for r in result]
                    if cols:
                        if "active_app" not in cols:
                            conn.execute(db.text("ALTER TABLE devices ADD COLUMN active_app VARCHAR(120)"))
                        if "active_domain" not in cols:
                            conn.execute(db.text("ALTER TABLE devices ADD COLUMN active_domain VARCHAR(150)"))
                        if "activity_updated_at" not in cols:
                            conn.execute(db.text("ALTER TABLE devices ADD COLUMN activity_updated_at DATETIME"))
                        if "is_admin_device" not in cols:
                            conn.execute(db.text("ALTER TABLE devices ADD COLUMN is_admin_device BOOLEAN DEFAULT 0"))
                        if "device_token" not in cols:
                            conn.execute(db.text("ALTER TABLE devices ADD COLUMN device_token VARCHAR(64)"))
                        if "update_status" not in cols:
                            conn.execute(db.text("ALTER TABLE devices ADD COLUMN update_status VARCHAR(50) DEFAULT 'up_to_date'"))
                        if "last_update_check" not in cols:
                            conn.execute(db.text("ALTER TABLE devices ADD COLUMN last_update_check DATETIME"))
                        conn.commit()
                elif "postgres" in engine_str:
                    result = conn.execute(db.text(
                        "SELECT column_name FROM information_schema.columns WHERE table_name = 'devices'"
                    )).fetchall()
                    cols = [r[0].lower() for r in result]
                    if cols:
                        if "active_app" not in cols:
                            conn.execute(db.text("ALTER TABLE devices ADD COLUMN active_app VARCHAR(120)"))
                        if "active_domain" not in cols:
                            conn.execute(db.text("ALTER TABLE devices ADD COLUMN active_domain VARCHAR(150)"))
                        if "activity_updated_at" not in cols:
                            conn.execute(db.text("ALTER TABLE devices ADD COLUMN activity_updated_at TIMESTAMP"))
                        if "is_admin_device" not in cols:
                            conn.execute(db.text("ALTER TABLE devices ADD COLUMN is_admin_device BOOLEAN DEFAULT FALSE"))
                        if "device_token" not in cols:
                            conn.execute(db.text("ALTER TABLE devices ADD COLUMN device_token VARCHAR(64)"))
                        if "update_status" not in cols:
                            conn.execute(db.text("ALTER TABLE devices ADD COLUMN update_status VARCHAR(50) DEFAULT 'up_to_date'"))
                        if "last_update_check" not in cols:
                            conn.execute(db.text("ALTER TABLE devices ADD COLUMN last_update_check TIMESTAMP"))
                        conn.commit()
        except Exception as e:
            logger.debug(f"Verificação de colunas em devices: {e}")

        # Semeia regras padrão corporativas de políticas se tabela estiver vazia
        try:
            if PolicyRule.query.count() == 0:
                default_rules = [
                    PolicyRule(name="Jogos Steam", rule_type="application", pattern="steam.exe", category="Jogos", severity="warning", scope_type="global", enabled=True),
                    PolicyRule(name="Jogos Valorant", rule_type="application", pattern="valorant.exe", category="Jogos", severity="critical", scope_type="global", enabled=True),
                    PolicyRule(name="Jogos Roblox", rule_type="application", pattern="robloxplayerbeta.exe", category="Jogos", severity="warning", scope_type="global", enabled=True),
                    PolicyRule(name="Apostas Bet365", rule_type="domain", pattern="bet365.com", category="Apostas", severity="critical", scope_type="global", enabled=True),
                    PolicyRule(name="Apostas Betano", rule_type="domain", pattern="betano.com", category="Apostas", severity="critical", scope_type="global", enabled=True),
                    PolicyRule(name="Streaming Netflix", rule_type="domain", pattern="netflix.com", category="Streaming", severity="warning", scope_type="global", enabled=True),
                    PolicyRule(name="Redes Sociais Instagram", rule_type="domain", pattern="instagram.com", category="Redes Sociais", severity="warning", scope_type="global", enabled=False),
                    PolicyRule(name="Redes Sociais TikTok", rule_type="domain", pattern="tiktok.com", category="Redes Sociais", severity="warning", scope_type="global", enabled=True)
                ]
                db.session.add_all(default_rules)
                db.session.commit()
                logger.info("Regras corporativas padrão de políticas inicializadas.")
        except Exception as e:
            logger.debug(f"Inicialização de regras padrão de políticas: {e}")

        # Cria usuário administrador padrão se não houver nenhum
        admin = User.query.filter_by(username=Config.ADMIN_USERNAME).first()
        if not admin:
            admin = User(username=Config.ADMIN_USERNAME, role="admin")
            admin.set_password(Config.ADMIN_PASSWORD)
            db.session.add(admin)
            db.session.commit()
            logger.info(f"Usuário administrador padrão '{Config.ADMIN_USERNAME}' inicializado com sucesso.")

        # Alerta de segurança em produção caso secrets de desenvolvimento ainda estejam em uso
        if Config.FLASK_ENV == "production":
            if "change_in_prod" in Config.SECRET_KEY or "fallback" in Config.SECRET_KEY:
                logger.warning("ALERTA DE SEGURANÇA: SECRET_KEY padrão detectada em produção. Defina SECRET_KEY no painel do Render!")
            if "dev" in Config.AGENT_SECRET_TOKEN:
                logger.warning("ALERTA DE SEGURANÇA: AGENT_SECRET_TOKEN padrão detectado em produção. Defina AGENT_SECRET_TOKEN no painel do Render!")


init_db()

if __name__ == "__main__":
    logger.info(f"Iniciando Givova Monitor Server em {Config.HOST}:{Config.PORT}...")
    # Em execução direta de desenvolvimento
    app.run(host=Config.HOST, port=Config.PORT, debug=(Config.FLASK_ENV == "development"))