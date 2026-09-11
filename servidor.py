import os
import logging
from datetime import datetime, timezone, timedelta
from functools import wraps
from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix

from config import Config
from models import db, User, Device, MetricHistory, Alert
from services import process_agent_payload, get_dashboard_stats

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
        # Permite token via header 'X-Agent-Token' ou via chave 'token' no JSON
        token = request.headers.get("X-Agent-Token") or request.headers.get("Authorization")
        if token and token.startswith("Bearer "):
            token = token.replace("Bearer ", "", 1)

        payload_token = None
        if request.is_json and request.json:
            payload_token = request.json.get("token")

        sent_token = token or payload_token

        expected_token = Config.AGENT_SECRET_TOKEN
        if expected_token:
            if not sent_token or sent_token.strip() != expected_token.strip():
                logger.warning(f"Tentativa de envio de métricas com token inválido de {request.remote_addr}")
                return jsonify({"error": "Token de autenticação do agente inválido ou ausente"}), 401
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

    return jsonify({
        "device": device.to_dict(Config.OFFLINE_THRESHOLD_SECONDS),
        "metrics": [m.to_dict() for m in metrics],
        "alerts": [a.to_dict() for a in alerts]
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

    if display_name is not None:
        device.display_name = display_name.strip()
    if department is not None:
        device.department = department.strip()

    db.session.commit()
    logger.info(f"Dispositivo {device.hostname} atualizado: nome='{device.display_name}', setor='{device.department}'")
    return jsonify({"status": "ok", "device": device.to_dict(Config.OFFLINE_THRESHOLD_SECONDS)})


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
                        conn.commit()
        except Exception as e:
            logger.debug(f"Verificação de colunas de atividade: {e}")

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