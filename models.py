from datetime import datetime, timezone
from datetime_utils import format_iso_utc, format_local_datetime, format_local_time
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import inspect
from sqlalchemy.orm import deferred
from sqlalchemy.orm.attributes import NO_VALUE
from werkzeug.security import generate_password_hash, check_password_hash
from config import Config

db = SQLAlchemy(session_options={"expire_on_commit": False})

class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(30), default="admin")
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_login = db.Column(db.DateTime, nullable=True)

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


def parse_semver(v: str) -> tuple:
    """Converte strings como '1.4.0' ou 'v1.4' em tupla de inteiros (1, 4, 0)."""
    try:
        if not v:
            return (1, 0, 0)
        clean = str(v).strip().lstrip("vV")
        parts = [int(p) for p in clean.split(".") if p.isdigit()]
        while len(parts) < 3:
            parts.append(0)
        return tuple(parts[:3])
    except Exception:
        return (1, 0, 0)


def compare_versions(v1: str, v2: str) -> int:
    """Retorna 1 se v1 > v2, -1 se v1 < v2, 0 se v1 == v2."""
    p1, p2 = parse_semver(v1), parse_semver(v2)
    if p1 > p2:
        return 1
    elif p1 < p2:
        return -1
    return 0


def normalize_domain(domain: str) -> str:
    """
    Normaliza hostname/domínio removendo porta, barras, query e espaços em minúsculas.
    Remove pontuação final (ex: 'example.com.' -> 'example.com') e prefixo 'www.'.
    """
    if not domain:
        return ""
    d = domain.strip().lower()
    if "://" in d:
        d = d.split("://", 1)[1]
    d = d.split("/")[0].split("?")[0].split("#")[0]
    d = d.split(":")[0].rstrip(".")
    if d.startswith("www."):
        d = d[4:]
    return d


def match_domain_secure(target_domain: str, pattern: str) -> bool:
    """
    Casamento seguro de domínios corporativos:
    Regra 'example.com' casa:
    - 'example.com'
    - 'www.example.com'
    - 'sub.example.com'
    - 'api.dev.example.com'
    MAS NUNCA casa:
    - 'notexample.com'
    - 'fakeexample.com'
    """
    norm_target = normalize_domain(target_domain)
    norm_pat = normalize_domain(pattern)
    if not norm_target or not norm_pat:
        return False

    if norm_pat.startswith("www."):
        norm_pat = norm_pat[4:]

    clean_target = norm_target[4:] if norm_target.startswith("www.") else norm_target

    if clean_target == norm_pat:
        return True

    if norm_target.endswith("." + norm_pat):
        return True

    return False


def match_application_secure(app_name: str, pattern: str) -> bool:
    """
    Casamento seguro de aplicativos e processos:
    Case-insensitive, normaliza extensão .exe.
    """
    if not app_name or not pattern:
        return False
    app = app_name.strip().lower()
    pat = pattern.strip().lower()

    if app == pat:
        return True

    app_base = app[:-4] if app.endswith(".exe") else app
    pat_base = pat[:-4] if pat.endswith(".exe") else pat

    if app_base == pat_base:
        return True

    if pat_base and (pat_base in app or app in pat_base):
        return True

    return False


class Device(db.Model):
    __tablename__ = "devices"

    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(64), unique=True, nullable=False, index=True)
    hostname = db.Column(db.String(120), nullable=False, index=True)
    display_name = db.Column(db.String(120), nullable=True)
    user_name = db.Column(db.String(120), nullable=True)
    department = db.Column(db.String(100), default="Não informado", index=True)
    
    # Informações de Rede
    ip_address = db.Column(db.String(64), nullable=True)
    mac_address = db.Column(db.String(64), nullable=True)
    
    # Informações de Hardware e Sistema
    os_name = db.Column(db.String(120), nullable=True)
    os_arch = db.Column(db.String(30), nullable=True)
    processor = db.Column(db.String(200), nullable=True)
    cpu_cores = db.Column(db.Integer, default=1)
    ram_total_gb = db.Column(db.Float, default=0.0)
    disk_total_gb = db.Column(db.Float, default=0.0)
    
    # Versão do agente instalado e status de atualização
    agent_version = db.Column(db.String(20), default="1.0.0")
    update_status = db.Column(db.String(50), default="up_to_date")
    last_update_check = db.Column(db.DateTime, nullable=True)

    # Segurança e Permissões Administrativas
    device_token = db.Column(db.String(64), nullable=True, unique=True, index=True)
    is_admin_device = db.Column(db.Boolean, default=False, index=True)
    
    # Atividade Atual em Primeiro Plano
    active_app = db.Column(db.String(120), nullable=True)
    active_domain = db.Column(db.String(150), nullable=True)
    activity_updated_at = db.Column(db.DateTime, nullable=True)
    
    # Últimas métricas instantâneas registradas
    last_cpu = db.Column(db.Float, default=0.0)
    last_ram = db.Column(db.Float, default=0.0)
    last_ram_used_gb = db.Column(db.Float, default=0.0)
    last_disk = db.Column(db.Float, default=0.0)
    last_disk_used_gb = db.Column(db.Float, default=0.0)
    last_uptime_seconds = db.Column(db.BigInteger, default=0)
    
    # Rastreamento de Sessão e Uso do Usuário (v1.5.0)
    current_session_state = db.Column(db.String(30), default="unknown", index=True)  # active, idle, overtime, off_hours, unknown
    last_input_at = db.Column(db.DateTime, nullable=True)
    last_idle_seconds = db.Column(db.Float, default=0.0)
    user_active = db.Column(db.Boolean, default=False)
    windows_session_id = db.Column(db.Integer, nullable=True)

    # Timestamps
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)

    # Relacionamentos
    metrics = db.relationship("MetricHistory", backref="device", cascade="all, delete-orphan", lazy="dynamic")
    alerts = db.relationship("Alert", backref="device", cascade="all, delete-orphan", lazy="dynamic")
    policy_events = db.relationship("PolicyEvent", backref="device", cascade="all, delete-orphan", lazy="dynamic")
    usage_sessions = db.relationship("UsageSession", backref="device", cascade="all, delete-orphan", lazy="dynamic")
    daily_usage = db.relationship("DailyUsageSummary", backref="device", cascade="all, delete-orphan", lazy="dynamic")

    def get_status(self, offline_threshold_seconds: int = 30) -> str:
        """
        Retorna status: 'online', 'warning', 'critical' ou 'offline'
        """
        if not self.updated_at:
            return "offline"

        now = datetime.now(timezone.utc)
        # Suporta datetime naive ou aware
        last = self.updated_at
        if last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)
            
        seconds_diff = (now - last).total_seconds()

        if seconds_diff > offline_threshold_seconds:
            return "offline"

        # Se respondeu recentemente, avalia se há condição crítica ou de alerta
        if (self.last_cpu and self.last_cpu >= 95.0) or (self.last_ram and self.last_ram >= 95.0) or (self.last_disk and self.last_disk >= 95.0):
            return "critical"
        elif (self.last_cpu and self.last_cpu >= 90.0) or (self.last_ram and self.last_ram >= 90.0) or (self.last_disk and self.last_disk >= 90.0):
            return "warning"

        return "online"

    def format_uptime(self) -> str:
        if not self.last_uptime_seconds:
            return "0m"
        seconds = self.last_uptime_seconds
        days = seconds // 86400
        hours = (seconds % 86400) // 3600
        minutes = (seconds % 3600) // 60
        if days > 0:
            return f"{days}d {hours}h {minutes}m"
        elif hours > 0:
            return f"{hours}h {minutes}m"
        return f"{minutes}m"

    def get_formatted_activity(self, offline_threshold_seconds: int = 30) -> str:
        """
        Retorna a atividade atual formatada com ícones corporativos limpos:
        Ex: '🌐 chatgpt.com', '📊 Microsoft Excel', '💻 VS Code', 'Sem atividade recente'
        """
        status = self.get_status(offline_threshold_seconds)
        if status == "offline" or not self.active_app or not self.activity_updated_at:
            return "Sem atividade recente"

        now = datetime.now(timezone.utc)
        act_time = self.activity_updated_at
        if act_time.tzinfo is None:
            act_time = act_time.replace(tzinfo=timezone.utc)

        # Se a atividade não for atualizada há mais que o dobro do threshold de offline, considera desatualizada
        if (now - act_time).total_seconds() > (offline_threshold_seconds * 2):
            return "Sem atividade recente"

        app_lower = self.active_app.lower()

        # Navegadores
        if any(b in app_lower for b in ["chrome", "edge", "chromium", "brave", "firefox"]):
            if self.active_domain:
                return f"🌐 {self.active_domain}"
            return f"🌐 {self.active_app}"

        # Aplicativos Corporativos e de Produtividade
        if "excel" in app_lower:
            return f"📊 {self.active_app}"
        if "word" in app_lower:
            return f"📝 {self.active_app}"
        if "powerpoint" in app_lower or "powerpnt" in app_lower:
            return f"📽️ {self.active_app}"
        if "outlook" in app_lower or "thunderbird" in app_lower or "mail" in app_lower:
            return f"📧 {self.active_app}"
        if "code" in app_lower or "visual studio" in app_lower:
            return f"💻 {self.active_app}"
        if "terminal" in app_lower or "powershell" in app_lower or "cmd" in app_lower:
            return f"⚡ {self.active_app}"
        if "teams" in app_lower or "slack" in app_lower or "discord" in app_lower:
            return f"💬 {self.active_app}"
        if "explorer" in app_lower or "arquivos" in app_lower:
            return f"📁 {self.active_app}"

        return f"🖥️ {self.active_app}"

    def get_version_info(self, latest_version: str = "1.4.0") -> dict:
        cur = self.agent_version or "1.0.0"
        cmp = compare_versions(cur, latest_version)
        if cmp >= 0:
            return {
                "status": "up_to_date",
                "label": f"Atualizado — v{cur}",
                "badge_class": "bg-emerald-50 text-emerald-700 border-emerald-200",
                "needs_update": False,
                "is_critical": False
            }

        p_cur = parse_semver(cur)
        p_lat = parse_semver(latest_version)
        is_crit = (p_cur[0] < p_lat[0]) or ((p_lat[1] - p_cur[1]) >= 2)
        if is_crit:
            return {
                "status": "outdated_critical",
                "label": f"Desatualizado Crítico — v{cur}",
                "badge_class": "bg-rose-50 text-rose-700 border-rose-200",
                "needs_update": True,
                "is_critical": True
            }

        return {
            "status": "update_available",
            "label": f"Atualização disponível — v{cur} → v{latest_version}",
            "badge_class": "bg-amber-50 text-amber-700 border-amber-200",
            "needs_update": True,
            "is_critical": False
        }

    def to_dict(self, offline_threshold_seconds: int = 30, latest_version: str = "1.4.0") -> dict:
        status = self.get_status(offline_threshold_seconds)
        activity_formatted = self.get_formatted_activity(offline_threshold_seconds)
        activity_time_str = format_local_time(self.activity_updated_at) if self.activity_updated_at else None
        v_info = self.get_version_info(latest_version)

        is_recent_activity = False
        if self.activity_updated_at and status != "offline":
            now = datetime.now(timezone.utc)
            act_time = self.activity_updated_at
            if act_time.tzinfo is None:
                act_time = act_time.replace(tzinfo=timezone.utc)
            is_recent_activity = (now - act_time).total_seconds() <= (offline_threshold_seconds * 2)

        # Estado de Sessão e Uso do Usuário (v1.5.0)
        computed_session_state = "offline" if status == "offline" else (self.current_session_state or "unknown")
        user_is_active = bool(self.user_active and status != "offline")

        return {
            "id": self.id,
            "uuid": self.uuid,
            "hostname": self.hostname,
            "display_name": self.display_name or self.hostname,
            "user_name": self.user_name or "Desconhecido",
            "department": self.department or "Geral",
            "ip_address": self.ip_address or "—",
            "mac_address": self.mac_address or "—",
            "os_name": self.os_name or "Desconhecido",
            "os_arch": self.os_arch or "x64",
            "processor": self.processor or "—",
            "cpu_cores": self.cpu_cores or 1,
            "ram_total_gb": round(self.ram_total_gb or 0.0, 1),
            "last_ram_used_gb": round(self.last_ram_used_gb or 0.0, 1),
            "disk_total_gb": round(self.disk_total_gb or 0.0, 1),
            "last_disk_used_gb": round(self.last_disk_used_gb or 0.0, 1),
            "disk_free_gb": round(max(0.0, (self.disk_total_gb or 0.0) - (self.last_disk_used_gb or 0.0)), 1),
            "agent_version": self.agent_version or "1.0.0",
            "version_status": v_info["status"],
            "version_label": v_info["label"],
            "version_badge_class": v_info["badge_class"],
            "version_needs_update": v_info["needs_update"],
            "version_is_critical": v_info["is_critical"],
            "latest_available_version": latest_version,
            "last_update_check_iso": format_iso_utc(self.last_update_check),
            "last_update_check": format_local_datetime(self.last_update_check) if self.last_update_check else "Nunca",  # LEGACY
            "is_admin_device": bool(self.is_admin_device),
            "has_individual_token": bool(self.device_token),
            "cpu": round(self.last_cpu or 0.0, 1),
            "ram": round(self.last_ram or 0.0, 1),
            "disco": round(self.last_disk or 0.0, 1),
            "uptime": self.format_uptime(),
            "uptime_seconds": self.last_uptime_seconds or 0,
            "status": status,
            "status_label": {
                "online": "Online",
                "warning": "Alerta",
                "critical": "Crítico",
                "offline": "Offline"
            }.get(status, "Desconhecido"),
            "session_state": computed_session_state,
            "session_state_label": {
                "active": "Ativo",
                "idle": "Ocioso",
                "overtime": "Hora extra",
                "off_hours": "Fora do expediente",
                "locked": "Bloqueado",
                "offline": "Offline",
                "unknown": "Desconhecido"
            }.get(computed_session_state, "Desconhecido"),
            "user_active": user_is_active,
            "idle_seconds": round(self.last_idle_seconds or 0.0, 1),
            "last_input_at_iso": format_iso_utc(self.last_input_at),
            "last_input_at": format_local_datetime(self.last_input_at) if self.last_input_at else None,  # LEGACY
            "windows_session_id": self.windows_session_id,
            "ultimo_contato_iso": format_iso_utc(self.updated_at),
            "ultimo_contato": format_local_datetime(self.updated_at) if self.updated_at else "Nunca",  # LEGACY
            "created_at_iso": format_iso_utc(self.created_at),
            "created_at": format_local_datetime(self.created_at) if self.created_at else "",  # LEGACY
            "active_app": self.active_app or "—",
            "active_domain": self.active_domain or "—",
            "active_activity_formatted": activity_formatted,
            "activity_updated_at_iso": format_iso_utc(self.activity_updated_at),
            "activity_updated_at": activity_time_str,  # LEGACY
            "activity_recent": is_recent_activity,
            "is_demo": False
        }



class MetricHistory(db.Model):
    __tablename__ = "metrics_history"

    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey("devices.id", ondelete="CASCADE"), nullable=False, index=True)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)

    cpu_percent = db.Column(db.Float, nullable=False)
    ram_percent = db.Column(db.Float, nullable=False)
    ram_used_gb = db.Column(db.Float, default=0.0)
    disk_percent = db.Column(db.Float, nullable=False)
    disk_used_gb = db.Column(db.Float, default=0.0)
    uptime_seconds = db.Column(db.BigInteger, default=0)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "timestamp_iso": format_iso_utc(self.timestamp),
            "timestamp": format_local_time(self.timestamp),  # LEGACY
            "cpu": round(self.cpu_percent or 0.0, 1),
            "ram": round(self.ram_percent or 0.0, 1),
            "ram_used_gb": round(self.ram_used_gb or 0.0, 1),
            "disk": round(self.disk_percent or 0.0, 1),
            "disk_used_gb": round(self.disk_used_gb or 0.0, 1)
        }


class Alert(db.Model):
    __tablename__ = "alerts"

    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey("devices.id", ondelete="CASCADE"), nullable=False, index=True)
    severity = db.Column(db.String(20), nullable=False, default="warning", index=True) # warning, critical
    alert_type = db.Column(db.String(50), nullable=False, index=True) # cpu_high, ram_high, disk_high, offline, error
    message = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    is_resolved = db.Column(db.Boolean, default=False, index=True)
    resolved_at = db.Column(db.DateTime, nullable=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "device_id": self.device_id,
            "device_name": self.device.display_name or self.device.hostname if self.device else "Desconhecido",
            "department": self.device.department if self.device else "—",
            "severity": self.severity,
            "alert_type": self.alert_type,
            "message": self.message,
            "created_at_iso": format_iso_utc(self.created_at),
            "created_at": format_local_datetime(self.created_at),  # LEGACY
            "is_resolved": self.is_resolved,
            "resolved_at_iso": format_iso_utc(self.resolved_at),
            "resolved_at": format_local_datetime(self.resolved_at) if self.resolved_at else None,  # LEGACY
            "is_demo": False
        }


class PolicyRule(db.Model):
    __tablename__ = "policy_rules"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    rule_type = db.Column(db.String(30), nullable=False, index=True)  # 'domain' ou 'application'
    pattern = db.Column(db.String(200), nullable=False, index=True)
    category = db.Column(db.String(50), nullable=False, index=True)  # adult, games, gambling, streaming, social_media, malware, phishing, etc.
    severity = db.Column(db.String(20), default="warning", nullable=False)  # 'info', 'warning', 'critical'
    scope_type = db.Column(db.String(30), default="global", nullable=False)  # 'global', 'department', 'device'
    scope_target = db.Column(db.String(100), nullable=True)  # Nome do setor ou hostname/UUID
    action = db.Column(db.String(30), default="alert", nullable=False)  # 'alert', 'log', 'allow'
    enabled = db.Column(db.Boolean, default=True, nullable=False, index=True)
    is_automatic = db.Column(db.Boolean, default=False)
    source_provider = db.Column(db.String(50), nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    events = db.relationship("PolicyEvent", backref="rule", lazy="dynamic")

    def matches(self, app_name: str | None, domain: str | None, device_dept: str | None, device_host: str | None, device_uuid: str | None) -> bool:
        if not self.enabled:
            return False

        # Avaliação de escopo
        if self.scope_type == "department":
            if not device_dept or device_dept.lower().strip() != str(self.scope_target).lower().strip():
                return False
        elif self.scope_type == "device":
            target = str(self.scope_target).lower().strip()
            host_match = device_host and device_host.lower().strip() == target
            uuid_match = device_uuid and device_uuid.lower().strip() == target
            if not (host_match or uuid_match):
                return False

        clean_pat = self.pattern.strip().lower()

        if self.rule_type == "domain":
            if not domain:
                return False
            return match_domain_secure(domain, clean_pat)
        elif self.rule_type == "application":
            if not app_name:
                return False
            return match_application_secure(app_name, clean_pat)

        return False

    def to_dict(self) -> dict:
        origin_label = "Regra Manual"
        if self.is_automatic:
            origin_label = "Classificação Automática"
        elif self.source_provider in ("seed", "corporate_base"):
            origin_label = "Base Corporativa"

        return {
            "id": self.id,
            "name": self.name,
            "rule_type": self.rule_type,
            "pattern": self.pattern,
            "category": self.category,
            "severity": self.severity,
            "scope_type": self.scope_type,
            "scope_target": self.scope_target or "Todos",
            "action": self.action,
            "enabled": self.enabled,
            "is_automatic": bool(self.is_automatic),
            "source_provider": self.source_provider or "manual",
            "origin": origin_label,
            "created_at_iso": format_iso_utc(self.created_at),
            "created_at": format_local_datetime(self.created_at),  # LEGACY
            "is_demo": False
        }


class PolicyEvent(db.Model):
    __tablename__ = "policy_events"

    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey("devices.id", ondelete="CASCADE"), nullable=False, index=True)
    policy_rule_id = db.Column(db.Integer, db.ForeignKey("policy_rules.id", ondelete="SET NULL"), nullable=True, index=True)
    event_type = db.Column(db.String(30), nullable=False)  # 'domain' ou 'application'
    category = db.Column(db.String(50), nullable=False, index=True)
    severity = db.Column(db.String(20), default="warning", index=True)
    application = db.Column(db.String(120), nullable=True)
    domain = db.Column(db.String(150), nullable=True)
    first_seen = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    last_seen = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    duration_seconds = db.Column(db.Integer, default=0)
    status = db.Column(db.String(20), default="active", index=True)  # 'active', 'closed'
    source = db.Column(db.String(50), default="manual_rule", index=True)  # 'manual_rule' ou 'automatic_classification'
    last_notification_sent_at = db.Column(db.DateTime, nullable=True)
    acknowledged = db.Column(db.Boolean, default=False, index=True)
    acknowledged_at = db.Column(db.DateTime, nullable=True)
    acknowledged_by = db.Column(db.String(80), nullable=True)
    resolved_at = db.Column(db.DateTime, nullable=True)
    resolved_by = db.Column(db.String(80), nullable=True)

    def format_duration(self) -> str:
        seconds = self.duration_seconds or 0
        if seconds < 60:
            return f"{seconds}s"
        minutes = seconds // 60
        rem_sec = seconds % 60
        if minutes < 60:
            return f"{minutes}m {rem_sec}s"
        hours = minutes // 60
        rem_min = minutes % 60
        return f"{hours}h {rem_min}m"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "device_id": self.device_id,
            "device_name": self.device.display_name or self.device.hostname if self.device else "Desconhecido",
            "department": self.device.department if self.device else "—",
            "user_name": self.device.user_name if self.device else "—",
            "policy_rule_id": self.policy_rule_id,
            "event_type": self.event_type,
            "category": self.category,
            "severity": self.severity,
            "application": self.application or "—",
            "domain": self.domain or "—",
            "first_seen_iso": format_iso_utc(self.first_seen),
            "first_seen": format_local_datetime(self.first_seen),  # LEGACY
            "last_seen_iso": format_iso_utc(self.last_seen),
            "last_seen": format_local_datetime(self.last_seen),  # LEGACY
            "duration_seconds": self.duration_seconds,
            "duration_formatted": self.format_duration(),
            "status": self.status,
            "source": self.source or "manual_rule",
            "acknowledged": self.acknowledged,
            "acknowledged_at_iso": format_iso_utc(self.acknowledged_at),
            "acknowledged_at": format_local_datetime(self.acknowledged_at) if self.acknowledged_at else None,  # LEGACY
            "acknowledged_by": self.acknowledged_by,
            "is_resolved": bool(self.resolved_at),
            "resolved_at_iso": format_iso_utc(self.resolved_at),
            "resolved_at": format_local_datetime(self.resolved_at) if self.resolved_at else None,  # LEGACY
            "resolved_by": self.resolved_by,
            "is_demo": False
        }


class PolicyAllowlist(db.Model):
    __tablename__ = "policy_allowlists"

    id = db.Column(db.Integer, primary_key=True)
    pattern = db.Column(db.String(200), nullable=False, index=True)
    target_type = db.Column(db.String(30), default="domain", nullable=False)  # 'domain' ou 'application'
    scope_type = db.Column(db.String(30), default="global", nullable=False)  # 'global', 'department', 'device'
    scope_target = db.Column(db.String(100), nullable=True)  # Nome do setor ou hostname/UUID
    reason = db.Column(db.String(255), nullable=True)
    enabled = db.Column(db.Boolean, default=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    created_by = db.Column(db.String(80), default="admin")

    def matches(self, app_name: str | None, domain: str | None, device_dept: str | None, device_host: str | None, device_uuid: str | None) -> bool:
        if not self.enabled:
            return False

        if self.scope_type == "department":
            if not device_dept or device_dept.lower().strip() != str(self.scope_target).lower().strip():
                return False
        elif self.scope_type == "device":
            target = str(self.scope_target).lower().strip()
            host_match = device_host and device_host.lower().strip() == target
            uuid_match = device_uuid and device_uuid.lower().strip() == target
            if not (host_match or uuid_match):
                return False

        clean_pat = self.pattern.strip().lower()
        if self.target_type == "domain":
            if not domain:
                return False
            return match_domain_secure(domain, clean_pat)
        elif self.target_type == "application":
            if not app_name:
                return False
            return match_application_secure(app_name, clean_pat)

        return False

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "pattern": self.pattern,
            "target_type": self.target_type,
            "scope_type": self.scope_type,
            "scope_target": self.scope_target or "Todos",
            "reason": self.reason or "—",
            "enabled": self.enabled,
            "created_at_iso": format_iso_utc(self.created_at),
            "created_at": format_local_datetime(self.created_at),  # LEGACY
            "created_by": self.created_by or "admin"
        }


class DomainClassification(db.Model):
    __tablename__ = "domain_classifications"

    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(150), unique=True, nullable=False, index=True)
    category = db.Column(db.String(50), nullable=False, default="unknown", index=True)  # adult, gambling, games, malware, safe, unknown
    risk_level = db.Column(db.String(20), nullable=False, default="info")  # critical, warning, info, safe
    confidence = db.Column(db.Float, default=1.0)
    source = db.Column(db.String(50), default="internal")  # internal, provider, manual
    status = db.Column(db.String(30), default="classified", index=True)  # pending, classified, error
    classified_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at = db.Column(db.DateTime, nullable=True)
    last_device_id = db.Column(db.Integer, db.ForeignKey("devices.id", ondelete="SET NULL"), nullable=True, index=True)
    last_accessed_at = db.Column(db.DateTime, nullable=True, index=True)

    last_device = db.relationship("Device", foreign_keys=[last_device_id])

    def is_expired(self) -> bool:
        if not self.expires_at:
            return False
        now = datetime.now(timezone.utc)
        exp = self.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        return now > exp

    def to_dict(self) -> dict:
        device = self.last_device
        return {
            "id": self.id,
            "domain": self.domain,
            "category": self.category,
            "risk_level": self.risk_level,
            "confidence": round(self.confidence or 0.0, 2),
            "source": self.source,
            "status": self.status,
            "classified_at_iso": format_iso_utc(self.classified_at),
            "classified_at": format_local_datetime(self.classified_at),  # LEGACY
            "expires_at_iso": format_iso_utc(self.expires_at),
            "expires_at": format_local_datetime(self.expires_at) if self.expires_at else "Nunca",  # LEGACY
            "last_device_id": self.last_device_id,
            "last_accessed_by": (device.user_name or "-") if device else "-",
            "last_computer": (device.display_name or device.hostname or "-") if device else "-",
            "last_department": (device.department or "-") if device else "-",
            "last_accessed_at_iso": format_iso_utc(self.last_accessed_at),
            "last_accessed_at": format_local_datetime(self.last_accessed_at) if self.last_accessed_at else "-",
        }


class PolicyAuditLog(db.Model):
    __tablename__ = "policy_audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(80), nullable=False)
    action = db.Column(db.String(50), nullable=False, index=True)  # RULE_CREATED, RULE_UPDATED, RULE_DELETED, EVENT_ACKNOWLEDGED, EVENT_RESOLVED
    details = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "user_name": self.user_name,
            "action": self.action,
            "details": self.details,
            "created_at_iso": format_iso_utc(self.created_at),
            "created_at": format_local_datetime(self.created_at)  # LEGACY
        }


class SystemMetadata(db.Model):
    """
    Tabela leve para versionamento global de configurações e sincronização
    entre múltiplos workers do Gunicorn sem necessidade de Redis.
    """
    __tablename__ = "system_metadata"

    key = db.Column(db.String(64), primary_key=True)
    value = db.Column(db.String(512), nullable=False)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    @classmethod
    def get_value(cls, key: str, default: str = "") -> str:
        try:
            row = db.session.get(cls, key)
            return row.value if row else default
        except Exception:
            return default

    @classmethod
    def set_value(cls, key: str, value: str):
        try:
            row = db.session.get(cls, key)
            if not row:
                row = cls(key=key, value=str(value))
                db.session.add(row)
            else:
                row.value = str(value)
                row.updated_at = datetime.now(timezone.utc)
            db.session.commit()
        except Exception:
            db.session.rollback()


class ReleaseTargetDevice(db.Model):
    """
    Tabela associativa entre releases de agentes e dispositivos autorizados para Canary rollout.
    Permite direcionar releases com rollout_scope='devices' para computadores específicos.
    """
    __tablename__ = "release_target_devices"

    id = db.Column(db.Integer, primary_key=True)
    release_id = db.Column(db.Integer, db.ForeignKey("agent_releases.id", ondelete="CASCADE"), nullable=False, index=True)
    device_id = db.Column(db.Integer, db.ForeignKey("devices.id", ondelete="CASCADE"), nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        db.UniqueConstraint("release_id", "device_id", name="uq_release_target_device"),
        db.Index("idx_rel_target_dev", "release_id", "device_id"),
    )


class AgentRelease(db.Model):
    """
    Armazenamento persistente de releases de agentes no banco PostgreSQL/SQLite.
    Elimina dependência do filesystem efêmero do Render: suporta tanto URLs externas
    (GitHub Releases / S3 / R2) quanto armazenamento binário nativo no PostgreSQL.
    Suporta canais de distribuição (canary, stable) e escopos de rollout (devices, global).
    """
    __tablename__ = "agent_releases"

    id = db.Column(db.Integer, primary_key=True)
    version = db.Column(db.String(32), unique=True, nullable=False, index=True)
    sha256 = db.Column(db.String(64), nullable=False)
    download_url = db.Column(db.String(512), nullable=False)
    changelog = db.Column(db.Text, default="")
    min_supported_version = db.Column(db.String(32), default="1.0.0")
    min_updater_version = db.Column(db.String(32), default="1.1.0", nullable=False)
    mandatory = db.Column(db.Boolean, default=False)
    storage_type = db.Column(db.String(32), default="external")  # "external", "database", "r2", "local"
    object_key = db.Column(db.String(512), nullable=True)  # ex: "agents/1.5.0/GivovaMonitorAgent.exe"
    file_size = db.Column(db.BigInteger, nullable=True)  # tamanho exato em bytes do binário
    # Otimização Crítica: binary_data é deferred para evitar transferir/materializar o BLOB de ~13,7 MB
    # do PostgreSQL para o worker em consultas de metadata (rollout-progress, listagens e polling).
    binary_data = deferred(db.Column(db.LargeBinary, nullable=True))

    # Rollout & Canais (v1.5.0 Canary Architecture)
    release_channel = db.Column(db.String(30), default="stable", nullable=False, index=True)  # 'canary', 'stable'
    rollout_scope = db.Column(db.String(30), default="global", nullable=False, index=True)     # 'devices', 'global'
    status = db.Column(db.String(30), default="active", nullable=False, index=True)             # 'draft', 'active', 'paused', 'superseded'

    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    created_by = db.Column(db.String(64), default="admin")

    # Relacionamento com computadores alvos para testes Canary
    target_devices = db.relationship(
        "Device",
        secondary="release_target_devices",
        backref=db.backref("targeted_releases", lazy="dynamic"),
        lazy="selectin"
    )

    def validate_invariants(self) -> tuple[bool, str]:
        """
        Valida que a release respeita as regras de invariantes corporativas:
        - Canary deve ter escopo 'devices'
        - Stable deve ter escopo 'global'
        """
        ch = (self.release_channel or "stable").lower()
        sc = (self.rollout_scope or "global").lower()
        if ch == "canary" and sc != "devices":
            return False, "Releases do canal 'canary' exigem escopo 'devices'."
        if ch == "stable" and sc != "global":
            return False, "Releases do canal 'stable' exigem escopo 'global'."
        return True, ""

    def to_dict(self) -> dict:
        targets = [
            {
                "id": d.id,
                "hostname": d.hostname,
                "uuid": d.uuid,
                "display_name": d.display_name or d.hostname,
                "agent_version": d.agent_version,
                "status": d.get_status(Config.OFFLINE_THRESHOLD_SECONDS)
            }
            for d in self.target_devices
        ] if self.target_devices else []

        # Determina has_binary com segurança SEM disparar lazy-load do BLOB de 13,7 MB
        if self.storage_type == "r2":
            has_binary = bool(self.object_key or self.sha256)
        else:
            insp = inspect(self)
            if "binary_data" in insp.dict:
                has_binary = bool(insp.dict["binary_data"])
            elif "binary_data" in insp.unloaded or (hasattr(insp.attrs, "binary_data") and insp.attrs.binary_data.loaded_value is NO_VALUE):
                # Documentação arquitetural: binary_data é deferred para evitar transferir 13,7 MB do PostgreSQL
                # nas consultas de metadata. Quando unloaded, inferimos has_binary com base em storage_type == 'database'
                # e presença de sha256 válido, sem materializar o BLOB do banco.
                has_binary = (self.storage_type == "database" and bool(self.sha256))
            else:
                has_binary = False

        return {
            "id": self.id,
            "version": self.version,
            "sha256": self.sha256,
            "download_url": self.download_url,
            "changelog": self.changelog,
            "min_supported_version": self.min_supported_version,
            "min_updater_version": self.min_updater_version or "1.1.0",
            "mandatory": self.mandatory,
            "storage_type": self.storage_type,
            "object_key": self.object_key,
            "file_size": self.file_size,
            "has_binary": has_binary,
            "release_channel": self.release_channel or "stable",
            "rollout_scope": self.rollout_scope or "global",
            "status": self.status or "active",
            "target_device_count": len(targets),
            "target_device_ids": [t["id"] for t in targets],
            "target_devices": targets,
            "created_at_iso": format_iso_utc(self.created_at),
            "created_at": format_local_datetime(self.created_at),  # LEGACY
            "updated_at_iso": format_iso_utc(self.updated_at),
            "created_by": self.created_by
        }


class UpdaterRelease(db.Model):
    """Independently versioned, immutable R2 Updater artifact metadata."""
    __tablename__ = "updater_releases"

    id = db.Column(db.Integer, primary_key=True)
    version = db.Column(db.String(32), unique=True, nullable=False, index=True)
    sha256 = db.Column(db.String(64), nullable=False)
    file_size = db.Column(db.BigInteger, nullable=False)
    object_key = db.Column(db.String(512), nullable=False)
    status = db.Column(db.String(30), default="draft", nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def artifact(self):
        return {
            "version": self.version,
            "sha256": self.sha256,
            "file_size": self.file_size,
            "object_key": self.object_key,
            "download_url": f"/api/agent/updater/download/{self.version}",
        }


class UsageSession(db.Model):
    """
    Registra períodos contínuos de uso do computador por estado (active, idle, locked).
    Fonte temporal canônica para cálculos de tempo de atividade, ociosidade e bloqueio.
    """
    __tablename__ = "usage_sessions"

    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey("devices.id", ondelete="CASCADE"), nullable=False, index=True)
    windows_session_id = db.Column(db.Integer, nullable=True)
    state = db.Column(db.String(30), nullable=False, index=True)  # active, idle, overtime, off_hours (locked legacy)
    started_at = db.Column(db.DateTime, nullable=False, index=True)  # UTC
    ended_at = db.Column(db.DateTime, nullable=True, index=True)  # UTC
    duration_seconds = db.Column(db.Integer, default=0)
    is_open = db.Column(db.Boolean, default=True, index=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)

    __table_args__ = (
        db.Index("idx_usage_device_open", "device_id", "is_open"),
        db.Index("idx_usage_device_started", "device_id", "started_at"),
        db.Index("idx_usage_started_state", "started_at", "state"),
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "device_id": self.device_id,
            "windows_session_id": self.windows_session_id,
            "state": self.state,
            "started_at_iso": format_iso_utc(self.started_at),
            "started_at": format_local_datetime(self.started_at),  # LEGACY
            "ended_at_iso": format_iso_utc(self.ended_at),
            "ended_at": format_local_datetime(self.ended_at) if self.ended_at else None,  # LEGACY
            "duration_seconds": self.duration_seconds or 0,
            "is_open": bool(self.is_open),
            "created_at_iso": format_iso_utc(self.created_at)
        }


class DailyUsageSummary(db.Model):
    """
    Resumo consolidado diário por computador no fuso corporativo (America/Sao_Paulo).
    Atualizado de forma idempotente a partir das sessões de uso.
    """
    __tablename__ = "daily_usage_summaries"

    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey("devices.id", ondelete="CASCADE"), nullable=False, index=True)
    date = db.Column(db.Date, nullable=False, index=True)  # Data civil no fuso corporativo
    online_seconds = db.Column(db.Integer, default=0)
    active_seconds = db.Column(db.Integer, default=0)
    idle_seconds = db.Column(db.Integer, default=0)
    locked_seconds = db.Column(db.Integer, default=0)
    overtime_seconds = db.Column(db.Integer, default=0)
    off_hours_seconds = db.Column(db.Integer, default=0)
    offline_seconds = db.Column(db.Integer, default=0)
    first_seen = db.Column(db.DateTime, nullable=True)  # UTC
    last_seen = db.Column(db.DateTime, nullable=True)  # UTC
    active_percentage = db.Column(db.Float, default=0.0)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        db.UniqueConstraint("device_id", "date", name="uq_device_daily_usage"),
        db.Index("idx_daily_usage_date", "date"),
    )

    def to_dict(self) -> dict:
        active_work_seconds = self.active_seconds or 0
        overtime_seconds = self.overtime_seconds or 0
        return {
            "id": self.id,
            "device_id": self.device_id,
            "date": str(self.date),
            "online_seconds": self.online_seconds or 0,
            "active_seconds": active_work_seconds + overtime_seconds,
            "active_work_seconds": active_work_seconds,
            "idle_seconds": self.idle_seconds or 0,
            "idle_work_seconds": self.idle_seconds or 0,
            "locked_seconds": self.locked_seconds or 0,
            "overtime_seconds": overtime_seconds,
            "off_hours_seconds": self.off_hours_seconds or 0,
            "offline_seconds": self.offline_seconds or 0,
            "active_percentage": round(self.active_percentage or 0.0, 1),
            "first_seen_iso": format_iso_utc(self.first_seen),
            "first_seen": format_local_datetime(self.first_seen) if self.first_seen else None,  # LEGACY
            "last_seen_iso": format_iso_utc(self.last_seen),
            "last_seen": format_local_datetime(self.last_seen) if self.last_seen else None,  # LEGACY
            "updated_at_iso": format_iso_utc(self.updated_at),
            "updated_at": format_local_datetime(self.updated_at) if self.updated_at else None  # LEGACY
        }

