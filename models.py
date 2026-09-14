from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

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
    department = db.Column(db.String(100), default="TI", index=True)
    
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
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)

    # Relacionamentos
    metrics = db.relationship("MetricHistory", backref="device", cascade="all, delete-orphan", lazy="dynamic")
    alerts = db.relationship("Alert", backref="device", cascade="all, delete-orphan", lazy="dynamic")
    policy_events = db.relationship("PolicyEvent", backref="device", cascade="all, delete-orphan", lazy="dynamic")

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
        activity_time_str = self.activity_updated_at.strftime("%H:%M:%S") if self.activity_updated_at else None
        v_info = self.get_version_info(latest_version)

        is_recent_activity = False
        if self.activity_updated_at and status != "offline":
            now = datetime.now(timezone.utc)
            act_time = self.activity_updated_at
            if act_time.tzinfo is None:
                act_time = act_time.replace(tzinfo=timezone.utc)
            is_recent_activity = (now - act_time).total_seconds() <= (offline_threshold_seconds * 2)

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
            "last_update_check": self.last_update_check.strftime("%d/%m/%Y %H:%M:%S") if self.last_update_check else "Nunca",
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
            "ultimo_contato": self.updated_at.strftime("%d/%m/%Y %H:%M:%S") if self.updated_at else "Nunca",
            "ultimo_contato_iso": self.updated_at.isoformat() if self.updated_at else None,
            "active_app": self.active_app or "—",
            "active_domain": self.active_domain or "—",
            "active_activity_formatted": activity_formatted,
            "activity_updated_at": activity_time_str,
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
            "timestamp": self.timestamp.strftime("%H:%M:%S") if self.timestamp else "",
            "timestamp_iso": self.timestamp.isoformat() if self.timestamp else "",
            "cpu": round(self.cpu_percent, 1),
            "ram": round(self.ram_percent, 1),
            "ram_used_gb": round(self.ram_used_gb, 1),
            "disk": round(self.disk_percent, 1),
            "disk_used_gb": round(self.disk_used_gb, 1)
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
            "created_at": self.created_at.strftime("%d/%m/%Y %H:%M:%S") if self.created_at else "",
            "created_at_iso": self.created_at.isoformat() if self.created_at else "",
            "is_resolved": self.is_resolved,
            "resolved_at": self.resolved_at.strftime("%d/%m/%Y %H:%M:%S") if self.resolved_at else None,
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

    events = db.relationship("PolicyEvent", backref="rule", cascade="all, delete-orphan", lazy="dynamic")

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
            "created_at": self.created_at.strftime("%d/%m/%Y %H:%M:%S") if self.created_at else "",
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
            "first_seen": self.first_seen.strftime("%d/%m/%Y %H:%M:%S") if self.first_seen else "",
            "first_seen_iso": self.first_seen.isoformat() if self.first_seen else "",
            "last_seen": self.last_seen.strftime("%d/%m/%Y %H:%M:%S") if self.last_seen else "",
            "last_seen_iso": self.last_seen.isoformat() if self.last_seen else "",
            "duration_seconds": self.duration_seconds,
            "duration_formatted": self.format_duration(),
            "status": self.status,
            "source": self.source or "manual_rule",
            "acknowledged": self.acknowledged,
            "acknowledged_at": self.acknowledged_at.strftime("%d/%m/%Y %H:%M:%S") if self.acknowledged_at else None,
            "acknowledged_by": self.acknowledged_by,
            "is_resolved": bool(self.resolved_at),
            "resolved_at": self.resolved_at.strftime("%d/%m/%Y %H:%M:%S") if self.resolved_at else None,
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
            "created_at": self.created_at.strftime("%d/%m/%Y %H:%M:%S") if self.created_at else "",
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

    def is_expired(self) -> bool:
        if not self.expires_at:
            return False
        now = datetime.now(timezone.utc)
        exp = self.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        return now > exp

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "domain": self.domain,
            "category": self.category,
            "risk_level": self.risk_level,
            "confidence": round(self.confidence or 0.0, 2),
            "source": self.source,
            "status": self.status,
            "classified_at": self.classified_at.strftime("%d/%m/%Y %H:%M:%S") if self.classified_at else "",
            "expires_at": self.expires_at.strftime("%d/%m/%Y %H:%M:%S") if self.expires_at else "Nunca"
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
            "created_at": self.created_at.strftime("%d/%m/%Y %H:%M:%S") if self.created_at else ""
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


class AgentRelease(db.Model):
    """
    Armazenamento persistente de releases de agentes no banco PostgreSQL/SQLite.
    Elimina dependência do filesystem efêmero do Render: suporta tanto URLs externas
    (GitHub Releases / S3 / R2) quanto armazenamento binário nativo no PostgreSQL.
    """
    __tablename__ = "agent_releases"

    id = db.Column(db.Integer, primary_key=True)
    version = db.Column(db.String(32), unique=True, nullable=False, index=True)
    sha256 = db.Column(db.String(64), nullable=False)
    download_url = db.Column(db.String(512), nullable=False)
    changelog = db.Column(db.Text, default="")
    min_supported_version = db.Column(db.String(32), default="1.0.0")
    mandatory = db.Column(db.Boolean, default=False)
    storage_type = db.Column(db.String(32), default="external")  # "external", "database", "local"
    binary_data = db.Column(db.LargeBinary, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    created_by = db.Column(db.String(64), default="admin")

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "sha256": self.sha256,
            "download_url": self.download_url,
            "changelog": self.changelog,
            "min_supported_version": self.min_supported_version,
            "mandatory": self.mandatory,
            "storage_type": self.storage_type,
            "has_binary": bool(self.binary_data),
            "created_at": self.created_at.strftime("%d/%m/%Y %H:%M:%S") if self.created_at else "",
            "created_at_iso": self.created_at.isoformat() if self.created_at else "",
            "created_by": self.created_by
        }

