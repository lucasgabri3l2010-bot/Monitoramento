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
    
    # Versão do agente instalado
    agent_version = db.Column(db.String(20), default="1.0.0")
    
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

    def to_dict(self, offline_threshold_seconds: int = 30) -> dict:
        status = self.get_status(offline_threshold_seconds)
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
            "ultimo_contato_iso": self.updated_at.isoformat() if self.updated_at else None
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
            "resolved_at": self.resolved_at.strftime("%d/%m/%Y %H:%M:%S") if self.resolved_at else None
        }
