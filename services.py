import random
from datetime import datetime, timezone, timedelta
from models import db, Device, MetricHistory, Alert
from config import Config

def process_agent_payload(data: dict) -> Device:
    """
    Processa payload enviado pelo agente de monitoramento, atualiza o dispositivo,
    registra métrica histórica e avalia condições de alerta.
    """
    uuid = data.get("uuid")
    hostname = data.get("computador") or data.get("hostname")
    
    if not hostname:
        raise ValueError("O campo 'computador' ou 'hostname' é obrigatório")

    # Se UUID não for fornecido, cria um identificador determinístico baseado no hostname
    if not uuid:
        uuid = f"host-{hostname.lower().strip()}"

    # Busca dispositivo existente por UUID ou pelo hostname
    device = Device.query.filter((Device.uuid == uuid) | (Device.hostname == hostname)).first()

    now = datetime.now(timezone.utc)

    if not device:
        device = Device(
            uuid=uuid,
            hostname=hostname,
            display_name=data.get("display_name") or hostname,
            user_name=data.get("usuario") or data.get("user_name"),
            department=data.get("setor") or data.get("department") or "TI",
            ip_address=data.get("ip"),
            mac_address=data.get("mac"),
            os_name=data.get("os_name") or data.get("sistema_operacional"),
            os_arch=data.get("os_arch") or data.get("arquitetura"),
            processor=data.get("processador"),
            cpu_cores=int(data.get("cpu_cores", 1)),
            ram_total_gb=float(data.get("ram_total_gb", 0.0)),
            disk_total_gb=float(data.get("disk_total_gb", 0.0)),
            agent_version=data.get("agent_version", "1.1.0"),
            created_at=now
        )
        db.session.add(device)
        db.session.flush() # Para obter device.id
    else:
        # Atualiza informações de hardware e rede se informadas
        if data.get("ip"):
            device.ip_address = data["ip"]
        if data.get("mac"):
            device.mac_address = data["mac"]
        if data.get("usuario"):
            device.user_name = data["usuario"]
        if data.get("setor") and device.department == "TI":
            device.department = data["setor"]
        if data.get("os_name"):
            device.os_name = data["os_name"]
        if data.get("os_arch"):
            device.os_arch = data["os_arch"]
        if data.get("processador"):
            device.processor = data["processador"]
        if data.get("cpu_cores"):
            device.cpu_cores = int(data["cpu_cores"])
        if data.get("ram_total_gb"):
            device.ram_total_gb = float(data["ram_total_gb"])
        if data.get("disk_total_gb"):
            device.disk_total_gb = float(data["disk_total_gb"])
        if data.get("agent_version"):
            device.agent_version = data["agent_version"]

    # Extrai métricas
    cpu = float(data.get("cpu", 0.0))
    ram = float(data.get("ram", 0.0))
    disco = float(data.get("disco", 0.0))
    ram_used_gb = float(data.get("ram_used_gb", 0.0))
    disk_used_gb = float(data.get("disk_used_gb", 0.0))
    uptime_seconds = int(data.get("uptime_seconds", 0))

    # Atualiza métricas instantâneas
    device.last_cpu = cpu
    device.last_ram = ram
    device.last_ram_used_gb = ram_used_gb
    device.last_disk = disco
    device.last_disk_used_gb = disk_used_gb
    device.last_uptime_seconds = uptime_seconds
    device.updated_at = now

    # Atualiza atividade em primeiro plano (caso habilitado na configuração)
    if Config.ACTIVITY_MONITORING_ENABLED and "active_application" in data:
        device.active_app = data.get("active_application")
        device.active_domain = data.get("active_domain")
        device.activity_updated_at = now

    # Registra no histórico temporal
    metric = MetricHistory(
        device_id=device.id,
        timestamp=now,
        cpu_percent=cpu,
        ram_percent=ram,
        ram_used_gb=ram_used_gb,
        disk_percent=disco,
        disk_used_gb=disk_used_gb,
        uptime_seconds=uptime_seconds
    )
    db.session.add(metric)

    # Avaliação de Alertas
    _evaluate_alerts(device, cpu, ram, disco, now)

    # Limpeza aleatória de métricas antigas (1 chance em 50 para evitar sobrecarga)
    if random.random() < 0.02:
        cleanup_old_metrics()

    db.session.commit()
    return device


def _evaluate_alerts(device: Device, cpu: float, ram: float, disco: float, now: datetime):
    """
    Avalia limites e registra ou resolve alertas de forma idempotente.
    """
    fifteen_mins_ago = now - timedelta(minutes=15)

    # 1. Alerta de CPU
    if cpu >= Config.CPU_ALERT_PERCENT:
        sev = "critical" if cpu >= 95.0 else "warning"
        recent_alert = Alert.query.filter(
            Alert.device_id == device.id,
            Alert.alert_type == "cpu_high",
            Alert.is_resolved == False,
            Alert.created_at >= fifteen_mins_ago
        ).first()

        if not recent_alert:
            alert = Alert(
                device_id=device.id,
                severity=sev,
                alert_type="cpu_high",
                message=f"Uso de CPU atingiu {round(cpu, 1)}% no computador {device.display_name or device.hostname}.",
                created_at=now
            )
            db.session.add(alert)
    elif cpu < (Config.CPU_ALERT_PERCENT - 10.0):
        # Auto-resolve alertas anteriores de CPU
        unresolved = Alert.query.filter_by(device_id=device.id, alert_type="cpu_high", is_resolved=False).all()
        for a in unresolved:
            a.is_resolved = True
            a.resolved_at = now

    # 2. Alerta de RAM
    if ram >= Config.RAM_ALERT_PERCENT:
        sev = "critical" if ram >= 95.0 else "warning"
        recent_alert = Alert.query.filter(
            Alert.device_id == device.id,
            Alert.alert_type == "ram_high",
            Alert.is_resolved == False,
            Alert.created_at >= fifteen_mins_ago
        ).first()

        if not recent_alert:
            alert = Alert(
                device_id=device.id,
                severity=sev,
                alert_type="ram_high",
                message=f"Consumo de Memória RAM atingiu {round(ram, 1)}% ({round(device.last_ram_used_gb, 1)} GB de {round(device.ram_total_gb, 1)} GB) em {device.display_name or device.hostname}.",
                created_at=now
            )
            db.session.add(alert)
    elif ram < (Config.RAM_ALERT_PERCENT - 10.0):
        unresolved = Alert.query.filter_by(device_id=device.id, alert_type="ram_high", is_resolved=False).all()
        for a in unresolved:
            a.is_resolved = True
            a.resolved_at = now

    # 3. Alerta de Disco
    if disco >= Config.DISK_ALERT_PERCENT:
        sev = "critical" if disco >= 95.0 else "warning"
        recent_alert = Alert.query.filter(
            Alert.device_id == device.id,
            Alert.alert_type == "disk_high",
            Alert.is_resolved == False,
            Alert.created_at >= fifteen_mins_ago
        ).first()

        if not recent_alert:
            alert = Alert(
                device_id=device.id,
                severity=sev,
                alert_type="disk_high",
                message=f"Armazenamento em disco atingiu {round(disco, 1)}% de capacidade em {device.display_name or device.hostname}.",
                created_at=now
            )
            db.session.add(alert)
    elif disco < (Config.DISK_ALERT_PERCENT - 5.0):
        unresolved = Alert.query.filter_by(device_id=device.id, alert_type="disk_high", is_resolved=False).all()
        for a in unresolved:
            a.is_resolved = True
            a.resolved_at = now


def cleanup_old_metrics():
    """
    Remove registros de métricas mais antigos que Config.METRICS_RETENTION_DAYS.
    """
    try:
        cutoff = datetime.now(timezone.utc) - timedelta(days=Config.METRICS_RETENTION_DAYS)
        deleted = MetricHistory.query.filter(MetricHistory.timestamp < cutoff).delete()
        db.session.commit()
        if deleted > 0:
            print(f"[Cleanup] Removidas {deleted} métricas históricas antigas.")
    except Exception as e:
        db.session.rollback()
        print(f"[Cleanup] Erro ao limpar métricas antigas: {e}")


def get_dashboard_stats():
    """
    Calcula agregados completos para o Dashboard da Givova Transportes.
    Suporta DEMO_MODE opcional com sobreposição virtual em memória (zero contaminação de banco).
    """
    # 1. Dispositivos reais do banco de dados
    real_devices = Device.query.all()
    all_devices = [d.to_dict(Config.OFFLINE_THRESHOLD_SECONDS) for d in real_devices]

    # 2. Se DEMO_MODE estiver ativo, anexa os dispositivos virtuais em memória
    demo_alerts = []
    if Config.DEMO_MODE:
        from demo_data import get_demo_devices, get_demo_alerts
        demo_devices = get_demo_devices()
        all_devices.extend(demo_devices)
        demo_alerts = get_demo_alerts()

    total_devices = len(all_devices)
    online_count = sum(1 for d in all_devices if d.get("status") in ("online", "warning", "critical"))
    offline_count = sum(1 for d in all_devices if d.get("status") == "offline")
    warning_count = sum(1 for d in all_devices if d.get("status") == "warning")
    critical_count = sum(1 for d in all_devices if d.get("status") == "critical")

    total_cpu = sum(float(d.get("cpu") or 0.0) for d in all_devices)
    total_ram = sum(float(d.get("ram") or 0.0) for d in all_devices)
    total_disk_gb = sum(float(d.get("disk_total_gb") or 0.0) for d in all_devices)
    total_disk_used_gb = sum(float(d.get("last_disk_used_gb") or 0.0) for d in all_devices)

    departments_map = {}
    for d in all_devices:
        dept = d.get("department") or "Outros"
        departments_map[dept] = departments_map.get(dept, 0) + 1

    avg_cpu = round(total_cpu / total_devices, 1) if total_devices > 0 else 0.0
    avg_ram = round(total_ram / total_devices, 1) if total_devices > 0 else 0.0
    total_disk_free_gb = round(max(0.0, total_disk_gb - total_disk_used_gb), 1)

    # Alertas ativos (reais + virtuais se DEMO_MODE)
    real_alerts = Alert.query.filter_by(is_resolved=False).order_by(Alert.created_at.desc()).limit(10).all()
    alerts_list = demo_alerts + [a.to_dict() for a in real_alerts]

    # Top computadores por consumo de CPU e RAM
    top_cpu = sorted(all_devices, key=lambda x: float(x.get("cpu") or 0.0), reverse=True)[:5]
    top_ram = sorted(all_devices, key=lambda x: float(x.get("ram") or 0.0), reverse=True)[:5]

    # Atividade em tempo real de computadores online
    recent_activities = []
    if Config.ACTIVITY_MONITORING_ENABLED:
        online_devs = [
            d for d in all_devices
            if d.get("status") in ("online", "warning", "critical")
            and d.get("active_app") and d.get("active_app") != "—"
        ]
        for d in online_devs[:8]:
            recent_activities.append({
                "id": d["id"],
                "name": d.get("display_name") or d.get("hostname"),
                "user_name": d.get("user_name") or "—",
                "department": d.get("department") or "—",
                "active_app": d.get("active_app") or "—",
                "active_domain": d.get("active_domain") or "—",
                "formatted_activity": d.get("active_activity_formatted") or d.get("active_app"),
                "activity_updated_at": d.get("activity_updated_at") or "—",
                "is_demo": d.get("is_demo", False)
            })

    return {
        "total_devices": total_devices,
        "online_count": online_count,
        "offline_count": offline_count,
        "warning_count": warning_count,
        "critical_count": critical_count,
        "avg_cpu": avg_cpu,
        "avg_ram": avg_ram,
        "total_disk_gb": round(total_disk_gb, 1),
        "total_disk_free_gb": total_disk_free_gb,
        "departments": departments_map,
        "active_alerts_count": len(alerts_list),
        "recent_alerts": alerts_list,
        "top_cpu_devices": [
            {
                "id": d["id"],
                "name": d.get("display_name") or d.get("hostname"),
                "department": d.get("department"),
                "cpu": round(float(d.get("cpu") or 0.0), 1),
                "is_demo": d.get("is_demo", False)
            }
            for d in top_cpu
        ],
        "top_ram_devices": [
            {
                "id": d["id"],
                "name": d.get("display_name") or d.get("hostname"),
                "department": d.get("department"),
                "ram": round(float(d.get("ram") or 0.0), 1),
                "is_demo": d.get("is_demo", False)
            }
            for d in top_ram
        ],
        "activity_monitoring_enabled": Config.ACTIVITY_MONITORING_ENABLED,
        "recent_activities": recent_activities,
        "demo_mode_active": Config.DEMO_MODE
    }

