import time
import random
from datetime import datetime, timezone, timedelta
from models import db, Device, MetricHistory, Alert, PolicyRule, PolicyEvent, PolicyAuditLog, SystemMetadata, match_domain_secure, match_application_secure
from config import Config

class CachedPolicyRule:
    """
    Representação leve e desanexada da sessão do SQLAlchemy para cache em memória.
    Totalmente thread-safe e livre de erros de DetachedInstanceError entre requisições.
    """
    def __init__(self, id: int, name: str, rule_type: str, pattern: str, category: str,
                 severity: str, scope_type: str, scope_target: str, action: str, enabled: bool):
        self.id = id
        self.name = name
        self.rule_type = rule_type
        self.pattern = pattern
        self.category = category
        self.severity = severity
        self.scope_type = scope_type
        self.scope_target = scope_target
        self.action = action
        self.enabled = enabled

    def matches(self, app_name: str | None, domain: str | None, device_dept: str | None,
                device_host: str | None, device_uuid: str | None) -> bool:
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

        if self.rule_type == "domain":
            if not domain:
                return False
            return match_domain_secure(domain, clean_pat)
        elif self.rule_type == "application":
            if not app_name:
                return False
            return match_application_secure(app_name, clean_pat)

        return False

# Cache local de regras de política compatível com múltiplos workers do Gunicorn
_local_rules_cache = None
_local_rules_version = None
_last_version_check_time = 0
LOCAL_VERSION_CHECK_INTERVAL = 5.0  # Checa a versão global no banco no máximo a cada 5 segundos


def get_active_policy_rules() -> list:
    """
    Retorna regras de política ativas utilizando cache local sincronizado entre workers:
    1. Mantém cache local em memória no worker atual para evitar hits repetidos no DB.
    2. A cada LOCAL_VERSION_CHECK_INTERVAL (5s), consulta 'policy_rules_version' no banco.
    3. Se a versão global mudou (por alteração feita em qualquer worker), recarrega as regras.
    """
    global _local_rules_cache, _local_rules_version, _last_version_check_time
    now_ts = time.time()

    # Se já temos regras em cache e ainda estamos dentro da janela do TTL, retorna imediatamente
    if _local_rules_cache is not None and (now_ts - _last_version_check_time) < LOCAL_VERSION_CHECK_INTERVAL:
        return _local_rules_cache

    try:
        db_ver = SystemMetadata.get_value("policy_rules_version", "1")
        _last_version_check_time = now_ts

        if _local_rules_cache is not None and _local_rules_version == db_ver:
            return _local_rules_cache

        # Versão global mudou ou inicialização do worker: recarrega regras do banco em objetos desacoplados
        db_rules = PolicyRule.query.filter_by(enabled=True).all()
        rules = [
            CachedPolicyRule(
                id=r.id,
                name=r.name,
                rule_type=r.rule_type,
                pattern=r.pattern,
                category=r.category,
                severity=r.severity,
                scope_type=r.scope_type,
                scope_target=r.scope_target,
                action=r.action,
                enabled=r.enabled
            )
            for r in db_rules
        ]
        _local_rules_cache = rules
        _local_rules_version = db_ver
        return rules
    except Exception as e:
        print(f"[PolicyCache] Erro ao sincronizar regras de políticas entre workers: {e}")
        return _local_rules_cache or []


def invalidate_policy_rules_cache():
    """
    Invalida o cache corporativo de políticas entre TODOS os workers do Gunicorn:
    1. Limpa o cache local em memória do worker atual.
    2. Atualiza a versão global persistida em system_metadata no PostgreSQL/SQLite.
    Qualquer outro worker do Gunicorn detectará a nova versão no próximo ciclo de checagem.
    """
    global _local_rules_cache, _local_rules_version, _last_version_check_time
    _local_rules_cache = None
    _local_rules_version = None
    _last_version_check_time = 0

    try:
        new_version = str(int(time.time() * 1000))
        SystemMetadata.set_value("policy_rules_version", new_version)
    except Exception as e:
        print(f"[PolicyCache] Erro ao persistir nova versão global de políticas: {e}")

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
        if data.get("device_token"):
            if not device.device_token:
                device.device_token = data["device_token"]

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
    if Config.ACTIVITY_MONITORING_ENABLED and ("active_application" in data or "active_app" in data):
        device.active_app = data.get("active_application") or data.get("active_app")
        device.active_domain = data.get("active_domain")
        device.activity_updated_at = now

    # Avaliação de Políticas Corporativas de Uso (com cache em memória e deduplicação)
    if Config.POLICY_MONITORING_ENABLED:
        if device.active_app or device.active_domain:
            _evaluate_policies(device, now)
        else:
            _close_open_policy_events(device, now)

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

    # Avaliação de Alertas de Hardware
    _evaluate_alerts(device, cpu, ram, disco, now)

    # Limpeza aleatória de métricas antigas e eventos de políticas (1 chance em 50 para evitar sobrecarga)
    if random.random() < 0.02:
        cleanup_old_metrics()
        cleanup_old_policy_events()

    db.session.commit()
    return device


def _evaluate_policies(device: Device, now: datetime):
    """
    Avalia a atividade atual do computador contra as regras corporativas ativas.
    Utiliza cache em memória para não onerar o banco de dados.
    Deduplica ocorrências acumulando duration_seconds para evitar enxurrada de alertas repetidos.
    """
    rules = get_active_policy_rules()
    matching_rules = []
    for r in rules:
        if r.matches(
            app_name=device.active_app,
            domain=device.active_domain,
            device_dept=device.department,
            device_host=device.hostname,
            device_uuid=device.uuid
        ):
            matching_rules.append(r)

    sev_weight = {"critical": 3, "warning": 2, "info": 1}
    matching_rules.sort(key=lambda r: sev_weight.get(r.severity, 0), reverse=True)

    if matching_rules:
        primary_rule = matching_rules[0]

        # Busca ocorrência ativa para este dispositivo que corresponda à regra ou ao domínio/aplicativo atual
        active_event = PolicyEvent.query.filter(
            PolicyEvent.device_id == device.id,
            PolicyEvent.status == "active",
            (
                (PolicyEvent.policy_rule_id == primary_rule.id) |
                ((PolicyEvent.domain == device.active_domain) & (PolicyEvent.domain.isnot(None))) |
                ((PolicyEvent.application == device.active_app) & (PolicyEvent.application.isnot(None)))
            )
        ).first()

        if active_event:
            # Deduplicação: Atualiza last_seen e acumula tempo de permanência aproximado
            active_event.last_seen = now
            if active_event.first_seen:
                f_seen = active_event.first_seen
                if f_seen.tzinfo is None:
                    f_seen = f_seen.replace(tzinfo=timezone.utc)
                active_event.duration_seconds = max(0, int((now - f_seen).total_seconds()))
        else:
            # Encerra qualquer outro evento aberto anteriormente de atividade diferente
            _close_open_policy_events(device, now, except_domain=device.active_domain, except_app=device.active_app)

            # Registra nova ocorrência corporativa
            new_event = PolicyEvent(
                device_id=device.id,
                policy_rule_id=primary_rule.id,
                event_type=primary_rule.rule_type,
                category=primary_rule.category,
                severity=primary_rule.severity,
                application=device.active_app,
                domain=device.active_domain,
                first_seen=now,
                last_seen=now,
                duration_seconds=0,
                status="active"
            )
            db.session.add(new_event)
    else:
        # Usuário retornou para aplicativo/site corporativo permitido: fecha eventos de política ativos
        _close_open_policy_events(device, now)


def _close_open_policy_events(device: Device, now: datetime, except_domain: str | None = None, except_app: str | None = None):
    """
    Encerra eventos que o usuário parou de utilizar, calculando a duração final.
    """
    query = PolicyEvent.query.filter(
        PolicyEvent.device_id == device.id,
        PolicyEvent.status == "active"
    )
    for event in query.all():
        if except_domain and event.domain == except_domain:
            continue
        if except_app and event.application == except_app:
            continue

        event.status = "closed"
        event.resolved_at = now
        if event.first_seen:
            f_seen = event.first_seen
            if f_seen.tzinfo is None:
                f_seen = f_seen.replace(tzinfo=timezone.utc)
            event.duration_seconds = max(0, int((now - f_seen).total_seconds()))


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


def cleanup_old_policy_events():
    """
    Remove ocorrências de políticas já resolvidas/fechadas com base em Config.POLICY_EVENT_RETENTION_DAYS.
    """
    try:
        cutoff = datetime.now(timezone.utc) - timedelta(days=Config.POLICY_EVENT_RETENTION_DAYS)
        deleted = PolicyEvent.query.filter(
            PolicyEvent.status == "closed",
            PolicyEvent.last_seen < cutoff
        ).delete()
        db.session.commit()
        if deleted > 0:
            print(f"[Cleanup] Removidas {deleted} ocorrências antigas de políticas.")
    except Exception as e:
        db.session.rollback()
        print(f"[Cleanup] Erro ao limpar ocorrências de políticas: {e}")


def get_dashboard_stats():
    """
    Calcula agregados completos para o Dashboard da Givova Transportes.
    Suporta DEMO_MODE opcional com sobreposição virtual em memória (zero contaminação de banco).
    """
    # 1. Dispositivos reais do banco de dados
    real_devices = Device.query.all()
    all_devices = [d.to_dict(Config.OFFLINE_THRESHOLD_SECONDS, Config.LATEST_AGENT_VERSION) for d in real_devices]

    # 2. Se DEMO_MODE estiver ativo, anexa os dispositivos virtuais em memória
    demo_alerts = []
    demo_policy_events = []
    if Config.DEMO_MODE:
        from demo_data import get_demo_devices, get_demo_alerts, get_demo_policy_events
        demo_devices = get_demo_devices()
        all_devices.extend(demo_devices)
        demo_alerts = get_demo_alerts()
        demo_policy_events = get_demo_policy_events()

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

    # Alertas de hardware ativos (reais + virtuais se DEMO_MODE)
    real_alerts = Alert.query.filter_by(is_resolved=False).order_by(Alert.created_at.desc()).limit(10).all()
    alerts_list = demo_alerts + [a.to_dict() for a in real_alerts]

    # Eventos de políticas corporativas ativos
    real_policy_events = PolicyEvent.query.filter_by(status="active").order_by(PolicyEvent.last_seen.desc()).limit(20).all()
    policy_events_list = demo_policy_events + [pe.to_dict() for pe in real_policy_events]
    active_policy_alerts_count = len(policy_events_list)

    # Resumo de Versões da Frota
    fleet_versions = {
        "latest_version": Config.LATEST_AGENT_VERSION,
        "up_to_date": sum(1 for d in all_devices if d.get("version_status") == "up_to_date"),
        "update_available": sum(1 for d in all_devices if d.get("version_status") == "update_available"),
        "outdated_critical": sum(1 for d in all_devices if d.get("version_status") == "outdated_critical")
    }

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
        "active_policy_alerts_count": active_policy_alerts_count,
        "recent_policy_events": policy_events_list,
        "fleet_versions": fleet_versions,
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
        "policy_monitoring_enabled": Config.POLICY_MONITORING_ENABLED,
        "recent_activities": recent_activities,
        "demo_mode_active": Config.DEMO_MODE
    }

