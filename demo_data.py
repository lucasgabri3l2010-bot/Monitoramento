"""
Givova Transportes - Módulo de Dados Virtuais de Demonstração (DEMO_MODE)
Finalidade: Fornecer dados fictícios exclusivamente em memória durante apresentações à diretoria.
Garantia: NUNCA grava dados no banco de dados nem contamina tabelas reais.
"""

from datetime import datetime, timezone, timedelta
import math
from datetime_utils import format_iso_utc, format_local_datetime, format_local_time, utc_now

def get_demo_devices() -> list:
    """
    Retorna a lista de 9 computadores virtuais de demonstração distribuídos
    nos 6 setores da Givova Transportes. Todos marcados com is_demo = True.
    """
    now = utc_now()
    recent_ts = format_local_datetime(now)
    recent_iso = format_iso_utc(now)
    recent_time = format_local_time(now)

    offline_time = now - timedelta(hours=4, minutes=15)
    offline_ts = format_local_datetime(offline_time)
    offline_iso = format_iso_utc(offline_time)

    return [
        # --- LOGÍSTICA ---
        {
            "id": 90001,
            "uuid": "demo-logistica-expedicao-01",
            "hostname": "PC-EXPEDICAO-01",
            "display_name": "PC Expedição 01",
            "user_name": "Operador de Cargas",
            "department": "Logística",
            "ip_address": "192.168.10.12",
            "mac_address": "00:1A:2B:3C:4D:01",
            "os_name": "Windows 11 Pro",
            "os_arch": "x64",
            "processor": "Intel Core i5-11400 @ 2.60GHz",
            "cpu_cores": 6,
            "ram_total_gb": 8.0,
            "last_ram_used_gb": 4.3,
            "disk_total_gb": 480.0,
            "last_disk_used_gb": 201.6,
            "disk_free_gb": 278.4,
            "agent_version": "1.3.0",
            "cpu": 28.5,
            "ram": 54.0,
            "disco": 42.0,
            "uptime": "2d 4h 15m",
            "uptime_seconds": 188100,
            "status": "online",
            "status_label": "Online",
            "ultimo_contato": recent_ts,
            "ultimo_contato_iso": recent_iso,
            "active_app": "Microsoft Excel — Planilha de Expedição",
            "active_domain": "—",
            "active_activity_formatted": "📊 Microsoft Excel — Planilha de Expedição",
            "activity_updated_at": recent_time,
            "activity_recent": True,
            "is_demo": True
        },
        {
            "id": 90002,
            "uuid": "demo-logistica-doca-02",
            "hostname": "PC-DOCA-ENTRADA",
            "display_name": "PC Doca de Entrada",
            "user_name": "Conferente de Pátio",
            "department": "Logística",
            "ip_address": "192.168.10.15",
            "mac_address": "00:1A:2B:3C:4D:02",
            "os_name": "Windows 10 Pro",
            "os_arch": "x64",
            "processor": "Intel Core i3-10100 @ 3.60GHz",
            "cpu_cores": 4,
            "ram_total_gb": 8.0,
            "last_ram_used_gb": 3.5,
            "disk_total_gb": 240.0,
            "last_disk_used_gb": 139.2,
            "disk_free_gb": 100.8,
            "agent_version": "1.3.0",
            "cpu": 16.0,
            "ram": 44.0,
            "disco": 58.0,
            "uptime": "1d 8h 30m",
            "uptime_seconds": 117000,
            "status": "online",
            "status_label": "Online",
            "ultimo_contato": recent_ts,
            "ultimo_contato_iso": recent_iso,
            "active_app": "ERP Givova Transportes",
            "active_domain": "—",
            "active_activity_formatted": "🖥️ ERP Givova Transportes",
            "activity_updated_at": recent_time,
            "activity_recent": True,
            "is_demo": True
        },

        # --- FATURAMENTO ---
        {
            "id": 90003,
            "uuid": "demo-faturamento-02",
            "hostname": "PC-FATURAMENTO-02",
            "display_name": "PC Faturamento 02",
            "user_name": "Analista Fiscal",
            "department": "Faturamento",
            "ip_address": "192.168.20.22",
            "mac_address": "00:1A:2B:3C:4D:03",
            "os_name": "Windows 11 Pro",
            "os_arch": "x64",
            "processor": "Intel Core i7-11700 @ 2.50GHz",
            "cpu_cores": 8,
            "ram_total_gb": 16.0,
            "last_ram_used_gb": 13.8,
            "disk_total_gb": 512.0,
            "last_disk_used_gb": 261.1,
            "disk_free_gb": 250.9,
            "agent_version": "1.3.0",
            "cpu": 92.4,
            "ram": 86.5,
            "disco": 51.0,
            "uptime": "5d 11h 45m",
            "uptime_seconds": 474300,
            "status": "warning",
            "status_label": "Alerta",
            "ultimo_contato": recent_ts,
            "ultimo_contato_iso": recent_iso,
            "active_app": "Emissor NF-e",
            "active_domain": "—",
            "active_activity_formatted": "🖥️ Emissor NF-e",
            "activity_updated_at": recent_time,
            "activity_recent": True,
            "is_demo": True
        },

        # --- FINANCEIRO ---
        {
            "id": 90004,
            "uuid": "demo-financeiro-01",
            "hostname": "PC-FINANCEIRO-01",
            "display_name": "PC Financeiro 01",
            "user_name": "Controladoria",
            "department": "Financeiro",
            "ip_address": "192.168.30.10",
            "mac_address": "00:1A:2B:3C:4D:04",
            "os_name": "Windows 11 Pro",
            "os_arch": "x64",
            "processor": "Intel Core i5-12400 @ 2.50GHz",
            "cpu_cores": 6,
            "ram_total_gb": 16.0,
            "last_ram_used_gb": 9.8,
            "disk_total_gb": 512.0,
            "last_disk_used_gb": 174.0,
            "disk_free_gb": 338.0,
            "agent_version": "1.3.0",
            "cpu": 22.0,
            "ram": 61.0,
            "disco": 34.0,
            "uptime": "3d 6h 10m",
            "uptime_seconds": 281400,
            "status": "online",
            "status_label": "Online",
            "ultimo_contato": recent_ts,
            "ultimo_contato_iso": recent_iso,
            "active_app": "Google Chrome",
            "active_domain": "banking.itau.com.br",
            "active_activity_formatted": "🌐 banking.itau.com.br",
            "activity_updated_at": recent_time,
            "activity_recent": True,
            "is_demo": True
        },
        {
            "id": 90005,
            "uuid": "demo-financeiro-tesouraria",
            "hostname": "PC-TESOURARIA",
            "display_name": "PC Tesouraria",
            "user_name": "Caixa Central",
            "department": "Financeiro",
            "ip_address": "192.168.30.18",
            "mac_address": "00:1A:2B:3C:4D:05",
            "os_name": "Windows 10 Pro",
            "os_arch": "x64",
            "processor": "Intel Core i3-9100 @ 3.60GHz",
            "cpu_cores": 4,
            "ram_total_gb": 8.0,
            "last_ram_used_gb": 0.0,
            "disk_total_gb": 240.0,
            "last_disk_used_gb": 67.2,
            "disk_free_gb": 172.8,
            "agent_version": "1.1.0",
            "cpu": 0.0,
            "ram": 0.0,
            "disco": 28.0,
            "uptime": "0m",
            "uptime_seconds": 0,
            "status": "offline",
            "status_label": "Offline",
            "ultimo_contato": offline_ts,
            "ultimo_contato_iso": offline_iso,
            "active_app": "—",
            "active_domain": "—",
            "active_activity_formatted": "Sem atividade recente",
            "activity_updated_at": None,
            "activity_recent": False,
            "is_demo": True
        },

        # --- JURÍDICO ---
        {
            "id": 90006,
            "uuid": "demo-juridico-01",
            "hostname": "PC-JURIDICO-01",
            "display_name": "PC Jurídico 01",
            "user_name": "Assessoria Jurídica",
            "department": "Jurídico",
            "ip_address": "192.168.40.05",
            "mac_address": "00:1A:2B:3C:4D:06",
            "os_name": "Windows 11 Pro",
            "os_arch": "x64",
            "processor": "AMD Ryzen 5 5600G @ 3.90GHz",
            "cpu_cores": 6,
            "ram_total_gb": 16.0,
            "last_ram_used_gb": 7.7,
            "disk_total_gb": 500.0,
            "last_disk_used_gb": 145.0,
            "disk_free_gb": 355.0,
            "agent_version": "1.3.0",
            "cpu": 14.5,
            "ram": 48.0,
            "disco": 29.0,
            "uptime": "4d 2h 00m",
            "uptime_seconds": 352800,
            "status": "online",
            "status_label": "Online",
            "ultimo_contato": recent_ts,
            "ultimo_contato_iso": recent_iso,
            "active_app": "Microsoft Word — Documento Jurídico",
            "active_domain": "—",
            "active_activity_formatted": "📝 Microsoft Word — Documento Jurídico",
            "activity_updated_at": recent_time,
            "activity_recent": True,
            "is_demo": True
        },

        # --- MONITORAMENTO ---
        {
            "id": 90007,
            "uuid": "demo-monitoramento-rastreamento-01",
            "hostname": "PC-RASTREAMENTO-01",
            "display_name": "PC Rastreamento 01",
            "user_name": "Operador de Frota",
            "department": "Monitoramento",
            "ip_address": "192.168.50.11",
            "mac_address": "00:1A:2B:3C:4D:07",
            "os_name": "Windows 11 Pro",
            "os_arch": "x64",
            "processor": "Intel Core i7-10700 @ 2.90GHz",
            "cpu_cores": 8,
            "ram_total_gb": 16.0,
            "last_ram_used_gb": 10.9,
            "disk_total_gb": 512.0,
            "last_disk_used_gb": 266.2,
            "disk_free_gb": 245.8,
            "agent_version": "1.3.0",
            "cpu": 36.0,
            "ram": 68.0,
            "disco": 52.0,
            "uptime": "6d 14h 20m",
            "uptime_seconds": 569000,
            "status": "online",
            "status_label": "Online",
            "ultimo_contato": recent_ts,
            "ultimo_contato_iso": recent_iso,
            "active_app": "Microsoft Edge",
            "active_domain": "autotrac.com.br",
            "active_activity_formatted": "🌐 autotrac.com.br",
            "activity_updated_at": recent_time,
            "activity_recent": True,
            "is_demo": True
        },
        {
            "id": 90008,
            "uuid": "demo-monitoramento-sascar-02",
            "hostname": "PC-SASCAR-02",
            "display_name": "PC Sascar 02",
            "user_name": "Central de Telemetria",
            "department": "Monitoramento",
            "ip_address": "192.168.50.14",
            "mac_address": "00:1A:2B:3C:4D:08",
            "os_name": "Windows 11 Pro",
            "os_arch": "x64",
            "processor": "Intel Core i5-11400 @ 2.60GHz",
            "cpu_cores": 6,
            "ram_total_gb": 16.0,
            "last_ram_used_gb": 9.9,
            "disk_total_gb": 480.0,
            "last_disk_used_gb": 235.2,
            "disk_free_gb": 244.8,
            "agent_version": "1.3.0",
            "cpu": 31.0,
            "ram": 62.0,
            "disco": 49.0,
            "uptime": "3d 18h 40m",
            "uptime_seconds": 326400,
            "status": "online",
            "status_label": "Online",
            "ultimo_contato": recent_ts,
            "ultimo_contato_iso": recent_iso,
            "active_app": "Google Chrome",
            "active_domain": "sascar.com.br",
            "active_activity_formatted": "🌐 sascar.com.br",
            "activity_updated_at": recent_time,
            "activity_recent": True,
            "is_demo": True
        },

        # --- TI ---
        {
            "id": 90009,
            "uuid": "demo-ti-srv-backup",
            "hostname": "SRV-BACKUP-TI",
            "display_name": "Servidor de Backup TI",
            "user_name": "Automatizado TI",
            "department": "TI",
            "ip_address": "192.168.1.200",
            "mac_address": "00:1A:2B:3C:4D:09",
            "os_name": "Windows Server 2022",
            "os_arch": "x64",
            "processor": "Intel Xeon Silver 4210 @ 2.20GHz",
            "cpu_cores": 10,
            "ram_total_gb": 32.0,
            "last_ram_used_gb": 18.5,
            "disk_total_gb": 2048.0,
            "last_disk_used_gb": 1607.6,
            "disk_free_gb": 440.4,
            "agent_version": "1.4.0",
            "cpu": 44.0,
            "ram": 58.0,
            "disco": 78.5,
            "uptime": "28d 10h 15m",
            "uptime_seconds": 2456100,
            "status": "online",
            "status_label": "Online",
            "ultimo_contato": recent_ts,
            "ultimo_contato_iso": recent_iso,
            "active_app": "Veeam Backup & Replication",
            "active_domain": "—",
            "active_activity_formatted": "🖥️ Veeam Backup & Replication",
            "activity_updated_at": recent_time,
            "activity_recent": True,
            "is_demo": True
        }
    ]

    for d in devices:
        _enrich_version_info(d)

    return devices


def _enrich_version_info(device_dict: dict, latest_version: str = "1.4.0"):
    from models import compare_versions, parse_semver
    cur = device_dict.get("agent_version", "1.0.0")
    cmp = compare_versions(cur, latest_version)
    if cmp >= 0:
        device_dict["version_status"] = "up_to_date"
        device_dict["version_label"] = f"Atualizado — v{cur}"
        device_dict["version_badge_class"] = "bg-emerald-50 text-emerald-700 border-emerald-200"
        device_dict["version_needs_update"] = False
        device_dict["version_is_critical"] = False
    else:
        p_cur = parse_semver(cur)
        p_lat = parse_semver(latest_version)
        is_crit = (p_cur[0] < p_lat[0]) or ((p_lat[1] - p_cur[1]) >= 2)
        if is_crit:
            device_dict["version_status"] = "outdated_critical"
            device_dict["version_label"] = f"Desatualizado Crítico — v{cur}"
            device_dict["version_badge_class"] = "bg-rose-50 text-rose-700 border-rose-200"
            device_dict["version_needs_update"] = True
            device_dict["version_is_critical"] = True
        else:
            device_dict["version_status"] = "update_available"
            device_dict["version_label"] = f"Atualização disponível — v{cur} → v{latest_version}"
            device_dict["version_badge_class"] = "bg-amber-50 text-amber-700 border-amber-200"
            device_dict["version_needs_update"] = True
            device_dict["version_is_critical"] = False
    device_dict["latest_available_version"] = latest_version
    device_dict["last_update_check"] = device_dict.get("ultimo_contato")
    device_dict["is_admin_device"] = device_dict.get("department") == "TI"
    device_dict["has_individual_token"] = True


def get_demo_device(device_id: int) -> dict | None:
    """
    Retorna os detalhes de um computador de demonstração pelo ID com métricas e alertas simulados.
    """
    devices = get_demo_devices()
    device = next((d for d in devices if d["id"] == device_id), None)
    if not device:
        return None

    # Gera 30 métricas históricas realistas com timestamps recentes
    now = utc_now()
    metrics = []
    base_cpu = device["cpu"]
    base_ram = device["ram"]

    for i in range(29, -1, -1):
        ts = now - timedelta(minutes=i * 2)
        # Variação senoidal suave para criar uma curva estética no Chart.js
        variation = math.sin(i * 0.5) * 4.0
        cpu_val = max(1.0, min(99.0, round(base_cpu + variation, 1)))
        ram_val = max(1.0, min(99.0, round(base_ram + (variation * 0.3), 1)))

        metrics.append({
            "id": 900000 + i,
            "timestamp": format_local_time(ts),
            "timestamp_iso": format_iso_utc(ts),
            "cpu": cpu_val,
            "ram": ram_val,
            "ram_used_gb": round(device["ram_total_gb"] * (ram_val / 100.0), 1),
            "disk": device["disco"],
            "disk_used_gb": round(device["last_disk_used_gb"], 1)
        })

    # Alertas específicos do dispositivo de demonstração
    alerts = []
    if device["status"] == "warning":
        alerts.append({
            "id": 9001,
            "device_id": device["id"],
            "device_name": device["display_name"],
            "department": device["department"],
            "severity": "warning",
            "alert_type": "cpu_high",
            "message": f"[DEMO] Processador acima do limite seguro: {device['cpu']}% (limite: 90.0%)",
            "created_at_iso": format_iso_utc(now - timedelta(minutes=25)),
            "created_at": format_local_datetime(now - timedelta(minutes=25)),
            "is_resolved": False,
            "resolved_at": None,
            "is_demo": True
        })
    elif device["status"] == "offline":
        alerts.append({
            "id": 9002,
            "device_id": device["id"],
            "device_name": device["display_name"],
            "department": device["department"],
            "severity": "warning",
            "alert_type": "offline",
            "message": "[DEMO] Dispositivo sem comunicação há mais de 4 horas",
            "created_at_iso": format_iso_utc(now - timedelta(hours=4)),
            "created_at": format_local_datetime(now - timedelta(hours=4)),
            "is_resolved": False,
            "resolved_at": None,
            "is_demo": True
        })

    return {
        "device": device,
        "metrics": metrics,
        "alerts": alerts
    }


def get_demo_metrics_history(device_id: int, limit: int = 60) -> list:
    """
    Retorna histórico cronológico de métricas para o gráfico temporal do dispositivo de demonstração.
    """
    details = get_demo_device(device_id)
    if not details:
        return []
    return details["metrics"][-limit:]


def get_demo_alerts() -> list:
    """
    Retorna os alertas virtuais de demonstração.
    """
    now = utc_now()
    return [
        {
            "id": 9001,
            "device_id": 90003,
            "device_name": "PC Faturamento 02",
            "department": "Faturamento",
            "severity": "warning",
            "alert_type": "cpu_high",
            "message": "[DEMO] Processador acima do limite de alerta: 92.4% (limite: 90.0%)",
            "created_at_iso": format_iso_utc(now - timedelta(minutes=25)),
            "created_at": format_local_datetime(now - timedelta(minutes=25)),
            "is_resolved": False,
            "resolved_at": None,
            "is_demo": True
        },
        {
            "id": 9002,
            "device_id": 90005,
            "device_name": "PC Tesouraria",
            "department": "Financeiro",
            "severity": "warning",
            "alert_type": "offline",
            "message": "[DEMO] Dispositivo sem comunicação há mais de 4 horas",
            "created_at_iso": format_iso_utc(now - timedelta(hours=4)),
            "created_at": format_local_datetime(now - timedelta(hours=4)),
            "is_resolved": False,
            "resolved_at": None,
            "is_demo": True
        }
    ]


def get_demo_policy_rules() -> list:
    """
    Retorna regras virtuais de demonstração em memória.
    """
    now = utc_now()
    ts = format_local_datetime(now)
    return [
        {
            "id": 9101,
            "name": "[DEMO] Jogos Steam",
            "rule_type": "application",
            "pattern": "steam.exe",
            "category": "Jogos",
            "severity": "warning",
            "scope_type": "global",
            "scope_target": "Todos",
            "action": "alert",
            "enabled": True,
            "created_at": ts,
            "created_at_iso": format_iso_utc(now),
            "is_demo": True
        },
        {
            "id": 9102,
            "name": "[DEMO] Apostas Bet365",
            "rule_type": "domain",
            "pattern": "bet365.com",
            "category": "Apostas",
            "severity": "critical",
            "scope_type": "global",
            "scope_target": "Todos",
            "action": "alert",
            "enabled": True,
            "created_at": ts,
            "created_at_iso": format_iso_utc(now),
            "is_demo": True
        },
        {
            "id": 9103,
            "name": "[DEMO] Streaming Netflix",
            "rule_type": "domain",
            "pattern": "netflix.com",
            "category": "Streaming",
            "severity": "warning",
            "scope_type": "global",
            "scope_target": "Todos",
            "action": "alert",
            "enabled": True,
            "created_at": ts,
            "created_at_iso": format_iso_utc(now),
            "is_demo": True
        },
        {
            "id": 9104,
            "name": "[DEMO] Redes Sociais TikTok",
            "rule_type": "domain",
            "pattern": "tiktok.com",
            "category": "Redes Sociais",
            "severity": "warning",
            "scope_type": "department",
            "scope_target": "Logística",
            "action": "alert",
            "enabled": True,
            "created_at": ts,
            "created_at_iso": format_iso_utc(now),
            "is_demo": True
        }
    ]


def get_demo_policy_events() -> list:
    """
    Retorna ocorrências virtuais de demonstração em memória.
    """
    now = utc_now()
    return [
        {
            "id": 9201,
            "device_id": 90001,
            "device_name": "PC Expedição 01",
            "department": "Logística",
            "user_name": "Operador de Cargas",
            "policy_rule_id": 9104,
            "event_type": "domain",
            "category": "Redes Sociais",
            "severity": "warning",
            "application": "Microsoft Edge",
            "domain": "tiktok.com",
            "first_seen_iso": format_iso_utc(now - timedelta(minutes=18)),
            "first_seen": format_local_datetime(now - timedelta(minutes=18)),
            "last_seen_iso": format_iso_utc(now - timedelta(minutes=2)),
            "last_seen": format_local_datetime(now - timedelta(minutes=2)),
            "duration_seconds": 960,
            "duration_formatted": "16m 0s",
            "status": "active",
            "acknowledged": False,
            "acknowledged_at_iso": None,
            "acknowledged_at": None,
            "acknowledged_by": None,
            "resolved_at_iso": None,
            "resolved_at": None,
            "is_demo": True
        },
        {
            "id": 9202,
            "device_id": 90003,
            "device_name": "PC Faturamento 02",
            "department": "Faturamento",
            "user_name": "Analista Fiscal",
            "policy_rule_id": 9101,
            "event_type": "application",
            "category": "Jogos",
            "severity": "warning",
            "application": "Steam",
            "domain": "—",
            "first_seen_iso": format_iso_utc(now - timedelta(minutes=45)),
            "first_seen": format_local_datetime(now - timedelta(minutes=45)),
            "last_seen_iso": format_iso_utc(now - timedelta(minutes=10)),
            "last_seen": format_local_datetime(now - timedelta(minutes=10)),
            "duration_seconds": 2100,
            "duration_formatted": "35m 0s",
            "status": "active",
            "acknowledged": True,
            "acknowledged_at_iso": format_iso_utc(now - timedelta(minutes=8)),
            "acknowledged_at": format_local_datetime(now - timedelta(minutes=8)),
            "acknowledged_by": "admin",
            "resolved_at_iso": None,
            "resolved_at": None,
            "is_demo": True
        }
    ]
