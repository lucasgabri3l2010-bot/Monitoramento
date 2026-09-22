import time
import random
from datetime import datetime, timezone, timedelta
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor
import threading
import requests

from models import (
    db, Device, MetricHistory, Alert, PolicyRule, PolicyEvent, PolicyAuditLog,
    PolicyAllowlist, DomainClassification, SystemMetadata, UsageSession, DailyUsageSummary,
    match_domain_secure, match_application_secure
)
from config import Config
from datetime_utils import utc_now, get_local_date
from usage_service import process_device_usage_telemetry, cleanup_old_usage_data

# Categorias canônicas padronizadas
CATEGORY_MAP = {
    "adult": "Adulto / +18",
    "gambling": "Apostas",
    "games": "Jogos",
    "malware": "Malware",
    "phishing": "Phishing",
    "scam": "Scam / Fraude",
    "torrent": "Torrent / Pirataria",
    "streaming": "Streaming",
    "social_media": "Redes Sociais",
    "vpn_proxy": "Proxy / VPN",
    "file_sharing": "Compartilhamento de Arquivos",
    "dating": "Namoro / Relacionamentos",
    "suspicious": "Sites Suspeitos",
    "crypto_mining": "Criptomineração",
    "unauthorized_application": "Aplicativo Não Autorizado",
    "unknown": "Não Classificado"
}

# Severidades padrão para categorias automáticas
DEFAULT_CATEGORY_SEVERITY = {
    "adult": "critical",
    "gambling": "critical",
    "malware": "critical",
    "phishing": "critical",
    "scam": "critical",
    "crypto_mining": "critical",
    "suspicious": "critical",
    "games": "warning",
    "torrent": "critical",
    "streaming": "warning",
    "social_media": "warning",
    "vpn_proxy": "critical",
    "file_sharing": "warning",
    "dating": "warning",
    "unauthorized_application": "warning",
    "unknown": "info"
}

class CachedPolicyRule:
    """
    Representação leve e desanexada da sessão do SQLAlchemy para cache em memória.
    Totalmente thread-safe e livre de erros de DetachedInstanceError entre requisições.
    """
    def __init__(self, id: int, name: str, rule_type: str, pattern: str, category: str,
                 severity: str, scope_type: str, scope_target: str, action: str, enabled: bool,
                 is_automatic: bool = False, source_provider: str = "manual"):
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
        self.is_automatic = is_automatic
        self.source_provider = source_provider or "manual"

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


class CachedPolicyAllowlist:
    """Lightweight allowlist entry safe to reuse outside the ORM session."""

    def __init__(self, pattern: str, target_type: str, scope_type: str,
                 scope_target: str | None, enabled: bool):
        self.pattern = pattern
        self.target_type = target_type
        self.scope_type = scope_type
        self.scope_target = scope_target
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

        clean_pattern = self.pattern.strip().lower()
        if self.target_type == "domain":
            return bool(domain and match_domain_secure(domain, clean_pattern))
        if self.target_type == "application":
            return bool(app_name and match_application_secure(app_name, clean_pattern))
        return False


class DomainReputationProvider(ABC):
    @abstractmethod
    def classify_domain(self, domain: str) -> dict:
        """
        Retorna dicionário conceitual:
        {
            "domain": "example.com",
            "category": "adult",
            "risk_level": "critical",
            "confidence": 0.95,
            "source": "provider"
        }
        """
        pass


class InternalDomainReputationProvider(DomainReputationProvider):
    """
    Provider interno leve mantido exclusivamente para listas/regras locais, testes e fallback.
    Não tenta fingir cobertura global da internet: domínios não catalogados retornam 'unknown'.
    """
    LOCAL_KNOWN_DOMAINS = {
        "bet365.com": {"category": "gambling", "risk": "critical", "confidence": 1.0},
        "betano.com": {"category": "gambling", "risk": "critical", "confidence": 1.0},
        "blaze.com": {"category": "gambling", "risk": "critical", "confidence": 1.0},
        "netflix.com": {"category": "streaming", "risk": "warning", "confidence": 1.0},
        "twitch.tv": {"category": "streaming", "risk": "warning", "confidence": 1.0},
        "tiktok.com": {"category": "social_media", "risk": "warning", "confidence": 1.0},
        "instagram.com": {"category": "social_media", "risk": "warning", "confidence": 1.0},
        "facebook.com": {"category": "social_media", "risk": "warning", "confidence": 1.0},
        "roblox.com": {"category": "games", "risk": "warning", "confidence": 1.0},
        "steamcommunity.com": {"category": "games", "risk": "warning", "confidence": 1.0},
        "pornhub.com": {"category": "adult", "risk": "critical", "confidence": 1.0},
        "xvideos.com": {"category": "adult", "risk": "critical", "confidence": 1.0},
        "thepiratebay.org": {"category": "torrent", "risk": "warning", "confidence": 1.0},
        "example-policy-test.local": {"category": "adult", "risk": "critical", "confidence": 1.0}
    }

    def classify_domain(self, domain: str) -> dict:
        norm_d = domain.strip().lower()
        if norm_d.startswith("www."):
            norm_d = norm_d[4:]

        for k_domain, info in self.LOCAL_KNOWN_DOMAINS.items():
            if norm_d == k_domain or norm_d.endswith("." + k_domain):
                return {
                    "domain": domain,
                    "category": info["category"],
                    "risk_level": info["risk"],
                    "confidence": info["confidence"],
                    "source": "internal"
                }

        # Desconhecido: retorna unknown sem acusar violação
        return {
            "domain": domain,
            "category": "unknown",
            "risk_level": "info",
            "confidence": 0.50,
            "source": "internal"
        }


class ExternalDomainReputationProvider(DomainReputationProvider):
    """
    Provider externo para categorização em nuvem via API.
    Envia ESTRITAMENTE o nome do domínio (sem paths, query, usuários ou dados corporativos).
    """
    def __init__(self, api_key: str, api_url: str = None):
        self.api_key = api_key
        self.api_url = api_url or "https://api.domainreputation.example/v1/classify"

    def classify_domain(self, domain: str) -> dict:
        clean_domain = domain.strip().lower().split("/")[0].split("?")[0]
        try:
            resp = requests.post(
                self.api_url,
                json={"domain": clean_domain},
                headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
                timeout=3
            )
            if resp.status_code == 200:
                data = resp.json()
                cat = data.get("category", "unknown").lower()
                conf = float(data.get("confidence", 0.90))
                risk = data.get("risk_level") or DEFAULT_CATEGORY_SEVERITY.get(cat, "info")
                return {
                    "domain": clean_domain,
                    "category": cat,
                    "risk_level": risk,
                    "confidence": conf,
                    "source": "provider"
                }
        except Exception as e:
            print(f"[ExternalProvider] Erro ao consultar API externa: {e}")

        return InternalDomainReputationProvider().classify_domain(clean_domain)


def get_reputation_provider() -> DomainReputationProvider:
    if Config.DOMAIN_CLASSIFICATION_API_KEY:
        return ExternalDomainReputationProvider(Config.DOMAIN_CLASSIFICATION_API_KEY)
    return InternalDomainReputationProvider()


# Executor assíncrono leve para consultas de reputação sem travar /api/agent/report
_classification_executor = ThreadPoolExecutor(max_workers=4)
_pending_domains_lock = threading.Lock()
_pending_domains_set = set()


def enqueue_domain_classification(app_context, domain: str):
    """
    Enfileira a classificação assíncrona de um domínio novo sem bloquear a rota de ingestão.
    Deduplica requisições simultâneas via _pending_domains_set.
    """
    clean_domain = domain.strip().lower()
    with _pending_domains_lock:
        if clean_domain in _pending_domains_set:
            return
        _pending_domains_set.add(clean_domain)

    def _async_task():
        try:
            with app_context:
                provider = get_reputation_provider()
                res = provider.classify_domain(clean_domain)

                cat = res.get("category", "unknown")
                risk = res.get("risk_level", "info")
                conf = float(res.get("confidence", 1.0))
                src = res.get("source", "internal")

                expires_at = datetime.now(timezone.utc) + timedelta(days=Config.DOMAIN_CLASSIFICATION_TTL_DAYS)

                db_item = DomainClassification.query.filter_by(domain=clean_domain).first()
                if not db_item:
                    db_item = DomainClassification(
                        domain=clean_domain,
                        category=cat,
                        risk_level=risk,
                        confidence=conf,
                        source=src,
                        status="classified",
                        classified_at=datetime.now(timezone.utc),
                        expires_at=expires_at
                    )
                    db.session.add(db_item)
                else:
                    db_item.category = cat
                    db_item.risk_level = risk
                    db_item.confidence = conf
                    db_item.source = src
                    db_item.status = "classified"
                    db_item.classified_at = datetime.now(timezone.utc)
                    db_item.expires_at = expires_at

                db.session.commit()

                # Se resultado for uma categoria arriscada com confiança >= MIN_CONFIDENCE, reavalia dispositivos nos últimos 10m
                if conf >= Config.DOMAIN_CLASSIFICATION_MIN_CONFIDENCE and cat in ("adult", "gambling", "malware", "phishing", "scam", "games", "torrent", "streaming", "social_media", "vpn_proxy", "crypto_mining"):
                    _reevaluate_devices_for_domain(clean_domain)

        except Exception as e:
            print(f"[AsyncClassification] Erro ao classificar domínio {clean_domain}: {e}")
            try:
                db.session.rollback()
            except Exception:
                pass
        finally:
            with _pending_domains_lock:
                _pending_domains_set.discard(clean_domain)

    if getattr(app_context, "app", None) and app_context.app.config.get("TESTING"):
        _async_task()
    else:
        _classification_executor.submit(_async_task)


def _reevaluate_devices_for_domain(domain: str):
    """
    Reavalia dispositivos que enviaram este domínio nos últimos 10 minutos após conclusão da classificação assíncrona.
    """
    ten_mins_ago = datetime.now(timezone.utc) - timedelta(minutes=10)
    recent_devs = Device.query.filter(
        Device.active_domain == domain,
        Device.updated_at >= ten_mins_ago
    ).all()

    now = datetime.now(timezone.utc)
    for dev in recent_devs:
        _evaluate_policies(dev, now)

    try:
        db.session.commit()
    except Exception:
        db.session.rollback()

# Cache local de regras de política compatível com múltiplos workers do Gunicorn
_local_rules_cache = None
_local_rules_version = None
_last_version_check_time = 0
_local_allowlists_cache = None
_last_allowlists_load_time = 0
LOCAL_VERSION_CHECK_INTERVAL = 5.0  # Checa a versão global no banco no máximo a cada 5 segundos
_idle_threshold_cache = None
_idle_threshold_cache_time = 0
STATE_EVALUATION_INTERVAL_SECONDS = 30.0
_evaluation_cache_lock = threading.Lock()
_last_policy_evaluation = {}
_last_normal_alert_evaluation = {}


def _policy_evaluation_due(device: Device) -> bool:
    now_ts = time.monotonic()
    signature = (
        device.active_app,
        device.active_domain,
        device.department,
        device.hostname,
        device.uuid,
    )
    with _evaluation_cache_lock:
        previous = _last_policy_evaluation.get(device.id)
        return not (
            previous is not None and previous[0] == signature and
            (now_ts - previous[1]) < STATE_EVALUATION_INTERVAL_SECONDS
        )


def _mark_policy_evaluated(device: Device) -> None:
    signature = (
        device.active_app,
        device.active_domain,
        device.department,
        device.hostname,
        device.uuid,
    )
    with _evaluation_cache_lock:
        _last_policy_evaluation[device.id] = (signature, time.monotonic())


def _normal_alert_evaluation_due(device_id: int) -> bool:
    now_ts = time.monotonic()
    with _evaluation_cache_lock:
        previous = _last_normal_alert_evaluation.get(device_id)
        return previous is None or (now_ts - previous) >= STATE_EVALUATION_INTERVAL_SECONDS


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
                enabled=r.enabled,
                is_automatic=getattr(r, 'is_automatic', False),
                source_provider=getattr(r, 'source_provider', 'manual') or 'manual'
            )
            for r in db_rules
        ]
        _local_rules_cache = rules
        _local_rules_version = db_ver
        return rules
    except Exception as e:
        try:
            db.session.rollback()
        except Exception:
            pass
        print(f"[PolicyCache] Erro ao sincronizar regras de políticas entre workers: {e}")
        return _local_rules_cache or []


def get_active_policy_allowlists() -> list:
    """Returns detached allowlist entries, refreshing at most once per cache window."""
    global _local_allowlists_cache, _last_allowlists_load_time
    now_ts = time.time()
    if (_local_allowlists_cache is not None and
            (now_ts - _last_allowlists_load_time) < LOCAL_VERSION_CHECK_INTERVAL):
        return _local_allowlists_cache

    try:
        rows = PolicyAllowlist.query.filter_by(enabled=True).all()
        _local_allowlists_cache = [
            CachedPolicyAllowlist(
                pattern=row.pattern,
                target_type=row.target_type,
                scope_type=row.scope_type,
                scope_target=row.scope_target,
                enabled=row.enabled,
            )
            for row in rows
        ]
        _last_allowlists_load_time = now_ts
        return _local_allowlists_cache
    except Exception as exc:
        try:
            db.session.rollback()
        except Exception:
            pass
        print(f"[PolicyCache] Erro ao carregar allowlist: {exc}")
        return _local_allowlists_cache or []


def get_idle_threshold_seconds() -> int:
    """Reads the server-authoritative idle threshold at most once per cache window."""
    global _idle_threshold_cache, _idle_threshold_cache_time
    now_ts = time.time()
    if (_idle_threshold_cache is not None and
            (now_ts - _idle_threshold_cache_time) < LOCAL_VERSION_CHECK_INTERVAL):
        return _idle_threshold_cache

    raw_value = SystemMetadata.get_value(
        "idle_threshold_seconds",
        str(Config.IDLE_THRESHOLD_SECONDS),
    )
    try:
        value = int(raw_value)
    except (TypeError, ValueError):
        value = int(Config.IDLE_THRESHOLD_SECONDS)
    _idle_threshold_cache = value
    _idle_threshold_cache_time = now_ts
    return value


def cache_idle_threshold_seconds(value: int) -> None:
    """Makes an administrative update visible immediately in the current worker."""
    global _idle_threshold_cache, _idle_threshold_cache_time
    _idle_threshold_cache = int(value)
    _idle_threshold_cache_time = time.time()


def invalidate_policy_rules_cache():
    """
    Invalida o cache corporativo de políticas entre TODOS os workers do Gunicorn:
    1. Limpa o cache local em memória do worker atual.
    2. Atualiza a versão global persistida em system_metadata no PostgreSQL/SQLite.
    Qualquer outro worker do Gunicorn detectará a nova versão no próximo ciclo de checagem.
    """
    global _local_rules_cache, _local_rules_version, _last_version_check_time
    global _local_allowlists_cache, _last_allowlists_load_time
    _local_rules_cache = None
    _local_rules_version = None
    _last_version_check_time = 0
    _local_allowlists_cache = None
    _last_allowlists_load_time = 0
    with _evaluation_cache_lock:
        _last_policy_evaluation.clear()

    try:
        new_version = str(int(time.time() * 1000))
        SystemMetadata.set_value("policy_rules_version", new_version)
    except Exception as e:
        print(f"[PolicyCache] Erro ao persistir nova versão global de políticas: {e}")

def process_agent_payload(data: dict, existing_device: Device | None = None) -> Device:
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

    # O middleware de autenticação já localizou o UUID. Reutiliza a mesma
    # instância para evitar uma segunda consulta no caminho quente.
    device = existing_device
    if device is not None and device.uuid != uuid:
        device = None
    if device is None:
        device = Device.query.filter((Device.uuid == uuid) | (Device.hostname == hostname)).first()

    now = datetime.now(timezone.utc)

    if not device:
        raw_dept = data.get("setor") or data.get("department")
        dept = raw_dept.strip() if raw_dept and raw_dept.strip() else "Não informado"
        raw_disp = data.get("display_name")
        disp_name = raw_disp.strip() if raw_disp and raw_disp.strip() else hostname

        device = Device(
            uuid=uuid,
            hostname=hostname,
            display_name=disp_name,
            user_name=data.get("usuario") or data.get("user_name"),
            department=dept,
            ip_address=data.get("ip"),
            mac_address=data.get("mac"),
            os_name=data.get("os_name") or data.get("so") or "Windows",
            os_arch=data.get("os_arch") or data.get("arquitetura") or "x64",
            processor=data.get("processor") or data.get("processador"),
            cpu_cores=data.get("cpu_cores") or data.get("cores") or 1,
            ram_total_gb=float(data.get("ram_total_gb") or 0.0),
            disk_total_gb=float(data.get("disk_total_gb") or 0.0),
            agent_version=data.get("agent_version") or data.get("versao_agente") or "1.0.0",
            created_at=now
        )
        if data.get("device_token"):
            device.device_token = data["device_token"]
        db.session.add(device)
        db.session.flush()

    # Atualiza informações técnicas do sistema sem sobrescrever campos administrativos configurados
    if not device.display_name and data.get("display_name"):
        device.display_name = data.get("display_name").strip()
    if (not device.department or device.department == "Não informado") and (data.get("setor") or data.get("department")):
        device.department = (data.get("setor") or data.get("department")).strip()
    if data.get("usuario") or data.get("user_name"):
        device.user_name = data.get("usuario") or data.get("user_name")
    if data.get("ip"):
        device.ip_address = data.get("ip")
    if data.get("mac"):
        device.mac_address = data.get("mac")
    if data.get("agent_version") or data.get("versao_agente"):
        device.agent_version = data.get("agent_version") or data.get("versao_agente")
    if data.get("ram_total_gb"):
        device.ram_total_gb = float(data.get("ram_total_gb"))
    if data.get("disk_total_gb"):
        device.disk_total_gb = float(data.get("disk_total_gb"))
    if data.get("device_token") and not device.device_token:
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

    # Mantém as alterações pendentes até que o fluxo de uso precise efetivamente
    # persistir. Assim, SELECTs intermediários não geram UPDATEs parciais do Device.
    with db.session.no_autoflush:
        # Avaliação de Políticas Corporativas de Uso (com cache em memória e deduplicação)
        if Config.POLICY_MONITORING_ENABLED and _policy_evaluation_due(device):
            if device.active_app or device.active_domain:
                _evaluate_policies(device, now)
            else:
                _close_open_policy_events(device, now)
            _mark_policy_evaluated(device)

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

        # Rastreamento de Sessão e Uso Real do Usuário (v1.5.0)
        process_device_usage_telemetry(device, data, now)

    # Limpeza aleatória de métricas antigas, eventos e sessões (1 chance em 50 para evitar sobrecarga)
    if random.random() < 0.02:
        cleanup_old_metrics()
        cleanup_old_policy_events()
        cleanup_old_usage_data()

    db.session.commit()
    return device


def _is_allowlisted(app_name: str | None, domain: str | None, device_dept: str | None, device_host: str | None, device_uuid: str | None) -> bool:
    """
    Verifica se a atividade está liberada por Allowlist (Precedência: Device > Department > Global).
    """
    allowlists = get_active_policy_allowlists()
    # 1. Scope Device
    for al in allowlists:
        if al.scope_type == "device" and al.matches(app_name, domain, device_dept, device_host, device_uuid):
            return True
    # 2. Scope Department
    for al in allowlists:
        if al.scope_type == "department" and al.matches(app_name, domain, device_dept, device_host, device_uuid):
            return True
    # 3. Scope Global
    for al in allowlists:
        if al.scope_type == "global" and al.matches(app_name, domain, device_dept, device_host, device_uuid):
            return True

    return False


def _evaluate_policies(device: Device, now: datetime):
    """
    Avalia a atividade atual contra a hierarquia estrita:
    1. Device Allowlist
    2. Department Allowlist
    3. Global Allowlist
    4. Manual PolicyRule (regras soberanas criadas pela TI)
    5. Corporate Seed PolicyRule (base corporativa pré-carregada)
    6. Cached Automatic Classification
    7. External/Internal Provider (Async)
    8. Unknown
    """
    if not Config.POLICY_MONITORING_ENABLED:
        return

    app_name = device.active_app
    domain = device.active_domain

    if not app_name and not domain:
        _close_open_policy_events(device, now)
        return

    # 1. Precedência 1..3: Check Allowlist (Device > Department > Global)
    if _is_allowlisted(app_name, domain, device.department, device.hostname, device.uuid):
        _close_open_policy_events(device, now)
        return

    # 2. Precedência 4 & 5: Regras Ativas (Manuais TI vs Base Corporativa)
    active_rules = get_active_policy_rules()
    matching_manual_rules = []
    matching_seed_rules = []

    for r in active_rules:
        if not r.is_automatic:
            if r.source_provider in ("seed", "corporate_base"):
                if r.matches(app_name, domain, device.department, device.hostname, device.uuid):
                    matching_seed_rules.append(r)
            else:
                if r.matches(app_name, domain, device.department, device.hostname, device.uuid):
                    matching_manual_rules.append(r)

    sev_weight = {"critical": 3, "warning": 2, "info": 1}

    # 2.1 Regras Manuais criadas pela TI têm precedência sobre a base corporativa
    if matching_manual_rules:
        matching_manual_rules.sort(key=lambda r: sev_weight.get(r.severity, 0), reverse=True)
        primary_rule = matching_manual_rules[0]

        if primary_rule.action == "allow":
            _close_open_policy_events(device, now)
            return

        _create_or_update_policy_event(
            device=device,
            rule_id=primary_rule.id,
            event_type=primary_rule.rule_type,
            category=primary_rule.category,
            severity=primary_rule.severity,
            source="manual_rule",
            now=now
        )
        return

    # 2.2 Regras da Base Corporativa (Seed)
    if matching_seed_rules:
        matching_seed_rules.sort(key=lambda r: sev_weight.get(r.severity, 0), reverse=True)
        primary_seed_rule = matching_seed_rules[0]

        if primary_seed_rule.action == "allow":
            _close_open_policy_events(device, now)
            return

        _create_or_update_policy_event(
            device=device,
            rule_id=primary_seed_rule.id,
            event_type=primary_seed_rule.rule_type,
            category=primary_seed_rule.category,
            severity=primary_seed_rule.severity,
            source="corporate_seed",
            now=now
        )
        return

    # 3. Precedência 6..7: Classificação Automática de Domínio
    if domain and Config.DOMAIN_CLASSIFICATION_ENABLED:
        clean_domain = domain.strip().lower()
        if clean_domain.startswith("www."):
            clean_domain = clean_domain[4:]

        cls = DomainClassification.query.filter_by(domain=clean_domain).first()

        if not cls:
            # Cache MISS -> Enfileira classificação assíncrona sem travar /api/agent/report
            from flask import current_app
            try:
                app_ctx = current_app._get_current_object().app_context()
                enqueue_domain_classification(app_ctx, clean_domain)
            except Exception:
                pass
        elif cls.status == "classified" and not cls.is_expired():
            if cls.confidence >= Config.DOMAIN_CLASSIFICATION_MIN_CONFIDENCE and cls.category in ("adult", "gambling", "malware", "phishing", "scam", "games", "torrent", "streaming", "social_media", "vpn_proxy", "crypto_mining"):
                sev = cls.risk_level or DEFAULT_CATEGORY_SEVERITY.get(cls.category, "warning")
                _create_or_update_policy_event(
                    device=device,
                    rule_id=None,
                    event_type="domain",
                    category=cls.category,
                    severity=sev,
                    source="automatic_classification",
                    now=now
                )
                return

    # Se nada violou: fecha eventos abertos anteriores
    _close_open_policy_events(device, now)


def _create_or_update_policy_event(device: Device, rule_id: int | None, event_type: str, category: str, severity: str, source: str, now: datetime):
    """
    Registra ou atualiza ocorrência corporativa de forma deduplicada.
    """
    active_event = PolicyEvent.query.filter(
        PolicyEvent.device_id == device.id,
        PolicyEvent.status == "active",
        (
            (PolicyEvent.policy_rule_id == rule_id) if rule_id else (PolicyEvent.category == category) |
            ((PolicyEvent.domain == device.active_domain) & (PolicyEvent.domain.isnot(None))) |
            ((PolicyEvent.application == device.active_app) & (PolicyEvent.application.isnot(None)))
        )
    ).first()

    if active_event:
        active_event.last_seen = now
        if active_event.first_seen:
            f_seen = active_event.first_seen
            if f_seen.tzinfo is None:
                f_seen = f_seen.replace(tzinfo=timezone.utc)
            active_event.duration_seconds = max(0, int((now - f_seen).total_seconds()))
    else:
        _close_open_policy_events(device, now, except_domain=device.active_domain, except_app=device.active_app)
        new_event = PolicyEvent(
            device_id=device.id,
            policy_rule_id=rule_id,
            event_type=event_type,
            category=category,
            severity=severity,
            application=device.active_app,
            domain=device.active_domain,
            first_seen=now,
            last_seen=now,
            duration_seconds=0,
            status="active",
            source=source
        )
        db.session.add(new_event)


def _close_open_policy_events(device: Device, now: datetime, except_domain: str | None = None, except_app: str | None = None):
    """
    Encerra eventos que o usuário parou de utilizar, calculando a duração final.
    NOTA: Encerramento de atividade (status='closed') indica apenas que o usuário saiu do site/app.
    Não confunde com resolved_at/resolved_by, que é preenchido manualmente quando o administrador resolve a ocorrência.
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
        event.last_seen = now
        if event.first_seen:
            f_seen = event.first_seen
            if f_seen.tzinfo is None:
                f_seen = f_seen.replace(tzinfo=timezone.utc)
            event.duration_seconds = max(0, int((now - f_seen).total_seconds()))


def _evaluate_alerts(device: Device, cpu: float, ram: float, disco: float, now: datetime):
    """
    Avalia limites e registra ou resolve alertas de forma idempotente.
    """
    normal_readings = (
        cpu < (Config.CPU_ALERT_PERCENT - 10.0) and
        ram < (Config.RAM_ALERT_PERCENT - 10.0) and
        disco < (Config.DISK_ALERT_PERCENT - 5.0)
    )
    # Uma leitura fora da faixa normal invalida o atalho. Assim, o primeiro
    # report normal subsequente sempre consulta e resolve alertas abertos,
    # inclusive quando IDs são reutilizados após remoção/recriação do device.
    if not normal_readings:
        with _evaluation_cache_lock:
            _last_normal_alert_evaluation.pop(device.id, None)
    if normal_readings and not _normal_alert_evaluation_due(device.id):
        return

    fifteen_mins_ago = now - timedelta(minutes=15)
    unresolved_alerts = Alert.query.filter(
        Alert.device_id == device.id,
        Alert.alert_type.in_(("cpu_high", "ram_high", "disk_high")),
        Alert.is_resolved == False,
    ).all()
    alerts_by_type = {alert_type: [] for alert_type in ("cpu_high", "ram_high", "disk_high")}
    for alert in unresolved_alerts:
        alerts_by_type[alert.alert_type].append(alert)

    def has_recent(alert_type: str) -> bool:
        for alert in alerts_by_type[alert_type]:
            created_at = alert.created_at
            if created_at and created_at.tzinfo is None:
                created_at = created_at.replace(tzinfo=timezone.utc)
            if created_at and created_at >= fifteen_mins_ago:
                return True
        return False

    def resolve_all(alert_type: str) -> None:
        for alert in alerts_by_type[alert_type]:
            alert.is_resolved = True
            alert.resolved_at = now

    # 1. Alerta de CPU
    if cpu >= Config.CPU_ALERT_PERCENT:
        sev = "critical" if cpu >= 95.0 else "warning"
        if not has_recent("cpu_high"):
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
        resolve_all("cpu_high")

    # 2. Alerta de RAM
    if ram >= Config.RAM_ALERT_PERCENT:
        sev = "critical" if ram >= 95.0 else "warning"
        if not has_recent("ram_high"):
            alert = Alert(
                device_id=device.id,
                severity=sev,
                alert_type="ram_high",
                message=f"Consumo de Memória RAM atingiu {round(ram, 1)}% ({round(device.last_ram_used_gb, 1)} GB de {round(device.ram_total_gb, 1)} GB) em {device.display_name or device.hostname}.",
                created_at=now
            )
            db.session.add(alert)
    elif ram < (Config.RAM_ALERT_PERCENT - 10.0):
        resolve_all("ram_high")

    # 3. Alerta de Disco
    if disco >= Config.DISK_ALERT_PERCENT:
        sev = "critical" if disco >= 95.0 else "warning"
        if not has_recent("disk_high"):
            alert = Alert(
                device_id=device.id,
                severity=sev,
                alert_type="disk_high",
                message=f"Armazenamento em disco atingiu {round(disco, 1)}% de capacidade em {device.display_name or device.hostname}.",
                created_at=now
            )
            db.session.add(alert)
    elif disco < (Config.DISK_ALERT_PERCENT - 5.0):
        resolve_all("disk_high")

    if normal_readings:
        with _evaluation_cache_lock:
            _last_normal_alert_evaluation[device.id] = time.monotonic()


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
                "activity_updated_at_iso": d.get("activity_updated_at_iso"),
                "activity_updated_at": d.get("activity_updated_at") or "—",
                "is_demo": d.get("is_demo", False)
            })

    # Métricas Operacionais de Uso Real (v1.5.0)
    today_local = get_local_date(utc_now())
    today_summaries = DailyUsageSummary.query.filter_by(date=today_local).all()
    active_seconds_today = sum(s.active_seconds or 0 for s in today_summaries)
    idle_seconds_today = sum(s.idle_seconds or 0 for s in today_summaries)
    overtime_seconds_today = sum(s.overtime_seconds or 0 for s in today_summaries)
    off_hours_seconds_today = sum(s.off_hours_seconds or 0 for s in today_summaries)
    locked_seconds_today = sum(s.locked_seconds or 0 for s in today_summaries)
    online_seconds_today = sum(s.online_seconds or 0 for s in today_summaries)
    work_seconds_today = active_seconds_today + idle_seconds_today + locked_seconds_today
    avg_active_pct_today = round((active_seconds_today / work_seconds_today * 100.0), 1) if work_seconds_today > 0 else 0.0

    active_now_count = sum(1 for d in all_devices if d.get("status") != "offline" and d.get("session_state") == "active")
    idle_now_count = sum(1 for d in all_devices if d.get("status") != "offline" and d.get("session_state") == "idle")
    overtime_now_count = sum(1 for d in all_devices if d.get("status") != "offline" and d.get("session_state") == "overtime")
    off_hours_now_count = sum(1 for d in all_devices if d.get("status") != "offline" and d.get("session_state") == "off_hours")
    locked_now_count = sum(1 for d in all_devices if d.get("status") != "offline" and d.get("session_state") == "locked")

    return {
        "total_devices": total_devices,
        "online_count": online_count,
        "offline_count": offline_count,
        "warning_count": warning_count,
        "critical_count": critical_count,
        "active_now": active_now_count,
        "idle_now": idle_now_count,
        "overtime_now": overtime_now_count,
        "off_hours_now": off_hours_now_count,
        "locked_now": locked_now_count,
        "active_seconds_today": active_seconds_today,
        "idle_seconds_today": idle_seconds_today,
        "overtime_seconds_today": overtime_seconds_today,
        "off_hours_seconds_today": off_hours_seconds_today,
        "locked_seconds_today": locked_seconds_today,
        "online_seconds_today": online_seconds_today,
        "average_active_percentage_today": avg_active_pct_today,
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

