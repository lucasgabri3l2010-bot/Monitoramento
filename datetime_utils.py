"""
Givova Monitor - Módulo Central de Utilitários de Data e Hora (Timezone Architecture)
Regra do Sistema:
1. BANCO / BACKEND: sempre armazena e opera em UTC (naive no SQLite/Postgres).
2. API: expõe timestamps ISO 8601 canônicos em UTC com sufixo 'Z' (ex: 2026-09-14T11:41:00Z).
3. FRONTEND: converte ISO 8601 UTC para o fuso horário corporativo (America/Sao_Paulo).
4. QUERIES TEMPORAIS: utilizam intervalos semiabertos [start_utc, next_start_utc).
"""

from datetime import datetime, timezone, timedelta
from zoneinfo import ZoneInfo
from typing import Optional, Tuple
import os

# Fuso horário padrão da organização (America/Sao_Paulo)
DEFAULT_TIMEZONE_NAME = os.getenv("APP_TIMEZONE", "America/Sao_Paulo").strip()


def get_app_timezone(tz_name: Optional[str] = None) -> ZoneInfo:
    """
    Retorna o objeto ZoneInfo correspondente ao timezone corporativo.
    """
    name = tz_name or DEFAULT_TIMEZONE_NAME
    try:
        return ZoneInfo(name)
    except Exception:
        return ZoneInfo("America/Sao_Paulo")


def utc_now() -> datetime:
    """
    Retorna o timestamp atual em UTC com tzinfo explícito (aware).
    """
    return datetime.now(timezone.utc)


def ensure_utc(dt: Optional[datetime]) -> Optional[datetime]:
    """
    Garante que um objeto datetime seja timezone-aware em UTC.
    - Se for None, retorna None.
    - Se for naive (sem tzinfo), assume que foi armazenado como UTC e anexa timezone.utc.
    - Se for aware com outro timezone, converte para UTC com .astimezone(timezone.utc).
    """
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def to_app_timezone(dt: Optional[datetime], tz_name: Optional[str] = None) -> Optional[datetime]:
    """
    Converte um datetime (naive ou aware UTC) para o fuso horário da aplicação (ex: America/Sao_Paulo).
    """
    if dt is None:
        return None
    utc_dt = ensure_utc(dt)
    target_tz = get_app_timezone(tz_name)
    return utc_dt.astimezone(target_tz)


def format_iso_utc(dt: Optional[datetime], include_microseconds: bool = False) -> Optional[str]:
    """
    Formata um datetime como ISO 8601 canônico em UTC com terminação 'Z' explícita.
    Exemplo: '2026-09-14T11:41:00Z' ou '2026-09-14T11:41:00.123456Z'
    Nunca retorna string ambígua sem timezone.
    """
    if dt is None:
        return None
    utc_dt = ensure_utc(dt)
    if include_microseconds and utc_dt.microsecond > 0:
        return utc_dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return utc_dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def format_local_datetime(dt: Optional[datetime], fmt: str = "%d/%m/%Y %H:%M:%S", tz_name: Optional[str] = None) -> str:
    """
    [LEGACY / COMPATIBILIDADE] Converte um datetime UTC para o fuso local da aplicação
    e formata como string legível.
    Fonte primária da API deve ser format_iso_utc().
    """
    if dt is None:
        return ""
    local_dt = to_app_timezone(dt, tz_name)
    return local_dt.strftime(fmt)


def format_local_time(dt: Optional[datetime], fmt: str = "%H:%M:%S", tz_name: Optional[str] = None) -> str:
    """
    [LEGACY / COMPATIBILIDADE] Converte um datetime UTC para o fuso local da aplicação
    e formata apenas a hora/minuto/segundo.
    """
    if dt is None:
        return ""
    local_dt = to_app_timezone(dt, tz_name)
    return local_dt.strftime(fmt)


def start_of_local_day_utc(ref_dt: Optional[datetime] = None, tz_name: Optional[str] = None) -> datetime:
    """
    Calcula o início do dia civil local (00:00:00.000000) no timezone da empresa,
    convertido para UTC ingênuo (naive) para consultas SQL no banco de dados.
    """
    tz = get_app_timezone(tz_name)
    now_utc = ensure_utc(ref_dt) if ref_dt else utc_now()
    now_local = now_utc.astimezone(tz)
    start_local = now_local.replace(hour=0, minute=0, second=0, microsecond=0)
    start_utc = start_local.astimezone(timezone.utc)
    return start_utc.replace(tzinfo=None)


def start_of_next_local_day_utc(ref_dt: Optional[datetime] = None, tz_name: Optional[str] = None) -> datetime:
    """
    Calcula o início do próximo dia civil local (00:00:00.000000 do dia seguinte) no timezone da empresa,
    convertido para UTC ingênuo (naive) para consultas semiabertas [start_utc, next_start_utc).
    """
    tz = get_app_timezone(tz_name)
    now_utc = ensure_utc(ref_dt) if ref_dt else utc_now()
    now_local = now_utc.astimezone(tz)
    start_next_local = (now_local + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    start_next_utc = start_next_local.astimezone(timezone.utc)
    return start_next_utc.replace(tzinfo=None)


def get_local_day_range_utc(ref_dt: Optional[datetime] = None, tz_name: Optional[str] = None) -> Tuple[datetime, datetime]:
    """
    Retorna o par (inicio_dia_utc, inicio_proximo_dia_utc) como intervalo semiaberto [start, end)
    para consultas SQL seguras e imunes a problemas de precisão de microssegundos.
    """
    return (
        start_of_local_day_utc(ref_dt, tz_name),
        start_of_next_local_day_utc(ref_dt, tz_name)
    )


def get_local_date(ref_dt: Optional[datetime] = None, tz_name: Optional[str] = None):
    """
    Retorna a data civil (date) no fuso horário corporativo da empresa (ex: America/Sao_Paulo).
    """
    local_dt = to_app_timezone(ref_dt or utc_now(), tz_name)
    return local_dt.date()


def get_local_midnight_utc(ref_dt: Optional[datetime] = None, tz_name: Optional[str] = None) -> datetime:
    """
    Retorna o timestamp UTC correspondente à meia-noite (00:00:00) do dia civil local.
    """
    return start_of_local_day_utc(ref_dt, tz_name)

