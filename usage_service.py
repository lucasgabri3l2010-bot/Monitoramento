"""
Givova Monitor - Serviço de Rastreamento de Sessões de Uso Real e Ociosidade (v1.5.0)
Responsabilidades:
1. Rastrear períodos contínuos de uso do usuário (active, idle, locked) em UsageSession.
2. Aplicar clamp rígido em ajustes retrospectivos (nunca inventar atividade antes do startup/gap).
3. Tratar gaps de telemetria (> MAX_USAGE_GAP_SECONDS) fechando sessões no último report confiável.
4. Tratar divisão automática de sessões na virada da meia-noite no fuso corporativo (America/Sao_Paulo).
5. Tratar troca de sessão do Windows (windows_session_id) de forma segura.
6. Consolidar DailyUsageSummary de forma estritamente idempotente (reprocessar o mesmo report não dobra tempo).
7. Prover endpoints de consulta de timeline e histórico diário.
"""

from datetime import datetime, timezone, timedelta, date
from typing import Optional, List, Dict, Any

from config import Config
from models import db, Device, UsageSession, DailyUsageSummary
from datetime_utils import (
    utc_now, ensure_utc, to_app_timezone, get_local_date,
    get_local_day_range_utc, get_local_midnight_utc, format_iso_utc,
    format_local_datetime
)


def to_naive_utc(dt: Optional[datetime]) -> Optional[datetime]:
    """
    Normaliza qualquer objeto datetime para UTC ingênuo (naive).
    Garante imunidade total a TypeErrors ao subtrair ou comparar com outros datetimes.
    """
    if dt is None:
        return None
    if dt.tzinfo is not None:
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def reconcile_daily_usage_for_date(device_id: int, target_date: date) -> DailyUsageSummary:
    """
    Consolida o resumo diário (DailyUsageSummary) de forma ESTRITAMENTE IDEMPOTENTE
    para um dispositivo e data específicos a partir das fatias temporais de UsageSession.
    
    Mesmo que o mesmo report seja reenviado dezenas de vezes ou sofra retries de rede,
    o cálculo recalcula as fatias exatas das sessões e resulta sempre nos mesmos valores.
    """
    ref_dt = datetime(target_date.year, target_date.month, target_date.day, 12, 0, 0, tzinfo=timezone.utc)
    start_day_raw, next_day_raw = get_local_day_range_utc(ref_dt)
    start_day_utc = to_naive_utc(start_day_raw)
    next_day_utc = to_naive_utc(next_day_raw)

    # Busca todas as sessões que tocam este dia civil
    sessions = UsageSession.query.filter(
        UsageSession.device_id == device_id,
        UsageSession.started_at < next_day_utc,
        (UsageSession.ended_at.is_(None) | (UsageSession.ended_at > start_day_utc))
    ).order_by(UsageSession.started_at.asc()).all()

    active_seconds = 0
    idle_seconds = 0
    locked_seconds = 0
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None

    now_utc_naive = to_naive_utc(utc_now())

    for sess in sessions:
        s_started = to_naive_utc(sess.started_at)
        s_ended = to_naive_utc(sess.ended_at)
        # Ponto de término efetivo da sessão
        effective_end = s_ended or now_utc_naive

        # Fatia da sessão pertencente estritamente a este dia civil
        slice_start = max(s_started, start_day_utc) if s_started else start_day_utc
        slice_end = min(effective_end, next_day_utc)

        if slice_end > slice_start:
            dur = max(0, int((slice_end - slice_start).total_seconds()))

            if sess.state == "active":
                active_seconds += dur
            elif sess.state == "idle":
                idle_seconds += dur
            elif sess.state == "locked":
                locked_seconds += dur

            if first_seen is None or slice_start < first_seen:
                first_seen = slice_start
            if last_seen is None or slice_end > last_seen:
                last_seen = slice_end

    online_seconds = active_seconds + idle_seconds + locked_seconds
    active_percentage = round((active_seconds / online_seconds * 100.0), 1) if online_seconds > 0 else 0.0

    summary = DailyUsageSummary.query.filter_by(
        device_id=device_id,
        date=target_date
    ).first()

    now_utc = utc_now().replace(tzinfo=None)

    if not summary:
        summary = DailyUsageSummary(
            device_id=device_id,
            date=target_date,
            online_seconds=online_seconds,
            active_seconds=active_seconds,
            idle_seconds=idle_seconds,
            locked_seconds=locked_seconds,
            offline_seconds=0,
            first_seen=first_seen,
            last_seen=last_seen,
            active_percentage=active_percentage,
            created_at=now_utc,
            updated_at=now_utc
        )
        db.session.add(summary)
    else:
        summary.online_seconds = online_seconds
        summary.active_seconds = active_seconds
        summary.idle_seconds = idle_seconds
        summary.locked_seconds = locked_seconds
        summary.first_seen = first_seen
        summary.last_seen = last_seen
        summary.active_percentage = active_percentage
        summary.updated_at = now_utc

    db.session.flush()
    return summary


def process_device_usage_telemetry(device: Device, data: dict, now: Optional[datetime] = None) -> None:
    """
    Processa a telemetria de uso e ociosidade de um dispositivo a partir do payload recebido.
    Garante:
    - Compatibilidade graciosa com agentes legados (sem campos de idle).
    - Rejeição e sanitização de dados impossíveis de idle.
    - Clamp rígido em retrospectiva de idle (evita inventar períodos antes do startup/gap).
    - Fechamento seguro de sessões diante de gaps (> MAX_USAGE_GAP_SECONDS) ou troca de sessão Windows.
    - Fatiamento automático na virada da meia-noite em America/Sao_Paulo.
    - Atualização idempotente de DailyUsageSummary.
    """
    now_dt = ensure_utc(now or utc_now())
    now_naive = now_dt.replace(tzinfo=None)

    raw_idle = data.get("idle_seconds")
    raw_state = data.get("session_state")
    raw_user_active = data.get("user_active")
    win_session_id = data.get("windows_session_id")

    # 1. Compatibilidade com agentes legados (<= 1.4.1)
    if raw_idle is None and raw_state is None:
        device.current_session_state = "unknown"
        device.user_active = False
        return

    # 2. Sanitização de idle_seconds e mitigação de anomalias da API
    try:
        idle_seconds = float(raw_idle or 0.0)
        # Rejeita leituras negativas ou anomalias impossíveis (> 1 ano de idle)
        if idle_seconds < 0.0 or idle_seconds > (86400 * 365):
            idle_seconds = 0.0
            raw_state = "unknown"
    except (TypeError, ValueError):
        idle_seconds = 0.0
        raw_state = "unknown"

    # 3. Determinação sanitizada do session_state
    session_state = str(raw_state or "unknown").strip().lower()
    if session_state not in ("active", "idle", "locked"):
        session_state = "unknown"

    user_active = bool(raw_user_active) if session_state == "active" else False

    # 4. Atualização do estado instantâneo do dispositivo
    device.current_session_state = session_state
    device.last_idle_seconds = idle_seconds
    device.user_active = user_active
    if win_session_id is not None:
        try:
            device.windows_session_id = int(win_session_id)
        except (TypeError, ValueError):
            pass

    if session_state in ("active", "idle", "locked"):
        last_input_calc = now_naive - timedelta(seconds=idle_seconds)
        device.last_input_at = last_input_calc

    # Se o estado não puder ser determinado com segurança, suspende criação de sessões especulativas
    if session_state == "unknown":
        return

    # 5. Busca sessão aberta mais recente do dispositivo
    open_session = UsageSession.query.filter(
        UsageSession.device_id == device.id,
        UsageSession.is_open == True
    ).order_by(UsageSession.started_at.desc()).first()

    s_started = to_naive_utc(open_session.started_at) if open_session else None
    s_ended = to_naive_utc(open_session.ended_at) if open_session else None
    d_updated = to_naive_utc(device.updated_at)

    # 6. Verificação de Troca de Sessão do Windows (Fast User Switching / RDP)
    if (
        open_session and
        win_session_id is not None and
        open_session.windows_session_id is not None and
        open_session.windows_session_id != win_session_id
    ):
        last_point = d_updated or s_ended or now_naive
        open_session.ended_at = last_point
        open_session.duration_seconds = max(0, int((last_point - s_started).total_seconds())) if s_started else 0
        open_session.is_open = False
        reconcile_daily_usage_for_date(device.id, get_local_date(s_started))
        open_session = None
        s_started = None
        s_ended = None

    # 7. Verificação de Gap de Telemetria (PC desligado / suspenso / sem rede)
    if open_session:
        last_seen = s_ended or d_updated or s_started or now_naive
        gap_seconds = (now_naive - last_seen).total_seconds()
        if gap_seconds > Config.MAX_USAGE_GAP_SECONDS:
            # Encerra sessão anterior no último ponto confiável de observação (last_seen)
            open_session.ended_at = last_seen
            open_session.duration_seconds = max(0, int((last_seen - s_started).total_seconds())) if s_started else 0
            open_session.is_open = False
            reconcile_daily_usage_for_date(device.id, get_local_date(s_started))
            open_session = None
            s_started = None
            s_ended = None

    # 8. Início de um Novo Período de Observação (Start do Agent ou Pós-Gap)
    if open_session is None:
        # CLAMP RÍGIDO: Nunca backfill tempo antes do startup/início confiável da observação (now_naive).
        # Mesmo que o Agent reporte idle_seconds = 7200 no 1º report, a sessão ociosa observada inicia em now_naive.
        new_session = UsageSession(
            device_id=device.id,
            windows_session_id=device.windows_session_id,
            state=session_state,
            started_at=now_naive,
            ended_at=now_naive,
            duration_seconds=0,
            is_open=True,
            created_at=now_naive
        )
        db.session.add(new_session)
        db.session.flush()
        reconcile_daily_usage_for_date(device.id, get_local_date(now_naive))
        return

    # 9. Continuação com o MESMO Estado
    if open_session.state == session_state:
        current_local_date = get_local_date(now_naive)
        session_start_date = get_local_date(s_started)

        # Divisão de meia-noite no fuso corporativo (America/Sao_Paulo)
        if current_local_date != session_start_date:
            midnight_utc = to_naive_utc(get_local_midnight_utc(now_naive))
            open_session.ended_at = midnight_utc
            open_session.duration_seconds = max(0, int((midnight_utc - s_started).total_seconds())) if s_started else 0
            open_session.is_open = False
            reconcile_daily_usage_for_date(device.id, session_start_date)

            new_session = UsageSession(
                device_id=device.id,
                windows_session_id=device.windows_session_id,
                state=session_state,
                started_at=midnight_utc,
                ended_at=now_naive,
                duration_seconds=max(0, int((now_naive - midnight_utc).total_seconds())),
                is_open=True,
                created_at=now_naive
            )
            db.session.add(new_session)
            db.session.flush()
            reconcile_daily_usage_for_date(device.id, current_local_date)
        else:
            # Estende a sessão atual
            open_session.ended_at = now_naive
            open_session.duration_seconds = max(0, int((now_naive - s_started).total_seconds())) if s_started else 0
            reconcile_daily_usage_for_date(device.id, current_local_date)
        return

    # 10. Transição de Estado (ex: active -> idle, idle -> active, active -> locked)
    if open_session.state != session_state:
        # Cálculo de transição com clamp seguro
        calculated_last_input = now_naive - timedelta(seconds=idle_seconds)

        # CLAMP: a transição nunca pode ocorrer antes do início da sessão anterior,
        # e nunca pode estar no futuro.
        transition_point = max(s_started, min(now_naive, calculated_last_input)) if s_started else now_naive

        # Fecha a sessão anterior no ponto exato da transição
        open_session.ended_at = transition_point
        open_session.duration_seconds = max(0, int((transition_point - s_started).total_seconds())) if s_started else 0
        open_session.is_open = False
        reconcile_daily_usage_for_date(device.id, get_local_date(s_started))

        # Abre a nova sessão a partir do ponto de transição até o momento presente
        new_session = UsageSession(
            device_id=device.id,
            windows_session_id=device.windows_session_id,
            state=session_state,
            started_at=transition_point,
            ended_at=now_naive,
            duration_seconds=max(0, int((now_naive - transition_point).total_seconds())),
            is_open=True,
            created_at=now_naive
        )
        db.session.add(new_session)
        db.session.flush()
        reconcile_daily_usage_for_date(device.id, get_local_date(now_naive))


def close_stale_device_sessions(offline_threshold_seconds: Optional[int] = None) -> int:
    """
    Encerra sessões que continuam com is_open=True para computadores que ficaram offline
    (ultrapassaram offline_threshold_seconds).
    A sessão é encerrada no último ponto de contato confiável (device.updated_at).
    """
    threshold = offline_threshold_seconds or Config.OFFLINE_THRESHOLD_SECONDS
    cutoff = to_naive_utc(utc_now()) - timedelta(seconds=threshold)

    stale_sessions = UsageSession.query.join(Device).filter(
        UsageSession.is_open == True,
        Device.updated_at < cutoff
    ).all()

    closed_count = 0
    for sess in stale_sessions:
        dev = sess.device
        s_started = to_naive_utc(sess.started_at)
        s_ended = to_naive_utc(sess.ended_at)
        d_updated = to_naive_utc(dev.updated_at)
        last_point = d_updated or s_ended or s_started or to_naive_utc(utc_now())
        sess.ended_at = last_point
        sess.duration_seconds = max(0, int((last_point - s_started).total_seconds())) if s_started else 0
        sess.is_open = False
        reconcile_daily_usage_for_date(sess.device_id, get_local_date(s_started))
        closed_count += 1

    if closed_count > 0:
        db.session.commit()
    return closed_count


def get_device_usage_data(device_id: int, target_date_str: Optional[str] = None,
                          start_date_str: Optional[str] = None,
                          end_date_str: Optional[str] = None) -> Dict[str, Any]:
    """
    Retorna o payload completo de tempo de uso para visualização no modal/Dashboard:
    - summary: resumo diário para a data solicitada (ou hoje).
    - timeline: lista de blocos temporais (UsageSession) do dia para barra gráfica.
    - history: lista de resumos diários para tabela com filtros (7d, 30d, etc).
    """
    today_local = get_local_date(utc_now())

    # 1. Determina a data de foco do resumo/timeline
    if target_date_str:
        try:
            target_date = datetime.strptime(target_date_str, "%Y-%m-%d").date()
        except ValueError:
            target_date = today_local
    else:
        target_date = today_local

    # Garante que o resumo do dia alvo esteja consolidado
    summary_obj = reconcile_daily_usage_for_date(device_id, target_date)
    summary_dict = summary_obj.to_dict()

    # 2. Timeline do dia alvo
    ref_dt = datetime(target_date.year, target_date.month, target_date.day, 12, 0, 0, tzinfo=timezone.utc)
    start_raw, next_raw = get_local_day_range_utc(ref_dt)
    start_utc = to_naive_utc(start_raw)
    next_utc = to_naive_utc(next_raw)

    sessions = UsageSession.query.filter(
        UsageSession.device_id == device_id,
        UsageSession.started_at < next_utc,
        (UsageSession.ended_at.is_(None) | (UsageSession.ended_at > start_utc))
    ).order_by(UsageSession.started_at.asc()).all()

    timeline = []
    now_naive = to_naive_utc(utc_now())

    for s in sessions:
        s_started = to_naive_utc(s.started_at)
        s_ended = to_naive_utc(s.ended_at)
        eff_end = s_ended or now_naive
        # Clampa para o limite do dia selecionado
        c_start = max(s_started, start_utc) if s_started else start_utc
        c_end = min(eff_end, next_utc)
        if c_end > c_start:
            timeline.append({
                "id": s.id,
                "state": s.state,
                "started_at_iso": format_iso_utc(c_start),
                "started_at": format_local_datetime(c_start),
                "ended_at_iso": format_iso_utc(c_end),
                "ended_at": format_local_datetime(c_end),
                "duration_seconds": max(0, int((c_end - c_start).total_seconds())),
                "is_open": bool(s.is_open and s.ended_at is None)
            })

    # 3. Histórico de dias anteriores
    if start_date_str:
        try:
            start_date = datetime.strptime(start_date_str, "%Y-%m-%d").date()
        except ValueError:
            start_date = today_local - timedelta(days=30)
    else:
        start_date = today_local - timedelta(days=30)

    if end_date_str:
        try:
            end_date = datetime.strptime(end_date_str, "%Y-%m-%d").date()
        except ValueError:
            end_date = today_local
    else:
        end_date = today_local

    hist_records = DailyUsageSummary.query.filter(
        DailyUsageSummary.device_id == device_id,
        DailyUsageSummary.date >= start_date,
        DailyUsageSummary.date <= end_date
    ).order_by(DailyUsageSummary.date.desc()).all()

    history = [h.to_dict() for h in hist_records]

    return {
        "device_id": device_id,
        "date": str(target_date),
        "summary": summary_dict,
        "timeline": timeline,
        "history": history
    }


def cleanup_old_usage_data() -> int:
    """
    Aplica política de retenção para dados de uso:
    - Sessões detalhadas: Config.USAGE_SESSION_RETENTION_DAYS (90 dias).
    - Resumos diários: Config.USAGE_SUMMARY_RETENTION_DAYS (365 dias).
    """
    deleted_sessions = 0
    deleted_summaries = 0
    now_utc = utc_now().replace(tzinfo=None)

    try:
        session_cutoff = now_utc - timedelta(days=Config.USAGE_SESSION_RETENTION_DAYS)
        deleted_sessions = UsageSession.query.filter(
            UsageSession.is_open == False,
            UsageSession.ended_at < session_cutoff
        ).delete(synchronize_session=False)

        summary_cutoff = (now_utc - timedelta(days=Config.USAGE_SUMMARY_RETENTION_DAYS)).date()
        deleted_summaries = DailyUsageSummary.query.filter(
            DailyUsageSummary.date < summary_cutoff
        ).delete(synchronize_session=False)

        db.session.commit()
    except Exception as e:
        db.session.rollback()

    return deleted_sessions + deleted_summaries
