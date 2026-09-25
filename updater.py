"""
Givova Transportes - Módulo Auxiliar de Atualização (GivovaMonitorUpdater)
Finalidade: Realizar a substituição atômica e segura do executável GivovaMonitorAgent.exe no Windows,
            supervisionar a inicialização da nova versão e executar rollback automático caso a nova versão
            crashe ou não confirme seu funcionamento saudável no prazo limite.
"""

import sys
import os
import time
import json
import logging
import argparse
import subprocess
import shutil
import re
import trusted_update

UPDATER_VERSION = "1.2.0"
INSTALL_DIR = r"C:\ProgramData\GivovaMonitor"
TRUSTED_DIR = r"C:\Program Files\GivovaMonitorUpdate"
TRUSTED_UPDATER = os.path.join(TRUSTED_DIR, "GivovaMonitorUpdater.exe")
UPDATE_TASK = "Givova Monitor Updater"
REQUEST_FILE = "approved_update_request.json"

if len(sys.argv) == 2 and sys.argv[1] in ("--version", "-v", "--updater-version"):
    print(f"GivovaMonitorUpdater v{UPDATER_VERSION}")
    sys.exit(0)

def setup_logging(target_dir: str):
    log_dir = os.path.join(target_dir, "logs")
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, "updater.log")

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [UPDATER-%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(log_file, encoding="utf-8"),
            logging.StreamHandler(sys.stdout) if sys.stdout is not None else logging.NullHandler()
        ]
    )
    return logging.getLogger("GivovaUpdater")


def terminate_pid(pid: int, logger):
    """Encerra um processo pelo PID de forma segura."""
    try:
        if sys.platform == "win32":
            subprocess.run(["taskkill", "/F", "/PID", str(pid)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            os.kill(pid, 9)
        logger.info(f"Processo PID {pid} encerrado com sucesso.")
    except Exception as e:
        logger.warning(f"Não foi possível encerrar PID {pid}: {e}")


def terminate_by_name(exe_name: str, logger):
    """Encerra processos pelo nome do executável."""
    try:
        if sys.platform == "win32":
            subprocess.run(["taskkill", "/F", "/IM", exe_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            logger.info(f"Processos '{exe_name}' encerrados.")
    except Exception as e:
        logger.warning(f"Erro ao encerrar '{exe_name}': {e}")


def register_failed_update(target_dir: str, version: str, reason: str, logger):
    """Registra versão defeituosa em failed_updates.json para evitar loops infinitos de update e rollback."""
    failed_file = os.path.join(target_dir, "failed_updates.json")
    failed_list = []
    if os.path.exists(failed_file):
        try:
            with open(failed_file, "r", encoding="utf-8") as f:
                failed_list = json.load(f)
                if not isinstance(failed_list, list):
                    failed_list = []
        except Exception:
            failed_list = []

    record = {
        "version": version,
        "failed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "reason": reason
    }
    if not any(item.get("version") == version for item in failed_list if isinstance(item, dict)):
        failed_list.append(record)

    try:
        with open(failed_file, "w", encoding="utf-8") as f:
            json.dump(failed_list, f, indent=2)
        logger.info(f"Versão {version} registrada na lista negra de atualizações com falha (failed_updates.json).")
    except Exception as e:
        logger.warning(f"Erro ao gravar failed_updates.json: {e}")


def execute_rollback(target_dir: str, current_exe: str, previous_exe: str, task_name: str, failed_version: str, reason: str, logger):
    """
    Restaura a versão anterior segura (GivovaMonitorAgent.previous.exe) e reinicia o serviço.
    """
    logger.error(f"[ROLLBACK CRÍTICO] Iniciando restauração para versão estável anterior. Motivo: {reason}")
    register_failed_update(target_dir, failed_version, reason, logger)

    terminate_by_name("GivovaMonitorAgent.exe", logger)
    time.sleep(2)

    if os.path.exists(previous_exe):
        try:
            shutil.copy2(previous_exe, current_exe)
            logger.info(f"[ROLLBACK] '{previous_exe}' restaurado como '{current_exe}'.")
        except Exception as e:
            logger.critical(f"[ROLLBACK FALHOU] Erro ao restaurar arquivo anterior: {e}")
            return False
    else:
        logger.critical(f"[ROLLBACK IMPOSSÍVEL] Arquivo de backup '{previous_exe}' não encontrado!")
        return False

    state_file = os.path.join(target_dir, "update_state.json")
    if os.path.exists(state_file):
        try:
            os.remove(state_file)
        except Exception:
            pass

    start_agent(target_dir, current_exe, task_name, logger)
    logger.info("[ROLLBACK CONCLUÍDO] Agente anterior reiniciado com sucesso.")
    return True


def start_agent(target_dir: str, current_exe: str, task_name: str, logger):
    """
    Inicia o agente via Agendador de Tarefas do Windows ou fallback direto.
    """
    started = False
    if task_name and sys.platform == "win32":
        try:
            res = subprocess.run(["schtasks", "/run", "/tn", task_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if res.returncode == 0:
                logger.info(f"Agente iniciado via Agendador de Tarefas ('{task_name}').")
                started = True
        except Exception as e:
            logger.warning(f"Falha ao iniciar via schtasks: {e}")

    if not started and os.path.exists(current_exe):
        try:
            DETACHED_PROCESS = 0x00000008
            CREATE_NEW_PROCESS_GROUP = 0x00000200
            flags = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
            subprocess.Popen([current_exe], cwd=target_dir, creationflags=flags)
            logger.info(f"Agente iniciado diretamente via processo desanexado: {current_exe}")
            started = True
        except Exception as e:
            logger.error(f"Erro ao iniciar executável diretamente: {e}")

    return started


def select_approved_updater(target_dir: str, agent_version: str):
    """Keep the signed canonical launcher; run a signed versioned engine if required."""
    base_url, headers = trusted_update.load_update_identity(target_dir)
    plan = trusted_update.fetch_updater_plan(base_url, headers, agent_version)
    minimum = plan["min_updater_version"]
    if not trusted_update.is_newer(minimum, UPDATER_VERSION):
        return None, minimum
    release = plan.get("updater_release")
    if not release or trusted_update.is_newer(minimum, release["version"]):
        raise ValueError("no approved updater satisfies the Agent minimum")
    canonical = TRUSTED_UPDATER if sys.platform == "win32" else os.path.join(target_dir, "GivovaMonitorUpdater.exe")
    store = TRUSTED_DIR if sys.platform == "win32" else target_dir
    engine = trusted_update.stage_updater(base_url, headers, release, store, canonical, agent_version)
    return engine, minimum


def _is_local_system():
    result = subprocess.run(["whoami", "/user", "/fo", "csv", "/nh"],
                            capture_output=True, text=True, timeout=10, check=False)
    return result.returncode == 0 and "S-1-5-18" in result.stdout


def _approved_request(target_dir, version, new_exe, update_id, old_pid, logger):
    """Queue fixed-path work for the one-time-installed LocalSystem task."""
    trusted_update.version_parts(version)
    if not re.fullmatch(r"upd-[0-9a-f]{12}", update_id):
        raise ValueError("invalid update identifier")
    expected = os.path.join(target_dir, "temp", f"update_v{version}.exe")
    if os.path.normcase(os.path.realpath(new_exe)) != os.path.normcase(os.path.realpath(expected)):
        raise ValueError("Agent artifact is outside the fixed staging path")
    if not os.path.isfile(expected) or not os.path.isfile(os.path.join(target_dir, "GivovaMonitorUpdater.exe")):
        raise ValueError("trusted Agent or Updater artifact missing")
    task = subprocess.run(["schtasks", "/query", "/tn", UPDATE_TASK],
                          capture_output=True, timeout=10, check=False)
    if task.returncode:
        raise RuntimeError("privileged update task is not installed")
    trusted_update.verify_same_signer(expected, os.path.join(target_dir, "GivovaMonitorUpdater.exe"))
    payload = {"version": version, "update_id": update_id, "old_pid": max(0, old_pid or 0)}
    request_path = os.path.join(target_dir, REQUEST_FILE)
    temporary = request_path + ".tmp"
    with open(temporary, "w", encoding="utf-8") as handle:
        json.dump(payload, handle)
    os.replace(temporary, request_path)
    logger.info("Approved update request queued for fixed privileged task")


def _worker_arguments(target_dir, logger):
    """Resolve only an active, device-authorized release; never trust request paths."""
    if not _is_local_system():
        raise PermissionError("update worker must run as LocalSystem")
    request_path = os.path.join(target_dir, REQUEST_FILE)
    with open(request_path, encoding="utf-8") as handle:
        payload = json.load(handle)
    version = payload.get("version")
    trusted_update.version_parts(version)
    update_id = payload.get("update_id")
    if not re.fullmatch(r"upd-[0-9a-f]{12}", update_id or ""):
        raise ValueError("invalid update identifier")
    base_url, headers = trusted_update.load_update_identity(target_dir)
    plan = trusted_update.fetch_updater_plan(base_url, headers, version)
    artifact = plan.get("agent_artifact")
    if not artifact or artifact.get("version") != version:
        raise ValueError("Agent release not authorized for this device")
    _, digest = trusted_update.validate_artifact(artifact, "agent")
    source = os.path.join(target_dir, "temp", f"update_v{version}.exe")
    protected_staging = os.path.join(TRUSTED_DIR, "staging")
    os.makedirs(protected_staging, exist_ok=True)
    staged = os.path.join(protected_staging, f"update_v{version}.exe")
    shutil.copy2(source, staged)
    trusted_update.verify_sha256(staged, digest)
    trusted_update.verify_same_signer(staged, TRUSTED_UPDATER)
    logger.info("Agent release authorization, SHA-256 and Authenticode verified")
    os.remove(request_path)
    return ["--target-dir", target_dir, "--new-exe", staged,
            "--old-pid", str(max(0, int(payload.get("old_pid") or 0))),
            "--version", version, "--update-id", update_id, "--task-worker"]


def run_updater():
    if sys.platform == "win32" and sys.argv[1:] == ["--apply-approved-request"]:
        target_dir = INSTALL_DIR
        logger = setup_logging(target_dir)
        try:
            sys.argv = [sys.argv[0]] + _worker_arguments(target_dir, logger)
        except FileNotFoundError:
            return  # the repeating task has no pending work
        except Exception as error:
            logger.error("Privileged update request rejected: %s", type(error).__name__)
            request_path = os.path.join(target_dir, REQUEST_FILE)
            if os.path.isfile(request_path):
                os.remove(request_path)
            current = os.path.join(target_dir, "GivovaMonitorAgent.exe")
            start_agent(target_dir, current, "Givova Monitor Agent", logger)
            return
    parser = argparse.ArgumentParser(description="Givova Monitor - Atualizador Supervisionado")
    parser.add_argument("--target-dir", dest="target_dir", required=True, help="Diretório de instalação do agente")
    parser.add_argument("--new-exe", dest="new_exe", help="Caminho do novo executável baixado")
    parser.add_argument("--old-pid", dest="old_pid", type=int, help="PID do agente anterior a ser aguardado")
    parser.add_argument("--version", dest="version", default="unknown", help="Número da nova versão")
    parser.add_argument("--update-id", dest="update_id", default="", help="Identificador único da tentativa de atualização")
    parser.add_argument("--timeout", dest="timeout", type=int, default=45, help="Tempo limite de confirmação em segundos")
    parser.add_argument("--task-name", dest="task_name", default="Givova Monitor Agent", help="Nome da tarefa no Agendador do Windows")
    parser.add_argument("--rollback", dest="do_rollback", action="store_true", help="Dispara rollback manual para versão anterior")
    parser.add_argument("--bootstrap-complete", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--required-updater-version", default="", help=argparse.SUPPRESS)
    parser.add_argument("--task-worker", action="store_true", help=argparse.SUPPRESS)

    args = parser.parse_args()
    target_dir = os.path.abspath(args.target_dir)
    logger = setup_logging(target_dir)

    logger.info("=" * 65)
    logger.info("   GIVOVA MONITOR UPDATER — ATUALIZADOR SUPERVISIONADO")
    logger.info(f"   Versão do Updater: {UPDATER_VERSION}")
    logger.info(f"   Diretório Alvo: {target_dir}")
    logger.info(f"   Versão Alvo: {args.version}")
    if args.update_id:
        logger.info(f"   Update ID: {args.update_id}")
    logger.info("=" * 65)

    current_exe = os.path.join(target_dir, "GivovaMonitorAgent.exe")
    previous_exe = os.path.join(target_dir, "GivovaMonitorAgent.previous.exe")
    confirmed_file = os.path.join(target_dir, "update_confirmed.json")
    state_file = os.path.join(target_dir, "update_state.json")

    if sys.platform == "win32" and os.path.normcase(target_dir) != os.path.normcase(INSTALL_DIR):
        logger.error("Updater target directory is not the registered Givova installation")
        sys.exit(1)

    # Tratamento de Rollback explícito
    if args.do_rollback:
        execute_rollback(target_dir, current_exe, previous_exe, args.task_name, args.version, "Solicitação explícita de rollback", logger)
        sys.exit(0)

    if not args.new_exe or not os.path.exists(args.new_exe):
        logger.error(f"Novo executável não informado ou inexistente: {args.new_exe}")
        sys.exit(1)

    if sys.platform == "win32" and not args.task_worker:
        try:
            _approved_request(target_dir, args.version, args.new_exe, args.update_id,
                              args.old_pid, logger)
            sys.exit(0)
        except Exception as error:
            logger.error("Unable to queue privileged update: %s", type(error).__name__)
            start_agent(target_dir, current_exe, args.task_name, logger)
            sys.exit(1)
    if sys.platform == "win32" and args.task_worker and not _is_local_system():
        logger.error("Privileged update worker rejected non-system execution")
        sys.exit(1)

    # The already-built Agent 1.5.3 still invokes this canonical filename.  A
    # signed canonical launcher can hand off to a signed, side-by-side engine
    # without replacing its own running executable or requiring recurring UAC.
    try:
        canonical = TRUSTED_UPDATER if sys.platform == "win32" else os.path.join(target_dir, "GivovaMonitorUpdater.exe")
        if sys.platform == "win32":
            trusted_update.verify_same_signer(args.new_exe, canonical)
        if args.bootstrap_complete:
            if not args.required_updater_version or trusted_update.is_newer(args.required_updater_version, UPDATER_VERSION):
                raise ValueError("versioned updater does not meet the required minimum")
            if sys.platform == "win32":
                trusted_update.verify_same_signer(sys.executable, canonical)
        else:
            engine, minimum = select_approved_updater(target_dir, args.version)
            if engine:
                command = [engine, "--target-dir", target_dir, "--new-exe", args.new_exe,
                           "--old-pid", str(args.old_pid or 0), "--version", args.version,
                           "--update-id", args.update_id, "--timeout", str(args.timeout),
                           "--task-name", args.task_name, "--bootstrap-complete",
                           "--task-worker",
                           "--required-updater-version", minimum]
                flags = 0x00000008 | 0x00000200 if sys.platform == "win32" else 0
                child = subprocess.Popen(command, cwd=target_dir, creationflags=flags,
                                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                         stderr=subprocess.DEVNULL, close_fds=True)
                if child.poll() is not None:
                    raise RuntimeError("approved updater exited before handoff")
                logger.info("Handed Agent update to verified Updater v%s", minimum)
                sys.exit(0)
    except Exception as error:
        logger.error("Trusted updater preparation failed: %s", type(error).__name__)
        start_agent(target_dir, current_exe, args.task_name, logger)
        sys.exit(1)

    # 1. Aguarda encerramento do processo anterior (libera o Mutex e o arquivo .exe)
    if args.old_pid:
        logger.info(f"Aguardando encerramento do processo anterior PID {args.old_pid}...")
        for _ in range(15):
            time.sleep(1)
            try:
                if sys.platform == "win32":
                    check = subprocess.run(["tasklist", "/FI", f"PID eq {args.old_pid}"], stdout=subprocess.PIPE, text=True)
                    if str(args.old_pid) not in check.stdout:
                        break
                else:
                    os.kill(args.old_pid, 0)
            except (OSError, Exception):
                break
        else:
            logger.warning(f"Processo PID {args.old_pid} não encerrou no tempo esperado. Forçando encerramento...")
            terminate_pid(args.old_pid, logger)
            time.sleep(2)

    # Garante que nenhum processo filho ou instância adicional do agente permaneça prendendo o arquivo
    terminate_by_name("GivovaMonitorAgent.exe", logger)
    time.sleep(1)

    # 2. Remove confirmação anterior se existir
    if os.path.exists(confirmed_file):
        try:
            os.remove(confirmed_file)
        except Exception:
            pass

    # 3. Faz backup seguro da versão atual
    if os.path.exists(current_exe):
        try:
            shutil.copy2(current_exe, previous_exe)
            logger.info(f"Backup da versão atual criado com sucesso em '{previous_exe}'.")
        except Exception as e:
            logger.error(f"Não foi possível fazer backup da versão atual: {e}")
            sys.exit(1)

    # 4. Substitui pelo novo executável
    try:
        for attempt in range(5):
            try:
                shutil.copy2(args.new_exe, current_exe)
                logger.info(f"Executável substituído com sucesso por v{args.version}.")
                break
            except PermissionError:
                logger.warning(f"Arquivo bloqueado (tentativa {attempt+1}/5). Aguardando 2s...")
                time.sleep(2)
        else:
            raise PermissionError("Arquivo continua bloqueado após várias tentativas.")
    except Exception as e:
        logger.critical(f"Falha ao substituir executável: {e}. Restaurando backup...")
        execute_rollback(target_dir, current_exe, previous_exe, args.task_name, args.version, f"Falha ao substituir arquivo: {e}", logger)
        sys.exit(1)

    # 5. Grava estado 'validating'
    try:
        with open(state_file, "w", encoding="utf-8") as f:
            json.dump({
                "target_version": args.version,
                "status": "validating",
                "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            }, f, indent=2)
    except Exception:
        pass

    # 6. Inicia a nova versão
    logger.info(f"Iniciando nova versão v{args.version}...")
    start_agent(target_dir, current_exe, args.task_name, logger)

    # 7. SUPERVISÃO DE BOOT: Aguarda confirmação ativa de saúde
    logger.info(f"Supervisionando inicialização de v{args.version} (timeout: {args.timeout}s)...")
    start_wait = time.time()
    confirmed = False

    pending_file = os.path.join(target_dir, "pending_update.json")

    while (time.time() - start_wait) < args.timeout:
        time.sleep(2)

        if os.path.exists(confirmed_file):
            try:
                with open(confirmed_file, "r", encoding="utf-8") as f:
                    cdata = json.load(f)
                    if cdata.get("status") == "confirmed":
                        # Validação do update_id para garantir que não é confirmação residual antiga
                        cid = cdata.get("update_id")
                        cver = cdata.get("version")
                        if args.update_id and cid != args.update_id:
                            logger.warning(f"Confirmação residual ignorada: update_id recebido '{cid}' != esperado '{args.update_id}'")
                            continue
                        if args.version and args.version != "unknown" and cver != args.version:
                            logger.warning(f"Confirmação residual ignorada: versão recebida '{cver}' != esperada '{args.version}'")
                            continue

                        logger.info(f"CONFIRMAÇÃO RECEBIDA! Versão v{args.version} (id: {cid}) reportou com sucesso ao servidor.")
                        confirmed = True
                        break
            except Exception:
                pass

    # 8. Decisão Final: Sucesso ou Rollback
    if confirmed:
        try:
            if os.path.exists(state_file):
                os.remove(state_file)
            if os.path.exists(pending_file):
                os.remove(pending_file)
            if os.path.exists(args.new_exe):
                os.remove(args.new_exe)
        except Exception:
            pass

        logger.info(f"Atualização para v{args.version} finalizada com 100% DE SUCESSO!")
        sys.exit(0)
    else:
        logger.error(f"TEMPO ESGOTADO! Versão v{args.version} não confirmou funcionamento em {args.timeout}s.")
        execute_rollback(
            target_dir=target_dir,
            current_exe=current_exe,
            previous_exe=previous_exe,
            task_name=args.task_name,
            failed_version=args.version,
            reason=f"Timeout de {args.timeout}s sem confirmação saudável de funcionamento",
            logger=logger
        )
        sys.exit(1)


if __name__ == "__main__":
    run_updater()
