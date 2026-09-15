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

UPDATER_VERSION = "1.1.0"

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


def run_updater():
    parser = argparse.ArgumentParser(description="Givova Monitor - Atualizador Supervisionado")
    parser.add_argument("--target-dir", dest="target_dir", required=True, help="Diretório de instalação do agente")
    parser.add_argument("--new-exe", dest="new_exe", help="Caminho do novo executável baixado")
    parser.add_argument("--old-pid", dest="old_pid", type=int, help="PID do agente anterior a ser aguardado")
    parser.add_argument("--version", dest="version", default="unknown", help="Número da nova versão")
    parser.add_argument("--update-id", dest="update_id", default="", help="Identificador único da tentativa de atualização")
    parser.add_argument("--timeout", dest="timeout", type=int, default=45, help="Tempo limite de confirmação em segundos")
    parser.add_argument("--task-name", dest="task_name", default="Givova Monitor Agent", help="Nome da tarefa no Agendador do Windows")
    parser.add_argument("--rollback", dest="do_rollback", action="store_true", help="Dispara rollback manual para versão anterior")

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

    # Tratamento de Rollback explícito
    if args.do_rollback:
        execute_rollback(target_dir, current_exe, previous_exe, args.task_name, args.version, "Solicitação explícita de rollback", logger)
        sys.exit(0)

    if not args.new_exe or not os.path.exists(args.new_exe):
        logger.error(f"Novo executável não informado ou inexistente: {args.new_exe}")
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
