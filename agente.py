"""
Givova Transportes - Agente de Monitoramento Interno de PCs
Versão: 1.2.0
Finalidade: Coleta técnica de telemetria de hardware e rede para suporte e inventário de TI corporativo.
"""

import sys
import os
import time
import socket
import platform
import getpass
import json
import logging
import argparse
import uuid
import psutil
import requests

# Configuração de Logging do Agente
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("agente.log", encoding="utf-8")
    ]
)
logger = logging.getLogger("GivovaAgent")

VERSION = "1.2.0"
CONFIG_FILE = "agent_config.json"


def load_config():
    """
    Carrega configurações priorizando argumentos CLI > variáveis de ambiente > agent_config.json > padrões.
    """
    defaults = {
        "server_url": os.getenv("SERVER_URL", "http://127.0.0.1:5000/api/agent/report"),
        "agent_token": os.getenv("AGENT_TOKEN", "givova_agent_token_dev_2026"),
        "department": os.getenv("DEPARTMENT", "TI"),
        "display_name": os.getenv("DISPLAY_NAME", ""),
        "interval_seconds": int(os.getenv("INTERVAL_SECONDS", "5")),
        "timeout_seconds": 5
    }

    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                file_cfg = json.load(f)
                defaults.update(file_cfg)
        except Exception as e:
            logger.warning(f"Não foi possível ler {CONFIG_FILE}: {e}")

    # Argumentos de linha de comando
    parser = argparse.ArgumentParser(description="Agente de Monitoramento de PCs - Givova Transportes")
    parser.add_argument("--server", dest="server_url", help="URL do servidor de monitoramento")
    parser.add_argument("--token", dest="agent_token", help="Token de autenticação do agente")
    parser.add_argument("--setor", dest="department", help="Setor/Departamento da máquina (ex: Logística, TI, Financeiro)")
    parser.add_argument("--nome", dest="display_name", help="Nome amigável da máquina")
    parser.add_argument("--intervalo", dest="interval_seconds", type=int, help="Intervalo de envio em segundos")

    args, _ = parser.parse_known_args()
    if args.server_url:
        defaults["server_url"] = args.server_url
    if args.agent_token:
        defaults["agent_token"] = args.agent_token
    if args.department:
        defaults["department"] = args.department
    if args.display_name:
        defaults["display_name"] = args.display_name
    if args.interval_seconds:
        defaults["interval_seconds"] = max(2, args.interval_seconds)

    return defaults


def get_machine_uuid():
    """
    Gera ou obtém identificador único persistente para a máquina física.
    """
    try:
        # Tenta obter endereço MAC
        mac = uuid.getnode()
        return f"node-{hex(mac)[2:]}"
    except Exception:
        hostname = socket.gethostname()
        return f"host-{hostname.lower().strip()}"


def get_system_metrics():
    """
    Coleta dados técnicos de hardware, rede e sistema operacional de forma segura e resiliente.
    """
    hostname = socket.gethostname()

    # Identificação do usuário logado
    try:
        current_user = getpass.getuser()
    except Exception:
        current_user = "sistema"

    # Endereço IP local
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except Exception:
        try:
            local_ip = socket.gethostbyname(hostname)
        except Exception:
            local_ip = "127.0.0.1"

    # Sistema Operacional e Arquitetura
    os_name = f"{platform.system()} {platform.release()}"
    os_arch = platform.machine() or "x64"

    # Processador e Núcleos
    processor = platform.processor() or "Processador Padrão"
    cores = psutil.cpu_count(logical=True) or 1

    # CPU percentual instantâneo
    try:
        cpu = psutil.cpu_percent(interval=0.5)
    except Exception:
        cpu = 0.0

    # Memória RAM
    try:
        vmem = psutil.virtual_memory()
        ram_percent = vmem.percent
        ram_total_gb = round(vmem.total / (1024 ** 3), 2)
        ram_used_gb = round(vmem.used / (1024 ** 3), 2)
    except Exception:
        ram_percent = 0.0
        ram_total_gb = 0.0
        ram_used_gb = 0.0

    # Disco Principal (suporta Windows e Linux)
    try:
        drive_path = "C:\\" if platform.system() == "Windows" else "/"
        # Caso C:\ não exista por algum motivo
        if not os.path.exists(drive_path) and platform.system() == "Windows":
            drive_path = os.getenv("SystemDrive", "C:") + "\\"

        disk = psutil.disk_usage(drive_path)
        disk_percent = disk.percent
        disk_total_gb = round(disk.total / (1024 ** 3), 2)
        disk_used_gb = round(disk.used / (1024 ** 3), 2)
    except Exception:
        disk_percent = 0.0
        disk_total_gb = 0.0
        disk_used_gb = 0.0

    # Uptime do sistema
    try:
        boot_time = psutil.boot_time()
        uptime_seconds = int(time.time() - boot_time)
    except Exception:
        uptime_seconds = 0

    return {
        "uuid": get_machine_uuid(),
        "computador": hostname,
        "hostname": hostname,
        "usuario": current_user,
        "ip": local_ip,
        "os_name": os_name,
        "os_arch": os_arch,
        "processador": processor,
        "cpu_cores": cores,
        "cpu": cpu,
        "ram": ram_percent,
        "ram_total_gb": ram_total_gb,
        "ram_used_gb": ram_used_gb,
        "disco": disk_percent,
        "disk_total_gb": disk_total_gb,
        "disk_used_gb": disk_used_gb,
        "uptime_seconds": uptime_seconds,
        "agent_version": VERSION
    }


def send_metrics(server_url: str, token: str, payload: dict, timeout: int = 5):
    """
    Envia métricas para o servidor com header de autenticação e timeout.
    """
    headers = {
        "Content-Type": "application/json",
        "X-Agent-Token": token,
        "User-Agent": f"GivovaMonitorAgent/{VERSION}"
    }

    try:
        response = requests.post(server_url, json=payload, headers=headers, timeout=timeout)
        if response.status_code == 200:
            return True, "Enviado com sucesso (HTTP 200)"
        elif response.status_code == 401:
            return False, "Falha de autenticação: Token inválido ou rejeitado pelo servidor"
        else:
            return False, f"Servidor respondeu com código de erro {response.status_code}"
    except requests.exceptions.Timeout:
        return False, "Tempo de resposta do servidor esgotado (Timeout)"
    except requests.exceptions.ConnectionError:
        return False, "Servidor indisponível ou conexão recusada"
    except Exception as e:
        return False, f"Erro de comunicação: {str(e)}"


def run_agent():
    config = load_config()

    logger.info("=" * 60)
    logger.info("   GIVOVA TRANSPORTES - AGENTE DE MONITORAMENTO DE PCS")
    logger.info(f"   Versão: {VERSION} | Setor: {config['department']}")
    logger.info(f"   Servidor: {config['server_url']}")
    logger.info(f"   Intervalo: {config['interval_seconds']}s")
    logger.info("=" * 60)

    # Cria arquivo de configuração inicial local caso não exista para facilitar customização
    if not os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump({
                    "server_url": config["server_url"],
                    "agent_token": config["agent_token"],
                    "department": config["department"],
                    "display_name": config["display_name"],
                    "interval_seconds": config["interval_seconds"]
                }, f, indent=4)
        except Exception:
            pass

    fail_count = 0

    while True:
        try:
            metrics = get_system_metrics()
            metrics["setor"] = config["department"]
            if config["display_name"]:
                metrics["display_name"] = config["display_name"]

            success, message = send_metrics(
                server_url=config["server_url"],
                token=config["agent_token"],
                payload=metrics,
                timeout=config["timeout_seconds"]
            )

            if success:
                fail_count = 0
                logger.info(
                    f"OK [{metrics['hostname']}] CPU: {metrics['cpu']}% | "
                    f"RAM: {metrics['ram']}% ({metrics['ram_used_gb']}G/{metrics['ram_total_gb']}G) | "
                    f"Disco: {metrics['disco']}% - {message}"
                )
            else:
                fail_count += 1
                logger.warning(f"Falha de envio ({fail_count}x): {message}")

        except KeyboardInterrupt:
            logger.info("Agente encerrado pelo operador.")
            break
        except Exception as e:
            logger.error(f"Erro inesperado no ciclo de coleta: {e}", exc_info=True)

        time.sleep(config["interval_seconds"])


if __name__ == "__main__":
    run_agent()