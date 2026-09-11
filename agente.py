"""
Givova Transportes - Agente de Monitoramento Interno de PCs
Versão: 1.3.0
Finalidade: Coleta técnica de telemetria de hardware, rede e atividade de primeiro plano para suporte corporativo.
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
import threading
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler

import psutil
import requests

# Detecção Windows para primeiro plano
if platform.system() == "Windows":
    import ctypes
    from ctypes import wintypes

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

VERSION = "1.3.0"
CONFIG_FILE = "agent_config.json"
LOCAL_RECEIVER_PORT = 5005

# Estado compartilhado e thread-safe para telemetria de abas da extensão corporativa
_tab_lock = threading.Lock()
_latest_browser_tab = {
    "domain": None,
    "browser": None,
    "updated_at": 0
}


class ExtensionReceiverHandler(BaseHTTPRequestHandler):
    """
    Receptor HTTP ultraleve ouvindo exclusivamente em 127.0.0.1 para receber
    notificações de domínio da extensão corporativa do Chrome / Edge.
    """
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_POST(self):
        if self.path == "/active-tab":
            try:
                content_length = int(self.headers.get("Content-Length", 0))
                post_data = self.rfile.read(content_length)
                data = json.loads(post_data.decode("utf-8"))
                raw_domain = data.get("domain")
                browser = data.get("browser", "Browser")

                clean_domain = None
                if raw_domain and isinstance(raw_domain, str):
                    # Sanitização de privacidade: estritamente hostname, sem paths ou parâmetros
                    clean_domain = raw_domain.strip().lower().split("/")[0].split("?")[0].split("#")[0]
                    if len(clean_domain) > 150:
                        clean_domain = clean_domain[:150]

                with _tab_lock:
                    _latest_browser_tab["domain"] = clean_domain
                    _latest_browser_tab["browser"] = browser
                    _latest_browser_tab["updated_at"] = time.time()

                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(b'{"status":"ok"}')
            except Exception:
                self.send_response(400)
                self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        # Suprime logs de requisições locais para manter a saída do terminal limpa
        pass


def start_extension_receiver(port=LOCAL_RECEIVER_PORT):
    """
    Inicia o servidor de recebimento da extensão em background (daemon thread).
    """
    try:
        server = HTTPServer(("127.0.0.1", port), ExtensionReceiverHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        logger.info(f"Receptor local da extensão iniciado em http://127.0.0.1:{port}/active-tab")
        return server
    except OSError as oe:
        logger.warning(f"Porta local {port} já em uso ou indisponível ({oe}). A detecção de domínio via extensão poderá estar desativada.")
        return None
    except Exception as e:
        logger.warning(f"Não foi possível iniciar receptor local da extensão: {e}")
        return None


def get_foreground_application():
    """
    Identifica o aplicativo em primeiro plano de forma leve e sem impacto em CPU no Windows.
    """
    if platform.system() != "Windows":
        return None

    try:
        hwnd = ctypes.windll.user32.GetForegroundWindow()
        if not hwnd:
            return None

        pid = wintypes.DWORD()
        ctypes.windll.user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        if not pid.value or pid.value == 0:
            return None

        try:
            proc = psutil.Process(pid.value)
            exe_name = proc.name().lower()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None

        # Mapeamento corporativo para identificação limpa dos aplicativos
        APP_MAP = {
            "chrome.exe": "Google Chrome",
            "msedge.exe": "Microsoft Edge",
            "brave.exe": "Brave Browser",
            "firefox.exe": "Mozilla Firefox",
            "excel.exe": "Microsoft Excel",
            "winword.exe": "Microsoft Word",
            "powerpnt.exe": "Microsoft PowerPoint",
            "outlook.exe": "Microsoft Outlook",
            "code.exe": "VS Code",
            "devenv.exe": "Visual Studio",
            "notepad.exe": "Bloco de Notas",
            "notepad++.exe": "Notepad++",
            "calc.exe": "Calculadora",
            "calculatorapp.exe": "Calculadora",
            "teams.exe": "Microsoft Teams",
            "ms-teams.exe": "Microsoft Teams",
            "slack.exe": "Slack",
            "discord.exe": "Discord",
            "spotify.exe": "Spotify",
            "explorer.exe": "Windows Explorer",
            "windowsterminal.exe": "Terminal Windows",
            "powershell.exe": "PowerShell",
            "cmd.exe": "Prompt de Comando",
            "taskmgr.exe": "Gerenciador de Tarefas"
        }

        return APP_MAP.get(exe_name, exe_name.replace(".exe", "").capitalize())
    except Exception:
        return None


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
        "timeout_seconds": 5,
        "activity_monitoring": os.getenv("ACTIVITY_MONITORING_ENABLED", "true").lower() in ("true", "1", "yes")
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
    parser.add_argument("--sem-atividade", dest="disable_activity", action="store_true", help="Desabilita o monitoramento de janela e domínio ativo")

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
    if args.disable_activity:
        defaults["activity_monitoring"] = False

    return defaults


def get_machine_uuid():
    """
    Gera ou obtém identificador único persistente para a máquina física.
    """
    try:
        mac = uuid.getnode()
        return f"node-{hex(mac)[2:]}"
    except Exception:
        hostname = socket.gethostname()
        return f"host-{hostname.lower().strip()}"


def get_system_metrics(activity_enabled: bool = True):
    """
    Coleta dados técnicos de hardware, rede, sistema operacional e atividade em primeiro plano.
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

    # Detecção de Atividade Atual em Primeiro Plano
    active_application = None
    active_domain = None

    if activity_enabled:
        active_application = get_foreground_application()
        if active_application:
            # Se for navegador, verifica se temos telemetria recente da extensão corporativa
            app_lower = active_application.lower()
            if any(b in app_lower for b in ["chrome", "edge", "chromium", "brave", "firefox"]):
                with _tab_lock:
                    # Considera domínio válido se recebido nos últimos 45 segundos
                    if _latest_browser_tab["domain"] and (time.time() - _latest_browser_tab["updated_at"] < 45):
                        active_domain = _latest_browser_tab["domain"]
                    else:
                        # FALLBACK SEGURO: Não inventa domínio se a extensão não reportou
                        active_domain = None
            else:
                # O usuário está em outro software (Excel, VS Code, etc.)
                active_domain = None
        else:
            # Fallback para serviços em background: se a extensão reportou atividade recentemente
            with _tab_lock:
                if _latest_browser_tab["domain"] and (time.time() - _latest_browser_tab["updated_at"] < 45):
                    active_application = _latest_browser_tab["browser"] or "Google Chrome"
                    active_domain = _latest_browser_tab["domain"]

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
        "active_application": active_application,
        "active_domain": active_domain,
        "activity_updated_at": datetime.now(timezone.utc).isoformat() if active_application else None,
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

    logger.info("=" * 65)
    logger.info("   GIVOVA TRANSPORTES - AGENTE DE MONITORAMENTO DE PCS")
    logger.info(f"   Versão: {VERSION} | Setor: {config['department']}")
    logger.info(f"   Servidor: {config['server_url']}")
    logger.info(f"   Intervalo: {config['interval_seconds']}s")
    logger.info(f"   Monitoramento de Atividade: {'Habilitado' if config['activity_monitoring'] else 'Desabilitado'}")
    logger.info("=" * 65)

    # Inicia o receptor local para a extensão Chromium se o monitoramento de atividade estiver ativo
    if config["activity_monitoring"]:
        start_extension_receiver(LOCAL_RECEIVER_PORT)

    # Cria arquivo de configuração inicial local caso não exista para facilitar customização
    if not os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump({
                    "server_url": config["server_url"],
                    "agent_token": config["agent_token"],
                    "department": config["department"],
                    "display_name": config["display_name"],
                    "interval_seconds": config["interval_seconds"],
                    "activity_monitoring": config["activity_monitoring"]
                }, f, indent=4)
        except Exception:
            pass

    fail_count = 0

    while True:
        try:
            metrics = get_system_metrics(activity_enabled=config["activity_monitoring"])
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
                activity_log = ""
                if metrics.get("active_application"):
                    if metrics.get("active_domain"):
                        activity_log = f" | Atividade: {metrics['active_application']} — {metrics['active_domain']}"
                    else:
                        activity_log = f" | Atividade: {metrics['active_application']}"

                logger.info(
                    f"OK [{metrics['hostname']}] CPU: {metrics['cpu']}% | "
                    f"RAM: {metrics['ram']}% ({metrics['ram_used_gb']}G/{metrics['ram_total_gb']}G) | "
                    f"Disco: {metrics['disco']}%{activity_log} - {message}"
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