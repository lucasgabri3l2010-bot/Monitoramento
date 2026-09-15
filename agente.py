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
import random
import shutil
import hashlib
import subprocess
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from logging.handlers import RotatingFileHandler

import psutil
import requests

# Detecção Windows para primeiro plano e Mutex
if platform.system() == "Windows":
    import ctypes
    from ctypes import wintypes

VERSION = "1.5.0"
LOCAL_RECEIVER_PORT = 5005


def get_app_dir() -> str:
    """
    Retorna o diretório base da aplicação:
    - Se for executável empacotado (PyInstaller): diretório do .exe
    - Se executado via python: diretório do script atual
    """
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


APP_DIR = get_app_dir()


def get_config_file_path() -> str:
    r"""
    Retorna o caminho do arquivo de configuração priorizando:
    1. GIVOVA_CONFIG_PATH (se definido no ambiente)
    2. C:\ProgramData\GivovaMonitor\agent_config.json (instalação padrão no Windows)
    3. agent_config.json no mesmo diretório do executável/script (APP_DIR)
    """
    env_path = os.getenv("GIVOVA_CONFIG_PATH")
    if env_path:
        return env_path

    standard_path = r"C:\ProgramData\GivovaMonitor\agent_config.json"
    if platform.system() == "Windows" and os.path.exists(standard_path):
        return standard_path

    app_dir_path = os.path.join(APP_DIR, "agent_config.json")
    if os.path.exists(app_dir_path):
        return app_dir_path

    if platform.system() == "Windows":
        return standard_path
    return app_dir_path


CONFIG_FILE = get_config_file_path()
LOG_DIR = os.getenv("GIVOVA_LOG_DIR", os.path.join(APP_DIR, "logs"))

try:
    os.makedirs(LOG_DIR, exist_ok=True)
except Exception:
    pass

LOG_FILE = os.path.join(LOG_DIR, "agente.log")

# Configuração de Logging do Agente com Rotação (5MB, 3 backups)
_handlers = []
if sys.stdout is not None:
    _handlers.append(logging.StreamHandler(sys.stdout))

try:
    _file_handler = RotatingFileHandler(
        LOG_FILE,
        maxBytes=5 * 1024 * 1024,  # 5 MB por arquivo
        backupCount=3,
        encoding="utf-8"
    )
    _handlers.append(_file_handler)
except Exception:
    # Se falhar o arquivo na pasta de logs, tenta no diretório da app
    try:
        _handlers.append(RotatingFileHandler(os.path.join(APP_DIR, "agente.log"), maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"))
    except Exception:
        pass

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=_handlers
)
logger = logging.getLogger("GivovaAgent")

# Named Mutex para controle de instância única no Windows
_single_instance_mutex = None


def acquire_single_instance_mutex() -> bool:
    """
    Garante que apenas uma única instância do agente execute no computador.
    Retorna True se adquiriu o mutex com sucesso, ou False se outra instância já estiver ativa.
    """
    global _single_instance_mutex
    if platform.system() != "Windows":
        return True

    try:
        ERROR_ALREADY_EXISTS = 183
        CreateMutexW = ctypes.windll.kernel32.CreateMutexW
        CreateMutexW.argtypes = [wintypes.LPVOID, wintypes.BOOL, wintypes.LPCWSTR]
        CreateMutexW.restype = wintypes.HANDLE

        GetLastError = ctypes.windll.kernel32.GetLastError
        GetLastError.restype = wintypes.DWORD

        # Tenta criar o mutex com escopo Global
        mutex_name = "Global\\GivovaMonitorAgent_SingleInstance_Mutex"
        handle = CreateMutexW(None, True, mutex_name)
        err = GetLastError()

        if err == ERROR_ALREADY_EXISTS:
            logger.warning("Outra instância do GivovaMonitorAgent já está em execução (Global Mutex detectado). Encerrando.")
            return False

        if not handle or handle == 0:
            # Fallback para escopo Local da sessão do usuário
            mutex_name = "Local\\GivovaMonitorAgent_SingleInstance_Mutex"
            handle = CreateMutexW(None, True, mutex_name)
            if GetLastError() == ERROR_ALREADY_EXISTS:
                logger.warning("Outra instância do GivovaMonitorAgent já está em execução (Local Mutex detectado). Encerrando.")
                return False

        _single_instance_mutex = handle
        return True
    except Exception as e:
        logger.warning(f"Não foi possível verificar mutex de instância única: {e}")
        return True

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


# =========================================================================
# Estruturas e APIs do Windows para Rastreamento de Ociosidade e Bloqueio
# =========================================================================

if platform.system() == "Windows":
    class LASTINPUTINFO(ctypes.Structure):
        _fields_ = [
            ("cbSize", wintypes.UINT),
            ("dwTime", wintypes.DWORD)
        ]

    WTS_CURRENT_SERVER_HANDLE = 0
    WTS_CURRENT_SESSION = -1
    WTSSessionInfoEx = 25
    WTS_SESSIONSTATE_LOCK = 0
    WTS_SESSIONSTATE_UNLOCK = 1
    WTS_SESSIONSTATE_UNKNOWN = 0xFFFFFFFF

    class WTSINFOEX_LEVEL1_W(ctypes.Structure):
        _fields_ = [
            ("SessionId", wintypes.ULONG),
            ("SessionState", wintypes.DWORD),
            ("SessionFlags", wintypes.DWORD),
            ("WinStationName", wintypes.WCHAR * 33),
            ("UserName", wintypes.WCHAR * 257),
            ("DomainName", wintypes.WCHAR * 18),
            ("LogonTime", wintypes.LARGE_INTEGER),
            ("ConnectTime", wintypes.LARGE_INTEGER),
            ("DisconnectTime", wintypes.LARGE_INTEGER),
            ("LastInputTime", wintypes.LARGE_INTEGER),
            ("LogonId", wintypes.LARGE_INTEGER),
            ("IncomingBytes", wintypes.LARGE_INTEGER),
            ("OutgoingBytes", wintypes.LARGE_INTEGER),
            ("IncomingFrames", wintypes.LARGE_INTEGER),
            ("OutgoingFrames", wintypes.LARGE_INTEGER),
            ("IncomingCompressedBytes", wintypes.LARGE_INTEGER),
            ("OutgoingCompressedBytes", wintypes.LARGE_INTEGER)
        ]

    class WTSINFOEX_UNION(ctypes.Union):
        _fields_ = [
            ("WTSInfoExLevel1", WTSINFOEX_LEVEL1_W)
        ]

    class WTSINFOEXW(ctypes.Structure):
        _fields_ = [
            ("Level", wintypes.DWORD),
            ("Data", WTSINFOEX_UNION)
        ]


def get_idle_seconds() -> float:
    """
    Mede com precisão técnica o tempo decorrido desde a última entrada local de teclado/mouse
    usando GetLastInputInfo do Windows.
    Garante:
    - Zero keylogging: não registra quais teclas foram pressionadas nem cliques.
    - Tratamento de wraparound de 32 bits do contador de tick.
    - Rejeição de leituras negativas ou anômalas.
    """
    if platform.system() != "Windows":
        return 0.0

    try:
        lii = LASTINPUTINFO()
        lii.cbSize = ctypes.sizeof(LASTINPUTINFO)
        if ctypes.windll.user32.GetLastInputInfo(ctypes.byref(lii)):
            now_tick = ctypes.windll.kernel32.GetTickCount()
            millis = (now_tick - lii.dwTime) & 0xFFFFFFFF
            idle_sec = millis / 1000.0
            if idle_sec < 0.0 or idle_sec > (86400 * 365):
                return 0.0
            return max(0.0, idle_sec)
    except Exception as e:
        logger.debug(f"Falha ao chamar GetLastInputInfo: {e}")
    return 0.0


def get_windows_session_info() -> tuple:
    """
    Obtém o ID da sessão interativa do Windows e o estado de bloqueio (locked/unlocked).
    Prioriza a API oficial WTSQuerySessionInformationW (WTSSessionInfoEx Level 1).
    Retorna: (windows_session_id: int | None, is_locked: bool | None)
    """
    if platform.system() != "Windows":
        return None, False

    session_id = None
    is_locked = None

    try:
        wtsapi32 = ctypes.windll.wtsapi32
        pBuffer = ctypes.c_void_p()
        bytesReturned = wintypes.DWORD()
        success = wtsapi32.WTSQuerySessionInformationW(
            WTS_CURRENT_SERVER_HANDLE,
            WTS_CURRENT_SESSION,
            WTSSessionInfoEx,
            ctypes.byref(pBuffer),
            ctypes.byref(bytesReturned)
        )
        if success and pBuffer.value:
            info = ctypes.cast(pBuffer, ctypes.POINTER(WTSINFOEXW)).contents
            if info.Level == 1:
                session_id = int(info.Data.WTSInfoExLevel1.SessionId)
                flags = info.Data.WTSInfoExLevel1.SessionFlags
                if flags == WTS_SESSIONSTATE_LOCK:
                    is_locked = True
                elif flags == WTS_SESSIONSTATE_UNLOCK:
                    is_locked = False
            wtsapi32.WTSFreeMemory(pBuffer)
            if is_locked is not None:
                return session_id, is_locked
    except Exception as e:
        logger.debug(f"Falha na consulta WTSQuerySessionInformationW: {e}")

    # Fallback secundário se WTS não retornar estado conclusivo: OpenInputDesktop
    try:
        DESKTOP_SWITCHDESKTOP = 0x0100
        hDesk = ctypes.windll.user32.OpenInputDesktop(0, False, DESKTOP_SWITCHDESKTOP)
        if not hDesk or hDesk == 0:
            return session_id, True
        else:
            ctypes.windll.user32.CloseDesktop(hDesk)
            return session_id, False
    except Exception:
        pass

    return session_id, None


def determine_session_state(idle_seconds: float, idle_threshold: float, is_locked) -> tuple:
    """
    Avalia os sinais coletados e determina o estado canônico da sessão:
    - 'locked': tela bloqueada no Windows (Win+L / tela de bloqueio).
    - 'idle': sem interação de teclado/mouse há mais tempo que o threshold.
    - 'active': interação recente detectada.
    - 'unknown': falha ou sinal indeterminado.
    Retorna: (session_state: str, user_active: bool)
    """
    if is_locked is True:
        return "locked", False
    if idle_seconds is None or idle_seconds < 0:
        return "unknown", False
    if idle_seconds >= idle_threshold:
        return "idle", False
    return "active", True


def parse_semver(v: str) -> tuple:
    """Converte '1.4.0' ou 'v1.4' em tupla (1, 4, 0)."""
    try:
        clean = str(v).strip().lstrip("vV")
        parts = [int(p) for p in clean.split(".") if p.isdigit()]
        while len(parts) < 3:
            parts.append(0)
        return tuple(parts[:3])
    except Exception:
        return (1, 0, 0)


def is_newer_version(latest_v: str, current_v: str) -> bool:
    """Retorna True se latest_v for estritamente mais recente que current_v."""
    return parse_semver(latest_v) > parse_semver(current_v)


def emit_health_confirmation():
    """
    Emite update_confirmed.json para sinalizar ao GivovaMonitorUpdater
    que a nova versão iniciou com sucesso e já enviou seu primeiro report ao servidor.
    Utiliza o update_id gravado em pending_update.json para confirmação unívoca.
    """
    pending_file = os.path.join(APP_DIR, "pending_update.json")
    if not os.path.exists(pending_file):
        return

    try:
        update_id = ""
        with open(pending_file, "r", encoding="utf-8") as f:
            pdata = json.load(f)
            if isinstance(pdata, dict):
                target_ver = pdata.get("target_version")
                # Confirma apenas se a versão deste agente for a esperada pelo update
                if target_ver and target_ver != VERSION:
                    return
                update_id = pdata.get("update_id", "")

        conf_file = os.path.join(APP_DIR, "update_confirmed.json")
        with open(conf_file, "w", encoding="utf-8") as f:
            json.dump({
                "version": VERSION,
                "update_id": update_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "status": "confirmed"
            }, f, indent=2)

        if os.path.exists(pending_file):
            try:
                os.remove(pending_file)
            except Exception:
                pass

        logger.info(f"Confirmação de saúde emitida com sucesso para v{VERSION} (update_id: {update_id})")
    except Exception as e:
        logger.debug(f"Falha ao emitir arquivo de confirmação de saúde: {e}")


def get_failed_versions() -> list:
    """Retorna lista de versões que sofreram rollback para evitar loops de repetição."""
    failed_file = os.path.join(APP_DIR, "failed_updates.json")
    if os.path.exists(failed_file):
        try:
            with open(failed_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    return [item.get("version") for item in data if isinstance(item, dict) and item.get("version")]
        except Exception:
            pass
    return []


def start_auto_update_worker(config: dict):
    """Inicia thread de background para verificação periódica e aplicação de atualizações."""
    if not config.get("auto_update", True):
        logger.info("Auto-update desabilitado por configuração.")
        return None
    t = threading.Thread(target=_auto_update_loop, args=(config,), daemon=True)
    t.start()
    return t


def _auto_update_loop(config: dict):
    # Jitter inicial aleatório (20 a 45 segundos após início)
    time.sleep(random.randint(20, 45))
    check_interval = config.get("update_check_interval", 6 * 3600)

    while True:
        try:
            _check_and_apply_update(config)
        except Exception as e:
            logger.warning(f"Erro no ciclo de verificação de atualização: {e}")

        # Intervalo com jitter de até ± 10 minutos
        jitter = random.randint(-600, 600)
        sleep_time = max(300, check_interval + jitter)
        time.sleep(sleep_time)


def _check_and_apply_update(config: dict):
    server_url = config.get("server_url", "")
    token = config.get("agent_token", "")
    device_token = config.get("device_token")
    uuid_str = get_machine_uuid()

    from urllib.parse import urlparse
    parsed = urlparse(server_url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    update_url = f"{base_url}/api/agent/update"

    headers = {
        "X-Agent-Token": token,
        "X-Device-UUID": uuid_str,
        "User-Agent": f"GivovaMonitorAgent/{VERSION}"
    }
    if device_token:
        headers["X-Device-Token"] = device_token

    params = {
        "current_version": VERSION,
        "uuid": uuid_str,
        "os_name": platform.system(),
        "os_arch": platform.machine()
    }

    try:
        resp = requests.get(update_url, headers=headers, params=params, timeout=15)
        if resp.status_code != 200:
            return
        data = resp.json()
    except Exception as e:
        logger.debug(f"Servidor de atualização inacessível: {e}")
        return

    if not data.get("update_available"):
        return

    target_version = data.get("latest_version")
    target_sha256 = (data.get("sha256") or "").strip().lower()
    download_url = data.get("download_url")

    if not target_version or not download_url:
        return

    # 1. Verifica se esta versão está na lista de falhas anteriores (evita loop de rollback)
    failed_list = get_failed_versions()
    if target_version in failed_list:
        logger.warning(f"Versão v{target_version} está na lista de falhas anteriores (failed_updates.json). Ignorando atualização automática.")
        return

    # 2. Bloqueia downgrade não autorizado
    if not is_newer_version(target_version, VERSION):
        return

    logger.info(f"Nova versão disponível: v{VERSION} → v{target_version}. Iniciando download seguro...")

    if download_url.startswith("/"):
        download_url = f"{base_url}{download_url}"

    temp_dir = os.path.join(APP_DIR, "temp")
    os.makedirs(temp_dir, exist_ok=True)
    temp_file = os.path.join(temp_dir, f"update_v{target_version}.tmp")
    dest_exe = os.path.join(temp_dir, f"update_v{target_version}.exe")

    try:
        dl_resp = requests.get(download_url, headers=headers, stream=True, timeout=60)
        if dl_resp.status_code != 200:
            logger.error(f"Falha ao baixar nova versão (HTTP {dl_resp.status_code}).")
            return

        hasher = hashlib.sha256()
        with open(temp_file, "wb") as f:
            for chunk in dl_resp.iter_content(chunk_size=65536):
                if chunk:
                    f.write(chunk)
                    hasher.update(chunk)

        computed_sha256 = hasher.hexdigest().lower()

        # 3. Verificação de integridade SHA-256
        if target_sha256 and computed_sha256 != target_sha256:
            logger.critical(f"INTEGRIDADE COMPROMETIDA! SHA-256 divergente: esperado '{target_sha256}', obtido '{computed_sha256}'. Abortando atualização.")
            if os.path.exists(temp_file):
                os.remove(temp_file)
            return

        logger.info(f"Integridade SHA-256 validada com sucesso: {computed_sha256[:16]}...")
        if os.path.exists(dest_exe):
            os.remove(dest_exe)
        shutil.move(temp_file, dest_exe)

    except Exception as e:
        logger.error(f"Erro durante o download da nova versão: {e}")
        if os.path.exists(temp_file):
            try:
                os.remove(temp_file)
            except Exception:
                pass
        return

    # 4. Localiza executável do Updater
    updater_candidates = [
        os.path.join(APP_DIR, "GivovaMonitorUpdater.exe"),
        os.path.join(APP_DIR, "updater.py"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "updater.py")
    ]
    updater_path = None
    for cand in updater_candidates:
        if os.path.exists(cand):
            updater_path = cand
            break

    if not updater_path:
        logger.error("Atualizador GivovaMonitorUpdater não localizado para prosseguir.")
        return

    # 5. Prepara identificador único de atualização e limpa confirmações residuais antigas
    update_id = f"upd-{uuid.uuid4().hex[:12]}"
    confirmed_file = os.path.join(APP_DIR, "update_confirmed.json")
    if os.path.exists(confirmed_file):
        try:
            os.remove(confirmed_file)
        except Exception:
            pass

    pending_file = os.path.join(APP_DIR, "pending_update.json")
    try:
        with open(pending_file, "w", encoding="utf-8") as f:
            json.dump({
                "update_id": update_id,
                "target_version": target_version,
                "created_at": datetime.now(timezone.utc).isoformat()
            }, f, indent=2)
    except Exception as e:
        logger.warning(f"Não foi possível gravar pending_update.json: {e}")

    logger.info(f"Invocando GivovaMonitorUpdater ({updater_path}) [update_id: {update_id}] e encerrando agente atual...")

    cmd = [
        updater_path,
        "--target-dir", APP_DIR,
        "--new-exe", dest_exe,
        "--old-pid", str(os.getpid()),
        "--version", target_version,
        "--update-id", update_id
    ]
    if updater_path.endswith(".py"):
        cmd.insert(0, sys.executable)

    DETACHED_PROCESS = 0x00000008
    CREATE_NEW_PROCESS_GROUP = 0x00000200
    flags = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP if platform.system() == "Windows" else 0

    subprocess.Popen(cmd, cwd=APP_DIR, creationflags=flags)
    time.sleep(1)
    # Encerra agente para liberação do lock no Windows
    sys.exit(0)


def start_admin_notifications_worker(config: dict):
    """Inicia worker de notificações Windows para computadores da equipe de TI autorizados."""
    if not config.get("admin_notifications", False):
        return None
    t = threading.Thread(target=_admin_notifications_loop, args=(config,), daemon=True)
    t.start()
    return t


def _admin_notifications_loop(config: dict):
    time.sleep(10)
    last_seen_id = 0
    server_url = config.get("server_url", "")
    token = config.get("agent_token", "")
    device_token = config.get("device_token")
    uuid_str = get_machine_uuid()

    from urllib.parse import urlparse
    parsed = urlparse(server_url)
    alerts_url = f"{parsed.scheme}://{parsed.netloc}/api/agent/admin-alerts"

    headers = {
        "X-Agent-Token": token,
        "X-Device-UUID": uuid_str,
        "User-Agent": f"GivovaMonitorAgent/{VERSION}"
    }
    if device_token:
        headers["X-Device-Token"] = device_token

    while True:
        try:
            params = {"since_id": last_seen_id, "uuid": uuid_str}
            resp = requests.get(alerts_url, headers=headers, params=params, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                alerts = data.get("alerts", [])
                for alert in alerts:
                    alert_id = alert.get("id", 0)
                    if alert_id > last_seen_id:
                        last_seen_id = alert_id
                        show_windows_toast(alert.get("title", "Givova Monitor"), alert.get("message", ""))
            elif resp.status_code == 403:
                # Dispositivo não configurado como admin no servidor: pausa por 2 minutos
                time.sleep(120)
                continue
        except Exception as e:
            logger.debug(f"Polling de notificações admin: {e}")

        time.sleep(45)


def show_windows_toast(title: str, message: str):
    """Exibe notificação nativa Windows Toast de forma assíncrona e silenciosa."""
    if platform.system() != "Windows":
        return
    try:
        clean_title = title.replace('"', '`"').replace("'", "''")
        clean_msg = message.replace('"', '`"').replace("'", "''")
        ps_cmd = f'''
        [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
        $template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
        $textNodes = $template.GetElementsByTagName("text")
        $textNodes.Item(0).AppendChild($template.CreateTextNode("{clean_title}")) | Out-Null
        $textNodes.Item(1).AppendChild($template.CreateTextNode("{clean_msg}")) | Out-Null
        $notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("Givova Monitor")
        $toast = [Windows.UI.Notifications.ToastNotification]::new($template)
        $notifier.Show($toast)
        '''
        subprocess.Popen(
            ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_cmd],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=0x08000000  # CREATE_NO_WINDOW
        )
    except Exception as e:
        logger.debug(f"Não foi possível emitir notificação Toast: {e}")


def is_valid_token(tok: str) -> bool:
    """
    Valida se um token de autenticação possui integridade e entropia mínima segura.
    NUNCA aceita tokens vazios, menores que 16 caracteres, com espaços ou placeholders.
    """
    if not tok or not isinstance(tok, str):
        return False
    clean = tok.strip()
    if len(clean) < 16:
        return False
    if " " in clean:
        return False
    lower = clean.lower()
    for bad in ("informado", "none", "token_aqui", "placeholder", "your_token_here", "copie_o"):
        if bad in lower:
            return False
    return True


def load_config():
    """
    Carrega configurações priorizando argumentos CLI > variáveis de ambiente > agent_config.json > padrões.
    NUNCA possui token hardcoded ou fallback fixo interno.
    """
    cfg = {
        "server_url": "https://monitoramento-gb9g.onrender.com/api/agent/report",
        "agent_token": "",
        "device_token": "",
        "department": "Não informado",
        "display_name": "",
        "interval_seconds": 5,
        "timeout_seconds": 10,
        "activity_monitoring": True,
        "auto_update": True,
        "admin_notifications": False,
        "update_check_interval": 6 * 3600,
        "idle_threshold_seconds": 300
    }

    # 1. Lê arquivo local agent_config.json caso exista
    config_file_path = get_config_file_path()
    if os.path.exists(config_file_path):
        try:
            with open(config_file_path, "r", encoding="utf-8-sig") as f:
                file_cfg = json.load(f)
                if isinstance(file_cfg, dict):
                    cfg.update(file_cfg)
        except Exception as e:
            logger.warning(f"Não foi possível ler {config_file_path}: {e}")

    # 2. Variáveis de ambiente (sobrescrevem agent_config.json)
    if os.getenv("SERVER_URL"):
        cfg["server_url"] = os.getenv("SERVER_URL")
    if os.getenv("AGENT_TOKEN"):
        cfg["agent_token"] = os.getenv("AGENT_TOKEN")
    if os.getenv("DEVICE_TOKEN"):
        cfg["device_token"] = os.getenv("DEVICE_TOKEN")
    if os.getenv("DEPARTMENT"):
        cfg["department"] = os.getenv("DEPARTMENT")
    if os.getenv("DISPLAY_NAME"):
        cfg["display_name"] = os.getenv("DISPLAY_NAME")
    if os.getenv("INTERVAL_SECONDS"):
        try:
            cfg["interval_seconds"] = int(os.getenv("INTERVAL_SECONDS"))
        except ValueError:
            pass
    if os.getenv("TIMEOUT_SECONDS"):
        try:
            cfg["timeout_seconds"] = int(os.getenv("TIMEOUT_SECONDS"))
        except ValueError:
            pass
    if os.getenv("IDLE_THRESHOLD_SECONDS"):
        try:
            cfg["idle_threshold_seconds"] = int(os.getenv("IDLE_THRESHOLD_SECONDS"))
        except ValueError:
            pass
    if os.getenv("ACTIVITY_MONITORING_ENABLED") is not None:
        cfg["activity_monitoring"] = os.getenv("ACTIVITY_MONITORING_ENABLED", "true").lower() in ("true", "1", "yes")
    if os.getenv("AUTO_UPDATE") is not None:
        cfg["auto_update"] = os.getenv("AUTO_UPDATE", "true").lower() in ("true", "1", "yes")
    if os.getenv("ADMIN_NOTIFICATIONS") is not None:
        cfg["admin_notifications"] = os.getenv("ADMIN_NOTIFICATIONS", "false").lower() in ("true", "1", "yes")

    # 3. Argumentos de linha de comando (prioridade máxima)
    parser = argparse.ArgumentParser(description="Agente de Monitoramento de PCs - Givova Transportes")
    parser.add_argument("--server", dest="server_url", help="URL do servidor de monitoramento")
    parser.add_argument("--token", dest="agent_token", help="Token de autenticação do agente")
    parser.add_argument("--device-token", dest="device_token", help="Token individual do dispositivo")
    parser.add_argument("--setor", dest="department", help="Setor/Departamento da máquina (ex: Logística, TI, Financeiro)")
    parser.add_argument("--nome", dest="display_name", help="Nome amigável da máquina")
    parser.add_argument("--intervalo", dest="interval_seconds", type=int, help="Intervalo de envio em segundos")
    parser.add_argument("--timeout", dest="timeout_seconds", type=int, help="Tempo limite para requisições")
    parser.add_argument("--idle-threshold", "--tempo-ocioso", dest="idle_threshold_seconds", type=int, help="Tempo sem interação para considerar o computador ocioso em segundos")
    parser.add_argument("--sem-atividade", dest="disable_activity", action="store_true", help="Desabilita o monitoramento de janela e domínio ativo")
    parser.add_argument("--sem-autoupdate", dest="disable_autoupdate", action="store_true", help="Desabilita verificação automática de updates")
    parser.add_argument("--admin-notif", dest="admin_notif", action="store_true", help="Habilita polling de notificações Windows de TI")

    args, _ = parser.parse_known_args()
    if args.server_url:
        cfg["server_url"] = args.server_url
    if args.agent_token:
        cfg["agent_token"] = args.agent_token
    if args.device_token:
        cfg["device_token"] = args.device_token
    if args.department:
        cfg["department"] = args.department
    if args.display_name:
        cfg["display_name"] = args.display_name
    if args.interval_seconds:
        cfg["interval_seconds"] = max(2, args.interval_seconds)
    if args.idle_threshold_seconds:
        cfg["idle_threshold_seconds"] = max(10, args.idle_threshold_seconds)
    if args.disable_activity:
        cfg["activity_monitoring"] = False
    if args.disable_autoupdate:
        cfg["auto_update"] = False
    if args.admin_notif:
        cfg["admin_notifications"] = True

    # Normalização inteligente da URL do servidor
    raw_url = str(cfg.get("server_url", "")).strip().rstrip("/")
    if raw_url:
        if not (raw_url.endswith("/api/agent/report") or raw_url.endswith("/monitoramento")):
            cfg["server_url"] = f"{raw_url}/api/agent/report"
        else:
            cfg["server_url"] = raw_url

    return cfg




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


def get_system_metrics(activity_enabled: bool = True, idle_threshold_seconds: float = 300.0):
    """
    Coleta dados técnicos de hardware, rede, sistema operacional, atividade em primeiro plano
    e telemetria de uso/ociosidade/bloqueio do Windows.
    Garante privacidade absoluta: zero keylogger, zero captura de cliques ou conteúdo digitado.
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

    # Detecção de Ociosidade e Bloqueio de Sessão do Windows (v1.5.0)
    idle_seconds = get_idle_seconds()
    win_session_id, is_locked = get_windows_session_info()
    session_state, user_active = determine_session_state(idle_seconds, idle_threshold_seconds, is_locked)

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
        "idle_seconds": round(idle_seconds, 1),
        "session_state": session_state,
        "user_active": user_active,
        "windows_session_id": win_session_id,
        "activity_sampled_at": datetime.now(timezone.utc).isoformat(),
        "agent_version": VERSION
    }


def send_metrics(server_url: str, token: str, payload: dict, timeout: int = 5, device_token: str = None):
    """
    Envia métricas para o servidor com headers de autenticação e timeout.
    Suporta autenticação por token compartilhado e token individual de dispositivo.
    Retorna: (success: bool, status_code: int | None, message: str, resp_data: dict | None)
    """
    headers = {
        "Content-Type": "application/json",
        "X-Agent-Token": token or "",
        "X-Device-UUID": payload.get("uuid", ""),
        "User-Agent": f"GivovaMonitorAgent/{VERSION}"
    }
    if device_token:
        headers["X-Device-Token"] = device_token
        payload["device_token"] = device_token

    try:
        response = requests.post(server_url, json=payload, headers=headers, timeout=timeout)
        resp_data = None
        try:
            resp_data = response.json()
        except Exception:
            pass

        if response.status_code == 200:
            return True, 200, "Enviado com sucesso (HTTP 200)", resp_data
        elif response.status_code == 401:
            return False, 401, "Falha de autenticação: Token inválido ou rejeitado pelo servidor", resp_data
        elif response.status_code == 403:
            return False, 403, "Acesso negado pelo servidor", resp_data
        elif response.status_code == 404:
            return False, 404, "Endpoint não encontrado", resp_data
        elif response.status_code >= 500:
            return False, response.status_code, f"Erro interno do servidor ({response.status_code})", resp_data
        else:
            return False, response.status_code, f"Servidor respondeu com código {response.status_code}", resp_data
    except requests.exceptions.Timeout:
        return False, None, "Tempo de resposta esgotado (timeout)", None
    except requests.exceptions.ConnectionError:
        return False, None, "Servidor indisponível ou conexão recusada", None
    except Exception as e:
        return False, None, f"Erro de comunicação: {str(e)}", None



def run_agent():
    # Garante instância única por máquina/sessão
    if not acquire_single_instance_mutex():
        sys.exit(0)

    config = load_config()
    config_path = get_config_file_path()
    raw_token = str(config.get("agent_token") or "").strip()
    has_token = bool(raw_token)
    token_valid = is_valid_token(raw_token)

    logger.info("=" * 65)
    logger.info("   GIVOVA TRANSPORTES - AGENTE DE MONITORAMENTO DE PCS")
    logger.info(f"   Config path: {config_path}")
    logger.info(f"   Server URL: {config['server_url']}")
    logger.info(f"   Agent version: {VERSION}")
    logger.info(f"   Token present: {'true' if has_token else 'false'}")
    logger.info(f"   Token validation: {'VALID' if token_valid else 'INVALID'}")
    logger.info(f"   Setor: {config['department']}")
    logger.info(f"   Intervalo: {config['interval_seconds']}s")
    logger.info(f"   Limite de Ociosidade: {config.get('idle_threshold_seconds', 300)}s")
    logger.info(f"   Monitoramento de Atividade: {'Habilitado' if config['activity_monitoring'] else 'Desabilitado'}")
    logger.info(f"   Auto-Update Remoto: {'Habilitado' if config['auto_update'] else 'Desabilitado'}")
    logger.info(f"   Notificações TI (Admin): {'Habilitado' if config['admin_notifications'] else 'Desabilitado'}")
    logger.info("=" * 65)

    if not has_token or not token_valid:
        logger.error("Agent authentication configuration is invalid.")

    # Inicia o receptor local para a extensão Chromium se o monitoramento de atividade estiver ativo
    if config["activity_monitoring"]:
        start_extension_receiver(LOCAL_RECEIVER_PORT)

    # Inicia workers de background para auto-update e notificações de TI
    start_auto_update_worker(config)
    start_admin_notifications_worker(config)

    # Cria arquivo de configuração inicial local caso não exista para facilitar customização
    if not os.path.exists(config_path):
        try:
            with open(config_path, "w", encoding="utf-8") as f:
                json.dump({
                    "server_url": config["server_url"],
                    "agent_token": config["agent_token"],
                    "device_token": config.get("device_token", ""),
                    "department": config["department"],
                    "display_name": config["display_name"],
                    "interval_seconds": config["interval_seconds"],
                    "timeout_seconds": config["timeout_seconds"],
                    "activity_monitoring": config["activity_monitoring"],
                    "auto_update": config.get("auto_update", True),
                    "admin_notifications": config.get("admin_notifications", False),
                    "idle_threshold_seconds": config.get("idle_threshold_seconds", 300)
                }, f, indent=4)
        except Exception:
            pass

    fail_count = 0
    consecutive_success = 0
    had_previous_failure = False
    first_success_logged = False
    last_reported_activity = None
    last_reported_session_state = None
    loop_cycle = 0

    while True:
        try:
            loop_cycle += 1
            metrics = get_system_metrics(
                activity_enabled=config["activity_monitoring"],
                idle_threshold_seconds=config.get("idle_threshold_seconds", 300)
            )
            metrics["setor"] = config["department"]
            if config["display_name"]:
                metrics["display_name"] = config["display_name"]

            success, status_code, message, resp_data = send_metrics(
                server_url=config["server_url"],
                token=config["agent_token"],
                payload=metrics,
                timeout=config["timeout_seconds"],
                device_token=config.get("device_token")
            )

            current_activity = (metrics.get("active_application"), metrics.get("active_domain"))
            activity_changed = (current_activity != last_reported_activity)

            if success:
                consecutive_success += 1
                emit_health_confirmation()

                # Sincronização dinâmica de configuração de ociosidade com o servidor
                if isinstance(resp_data, dict):
                    server_thresh = resp_data.get("idle_threshold_seconds")
                    if server_thresh and isinstance(server_thresh, (int, float)):
                        if 30 <= server_thresh <= 3600 and server_thresh != config.get("idle_threshold_seconds"):
                            logger.info(f"Limite de ociosidade sincronizado com o servidor: {config.get('idle_threshold_seconds')}s -> {int(server_thresh)}s")
                            config["idle_threshold_seconds"] = int(server_thresh)

                # Log de transição de estado da sessão (Directive 35: sem flood)
                current_session_state = metrics.get("session_state")
                if current_session_state != last_reported_session_state:
                    if last_reported_session_state is not None:
                        logger.info(f"Session state: {last_reported_session_state} -> {current_session_state} (idle: {metrics.get('idle_seconds', 0)}s)")
                    last_reported_session_state = current_session_state

                if had_previous_failure:
                    logger.info("Conexão restabelecida - Report sent successfully - HTTP 200")
                    had_previous_failure = False
                elif not first_success_logged:
                    logger.info("Report sent successfully - HTTP 200")
                    first_success_logged = True

                fail_count = 0

                # Log detalhado apenas na primeira execução, quando houver mudança de atividade, ou a cada ~60s
                if consecutive_success == 1 or activity_changed or (loop_cycle % 12 == 0):
                    activity_log = ""
                    if metrics.get("active_application"):
                        if metrics.get("active_domain"):
                            activity_log = f" | Atividade: {metrics['active_application']} — {metrics['active_domain']}"
                        else:
                            activity_log = f" | Atividade: {metrics['active_application']}"

                    session_log = f" | Sessão: {str(metrics.get('session_state', 'unknown')).upper()} (idle: {metrics.get('idle_seconds', 0)}s)"

                    logger.info(
                        f"OK [{metrics['hostname']}] CPU: {metrics['cpu']}% | "
                        f"RAM: {metrics['ram']}% ({metrics['ram_used_gb']}G/{metrics['ram_total_gb']}G) | "
                        f"Disco: {metrics['disco']}%{activity_log}{session_log} - HTTP 200"
                    )
                    last_reported_activity = current_activity
            else:
                fail_count += 1
                consecutive_success = 0
                had_previous_failure = True
                first_success_logged = False
                if status_code:
                    logger.warning(f"Report failed - HTTP {status_code} ({message})")
                else:
                    logger.warning(f"Report failed - {message}")

        except KeyboardInterrupt:
            logger.info("Agente encerrado pelo operador.")
            break
        except Exception as e:
            logger.error(f"Erro inesperado no ciclo de coleta: {e}", exc_info=True)

        sleep_time = config["interval_seconds"]
        if fail_count > 3:
            # Em caso de instabilidade prolongada (ex: cold start do Render), pausa suavemente para poupar recursos
            sleep_time = min(20, config["interval_seconds"] * min(fail_count - 2, 4))
        time.sleep(sleep_time)


if __name__ == "__main__":
    run_agent()