# network-api-monitoring.py
"""
Win API Monitor (standalone EXE friendly) — balloon notification only (no winrt)
- Requirements at runtime: pydivert, psutil (install in build env)
- Test notification: python ... --test-notify
- Build with PyInstaller --onefile --uac-admin (command below).
"""

import os
import sys
import time
import threading
import json
import socket
import struct
import psutil
import traceback
import ctypes
import ctypes.wintypes
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime
from pathlib import Path

# Flags
TEST_NOTIFY = "--test-notify" in sys.argv
DRY_RUN = "--dry" in sys.argv

# Basic config (tweak as needed)
WIN_DIVERT_FILTER = (
    "outbound and (tcp.DstPort == 80 or tcp.DstPort == 443 or tcp.DstPort == 8080 or "
    "tcp.DstPort == 8443 or tcp.DstPort == 3000 or tcp.DstPort == 5000 or tcp.DstPort == 8000 or tcp.DstPort == 9000)"
)
NOTIFICATION_DURATION = 5  # seconds
POPUP_INTERVAL = 30        # per (pid, host)
CACHE_TTL = 10

# Log files (structured)
LOG_FILE = "alerts.jsonl"         # rotating JSON-lines (primary)
JSONL_PATH = Path("alerts.jsonl")
ECS_JSONL_PATH = Path("alerts_ecs.jsonl")
CEF_PATH = Path("alerts.cef")

# State locks / caches
POPUP_CACHE = {}
POPUP_CACHE_LOCK = threading.Lock()
SINK_LOCK = threading.Lock()

# ---------------- Logging setup ----------------
class JSONFormatter(logging.Formatter):
    def format(self, record):
        ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        obj = {"timestamp": ts, "level": record.levelname, "logger": record.name, "thread": record.threadName, "message": record.getMessage()}
        for attr in ("event", "status", "details"):
            v = getattr(record, attr, None)
            if v is not None:
                try:
                    json.dumps(v)
                    obj[attr] = v
                except Exception:
                    obj[attr] = str(v)
        if record.exc_info:
            obj["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(obj, ensure_ascii=False)

def setup_logger(path=LOG_FILE):
    logger = logging.getLogger("win_api_monitor")
    logger.setLevel(logging.INFO)
    fh = RotatingFileHandler(path, maxBytes=20*1024*1024, backupCount=5, encoding="utf-8")
    fh.setFormatter(JSONFormatter())
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    if not logger.handlers:
        logger.addHandler(fh)
        logger.addHandler(ch)
    logger.propagate = False
    return logger

logger = setup_logger()

def log_struct(event, status, details, level=logging.INFO, msg=None, exc_info=None):
    message = msg or event
    extra = {"event": event, "status": status, "details": details}
    logger.log(level, message, extra=extra, exc_info=exc_info)

# ---------------- Multi-sink writers (JSONL, ECS-like, CEF) ----------------
def now_ts():
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")

def _safe_str(v):
    if v is None:
        return ""
    if isinstance(v, (dict, list)):
        try:
            return json.dumps(v, ensure_ascii=False)
        except Exception:
            return str(v)
    return str(v)

def _build_ecs_record(event, status, details):
    return {
        "@timestamp": now_ts(),
        "event": {"action": event, "severity": "info" if status in ("info","skipped") else ("high" if status=="alert" else "error")},
        "source": {"ip": details.get("local_addr"), "port": details.get("local_port")},
        "destination": {"ip": details.get("remote_addr"), "port": details.get("remote_port"), "domain": details.get("hostname"), "url": details.get("api_endpoint")},
        "process": {"pid": details.get("pid"), "name": details.get("proc_name"), "executable": details.get("exe"), "command_line": details.get("cmdline")},
        "meta": {"popup_shown": details.get("popup_shown", False)}
    }

def _build_cef_line(event, status, details):
    vendor="MyOrg"; product="WinAPIMonitor"; ver="1.0"
    sig_map={"app-not-installed":"1001","rate-limited":"1002","processing-error":"2001","monitor-failure":"2002"}
    sig = sig_map.get(event, "9999")
    name = event
    severity = "10" if status == "alert" else ("5" if status == "skipped" else "3")
    ext_items = {
        "src":_safe_str(details.get("local_addr")),
        "spt":_safe_str(details.get("local_port")),
        "dst":_safe_str(details.get("remote_addr")),
        "dpt":_safe_str(details.get("remote_port")),
        "dhost":_safe_str(details.get("hostname")),
        "request":_safe_str(details.get("api_endpoint")),
        "proc":_safe_str(details.get("proc_name")),
        "pid":_safe_str(details.get("pid"))
    }
    def esc(v): return str(v).replace("\\","\\\\").replace("\n"," ").replace("\r"," ").replace("=","\\=")
    ext = " ".join(f"{k}={esc(v)}" for k,v in ext_items.items() if v != "")
    return f"CEF:0|{vendor}|{product}|{ver}|{sig}|{name}|{severity}|{ext}"

def emit_all_sinks(event, status, details):
    base = {"timestamp": now_ts(), "event": event, "status": status, "details": details}
    ecs = _build_ecs_record(event, status, details)
    cef = _build_cef_line(event, status, details)
    with SINK_LOCK:
        try:
            JSONL_PATH.open("a", encoding="utf-8").write(json.dumps(base, ensure_ascii=False) + "\n")
            ECS_JSONL_PATH.open("a", encoding="utf-8").write(json.dumps(ecs, ensure_ascii=False) + "\n")
            CEF_PATH.open("a", encoding="utf-8").write(cef + "\n")
        except Exception:
            logger.exception("Failed writing multi-sink logs")

# ---------------- Notification: balloon using Shell_NotifyIcon (works from EXE) ----------------
def _show_balloon(title: str, msg: str, duration: int = NOTIFICATION_DURATION):
    """
    Show a tray balloon using Shell_NotifyIconW.
    Runs a minimal message loop so the balloon displays properly and the icon is cleaned up.
    Returns True on best-effort success.
    """
    try:
        user32 = ctypes.windll.user32
        shell32 = ctypes.windll.shell32
        kernel32 = ctypes.windll.kernel32

        WM_DESTROY = 0x0002
        WM_USER = 0x0400

        NIF_MESSAGE = 0x00000001
        NIF_ICON    = 0x00000002
        NIF_TIP     = 0x00000004
        NIF_INFO    = 0x00000010

        NIM_ADD     = 0x00000000
        NIM_MODIFY  = 0x00000001
        NIM_DELETE  = 0x00000002

        NIIF_NONE   = 0x00000000
        NIIF_INFO   = 0x00000001
        NIIF_WARNING= 0x00000002
        NIIF_ERROR  = 0x00000003

        class WNDCLASSEXW(ctypes.Structure):
            _fields_ = [
                ("cbSize", ctypes.c_uint),
                ("style", ctypes.c_uint),
                ("lpfnWndProc", ctypes.c_void_p),
                ("cbClsExtra", ctypes.c_int),
                ("cbWndExtra", ctypes.c_int),
                ("hInstance", ctypes.c_void_p),
                ("hIcon", ctypes.c_void_p),
                ("hCursor", ctypes.c_void_p),
                ("hbrBackground", ctypes.c_void_p),
                ("lpszMenuName", ctypes.c_wchar_p),
                ("lpszClassName", ctypes.c_wchar_p),
                ("hIconSm", ctypes.c_void_p)
            ]

        class NOTIFYICONDATAW(ctypes.Structure):
            _fields_ = [
                ("cbSize", ctypes.c_ulong),
                ("hWnd", ctypes.c_void_p),
                ("uID", ctypes.c_uint),
                ("uFlags", ctypes.c_uint),
                ("uCallbackMessage", ctypes.c_uint),
                ("hIcon", ctypes.c_void_p),
                ("szTip", ctypes.c_wchar * 128),
                ("dwState", ctypes.c_uint),
                ("dwStateMask", ctypes.c_uint),
                ("szInfo", ctypes.c_wchar * 256),
                ("uTimeoutOrVersion", ctypes.c_uint),
                ("szInfoTitle", ctypes.c_wchar * 64),
                ("dwInfoFlags", ctypes.c_uint),
                ("guidItem", ctypes.c_byte * 16),
                ("hBalloonIcon", ctypes.c_void_p)
            ]

        WNDPROCTYPE = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p, ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p)
        def _wndproc(hWnd, uMsg, wParam, lParam):
            if uMsg == WM_DESTROY:
                user32.PostQuitMessage(0)
            return user32.DefWindowProcW(hWnd, uMsg, wParam, lParam)

        hInstance = kernel32.GetModuleHandleW(None)
        className = f"WinApiMonNotify_{int(time.time()*1000)}"

        wndclass = WNDCLASSEXW()
        wndclass.cbSize = ctypes.sizeof(WNDCLASSEXW)
        wndclass.style = 0

        # Create function pointer and cast to c_void_p before assigning
        fp = WNDPROCTYPE(_wndproc)
        wndclass.lpfnWndProc = ctypes.cast(fp, ctypes.c_void_p)

        wndclass.cbClsExtra = wndclass.cbWndExtra = 0
        wndclass.hInstance = hInstance
        wndclass.hIcon = wndclass.hIconSm = user32.LoadIconW(0, ctypes.c_wchar_p(32512))  # IDI_APPLICATION
        wndclass.hCursor = 0
        wndclass.hbrBackground = 0
        wndclass.lpszMenuName = None
        wndclass.lpszClassName = className

        try:
            user32.RegisterClassExW(ctypes.byref(wndclass))
        except Exception:
            pass

        # Create message-only window
        hWnd = user32.CreateWindowExW(0, className, "WinApiMonNotify", 0, 0, 0, 0, 0, 0, 0, hInstance, None)
        if not hWnd:
            logger.debug("CreateWindowExW failed; cannot show balloon")
            return False

        nid = NOTIFYICONDATAW()
        nid.cbSize = ctypes.sizeof(NOTIFYICONDATAW)
        nid.hWnd = hWnd
        nid.uID = 1
        nid.uFlags = NIF_MESSAGE | NIF_TIP | NIF_INFO
        nid.uCallbackMessage = WM_USER + 1
        nid.hIcon = wndclass.hIconSm
        nid.szTip = (className + " ")[:127]
        nid.szInfo = str(msg)[:255]
        nid.uTimeoutOrVersion = int(duration * 1000)
        nid.szInfoTitle = str(title)[:63]
        nid.dwInfoFlags = NIIF_INFO

        shell32.Shell_NotifyIconW(NIM_ADD, ctypes.byref(nid))
        shell32.Shell_NotifyIconW(NIM_MODIFY, ctypes.byref(nid))

        # Minimal message loop to keep the balloon visible and responsive
        start = time.time()
        msg = ctypes.wintypes.MSG()
        while time.time() - start < max(1, duration):
            if user32.PeekMessageW(ctypes.byref(msg), hWnd, 0, 0, 1):
                user32.TranslateMessage(ctypes.byref(msg))
                user32.DispatchMessageW(ctypes.byref(msg))
            time.sleep(0.05)

        # remove and cleanup
        try:
            shell32.Shell_NotifyIconW(NIM_DELETE, ctypes.byref(nid))
        except Exception:
            pass
        try:
            user32.DestroyWindow(hWnd)
            user32.UnregisterClassW(className, hInstance)
        except Exception:
            pass
        return True
    except Exception:
        logger.exception("Balloon notification failed")
        return False

def show_notification(title, message, duration=NOTIFICATION_DURATION):
    try:
        threading.Thread(target=_show_balloon, args=(title, message, duration), daemon=True).start()
        return True
    except Exception:
        logger.exception("Failed to spawn notification thread")
        return False

# ---------------- Utility parsers, resolver, registry check (unchanged) ----------------
def normalize_hostname(host):
    if not host: return None
    h = host.strip().lower()
    if ":" in h and not h.startswith("["):
        if h.count(":") == 1 and h.split(":")[1].isdigit():
            h = h.split(":")[0]
    if h.startswith("[") and "]" in h:
        h = h.split("]")[0].lstrip("[")
    return h or None

def parse_http_request(payload_bytes):
    try:
        text = payload_bytes.decode('latin1', errors='ignore')
    except Exception:
        return None, None, None
    lines = text.split("\r\n")
    if not lines: return None, None, None
    first = lines[0].strip(); parts = first.split()
    if len(parts) < 2: return None, None, None
    method = parts[0].upper(); path = parts[1]
    if method not in {"GET","POST","PUT","DELETE","HEAD","OPTIONS","PATCH","CONNECT","TRACE"}:
        return None, None, None
    host = None
    for l in lines[1:12]:
        if not l: continue
        if l.lower().startswith("host:"):
            host = l.split(":",1)[1].strip(); break
    if method == "CONNECT" and path:
        host = path.split(":")[0]
    return method, path, normalize_hostname(host)

def parse_tls_sni(payload_bytes):
    try:
        b = payload_bytes
        if len(b) < 5 or b[0] != 22: return None
        rec_len = struct.unpack('!H', b[3:5])[0]
        if len(b) < 5 + rec_len: return None
        handshake = b[5:5+rec_len]
        if len(handshake) < 4 or handshake[0] != 1: return None
        ptr = 1 + 3 + 2 + 32
        if len(handshake) < ptr: return None
        session_id_len = handshake[ptr]; ptr += 1 + session_id_len
        if ptr + 2 > len(handshake): return None
        cs_len = struct.unpack('!H', handshake[ptr:ptr+2])[0]; ptr += 2 + cs_len
        if ptr + 1 > len(handshake): return None
        comp_len = handshake[ptr]; ptr += 1 + comp_len
        if ptr + 2 > len(handshake): return None
        ext_len = struct.unpack('!H', handshake[ptr:ptr+2])[0]; ptr += 2
        end_ext = ptr + ext_len
        if end_ext > len(handshake): end_ext = len(handshake)
        while ptr + 4 <= end_ext:
            etype = struct.unpack('!H', handshake[ptr:ptr+2])[0]; elen = struct.unpack('!H', handshake[ptr+2:ptr+4])[0]; ptr += 4
            if ptr + elen > end_ext: break
            if etype == 0x00:
                if elen < 2: break
                list_len = struct.unpack('!H', handshake[ptr:ptr+2])[0]; p2 = ptr + 2; end_list = p2 + list_len
                while p2 + 3 <= end_list:
                    name_type = handshake[p2]; name_len = struct.unpack('!H', handshake[p2+1:p2+3])[0]; p2 += 3
                    if p2 + name_len > end_list: break
                    if name_type == 0:
                        return normalize_hostname(handshake[p2:p2+name_len].decode('latin1', errors='ignore'))
                    p2 += name_len
            ptr += elen
    except Exception:
        return None
    return None

class ConnPidResolver:
    def __init__(self, ttl=CACHE_TTL):
        self.cache = {}; self.ttl = ttl; self.lock = threading.Lock()
    def _key(self, l_ip, l_port, r_ip, r_port):
        return (str(l_ip), int(l_port), str(r_ip), int(r_port))
    def resolve(self, l_ip, l_port, r_ip, r_port):
        key = self._key(l_ip, l_port, r_ip, r_port); now = time.time()
        with self.lock:
            if key in self.cache:
                pid, ts = self.cache[key]
                if now - ts < self.ttl: return pid
        try:
            conns = psutil.net_connections(kind="inet")
        except Exception:
            conns = []
        found = -1
        for c in conns:
            try:
                if not c.laddr or not c.raddr: continue
                try:
                    lip, lport = (c.laddr.ip, c.laddr.port); rip, rport = (c.raddr.ip, c.raddr.port)
                except Exception:
                    try:
                        lip, lport = (c.laddr[0], c.laddr[1]); rip, rport = (c.raddr[0], c.raddr[1])
                    except Exception: continue
            except Exception: continue
            try:
                if (str(lip), int(lport), str(rip), int(rport)) == key:
                    found = c.pid or -1; break
            except Exception:
                continue
        with self.lock:
            self.cache[key] = (found, now)
        return found

def is_program_registered_in_uninstall(exe_name_or_str):
    try:
        import winreg
    except Exception:
        return False
    keys = [r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"]
    hives = [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]
    target = (exe_name_or_str or "").lower()
    if not target: return False
    for hive in hives:
        for key in keys:
            try: reg = winreg.OpenKey(hive, key)
            except FileNotFoundError: continue
            i = 0
            while True:
                try:
                    sub = winreg.EnumKey(reg, i); i += 1
                    try:
                        subk = winreg.OpenKey(reg, sub)
                    except Exception:
                        continue
                    try:
                        display, _ = winreg.QueryValueEx(subk, "DisplayName")
                        if display and target in str(display).lower(): return True
                    except Exception:
                        pass
                except OSError:
                    break
    return False

def should_rate_limit(pid, hostname):
    if not hostname: hostname = "<unknown>"
    key = (int(pid or -1), hostname); now = time.time()
    with POPUP_CACHE_LOCK:
        last = POPUP_CACHE.get(key, 0)
        if now - last < POPUP_INTERVAL:
            return True
        POPUP_CACHE[key] = now
    return False

def init_paths():
    for p in (JSONL_PATH, ECS_JSONL_PATH, CEF_PATH, Path(LOG_FILE)):
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            p.touch(exist_ok=True)
        except Exception:
            pass

# ---------------- Main monitor loop ----------------
def run_monitor():
    logger.info("Starting monitor", extra={"event":"monitor-start","status":"info","details":{"filter": WIN_DIVERT_FILTER}})
    init_paths()
    resolver = ConnPidResolver()
    # Try to import pydivert when entering capture loop
    try:
        import pydivert
    except Exception:
        logger.error("pydivert not installed or failed to import. Install pydivert and run as admin.")
        return
    try:
        with pydivert.WinDivert(WIN_DIVERT_FILTER) as w:
            for pkt in w:
                try:
                    if not pkt.tcp or not pkt.payload:
                        w.send(pkt); continue
                    payload = bytes(pkt.payload)
                    l_ip, l_port = pkt.src_addr, pkt.src_port
                    r_ip, r_port = pkt.dst_addr, pkt.dst_port
                    hostname = None; http_method = None; http_path = None
                    if r_port in (80,8080,8000,3000,5000,9000):
                        http_method, http_path, hostname = parse_http_request(payload)
                    elif r_port in (443,8443):
                        hostname = parse_tls_sni(payload)
                    if not hostname:
                        try:
                            if r_ip and not r_ip.startswith("127.") and r_ip != "0.0.0.0":
                                hostname = socket.gethostbyaddr(r_ip)[0]; hostname = normalize_hostname(hostname)
                        except Exception:
                            hostname = None
                    pid = resolver.resolve(l_ip, l_port, r_ip, r_port)
                    proc_info = {"pid": pid, "name": None, "exe": None, "cmdline": None, "username": None}
                    if pid and pid > 0:
                        try:
                            p = psutil.Process(pid)
                            proc_info.update({"name": p.name(), "exe": p.exe(), "cmdline": " ".join(p.cmdline()) if p.cmdline() else "", "username": p.username()})
                        except Exception:
                            pass
                    exe_name = os.path.basename(proc_info.get("exe") or proc_info.get("name") or "").lower()
                    installed = False
                    if exe_name:
                        try: installed = is_program_registered_in_uninstall(exe_name)
                        except Exception: installed = False
                    api_endpoint = None
                    if hostname and http_path:
                        api_endpoint = f"https://{hostname}{http_path}" if r_port in (443,8443) else f"http://{hostname}{http_path}"
                    elif hostname:
                        api_endpoint = hostname
                    else:
                        api_endpoint = r_ip
                    calling_app = proc_info.get("name") or exe_name or "Unknown Process"
                    normalized_host = hostname or r_ip or "<unknown>"
                    if not installed:
                        rate_limited = should_rate_limit(pid, normalized_host)
                        details = {"pid": pid, "proc_name": calling_app, "exe": proc_info.get("exe"), "cmdline": proc_info.get("cmdline"), "username": proc_info.get("username"), "local_addr": l_ip, "local_port": l_port, "remote_addr": r_ip, "remote_port": r_port, "hostname": hostname, "http_method": http_method, "http_path": http_path, "api_endpoint": api_endpoint, "popup_shown": False}
                        if rate_limited:
                            emit_all_sinks("app-not-installed","skipped",details)
                            logger.info("Rate-limited alert", extra={"event":"app-not-installed","status":"skipped","details":details})
                            w.send(pkt); continue
                        short_endpoint = api_endpoint if len(str(api_endpoint)) <= 120 else (str(api_endpoint)[:117] + "...")
                        notification_title = "⚠️ Suspicious Network Activity"
                        notification_text = f"{calling_app} is reaching {short_endpoint}"
                        popup_shown = False
                        try:
                            popup_shown = show_notification(notification_title, notification_text, duration=NOTIFICATION_DURATION)
                        except Exception:
                            popup_shown = False
                        details["popup_shown"] = bool(popup_shown)
                        emit_all_sinks("app-not-installed","alert",details)
                        logger.info("App not installed; connection observed", extra={"event":"app-not-installed","status":"alert","details":details})
                    w.send(pkt)
                except Exception:
                    try: w.send(pkt)
                    except Exception: pass
                    tb = traceback.format_exc()
                    emit_all_sinks("processing-error","error",{"error":tb})
                    logger.error("Error processing packet", extra={"event":"processing-error","status":"error","details":{"error":tb}})
    except KeyboardInterrupt:
        logger.info("Stopped by user", extra={"event":"monitor-stop","status":"info","details":{}})
    except Exception:
        tb = traceback.format_exc()
        emit_all_sinks("monitor-failure","error",{"error":tb})
        logger.exception("Monitor failure")

# ---------------- Entrypoint ----------------
if __name__ == "__main__":
    if os.name != "nt":
        print("This tool runs only on Windows.")
        sys.exit(1)
    try:
        is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        is_admin = False
    if not is_admin:
        print("Please run this script as Administrator.")
        sys.exit(1)

    init_paths = lambda: [p.parent.mkdir(parents=True, exist_ok=True) or p.touch(exist_ok=True) for p in (JSONL_PATH, ECS_JSONL_PATH, CEF_PATH, Path(LOG_FILE))]
    init_paths()

    if TEST_NOTIFY:
        print("Testing balloon notification (5s)...")
        ok = show_notification("Test Notification", "Balloon notification (no winrt) - 5s", duration=5)
        print("Notification spawned:", ok)
        time.sleep(6)
        sys.exit(0)

    logger.info("Initializing balloon-only monitor", extra={"event":"init","status":"info","details":{}})
    run_monitor()
