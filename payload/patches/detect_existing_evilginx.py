#!/usr/bin/env python3
"""Find an already-installed Evilginx binary, dir, phishlets, config, extra argv.

Prints one JSON object to stdout. Used by Install Only CP. Read-only.
"""
from __future__ import annotations

import json
import os
import re
import subprocess


SKIP_SUB = (
    "evilginx-panel",
    "/venv/",
    "apply_egx",
    "detect_existing",
)


def _run(cmd, timeout=8):
    try:
        p = subprocess.run(
            cmd, shell=True, capture_output=True, timeout=timeout,
            text=True, errors="replace",
        )
        return (p.stdout or "") + (p.stderr or "")
    except Exception:
        return ""


def _is_bin(path: str) -> bool:
    if not path or not os.path.isfile(path):
        return False
    if not os.access(path, os.X_OK):
        return False
    low = path.replace("\\", "/").lower()
    if any(s in low for s in SKIP_SUB):
        return False
    try:
        with open(path, "rb") as f:
            magic = f.read(4)
        if magic != b"\x7fELF":
            return False
    except Exception:
        return False
    return True


def _looks_like_evilginx(path: str) -> bool:
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as f:
            blob = f.read(min(size, 8 * 1024 * 1024))
    except Exception:
        return False
    return b"phishlet" in blob or b"evilginx" in blob.lower() or b"Phishlet" in blob


def _dir_for_bin(bin_path: str) -> str:
    d = os.path.dirname(os.path.abspath(bin_path))
    base = os.path.basename(d)
    if base in ("build", "bin") and os.path.isdir(os.path.join(os.path.dirname(d), "phishlets")):
        return os.path.dirname(d)
    if os.path.isdir(os.path.join(d, "phishlets")):
        return d
    parent = os.path.dirname(d)
    if os.path.isdir(os.path.join(parent, "phishlets")):
        return parent
    return d


def _split_argv(line: str) -> list:
    line = (line or "").strip()
    if not line:
        return []
    out, buf, q = [], [], None
    for ch in line:
        if q:
            if ch == q:
                q = None
            else:
                buf.append(ch)
            continue
        if ch in ("'", '"'):
            q = ch
            continue
        if ch.isspace():
            if buf:
                out.append("".join(buf))
                buf = []
            continue
        buf.append(ch)
    if buf:
        out.append("".join(buf))
    return out


def _phish_from_argv(argv: list) -> str:
    for i, a in enumerate(argv):
        if a in ("-p", "--phishlets") and i + 1 < len(argv):
            return argv[i + 1]
    return ""


def _extra_args(argv: list, bin_path: str) -> list:
    extra = []
    skip_next = False
    bin_base = os.path.basename(bin_path)
    for i, a in enumerate(argv):
        if skip_next:
            skip_next = False
            continue
        if i == 0 and (
            a == bin_path
            or os.path.basename(a) == bin_base
            or a.endswith("evilginx")
            or a.endswith("evilginx2")
        ):
            continue
        if a in ("-p", "--phishlets"):
            skip_next = True
            continue
        extra.append(a)
    return extra


def _systemd_unit_names() -> list:
    names = []
    text = _run("systemctl list-unit-files --type=service --no-legend 2>/dev/null")
    text += "\n" + _run("ls /etc/systemd/system/evilginx*.service /lib/systemd/system/evilginx*.service 2>/dev/null")
    for line in text.splitlines():
        tok = line.split()[0] if line.split() else ""
        tok = os.path.basename(tok).strip()
        if re.match(r"^evilginx.*\.service$", tok, re.I):
            low = tok.lower()
            if "panel" in low or "feed" in low:
                continue
            if tok not in names:
                names.append(tok)
    for n in ("evilginx.service", "evilginx2.service", "evilginx-phish.service"):
        if n not in names:
            names.append(n)
    return names


def _exec_start(unit: str) -> list:
    text = _run(f"systemctl show {unit} -p ExecStart -p FragmentPath 2>/dev/null")
    m = re.search(r"argv\[\]=([^;]+)", text)
    if m:
        return _split_argv(m.group(1).strip())
    m = re.search(r"path=([^ ;\n]+)", text)
    if m and "evilginx" in m.group(1).lower():
        return [m.group(1).strip()]
    return []


def main() -> int:
    running_bins = []
    systemd_bins = []
    proc_argv = []
    unit_argv = []
    unit_names = []

    ps = _run("ps -eo args= 2>/dev/null")
    for line in ps.splitlines():
        if "evilginx" not in line.lower():
            continue
        if "evilginx-panel" in line or "apply_egx" in line or "detect_existing" in line:
            continue
        argv = _split_argv(line)
        if not argv:
            continue
        running_bins.append(argv[0])
        if not proc_argv:
            proc_argv = argv

    for unit in _systemd_unit_names():
        argv = _exec_start(unit)
        if argv:
            unit_names.append(unit)
            systemd_bins.append(argv[0])
            if not unit_argv:
                unit_argv = argv
        elif _run(f"systemctl status {unit} 2>/dev/null | head -5"):
            # unit file exists even if ExecStart parse failed
            if "Loaded:" in _run(f"systemctl show {unit} -p LoadState"):
                st = _run(f"systemctl show {unit} -p LoadState --value").strip()
                if st == "loaded" and unit not in unit_names:
                    unit_names.append(unit)

    cands = []
    cands.extend(running_bins)
    cands.extend(systemd_bins)
    cands.extend([
        "/root/evilginx2/evilginx2",
        "/root/evilginx2/build/evilginx",
        "/root/evilginx2/evilginx",
        "/root/evilginx/build/evilginx",
        "/opt/evilginx2/build/evilginx",
        "/opt/evilginx2/evilginx2",
        "/usr/local/bin/evilginx",
        "/usr/local/bin/evilginx2",
        "/usr/bin/evilginx",
    ])
    which = _run("command -v evilginx; command -v evilginx2").splitlines()
    cands.extend(x.strip() for x in which if x.strip())
    found = _run(
        "find /root /opt /usr/local /usr/bin -maxdepth 6 -type f "
        "\\( -name evilginx -o -name evilginx2 \\) 2>/dev/null"
    )
    cands.extend(x.strip() for x in found.splitlines() if x.strip())

    valid = []
    seen = set()
    for p in cands:
        if not p:
            continue
        p = os.path.abspath(p)
        if p in seen:
            continue
        seen.add(p)
        if _is_bin(p) and _looks_like_evilginx(p):
            valid.append(p)

    if not valid:
        print(json.dumps({"ok": False, "error": "evilginx binary not found"}))
        return 1

    running_abs = {os.path.abspath(x) for x in running_bins if x}
    systemd_abs = {os.path.abspath(x) for x in systemd_bins if x}

    def score(path: str) -> tuple:
        s = 0
        if path in running_abs:
            s += 100
        if path in systemd_abs:
            s += 80
        base = os.path.basename(path)
        if base == "evilginx2":
            s += 25
        if path.endswith("/build/evilginx"):
            s += 5
        try:
            s += min(int(os.path.getsize(path) / (1024 * 1024)), 15)
        except Exception:
            pass
        return (s, path)

    bin_path = max(valid, key=score)

    d = _dir_for_bin(bin_path)
    argv = proc_argv or unit_argv or [bin_path, "-p", "phishlets/"]
    phish_arg = _phish_from_argv(argv)
    if phish_arg:
        phish = phish_arg if os.path.isabs(phish_arg) else os.path.join(d, phish_arg)
        phish = os.path.abspath(phish.rstrip("/"))
        if os.path.basename(phish) != "phishlets" and os.path.isdir(os.path.join(phish, "phishlets")):
            phish = os.path.join(phish, "phishlets")
    else:
        phish = os.path.join(d, "phishlets")
        if not os.path.isdir(phish):
            alt = os.path.join(os.path.dirname(bin_path), "phishlets")
            if os.path.isdir(alt):
                phish = alt
                d = os.path.dirname(phish)

    cfg = "/root/.evilginx/config.json"
    if not os.path.isfile(cfg):
        home = os.environ.get("HOME") or "/root"
        cfg2 = os.path.join(home, ".evilginx", "config.json")
        if os.path.isfile(cfg2):
            cfg = cfg2

    data = os.path.join(os.path.dirname(cfg), "data.db")
    extra = _extra_args(argv, bin_path)

    src_go = os.path.join(d, "core", "http_proxy.go")
    help_txt = _run(f"{bin_path} -h 2>&1 | head -60")
    ver_txt = _run(f"{bin_path} -v 2>&1 | head -8")
    if not ver_txt.strip():
        ver_txt = _run(f"{bin_path} version 2>&1 | head -8")

    out = {
        "ok": True,
        "bin": bin_path,
        "dir": d,
        "phishlets": phish if os.path.isdir(phish) else os.path.join(d, "phishlets"),
        "config": cfg,
        "data": data if os.path.isfile(data) else os.path.join(os.path.dirname(cfg), "data.db"),
        "args": extra,
        "units": unit_names,
        "has_source": os.path.isfile(src_go),
        "src_go": src_go if os.path.isfile(src_go) else "",
        "has_dashboard_flag": "-dashboard" in help_txt,
        "version": (ver_txt.strip().splitlines()[-1] if ver_txt.strip() else "")[:160],
        "candidates": valid[:8],
    }
    print(json.dumps(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
