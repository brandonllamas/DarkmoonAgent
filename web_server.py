"""
HackerAgent Web Server — web_server.py
Provides a full-featured web UI for HackerAgent with:
  - Multi-project management
  - Multi-chat sessions per project
  - Real-time Ollama streaming via SSE
  - Skill toggles per session
  - Vulnerability dashboard (findings from project_state.json)
  - File upload & reference
  - Command history log viewer

Usage:
  python agent.py --web              # starts at http://127.0.0.1:7860
  python agent.py --web --port 8080  # custom port
"""
from __future__ import annotations

import json
import database
import os
import queue
import re
import subprocess
import sys
import threading
import time
import uuid
import mimetypes
from datetime import datetime
from pathlib import Path

_ACTIVE_SESSIONS = {}

# ── Persistent tool-event log ─────────────────────────────────────────────────
# Events that should be persisted so they can be replayed when reloading a session
_PERSIST_EVENT_TYPES = {
    "thinking", "message",
    "command_start", "command_done",
    "skill_start", "skill_done",
    "fetch_start", "fetch_done",
    "file_ready", "new_findings",
    "nuclei_findings", "vuln_indicators",
    "error",
}

def _events_log_path(session_name: str, project_dir: Path) -> Path:
    return project_dir / f"{session_name}.events.jsonl"

def _load_events_log(session_name: str, project_dir: Path) -> list:
    return database.get_events(session_name)

def _append_event_log(session_name: str, project_dir: Path, event: dict):
    if event.get("type") not in _PERSIST_EVENT_TYPES and event.get("type") != "user_turn":
        return
    database.append_event(session_name, event)


class EventStreamer:
    def __init__(self, session_name: str | None = None, project_dir: Path | None = None):
        self.history = []
        self.cond = threading.Condition()
        self.is_done = False
        self.session_name = session_name
        self.project_dir = project_dir

    def put(self, event):
        with self.cond:
            self.history.append(event)
            if event.get("type") == "done" or event.get("type") == "error":
                self.is_done = True
            self.cond.notify_all()
        # Persist tool events to disk for session history replay
        if self.session_name and self.project_dir:
            _append_event_log(self.session_name, self.project_dir, event)

    def get_iterator(self, thread):
        idx = 0
        idle_ticks = 0
        while True:
            event = None
            with self.cond:
                if idx < len(self.history):
                    event = self.history[idx]
                    idx += 1
                elif self.is_done:
                    break
                else:
                    self.cond.wait(timeout=30)

            if event:
                idle_ticks = 0
                yield event
                if event.get("type") == "done" or event.get("type") == "error":
                    break
            else:
                if not thread.is_alive():
                    idle_ticks += 1
                    if idle_ticks >= 2:
                        yield {"type": "error", "content": "El proceso terminó sin respuesta"}
                        break
                yield None


# ── Auto-install Flask ─────────────────────────────────────────────────────────
def _ensure_flask():
    try:
        import flask
        return True
    except ImportError:
        print("[web] Flask no encontrado — instalando...")
        try:
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", "flask", "-q",
                 "--disable-pip-version-check"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            print("[web] Flask instalado correctamente.")
            return True
        except Exception as e:
            print(f"[web] ERROR: No se pudo instalar Flask: {e}")
            print("[web] Ejecuta manualmente: pip install flask")
            sys.exit(1)


_ensure_flask()

from flask import Flask, Response, abort, jsonify, request, send_file

# ── Import agent.py utilities ─────────────────────────────────────────────────
_HERE = Path(__file__).parent
sys.path.insert(0, str(_HERE))

from agent import (
    OLLAMA_URL, LMSTUDIO_URL, OUT_DIR, BASE_DIR,
    LLM_BACKEND,
    call_llm, call_ollama,
    check_backend, check_ollama, check_lmstudio,
    _backend_display_name, _backend_url,
    parse_skill_call,
    load_skills, skill_names,
    _skills_by_category, CATEGORY_LABELS, CATEGORY_ORDER,
    SYSTEM_PROMPT,
    _skills_context,
    save_session, load_session_in_project, list_project_sessions,
    generate_session_name,
    ProjectState, LogWriter, ScanCache,
    score_model, 
    get_api_key,
    summarize_if_needed, CircuitBreaker,
    inject_nuclei_json, parse_nuclei_json, format_nuclei_findings,
    nuclei_fix_template_paths, _map_raw_to_skill,
    verify_http_response, fetch_url as _agent_fetch_url,
    load_tool_confs, build_tools_context,
    _NUCLEI_TEMPLATES_PATH,
    run_command as _agent_run_command,
    is_parallel_safe,
    run_skill as _run_skill,
    get_model, get_model_auto, get_model_lmstudio,
    _SUBDOMAIN_TRIGGER, _PENTEST_TRIGGER,
)

app = Flask(__name__)
load_skills()

# ══════════════════════════════════════════════════════════════════════════════
# Helpers
# ══════════════════════════════════════════════════════════════════════════════

def _sanitize(name: str) -> str:
    return re.sub(r"[^\w\-]", "_", name.lower().replace(" ", "_"))[:40] or "project"


def _read_project_meta(project_dir: Path) -> dict:
    p = database.get_project(project_dir.name)
    if p:
        p["findings"] = database.get_findings(project_dir.name)
        p["sev_summary"] = database.get_severity_summary(project_dir.name)
        return p
    return {}


def _list_projects() -> list[dict]:
    projects = []
    for p in database.get_all_projects():
        pid = p["id"]
        sessions = list_project_sessions(OUT_DIR / pid)
        projects.append({
            "id":           pid,
            "name":         p["name"],
            "target":       p["target"],
            "path":         str(OUT_DIR / pid),
            "sessions":     sessions,
            "findings":     database.get_findings(pid),
            "sev_summary":  database.get_severity_summary(pid),
            "updated_at":   p["updated_at"],
            "project_type": p["project_type"],
        })
    return projects


def _get_or_create_model() -> tuple[str, list[str]]:
    """Get a model safely, never crashing or returning 'unknown'."""
    # Try the normal path first
    try:
        model, models = get_model_auto()
        if model and model != "unknown":
            return model, models
    except (SystemExit, Exception):
        pass

    # Fallback: query Ollama directly
    try:
        ok, models = check_ollama()
        if ok and models:
            # Pick best model by score
            scored = sorted(models, key=lambda m: score_model(m)[0], reverse=True)
            return scored[0], models
    except Exception:
        pass

    # Fallback: try LM Studio
    try:
        ok, models = check_lmstudio()
        if ok and models:
            return models[0], models
    except Exception:
        pass

    print("[web] ⚠ No se pudo obtener ningún modelo del backend")
    return "unknown", []


# ══════════════════════════════════════════════════════════════════════════════
# Chat streaming engine
# ══════════════════════════════════════════════════════════════════════════════

def _process_chat_turn(
    project_dir: Path,
    session_name: str,
    user_message: str,
    model: str,
    enabled_skills: list[str] | None = None,
    event_queue: queue.Queue | None = None,
    uploaded_file_content: str = "",
):
    """
    Run one chat turn: send user_message to Ollama, execute any returned
    commands/skills, and save the session.
    Emits dicts to event_queue for SSE streaming.
    """
    eq = event_queue  # It's an EventStreamer now

    def emit(data: dict):
        eq.put(data)

    try:
        # Load or create conversation
        conversation, saved_model, _ = load_session_in_project(session_name, project_dir)
        if conversation is None:
            # New session: build system prompt
            tools_ctx  = build_tools_context(load_tool_confs())
            skills_ctx = _skills_context(enabled_skills)
            conversation = [{
                "role":    "system",
                "content": SYSTEM_PROMPT + tools_ctx + skills_ctx,
            }]
            saved_model = model

        # Ensure session exists in database (for FOREIGN KEY constraints on events)
        database.create_session(session_name, project_dir.name, saved_model or model)

        actual_model = saved_model or model
        # If model is unknown, try to get a real one
        if actual_model == "unknown" or not actual_model:
            try:
                ok, models = check_ollama()
                if ok and models:
                    actual_model = models[0]
                else:
                    ok2, models2 = check_lmstudio()
                    if ok2 and models2:
                        actual_model = models2[0]
            except Exception:
                pass
            if actual_model == "unknown" or not actual_model:
                emit({"type": "error", "content": "No hay modelos disponibles. Verifica Ollama/LM Studio."})
                emit({"type": "done", "session": session_name})
                return

        # Compose user content (include uploaded file if present)
        available_keys = {k: bool(get_api_key(k)) for k in [
            "WPSCAN_API_KEY", "SHODAN_API_KEY", "VIRUSTOTAL_API_KEY", "WHITEINTEL_API_KEY",
        ]}
        user_content = f"[API Keys: {json.dumps(available_keys)}]\n{user_message}"
        if uploaded_file_content:
            user_content += f"\n\n[ARCHIVO ADJUNTO]\n{uploaded_file_content[:12000]}"

        conversation.append({"role": "user", "content": user_content})

        # Project state & log
        log   = LogWriter(session_name, project_dir)
        cache = ScanCache(project_dir)
        ps    = ProjectState(project_dir)

        # ── Shortcut: "dame las ips" / "ips" / "targets" ─────────────────────
        _ips_pat = re.compile(
            r'^(?:ips?|targets?|hosts?|c[aá]maras?|dispositivos?|'
            r'dame\s+(?:las?\s+)?(?:ips?|hosts?|targets?|c[aá]maras?)|'
            r'(?:lista(?:me|r)?|mostrar|mu[eé]strame)\s+(?:(?:los?|las?)\s+)?'
            r'(?:ips?|hosts?|targets?|c[aá]maras?|dispositivos?))\s*$',
            re.I,
        )
        if _ips_pat.match(user_message.strip()):
            ip_set = []
            seen_ips: set = set()
            type_map: dict = {}
            for f in ps.findings:
                ip_m = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', f.get("value", ""))
                if ip_m:
                    ip = ip_m.group(0)
                    if ip not in seen_ips:
                        seen_ips.add(ip)
                        ip_set.append(ip)
                        type_map[ip] = f"{f.get('type','?')} [{f.get('severity','?')}]"
            if ip_set:
                rows = "\n".join(f"- **{ip}** — {type_map[ip]}" for ip in ip_set[:50])
                reply = (
                    f"### IPs / Hosts encontrados ({len(ip_set)} en total)\n\n"
                    f"{rows}\n\n"
                    f"_Fuente: project_state — {len(ps.findings)} hallazgos acumulados._"
                )
            else:
                reply = (
                    "No hay IPs/hosts en el project_state aún. "
                    "Ejecuta primero `SKILL:shodan_query`, `SKILL:scan_red` o `SKILL:subfinder_enum`."
                )
            emit({"type": "message", "content": reply, "phase": "recon", "risk": "low"})
            emit({"type": "done", "session": session_name})
            ps.save()
            save_session(session_name, conversation, actual_model, project_dir)
            return

        # ── Subdominios: detecta "subdominios de dominio.com" ──────────────────
        sub_match = _SUBDOMAIN_TRIGGER.search(user_message)
        if sub_match:
            sub_domain = sub_match.group(1).strip().rstrip(".")
            emit({"type": "status", "content": f"🔍 Enumerando subdominios de {sub_domain}…"})
            emit({"type": "thinking_start"})

            all_subs: set[str] = set()
            sources_stats: list[str] = []
            http_active: list[str] = []

            # CRT.SH (100% pasivo)
            crtsh_r = _run_skill("crtsh_enum", domain=sub_domain)
            if crtsh_r.get("success"):
                crt_names = {f["value"] for f in crtsh_r.get("findings", [])}
                all_subs.update(crt_names)
                sources_stats.append(f"CRT.SH: {len(crt_names)}")
                for f in crtsh_r.get("findings", []):
                    ps.add_finding(f)

            # Subfinder + httpx
            subf_r = _run_skill("subfinder_enum", domain=sub_domain, verify_http="true")
            if subf_r.get("success"):
                subf_names = {f["value"] for f in subf_r.get("findings", []) if f["type"] == "subdomain"}
                all_subs.update(subf_names)
                sources_stats.append(f"Subfinder: {len(subf_names)}")
                for f in subf_r.get("findings", []):
                    ps.add_finding(f)
                    if f["type"] == "http_active":
                        http_active.append(f["value"])

            # HackerTarget (gratis, similar a DNSDumpster)
            try:
                import subprocess as _sp
                ht_r = _sp.run(
                    ["curl", "-s", "--max-time", "15",
                     f"https://api.hackertarget.com/hostsearch/?q={sub_domain}"],
                    capture_output=True, text=True, timeout=20,
                )
                ht_out = ht_r.stdout.strip()
                if ht_out and not ht_out.startswith("error") and "," in ht_out:
                    ht_lines = [l.split(",")[0].strip() for l in ht_out.splitlines() if l.strip() and "," in l]
                    all_subs.update(ht_lines)
                    sources_stats.append(f"HackerTarget: {len(ht_lines)}")
                    for h in ht_lines:
                        ps.add_finding({"type": "subdomain", "value": h, "severity": "info"})
            except Exception:
                pass

            ps.save()

            # ── Unificar y mostrar ─────────────────────────────────────────
            sorted_subs = sorted(all_subs)
            source_line = " + ".join(sources_stats)
            body = "\n".join(f"- `{s}`" for s in sorted_subs)
            if http_active:
                body += "\n\n**🌐 Responden HTTP:**\n" + "\n".join(f"- `{h}`" for h in http_active[:20])

            summary = (
                f"### 🔍 Subdominios de `{sub_domain}`\n\n"
                f"**{len(sorted_subs)} únicos** ({source_line})\n\n"
                f"{body}"
            )
            emit({"type": "message", "content": summary, "phase": "recon", "risk": "info"})
            emit({"type": "done", "session": session_name})
            save_session(session_name, conversation, actual_model, project_dir)
            return

        emit({"type": "thinking_start"})

        max_iters = 12
        executed_all: set[str] = set()
        breaker    = CircuitBreaker(max_repeats=3)

        _last_json_err = False  # track consecutive JSON parse errors
        _json_err_count = 0     # abort after 3 consecutive parse errors

        # ── Auto-optimización antes de cada turno ────────────────────────────
        try:
            from agent import _SKILLS_AVAILABLE as _sk_avail
            if _sk_avail:
                # Detectar tarea y optimizar
                _opt_input = user_message[:200]
                _opt_result = _run_skill("auto_optimizer", action="auto", input=_opt_input)
                if _opt_result.get("success") and _opt_result.get("output", "").strip():
                    _opt_out = _opt_result["output"].strip()
                    emit({"type": "status", "content": f"⚡ {_opt_out}"})
        except Exception:
            pass  # Auto-optimización no crítica

        for iteration in range(max_iters):
            # Summarize context if too large
            conversation = summarize_if_needed(actual_model, conversation)

            # Ollama requires strict user/assistant alternation.
            # If the last message is "assistant", insert a user nudge before calling.
            if conversation and conversation[-1]["role"] == "assistant":
                if _last_json_err:
                    _nudge = (
                        "⚠️ Tu respuesta anterior no era JSON válido. "
                        "Responde ÚNICAMENTE con un objeto JSON puro, SIN bloques ```json```, "
                        "SIN texto fuera del objeto. Ejemplo mínimo:\n"
                        '{"thinking":"...","commands":["SKILL:..."],'
                        '"message":"...","task_complete":false,'
                        '"risk_level":"low","phase":"recon",'
                        '"requires_confirmation":false,"needs_api_keys":[],'
                        '"open_browser":"","fetch_url":""}'
                    )
                else:
                    _nudge = "Continúa. Emite los comandos SKILL necesarios o marca task_complete:true."
                conversation.append({"role": "user", "content": _nudge})

            # Call Ollama
            emit({"type": "status", "content": f"Consultando {actual_model}…"})
            try:
                resp = call_llm(actual_model, conversation)
            except Exception as e:
                err_str = str(e)
                if "400" in err_str or "context" in err_str.lower():
                    # Context overflow — truncate hard and retry once
                    from agent import _hard_truncate as _ht
                    conversation = _ht(conversation, target_chars=5000)
                    emit({"type": "status", "content": "Contexto reducido, reintentando…"})
                    try:
                        resp = call_llm(actual_model, conversation)
                    except Exception as e2:
                        emit({"type": "error", "content": f"Error {_backend_display_name()}: {e2}"})
                        break
                else:
                    emit({"type": "error", "content": f"Error {_backend_display_name()}: {e}"})
                    break

            _last_json_err = bool(resp.get("_json_parse_error"))
            if _last_json_err:
                _json_err_count += 1
                if _json_err_count >= 3:
                    emit({"type": "error", "content": "El modelo no genera JSON válido tras 3 intentos. Cambia de modelo o reinicia la sesión."})
                    break
            else:
                _json_err_count = 0

            thinking    = resp.get("thinking", "")
            message     = resp.get("message", "")
            commands    = resp.get("commands", []) or []
            task_done   = bool(resp.get("task_complete", False))
            risk        = resp.get("risk_level", "low")
            phase       = resp.get("phase", "recon")
            fetch_target = resp.get("fetch_url", "")
            open_browser = resp.get("open_browser", "")
            json_err = bool(resp.get("_json_parse_error"))
            if thinking and not json_err:
                emit({"type": "thinking", "content": thinking, "phase": phase, "risk": risk})
            if message and not json_err:
                # Only emit clean messages; raw markdown from parse errors is suppressed
                emit({"type": "message", "content": message, "phase": phase, "risk": risk})
            elif json_err:
                emit({"type": "status", "content": "⚠️ Formato inválido — reintentando con JSON…"})
            log.thinking(thinking, phase, risk)
            if message and not json_err:
                log.message(message)

            if task_done and not commands:
                break

            # requires_confirmation is always auto-approved — the session wizard handles authorization

            # Fetch URL if requested
            fetch_result_text = ""
            if fetch_target:
                emit({"type": "fetch_start", "url": fetch_target})
                result, err = _agent_fetch_url(fetch_target)
                if result:
                    fetch_result_text = json.dumps(result)[:4000]
                    emit({"type": "fetch_done", "url": fetch_target,
                          "status": result.get("status_code"),
                          "preview": result.get("body_preview", "")[:1000]})
                else:
                    emit({"type": "fetch_done", "url": fetch_target, "error": err})

            if not commands:
                conversation.append({"role": "assistant",
                                     "content": json.dumps(resp, ensure_ascii=False)})
                if task_done:
                    break
                continue

            # Filter already-executed & circuit-breaker
            new_cmds = []
            for cmd in commands:
                cmd_mapped = _map_raw_to_skill(cmd)
                cmd_fixed  = nuclei_fix_template_paths(cmd_mapped)
                if cmd_fixed not in executed_all and not breaker.tripped([cmd_fixed]):
                    new_cmds.append(cmd_fixed)
                else:
                    emit({"type": "skipped_cmd", "cmd": cmd_fixed,
                          "reason": "ya ejecutado o circuito abierto"})

            if not new_cmds:
                conversation.append({"role": "assistant",
                                     "content": json.dumps(resp, ensure_ascii=False)})
                break

            # Separate parallel-safe from sequential
            parallel_cmds   = [c for c in new_cmds if is_parallel_safe(c) and not c.upper().startswith("SKILL:")]
            sequential_cmds = [c for c in new_cmds if c not in parallel_cmds]

            all_output: list[dict] = []
            all_nuclei: list[dict] = []

            # ── Execute parallel commands ──────────────────────────────────────
            if parallel_cmds:
                import concurrent.futures
                def _run_par(cmd_p):
                    cached = cache.get(cmd_p)
                    if cached:
                        return cmd_p, cached["stdout"], cached["stderr"], cached["code"], True
                    so, se, code = _agent_run_command(cmd_p)
                    cache.put(cmd_p, so, se, code)
                    return cmd_p, so, se, code, False

                with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
                    futures = {ex.submit(_run_par, c): c for c in parallel_cmds}
                    for f in concurrent.futures.as_completed(futures):
                        try:
                            cmd_p, so, se, code, cached = f.result()
                            executed_all.add(cmd_p)
                            breaker.record([cmd_p])
                            emit({"type": "command_done", "cmd": cmd_p,
                                  "stdout": so[:4000], "stderr": se[:800],
                                  "code": code, "cached": cached})
                            log.command(cmd_p, so, se, code, cached=cached)
                            all_output.append({"command": cmd_p, "stdout": so[:8000],
                                               "stderr": se[:1000], "returncode": code})
                        except Exception as ex_err:
                            emit({"type": "error", "content": str(ex_err)})

            # ── Execute sequential commands ────────────────────────────────────
            for cmd in sequential_cmds:
                skill_name, skill_args = parse_skill_call(cmd)
                if skill_name:
                    emit({"type": "skill_start", "skill": skill_name, "args": skill_args})
                    try:
                        sr = _run_skill(skill_name, **skill_args)
                        skill_out  = sr.get("output", "")
                        skill_ok   = sr.get("success", False)
                        skill_finds = sr.get("findings", [])
                        emit({"type": "skill_done", "skill": skill_name,
                              "output": skill_out[:5000], "success": skill_ok,
                              "findings": skill_finds[:50]})
                        log.command(cmd, skill_out, "", 0 if skill_ok else 1)
                        new_domains = ps.ingest_skill_findings(skill_name, skill_finds)
                        if skill_finds:
                            emit({"type": "new_findings", "findings": skill_finds[:20]})
                        all_output.append({"skill": skill_name, "output": skill_out[:8000],
                                           "success": skill_ok, "findings": skill_finds[:30]})
                        # Emit file_ready for skills that generate downloadable files
                        _emit_file_ready(emit, sr, skill_name)
                    except Exception as se2:
                        emit({"type": "error", "content": f"Skill {skill_name}: {se2}"})
                    executed_all.add(cmd)
                    breaker.record([cmd])
                    continue

                # WPScan: inject API token
                wk = get_api_key("WPSCAN_API_KEY")
                if "wpscan" in cmd:
                    if wk and "--api-token" not in cmd:
                        cmd += f" --api-token {wk}"
                    if "--random-user-agent" not in cmd:
                        cmd += " --random-user-agent"

                # Nuclei: inject json-export
                nuclei_json_path = None
                first_word = Path(cmd.strip().split()[0]).name.lower() if cmd.strip() else ""
                if first_word == "nuclei":
                    cmd, nuclei_json_path = inject_nuclei_json(cmd)

                emit({"type": "command_start", "cmd": cmd})
                cached_entry = cache.get(cmd)
                if cached_entry:
                    stdout, stderr, code = (cached_entry["stdout"],
                                            cached_entry["stderr"],
                                            cached_entry["code"])
                    is_cached = True
                else:
                    stdout, stderr, code = _agent_run_command(cmd)
                    # Gobuster wildcard
                    if first_word == "gobuster" and code != 0 and "wildcard" in stderr.lower():
                        cmd_wc = cmd + " --wildcard"
                        stdout, stderr, code = _agent_run_command(cmd_wc)
                        cmd = cmd_wc
                    cache.put(cmd, stdout, stderr, code)
                    is_cached = False

                executed_all.add(cmd)
                breaker.record([cmd])

                # Parse nuclei JSON
                if nuclei_json_path:
                    nf = parse_nuclei_json(nuclei_json_path)
                    if nf:
                        all_nuclei.extend(nf)
                        log.nuclei_findings(nf)
                        stdout += format_nuclei_findings(nf)
                        emit({"type": "nuclei_findings", "findings": nf[:30]})

                # HTTP vuln indicators
                if first_word in ("curl", "httpx", "wget"):
                    hc = verify_http_response(stdout, stderr)
                    if hc.get("vuln_indicators"):
                        emit({"type": "vuln_indicators", "indicators": hc["vuln_indicators"]})

                emit({"type": "command_done", "cmd": cmd,
                      "stdout": stdout[:5000], "stderr": stderr[:1000],
                      "code": code, "cached": is_cached})
                log.command(cmd, stdout, stderr, code, cached=is_cached)
                all_output.append({"command": cmd, "stdout": stdout[:10000],
                                   "stderr": stderr[:2000], "returncode": code})

            # Build result summary
            result_str = json.dumps(all_output, ensure_ascii=False)
            if fetch_result_text:
                result_str += f"\nFetch {fetch_target}: {fetch_result_text}"
            if all_nuclei:
                result_str += f"\n{format_nuclei_findings(all_nuclei)}"

            # Build pre-formatted device/host table from this turn's skill findings
            _DEVICE_TYPES = {"device_found", "host_info", "risky_port", "cve_exposure",
                             "exploit_available", "subdomain", "http_active"}
            _turn_finds = []
            for _e in all_output:
                for _f in _e.get("findings", []):
                    if _f.get("type") in _DEVICE_TYPES and _f.get("value"):
                        _turn_finds.append(_f)
            _devices_block = ""
            if _turn_finds:
                _rows = []
                for _i, _f in enumerate(_turn_finds[:40], 1):
                    _sev  = _f.get("severity", "info").upper()
                    _val  = _f.get("value", "")
                    _desc = _f.get("description", "")[:90]
                    _rows.append(f"| {_i} | `{_val}` | {_sev} | {_desc} |")
                _devices_block = (
                    "\n\n[TABLA OBLIGATORIA — COPIAR ÍNTEGRA EN message]\n"
                    "| # | IP / Host | Sev | Detalle |\n"
                    "|---|-----------|-----|---------|\n"
                    + "\n".join(_rows)
                )

            conversation.append({"role": "assistant",
                                  "content": json.dumps(resp, ensure_ascii=False)})
            if task_done:
                conversation.append({"role": "user",
                                      "content": f"Resultado: {result_str}{_devices_block}"})
                break
            # Contexto acumulado de hallazgos para que el LLM no olvide IPs/hosts
            ps_ctx = ""
            if ps.findings:
                top = ps.top_findings(30)
                ip_set = []
                seen_ips: set = set()
                for f in ps.findings:
                    ip_m = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', f.get("value", ""))
                    if ip_m and ip_m.group(0) not in seen_ips:
                        seen_ips.add(ip_m.group(0))
                        ip_set.append(ip_m.group(0))
                ps_ctx = (
                    f"\n[PROYECTO — hallazgos acumulados: {len(ps.findings)} total]\n"
                    + (f"IPs/hosts conocidos: {', '.join(ip_set[:20])}\n" if ip_set else "")
                    + "Top hallazgos:\n"
                    + "\n".join(
                        f"  [{f.get('severity','?').upper()}] {f.get('type','?')}: {f.get('value','')[:80]}"
                        for f in top[:15]
                    )
                )

            conversation.append({"role": "user",
                                  "content": (
                                      f"Resultados:\n{result_str}\n\n"
                                      f"{ps_ctx}"
                                      f"{_devices_block}\n\n"
                                      f"[YA EJECUTADOS — NO repetir]: {json.dumps(sorted(executed_all))}\n"
                                      "IMPORTANTE: Si los resultados incluyen hosts, IPs, cámaras o "
                                      "dispositivos, DEBES listarlos TODOS en tu message en formato tabla "
                                      "markdown con IP, puerto, ISP y ciudad. No omitas ninguno aunque no "
                                      "haya CVEs. IPs de Shodan son válidas aunque nmap no las alcance. "
                                      "Si tienes suficiente info, marca task_complete: true."
                                  )})

        # Save session & project state
        ps.save()
        save_session(session_name, conversation, actual_model, project_dir)
        emit({"type": "done", "session": session_name})

    except Exception as exc:
        emit({"type": "error", "content": str(exc)})
        emit({"type": "done", "session": session_name})


# ── Helpers para file_ready ───────────────────────────────────────────────────
_EXT_LANG = {
    "py": "python", "sh": "bash", "ps1": "powershell", "go": "go",
    "c": "c", "cpp": "cpp", "rs": "rust", "rb": "ruby", "php": "php",
    "js": "javascript", "java": "java", "cs": "csharp", "txt": "duckyscript",
}

def _emit_file_ready(emit_fn, skill_result: dict, skill_name: str):
    """Emit a file_ready event when a skill produces a downloadable file."""
    from pathlib import Path
    # Gather candidate file paths from skill result keys
    candidates = []
    for key in ("code_file", "saved", "script_path", "report_file"):
        val = skill_result.get(key)
        if val:
            candidates.append(str(val))
    # ducky_dev also returns inline 'script' content + 'saved' path
    inline_content = skill_result.get("script", "")
    if not candidates and not inline_content:
        return
    for file_path_str in candidates:
        try:
            fp = Path(file_path_str)
            if not fp.exists():
                continue
            content = fp.read_text(encoding="utf-8", errors="replace")
            ext = fp.suffix.lstrip(".")
            lang = _EXT_LANG.get(ext, ext or "text")
            # For ducky payloads, use duckyscript highlighting hint
            if skill_name in ("ducky_dev",) or ext == "txt":
                lang = "duckyscript"
            emit_fn({"type": "file_ready", "path": file_path_str,
                     "filename": fp.name, "language": lang,
                     "content": content, "size": len(content)})
            return  # emit only the first valid file
        except Exception:
            continue
    # Fallback: use inline content from skill result (e.g. ducky_dev 'script')
    if inline_content and not candidates:
        emit_fn({"type": "file_ready", "path": "", "filename": f"{skill_name}_output.txt",
                 "language": "duckyscript" if skill_name == "ducky_dev" else "text",
                 "content": inline_content, "size": len(inline_content)})


# ══════════════════════════════════════════════════════════════════════════════
# REST API routes
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/download")
def api_download():
    """Serve a file from the out/ directory for download."""
    from flask import request as freq, send_file, abort
    from pathlib import Path
    file_path = freq.args.get("path", "").strip()
    if not file_path:
        abort(400)
    fp = Path(file_path)
    # Security: only serve files within the project base dir
    base = Path(__file__).parent.resolve()
    try:
        fp.resolve().relative_to(base)
    except ValueError:
        abort(403)
    if not fp.exists() or not fp.is_file():
        abort(404)
    return send_file(str(fp.resolve()), as_attachment=True, download_name=fp.name)


@app.route("/api/projects", methods=["GET"])
def api_projects():
    return jsonify(_list_projects())


@app.route("/api/projects", methods=["POST"])
def api_create_project():
    data         = request.json or {}
    name         = data.get("name", "").strip()
    target       = data.get("target", "").strip()
    custom_path  = data.get("path", "").strip()
    project_type = data.get("project_type", "full").strip()

    if not name:
        return jsonify({"error": "name required"}), 400

    safe_id = _sanitize(name)
    if custom_path:
        project_dir = Path(custom_path)
    else:
        project_dir = OUT_DIR / safe_id

    project_dir.mkdir(parents=True, exist_ok=True)

    ps = ProjectState(project_dir, project_name=name, target=target, project_type=project_type)
    ps.save()

    return jsonify({
        "id":           safe_id,
        "name":         name,
        "target":       target,
        "project_type": project_type,
        "path":         str(project_dir),
    })


@app.route("/api/projects/<proj_id>", methods=["PUT"])
def api_update_project(proj_id: str):
    """Actualizar nombre/target/tipo de un proyecto."""
    data = request.json or {}
    name = data.get("name", "").strip()
    target = data.get("target", "").strip()
    project_type = data.get("project_type", "").strip()

    if not name:
        return jsonify({"error": "name required"}), 400

    # Get current project
    p = database.get_project(proj_id)
    if not p:
        return jsonify({"error": "project not found"}), 404

    from agent import ProjectState as _PS
    project_dir = OUT_DIR / proj_id
    ps = _PS(project_dir, project_name=name, target=target or p.get("target", ""),
             project_type=project_type or p.get("project_type", "full"))
    ps.save()
    return jsonify({
        "id": proj_id,
        "name": name,
        "target": target or p.get("target", ""),
        "project_type": project_type or p.get("project_type", "full"),
    })


@app.route("/api/projects/<proj_id>", methods=["DELETE"])
def api_delete_project(proj_id: str):
    """Eliminar un proyecto y todos sus datos."""
    # Delete from database (cascade deletes sessions, messages, events, findings)
    database.delete_project(proj_id)

    # Also delete project directory and files
    project_dir = OUT_DIR / proj_id
    if project_dir.exists():
        import shutil
        shutil.rmtree(project_dir, ignore_errors=True)

    return jsonify({"deleted": proj_id})


@app.route("/api/projects/<proj_id>/sessions", methods=["GET"])
def api_sessions(proj_id: str):
    project_dir = OUT_DIR / proj_id
    if not project_dir.exists():
        return jsonify([])
    return jsonify(list_project_sessions(project_dir))


@app.route("/api/projects/<proj_id>/sessions", methods=["POST"])
def api_create_session(proj_id: str):
    project_dir = OUT_DIR / proj_id
    project_dir.mkdir(parents=True, exist_ok=True)
    sess_name = generate_session_name()
    # Create the session in database so events/messages can reference it
    database.create_session(sess_name, proj_id, "unknown")
    return jsonify({"session": sess_name})


@app.route("/api/projects/<proj_id>/sessions/<sess_name>", methods=["DELETE"])
def api_delete_session(proj_id: str, sess_name: str):
    database.delete_session(sess_name)
    return jsonify({"deleted": [sess_name]})


@app.route("/api/projects/<proj_id>/sessions/<sess_name>/history", methods=["GET"])
def api_chat_history(proj_id: str, sess_name: str):
    project_dir = OUT_DIR / proj_id
    conv, model, _ = load_session_in_project(sess_name, project_dir)
    if conv is None:
        return jsonify({"messages": [], "model": None})
    # Return only user/assistant messages (not system)
    messages = [m for m in conv if m["role"] != "system"]
    return jsonify({"messages": messages, "model": model})


@app.route("/api/projects/<proj_id>/sessions/<sess_name>/events", methods=["GET"])
def api_session_events(proj_id: str, sess_name: str):
    """Return the persisted SSE events log for a session (tool outputs, commands, skills)."""
    project_dir = OUT_DIR / proj_id
    events = _load_events_log(sess_name, project_dir)
    return jsonify({"events": events})


@app.route("/api/projects/<proj_id>/sessions/<sess_name>", methods=["PUT"])
def api_rename_session(proj_id: str, sess_name: str):
    project_dir = OUT_DIR / proj_id
    if not project_dir.exists():
        return jsonify({"error": "project not found"}), 404
        
    data = request.json or {}
    new_name = data.get("name", "").strip()
    if not new_name:
        return jsonify({"error": "new name required"}), 400
        
    # Validar nuevo nombre
    safe_new_name = re.sub(r"[^\w\-]", "_", new_name.lower().replace(" ", "_"))[:40]
    
    # Check if target already exists
    if (project_dir / f"{safe_new_name}.json").exists():
        return jsonify({"error": "a session with that name already exists"}), 400

    renamed = []
    # Renombrar todos los archivos que empiezan por sess_name
    for f in project_dir.iterdir():
        if f.is_file() and f.name.startswith(sess_name):
            new_filename = f.name.replace(sess_name, safe_new_name, 1)
            new_path = project_dir / new_filename
            f.rename(new_path)
            renamed.append(new_filename)
            
            # Si es el json, actualizar la propiedad 'name' internamente
            if new_path.suffix == ".json":
                try:
                    s_data = json.loads(new_path.read_text(encoding="utf-8"))
                    s_data["name"] = safe_new_name
                    new_path.write_text(json.dumps(s_data, ensure_ascii=False, indent=2), encoding="utf-8")
                except Exception:
                    pass
                    
    if not renamed:
        return jsonify({"error": "session not found"}), 404
        
    return jsonify({"old_name": sess_name, "new_name": safe_new_name, "renamed": renamed})


@app.route("/api/projects/<proj_id>/sessions/<sess_name>/export", methods=["GET"])
def api_export_session(proj_id: str, sess_name: str):
    """Exportar una sesión como archivo Markdown o JSON."""
    project_dir = OUT_DIR / proj_id
    fmt = request.args.get("format", "markdown").strip().lower()

    # Get conversation
    conv, model, _ = load_session_in_project(sess_name, project_dir)
    if conv is None:
        return jsonify({"error": "session not found"}), 404

    # Get project info
    p = database.get_project(proj_id) or {}
    proj_name = p.get("name", proj_id)
    proj_target = p.get("target", "")

    if fmt == "json":
        # Export as JSON
        export = {
            "project": proj_name,
            "target": proj_target,
            "session": sess_name,
            "model": model,
            "exported_at": datetime.now().isoformat(),
            "messages": [
                {"role": m["role"], "content": m["content"]}
                for m in conv if m["role"] != "system"
            ],
        }
        json_str = json.dumps(export, ensure_ascii=False, indent=2)
        return Response(
            json_str,
            mimetype="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="{sess_name}.json"',
                "Content-Type": "application/json; charset=utf-8",
            },
        )
    else:
        # Export as Markdown
        lines = [
            f"# HackerAgent — Exportación de Sesión",
            f"",
            f"**Proyecto:** {proj_name}  ",
            f"**Sesión:** {sess_name}  ",
            f"**Target:** {proj_target or '—'}  ",
            f"**Modelo:** {model or '—'}  ",
            f"**Exportado:** {datetime.now():%Y-%m-%d %H:%M:%S}  ",
            f"",
            f"---",
            f"",
        ]
        for m in conv:
            if m["role"] == "system":
                continue
            role = "👤 **Usuario**" if m["role"] == "user" else "🤖 **HackerAgent**"
            content = m.get("content", "")
            # Try to pretty-print JSON content
            try:
                parsed = json.loads(content)
                if isinstance(parsed, dict):
                    content = f"```json\n{json.dumps(parsed, indent=2, ensure_ascii=False)}\n```"
            except Exception:
                pass
            lines.append(f"### {role}")
            lines.append(f"")
            lines.append(content)
            lines.append(f"")
            lines.append(f"---")
            lines.append(f"")

        md_content = "\n".join(lines)
        return Response(
            md_content,
            mimetype="text/markdown",
            headers={
                "Content-Disposition": f'attachment; filename="{sess_name}_export.md"',
                "Content-Type": "text/markdown; charset=utf-8",
            },
        )


@app.route("/api/projects/<proj_id>/sessions/<sess_name>/chat", methods=["POST"])
def api_chat(proj_id: str, sess_name: str):
    """SSE endpoint: streams agent events as text/event-stream."""
    try:
        project_dir = OUT_DIR / proj_id
        if not project_dir.exists():
            return jsonify({"error": "project not found"}), 404

        data           = request.json or {}
        user_message   = data.get("message", "").strip()
        model_req      = data.get("model", "")
        enabled_skills = data.get("enabled_skills")
        file_content   = data.get("file_content", "")
        reconnect      = data.get("reconnect", False)

        session_key = (proj_id, sess_name)

        if reconnect or (not user_message and session_key in _ACTIVE_SESSIONS):
            if session_key not in _ACTIVE_SESSIONS:
                return jsonify({"error": "no active session"}), 404
            active = _ACTIVE_SESSIONS[session_key]
            streamer = active["streamer"]
            t = active["thread"]
        else:
            if not user_message:
                return jsonify({"error": "message required"}), 400

            model, _ = _get_or_create_model()
            if model_req:
                model = model_req

            streamer = EventStreamer(session_name=sess_name, project_dir=project_dir)
            _append_event_log(sess_name, project_dir, {"type": "user_turn", "content": user_message})

            def _bg():
                try:
                    _process_chat_turn(
                        project_dir=project_dir,
                        session_name=sess_name,
                        user_message=user_message,
                        model=model,
                        enabled_skills=enabled_skills,
                        event_queue=streamer,
                        uploaded_file_content=file_content,
                    )
                except Exception as e:
                    streamer.put({"type": "error", "content": str(e)})

            t = threading.Thread(target=_bg, daemon=True)
            _ACTIVE_SESSIONS[session_key] = {"streamer": streamer, "thread": t}
            t.start()

        def generate():
            for event in streamer.get_iterator(t):
                if event is None:
                    yield ": keepalive\n\n"
                else:
                    yield f"data: {json.dumps(event, ensure_ascii=False)}\n\n"

        return Response(
            generate(),
            mimetype="text/event-stream",
            headers={
                "Cache-Control":  "no-cache",
                "X-Accel-Buffering": "no",
                "Access-Control-Allow-Origin": "*",
            },
        )
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@app.route("/api/projects/<proj_id>/state", methods=["GET"])
def api_project_state(proj_id: str):
    project_dir = OUT_DIR / proj_id
    meta = _read_project_meta(project_dir)
    return jsonify(meta)


@app.route("/api/projects/<proj_id>/sessions/<sess_name>/skills", methods=["GET"])
def api_get_skills(proj_id: str, sess_name: str):
    all_skills = skill_names()
    by_cat = _skills_by_category(all_skills)
    cats = []
    all_cats = list(CATEGORY_ORDER) + [c for c in by_cat if c not in CATEGORY_ORDER]
    for cat in all_cats:
        items = by_cat.get(cat, [])
        if not items:
            continue
        cats.append({
            "id":    cat,
            "label": CATEGORY_LABELS.get(cat, cat),
            "skills": [{"name": s, "desc": d} for s, d, _ in items],
        })
    return jsonify({"categories": cats, "all_skills": all_skills})


@app.route("/api/projects/<proj_id>/sessions/<sess_name>/upload", methods=["POST"])
def api_upload(proj_id: str, sess_name: str):
    project_dir = OUT_DIR / proj_id
    uploads_dir = project_dir / "uploads"
    uploads_dir.mkdir(parents=True, exist_ok=True)

    if "file" not in request.files:
        return jsonify({"error": "no file"}), 400

    f = request.files["file"]
    filename = re.sub(r"[^\w.\-]", "_", f.filename)[:120]
    dest = uploads_dir / filename
    f.save(dest)

    # Read text content (up to 1MB)
    content = ""
    try:
        size = dest.stat().st_size
        if size < 1_048_576:  # 1 MB
            mt, _ = mimetypes.guess_type(str(dest))
            if not mt or mt.startswith("text"):
                content = dest.read_text(encoding="utf-8", errors="replace")[:12000]
    except Exception:
        pass

    return jsonify({
        "filename": filename,
        "path":     str(dest),
        "size":     dest.stat().st_size,
        "content":  content,
    })


@app.route("/api/models", methods=["GET"])
def api_models():
    import agent as _ag
    backend = _ag.LLM_BACKEND
    ok, models = check_backend()
    if not ok:
        return jsonify({"available": False, "models": [], "backend": backend})
    ranked = sorted(models, key=lambda m: score_model(m)[0], reverse=True)
    return jsonify({
        "available": True,
        "backend":   backend,
        "backend_name": _backend_display_name(),
        "models":    [{"name": m, "stars": score_model(m)[0], "desc": score_model(m)[1]}
                      for m in ranked],
    })


@app.route("/api/backends", methods=["GET"])
def api_backends():
    """Lista los backends disponibles con su estado online/offline."""
    import agent as _ag
    ollama_ok, ollama_models     = check_ollama()
    lmstudio_ok, lmstudio_models = check_lmstudio()
    return jsonify({
        "active": _ag.LLM_BACKEND,
        "backends": [
            {
                "id": "ollama",
                "name": "Ollama",
                "icon": "🦙",
                "url": OLLAMA_URL,
                "online": ollama_ok,
                "model_count": len(ollama_models),
            },
            {
                "id": "lmstudio",
                "name": "LM Studio",
                "icon": "🖥️",
                "url": LMSTUDIO_URL,
                "online": lmstudio_ok,
                "model_count": len(lmstudio_models),
            },
        ]
    })


@app.route("/api/backend/switch", methods=["POST"])
def api_switch_backend():
    """Cambia el backend LLM activo."""
    import agent as _ag
    data = request.json or {}
    new_backend = data.get("backend", "").strip().lower()
    if new_backend not in ("ollama", "lmstudio"):
        return jsonify({"error": "backend must be 'ollama' or 'lmstudio'"}), 400
    _ag.LLM_BACKEND = new_backend
    # Return the models for the new backend
    ok, models = check_backend()
    ranked = sorted(models, key=lambda m: score_model(m)[0], reverse=True) if ok else []
    return jsonify({
        "backend":      new_backend,
        "backend_name": _ag.LLM_BACKEND and _backend_display_name(),
        "available":    ok,
        "models":       [{"name": m, "stars": score_model(m)[0], "desc": score_model(m)[1]}
                         for m in ranked],
    })


@app.route("/api/projects/<proj_id>/report", methods=["POST"])
def api_generate_report(proj_id: str):
    data     = request.json or {}
    sess     = data.get("session", "")
    project_dir = OUT_DIR / proj_id
    if not project_dir.exists() or not sess:
        return jsonify({"error": "invalid request"}), 400

    log_path = project_dir / f"{sess}.md"
    if not log_path.exists():
        return jsonify({"error": "log not found"}), 404

    return jsonify({"report_path": str(log_path)})


# ══════════════════════════════════════════════════════════════════════════════
# Tool Management API
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/tools/status", methods=["GET"])
def api_tools_status():
    """Return installation status of all known tools."""
    try:
        from tool_manager import scan_tools, get_tool_install_report
        status = scan_tools()
        html_report = get_tool_install_report()
        installed = sum(1 for v in status.values() if v)
        total = len(status)
        return jsonify({
            "tools": status,
            "installed": installed,
            "total": total,
            "html_report": html_report,
        })
    except Exception as e:
        return jsonify({"error": str(e), "tools": {}, "installed": 0, "total": 0})


@app.route("/api/tools/install", methods=["POST"])
def api_tools_install():
    """Install a specific tool by name."""
    data = request.json or {}
    tool_name = data.get("tool", "").strip().lower()
    if not tool_name:
        return jsonify({"error": "tool name required"}), 400
    try:
        from tool_manager import install_tool
        ok = install_tool(tool_name)
        return jsonify({"tool": tool_name, "success": ok})
    except Exception as e:
        return jsonify({"tool": tool_name, "success": False, "error": str(e)})


@app.route("/api/tools/install-all", methods=["POST"])
def api_tools_install_all():
    """Install all missing tools (non-interactive)."""
    try:
        from tool_manager import install_missing_tools
        results = install_missing_tools(interactive=False)
        return jsonify({
            "installed": {k: v for k, v in results.items() if v},
            "failed": {k: v for k, v in results.items() if not v},
        })
    except Exception as e:
        return jsonify({"error": str(e)})


@app.route("/api/tools/update", methods=["POST"])
def api_tools_update():
    """Update nuclei templates and other updatable tools."""
    try:
        from tool_manager import update_all_tools
        results = update_all_tools()
        return jsonify({"results": results})
    except Exception as e:
        return jsonify({"error": str(e)})


# ══════════════════════════════════════════════════════════════════════════════
# Main page (SPA)
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/")
def index():
    index_path = os.path.join(os.path.dirname(__file__), "page", "index.html")
    with open(index_path, "r", encoding="utf-8") as f:
        html_data = f.read()
    return html_data, 200, {"Content-Type": "text/html; charset=utf-8"}


# ══════════════════════════════════════════════════════════════════════════════
# Launch
# ══════════════════════════════════════════════════════════════════════════════

def launch(host: str = "0.0.0.0", port: int = 7860, debug: bool = False):
    """Start the HackerAgent web server."""
    import socket
    import agent as _ag

    # Auto-detect backend
    ollama_ok, ollama_models     = check_ollama()
    lmstudio_ok, lmstudio_models = check_lmstudio()

    if ollama_ok and not lmstudio_ok:
        _ag.LLM_BACKEND = "ollama"
    elif lmstudio_ok and not ollama_ok:
        _ag.LLM_BACKEND = "lmstudio"
    elif ollama_ok and lmstudio_ok:
        _ag.LLM_BACKEND = "ollama"

    backend_name = _backend_display_name()
    ok, models = check_backend()
    model_count = len(models) if ok else 0

    local_ip = "127.0.0.1"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except Exception:
        pass

    print()
    print(f"  {'═' * 52}")
    print(f"  🌐  HackerAgent Web UI")
    print(f"  {'═' * 52}")
    print(f"  Local   :  http://127.0.0.1:{port}")
    print(f"  Red     :  http://{local_ip}:{port}")
    print(f"  Backend :  {backend_name} ({model_count} modelos)")
    print(f"  {'─' * 52}")
    print(f"  Presiona Ctrl+C para detener")
    print(f"  {'═' * 52}")
    print()

    app.run(host=host, port=port, debug=debug, threaded=True)


if __name__ == "__main__":
    launch()

