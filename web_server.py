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
    OLLAMA_URL, OUT_DIR, BASE_DIR,
    call_ollama,
    parse_skill_call,
    load_skills, skill_names,
    _skills_by_category, CATEGORY_LABELS, CATEGORY_ORDER,
    SYSTEM_PROMPT,
    _skills_context,
    save_session, load_session_in_project, list_project_sessions,
    generate_session_name,
    ProjectState, LogWriter, ScanCache,
    score_model, check_ollama,
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
    get_model,
)

app = Flask(__name__)
load_skills()

# ══════════════════════════════════════════════════════════════════════════════
# Helpers
# ══════════════════════════════════════════════════════════════════════════════

def _sanitize(name: str) -> str:
    return re.sub(r"[^\w\-]", "_", name.lower().replace(" ", "_"))[:40] or "project"


def _read_project_meta(project_dir: Path) -> dict:
    f = project_dir / "project_state.json"
    if not f.exists():
        return {}
    try:
        return json.loads(f.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _list_projects() -> list[dict]:
    projects = []
    if not OUT_DIR.exists():
        return projects
    for d in sorted(OUT_DIR.iterdir(), key=lambda x: x.stat().st_mtime, reverse=True):
        if not d.is_dir():
            continue
        meta     = _read_project_meta(d)
        sessions = list_project_sessions(d)
        sev_s    = meta.get("sev_summary", {})
        projects.append({
            "id":           d.name,
            "name":         meta.get("project_name") or d.name,
            "target":       meta.get("target", ""),
            "path":         str(d),
            "sessions":     sessions,
            "findings":     meta.get("findings", []),
            "sev_summary":  sev_s,
            "updated_at":   meta.get("updated_at", ""),
            "project_type": meta.get("project_type", "full"),
        })
    return projects


def _get_or_create_model() -> tuple[str, list[str]]:
    try:
        model, models = get_model()
        return model, models
    except SystemExit:
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
    eq = event_queue or queue.Queue()

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

        actual_model = saved_model or model

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

        emit({"type": "thinking_start"})

        max_iters = 12
        executed_all: set[str] = set()
        breaker    = CircuitBreaker(max_repeats=3)

        _last_json_err = False  # track consecutive JSON parse errors
        _json_err_count = 0     # abort after 3 consecutive parse errors

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
                resp = call_ollama(actual_model, conversation)
            except Exception as e:
                err_str = str(e)
                if "400" in err_str or "context" in err_str.lower():
                    # Context overflow — truncate hard and retry once
                    from agent import _hard_truncate as _ht
                    conversation = _ht(conversation, target_chars=10000)
                    emit({"type": "status", "content": "Contexto reducido, reintentando…"})
                    try:
                        resp = call_ollama(actual_model, conversation)
                    except Exception as e2:
                        emit({"type": "error", "content": f"Error llamando a Ollama: {e2}"})
                        break
                else:
                    emit({"type": "error", "content": f"Error llamando a Ollama: {e}"})
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


@app.route("/api/projects/<proj_id>", methods=["DELETE"])
def api_delete_project(proj_id: str):
    project_dir = OUT_DIR / proj_id
    if not project_dir.exists():
        return jsonify({"error": "not found"}), 404
    import shutil
    shutil.rmtree(project_dir)
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
    return jsonify({"session": sess_name})


@app.route("/api/projects/<proj_id>/sessions/<sess_name>", methods=["DELETE"])
def api_delete_session(proj_id: str, sess_name: str):
    project_dir = OUT_DIR / proj_id
    if not project_dir.exists():
        return jsonify({"error": "project not found"}), 404
    # Remove all files whose stem starts with sess_name (JSON, MD, report files)
    deleted = []
    for f in project_dir.iterdir():
        if f.is_file() and f.stem.startswith(sess_name):
            f.unlink()
            deleted.append(f.name)
    if not deleted:
        return jsonify({"error": "session not found"}), 404
    return jsonify({"deleted": deleted})


@app.route("/api/projects/<proj_id>/sessions/<sess_name>/history", methods=["GET"])
def api_chat_history(proj_id: str, sess_name: str):
    project_dir = OUT_DIR / proj_id
    conv, model, _ = load_session_in_project(sess_name, project_dir)
    if conv is None:
        return jsonify({"messages": [], "model": None})
    # Return only user/assistant messages (not system)
    messages = [m for m in conv if m["role"] != "system"]
    return jsonify({"messages": messages, "model": model})


@app.route("/api/projects/<proj_id>/sessions/<sess_name>/chat", methods=["POST"])
def api_chat(proj_id: str, sess_name: str):
    """SSE endpoint: streams agent events as text/event-stream."""
    project_dir = OUT_DIR / proj_id
    if not project_dir.exists():
        return jsonify({"error": "project not found"}), 404

    data           = request.json or {}
    user_message   = data.get("message", "").strip()
    model_req      = data.get("model", "")
    enabled_skills = data.get("enabled_skills")
    file_content   = data.get("file_content", "")

    if not user_message:
        return jsonify({"error": "message required"}), 400

    model, _ = _get_or_create_model()
    if model_req:
        model = model_req

    eq = queue.Queue()

    def _bg():
        _process_chat_turn(
            project_dir=project_dir,
            session_name=sess_name,
            user_message=user_message,
            model=model,
            enabled_skills=enabled_skills,
            event_queue=eq,
            uploaded_file_content=file_content,
        )

    t = threading.Thread(target=_bg, daemon=True)
    t.start()

    def generate():
        # Poll queue in 30s slices; send keepalive comments so the browser
        # doesn't close the SSE connection during long Ollama generations.
        # Only give up if the background thread has died AND the queue is empty.
        max_idle = 20  # 20 × 30s = 10 min idle max after thread dies
        idle_ticks = 0
        while True:
            try:
                event = eq.get(timeout=30)
                idle_ticks = 0
            except queue.Empty:
                if not t.is_alive():
                    idle_ticks += 1
                    if idle_ticks >= 2:
                        yield f"data: {json.dumps({'type': 'error', 'content': 'El proceso terminó sin respuesta'})}\n\n"
                        break
                # Thread still running or just finished — send keepalive comment
                yield ": keepalive\n\n"
                continue
            yield f"data: {json.dumps(event, ensure_ascii=False)}\n\n"
            if event.get("type") == "done":
                break

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control":  "no-cache",
            "X-Accel-Buffering": "no",
            "Access-Control-Allow-Origin": "*",
        },
    )


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
    ok, models = check_ollama()
    if not ok:
        return jsonify({"available": False, "models": []})
    ranked = sorted(models, key=lambda m: score_model(m)[0], reverse=True)
    return jsonify({
        "available": True,
        "models":    [{"name": m, "stars": score_model(m)[0], "desc": score_model(m)[1]}
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
# Main page (SPA)
# ══════════════════════════════════════════════════════════════════════════════

# ══════════════════════════════════════════════════════════════════════════════
# Main page (SPA)
# ══════════════════════════════════════════════════════════════════════════════


# El HTML ahora se carga desde page/index.html



@app.route("/")
def index():
    import os
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
    local_ip = "127.0.0.1"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except Exception:
        pass

    print(f"\n{'='*56}")
    print(f"  [WEB UI] HackerAgent")
    print(f"{'-'*56}")
    print(f"  Local   :  http://127.0.0.1:{port}")
    if host == "0.0.0.0":
        print(f"  Network :  http://{local_ip}:{port}")
    print(f"  Proyectos: {OUT_DIR}")
    print(f"  Presiona Ctrl+C para detener")
    print(f"{'='*56}\n")
    # Open browser automatically
    import threading as _t, webbrowser as _wb
    def _open():
        import time as _time; _time.sleep(1.2)
        try:_wb.open(f"http://127.0.0.1:{port}")
        except Exception:pass
    _t.Thread(target=_open,daemon=True).start()
    app.run(host=host, port=port, debug=debug, threaded=True, use_reloader=False)
