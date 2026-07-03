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
            "id":        d.name,
            "name":      meta.get("project_name") or d.name,
            "target":    meta.get("target", ""),
            "path":      str(d),
            "sessions":  sessions,
            "findings":  meta.get("findings", []),
            "sev_summary": sev_s,
            "updated_at": meta.get("updated_at", ""),
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
        user_content = user_message
        if uploaded_file_content:
            user_content += f"\n\n[ARCHIVO ADJUNTO]\n{uploaded_file_content[:12000]}"

        conversation.append({"role": "user", "content": user_content})

        # Project state & log
        log   = LogWriter(session_name, project_dir)
        cache = ScanCache(project_dir)
        ps    = ProjectState(project_dir)

        emit({"type": "thinking_start"})

        max_iters = 12
        executed_all: set[str] = set()
        breaker    = CircuitBreaker(max_repeats=3)

        for iteration in range(max_iters):
            # Summarize context if too large
            conversation = summarize_if_needed(actual_model, conversation)

            # Call Ollama
            emit({"type": "status", "content": f"Consultando {actual_model}…"})
            try:
                resp = call_ollama(actual_model, conversation)
            except Exception as e:
                emit({"type": "error", "content": f"Error llamando a Ollama: {e}"})
                break

            thinking    = resp.get("thinking", "")
            message     = resp.get("message", "")
            commands    = resp.get("commands", []) or []
            task_done   = bool(resp.get("task_complete", False))
            risk        = resp.get("risk_level", "low")
            phase       = resp.get("phase", "recon")
            fetch_target = resp.get("fetch_url", "")
            open_browser = resp.get("open_browser", "")
            req_confirm  = resp.get("requires_confirmation", False)

            if thinking:
                emit({"type": "thinking", "content": thinking, "phase": phase, "risk": risk})
            if message:
                emit({"type": "message", "content": message, "phase": phase, "risk": risk})
            log.thinking(thinking, phase, risk)
            if message:
                log.message(message)

            if task_done and not commands:
                break

            if req_confirm and commands:
                emit({"type": "confirm_request", "commands": commands, "risk": risk})
                # In web mode we auto-confirm (user can manage risk via web)

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
                                           "success": skill_ok})
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

            conversation.append({"role": "assistant",
                                  "content": json.dumps(resp, ensure_ascii=False)})
            if task_done:
                conversation.append({"role": "user",
                                      "content": f"Resultado: {result_str}"})
                break
            conversation.append({"role": "user",
                                  "content": (
                                      f"Resultados:\n{result_str}\n\n"
                                      f"[YA EJECUTADOS — NO repetir]: {json.dumps(sorted(executed_all))}\n"
                                      "Si tienes suficiente info, marca task_complete: true."
                                  )})

        # Save session & project state
        ps.save()
        save_session(session_name, conversation, actual_model, project_dir)
        emit({"type": "done", "session": session_name})

    except Exception as exc:
        emit({"type": "error", "content": str(exc)})
        emit({"type": "done", "session": session_name})


# ══════════════════════════════════════════════════════════════════════════════
# REST API routes
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/projects", methods=["GET"])
def api_projects():
    return jsonify(_list_projects())


@app.route("/api/projects", methods=["POST"])
def api_create_project():
    data       = request.json or {}
    name       = data.get("name", "").strip()
    target     = data.get("target", "").strip()
    custom_path = data.get("path", "").strip()

    if not name:
        return jsonify({"error": "name required"}), 400

    safe_id = _sanitize(name)
    if custom_path:
        project_dir = Path(custom_path)
    else:
        project_dir = OUT_DIR / safe_id

    project_dir.mkdir(parents=True, exist_ok=True)

    # Init project state
    ps = ProjectState(project_dir, project_name=name, target=target)
    ps.save()

    return jsonify({
        "id":     safe_id,
        "name":   name,
        "target": target,
        "path":   str(project_dir),
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
        while True:
            try:
                event = eq.get(timeout=180)
            except queue.Empty:
                yield f"data: {json.dumps({'type': 'error', 'content': 'Timeout esperando respuesta'})}\n\n"
                break
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

_HTML = r"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>HackerAgent — Web UI</title>
<meta name="description" content="HackerAgent - AI-powered pentesting and security auditing platform">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:ital,wght@0,300;0,400;0,500;0,700;1,400&family=Inter:wght@300;400;500;600;700&display=swap">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/github-dark.min.css">
<script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
<style>
:root {
  --bg:          #05070d;
  --bg2:         #080c14;
  --bg3:         #0c1220;
  --bg4:         #111d2e;
  --bg5:         #172338;
  --border:      #162030;
  --border2:     #1e2d44;
  --border3:     #253548;
  --text:        #cdd9e8;
  --text-dim:    #415870;
  --text-muted:  #5e7a96;
  --accent:      #00cfff;
  --accent2:     #00ff88;
  --accent3:     #a78bfa;
  --accent-glow: rgba(0,207,255,0.12);
  --green:       #00ff88;
  --green-glow:  rgba(0,255,136,0.1);
  --red:         #ff3355;
  --red-glow:    rgba(255,51,85,0.1);
  --orange:      #ff6a00;
  --yellow:      #ffd600;
  --purple:      #a78bfa;
  --crit:        #ff2244;
  --high:        #ff6a00;
  --med:         #ffd600;
  --low:         #4488ff;
  --info:        #4a6a88;
  --radius:      10px;
  --radius-sm:   6px;
  --sidebar-w:   272px;
  --right-w:     256px;
  --trans:       all .2s cubic-bezier(.4,0,.2,1);
}

*{box-sizing:border-box;margin:0;padding:0;}
html,body{height:100%;overflow:hidden;background:var(--bg);color:var(--text);
  font-family:'Inter',sans-serif;font-size:14px;}

/* ── Scrollbar ─────────────────────────── */
::-webkit-scrollbar{width:4px;height:4px;}
::-webkit-scrollbar-track{background:transparent;}
::-webkit-scrollbar-thumb{background:var(--border2);border-radius:4px;}
::-webkit-scrollbar-thumb:hover{background:var(--border3);}

/* ── Animated canvas background ─────────── */
#bg-canvas{
  position:fixed;inset:0;z-index:0;pointer-events:none;opacity:.35;
}

/* ── App layout ─────────────────────────── */
#app{
  position:relative;z-index:1;
  display:flex;height:100vh;overflow:hidden;
}

/* ══════════════════════════════════════════
   SIDEBAR
══════════════════════════════════════════ */
#sidebar{
  width:var(--sidebar-w);flex-shrink:0;
  background:linear-gradient(180deg,var(--bg2) 0%,rgba(8,12,20,.97) 100%);
  border-right:1px solid var(--border);
  display:flex;flex-direction:column;overflow:hidden;
  box-shadow:4px 0 24px rgba(0,0,0,.4);
}

/* Logo */
#sidebar-header{
  padding:18px 16px 14px;
  border-bottom:1px solid var(--border);
  display:flex;align-items:center;gap:10px;flex-shrink:0;
  background:linear-gradient(135deg,rgba(0,207,255,.04),rgba(167,139,250,.04));
}
.logo-wrap{display:flex;align-items:center;gap:8px;flex:1;min-width:0;}
.logo-icon{
  width:32px;height:32px;border-radius:8px;
  background:linear-gradient(135deg,var(--accent),var(--accent3));
  display:flex;align-items:center;justify-content:center;font-size:16px;
  box-shadow:0 0 16px rgba(0,207,255,.3);flex-shrink:0;
  animation:logoPulse 3s ease-in-out infinite;
}
@keyframes logoPulse{
  0%,100%{box-shadow:0 0 16px rgba(0,207,255,.3);}
  50%{box-shadow:0 0 28px rgba(0,207,255,.6),0 0 48px rgba(0,207,255,.2);}
}
.logo-text{font-family:'JetBrains Mono',monospace;font-size:14px;font-weight:700;
  letter-spacing:.5px;color:var(--text);}
.logo-text span{color:var(--accent);}
.logo-sub{font-size:9px;color:var(--text-dim);letter-spacing:.5px;margin-top:1px;}

#btn-new-project{
  background:linear-gradient(135deg,var(--accent),rgba(0,180,255,.8));
  color:#000;border:none;border-radius:var(--radius-sm);
  padding:6px 11px;font-size:11px;font-weight:700;cursor:pointer;
  font-family:'JetBrains Mono',monospace;flex-shrink:0;
  transition:var(--trans);letter-spacing:.3px;
  box-shadow:0 2px 12px rgba(0,207,255,.25);
}
#btn-new-project:hover{
  transform:translateY(-1px);
  box-shadow:0 4px 20px rgba(0,207,255,.45);
  background:linear-gradient(135deg,#00eeff,var(--accent));
}

/* Search */
#sidebar-search{
  padding:10px 12px;border-bottom:1px solid var(--border);flex-shrink:0;
}
#sidebar-search input{
  width:100%;background:var(--bg3);border:1px solid var(--border2);
  border-radius:var(--radius-sm);padding:7px 10px;color:var(--text);
  font-size:12px;font-family:'JetBrains Mono',monospace;outline:none;
  transition:var(--trans);
}
#sidebar-search input:focus{border-color:var(--accent);background:var(--bg4);}
#sidebar-search input::placeholder{color:var(--text-dim);}

/* Project list */
#project-list{flex:1;overflow-y:auto;padding:6px 0;}

.proj-item{cursor:pointer;}
.proj-header{
  display:flex;align-items:center;padding:8px 12px;gap:8px;
  transition:var(--trans);border-radius:0;
}
.proj-header:hover,.proj-item.active>.proj-header{
  background:rgba(0,207,255,.06);
}
.proj-arrow{
  font-size:9px;color:var(--text-dim);
  transition:transform .25s ease;width:10px;flex-shrink:0;
}
.proj-item.open>.proj-header>.proj-arrow{transform:rotate(90deg);}
.proj-icon{font-size:13px;flex-shrink:0;}
.proj-info{flex:1;min-width:0;}
.proj-name{
  font-weight:600;font-size:13px;white-space:nowrap;
  overflow:hidden;text-overflow:ellipsis;
}
.proj-target{
  font-size:10px;color:var(--text-dim);white-space:nowrap;
  overflow:hidden;text-overflow:ellipsis;
  font-family:'JetBrains Mono',monospace;margin-top:1px;
}
.proj-sev{display:flex;gap:3px;flex-shrink:0;align-items:center;}

/* Severity badges */
.sev-badge{
  font-size:9px;padding:2px 5px;border-radius:3px;
  font-weight:700;font-family:'JetBrains Mono',monospace;
}
.sev-badge.critical{background:rgba(255,34,68,.25);color:var(--crit);border:1px solid rgba(255,34,68,.3);}
.sev-badge.high    {background:rgba(255,106,0,.2);color:var(--high);border:1px solid rgba(255,106,0,.25);}
.sev-badge.medium  {background:rgba(255,214,0,.2);color:var(--med);border:1px solid rgba(255,214,0,.2);}
.sev-badge.low     {background:rgba(68,136,255,.2);color:var(--low);border:1px solid rgba(68,136,255,.2);}
.sev-badge.info    {background:rgba(74,106,136,.2);color:var(--info);}

/* Sessions list */
.sess-list{
  overflow:hidden;max-height:0;
  transition:max-height .35s cubic-bezier(.4,0,.2,1);
  padding-left:8px;
}
.proj-item.open>.sess-list{max-height:600px;}

.sess-item{
  display:flex;align-items:center;gap:6px;padding:5px 10px 5px 10px;
  border-radius:var(--radius-sm);cursor:pointer;
  transition:var(--trans);font-size:12px;color:var(--text-muted);
  margin:2px 6px;border:1px solid transparent;
}
.sess-item:hover{
  background:rgba(0,207,255,.06);color:var(--text);
  border-color:rgba(0,207,255,.1);
}
.sess-item.active{
  background:linear-gradient(135deg,rgba(0,207,255,.1),rgba(167,139,250,.06));
  color:var(--accent);border-color:rgba(0,207,255,.25);
  box-shadow:0 0 12px rgba(0,207,255,.08);
}
.sess-item .sess-icon{font-size:11px;flex-shrink:0;}
.sess-item .sess-name{
  flex:1;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;
  font-family:'JetBrains Mono',monospace;
}
.sess-item .sess-turns{font-size:9px;color:var(--text-dim);flex-shrink:0;}
.sess-new{
  display:flex;align-items:center;gap:6px;padding:5px 10px;
  border-radius:var(--radius-sm);cursor:pointer;color:var(--accent2);
  font-size:11px;margin:2px 6px;transition:var(--trans);
  border:1px solid transparent;
}
.sess-new:hover{background:var(--green-glow);border-color:rgba(0,255,136,.15);}

/* ══════════════════════════════════════════
   MAIN AREA
══════════════════════════════════════════ */
#main{flex:1;display:flex;flex-direction:column;overflow:hidden;min-width:0;}

/* Topbar */
#topbar{
  display:flex;align-items:center;gap:12px;padding:10px 18px;
  background:linear-gradient(90deg,var(--bg2),rgba(8,12,20,.98));
  border-bottom:1px solid var(--border);flex-shrink:0;
  box-shadow:0 2px 16px rgba(0,0,0,.3);
}
#current-context{flex:1;min-width:0;}
#ctx-project{font-size:14px;font-weight:600;color:var(--text);}
#ctx-session{
  font-size:10px;color:var(--text-dim);
  font-family:'JetBrains Mono',monospace;margin-top:1px;
}
.tab-bar{display:flex;gap:3px;flex-shrink:0;}
.tab-btn{
  padding:6px 14px;border-radius:var(--radius-sm);
  border:1px solid transparent;font-size:12px;font-weight:500;
  cursor:pointer;background:transparent;color:var(--text-muted);
  transition:var(--trans);letter-spacing:.1px;
}
.tab-btn:hover{color:var(--text);background:var(--bg3);border-color:var(--border2);}
.tab-btn.active{
  background:linear-gradient(135deg,rgba(0,207,255,.12),rgba(0,207,255,.05));
  color:var(--accent);border-color:rgba(0,207,255,.25);
  box-shadow:0 0 12px rgba(0,207,255,.08);
}

/* Ollama status */
#ollama-status{
  display:flex;align-items:center;gap:6px;font-size:11px;
  color:var(--text-muted);flex-shrink:0;
  background:var(--bg3);border:1px solid var(--border2);
  border-radius:20px;padding:4px 10px;
}
#status-dot{
  width:6px;height:6px;border-radius:50%;background:var(--text-dim);
  transition:var(--trans);
}
#status-dot.online{
  background:var(--green);
  box-shadow:0 0 8px var(--green);
  animation:statusPulse 2s ease-in-out infinite;
}
#status-dot.offline{background:var(--red);box-shadow:0 0 6px var(--red);}
@keyframes statusPulse{
  0%,100%{box-shadow:0 0 6px var(--green);}
  50%{box-shadow:0 0 14px var(--green),0 0 24px rgba(0,255,136,.3);}
}

/* Tab content */
.tab-content{display:none;flex:1;overflow:hidden;flex-direction:column;}
.tab-content.active{display:flex;}

/* ══════════════════════════════════════════
   CHAT
══════════════════════════════════════════ */
#chat-messages{
  flex:1;overflow-y:auto;padding:24px 20px;
  display:flex;flex-direction:column;gap:16px;
  background:radial-gradient(ellipse at 70% 10%,rgba(0,207,255,.03) 0%,transparent 60%),
             radial-gradient(ellipse at 20% 80%,rgba(167,139,250,.03) 0%,transparent 60%);
}

/* Message rows */
.msg-row{
  display:flex;gap:10px;align-items:flex-start;
  animation:msgIn .3s cubic-bezier(.34,1.56,.64,1) both;
}
@keyframes msgIn{
  from{opacity:0;transform:translateY(12px) scale(.97);}
  to  {opacity:1;transform:none;}
}
.msg-row.user{flex-direction:row-reverse;}

.msg-avatar{
  width:32px;height:32px;border-radius:50%;flex-shrink:0;
  display:flex;align-items:center;justify-content:center;font-size:14px;
}
.msg-row.agent .msg-avatar{
  background:linear-gradient(135deg,var(--bg4),var(--bg5));
  border:1px solid var(--border2);
}
.msg-row.user .msg-avatar{
  background:linear-gradient(135deg,rgba(0,207,255,.15),rgba(0,207,255,.08));
  border:1px solid rgba(0,207,255,.25);
}

/* Bubbles */
.msg-bubble{
  max-width:72%;background:var(--bg3);
  border:1px solid var(--border2);border-radius:var(--radius);
  padding:12px 15px;line-height:1.65;position:relative;
  box-shadow:0 2px 12px rgba(0,0,0,.2);
}
.msg-row.agent .msg-bubble{
  border-top-left-radius:2px;
  background:linear-gradient(135deg,var(--bg3),rgba(17,29,46,.9));
}
.msg-row.user .msg-bubble{
  border-top-right-radius:2px;
  background:linear-gradient(135deg,rgba(0,207,255,.08),rgba(0,207,255,.04));
  border-color:rgba(0,207,255,.2);
}
.msg-bubble p{margin:0 0 8px;}
.msg-bubble p:last-child{margin:0;}
.msg-bubble a{color:var(--accent);}
.msg-bubble ul,
.msg-bubble ol{margin:6px 0 6px 20px;}
.msg-bubble li{margin-bottom:2px;}
.msg-bubble strong{color:var(--text);}
.msg-bubble code{
  background:rgba(0,0,0,.35);border:1px solid var(--border2);
  border-radius:4px;padding:1px 6px;font-size:.83em;
  font-family:'JetBrains Mono',monospace;color:var(--green);
}
.msg-bubble pre{
  background:rgba(0,0,0,.4);border:1px solid var(--border2);
  border-radius:var(--radius-sm);padding:12px;overflow-x:auto;margin:8px 0;
}
.msg-bubble pre code{background:none;border:none;padding:0;color:var(--text);}

/* Phase label */
.msg-phase{
  font-size:10px;font-family:'JetBrains Mono',monospace;
  color:var(--text-dim);margin-bottom:6px;
  display:flex;align-items:center;gap:6px;letter-spacing:.3px;
}
.risk-badge{
  font-size:9px;padding:2px 6px;border-radius:3px;
  font-weight:700;letter-spacing:.3px;
}
.risk-badge.low     {background:rgba(0,255,136,.12);color:var(--green);}
.risk-badge.medium  {background:rgba(255,214,0,.12);color:var(--yellow);}
.risk-badge.high    {background:rgba(255,106,0,.12);color:var(--orange);}
.risk-badge.critical{background:rgba(255,34,68,.15);color:var(--red);}

/* Thinking block */
.thinking-block{
  background:linear-gradient(135deg,rgba(0,0,0,.4),rgba(5,8,14,.6));
  border:1px solid var(--border);border-left:3px solid var(--text-dim);
  border-radius:var(--radius);padding:10px 14px;
  font-size:11px;color:var(--text-dim);font-style:italic;
  font-family:'JetBrains Mono',monospace;line-height:1.55;
  max-width:75%;animation:msgIn .3s ease both;
}

/* Command block */
.cmd-block{
  background:rgba(0,0,0,.35);border:1px solid var(--border2);
  border-radius:var(--radius);overflow:hidden;
  max-width:85%;animation:msgIn .3s ease both;
  box-shadow:0 2px 12px rgba(0,0,0,.2);
}
.cmd-header{
  display:flex;align-items:center;gap:8px;padding:8px 12px;
  background:linear-gradient(90deg,rgba(0,207,255,.06),transparent);
  border-bottom:1px solid var(--border);
}
.cmd-prompt{
  color:var(--green);font-size:12px;
  font-family:'JetBrains Mono',monospace;flex-shrink:0;
}
.cmd-text{
  flex:1;font-size:12px;font-family:'JetBrains Mono',monospace;
  color:var(--text);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;
}
.cmd-status{font-size:11px;font-weight:700;flex-shrink:0;}
.cmd-status.ok {color:var(--green);}
.cmd-status.err{color:var(--red);}
.cmd-status.run{color:var(--yellow);animation:blink .8s linear infinite;}
@keyframes blink{50%{opacity:.4;}}
.cmd-cache-tag{
  font-size:9px;color:var(--text-dim);background:var(--bg4);
  border:1px solid var(--border2);border-radius:3px;padding:1px 5px;
  font-family:'JetBrains Mono',monospace;flex-shrink:0;
}
.cmd-output-toggle{
  background:none;border:none;color:var(--text-dim);cursor:pointer;
  font-size:10px;padding:2px 8px;border-radius:3px;transition:var(--trans);flex-shrink:0;
}
.cmd-output-toggle:hover{background:var(--bg4);color:var(--text);}
.cmd-output{max-height:0;overflow:hidden;transition:max-height .35s cubic-bezier(.4,0,.2,1);}
.cmd-output.open{max-height:320px;}
.cmd-output pre{
  padding:10px 12px;font-size:11px;font-family:'JetBrains Mono',monospace;
  color:var(--text-muted);white-space:pre-wrap;word-break:break-all;
  max-height:300px;overflow-y:auto;line-height:1.5;
}

/* Skill block */
.skill-block{
  background:linear-gradient(135deg,rgba(0,255,136,.04),rgba(0,207,255,.03));
  border:1px solid var(--border2);border-left:3px solid var(--green);
  border-radius:var(--radius);padding:12px 14px;
  max-width:85%;animation:msgIn .3s ease both;
  box-shadow:0 0 20px rgba(0,255,136,.05);
}
.skill-header{display:flex;align-items:center;gap:8px;margin-bottom:8px;flex-wrap:wrap;}
.skill-name{
  font-family:'JetBrains Mono',monospace;font-size:12px;
  color:var(--green);font-weight:700;letter-spacing:.2px;
}
.skill-ok{color:var(--green);font-size:11px;}
.skill-err{color:var(--red);font-size:11px;}
.skill-running{color:var(--yellow);font-size:11px;animation:blink .8s linear infinite;}
.skill-findings-count{
  font-size:10px;background:rgba(0,255,136,.12);color:var(--green);
  padding:2px 7px;border-radius:10px;
  font-family:'JetBrains Mono',monospace;font-weight:600;
  border:1px solid rgba(0,255,136,.2);
}
.skill-output{
  font-size:11px;color:var(--text-muted);font-family:'JetBrains Mono',monospace;
  white-space:pre-wrap;max-height:220px;overflow-y:auto;line-height:1.5;
  word-break:break-all;
}

/* Typing indicator */
.typing-row{display:flex;gap:10px;align-items:flex-start;animation:msgIn .3s ease both;}
.typing-bubble{
  background:linear-gradient(135deg,var(--bg3),rgba(17,29,46,.9));
  border:1px solid var(--border2);border-top-left-radius:2px;
  border-radius:var(--radius);padding:12px 16px;
  display:flex;align-items:center;gap:5px;
}
.typing-bubble span{
  width:6px;height:6px;border-radius:50%;
  background:linear-gradient(135deg,var(--accent),var(--accent3));
  animation:typingBounce .9s ease infinite;
  box-shadow:0 0 6px rgba(0,207,255,.4);
}
.typing-bubble span:nth-child(2){animation-delay:.15s;}
.typing-bubble span:nth-child(3){animation-delay:.3s;}
@keyframes typingBounce{
  0%,60%,100%{transform:translateY(0) scale(1);}
  30%{transform:translateY(-7px) scale(1.1);}
}

/* Scan pulse indicator */
.scan-status{
  display:flex;align-items:center;gap:8px;font-size:11px;
  color:var(--accent);font-family:'JetBrains Mono',monospace;
  padding:4px 0;
}
.scan-pulse{
  width:8px;height:8px;border-radius:50%;background:var(--accent);
  animation:scanPulse 1s ease-in-out infinite;flex-shrink:0;
}
@keyframes scanPulse{
  0%,100%{transform:scale(1);opacity:1;box-shadow:0 0 4px var(--accent);}
  50%{transform:scale(1.5);opacity:.7;box-shadow:0 0 12px var(--accent),0 0 20px rgba(0,207,255,.4);}
}

/* ── Chat input area ─────────────────────── */
#chat-input-area{
  padding:14px 18px;border-top:1px solid var(--border);
  background:linear-gradient(0deg,var(--bg2),rgba(8,12,20,.97));
  flex-shrink:0;
}
.upload-previews{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:8px;}
.upload-chip{
  display:flex;align-items:center;gap:5px;background:var(--bg4);
  border:1px solid var(--border2);border-radius:4px;padding:3px 9px;
  font-size:11px;font-family:'JetBrains Mono',monospace;color:var(--text-muted);
  animation:chipIn .2s ease;
}
@keyframes chipIn{from{opacity:0;transform:scale(.9);}to{opacity:1;transform:none;}}
.upload-chip button{
  background:none;border:none;color:var(--red);cursor:pointer;
  font-size:13px;padding:0 2px;line-height:1;transition:var(--trans);
}
.upload-chip button:hover{color:#ff6688;}

.input-row{display:flex;align-items:flex-end;gap:8px;}
#chat-input{
  flex:1;background:var(--bg3);border:1px solid var(--border2);
  border-radius:var(--radius);padding:10px 14px;color:var(--text);
  font-size:14px;font-family:'Inter',sans-serif;
  resize:none;outline:none;min-height:46px;max-height:200px;line-height:1.55;
  transition:border-color .2s,box-shadow .2s;
}
#chat-input:focus{
  border-color:var(--accent);
  box-shadow:0 0 0 3px rgba(0,207,255,.08),0 0 20px rgba(0,207,255,.06);
}
#chat-input::placeholder{color:var(--text-dim);}

.input-actions{display:flex;gap:5px;align-items:flex-end;}
.icon-btn{
  width:40px;height:40px;border-radius:var(--radius-sm);
  border:1px solid var(--border2);background:var(--bg3);color:var(--text-muted);
  cursor:pointer;display:flex;align-items:center;justify-content:center;
  font-size:16px;transition:var(--trans);flex-shrink:0;
}
.icon-btn:hover{background:var(--bg4);color:var(--text);border-color:var(--border3);}

#btn-send{
  width:40px;height:40px;border-radius:var(--radius-sm);border:none;
  background:linear-gradient(135deg,var(--accent),rgba(0,160,220,.9));
  color:#000;cursor:pointer;display:flex;align-items:center;
  justify-content:center;font-size:17px;transition:var(--trans);
  flex-shrink:0;font-weight:700;
  box-shadow:0 2px 12px rgba(0,207,255,.3);
}
#btn-send:hover{
  background:linear-gradient(135deg,#00eeff,var(--accent));
  transform:translateY(-1px);box-shadow:0 4px 20px rgba(0,207,255,.5);
}
#btn-send:disabled{
  background:var(--bg4);color:var(--text-dim);transform:none;
  cursor:not-allowed;box-shadow:none;
}
#btn-send.streaming{
  background:linear-gradient(135deg,var(--red),#cc2244);
  box-shadow:0 2px 12px rgba(255,51,85,.3);
  animation:sendPulse 1.2s ease infinite;
}
@keyframes sendPulse{50%{box-shadow:0 4px 20px rgba(255,51,85,.5);}}

#file-input{display:none;}

/* ══════════════════════════════════════════
   EMPTY STATE
══════════════════════════════════════════ */
#empty-state{
  flex:1;display:flex;flex-direction:column;align-items:center;
  justify-content:center;gap:18px;padding:40px;text-align:center;
}
.empty-logo{
  width:80px;height:80px;border-radius:20px;
  background:linear-gradient(135deg,rgba(0,207,255,.15),rgba(167,139,250,.1));
  border:1px solid rgba(0,207,255,.2);
  display:flex;align-items:center;justify-content:center;font-size:36px;
  box-shadow:0 0 40px rgba(0,207,255,.12),0 0 80px rgba(0,207,255,.06);
  animation:emptyFloat 3s ease-in-out infinite;
}
@keyframes emptyFloat{
  0%,100%{transform:translateY(0) rotate(0deg);}
  50%{transform:translateY(-8px) rotate(2deg);}
}
.empty-title{font-size:22px;font-weight:700;color:var(--text);}
.empty-sub{font-size:13px;color:var(--text-muted);line-height:1.7;max-width:380px;}
.empty-hint{
  font-family:'JetBrains Mono',monospace;font-size:12px;
  background:var(--bg3);border:1px solid var(--border2);border-radius:var(--radius-sm);
  padding:8px 16px;color:var(--accent);
  box-shadow:0 0 20px rgba(0,207,255,.08);
}
.empty-steps{
  display:flex;gap:10px;flex-wrap:wrap;justify-content:center;margin-top:6px;
}
.empty-step{
  display:flex;align-items:center;gap:6px;
  background:var(--bg3);border:1px solid var(--border2);border-radius:var(--radius-sm);
  padding:8px 14px;font-size:12px;color:var(--text-muted);
}
.empty-step .step-num{
  width:20px;height:20px;border-radius:50%;
  background:linear-gradient(135deg,var(--accent),var(--accent3));
  color:#000;font-size:10px;font-weight:700;
  display:flex;align-items:center;justify-content:center;flex-shrink:0;
}

/* ══════════════════════════════════════════
   DASHBOARD
══════════════════════════════════════════ */
#dashboard-content{flex:1;overflow-y:auto;padding:22px;}

/* Severity cards */
.sev-cards{
  display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:24px;
}
.sev-card{
  background:var(--bg3);border:1px solid var(--border2);border-radius:var(--radius);
  padding:18px 14px;text-align:center;transition:var(--trans);cursor:default;
  position:relative;overflow:hidden;
}
.sev-card::before{
  content:'';position:absolute;top:0;left:0;right:0;height:2px;
  opacity:0;transition:opacity .3s;
}
.sev-card:hover{transform:translateY(-3px);}
.sev-card:hover::before{opacity:1;}
.sev-card.critical::before{background:linear-gradient(90deg,var(--crit),transparent);}
.sev-card.high::before    {background:linear-gradient(90deg,var(--high),transparent);}
.sev-card.medium::before  {background:linear-gradient(90deg,var(--med),transparent);}
.sev-card.low::before     {background:linear-gradient(90deg,var(--low),transparent);}
.sev-card.info::before    {background:linear-gradient(90deg,var(--info),transparent);}
.sev-card.critical{border-color:rgba(255,34,68,.2);}
.sev-card.high    {border-color:rgba(255,106,0,.2);}
.sev-card.medium  {border-color:rgba(255,214,0,.15);}
.sev-card.low     {border-color:rgba(68,136,255,.15);}
.sev-card .num{
  font-size:34px;font-weight:700;font-family:'JetBrains Mono',monospace;
  line-height:1;margin-bottom:6px;transition:var(--trans);
}
.sev-card.critical .num{color:var(--crit);text-shadow:0 0 20px rgba(255,34,68,.4);}
.sev-card.high     .num{color:var(--high);text-shadow:0 0 20px rgba(255,106,0,.4);}
.sev-card.medium   .num{color:var(--med);text-shadow:0 0 20px rgba(255,214,0,.3);}
.sev-card.low      .num{color:var(--low);text-shadow:0 0 20px rgba(68,136,255,.4);}
.sev-card.info     .num{color:var(--info);}
.sev-card .lbl{
  font-size:10px;color:var(--text-dim);text-transform:uppercase;
  letter-spacing:.6px;font-weight:600;
}

/* Counter animation */
@keyframes countUp{from{opacity:0;transform:scale(.8);}to{opacity:1;transform:none;}}

.dash-section{margin-bottom:28px;}
.dash-section h3{
  font-size:11px;font-weight:600;color:var(--text-dim);text-transform:uppercase;
  letter-spacing:.6px;margin-bottom:14px;padding-bottom:8px;
  border-bottom:1px solid var(--border);
  display:flex;align-items:center;gap:6px;
}

/* Findings table */
.filter-row{display:flex;gap:6px;margin-bottom:12px;flex-wrap:wrap;}
.filter-btn{
  padding:4px 12px;border-radius:20px;
  border:1px solid var(--border2);background:var(--bg3);
  color:var(--text-muted);font-size:11px;cursor:pointer;
  transition:var(--trans);font-family:'JetBrains Mono',monospace;
}
.filter-btn:hover{background:var(--bg4);color:var(--text);}
.filter-btn.active{
  background:linear-gradient(135deg,rgba(0,207,255,.1),rgba(0,207,255,.05));
  color:var(--accent);border-color:rgba(0,207,255,.3);
}

.findings-table{width:100%;border-collapse:collapse;}
.findings-table th{
  background:var(--bg2);padding:8px 12px;text-align:left;
  font-size:10px;font-weight:600;color:var(--text-dim);
  text-transform:uppercase;letter-spacing:.5px;
  border-bottom:1px solid var(--border);
  font-family:'JetBrains Mono',monospace;
}
.findings-table td{
  padding:9px 12px;border-bottom:1px solid var(--border);
  font-size:12px;font-family:'JetBrains Mono',monospace;
  word-break:break-all;transition:background .15s;
}
.findings-table tr:hover td{background:rgba(0,207,255,.03);}
.sev-tag{
  font-size:10px;font-weight:700;padding:2px 7px;border-radius:3px;
  text-transform:uppercase;letter-spacing:.3px;
}
.sev-tag.critical{background:rgba(255,34,68,.18);color:var(--crit);border:1px solid rgba(255,34,68,.25);}
.sev-tag.high    {background:rgba(255,106,0,.18);color:var(--high);border:1px solid rgba(255,106,0,.2);}
.sev-tag.medium  {background:rgba(255,214,0,.15);color:var(--med);border:1px solid rgba(255,214,0,.2);}
.sev-tag.low     {background:rgba(68,136,255,.15);color:var(--low);border:1px solid rgba(68,136,255,.2);}
.sev-tag.info    {background:rgba(74,106,136,.15);color:var(--info);}

/* Domains list */
#domains-list{
  font-family:'JetBrains Mono',monospace;font-size:12px;
  display:flex;flex-wrap:wrap;gap:6px;
}
.domain-chip{
  padding:4px 10px;border-radius:4px;
  background:rgba(0,207,255,.08);border:1px solid rgba(0,207,255,.15);
  color:var(--accent);transition:var(--trans);
}
.domain-chip:hover{background:rgba(0,207,255,.15);}

/* ══════════════════════════════════════════
   HISTORY
══════════════════════════════════════════ */
#history-content{flex:1;overflow-y:auto;padding:16px;}
.history-cmd{
  background:var(--bg3);border:1px solid var(--border2);
  border-radius:var(--radius);margin-bottom:8px;overflow:hidden;
  transition:border-color .2s;
}
.history-cmd:hover{border-color:var(--border3);}
.history-cmd-header{
  display:flex;align-items:center;gap:8px;padding:9px 14px;cursor:pointer;
  transition:background .15s;
}
.history-cmd-header:hover{background:var(--bg4);}
.history-cmd-prompt{color:var(--green);font-size:13px;font-family:'JetBrains Mono',monospace;flex-shrink:0;}
.history-cmd-text{
  flex:1;font-size:12px;font-family:'JetBrains Mono',monospace;
  color:var(--text);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;
}
.history-cmd-output{max-height:0;overflow:hidden;transition:max-height .35s ease;}
.history-cmd-output.open{max-height:500px;}
.history-cmd-output pre{
  padding:12px 14px;font-size:11px;font-family:'JetBrains Mono',monospace;
  color:var(--text-muted);white-space:pre-wrap;
  border-top:1px solid var(--border);word-break:break-all;
  max-height:480px;overflow-y:auto;line-height:1.5;
}

/* ══════════════════════════════════════════
   RIGHT PANEL
══════════════════════════════════════════ */
#right-panel{
  width:var(--right-w);flex-shrink:0;
  background:linear-gradient(180deg,var(--bg2) 0%,rgba(8,12,20,.97) 100%);
  border-left:1px solid var(--border);
  display:flex;flex-direction:column;overflow:hidden;
  box-shadow:-4px 0 24px rgba(0,0,0,.3);
}
#right-header{
  padding:16px 14px 12px;border-bottom:1px solid var(--border);flex-shrink:0;
}
#right-header h3{
  font-size:10px;color:var(--text-dim);text-transform:uppercase;
  letter-spacing:.6px;font-weight:600;margin-bottom:10px;
}
#model-select{
  width:100%;background:var(--bg3);border:1px solid var(--border2);
  border-radius:var(--radius-sm);padding:7px 10px;color:var(--text);
  font-size:12px;font-family:'JetBrains Mono',monospace;outline:none;cursor:pointer;
  transition:var(--trans);
}
#model-select:focus{border-color:var(--accent);}

/* Skills panel */
#skills-panel{flex:1;overflow-y:auto;padding:6px 0;}
.skills-cat{margin-bottom:2px;}
.skills-cat-header{
  padding:6px 14px;font-size:10px;font-weight:600;color:var(--text-dim);
  text-transform:uppercase;letter-spacing:.5px;cursor:pointer;
  display:flex;align-items:center;justify-content:space-between;
  transition:var(--trans);
}
.skills-cat-header:hover{background:var(--bg3);}
.skills-cat-arrow{font-size:9px;transition:transform .2s;}
.skills-cat.open .skills-cat-arrow{transform:rotate(90deg);}
.skills-cat-body{display:none;padding:2px 0;}
.skills-cat.open .skills-cat-body{display:block;}

.skill-toggle{
  display:flex;align-items:center;gap:8px;padding:5px 14px;
  cursor:pointer;transition:var(--trans);border-radius:0;
}
.skill-toggle:hover{background:rgba(0,207,255,.04);}
.skill-toggle-name{
  flex:1;font-size:11px;font-family:'JetBrains Mono',monospace;color:var(--text-muted);
  transition:color .15s;
}
.skill-toggle:hover .skill-toggle-name{color:var(--text);}

/* Toggle switch */
.toggle-sw{
  width:30px;height:16px;border-radius:10px;background:var(--border2);
  position:relative;transition:var(--trans);flex-shrink:0;
  border:1px solid var(--border3);
}
.toggle-sw::after{
  content:'';position:absolute;top:2px;left:2px;width:10px;height:10px;
  border-radius:50%;background:var(--text-dim);transition:all .25s cubic-bezier(.34,1.56,.64,1);
}
.skill-toggle.enabled .toggle-sw{
  background:rgba(0,255,136,.2);border-color:rgba(0,255,136,.3);
}
.skill-toggle.enabled .toggle-sw::after{
  background:var(--green);transform:translateX(14px);
  box-shadow:0 0 6px rgba(0,255,136,.6);
}

/* Skills count badge */
.skills-count-badge{
  font-size:9px;background:var(--bg4);border:1px solid var(--border2);
  border-radius:10px;padding:1px 6px;font-family:'JetBrains Mono',monospace;
  color:var(--text-dim);
}

/* ══════════════════════════════════════════
   MODAL
══════════════════════════════════════════ */
#modal-overlay{
  display:none;position:fixed;inset:0;
  background:rgba(0,0,0,.75);backdrop-filter:blur(6px);
  z-index:1000;align-items:center;justify-content:center;
}
#modal-overlay.show{display:flex;animation:modalFadeIn .2s ease;}
@keyframes modalFadeIn{from{opacity:0;}to{opacity:1;}}

.modal{
  background:linear-gradient(135deg,var(--bg2),var(--bg3));
  border:1px solid var(--border2);border-radius:14px;
  padding:30px;width:440px;max-width:95vw;
  box-shadow:0 24px 80px rgba(0,0,0,.7),0 0 0 1px rgba(0,207,255,.06);
  animation:modalSlideIn .25s cubic-bezier(.34,1.56,.64,1);
}
@keyframes modalSlideIn{
  from{opacity:0;transform:translateY(-20px) scale(.95);}
  to{opacity:1;transform:none;}
}
.modal h2{
  font-size:17px;margin-bottom:22px;color:var(--text);
  display:flex;align-items:center;gap:8px;
}
.form-group{margin-bottom:16px;}
.form-group label{
  display:block;font-size:11px;color:var(--text-muted);margin-bottom:5px;
  font-weight:600;text-transform:uppercase;letter-spacing:.3px;
}
.form-group input{
  width:100%;background:var(--bg4);border:1px solid var(--border2);
  border-radius:var(--radius-sm);padding:9px 12px;color:var(--text);
  font-size:13px;font-family:'JetBrains Mono',monospace;outline:none;
  transition:var(--trans);
}
.form-group input:focus{
  border-color:var(--accent);background:var(--bg5);
  box-shadow:0 0 0 3px rgba(0,207,255,.08);
}
.form-group small{font-size:11px;color:var(--text-dim);margin-top:4px;display:block;}
.modal-actions{display:flex;gap:8px;justify-content:flex-end;margin-top:26px;}
.btn-primary{
  background:linear-gradient(135deg,var(--accent),rgba(0,160,220,.9));
  color:#000;border:none;border-radius:var(--radius-sm);padding:9px 20px;
  font-size:13px;font-weight:700;cursor:pointer;transition:var(--trans);
  box-shadow:0 2px 12px rgba(0,207,255,.3);
}
.btn-primary:hover{
  transform:translateY(-1px);box-shadow:0 4px 20px rgba(0,207,255,.5);
}
.btn-secondary{
  background:var(--bg4);color:var(--text-muted);border:1px solid var(--border2);
  border-radius:var(--radius-sm);padding:9px 18px;font-size:13px;cursor:pointer;
  transition:var(--trans);
}
.btn-secondary:hover{color:var(--text);background:var(--bg5);}

/* ══════════════════════════════════════════
   TOASTS
══════════════════════════════════════════ */
#toast-container{
  position:fixed;bottom:22px;right:22px;
  display:flex;flex-direction:column;gap:8px;z-index:2000;
}
.toast{
  background:linear-gradient(135deg,var(--bg3),var(--bg4));
  border:1px solid var(--border2);border-radius:var(--radius);
  padding:11px 16px;font-size:12px;min-width:220px;max-width:380px;
  box-shadow:0 8px 32px rgba(0,0,0,.5);
  animation:toastIn .25s cubic-bezier(.34,1.56,.64,1);
  display:flex;align-items:center;gap:10px;
}
.toast.success{border-left:3px solid var(--green);}
.toast.error  {border-left:3px solid var(--red);}
.toast.info   {border-left:3px solid var(--accent);}
@keyframes toastIn{
  from{transform:translateX(30px);opacity:0;}
  to{transform:none;opacity:1;}
}
@keyframes toastOut{
  to{transform:translateX(30px);opacity:0;}
}

/* ══════════════════════════════════════════
   MISC
══════════════════════════════════════════ */
.hidden{display:none!important;}
.divider{height:1px;background:var(--border);margin:4px 0;}
</style>
</head>
<body>

<canvas id="bg-canvas"></canvas>

<div id="app">

<!-- ══════════ SIDEBAR ══════════ -->
<aside id="sidebar">
  <div id="sidebar-header">
    <div class="logo-wrap">
      <div class="logo-icon">🔐</div>
      <div>
        <div class="logo-text">HACKER<span>AGENT</span></div>
        <div class="logo-sub">AI SECURITY PLATFORM</div>
      </div>
    </div>
    <button id="btn-new-project" onclick="showNewProjectModal()">＋ Nuevo</button>
  </div>

  <div id="sidebar-search">
    <input type="text" id="search-input" placeholder="🔍  Buscar proyecto…" oninput="filterProjects(this.value)">
  </div>

  <div id="project-list"></div>
</aside>

<!-- ══════════ MAIN ══════════ -->
<main id="main">

  <!-- Topbar -->
  <div id="topbar">
    <div id="current-context">
      <div id="ctx-project">Selecciona o crea un proyecto</div>
      <div id="ctx-session"></div>
    </div>
    <div class="tab-bar">
      <button class="tab-btn active" id="tab-btn-chat"
              onclick="switchTab('chat')">💬 Chat</button>
      <button class="tab-btn" id="tab-btn-dashboard"
              onclick="switchTab('dashboard')">📊 Dashboard</button>
      <button class="tab-btn" id="tab-btn-history"
              onclick="switchTab('history')">⌨ Historial</button>
    </div>
    <div id="ollama-status">
      <div id="status-dot"></div>
      <span id="status-label">Conectando…</span>
    </div>
  </div>

  <!-- ══ CHAT TAB ══ -->
  <div class="tab-content active" id="tab-chat">
    <div id="chat-messages">
      <div id="empty-state">
        <div class="empty-logo">🔐</div>
        <div class="empty-title">HackerAgent Web UI</div>
        <div class="empty-sub">Plataforma de auditoría de seguridad potenciada por IA local. Chat en tiempo real, gestión de proyectos, dashboard de vulnerabilidades.</div>
        <div class="empty-steps">
          <div class="empty-step"><div class="step-num">1</div> Crea un proyecto</div>
          <div class="empty-step"><div class="step-num">2</div> Inicia una sesión</div>
          <div class="empty-step"><div class="step-num">3</div> Describe el objetivo</div>
        </div>
        <div class="empty-hint">python agent.py --web</div>
      </div>
    </div>

    <div id="chat-input-area" class="hidden">
      <div class="upload-previews" id="upload-previews"></div>
      <div class="input-row">
        <textarea id="chat-input" rows="1"
          placeholder="Escribe tu instrucción… (Enter = enviar · Shift+Enter = nueva línea)"
          oninput="autoResizeInput(this)" onkeydown="handleInputKey(event)"></textarea>
        <div class="input-actions">
          <label for="file-input" class="icon-btn" title="Adjuntar archivo">📎</label>
          <input type="file" id="file-input" multiple onchange="handleFileSelect(event)">
          <button class="icon-btn" title="Nueva sesión de chat" onclick="createNewSession()">✏️</button>
          <button id="btn-send" onclick="sendMessage()" disabled title="Enviar">▶</button>
        </div>
      </div>
    </div>
  </div>

  <!-- ══ DASHBOARD TAB ══ -->
  <div class="tab-content" id="tab-dashboard">
    <div id="dashboard-content">
      <div class="sev-cards">
        <div class="sev-card critical">
          <div class="num" id="cnt-critical">0</div>
          <div class="lbl">🔴 Crítico</div>
        </div>
        <div class="sev-card high">
          <div class="num" id="cnt-high">0</div>
          <div class="lbl">🟠 Alto</div>
        </div>
        <div class="sev-card medium">
          <div class="num" id="cnt-medium">0</div>
          <div class="lbl">🟡 Medio</div>
        </div>
        <div class="sev-card low">
          <div class="num" id="cnt-low">0</div>
          <div class="lbl">🔵 Bajo</div>
        </div>
        <div class="sev-card info">
          <div class="num" id="cnt-info">0</div>
          <div class="lbl">⚪ Info</div>
        </div>
      </div>

      <div class="dash-section">
        <h3>🎯 Hallazgos de seguridad</h3>
        <div class="filter-row" id="finding-filters">
          <button class="filter-btn active" onclick="filterFindings('all',this)">Todos</button>
          <button class="filter-btn" onclick="filterFindings('critical',this)">🔴 Crítico</button>
          <button class="filter-btn" onclick="filterFindings('high',this)">🟠 Alto</button>
          <button class="filter-btn" onclick="filterFindings('medium',this)">🟡 Medio</button>
          <button class="filter-btn" onclick="filterFindings('low',this)">🔵 Bajo</button>
          <button class="filter-btn" onclick="filterFindings('info',this)">⚪ Info</button>
        </div>
        <table class="findings-table" id="findings-table">
          <thead><tr>
            <th>Sev</th><th>Tipo</th><th>Valor</th><th>Detalle</th>
          </tr></thead>
          <tbody id="findings-tbody">
            <tr><td colspan="4" style="color:var(--text-dim);text-align:center;padding:28px;font-size:12px;">
              Sin hallazgos — ejecuta un escaneo para ver resultados aquí.
            </td></tr>
          </tbody>
        </table>
      </div>

      <div class="dash-section">
        <h3>🌐 Subdominios / Hosts descubiertos</h3>
        <div id="domains-list" style="color:var(--text-dim);font-size:12px;">—</div>
      </div>
    </div>
  </div>

  <!-- ══ HISTORY TAB ══ -->
  <div class="tab-content" id="tab-history">
    <div id="history-content">
      <p style="color:var(--text-dim);font-size:12px;padding:8px;">
        Selecciona una sesión para ver el historial de comandos.
      </p>
    </div>
  </div>
</main>

<!-- ══════════ RIGHT PANEL ══════════ -->
<aside id="right-panel">
  <div id="right-header">
    <h3>⚙ Configuración</h3>
    <select id="model-select" onchange="state.model=this.value" title="Modelo de Ollama">
      <option value="">⏳ Cargando modelos…</option>
    </select>
  </div>
  <div id="skills-panel"></div>
</aside>

</div><!-- #app -->

<!-- ══════════ MODAL ══════════ -->
<div id="modal-overlay">
  <div class="modal">
    <h2>🆕 Nuevo Proyecto</h2>
    <div class="form-group">
      <label>Nombre del proyecto *</label>
      <input type="text" id="modal-name" placeholder="Auditoría Corp 2026"
             onkeydown="if(event.key==='Enter')createProject()">
    </div>
    <div class="form-group">
      <label>Target (opcional)</label>
      <input type="text" id="modal-target"
             placeholder="192.168.1.0/24 · corp.local · https://example.com">
    </div>
    <div class="form-group">
      <label>Carpeta personalizada (opcional)</label>
      <input type="text" id="modal-path"
             placeholder="C:\proyectos\auditoria  ·  /opt/audits/corp">
      <small>Vacío = usa out/ por defecto del proyecto.</small>
    </div>
    <div class="modal-actions">
      <button class="btn-secondary" onclick="hideModal()">Cancelar</button>
      <button class="btn-primary" onclick="createProject()">✓ Crear proyecto</button>
    </div>
  </div>
</div>

<div id="toast-container"></div>

<!-- ══════════════════════════════════════
     JAVASCRIPT
══════════════════════════════════════ -->
<script>
/* ── marked + highlight config ─────────────── */
marked.setOptions({
  highlight:(code,lang)=>{
    if(lang&&hljs.getLanguage(lang))return hljs.highlight(code,{language:lang}).value;
    return hljs.highlightAuto(code).value;
  },
  breaks:true,gfm:true,
});

/* ── Canvas particle background ─────────────── */
(function(){
  const canvas=document.getElementById('bg-canvas');
  const ctx=canvas.getContext('2d');
  let W,H,pts=[];
  function resize(){W=canvas.width=window.innerWidth;H=canvas.height=window.innerHeight;}
  function init(){
    pts=[];
    const N=Math.floor((W*H)/18000);
    for(let i=0;i<N;i++){
      pts.push({
        x:Math.random()*W,y:Math.random()*H,
        vx:(Math.random()-.5)*.4,vy:(Math.random()-.5)*.4,
        r:Math.random()*1.2+.3,
        a:Math.random(),
      });
    }
  }
  function draw(){
    ctx.clearRect(0,0,W,H);
    ctx.fillStyle='rgba(0,207,255,';
    for(const p of pts){
      p.x+=p.vx;p.y+=p.vy;
      if(p.x<0)p.x=W;if(p.x>W)p.x=0;
      if(p.y<0)p.y=H;if(p.y>H)p.y=0;
      ctx.beginPath();
      ctx.arc(p.x,p.y,p.r,0,Math.PI*2);
      ctx.fillStyle=`rgba(0,207,255,${p.a*0.6})`;
      ctx.fill();
    }
    // Connect nearby particles
    for(let i=0;i<pts.length;i++){
      for(let j=i+1;j<pts.length;j++){
        const dx=pts[i].x-pts[j].x,dy=pts[i].y-pts[j].y;
        const d=Math.sqrt(dx*dx+dy*dy);
        if(d<120){
          ctx.beginPath();
          ctx.moveTo(pts[i].x,pts[i].y);
          ctx.lineTo(pts[j].x,pts[j].y);
          ctx.strokeStyle=`rgba(0,207,255,${(1-d/120)*0.08})`;
          ctx.lineWidth=.5;
          ctx.stroke();
        }
      }
    }
    requestAnimationFrame(draw);
  }
  resize();init();draw();
  window.addEventListener('resize',()=>{resize();init();});
})();

/* ── App state ──────────────────────────────── */
const state={
  projects:[],
  currentProject:null,
  currentSession:null,
  model:'',
  enabledSkills:[],
  allSkills:[],
  skillCategories:[],
  uploadedFiles:[],
  isStreaming:false,
  allFindings:[],
  findingFilter:'all',
  cmdCounter:0,
};

/* ── Boot ───────────────────────────────────── */
window.onload=async()=>{
  await Promise.all([loadProjects(),loadModels(),checkOllama()]);
  setInterval(checkOllama,15000);
};

/* ── Ollama status ──────────────────────────── */
async function checkOllama(){
  try{
    const r=await fetch('/api/models');const d=await r.json();
    const dot=document.getElementById('status-dot');
    const lbl=document.getElementById('status-label');
    if(d.available){
      dot.className='online';
      lbl.textContent=`Online (${d.models.length} modelos)`;
    }else{
      dot.className='offline';lbl.textContent='Ollama offline';
    }
  }catch{
    document.getElementById('status-dot').className='offline';
    document.getElementById('status-label').textContent='Sin conexión';
  }
}

async function loadModels(){
  try{
    const r=await fetch('/api/models');const d=await r.json();
    const sel=document.getElementById('model-select');
    if(!d.available||!d.models.length){
      sel.innerHTML='<option>Sin modelos disponibles</option>';return;
    }
    sel.innerHTML=d.models.map(m=>
      `<option value="${m.name}">${'★'.repeat(Math.min(m.stars,5))} ${m.name}</option>`
    ).join('');
    state.model=d.models[0].name;
  }catch(e){console.error(e);}
}

/* ── Projects ───────────────────────────────── */
async function loadProjects(){
  try{
    const r=await fetch('/api/projects');
    state.projects=await r.json();
    renderProjects();
  }catch(e){console.error(e);}
}

function renderProjects(filter=''){
  const container=document.getElementById('project-list');
  const fl=filter.toLowerCase();
  const list=fl
    ?state.projects.filter(p=>p.name.toLowerCase().includes(fl)||p.target.toLowerCase().includes(fl))
    :state.projects;
  if(!list.length){
    container.innerHTML=`<div style="padding:24px 16px;text-align:center;color:var(--text-dim);font-size:12px;">
      Sin proyectos — haz clic en "+ Nuevo" para crear uno.
    </div>`;
    return;
  }
  container.innerHTML=list.map(p=>renderProjectItem(p)).join('');
}

function renderProjectItem(p){
  const isActive=state.currentProject&&state.currentProject.id===p.id;
  const sev=p.sev_summary||{};
  const badges=Object.entries(sev)
    .filter(([,v])=>v>0)
    .map(([s,v])=>`<span class="sev-badge ${s}">${v}</span>`)
    .join('');
  const sessions=(p.sessions||[]);
  return `
<div class="proj-item${isActive?' active':''}" id="proj-${p.id}">
  <div class="proj-header" onclick="toggleProject('${p.id}')">
    <span class="proj-arrow">▶</span>
    <span class="proj-icon">📁</span>
    <div class="proj-info">
      <div class="proj-name">${esc(p.name)}</div>
      ${p.target?`<div class="proj-target">${esc(p.target)}</div>`:''}
    </div>
    <div class="proj-sev">
      ${badges||'<span style="font-size:10px;color:var(--text-dim)">—</span>'}
    </div>
  </div>
  <div class="sess-list" id="sess-list-${p.id}">
    ${sessions.slice(0,10).map(s=>renderSessionItem(p,s)).join('')}
    <div class="sess-new" onclick="createNewSessionForProject('${p.id}')">
      <span>✏️</span><span>Nueva sesión de chat</span>
    </div>
  </div>
</div>`;
}

function renderSessionItem(p,s){
  const isActive=state.currentSession===s.name&&state.currentProject&&state.currentProject.id===p.id;
  return `
<div class="sess-item${isActive?' active':''}"
     onclick="selectSession('${p.id}','${s.name}')">
  <span class="sess-icon">💬</span>
  <span class="sess-name">${esc(s.name)}</span>
  <span class="sess-turns">${s.turns}t</span>
</div>`;
}

function toggleProject(projId){
  const el=document.getElementById(`proj-${projId}`);
  if(el)el.classList.toggle('open');
}
function filterProjects(val){renderProjects(val);}

async function selectSession(projId,sessName){
  const proj=state.projects.find(p=>p.id===projId);
  if(!proj)return;
  state.currentProject=proj;
  state.currentSession=sessName;
  document.getElementById('ctx-project').textContent=proj.name;
  document.getElementById('ctx-session').textContent=sessName;
  document.getElementById('chat-input-area').classList.remove('hidden');
  document.getElementById('btn-send').disabled=false;
  renderProjects(document.getElementById('search-input').value);
  const projEl=document.getElementById(`proj-${projId}`);
  if(projEl)projEl.classList.add('open','active');
  await loadSkills(projId,sessName);
  await loadChatHistory(projId,sessName);
  await loadDashboard(projId);
}

async function createNewSessionForProject(projId){
  try{
    const r=await fetch(`/api/projects/${projId}/sessions`,{method:'POST'});
    const d=await r.json();
    await loadProjects();
    await selectSession(projId,d.session);
  }catch(e){toast('Error al crear sesión: '+e,'error');}
}
async function createNewSession(){
  if(!state.currentProject)return;
  await createNewSessionForProject(state.currentProject.id);
}

/* ── Chat ───────────────────────────────────── */
async function loadChatHistory(projId,sessName){
  const container=document.getElementById('chat-messages');
  try{
    const r=await fetch(`/api/projects/${projId}/sessions/${sessName}/history`);
    const d=await r.json();
    container.innerHTML='';
    const msgs=d.messages||[];
    for(const msg of msgs){
      if(msg.role==='user'){appendUserMessage(msg.content,false);}
      else if(msg.role==='assistant'){
        try{
          const p=JSON.parse(msg.content);
          if(p.thinking&&p.thinking.trim())appendThinking(p.thinking,false);
          if(p.message&&p.message.trim())appendAgentMessage(p.message,p.phase||'recon',p.risk_level||'low',false);
        }catch{
          if(msg.content&&msg.content.trim())appendAgentMessage(msg.content,'recon','low',false);
        }
      }
    }
    if(!msgs.length){
      container.innerHTML=`<div style="color:var(--text-dim);font-size:13px;
        text-align:center;padding:60px 20px;">
        <div style="font-size:32px;margin-bottom:12px;">✏️</div>
        Nueva sesión — escribe tu primera instrucción abajo.
      </div>`;
    }
    scrollChat();
  }catch(e){console.error(e);}
}

function appendUserMessage(content,animate=true){
  const div=document.createElement('div');
  div.className='msg-row user'+(animate?'':' no-anim');
  if(!animate)div.style.animation='none';
  div.innerHTML=`
    <div class="msg-avatar">👤</div>
    <div class="msg-bubble">
      <div class="msg-phase" style="justify-content:flex-end">Tú</div>
      <div>${esc(content).replace(/\n/g,'<br>')}</div>
    </div>`;
  document.getElementById('chat-messages').appendChild(div);
}

function appendThinking(content,animate=true){
  if(!content||!content.trim())return;
  const div=document.createElement('div');
  if(!animate)div.style.animation='none';
  div.className='thinking-block';
  div.textContent='🧠 '+content.trim().slice(0,1000);
  document.getElementById('chat-messages').appendChild(div);
}

function appendAgentMessage(content,phase,risk,animate=true){
  const div=document.createElement('div');
  div.className='msg-row agent';
  if(!animate)div.style.animation='none';
  const phaseIcons={recon:'🔍',scan:'📡',exploit:'💥','post-exploit':'🏴',report:'📋'};
  const pi=phaseIcons[phase]||'🤖';
  div.innerHTML=`
    <div class="msg-avatar">🤖</div>
    <div class="msg-bubble">
      <div class="msg-phase">
        ${pi} ${esc(phase.toUpperCase())}
        <span class="risk-badge ${risk}">${esc(risk.toUpperCase())}</span>
      </div>
      <div class="msg-content">${marked.parse(content||'')}</div>
    </div>`;
  document.getElementById('chat-messages').appendChild(div);
  div.querySelectorAll('pre code').forEach(b=>hljs.highlightElement(b));
}

function appendCommandBlock(cmd,stdout,stderr,code,cached){
  const id='cmd-'+Date.now()+'-'+(state.cmdCounter++);
  const div=document.createElement('div');
  div.className='cmd-block';
  const running=code===-1;
  const statusClass=running?'run':(code===0?'ok':'err');
  const statusText=running?'⌛ ejecutando…':(code===0?'✓ OK':`✗ exit ${code}`);
  const out=((stdout||'')+(stderr?'\n'+stderr:'')).trim().slice(0,6000)||'(sin output)';
  div.id=id+'-block';
  div.innerHTML=`
    <div class="cmd-header">
      <span class="cmd-prompt">❯</span>
      <span class="cmd-text" title="${esc(cmd)}">${esc(cmd)}</span>
      ${cached?'<span class="cmd-cache-tag">cache</span>':''}
      <span class="cmd-status ${statusClass}" id="${id}-status">${statusText}</span>
      <button class="cmd-output-toggle" onclick="toggleCmdOut('${id}')">▾ output</button>
    </div>
    <div class="cmd-output" id="${id}-out"><pre>${esc(out)}</pre></div>`;
  document.getElementById('chat-messages').appendChild(div);
  return id;
}

function updateCommandBlock(id,stdout,stderr,code){
  const statusEl=document.getElementById(id+'-status');
  const outEl=document.getElementById(id+'-out');
  if(statusEl){
    statusEl.className='cmd-status '+(code===0?'ok':'err');
    statusEl.textContent=code===0?'✓ OK':`✗ exit ${code}`;
  }
  if(outEl){
    const out=((stdout||'')+(stderr?'\n'+stderr:'')).trim().slice(0,6000)||'(sin output)';
    outEl.querySelector('pre').textContent=out;
  }
}

function toggleCmdOut(id){
  const el=document.getElementById(id+'-out');
  if(el)el.classList.toggle('open');
}

function appendSkillBlock(skillName,output,success,findings,running=false){
  const div=document.createElement('div');
  div.className='skill-block';
  const statusHtml=running
    ?`<span class="skill-running">⌛ ejecutando…</span>`
    :(success?`<span class="skill-ok">✓ OK</span>`:`<span class="skill-err">✗ Error</span>`);
  const findBadge=findings&&findings.length
    ?`<span class="skill-findings-count">🎯 ${findings.length} hallazgo(s)</span>`:'';
  div.innerHTML=`
    <div class="skill-header">
      <span class="skill-name">⚡ SKILL:${esc(skillName)}</span>
      ${statusHtml}
      ${findBadge}
    </div>
    ${output?`<div class="skill-output">${esc(output.trim().slice(0,4000))}</div>`:''}`;
  document.getElementById('chat-messages').appendChild(div);
}

function appendScanStatus(text){
  const div=document.createElement('div');
  div.id='scan-status-indicator';
  div.className='scan-status';
  div.innerHTML=`<div class="scan-pulse"></div><span>${esc(text)}</span>`;
  document.getElementById('chat-messages').appendChild(div);
}
function removeScanStatus(){
  const el=document.getElementById('scan-status-indicator');
  if(el)el.remove();
}

function appendTypingIndicator(){
  const div=document.createElement('div');
  div.id='typing-indicator';
  div.className='typing-row';
  div.innerHTML=`
    <div class="msg-avatar" style="background:var(--bg4);border:1px solid var(--border2);">🤖</div>
    <div class="typing-bubble">
      <span></span><span></span><span></span>
    </div>`;
  document.getElementById('chat-messages').appendChild(div);
  scrollChat();
}
function removeTypingIndicator(){
  const el=document.getElementById('typing-indicator');
  if(el)el.remove();
}
function scrollChat(){
  const c=document.getElementById('chat-messages');
  c.scrollTop=c.scrollHeight;
}

/* ── Send message ───────────────────────────── */
async function sendMessage(){
  if(state.isStreaming)return;
  const input=document.getElementById('chat-input');
  const msg=input.value.trim();
  if(!msg)return;
  if(!state.currentProject||!state.currentSession){
    toast('Selecciona primero un proyecto y sesión.','error');return;
  }
  input.value='';input.style.height='auto';

  // Remove empty state
  const empty=document.getElementById('empty-state');
  if(empty)empty.remove();

  appendUserMessage(msg);
  scrollChat();
  appendTypingIndicator();
  state.isStreaming=true;
  const sendBtn=document.getElementById('btn-send');
  sendBtn.disabled=true;
  sendBtn.classList.add('streaming');
  sendBtn.textContent='■';

  const fileContent=state.uploadedFiles.map(
    f=>`\n\n--- Archivo: ${f.filename} ---\n${f.content}`
  ).join('');
  state.uploadedFiles=[];
  renderUploadPreviews();

  const body={
    message:msg,
    model:state.model||document.getElementById('model-select').value,
    enabled_skills:state.enabledSkills.length?state.enabledSkills:state.allSkills,
    file_content:fileContent,
  };

  let activeCmdId=null;

  try{
    const resp=await fetch(
      `/api/projects/${state.currentProject.id}/sessions/${state.currentSession}/chat`,
      {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}
    );
    if(!resp.ok)throw new Error(`HTTP ${resp.status}`);
    const reader=resp.body.getReader();
    const decoder=new TextDecoder();
    let buf='';
    while(true){
      const {done,value}=await reader.read();
      if(done)break;
      buf+=decoder.decode(value,{stream:true});
      const lines=buf.split('\n');
      buf=lines.pop()||'';
      for(const line of lines){
        if(!line.startsWith('data: '))continue;
        try{handleSSEEvent(JSON.parse(line.slice(6)));}catch{}
      }
    }
  }catch(e){
    removeTypingIndicator();removeScanStatus();
    appendAgentMessage(`❌ Error de conexión: ${e.message}`,'recon','critical');
    toast('Error: '+e.message,'error');
  }finally{
    state.isStreaming=false;
    removeTypingIndicator();removeScanStatus();
    sendBtn.disabled=false;
    sendBtn.classList.remove('streaming');
    sendBtn.textContent='▶';
    scrollChat();
    if(state.currentProject)loadDashboard(state.currentProject.id);
  }
}

let _activeCmdId=null;

function handleSSEEvent(ev){
  switch(ev.type){
    case 'thinking_start':
      removeScanStatus();
      appendScanStatus('Analizando con IA…');
      break;
    case 'thinking':
      removeScanStatus();
      removeTypingIndicator();
      appendThinking(ev.content);
      appendTypingIndicator();
      scrollChat();
      break;
    case 'message':
      removeScanStatus();
      removeTypingIndicator();
      appendAgentMessage(ev.content,ev.phase||'recon',ev.risk||'low');
      appendTypingIndicator();
      scrollChat();
      break;
    case 'status':
      removeScanStatus();
      appendScanStatus(ev.content||'Procesando…');
      break;
    case 'command_start':
      removeScanStatus();removeTypingIndicator();
      _activeCmdId=appendCommandBlock(ev.cmd,'','Running…',-1,false);
      appendTypingIndicator();scrollChat();
      break;
    case 'command_done':
      removeTypingIndicator();
      if(_activeCmdId){
        updateCommandBlock(_activeCmdId,ev.stdout,ev.stderr,ev.code);
        _activeCmdId=null;
      }else{
        appendCommandBlock(ev.cmd,ev.stdout,ev.stderr,ev.code,ev.cached);
      }
      appendTypingIndicator();scrollChat();
      break;
    case 'skill_start':
      removeScanStatus();removeTypingIndicator();
      appendSkillBlock(ev.skill,'',true,[],true);
      appendScanStatus(`Ejecutando SKILL:${ev.skill}…`);
      appendTypingIndicator();scrollChat();
      break;
    case 'skill_done':
      removeTypingIndicator();removeScanStatus();
      appendSkillBlock(ev.skill,ev.output,ev.success,ev.findings||[]);
      if(ev.findings&&ev.findings.length){
        state.allFindings.push(...ev.findings);
        renderFindingCounts();
      }
      appendTypingIndicator();scrollChat();
      break;
    case 'new_findings':
      state.allFindings.push(...(ev.findings||[]));
      renderFindingCounts();
      break;
    case 'fetch_done':
      removeTypingIndicator();
      if(ev.status){
        appendAgentMessage(`🌐 Fetch \`${ev.url}\` → HTTP ${ev.status}`,'recon','low');
      }
      appendTypingIndicator();scrollChat();
      break;
    case 'nuclei_findings':
      toast(`🎯 Nuclei: ${(ev.findings||[]).length} hallazgo(s)`,'info');
      break;
    case 'vuln_indicators':
      toast(`⚠️ Indicadores de vuln: ${ev.indicators.join(', ')}`,'info');
      break;
    case 'skipped_cmd':
      break;
    case 'error':
      removeScanStatus();removeTypingIndicator();
      appendAgentMessage(`❌ ${ev.content}`,'recon','critical');
      scrollChat();
      break;
    case 'done':
      removeScanStatus();removeTypingIndicator();
      toast('✓ Turno completado','success');
      break;
  }
}

/* ── Skills ─────────────────────────────────── */
async function loadSkills(projId,sessName){
  try{
    const r=await fetch(`/api/projects/${projId}/sessions/${sessName}/skills`);
    const d=await r.json();
    state.allSkills=d.all_skills||[];
    state.skillCategories=d.categories||[];
    state.enabledSkills=[...state.allSkills];
    renderSkillsPanel();
  }catch(e){console.error(e);}
}

function renderSkillsPanel(){
  const panel=document.getElementById('skills-panel');
  if(!state.skillCategories.length){
    panel.innerHTML='<div style="padding:16px;color:var(--text-dim);font-size:12px;">Sin skills.</div>';
    return;
  }
  panel.innerHTML=state.skillCategories.map(cat=>`
<div class="skills-cat open" id="cat-${cat.id}">
  <div class="skills-cat-header" onclick="toggleSkillCat('${cat.id}')">
    <span>${esc(cat.label)}</span>
    <div style="display:flex;align-items:center;gap:5px;">
      <span class="skills-count-badge">${cat.skills.length}</span>
      <span class="skills-cat-arrow">▶</span>
    </div>
  </div>
  <div class="skills-cat-body">
    ${cat.skills.map(s=>`
    <div class="skill-toggle enabled" id="skill-${s.name}"
         onclick="toggleSkill('${s.name}')" title="${esc(s.desc)}">
      <span class="skill-toggle-name">${esc(s.name)}</span>
      <div class="toggle-sw"></div>
    </div>`).join('')}
  </div>
</div>`).join('');
}

function toggleSkillCat(catId){
  const el=document.getElementById('cat-'+catId);
  if(el)el.classList.toggle('open');
}
function toggleSkill(name){
  const el=document.getElementById('skill-'+name);
  if(!el)return;
  el.classList.toggle('enabled');
  if(el.classList.contains('enabled')){
    if(!state.enabledSkills.includes(name))state.enabledSkills.push(name);
  }else{
    state.enabledSkills=state.enabledSkills.filter(s=>s!==name);
  }
}

/* ── Dashboard ──────────────────────────────── */
async function loadDashboard(projId){
  try{
    const r=await fetch(`/api/projects/${projId}/state`);
    const d=await r.json();
    state.allFindings=d.findings||[];
    const sev=d.sev_summary||{};
    animateCount('cnt-critical',sev.critical||0);
    animateCount('cnt-high',sev.high||0);
    animateCount('cnt-medium',sev.medium||0);
    animateCount('cnt-low',sev.low||0);
    animateCount('cnt-info',sev.info||0);
    renderFindingsTable(state.allFindings,state.findingFilter);
    const domains=d.domains||[];
    const dl=document.getElementById('domains-list');
    dl.innerHTML=domains.length
      ?domains.map(d=>`<span class="domain-chip">${esc(d)}</span>`).join('')
      :'<span style="color:var(--text-dim)">—</span>';
  }catch(e){console.error(e);}
}

function animateCount(id,target){
  const el=document.getElementById(id);
  if(!el)return;
  const current=parseInt(el.textContent)||0;
  if(current===target){return;}
  const step=target>current?1:-1;
  const delay=Math.max(20,Math.floor(300/Math.abs(target-current)));
  let v=current;
  const iv=setInterval(()=>{
    v+=step;el.textContent=v;
    if(v===target)clearInterval(iv);
  },delay);
}

function renderFindingCounts(){
  const sev={};
  for(const f of state.allFindings){const s=f.severity||'info';sev[s]=(sev[s]||0)+1;}
  for(const s of ['critical','high','medium','low','info']){
    animateCount('cnt-'+s,sev[s]||0);
  }
}

function filterFindings(sev,btn){
  state.findingFilter=sev;
  document.querySelectorAll('#finding-filters .filter-btn').forEach(b=>b.classList.remove('active'));
  if(btn)btn.classList.add('active');
  renderFindingsTable(state.allFindings,sev);
}

function renderFindingsTable(findings,filter){
  const tbody=document.getElementById('findings-tbody');
  if(!tbody)return;
  const SEV_RANK={critical:0,high:1,medium:2,low:3,info:4};
  let filtered=filter&&filter!=='all'
    ?findings.filter(f=>f.severity===filter):findings;
  filtered=filtered.slice().sort((a,b)=>(SEV_RANK[a.severity]||4)-(SEV_RANK[b.severity]||4));
  if(!filtered.length){
    tbody.innerHTML=`<tr><td colspan="4" style="color:var(--text-dim);text-align:center;padding:24px;font-size:12px;">
      Sin hallazgos en esta categoría.
    </td></tr>`;
    return;
  }
  tbody.innerHTML=filtered.slice(0,300).map(f=>`
<tr>
  <td><span class="sev-tag ${f.severity||'info'}">${(f.severity||'info').toUpperCase()}</span></td>
  <td style="color:var(--accent)">${esc(f.type||'?')}</td>
  <td>${esc(String(f.value||'?'))}</td>
  <td style="color:var(--text-muted)">${esc(f.detail||'')}</td>
</tr>`).join('');
}

/* ── Tabs ───────────────────────────────────── */
function switchTab(tab){
  document.querySelectorAll('.tab-content').forEach(t=>t.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(b=>b.classList.remove('active'));
  document.getElementById('tab-'+tab).classList.add('active');
  document.getElementById('tab-btn-'+tab).classList.add('active');
  if(tab==='dashboard'&&state.currentProject)loadDashboard(state.currentProject.id);
}

/* ── File upload ────────────────────────────── */
async function handleFileSelect(event){
  const files=[...event.target.files];
  for(const file of files){
    if(!state.currentProject||!state.currentSession){
      toast('Selecciona un proyecto primero.','error');return;
    }
    const fd=new FormData();fd.append('file',file);
    try{
      const r=await fetch(
        `/api/projects/${state.currentProject.id}/sessions/${state.currentSession}/upload`,
        {method:'POST',body:fd}
      );
      const d=await r.json();
      if(d.error){toast(d.error,'error');}
      else{
        state.uploadedFiles.push({filename:d.filename,content:d.content||''});
        renderUploadPreviews();
        toast(`📎 Archivo: ${d.filename}`,'success');
      }
    }catch(e){toast('Error subiendo archivo: '+e,'error');}
  }
  event.target.value='';
}
function renderUploadPreviews(){
  const c=document.getElementById('upload-previews');
  c.innerHTML=state.uploadedFiles.map((f,i)=>`
<div class="upload-chip">
  📎 ${esc(f.filename)}
  <button onclick="removeUpload(${i})" title="Quitar">✕</button>
</div>`).join('');
}
function removeUpload(i){
  state.uploadedFiles.splice(i,1);renderUploadPreviews();
}

/* ── Project creation ───────────────────────── */
function showNewProjectModal(){
  document.getElementById('modal-overlay').classList.add('show');
  setTimeout(()=>document.getElementById('modal-name').focus(),120);
}
function hideModal(){
  document.getElementById('modal-overlay').classList.remove('show');
  ['modal-name','modal-target','modal-path'].forEach(id=>{
    const el=document.getElementById(id);if(el)el.value='';
  });
}
document.getElementById('modal-overlay')
  .addEventListener('click',function(e){if(e.target===this)hideModal();});

async function createProject(){
  const name=document.getElementById('modal-name').value.trim();
  if(!name){toast('El nombre es obligatorio.','error');return;}
  const target=document.getElementById('modal-target').value.trim();
  const path=document.getElementById('modal-path').value.trim();
  try{
    const r=await fetch('/api/projects',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({name,target,path}),
    });
    const d=await r.json();
    if(d.error){toast(d.error,'error');return;}
    hideModal();
    await loadProjects();
    await createNewSessionForProject(d.id);
    toast(`✓ Proyecto "${name}" creado`,'success');
  }catch(e){toast('Error: '+e,'error');}
}

/* ── Input helpers ──────────────────────────── */
function autoResizeInput(el){
  el.style.height='auto';
  el.style.height=Math.min(el.scrollHeight,200)+'px';
}
function handleInputKey(e){
  if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();sendMessage();}
}

/* ── Utilities ──────────────────────────────── */
function esc(s){
  return String(s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function toast(msg,type='info'){
  const el=document.createElement('div');
  el.className=`toast ${type}`;
  const icon={success:'✓',error:'✗',info:'ℹ'}[type]||'•';
  el.innerHTML=`<span>${icon}</span><span>${esc(msg)}</span>`;
  document.getElementById('toast-container').appendChild(el);
  setTimeout(()=>{
    el.style.animation='toastOut .2s ease forwards';
    setTimeout(()=>el.remove(),200);
  },3500);
}
</script>
</body>
</html>"""


@app.route("/")
def index():
    return _HTML, 200, {"Content-Type": "text/html; charset=utf-8"}


# ══════════════════════════════════════════════════════════════════════════════
# Launch
# ══════════════════════════════════════════════════════════════════════════════

def launch(host: str = "127.0.0.1", port: int = 7860, debug: bool = False):
    """Start the HackerAgent web server."""
    print(f"\n{'='*56}")
    print(f"  [WEB UI] HackerAgent")
    print(f"{'-'*56}")
    print(f"  URL     :  http://{host}:{port}")
    print(f"  Proyectos: {OUT_DIR}")
    print(f"  Presiona Ctrl+C para detener")
    print(f"{'='*56}\n")
    # Open browser automatically
    import threading as _t, webbrowser as _wb
    def _open():
        import time as _time; _time.sleep(1.2)
        try:_wb.open(f"http://{'localhost' if host in ('0.0.0.0','127.0.0.1') else host}:{port}")
        except Exception:pass
    _t.Thread(target=_open,daemon=True).start()
    app.run(host=host, port=port, debug=debug, threaded=True, use_reloader=False)
