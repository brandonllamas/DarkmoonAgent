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
from urllib.parse import quote
from datetime import datetime
from pathlib import Path
from research_engine import (
    build_research_context,
    fallback_research_summary,
    parse_research_command,
    research_query_for_message,
    research_web,
)

_ACTIVE_SESSIONS = {}
_BACKEND_REFRESH_LOCK = threading.Lock()
_BACKEND_REFRESHING = False

_DOMAIN_AVAILABILITY_TRIGGER = re.compile(
    r"\b(?:verifica(?:r)?|comprueba|revisa|chequea)\s+(?:la\s+)?"
    r"(?:disponibilidad|estado|alcance|reachability)\s+(?:de\s+)?(?:los?\s+)?dominios?\b",
    re.I,
)

_EXPLOIT_REQUEST_TRIGGER = re.compile(
    r"\b(?:explota(?:r)?|explot(?:a|ar)|verifica(?:r)?\s+(?:la\s+)?vulnerabilidad|poc)\b",
    re.I,
)


def _exploit_workflow_context(user_message: str) -> str:
    """Give the model a repeatable, evidence-first exploitation workflow."""
    if not _EXPLOIT_REQUEST_TRIGGER.search(user_message):
        return ""
    cve = re.search(r"\bCVE-\d{4}-\d{4,7}\b", user_message, re.I)
    identifier = cve.group(0).upper() if cve else "el CVE o hallazgo indicado por el usuario"
    return (
        "\n\n[FLUJO OBLIGATORIO: VERIFICACIÓN DE VULNERABILIDAD AUTORIZADA]\n"
        f"El usuario pide verificar/explotar {identifier}. Primero investiga y valida, no inventes un exploit.\n"
        "1. Busca referencias públicas: `SKILL:exploit_db cve=<CVE>` si hay CVE; si no, "
        "`SKILL:exploit_db search=<producto_o_hallazgo>`.\n"
        "2. Busca módulos disponibles: `SKILL:metasploit mode=search cve=<CVE>` o por producto.\n"
        "3. Confirma versión, exposición y precondiciones con una comprobación no destructiva "
        "(nuclei/scan/HTTP). No ejecutes payloads ni abras sesiones automáticamente.\n"
        "4. Si no existe exploit público y la evidencia técnica es suficiente, solicita a `SKILL:code_dev` "
        "un **PoC de verificación no destructiva**: debe limitarse al target indicado, no modificar datos, "
        "no obtener shell y reportar evidencia reproducible.\n"
        "5. En el message resume fuente, precondiciones, resultado de validación y siguiente acción segura.\n"
    )

# ── Persistent tool-event log ─────────────────────────────────────────────────
# Events that should be persisted so they can be replayed when reloading a session
_PERSIST_EVENT_TYPES = {
    "thinking", "message",
    "llm_stream_end", "model_route",
    "command_start", "command_done",
    "skill_start", "skill_done",
    "fetch_start", "fetch_done",
    "file_ready", "new_findings",
    "nuclei_findings", "vuln_indicators",
    "classification_done",
    "dependency_start", "dependency_done",
    "research_mode", "research_done",
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
            if event.get("type") == "done" or (event.get("type") == "error" and event.get("fatal")):
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
                if event.get("type") == "done" or (event.get("type") == "error" and event.get("fatal")):
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
    OLLAMA_URL, LMSTUDIO_URL, DEEPSEEK_API_URL, DEEPSEEK_API_KEY,
    OPENROUTER_API_URL, OPENROUTER_API_KEY,
    OUT_DIR, BASE_DIR,
    LLM_BACKEND,
    call_llm, call_llm_stream, call_ollama,
    check_backend, check_ollama, check_lmstudio, check_deepseek, check_openrouter,
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
    get_model, get_model_auto, get_model_lmstudio, get_model_deepseek, get_model_openrouter,
    get_model_catalog, select_llm_route,
    lmstudio_diagnostics,
    _SUBDOMAIN_TRIGGER, _PENTEST_TRIGGER,
    sanitize_commands,
)

app = Flask(__name__)
load_skills()

# ══════════════════════════════════════════════════════════════════════════════
# Helpers
# ══════════════════════════════════════════════════════════════════════════════

def _sanitize(name: str) -> str:
    return re.sub(r"[^\w\-]", "_", name.lower().replace(" ", "_"))[:40] or "project"


def _classify_turn_output(ps, all_output: list[dict], emit) -> list[dict]:
    """Classify every tool response from a turn, even when it has no high finding.

    The classifier is deliberately invoked once per batch, rather than once per
    command, so it sees the context needed to distinguish a real issue from a
    scanner banner or a duplicate result.
    """
    if not all_output or "vuln_classifier" not in skill_names():
        return []

    labels = {item.get("skill") or item.get("command") or "respuesta" for item in all_output}
    if "web_asset_mirror" in labels and labels <= {"web_asset_mirror", "assistant_response"}:
        return []

    parts = []
    for item in all_output:
        label = item.get("skill") or item.get("command") or "respuesta"
        if label == "web_asset_mirror":
            # Es inventario/análisis de artefactos, no un hallazgo que requiera
            # una segunda llamada de clasificación TP/FP.
            continue
        raw = item.get("output") or item.get("stdout") or ""
        stderr = item.get("stderr") or ""
        structured = item.get("findings") or []
        # Preserve every response, including short and informational ones.
        parts.append(
            f"[FUENTE: {label}]\n{str(raw)}\n{str(stderr)}\n"
            f"FINDINGS ESTRUCTURADOS: {json.dumps(structured, ensure_ascii=False)}"
        )

    evidence = "\n\n".join(parts)
    if not evidence.strip():
        return []
    try:
        result = _run_skill(
            "vuln_classifier", input=evidence[:25000], source="turn_auto", format="normal"
        )
    except Exception as exc:
        emit({"type": "classification_done", "success": False,
              "summary": f"Clasificación no disponible: {exc}", "findings": []})
        return []

    classified = result.get("findings", []) if result.get("success") else []
    if classified:
        ps.ingest_skill_findings("vuln_classifier_auto", classified)
        emit({"type": "new_findings", "findings": classified[:50]})
    emit({
        "type": "classification_done",
        "success": bool(result.get("success")),
        "summary": result.get("output", "")[:1200],
        "findings": classified[:50],
    })
    return classified


def _model_response_message(resp: dict) -> tuple[str, bool]:
    """Extrae el texto visible y detecta errores terminales del modelo.

    Algunos backends devuelven ``{"error": "...", "task_complete": false}``
    fuera del esquema normal. Antes la Web UI ocultaba ese error y repetía la
    misma consulta hasta agotar el bucle.
    """
    message = (
        resp.get("message", "")
        or resp.get("summary", "")
        or resp.get("content", "")
        or resp.get("response", "")
    )
    model_error = resp.get("error")
    if not message and model_error:
        if isinstance(model_error, str):
            message = model_error
        else:
            try:
                message = json.dumps(model_error, ensure_ascii=False)
            except (TypeError, ValueError):
                message = str(model_error)
    return message, bool(model_error)


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
            # The sidebar only needs counters. Full findings are fetched on
            # demand from /state when that project is selected.
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

    # Fallback: try DeepSeek API
    try:
        ok, models = check_deepseek()
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
    uploaded_file_paths: str = "",
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

        # Research mode is session-scoped and can be toggled without an LLM.
        research_action, _direct_research_query = parse_research_command(user_message)
        if research_action in ("enable", "disable", "status"):
            enabled = bool(database.get_session_setting(session_name, "research_mode", False))
            if research_action == "enable":
                enabled = True
                reply = (
                    "🔎 **Modo investigación activado.** Las próximas preguntas buscarán en Internet, "
                    "leerán varias fuentes y responderán con enlaces verificables."
                )
            elif research_action == "disable":
                enabled = False
                reply = "**Modo investigación desactivado.** Las próximas preguntas usarán el chat normal."
            else:
                reply = f"Modo investigación: **{'activado' if enabled else 'desactivado'}**."
            if research_action != "status":
                database.set_session_setting(session_name, "research_mode", enabled)
            actual_model = saved_model or model or "system"
            conversation.append({"role": "user", "content": user_message})
            assistant_payload = {
                "thinking": "", "commands": [], "message": reply,
                "requires_confirmation": False, "task_complete": True,
                "risk_level": "low", "phase": "report", "needs_api_keys": [],
                "open_browser": "", "fetch_url": "",
            }
            conversation.append({"role": "assistant", "content": json.dumps(assistant_payload, ensure_ascii=False)})
            save_session(session_name, conversation, actual_model, project_dir)
            emit({"type": "research_mode", "enabled": enabled})
            emit({"type": "message", "content": reply, "phase": "report", "risk": "low"})
            emit({"type": "done", "session": session_name})
            return

        # An explicit dependency request is a deterministic system action: it must
        # work even when LM Studio/Ollama is offline and therefore bypasses the LLM.
        import tool_manager as _tools
        if _tools.is_dependency_install_request(user_message):
            actual_model = saved_model or model or "system"
            conversation.append({"role": "user", "content": user_message})
            save_session(session_name, conversation, actual_model, project_dir)
            log = LogWriter(session_name, project_dir)
            log.separator()
            log.user_input(user_message)
            emit({"type": "dependency_start", "message": "Comprobando el entorno completo"})

            def _dependency_progress(event: dict):
                emit({"type": "dependency_progress", **event})

            try:
                report = _tools.install_all_dependencies(progress=_dependency_progress)
                summary = _tools.format_dependency_report(report)
            except Exception as exc:
                report = {"success": False, "python": {}, "tools": {"total": 0, "ready_after": 0,
                          "installed": [], "missing": [], "failed": [], "unsupported": []}}
                summary = f"❌ No se pudo completar la instalación: {exc}"
            emit({"type": "dependency_done", "report": report, "summary": summary})
            assistant_payload = {
                "thinking": "", "commands": [], "message": summary,
                "requires_confirmation": False, "task_complete": True,
                "risk_level": "low" if report.get("success") else "medium",
                "phase": "report", "install_needed": report.get("tools", {}).get("missing", []),
                "needs_api_keys": [], "open_browser": "", "fetch_url": "",
            }
            conversation.append({"role": "assistant", "content": json.dumps(assistant_payload, ensure_ascii=False)})
            save_session(session_name, conversation, actual_model, project_dir)
            log.message(summary)
            emit({"type": "message", "content": summary, "phase": "report",
                  "risk": "low" if report.get("success") else "medium"})
            emit({"type": "done", "session": session_name})
            return

        research_mode = bool(database.get_session_setting(session_name, "research_mode", False))
        research_query = research_query_for_message(user_message, research_mode)
        research_turn = bool(research_query)
        research_context = ""
        research_report = None
        if research_turn:
            emit({"type": "research_start", "query": research_query,
                  "mode_enabled": research_mode})

            def _research_progress(event: dict):
                emit({"type": "research_progress", **event})

            research_report = research_web(research_query, progress=_research_progress)
            research_context = build_research_context(research_report)
            sources = [
                {"index": item.get("index"), "title": item.get("title", ""),
                 "url": item.get("url", ""), "snippet": item.get("snippet", "")[:500]}
                for item in research_report.get("results", [])
            ]
            emit({
                "type": "research_done", "success": bool(research_report.get("success")),
                "query": research_query, "provider": research_report.get("provider", "none"),
                "sources": sources, "fetched": research_report.get("fetched", 0),
                "errors": research_report.get("errors", [])[:4],
            })

        import agent as _ag
        actual_model = saved_model or model
        if _ag.LLM_BACKEND == "auto":
            # En Auto IA se guarda el selector, no el último modelo físico usado.
            requested = model or saved_model or "auto"
            actual_model = requested if requested != "unknown" else "auto"
        # Una sesión puede haberse creado con Ollama y reanudarse ahora con
        # --deepseek. No enviar nombres locales (p. ej. deepseek-r1:14b) a la API.
        backend_ok = False
        try:
            backend_ok, backend_models = check_backend()
            if backend_ok and backend_models and actual_model not in backend_models:
                actual_model = "auto" if _ag.LLM_BACKEND == "auto" else (
                    model if model in backend_models else backend_models[0]
                )
        except Exception:
            pass
        if research_turn and not backend_ok:
            summary = fallback_research_summary(research_report or {})
            conversation.append({"role": "user", "content": user_message})
            conversation.append({"role": "assistant", "content": json.dumps({
                "thinking": "", "commands": [], "message": summary,
                "requires_confirmation": False, "task_complete": True,
                "risk_level": "medium", "phase": "report", "needs_api_keys": [],
                "open_browser": "", "fetch_url": "",
            }, ensure_ascii=False)})
            save_session(session_name, conversation, actual_model or "system", project_dir)
            emit({"type": "message", "content": summary, "phase": "report", "risk": "medium"})
            emit({"type": "done", "session": session_name})
            return
        if _ag.LLM_BACKEND == "auto" and not backend_ok:
            emit({"type": "error", "content": "Auto IA no encontró modelos disponibles. Inicia Ollama/LM Studio o configura DeepSeek/OpenRouter."})
            emit({"type": "done", "session": session_name})
            return
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
                    else:
                        ok3, models3 = check_deepseek()
                        if ok3 and models3:
                            actual_model = models3[0]
                        else:
                            ok4, models4 = check_openrouter()
                            if ok4 and models4:
                                actual_model = models4[0]
            except Exception:
                pass
            if actual_model == "unknown" or not actual_model:
                emit({"type": "error", "content": "No hay modelos disponibles. Verifica Ollama/LM Studio/DeepSeek/OpenRouter."})
                emit({"type": "done", "session": session_name})
                return

        # Compose user content (include uploaded file if present)
        available_keys = {k: bool(get_api_key(k)) for k in [
            "WPSCAN_API_KEY", "SHODAN_API_KEY", "VIRUSTOTAL_API_KEY", "WHITEINTEL_API_KEY",
        ]}
        user_content = f"[API Keys: {json.dumps(available_keys)}]\n{user_message}"
        if not research_turn:
            user_content += _exploit_workflow_context(user_message)
        if uploaded_file_content:
            user_content += f"\n\n[ARCHIVO ADJUNTO — contenido textual]\n{uploaded_file_content[:12000]}"
        if uploaded_file_paths:
            user_content += f"\n\n[ARCHIVOS DISPONIBLES LOCALMENTE]\n{uploaded_file_paths}\n\nPuedes usar estos archivos con los SKILLs correspondientes (ej: SKILL:apk_analyze target=RUTA_DEL_ARCHIVO, SKILL:ing_inversa target=RUTA_DEL_ARCHIVO). Las rutas son absolutas y el archivo ya está guardado en disco."
        if research_context:
            user_content += f"\n\n{research_context}"

        conversation.append({"role": "user", "content": user_content})

        # ── Persist the conversation IMMEDIATELY so the user message survives server restart
        save_session(session_name, conversation, actual_model, project_dir)

        # Project state & log
        log   = LogWriter(session_name, project_dir)
        cache = ScanCache(project_dir)
        ps    = ProjectState(project_dir)

        # Explicit skills execute alone: do not let the model expand them into
        # a different scan such as Nuclei.
        explicit_skill, explicit_args = parse_skill_call(user_message)
        if explicit_skill and not research_turn:
            if explicit_skill == "web_asset_mirror":
                explicit_args.setdefault("output_dir", str(project_dir / "web_assets"))
            emit({"type": "skill_start", "skill": explicit_skill, "args": explicit_args})
            try:
                result = _run_skill(explicit_skill, **explicit_args)
                output = result.get("output", "")
                findings = result.get("findings", [])
                success = result.get("success", False)
                emit({
                    "type": "skill_done", "skill": explicit_skill, "output": output[:12000],
                    "success": success, "findings": findings[:100],
                    "artifact_root": result.get("artifact_root", ""),
                    "manifest_file": result.get("manifest_file", ""),
                    "analysis_file": result.get("analysis_file", ""),
                    "stats": result.get("stats", {}),
                })
                log.command(user_message, output, "", 0 if success else 1)
                ps.ingest_skill_findings(explicit_skill, findings)
                if findings:
                    emit({"type": "new_findings", "findings": findings[:50]})
                _emit_file_ready(emit, result, explicit_skill)
                reply = (
                    f"SKILL:{explicit_skill} completado." if success
                    else f"SKILL:{explicit_skill} terminó con errores; revisa la salida."
                )
                conversation.append({"role": "assistant", "content": json.dumps({
                    "message": reply, "phase": "recon", "risk_level": "info",
                }, ensure_ascii=False)})
                emit({"type": "message", "content": reply, "phase": "recon", "risk": "info"})
            except Exception as exc:
                emit({"type": "error", "content": f"Skill {explicit_skill}: {exc}"})
            ps.save()
            save_session(session_name, conversation, actual_model, project_dir)
            emit({"type": "done", "session": session_name})
            return

        # Verify previously discovered domains without waiting for an LLM.
        if not research_turn and _DOMAIN_AVAILABILITY_TRIGGER.search(user_message):
            from urllib.parse import urlparse
            import concurrent.futures
            import requests
            requests.packages.urllib3.disable_warnings()

            explicit_domains = {
                match.group(0).lower().rstrip(".")
                for match in re.finditer(
                    r"(?<!@)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b",
                    user_message, re.I,
                )
            }
            for domain in explicit_domains:
                ps.add_domain(domain)
            domains = sorted(
                {str(d).strip().lower().rstrip(".") for d in ps.domains if str(d).strip()}
                | explicit_domains
            )
            if not domains:
                reply = "No hay dominios descubiertos todavía en este proyecto. Ejecuta primero una enumeración de subdominios o reconocimiento."
            else:
                emit({"type": "status", "content": f"Verificando {len(domains)} dominio(s) en paralelo..."})

                def _check_domain(domain: str) -> dict:
                    parsed = urlparse(domain if "://" in domain else f"//{domain}")
                    host = (parsed.netloc or parsed.path.split("/")[0]).strip().strip("[]")
                    if not host or any(ch.isspace() for ch in host):
                        return {"domain": domain, "up": False, "reason": "nombre invalido"}
                    errors = []
                    for scheme in ("https", "http"):
                        try:
                            response = requests.get(
                                f"{scheme}://{host}", timeout=(3, 6), allow_redirects=True,
                                verify=False, headers={"User-Agent": "HackerAgent availability check/1.0"}, stream=True,
                            )
                            try:
                                return {"domain": host, "up": True, "status": response.status_code, "url": response.url}
                            finally:
                                response.close()
                        except requests.RequestException as exc:
                            errors.append(f"{scheme}: {str(exc).split(':', 1)[0]}")
                    return {"domain": host, "up": False, "reason": "; ".join(errors)[:160] or "sin respuesta"}

                results = []
                with concurrent.futures.ThreadPoolExecutor(max_workers=min(12, len(domains))) as executor:
                    futures = [executor.submit(_check_domain, domain) for domain in domains]
                    for future in concurrent.futures.as_completed(futures):
                        try:
                            results.append(future.result())
                        except Exception as exc:
                            results.append({"domain": "desconocido", "up": False, "reason": str(exc)[:120]})

                up = sorted((item for item in results if item["up"]), key=lambda item: item["domain"])
                down = sorted((item for item in results if not item["up"]), key=lambda item: item["domain"])
                status_findings = []
                for item in up:
                    status_findings.append({
                        "type": "domain_up", "value": item["domain"], "severity": "info",
                        "detail": f"Disponible: HTTP {item['status']} en {item['url']}",
                    })
                for item in down:
                    status_findings.append({
                        "type": "domain_down", "value": item["domain"], "severity": "low",
                        "detail": f"Sin respuesta: {item['reason']}",
                    })
                for finding in status_findings:
                    ps.add_finding(finding)
                ps.save()
                if status_findings:
                    emit({"type": "new_findings", "findings": status_findings})

                up_rows = "\n".join(f"- **{item['domain']}** - HTTP {item['status']} ({item['url']})" for item in up) or "- Ninguno"
                down_rows = "\n".join(f"- **{item['domain']}** - {item['reason']}" for item in down) or "- Ninguno"
                scan_rows = "\n".join(
                    f"- SKILL:nuclei_scan target={item['url']} severity=critical,high" for item in up
                ) or "- No hay dominios disponibles para escanear."
                reply = (
                    f"### Disponibilidad de dominios\n\n"
                    f"**{len(up)} arriba** / **{len(down)} sin respuesta** / {len(results)} verificados\n\n"
                    f"#### Arriba\n{up_rows}\n\n#### Listos para escanear\n{scan_rows}\n\n"
                    f"#### Sin respuesta (omitidos)\n{down_rows}"
                )

            result_message = {"message": reply, "phase": "recon", "risk_level": "info"}
            conversation.append({"role": "assistant", "content": json.dumps(result_message, ensure_ascii=False)})
            emit({"type": "message", "content": reply, "phase": "recon", "risk": "info"})
            emit({"type": "done", "session": session_name})
            save_session(session_name, conversation, actual_model, project_dir)
            return

        # ── Shortcut: "dame las ips" / "ips" / "targets" ─────────────────────
        _ips_pat = re.compile(
            r'^(?:ips?|targets?|hosts?|c[aá]maras?|dispositivos?|'
            r'dame\s+(?:las?\s+)?(?:ips?|hosts?|targets?|c[aá]maras?)|'
            r'(?:lista(?:me|r)?|mostrar|mu[eé]strame)\s+(?:(?:los?|las?)\s+)?'
            r'(?:ips?|hosts?|targets?|c[aá]maras?|dispositivos?))\s*$',
            re.I,
        )
        if not research_turn and _ips_pat.match(user_message.strip()):
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
        sub_match = None if research_turn else _SUBDOMAIN_TRIGGER.search(user_message)
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

        # Keep active web scanners away from hosts that this project has
        # already classified as unavailable. Passive/recon skills are left
        # untouched because they can still be useful without HTTP service.
        _ACTIVE_WEB_SKILLS = {
            "nuclei_scan", "wpscan_run", "web_attack", "sqli_scan",
            "spider_code", "web_code", "gobuster_dir",
        }
        _domain_status: dict[str, str] = {}
        for finding in ps.findings:
            if finding.get("type") in ("domain_up", "domain_down"):
                _domain_status[str(finding.get("value", "")).lower().rstrip(".")] = (
                    "up" if finding.get("type") == "domain_up" else "down"
                )

        def _target_is_unavailable(skill_name: str, skill_args: dict) -> bool:
            if skill_name not in _ACTIVE_WEB_SKILLS:
                return False
            from urllib.parse import urlparse
            raw_target = str(skill_args.get("target", "")).strip()
            if not raw_target:
                return False
            parsed = urlparse(raw_target if "://" in raw_target else f"//{raw_target}")
            host = (parsed.hostname or "").lower().rstrip(".")
            return bool(host and _domain_status.get(host) == "down")

        max_iters = 12
        executed_all: set[str] = set()
        breaker    = CircuitBreaker(max_repeats=3)

        _last_json_err = False  # track consecutive JSON parse errors
        _json_err_count = 0     # abort after 3 consecutive parse errors

        # ── Auto-optimización antes de cada turno ────────────────────────────
        try:
            from agent import _SKILLS_AVAILABLE as _sk_avail
            if _sk_avail and not research_turn:
                # Detectar tarea y optimizar
                _opt_input = user_message[:200]
                _opt_result = _run_skill("auto_optimizer", action="auto", input=_opt_input)
                if _opt_result.get("success") and _opt_result.get("output", "").strip():
                    _opt_out = _opt_result["output"].strip()
                    emit({"type": "status", "content": f"⚡ {_opt_out}"})
        except Exception:
            pass  # Auto-optimización no crítica

        def _call_agent_model() -> dict:
            """DeepSeek en streaming con lotes pequeños; fallback compatible para local."""
            import agent as _ag
            if _ag.LLM_BACKEND not in ("auto", "deepseek", "openrouter", "lmstudio"):
                return call_llm(actual_model, conversation)

            emit({"type": "llm_stream_start", "model": actual_model,
                  "backend": _ag.LLM_BACKEND})
            pending = {"kind": "", "text": "", "last": time.monotonic()}

            def _flush(force: bool = False):
                if not pending["text"]:
                    return
                if not force and len(pending["text"]) < 96 and time.monotonic() - pending["last"] < .06:
                    return
                emit({"type": "llm_delta", "channel": pending["kind"],
                      "content": pending["text"]})
                pending["text"] = ""
                pending["last"] = time.monotonic()

            def _on_delta(kind: str, text: str):
                if pending["kind"] and pending["kind"] != kind:
                    _flush(True)
                pending["kind"] = kind
                pending["text"] += text
                _flush(False)

            try:
                result = call_llm_stream(actual_model, conversation, on_delta=_on_delta)
                _flush(True)
                raw = result.pop("_stream_raw", "")
                reasoning = result.pop("_reasoning_content", "")
                usage = result.pop("_usage", {})
                route_info = result.get("_routing", {})
                emit({"type": "llm_stream_end",
                      "model": route_info.get("model", actual_model),
                      "backend": route_info.get("backend", _ag.LLM_BACKEND),
                      "raw": raw[:100000], "reasoning": reasoning[:100000],
                      "usage": usage})
                return result
            except Exception:
                _flush(True)
                raise

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

            # Auto IA clasifica la tarea antes de consultar al proveedor.
            status_text = (
                "Auto IA evaluando tarea y modelos disponibles…"
                if _ag.LLM_BACKEND == "auto" else f"Consultando {actual_model}…"
            )
            emit({"type": "status", "content": status_text})
            try:
                resp = _call_agent_model()
            except Exception as e:
                err_str = str(e)
                if "400" in err_str or "context" in err_str.lower():
                    # Context overflow — truncate hard and retry once
                    from agent import _hard_truncate as _ht
                    conversation = _ht(conversation, target_chars=5000)
                    emit({"type": "status", "content": "Contexto reducido, reintentando…"})
                    try:
                        resp = _call_agent_model()
                    except Exception as e2:
                        emit({"type": "error", "content": f"Error {_backend_display_name()}: {e2}"})
                        break
                else:
                    emit({"type": "error", "content": f"Error {_backend_display_name()}: {e}"})
                    break

            route_info = resp.get("_routing", {})
            if route_info:
                emit({
                    "type": "model_route",
                    "backend": route_info.get("backend", ""),
                    "backend_name": route_info.get("backend_name", ""),
                    "model": route_info.get("model", ""),
                    "profile": route_info.get("profile", "general"),
                    "policy": route_info.get("policy", "balanced"),
                    "reason": route_info.get("reason", ""),
                    "fallbacks": route_info.get("fallbacks", []),
                })

            _last_json_err = bool(resp.get("_json_parse_error"))
            textual_fallback = str(
                resp.get("message") or resp.get("content") or resp.get("response") or ""
            ).strip()
            if _last_json_err and textual_fallback:
                # Modelos sin structured output todavía pueden responder bien
                # en texto libre. Conservar esa respuesta es mejor que ocultarla
                # tras tres reintentos de formato idénticos.
                resp = dict(resp)
                resp["task_complete"] = True
                resp["commands"] = []
                emit({"type": "status", "content": "Respuesta textual recibida (modo compatible)."})
                _last_json_err = False
            if _last_json_err:
                _json_err_count += 1
                if _json_err_count >= 3:
                    emit({"type": "error", "content": "El modelo no genera JSON válido tras 3 intentos. Cambia de modelo o reinicia la sesión."})
                    break
            else:
                _json_err_count = 0

            thinking = resp.get("thinking", "")
            message, response_has_error = _model_response_message(resp)
            
            raw_cmds = resp.get("commands")
            if raw_cmds is None:
                if any(k in resp for k in ("skill", "action", "tool", "command")):
                    raw_cmds = [resp]
                else:
                    raw_cmds = []

            commands = sanitize_commands(raw_cmds, current_target=ps.target)
            terminal_model_error = response_has_error and not commands
            
            if not message and commands:
                message = f"Ejecutando herramienta: `{commands[0]}`..."
            elif terminal_model_error:
                message = (
                    f"{message}\n\n"
                    "No se ejecutó ninguna herramienta y no se creó ningún artefacto."
                )
                # Normalizar antes de persistir para que el historial también
                # muestre el error como respuesta del asistente.
                resp = dict(resp)
                resp["message"] = message
                resp["task_complete"] = True

            # Sanitizar tipos de datos para prevenir crashes
            if isinstance(thinking, dict):
                thinking = thinking.get("content", str(thinking))
            elif not isinstance(thinking, str):
                thinking = str(thinking) if thinking is not None else ""

            if isinstance(message, dict):
                message = message.get("content", str(message))
            elif not isinstance(message, str):
                message = str(message) if message is not None else ""
            task_done   = bool(resp.get("task_complete", False)) or terminal_model_error
            risk        = resp.get("risk_level", "low")
            phase       = resp.get("phase", "recon")
            fetch_target = resp.get("fetch_url", "")
            open_browser = resp.get("open_browser", "")
            json_err = bool(resp.get("_json_parse_error"))
            if research_turn:
                # Web evidence is untrusted. Research-only turns may cite it,
                # but never execute commands, fetch requests or browser actions
                # proposed by the model/page content.
                commands = []
                task_done = True
                risk = "low"
                phase = "report"
                fetch_target = ""
                open_browser = ""
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
                # Even a turn with no command can contain an assessment from
                # the model (for example, analysis of an uploaded report).
                if not terminal_model_error:
                    _responses_to_classify = [{
                        "skill": "assistant_response", "output": message, "findings": []
                    }]
                    if fetch_result_text:
                        _responses_to_classify.append({
                            "command": f"fetch {fetch_target}", "stdout": fetch_result_text,
                            "stderr": "", "returncode": 0,
                        })
                    _classify_turn_output(
                        ps, _responses_to_classify, emit
                    )
                ps.save()
                conversation.append({"role": "assistant",
                                     "content": json.dumps(resp, ensure_ascii=False)})
                save_session(session_name, conversation, actual_model, project_dir)
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
                save_session(session_name, conversation, actual_model, project_dir)
                break

            # Separate parallel-safe from sequential
            parallel_cmds   = [c for c in new_cmds if is_parallel_safe(c) and not c.upper().startswith("SKILL:")]
            sequential_cmds = [c for c in new_cmds if c not in parallel_cmds]

            # Include the model's explanation too. This lets the classifier
            # review evidence provided in natural-language replies alongside
            # raw scanner output.
            all_output: list[dict] = ([{
                "skill": "assistant_response", "output": message, "findings": []
            }] if message else [])
            all_nuclei: list[dict] = []

            # En modo DeepSeek rápido, los skills independientes de reconocimiento
            # y análisis arrancan juntos. Los de explotación/desarrollo conservan
            # ejecución secuencial para no mezclar estado ni artefactos.
            _completed_skill_cmds: set[str] = set()
            _parallel_skill_deny = {
                "metasploit", "cred_stuff", "sqli_scan", "web_attack",
                "apk_dynamic", "code_dev", "ducky_dev", "evasion_dev",
                "ing_inversa", "vuln_classifier",
            }

            def _skill_args_for_project(name: str, args: dict) -> dict:
                prepared = dict(args)
                if name == "web_asset_mirror":
                    prepared.setdefault("output_dir", str(project_dir / "web_assets"))
                return prepared

            fast_mode = os.environ.get("HACKERAGENT_FAST_MODE") == "1"
            skill_jobs = []
            if fast_mode:
                for skill_cmd in sequential_cmds:
                    skill_name, skill_args = parse_skill_call(skill_cmd)
                    if (skill_name and skill_name not in _parallel_skill_deny
                            and not _target_is_unavailable(skill_name, skill_args)):
                        skill_jobs.append((skill_cmd, skill_name,
                                           _skill_args_for_project(skill_name, skill_args)))

            if len(skill_jobs) > 1:
                import concurrent.futures
                worker_count = max(2, min(int(os.environ.get("HACKERAGENT_WORKERS", "6")),
                                          len(skill_jobs), 12))
                emit({"type": "parallel_start", "count": len(skill_jobs),
                      "workers": worker_count})
                for _, skill_name, skill_args in skill_jobs:
                    emit({"type": "skill_start", "skill": skill_name, "args": skill_args,
                          "parallel": True})
                with concurrent.futures.ThreadPoolExecutor(max_workers=worker_count) as executor:
                    futures = {
                        executor.submit(_run_skill, skill_name, **skill_args):
                            (skill_cmd, skill_name, skill_args)
                        for skill_cmd, skill_name, skill_args in skill_jobs
                    }
                    for future in concurrent.futures.as_completed(futures):
                        skill_cmd, skill_name, skill_args = futures[future]
                        try:
                            sr = future.result()
                            skill_out = sr.get("output", "")
                            skill_ok = sr.get("success", False)
                            skill_finds = sr.get("findings", [])
                            emit({"type": "skill_done", "skill": skill_name,
                                  "output": skill_out[:12000], "success": skill_ok,
                                  "findings": skill_finds[:100],
                                  "artifact_root": sr.get("artifact_root", ""),
                                  "manifest_file": sr.get("manifest_file", ""),
                                  "stats": sr.get("stats", {})})
                            log.command(skill_cmd, skill_out, "", 0 if skill_ok else 1)
                            ps.ingest_skill_findings(skill_name, skill_finds)
                            if skill_finds:
                                emit({"type": "new_findings", "findings": skill_finds[:50]})
                            all_output.append({"skill": skill_name, "output": skill_out[:12000],
                                               "success": skill_ok, "findings": skill_finds[:50]})
                            _emit_file_ready(emit, sr, skill_name)
                        except Exception as skill_exc:
                            emit({"type": "error", "content": f"Skill {skill_name}: {skill_exc}"})
                        _completed_skill_cmds.add(skill_cmd)
                        executed_all.add(skill_cmd)
                        breaker.record([skill_cmd])
                emit({"type": "parallel_done", "count": len(skill_jobs)})

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
                if cmd in _completed_skill_cmds:
                    continue
                skill_name, skill_args = parse_skill_call(cmd)
                if skill_name:
                    skill_args = _skill_args_for_project(skill_name, skill_args)
                    if _target_is_unavailable(skill_name, skill_args):
                        blocked_target = skill_args.get("target", "")
                        emit({"type": "status", "content": f"Omitido {skill_name}: {blocked_target} está marcado como dominio abajo."})
                        all_output.append({
                            "skill": skill_name, "output": "Omitido: dominio sin respuesta en la última verificación.",
                            "success": False, "findings": [],
                        })
                        executed_all.add(cmd)
                        breaker.record([cmd])
                        continue
                    emit({"type": "skill_start", "skill": skill_name, "args": skill_args})
                    try:
                        sr = _run_skill(skill_name, **skill_args)
                        skill_out  = sr.get("output", "")
                        skill_ok   = sr.get("success", False)
                        skill_finds = sr.get("findings", [])
                        emit({"type": "skill_done", "skill": skill_name,
                              "output": skill_out[:12000], "success": skill_ok,
                              "findings": skill_finds[:100],
                              "artifact_root": sr.get("artifact_root", ""),
                              "manifest_file": sr.get("manifest_file", ""),
                              "stats": sr.get("stats", {})})
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

            # Include fetched HTTP responses in the same continuous classification
            # pipeline as command and skill outputs.
            if fetch_result_text:
                all_output.append({
                    "command": f"fetch {fetch_target}",
                    "stdout": fetch_result_text,
                    "stderr": "",
                    "returncode": 0,
                })

            # Every response from this turn is evaluated, including low/info
            # results. The structured verdicts are persisted in ProjectState.
            _classify_turn_output(ps, all_output, emit)

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
            save_session(session_name, conversation, actual_model, project_dir)
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
            # Persist after each iteration so progress survives server restart
            save_session(session_name, conversation, actual_model, project_dir)

        # Save session & project state
        ps.save()
        save_session(session_name, conversation, actual_model, project_dir)
        emit({"type": "done", "session": session_name})

    except Exception as exc:
        emit({"type": "error", "content": str(exc), "fatal": True})
        # Try to save whatever conversation we have so far
        try:
            save_session(session_name, conversation, actual_model, project_dir)
        except Exception:
            pass
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
    if skill_name == "web_asset_mirror":
        # El manifiesto puede ser grande y ya se sirve desde Asset Explorer.
        return
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


def _asset_capture_dir(proj_id: str, capture: str = "") -> tuple[Path, Path]:
    """Resuelve web_assets/capture sin permitir escapes ni symlinks externos."""
    out_root = OUT_DIR.resolve()
    project_dir = (OUT_DIR / proj_id).resolve()
    try:
        project_dir.relative_to(out_root)
    except ValueError:
        abort(403)
    if not project_dir.is_dir():
        abort(404)
    base = (project_dir / "web_assets").resolve()
    base.mkdir(parents=True, exist_ok=True)
    if not capture:
        return base, base
    candidate = (base / capture).resolve()
    try:
        candidate.relative_to(base)
    except ValueError:
        abort(403)
    if not candidate.is_dir():
        abort(404)
    return base, candidate


def _asset_file(proj_id: str, capture: str, relative_path: str) -> tuple[Path, Path]:
    _, capture_dir = _asset_capture_dir(proj_id, capture)
    candidate = (capture_dir / relative_path).resolve()
    try:
        candidate.relative_to(capture_dir)
    except ValueError:
        abort(403)
    if not candidate.is_file():
        abort(404)
    return capture_dir, candidate


@app.route("/api/projects/<proj_id>/assets", methods=["GET"])
def api_asset_captures(proj_id: str):
    base, _ = _asset_capture_dir(proj_id)
    captures = []
    for folder in sorted((p for p in base.iterdir() if p.is_dir()),
                         key=lambda p: p.stat().st_mtime, reverse=True):
        manifest = {}
        manifest_file = folder / "manifest.json"
        if manifest_file.is_file():
            try:
                manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
            except Exception:
                manifest = {}
        stats = manifest.get("stats", {})
        analysis = {}
        analysis_file = folder / "analysis.json"
        if analysis_file.is_file():
            try:
                analysis = json.loads(analysis_file.read_text(encoding="utf-8"))
            except Exception:
                analysis = {}
        captures.append({
            "id": folder.name, "name": folder.name,
            "target": manifest.get("target", ""),
            "created_at": manifest.get("created_at") or datetime.fromtimestamp(folder.stat().st_mtime).isoformat(),
            "stats": stats,
            "analyzed": bool(analysis),
            "analysis_stats": analysis.get("stats", {}),
            "verifier": analysis.get("verifier", {}),
        })
    return jsonify({"captures": captures})


@app.route("/api/projects/<proj_id>/assets/tree", methods=["GET"])
def api_asset_tree(proj_id: str):
    capture = request.args.get("capture", "").strip()
    if not capture:
        return jsonify({"error": "capture required"}), 400
    _, root = _asset_capture_dir(proj_id, capture)
    files = []
    for file in root.rglob("*"):
        if not file.is_file() or file.is_symlink():
            continue
        try:
            relative = file.relative_to(root).as_posix()
            mime = mimetypes.guess_type(file.name)[0] or "application/octet-stream"
            size = file.stat().st_size
        except OSError:
            continue
        is_text = (mime.startswith("text/") or mime in {
            "application/json", "application/javascript", "application/xml",
            "image/svg+xml", "application/manifest+json",
        } or file.suffix.lower() in {".js", ".mjs", ".cjs", ".css", ".map", ".md"})
        files.append({"path": relative, "name": file.name, "size": size,
                      "mime": mime, "is_text": is_text,
                      "is_image": mime.startswith("image/") and mime != "image/svg+xml"})
    files.sort(key=lambda item: (item["path"].count("/"), item["path"].lower()))
    return jsonify({"capture": capture, "files": files, "count": len(files)})


@app.route("/api/projects/<proj_id>/assets/analysis", methods=["GET"])
def api_asset_analysis(proj_id: str):
    capture = request.args.get("capture", "").strip()
    if not capture:
        return jsonify({"error": "capture required"}), 400
    _, root = _asset_capture_dir(proj_id, capture)
    analysis_file = root / "analysis.json"
    if not analysis_file.is_file():
        return jsonify({"capture": capture, "analysis": None})
    try:
        analysis = json.loads(analysis_file.read_text(encoding="utf-8"))
    except Exception as exc:
        return jsonify({"error": f"analysis.json inválido: {exc}"}), 500
    return jsonify({"capture": capture, "analysis": analysis})


@app.route("/api/projects/<proj_id>/assets/analyze", methods=["POST"])
def api_analyze_asset_capture(proj_id: str):
    data = request.get_json(silent=True) or {}
    capture = str(data.get("capture", "")).strip()
    if not capture:
        return jsonify({"error": "capture required"}), 400
    base, _ = _asset_capture_dir(proj_id, capture)
    try:
        max_files = max(1, min(int(data.get("max_files", 500)), 5000))
    except (TypeError, ValueError):
        max_files = 500
    verify_ai = str(data.get("verify_ai", "true")).strip().lower() not in {"0", "false", "no", "off"}
    result = _run_skill(
        "web_asset_mirror", action="analyze", capture=capture,
        output_dir=str(base), ai="true" if verify_ai else "false", max_files=str(max_files),
        model=str(data.get("model", "")).strip(),
        query="inventario completo de rutas, APIs, servidores, parámetros, Firebase, GraphQL y WebSockets",
    )
    if not result.get("success"):
        return jsonify({"error": result.get("output", "No se pudo analizar la captura")}), 500
    analysis = result.get("analysis")
    if not analysis:
        analysis_file = Path(result.get("analysis_file", ""))
        if analysis_file.is_file():
            analysis = json.loads(analysis_file.read_text(encoding="utf-8"))
    return jsonify({
        "capture": capture, "analysis": analysis or {},
        "stats": result.get("stats", {}), "verifier": (analysis or {}).get("verifier", {}),
        "output": result.get("output", "")[:4000],
    })


@app.route("/api/projects/<proj_id>/assets/file", methods=["GET"])
def api_asset_preview(proj_id: str):
    capture = request.args.get("capture", "").strip()
    relative = request.args.get("path", "").strip()
    if not capture or not relative:
        return jsonify({"error": "capture and path required"}), 400
    _, file = _asset_file(proj_id, capture, relative)
    mime = mimetypes.guess_type(file.name)[0] or "application/octet-stream"
    raw_url = (f"/api/projects/{quote(proj_id, safe='')}/assets/raw?"
               f"capture={quote(capture, safe='')}&path={quote(relative, safe='')}")
    if mime.startswith("image/") and mime != "image/svg+xml":
        return jsonify({"kind": "image", "mime": mime, "size": file.stat().st_size,
                        "raw_url": raw_url, "path": relative})
    is_text = (mime.startswith("text/") or mime in {
        "application/json", "application/javascript", "application/xml", "image/svg+xml",
    } or file.suffix.lower() in {".js", ".mjs", ".cjs", ".css", ".map", ".md"})
    if is_text:
        content = file.read_text(encoding="utf-8", errors="replace")
        truncated = len(content) > 500000
        return jsonify({"kind": "text", "mime": mime, "size": file.stat().st_size,
                        "content": content[:500000], "truncated": truncated,
                        "raw_url": raw_url, "path": relative})
    return jsonify({"kind": "binary", "mime": mime, "size": file.stat().st_size,
                    "raw_url": raw_url, "path": relative})


@app.route("/api/projects/<proj_id>/assets/raw", methods=["GET"])
def api_asset_raw(proj_id: str):
    capture = request.args.get("capture", "").strip()
    relative = request.args.get("path", "").strip()
    if not capture or not relative:
        abort(400)
    _, file = _asset_file(proj_id, capture, relative)
    mime = mimetypes.guess_type(file.name)[0] or "application/octet-stream"
    inline_safe = mime.startswith("image/") and mime != "image/svg+xml"
    response = send_file(str(file),
                         as_attachment=request.args.get("download") == "1" or not inline_safe,
                         download_name=file.name)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Security-Policy"] = "sandbox"
    return response


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
    current = database.get_session(sess_name)
    if not current or current.get("project_id") != proj_id:
        return jsonify({"error": "session not found"}), 404
    database.delete_session(sess_name)
    return jsonify({"deleted": [sess_name]})


@app.route("/api/projects/<proj_id>/sessions/<sess_name>/history", methods=["GET"])
def api_chat_history(proj_id: str, sess_name: str):
    project_dir = OUT_DIR / proj_id
    conv, model, _ = load_session_in_project(sess_name, project_dir)
    if conv is None:
        return jsonify({"messages": [], "model": None, "research_mode": False})
    # Return only user/assistant messages (not system)
    messages = [m for m in conv if m["role"] != "system"]
    return jsonify({
        "messages": messages, "model": model,
        "research_mode": bool(database.get_session_setting(sess_name, "research_mode", False)),
    })


@app.route("/api/projects/<proj_id>/sessions/<sess_name>/research-mode", methods=["GET", "PUT"])
def api_research_mode(proj_id: str, sess_name: str):
    current = database.get_session(sess_name)
    if not current or current.get("project_id") != proj_id:
        return jsonify({"error": "session not found"}), 404
    if request.method == "PUT":
        data = request.json or {}
        enabled = bool(data.get("enabled", False))
        database.set_session_setting(sess_name, "research_mode", enabled)
        return jsonify({"enabled": enabled})
    return jsonify({
        "enabled": bool(database.get_session_setting(sess_name, "research_mode", False)),
    })


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
    
    # Session data is database-backed; check there instead of legacy files.
    if database.get_session(safe_new_name):
        return jsonify({"error": "a session with that name already exists"}), 400
    current = database.get_session(sess_name)
    if not current or current.get("project_id") != proj_id:
        return jsonify({"error": "session not found"}), 404
    if not database.rename_session(sess_name, safe_new_name):
        return jsonify({"error": "could not rename session"}), 400
    return jsonify({"old_name": sess_name, "new_name": safe_new_name})


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
        file_paths     = data.get("file_paths", "")
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
                        uploaded_file_paths=file_paths,
                    )
                except Exception as e:
                    streamer.put({"type": "error", "content": str(e), "fatal": True})

            t = threading.Thread(target=_bg, daemon=True)
            _ACTIVE_SESSIONS[session_key] = {"streamer": streamer, "thread": t}
            t.start()

        def generate():
            try:
                for event in streamer.get_iterator(t):
                    if event is None:
                        yield ": keepalive\n\n"
                    else:
                        yield f"data: {json.dumps(event, ensure_ascii=False)}\n\n"
            finally:
                if streamer.is_done and not t.is_alive():
                    _ACTIVE_SESSIONS.pop(session_key, None)

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
    safe_name = re.sub(r"[^\w.\-]", "_", f.filename or "unnamed")[:120]
    # Avoid overwrites: append counter if file exists
    dest = uploads_dir / safe_name
    counter = 1
    stem, ext = (safe_name.rsplit(".", 1) + [""])[:2]
    while dest.exists():
        dest = uploads_dir / f"{stem}_{counter}.{ext}" if ext else uploads_dir / f"{stem}_{counter}"
        counter += 1
    f.save(dest)

    size = dest.stat().st_size
    mt, _ = mimetypes.guess_type(str(dest))
    mime = mt or "application/octet-stream"

    # Determine file kind
    is_text = mime and (mime.startswith("text/") or mime in (
        "application/json", "application/xml", "application/javascript",
        "application/x-yaml", "application/x-sh", "application/x-python",
    ))
    is_apk = ext.lower() == ".apk" or "android" in (mime or "").lower() or "vnd.android" in (mime or "")

    # Read text content for small text files
    content = ""
    if is_text and size < 1_048_576:
        try:
            content = dest.read_text(encoding="utf-8", errors="replace")[:12000]
        except Exception:
            pass

    result = {
        "filename": safe_name,
        "path":     str(dest),
        "size":     size,
        "mime":     mime,
        "content":  content,
        "is_binary": not is_text,
        "is_apk":   is_apk,
    }

    # For APKs, suggest the skill to the front-end
    if is_apk:
        result["hint"] = f"APK detectado. Usa SKILL:apk_analyze target={dest}"

    return jsonify(result)


@app.route("/api/models", methods=["GET"])
def api_models():
    import agent as _ag
    backend = _ag.LLM_BACKEND
    if backend == "auto":
        catalog = get_model_catalog()
        route = select_llm_route("tarea general del agente") if catalog else {}
        ranked = route.get("candidates", [])[:40]
        return jsonify({
            "available": bool(catalog),
            "backend": "auto",
            "backend_name": "Auto IA",
            "fast_mode": True,
            "router": {
                "policy": route.get("policy", os.environ.get("HACKERAGENT_ROUTER_POLICY", "balanced")),
                "default_route": route.get("choice"),
                "reason": route.get("reason", ""),
                "providers": len({item["backend"] for item in catalog}),
            },
            "models": ([{
                "name": "auto", "label": "✨ Automático (recomendado)",
                "stars": 5, "desc": "elige modelo por tarea y aplica fallback",
            }] if catalog else []) + [{
                "name": f"{item['backend']}::{item['model']}",
                "label": f"{item['backend_name']} · {item['model']}",
                "stars": score_model(item["model"])[0],
                "desc": f"fijar preferencia · {item['quality_desc']}",
            } for item in ranked],
        })
    ok, models = check_backend()
    if not ok:
        diagnostic = lmstudio_diagnostics() if backend == "lmstudio" else None
        return jsonify({
            "available": False, "models": [], "backend": backend,
            "backend_name": _backend_display_name(), "diagnostic": diagnostic,
        })
    ranked = sorted(models, key=lambda m: score_model(m)[0], reverse=True)
    return jsonify({
        "available": True,
        "backend":   backend,
        "backend_name": _backend_display_name(),
        "fast_mode": os.environ.get("HACKERAGENT_FAST_MODE") == "1",
        "models":    [{"name": m, "stars": score_model(m)[0], "desc": score_model(m)[1]}
                      for m in ranked],
    })


@app.route("/api/backends", methods=["GET"])
def api_backends():
    """Lista los backends disponibles con su estado online/offline."""
    import agent as _ag
    global _BACKEND_REFRESHING
    cached = _ag._CATALOG_CACHE.get("value")
    catalog = [dict(item) for item in cached] if cached is not None else get_model_catalog()

    # Stale-while-revalidate: los chips aparecen inmediatamente aunque un
    # proveedor cloud tarde varios segundos en responder.
    cache_age = time.time() - float(_ag._CATALOG_CACHE.get("ts", 0))
    if cached is not None and cache_age > 20:
        def _refresh_backends():
            global _BACKEND_REFRESHING
            try:
                get_model_catalog(force=True)
            finally:
                with _BACKEND_REFRESH_LOCK:
                    _BACKEND_REFRESHING = False

        with _BACKEND_REFRESH_LOCK:
            if not _BACKEND_REFRESHING:
                _BACKEND_REFRESHING = True
                threading.Thread(target=_refresh_backends, daemon=True).start()
    grouped = {
        backend: [item["model"] for item in catalog if item["backend"] == backend]
        for backend in ("ollama", "lmstudio", "deepseek", "openrouter")
    }
    ollama_models, lmstudio_models = grouped["ollama"], grouped["lmstudio"]
    deepseek_models, openrouter_models = grouped["deepseek"], grouped["openrouter"]
    ollama_ok, lmstudio_ok = bool(ollama_models), bool(lmstudio_models)
    deepseek_ok, openrouter_ok = bool(deepseek_models), bool(openrouter_models)
    all_count = sum(map(len, (ollama_models, lmstudio_models, deepseek_models, openrouter_models)))
    return jsonify({
        "active": _ag.LLM_BACKEND,
        "backends": [
            {
                "id": "auto",
                "name": "Auto IA",
                "icon": "✨",
                "url": "router://multi-ia",
                "online": all_count > 0,
                "model_count": all_count,
            },
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
            {
                "id": "deepseek",
                "name": "DeepSeek API",
                "icon": "🌐",
                "url": DEEPSEEK_API_URL,
                "online": deepseek_ok,
                "model_count": len(deepseek_models),
            },
            {
                "id": "openrouter",
                "name": "OpenRouter",
                "icon": "🔀",
                "url": OPENROUTER_API_URL,
                "online": openrouter_ok,
                "model_count": len(openrouter_models),
            },
        ]
    })


@app.route("/api/backend/switch", methods=["POST"])
def api_switch_backend():
    """Cambia el backend LLM activo."""
    import agent as _ag
    data = request.json or {}
    new_backend = data.get("backend", "").strip().lower()
    if new_backend not in ("auto", "ollama", "lmstudio", "deepseek", "openrouter"):
        return jsonify({"error": "backend must be auto, ollama, lmstudio, deepseek or openrouter"}), 400
    _ag.LLM_BACKEND = new_backend
    os.environ["HACKERAGENT_LLM_BACKEND"] = new_backend
    _ag._CATALOG_CACHE.update(ts=0.0, value=None)
    if new_backend in ("auto", "deepseek"):
        os.environ["HACKERAGENT_FAST_MODE"] = "1"
    else:
        os.environ.pop("HACKERAGENT_FAST_MODE", None)
    # Return the models for the new backend
    ok, models = check_backend()
    if new_backend == "auto":
        route = select_llm_route("tarea general del agente") if ok else {}
        ranked_items = route.get("candidates", [])[:40]
        model_payload = ([{
            "name": "auto", "label": "✨ Automático (recomendado)",
            "stars": 5, "desc": "elige modelo por tarea y aplica fallback",
        }] if ok else []) + [{
            "name": f"{item['backend']}::{item['model']}",
            "label": f"{item['backend_name']} · {item['model']}",
            "stars": score_model(item["model"])[0], "desc": item["quality_desc"],
        } for item in ranked_items]
    else:
        ranked = sorted(models, key=lambda m: score_model(m)[0], reverse=True) if ok else []
        model_payload = [
            {"name": m, "label": m, "stars": score_model(m)[0], "desc": score_model(m)[1]}
            for m in ranked
        ]
    return jsonify({
        "backend":      new_backend,
        "backend_name": _ag.LLM_BACKEND and _backend_display_name(),
        "available":    ok,
        "models":       model_payload,
    })


@app.route("/api/lmstudio/status", methods=["GET"])
def api_lmstudio_status():
    """Diagnóstico rico de LM Studio para la tarjeta de configuración."""
    force = request.args.get("force", "").lower() in {"1", "true", "yes"}
    result = lmstudio_diagnostics(force=force)
    return jsonify(result), (200 if result.get("online") else 503)


@app.route("/api/lmstudio/test", methods=["POST"])
def api_lmstudio_test():
    """Comprueba conectividad y, opcionalmente, una inferencia mínima real."""
    from lmstudio_client import LMStudioError, lmstudio_chat_text

    data = request.json or {}
    diagnostic = lmstudio_diagnostics()
    if not diagnostic.get("online"):
        return jsonify(diagnostic), 503
    if data.get("deep", True) is False:
        return jsonify({**diagnostic, "inference_ok": None})
    inventory = diagnostic.get("models") or []
    requested = str(data.get("model") or "").strip()
    if "::" in requested:
        provider, requested_model = requested.split("::", 1)
        requested = requested_model if provider == "lmstudio" else ""
    model = requested if any(item.get("id") == requested for item in inventory) else ""
    if not model:
        loaded = next((item for item in inventory if item.get("loaded") is True), None)
        model = (loaded or (inventory[0] if inventory else {})).get("id", "")
    if not model:
        return jsonify({**diagnostic, "inference_ok": False,
                        "error": "No hay un modelo de chat disponible para probar."}), 409
    started = time.perf_counter()
    try:
        answer = lmstudio_chat_text(
            model,
            [{"role": "user", "content": "Responde exactamente: OK"}],
            temperature=0, max_tokens=12, timeout=60,
        )
    except LMStudioError as exc:
        return jsonify({
            **diagnostic, "inference_ok": False, "model_tested": model,
            "error": str(exc), "hint": exc.hint,
        }), 502
    return jsonify({
        **diagnostic, "inference_ok": True, "model_tested": model,
        "inference_ms": round((time.perf_counter() - started) * 1000),
        "response_preview": answer[:120],
    })


@app.route("/api/router/policy", methods=["GET", "POST"])
def api_router_policy():
    """Consulta o cambia la prioridad del router sin reiniciar el servidor."""
    allowed = {
        "balanced": "Equilibrio entre calidad, latencia y ejecución local",
        "quality": "Prioriza el modelo con mayor capacidad",
        "local": "Prioriza Ollama/LM Studio y privacidad",
        "cost": "Prioriza modelos locales o económicos",
    }
    if request.method == "POST":
        policy = str((request.json or {}).get("policy", "")).lower().strip()
        if policy not in allowed:
            return jsonify({"error": f"policy must be one of: {', '.join(allowed)}"}), 400
        os.environ["HACKERAGENT_ROUTER_POLICY"] = policy
    current = os.environ.get("HACKERAGENT_ROUTER_POLICY", "balanced").lower()
    if current not in allowed:
        current = "balanced"
    return jsonify({"policy": current, "policies": allowed})


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
    """Install Python requirements and all missing tools (non-interactive)."""
    try:
        from tool_manager import install_all_dependencies
        return jsonify(install_all_dependencies())
    except Exception as e:
        return jsonify({"error": str(e), "success": False}), 500


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
    # Inject cache-busting version tag so browsers always get the latest
    html_data = html_data.replace(
        "</head>",
        f'<meta name="ha-version" content="{time.time()}"></head>'
    )
    return html_data, 200, {
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "no-cache, no-store, must-revalidate",
        "Pragma": "no-cache",
        "Expires": "0",
    }


# ══════════════════════════════════════════════════════════════════════════════
# Launch
# ══════════════════════════════════════════════════════════════════════════════

def launch(host: str = "0.0.0.0", port: int = 7860, debug: bool = False, verbose: bool = False):
    """Start the HackerAgent web server."""
    import socket
    import agent as _ag

    _ag.VERBOSE = verbose

    # Inventario paralelo compartido por el router y la UI.
    catalog = get_model_catalog(force=True)
    grouped = {
        backend: [item["model"] for item in catalog if item["backend"] == backend]
        for backend in ("ollama", "lmstudio", "deepseek", "openrouter")
    }
    ollama_models, lmstudio_models = grouped["ollama"], grouped["lmstudio"]
    deepseek_models, openrouter_models = grouped["deepseek"], grouped["openrouter"]
    ollama_ok, lmstudio_ok = bool(ollama_models), bool(lmstudio_models)
    deepseek_ok, openrouter_ok = bool(deepseek_models), bool(openrouter_models)

    # Respetar siempre la elección explícita. Antes, arrancar la Web UI podía
    # cambiar silenciosamente de LM Studio a Ollama si ambos respondían.
    if _ag.LLM_BACKEND not in {"auto", "ollama", "lmstudio", "deepseek", "openrouter"}:
        _ag.LLM_BACKEND = "lmstudio"

    os.environ["HACKERAGENT_LLM_BACKEND"] = _ag.LLM_BACKEND
    if _ag.LLM_BACKEND in ("auto", "deepseek"):
        os.environ["HACKERAGENT_FAST_MODE"] = "1"
    else:
        os.environ.pop("HACKERAGENT_FAST_MODE", None)

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

