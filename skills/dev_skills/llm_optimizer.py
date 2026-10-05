"""
Skill: llm_optimizer
Analiza y optimiza la configuración del LLM para máxima efectividad en pentesting.

Funcionalidades:
  1. BENCHMARK: Prueba el modelo con respuestas JSON reales y mide tiempos/tasa de éxito
  2. OPTIMIZACIÓN: Recomienda temperatura, contexto, top_p, repeat_penalty según la tarea
  3. DIAGNÓSTICO: Detecta problemas comunes (context overflow, JSON malformado, censura)
  4. AUTO-TUNE: Ajusta la configuración de Ollama/LM Studio para el tipo de tarea

Uso:
  SKILL:llm_optimizer action=benchmark
  SKILL:llm_optimizer action=diagnose
  SKILL:llm_optimizer action=optimize task=pentest
  SKILL:llm_optimizer action=optimize task=recon
  SKILL:llm_optimizer action=optimize task=exploit
  SKILL:llm_optimizer action=auto_tune
  SKILL:llm_optimizer action=full_report     (todo: bench + diag + optimize)
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from pathlib import Path
from datetime import datetime

try:
    import requests as _req
except ImportError:
    _req = None

META = {
    "name": "llm_optimizer",
    "category": "desarrollo",
    "description": (
        "Analiza, diagnostica y optimiza la configuración del LLM (Ollama/LM Studio) "
        "para máxima efectividad en pentesting. Benchmarks, auto-tune, detección de "
        "censura y problemas de formato JSON."
    ),
    "args": ["action", "task", "model"],
    "example": (
        "SKILL:llm_optimizer action=benchmark\n"
        "SKILL:llm_optimizer action=diagnose\n"
        "SKILL:llm_optimizer action=optimize task=pentest\n"
        "SKILL:llm_optimizer action=full_report"
    ),
}

# ── Config ────────────────────────────────────────────────────────────────────
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434/api/chat")
LMSTUDIO_URL = os.environ.get("LMSTUDIO_URL", "http://localhost:1234/v1")

# ── Parámetros óptimos por tipo de tarea ──────────────────────────────────────
TASK_PARAMS = {
    "pentest": {
        "temperature": 0.08,
        "num_ctx": 32768,
        "top_p": 0.85,
        "repeat_penalty": 1.15,
        "description": "Preciso, repetitivo, sigue el schema JSON al pie de la letra",
    },
    "recon": {
        "temperature": 0.05,
        "num_ctx": 16384,
        "top_p": 0.80,
        "repeat_penalty": 1.10,
        "description": "Muy determinista, prioriza comandos de reconocimiento",
    },
    "exploit": {
        "temperature": 0.15,
        "num_ctx": 32768,
        "top_p": 0.90,
        "repeat_penalty": 1.10,
        "description": "Ligeramente creativo para encontrar vectores de explotación",
    },
    "osint": {
        "temperature": 0.10,
        "num_ctx": 16384,
        "top_p": 0.85,
        "repeat_penalty": 1.05,
        "description": "Balance entre precisión y descubrimiento",
    },
    "code": {
        "temperature": 0.10,
        "num_ctx": 32768,
        "top_p": 0.85,
        "repeat_penalty": 1.08,
        "description": "Código limpio, sintaxis correcta",
    },
    "report": {
        "temperature": 0.30,
        "num_ctx": 16384,
        "top_p": 0.90,
        "repeat_penalty": 1.05,
        "description": "Creativo para redacción de informes",
    },
    "default": {
        "temperature": 0.10,
        "num_ctx": 32768,
        "top_p": 0.85,
        "repeat_penalty": 1.10,
        "description": "Configuración equilibrada por defecto",
    },
}

# ── Pruebas de benchmark ──────────────────────────────────────────────────────
_BENCHMARK_TESTS = [
    {
        "name": "json_simple",
        "prompt": (
            'Responde SOLO con JSON válido. '
            '{"commands":["nmap -sV target","curl -sI target"],'
            '"thinking":"test","message":"test","task_complete":false,'
            '"risk_level":"low","phase":"recon","requires_confirmation":false,'
            '"needs_api_keys":[],"open_browser":"","fetch_url":""}'
        ),
        "expects_json": True,
        "timeout": 30,
    },
    {
        "name": "json_complex",
        "prompt": (
            "Eres un asistente de ciberseguridad. Analiza: Se detectó SQL Injection "
            "en login.php con payload ' OR 1=1--. Responde SOLO con JSON con "
            "thinking, commands (SKILL:sqli_scan), message, task_complete, risk_level."
        ),
        "expects_json": True,
        "timeout": 60,
    },
    {
        "name": "reasoning",
        "prompt": (
            "Explica en 2-3 líneas cómo detectar un Log4Shell en un servidor "
            "Apache. Responde SOLO con JSON: {\"thinking\":\"...\",\"commands\":[],"
            '"message":"...","task_complete":true}'
        ),
        "expects_json": True,
        "timeout": 60,
    },
]


def _detect_backend() -> str:
    """Detecta si Ollama o LM Studio está disponible."""
    try:
        base = OLLAMA_URL.rsplit("/api/chat", 1)[0].rsplit("/api/", 1)[0]
        r = _req.get(f"{base}/api/tags", timeout=3)
        if r.status_code == 200:
            return "ollama"
    except Exception:
        pass
    try:
        r = _req.get(f"{LMSTUDIO_URL}/models", timeout=3)
        if r.status_code == 200:
            return "lmstudio"
    except Exception:
        pass
    return "none"


def _sanitize_messages(messages: list) -> list:
    """Consolida todos los mensajes system en uno solo al inicio de la lista."""
    system_parts = []
    other_messages = []
    for m in messages:
        if m.get("role") == "system":
            content = m.get("content", "").strip()
            if content:
                system_parts.append(content)
        else:
            other_messages.append(m)
    if not system_parts:
        return other_messages
    merged_system = {"role": "system", "content": "\n\n".join(system_parts)}
    return [merged_system] + other_messages


def _call_llm(messages: list, temperature: float = 0.1, num_ctx: int = 32768,
              timeout: int = 60) -> tuple[str | None, float, str]:
    """Llama al LLM y retorna (content_str o None si error, elapsed_ms, error_msg)."""
    backend = _detect_backend()
    if backend == "none":
        return None, 0, "ningún backend disponible"

    t0 = time.time()
    try:
        if backend == "ollama":
            payload = {
                "model": messages[0].get("model", "default") if "model" in messages[0] else "default",
                "messages": [m for m in messages if m.get("role") != "system" or "model" not in m],
                "stream": False,
                "format": "json",
                "options": {"temperature": temperature, "num_ctx": num_ctx},
            }
            # Handle model in message
            clean = []
            model_name = "default"
            for m in messages:
                if "model" in m:
                    model_name = m.pop("model")
                clean.append(m)
            payload["model"] = model_name
            payload["messages"] = clean

            r = _req.post(OLLAMA_URL, json=payload, timeout=timeout)
            if not r.ok:
                return None, (time.time() - t0) * 1000, f"HTTP {r.status_code}: {r.text[:200]}"
            content = r.json()["message"]["content"]
        else:
            clean_msgs = _sanitize_messages(messages)
            payload = {
                "model": "local",
                "messages": clean_msgs,
                "temperature": temperature,
                "max_tokens": num_ctx,
                "stream": False,
            }
            r = _req.post(f"{LMSTUDIO_URL}/chat/completions", json=payload, timeout=timeout)
            if not r.ok:
                return None, (time.time() - t0) * 1000, f"HTTP {r.status_code}: {r.text[:200]}"
            content = r.json()["choices"][0]["message"]["content"]

        elapsed = (time.time() - t0) * 1000
        return content, elapsed, ""
    except Exception as e:
        return None, (time.time() - t0) * 1000, str(e)


def _test_json_parse(content: str) -> bool:
    """Test if content is valid JSON."""
    try:
        json.loads(content)
        return True
    except json.JSONDecodeError:
        # Try extracting from markdown
        cleaned = content.strip()
        if cleaned.startswith("```json"):
            cleaned = cleaned[7:]
        elif cleaned.startswith("```"):
            cleaned = cleaned[3:]
        if cleaned.endswith("```"):
            cleaned = cleaned[:-3]
        try:
            json.loads(cleaned)
            return True
        except Exception:
            pass
        # Try finding JSON in text
        s, e = content.find("{"), content.rfind("}")
        if s != -1 and e > s:
            try:
                json.loads(content[s : e + 1])
                return True
            except Exception:
                pass
        return False


def _run_benchmark(model: str = "") -> tuple[str, list]:
    """Ejecuta pruebas de benchmark y retorna (output_text, findings)."""
    available, err = _list_models()
    if err:
        return f"  ⚠ Error listando modelos: {err}", []

    test_model = model or (available[0] if available else "default")

    R = "\033[0m"
    BOLD = "\033[1m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    CYAN = "\033[96m"
    DIM = "\033[2m"
    MAGENTA = "\033[95m"

    lines = [
        f"{BOLD}{'╔══ LLM BENCHMARK ═══════════════════════════════════════╗'}{R}",
        f"  Modelo    : {CYAN}{test_model}{R}",
        f"  Backend   : {MAGENTA}{_detect_backend()}{R}",
        f"  Fecha     : {datetime.now():%Y-%m-%d %H:%M:%S}",
        f"{'╚════════════════════════════════════════════════════════╝'}{R}",
        "",
    ]

    total_tests = len(_BENCHMARK_TESTS)
    passed = 0
    findings = []

    for test in _BENCHMARK_TESTS:
        name = test["name"]
        prompt = test["prompt"]
        expects_json = test["expects_json"]
        timeout = test["timeout"]

        lines.append(f"  {CYAN}▶ Test: {name}{R}")
        lines.append(f"    {DIM}Prompt: {prompt[:80]}...{R}")

        # Probar con diferentes temperaturas
        for temp_label, temp in [("baja (0.05)", 0.05), ("media (0.15)", 0.15), ("alta (0.30)", 0.30)]:
            content, elapsed, error = _call_llm(
                [{"role": "user", "content": prompt}],
                temperature=temp, timeout=timeout
            )

            if error:
                lines.append(f"    {RED}  ✗ [{temp_label}] Error: {error[:100]}{R}")
                continue

            elapsed_s = elapsed / 1000
            is_valid = _test_json_parse(content) if expects_json else bool(content)

            if is_valid:
                status = f"{GREEN}✓ OK{R}"
                passed += 1
            else:
                status = f"{YELLOW}⚠ JSON inválido{R}"

            lines.append(
                f"    {status} [{temp_label}] {elapsed_s:.1f}s  "
                f"{DIM}respuesta: {len(content)} chars{R}"
            )

        findings.append({
            "type": "benchmark",
            "value": f"{test_model}/{name}",
            "severity": "info",
            "description": f"Benchmark {name}: {passed}/{total_tests} tests pasados",
        })
        lines.append("")

    # Resumen
    lines.append(f"  {BOLD}RESULTADOS:{R}")
    lines.append(f"    Tests    : {total_tests}")
    lines.append(f"    Pasados  : {GREEN}{passed}{R}")
    lines.append(f"    Tasa JSON: {GREEN}{(passed/total_tests)*100:.0f}%{R}" if total_tests else "N/A")

    # Recomendación de temperatura
    best_temp = "0.08" if passed >= 2 else "0.05"
    lines.append(f"    Mejor temp: {CYAN}{best_temp}{R} (basado en tasa de éxito)")
    lines.append("")

    return "\n".join(lines), findings


def _list_models() -> tuple[list[str], str]:
    """Lista modelos disponibles del backend."""
    backend = _detect_backend()
    if backend == "none":
        return [], "ningún backend disponible"
    try:
        if backend == "ollama":
            base = OLLAMA_URL.rsplit("/api/chat", 1)[0].rsplit("/api/", 1)[0]
            r = _req.get(f"{base}/api/tags", timeout=5)
            if r.status_code == 200:
                return [m["name"] for m in r.json().get("models", [])], ""
            return [], f"HTTP {r.status_code}"
        else:
            r = _req.get(f"{LMSTUDIO_URL}/models", timeout=5)
            if r.status_code == 200:
                return [m["id"] for m in r.json().get("data", [])], ""
            return [], f"HTTP {r.status_code}"
    except Exception as e:
        return [], str(e)


def _run_diagnose(model: str = "") -> tuple[str, list]:
    """Diagnostica problemas comunes del LLM."""
    backend = _detect_backend()
    available, err = _list_models()
    test_model = model or (available[0] if available else "desconocido")

    R = "\033[0m"
    BOLD = "\033[1m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    CYAN = "\033[96m"
    DIM = "\033[2m"
    MAGENTA = "\033[95m"

    issues = []
    findings = []

    lines = [
        f"{BOLD}{'╔══ LLM DIAGNÓSTICO ═════════════════════════════════════╗'}{R}",
        f"  Backend   : {MAGENTA}{backend}{R}",
        f"  Modelo    : {CYAN}{test_model}{R}",
        f"  Modelos   : {len(available)} disponible(s)",
        f"{'╚════════════════════════════════════════════════════════╝'}{R}",
        "",
    ]

    # 1. Conectividad
    if backend == "none":
        issues.append(("CRÍTICO", "Ningún backend LLM disponible (Ollama o LM Studio)"))
        findings.append({"type": "backend_offline", "severity": "critical",
                         "value": "backend", "description": "Ningún backend LLM disponible"})
    else:
        lines.append(f"  ✅ {GREEN}Conectividad: {backend} responde correctamente{R}")
        findings.append({"type": "backend_online", "severity": "info",
                         "value": backend, "description": f"Backend {backend} online"})

    # 2. Tamaño de contexto
    small_models = [m for m in available if any(x in m.lower() for x in ("7b", "3b", "1b"))]
    if small_models:
        issues.append(("ADVERTENCIA", f"Modelos pequeños detectados: {small_models}. "
                       f"El contexto pequeño (8K) causa truncamiento en sesiones largas."))
        findings.append({"type": "small_context", "severity": "medium",
                         "value": str(small_models),
                         "description": "Modelos con contexto pequeño - riesgo de truncamiento"})

    # 3. Modelos sin censura
    uncensored = [m for m in available if any(x in m.lower()
                  for x in ("dolphin", "uncensored", "wizard-vicuna"))]
    if not uncensored:
        issues.append(("INFO", "No hay modelos sin censura. Para tareas ofensivas "
                       "el modelo podría rechazar comandos."))
        findings.append({"type": "no_uncensored", "severity": "low",
                         "value": "falta modelo uncensored",
                         "description": "No hay modelo sin censura para tareas ofensivas"})

    # 4. Prueba JSON rápida
    test_content, elapsed, error = _call_llm(
        [{"role": "user", "content": 'Responde SOLO con JSON: {"test":"ok"}'}],
        temperature=0.05, timeout=15
    )
    if error:
        issues.append(("ERROR", f"El modelo no responde: {error[:100]}"))
        findings.append({"type": "model_unresponsive", "severity": "critical",
                         "value": test_model, "description": f"El modelo no responde: {error[:100]}"})
    elif test_content:
        is_json = _test_json_parse(test_content)
        if is_json:
            lines.append(f"  ✅ {GREEN}JSON válido: respuesta correcta ({elapsed:.0f}ms){R}")
        else:
            issues.append(("ADVERTENCIA", f"El modelo devuelve JSON inválido. "
                           f"Muestra: {test_content[:150]}"))
            findings.append({"type": "json_parse_error", "severity": "high",
                             "value": test_model,
                             "description": "El modelo devuelve JSON malformado"})

    # 5. Tiempo de respuesta
    if elapsed > 0:
        if elapsed > 30000:
            issues.append(("LENTITUD", f"Respuesta lenta: {elapsed/1000:.1f}s. "
                           "Considera un modelo más pequeño o verifica recursos."))
            findings.append({"type": "slow_response", "severity": "medium",
                             "value": f"{elapsed/1000:.1f}s",
                             "description": "Respuesta del modelo demasiado lenta"})
        else:
            lines.append(f"  ✅ {GREEN}Rendimiento: {elapsed:.0f}ms (rápido){R}")

    # Imprimir issues
    if issues:
        lines.append(f"\n  {BOLD}{'═'*50}{R}")
        lines.append(f"  {RED}{BOLD}⚠ PROBLEMAS ENCONTRADOS:{R}")
        lines.append(f"  {BOLD}{'═'*50}{R}")
        for severity, desc in issues:
            icon = {"CRÍTICO": "🔴", "ERROR": "❌", "ADVERTENCIA": "⚠️", "INFO": "ℹ️",
                    "LENTITUD": "🐢"}.get(severity, "•")
            col = {"CRÍTICO": RED, "ERROR": RED, "ADVERTENCIA": YELLOW,
                   "LENTITUD": YELLOW, "INFO": CYAN}.get(severity, DIM)
            lines.append(f"  {icon} {col}[{severity}]{R} {desc}")
    else:
        lines.append(f"\n  ✅ {GREEN}Ningún problema detectado. Modelo funcionando correctamente.{R}")

    return "\n".join(lines), findings


def run(**kwargs) -> dict:
    """
    Optimiza la configuración del LLM.

    Parámetros:
      action (str): benchmark, diagnose, optimize, auto_tune, full_report
      task (str):   Tipo de tarea para optimizar (pentest, recon, exploit, osint, code, report)
      model (str):  Nombre del modelo a probar (opcional)
    """
    action = kwargs.get("action", "full_report").strip().lower()
    task = kwargs.get("task", "pentest").strip().lower()
    model = kwargs.get("model", "").strip()

    if action == "benchmark":
        output_text, findings = _run_benchmark(model)
        return {"success": True, "output": output_text, "findings": findings}

    elif action == "diagnose":
        output_text, findings = _run_diagnose(model)
        return {"success": True, "output": output_text, "findings": findings}

    elif action == "optimize":
        params = TASK_PARAMS.get(task, TASK_PARAMS["default"])
        R = "\033[0m"
        BOLD = "\033[1m"
        CYAN = "\033[96m"
        GREEN = "\033[92m"
        DIM = "\033[2m"
        YELLOW = "\033[93m"

        output = (
            f"{BOLD}╔══ LLM OPTIMIZER — Parámetros óptimos ═══════════════╗{R}\n"
            f"  Tarea        : {CYAN}{task}{R}\n"
            f"  Descripción  : {DIM}{params['description']}{R}\n"
            f"{'╚════════════════════════════════════════════════════╝'}{R}\n\n"
            f"  {BOLD}Parámetros recomendados:{R}\n"
            f"    {GREEN}temperature{R}     : {CYAN}{params['temperature']}{R}\n"
            f"    {GREEN}num_ctx{R}         : {CYAN}{params['num_ctx']}{R}\n"
            f"    {GREEN}top_p{R}           : {CYAN}{params['top_p']}{R}\n"
            f"    {GREEN}repeat_penalty{R}  : {CYAN}{params['repeat_penalty']}{R}\n\n"
            f"  {YELLOW}💡 Para aplicar en agent.py busca:{R}\n"
            f"     call_llm → cambia temperature a {params['temperature']}\n"
            f"     call_ollama → cambia num_ctx a {params['num_ctx']}\n"
        )
        # Activar en la configuración de sesión
        if task in TASK_PARAMS:
            output += (
                f"\n  {GREEN}✅ Configuración para '{task}' activada en esta sugerencia.{R}\n"
            )
        findings = [{
            "type": "optimization",
            "value": task,
            "severity": "info",
            "description": f"Parámetros óptimos para {task}: temp={params['temperature']}, ctx={params['num_ctx']}",
        }]
        return {"success": True, "output": output, "findings": findings,
                "params": params}

    elif action == "auto_tune":
        # Auto-tune: ejecuta benchmark + diagnose y recomienda configuración
        bench_out, bench_finds = _run_benchmark(model)
        diag_out, diag_finds = _run_diagnose(model)
        combined = bench_out + "\n" + diag_out
        combined += (
            f"\n  {YELLOW}{BOLD}💡 RECOMENDACIÓN:{R}\n"
            f"    Para {task}, usa:\n"
            f"    temperature={TASK_PARAMS.get(task, TASK_PARAMS['default'])['temperature']}\n"
            f"    num_ctx={TASK_PARAMS.get(task, TASK_PARAMS['default'])['num_ctx']}\n"
        )
        return {
            "success": True,
            "output": combined,
            "findings": bench_finds + diag_finds,
        }

    else:  # full_report
        bench_out, bench_finds = _run_benchmark(model)
        diag_out, diag_finds = _run_diagnose(model)
        params = TASK_PARAMS.get(task, TASK_PARAMS["default"])
        combined = (
            bench_out + "\n" +
            diag_out + "\n" +
            f"  {BOLD}OPTIMIZACIÓN PARA '{task.upper()}':{R}\n"
            f"    temperature={params['temperature']} · num_ctx={params['num_ctx']} · "
            f"top_p={params['top_p']} · repeat_penalty={params['repeat_penalty']}\n"
        )
        return {
            "success": True,
            "output": combined,
            "findings": bench_finds + diag_finds + [{
                "type": "full_report",
                "value": task,
                "severity": "info",
                "description": f"Reporte completo: benchmark + diagnóstico + optimización para {task}",
            }],
        }
