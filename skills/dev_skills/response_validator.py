"""
Skill: response_validator
Valida, corrige y optimiza las respuestas del LLM para garantizar JSON válido
y comandos ejecutables. Es el guardián de calidad entre el modelo y la ejecución.

Funcionalidades:
  1. VALIDATE: Valida una respuesta JSON del LLM y reporta problemas
  2. FIX: Intenta corregir automáticamente JSON malformado
  3. ENSURE_KEYS: Verifica que el JSON tenga todas las claves requeridas
  4. SANITIZE: Limpia comandos (quita rutas inválidas, corrige SKILL: calls)
  5. QUALITY_SCORE: Puntúa la calidad de la respuesta (0-100)

Uso:
  SKILL:response_validator action=validate json='{"thinking":"...","commands":[]}'
  SKILL:response_validator action=fix json='{"thinking:test,commands:[]}'
  SKILL:response_validator action=ensure_keys json='{"commands":["nmap"]}'
  SKILL:response_validator action=sanitize json='{"commands":["nuclei -u {{URL}}"]}'
  SKILL:response_validator action=quality_score json='{"thinking":"...","commands":[]}'
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

META = {
    "name": "response_validator",
    "category": "desarrollo",
    "description": (
        "Valida, corrige y optimiza las respuestas JSON del LLM. Garantiza que "
        "los comandos sean ejecutables y el JSON sea parseable. Mejora la tasa "
        "de éxito de las respuestas del modelo."
    ),
    "args": ["action", "json"],
    "example": (
        "SKILL:response_validator action=validate json='{\"commands\":[\"nmap\"]}'\n"
        "SKILL:response_validator action=fix json='{broken json}'\n"
        "SKILL:response_validator action=quality_score json='{\"commands\":[]}'"
    ),
}

# ── Claves requeridas en el JSON de respuesta ─────────────────────────────────
REQUIRED_KEYS = {
    "thinking": (str, "El razonamiento interno del agente"),
    "commands": (list, "Lista de comandos a ejecutar"),
    "message": (str, "Mensaje para el usuario"),
    "requires_confirmation": (bool, "Si requiere confirmación"),
    "task_complete": (bool, "Si la tarea está completa"),
    "risk_level": (str, "Nivel de riesgo: low|medium|high|critical"),
    "phase": (str, "Fase: recon|scan|exploit|post-exploit|report"),
}

OPTIONAL_KEYS = {
    "needs_api_keys": (list, "API keys necesarias"),
    "open_browser": (str, "URL a abrir en el navegador"),
    "fetch_url": (str, "URL a fetch"),
}

VALID_RISK = ("low", "medium", "high", "critical")
VALID_PHASE = ("recon", "scan", "exploit", "post-exploit", "report")


def _fix_json(raw: str) -> tuple[str | None, list[str]]:
    """
    Intenta corregir JSON malformado.
    Retorna (json_corregido, lista_de_correcciones_aplicadas).
    """
    corrections = []
    content = raw.strip()

    if not content:
        return None, ["input vacío"]

    # Remove BOM and other invisible chars
    content = content.strip('\ufeff').strip()

    # Case 1: wrapped in ```json ... ```
    if content.startswith("```"):
        corrections.append("eliminado bloque markdown ```")
        if content.startswith("```json"):
            content = content[7:]
        else:
            content = content[3:]
        if content.endswith("```"):
            content = content[:-3]
        content = content.strip()

    # Case 2: wrapped in ``` ... ``` (no language tag)
    if content.startswith("```") and content.endswith("```"):
        corrections.append("eliminado bloque ``` sin tag")
        content = content[3:-3].strip()

    # Case 3: text before first { or after last }
    first_brace = content.find("{")
    last_brace = content.rfind("}")
    if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
        before = content[:first_brace].strip()
        after = content[last_brace + 1:].strip()
        if before:
            corrections.append(f"eliminado texto antes del JSON ({len(before)} chars)")
        if after:
            corrections.append(f"eliminado texto después del JSON ({len(after)} chars)")
        content = content[first_brace:last_brace + 1]

    # Case 4: single quotes instead of double quotes
    # Try to parse first
    try:
        json.loads(content)
        return content, corrections
    except json.JSONDecodeError:
        pass

    # Replace single quotes with double quotes
    # Step 1: quoted keys: 'key': or 'key' :
    fixed = re.sub(r"'([^']+)'\s*:", r'"\1":', content)
    # Step 2: quoted string values:  : 'value' or :'value'
    fixed = re.sub(r":\s*'([^']*)'\s*", r': "\1" ', fixed)
    # Step 3: quoted values in arrays: ['a','b']
    fixed = re.sub(r"'([^']*)'", r'"\1"', fixed)
    if fixed != content:
        corrections.append("reemplazadas comillas simples por dobles")
        content = fixed

    # Case 5: trailing commas in objects/arrays
    content = re.sub(r',\s*}', '}', content)
    content = re.sub(r',\s*\]', ']', content)
    corrections.append("eliminadas comas finales")

    # Case 6: unquoted keys (Python-style)
    content = re.sub(r'([{,]\s*)(\w+)(\s*:)', r'\1"\2"\3', content)
    corrections.append("entrecomilladas keys sin comillas")

    # Case 6b: unquoted string values after colon
    content = re.sub(r':\s*([a-zA-Z_][a-zA-Z0-9_]*)([\s,}\]])', r': "\1"\2', content)
    corrections.append("entrecomillados valores string sin comillas")

    # Case 6c: unquoted values inside arrays: [value1,value2]
    content = re.sub(r'\[\s*([a-zA-Z_][a-zA-Z0-9_.]*)\s*\]', r'["\1"]', content)
    corrections.append("entrecomillados valores dentro de arrays")

    # Case 7: boolean/null normalization
    content = re.sub(r':\s*True\b', ': true', content)
    content = re.sub(r':\s*False\b', ': false', content)
    content = re.sub(r':\s*None\b', ': null', content)
    content = re.sub(r':\s*null\b', ': null', content)
    corrections.append("normalizados booleanos (True→true, Null→null)")

    # Try parsing again
    try:
        json.loads(content)
        return content, corrections
    except json.JSONDecodeError:
        pass

    # Case 8: truncated JSON — try to close it
    if content.count("{") > content.count("}"):
        content += "}" * (content.count("{") - content.count("}"))
        corrections.append("cerrados objetos JSON sin cerrar")
    if content.count("[") > content.count("]"):
        content += "]" * (content.count("[") - content.count("]"))
        corrections.append("cerrados arrays JSON sin cerrar")

    # Try one more time
    try:
        json.loads(content)
        return content, corrections
    except json.JSONDecodeError:
        return None, corrections


def _validate_commands(commands: list) -> list[dict]:
    """Valida cada comando y reporta problemas."""
    issues = []
    for i, cmd in enumerate(commands):
        if not isinstance(cmd, str):
            issues.append({"index": i, "cmd": str(cmd), "issue": "no es string"})
            continue
        if not cmd.strip():
            issues.append({"index": i, "cmd": "(vacío)", "issue": "comando vacío"})
            continue
        # Check for placeholder variables
        placeholders = re.findall(r'\{\{[^}]+\}\}', cmd)
        if placeholders:
            issues.append({
                "index": i, "cmd": cmd[:80],
                "issue": f"contiene placeholders sin sustituir: {placeholders}",
            })
        # Check for dangerous patterns
        dangerous = re.findall(r'(rm\s+-rf\s+/\s*|:(){ :|:& };:\s*|mkfs\.\w+\s+/dev/)', cmd, re.I)
        if dangerous:
            issues.append({
                "index": i, "cmd": cmd[:80],
                "issue": f"comando potencialmente destructivo: {dangerous[0][:50]}",
            })
    return issues


def _quality_score(data: dict) -> dict:
    """Puntúa la calidad de una respuesta del LLM (0-100)."""
    score = 100

    # Penalización por JSON inválido (esto no debería llegar aquí)
    score -= 20

    # Penalización por campos faltantes
    for key in REQUIRED_KEYS:
        if key not in data:
            score -= 5

    # Penalización por comandos vacíos con task_complete=False
    commands = data.get("commands", [])
    task_done = data.get("task_complete", False)
    if not commands and not task_done:
        score -= 15

    # Bono por comandos útiles
    if len(commands) > 0:
        score += 5
    if len(commands) > 2:
        score += 5

    # Penalización por risk_level inapropiado
    risk = data.get("risk_level", "")
    if risk not in VALID_RISK:
        score -= 5

    # Penalización por fase incorrecta
    phase = data.get("phase", "")
    if phase not in VALID_PHASE:
        score -= 5

    # Penalización por message vacío o demasiado largo
    msg = data.get("message", "")
    if not msg:
        score -= 10
    elif len(msg) > 500:
        score -= 5

    # Penalización por thinking vacío
    thinking = data.get("thinking", "")
    if not thinking:
        score -= 5
    elif len(thinking) < 10:
        score -= 3

    # Placeholders sin sustituir
    for cmd in commands:
        if isinstance(cmd, str) and "{{" in cmd:
            score -= 10

    # Bono por usar SKILL: commands
    skill_count = sum(1 for c in commands if isinstance(c, str) and "SKILL:" in c)
    score += min(skill_count * 3, 10)

    return {
        "score": max(0, min(100, score)),
        "breakdown": {
            "campos_faltantes": 5 * sum(1 for k in REQUIRED_KEYS if k not in data),
            "comandos_vacios": 15 if (not commands and not task_done) else 0,
            "calidad_comandos": min(len(commands) * (5 if len(commands) > 2 else 2.5), 10),
            "riesgo_invalido": 5 if risk not in VALID_RISK else 0,
            "fase_invalida": 5 if phase not in VALID_PHASE else 0,
            "mensaje": (10 if not msg else 5 if len(msg) > 500 else 0),
            "razonamiento": (5 if not thinking else 3 if len(thinking) < 10 else 0),
            "placeholders": 10 * sum(1 for c in commands if isinstance(c, str) and "{{" in c),
            "bono_skills": min(skill_count * 3, 10),
        },
    }


def run(**kwargs) -> dict:
    """
    Valida y corrige respuestas del LLM.

    Parámetros:
      action (str): validate, fix, ensure_keys, sanitize, quality_score
      json (str):   JSON string a validar/corregir
    """
    action = kwargs.get("action", "validate").strip().lower()
    json_str = kwargs.get("json", "").strip()

    if not json_str:
        return {
            "success": False,
            "output": "Proporciona un JSON string para validar.\n\n"
                      "Ej: SKILL:response_validator action=validate json='{\"commands\":[]}'",
            "findings": [],
        }

    R = "\033[0m"
    BOLD = "\033[1m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    CYAN = "\033[96m"
    DIM = "\033[2m"

    # ── ACTION: fix ──────────────────────────────────────────────────────────
    if action == "fix":
        fixed, corrections = _fix_json(json_str)

        output = (
            f"{BOLD}{'╔══ RESPONSE FIXER ═══════════════════════════════════════╗'}{R}\n"
        )

        if fixed is None:
            output += (
                f"  {RED}✗ No se pudo corregir el JSON{R}\n"
                f"  Correcciones intentadas: {corrections or 'ninguna'}\n"
                f"{'╚═════════════════════════════════════════════════════════╝'}{R}\n"
                f"\n  Input original:\n  {DIM}{json_str[:500]}{R}\n"
            )
            return {"success": False, "output": output, "findings": []}

        output += (
            f"  {GREEN}✅ JSON corregido exitosamente{R}\n"
            f"  Correcciones: {', '.join(corrections) if corrections else 'ninguna necesaria'}\n"
            f"{'╚═════════════════════════════════════════════════════════╝'}{R}\n"
            f"\n  JSON corregido:\n  {DIM}{fixed[:1000]}{R}\n"
        )
        if len(fixed) > 1000:
            output += f"\n  {YELLOW}...({len(fixed)} chars totales){R}\n"

        return {
            "success": True,
            "output": output,
            "findings": [{
                "type": "json_fixed",
                "value": f"{len(corrections)} correcciones",
                "severity": "info",
                "description": f"JSON corregido: {', '.join(corrections[:5])}",
            }],
            "fixed_json": fixed,
        }

    # ── Parsear JSON primero para las demás acciones ─────────────────────────
    parsed = None
    parse_errors = []
    try:
        parsed = json.loads(json_str)
    except json.JSONDecodeError:
        # Try to fix it first
        fixed, corrections = _fix_json(json_str)
        if fixed:
            try:
                parsed = json.loads(fixed)
                parse_errors.append(f"corregido automáticamente ({'; '.join(corrections[:3])})")
            except json.JSONDecodeError as e:
                parse_errors.append(str(e))
        else:
            parse_errors.append("no se pudo parsear ni corregir")

    # ── ACTION: validate ─────────────────────────────────────────────────────
    if action == "validate":
        if parsed is None:
            output = (
                f"{BOLD}{'╔══ RESPONSE VALIDATOR ═════════════════════════════════╗'}{R}\n"
                f"  {RED}✗ JSON inválido{R}\n"
                f"  Error: {parse_errors[0] if parse_errors else 'desconocido'}\n"
                f"{'╚═════════════════════════════════════════════════════════╝'}{R}\n"
            )
            return {"success": False, "output": output, "findings": []}

        missing_keys = [k for k in REQUIRED_KEYS if k not in parsed]
        extra_keys = [k for k in parsed if k not in REQUIRED_KEYS and k not in OPTIONAL_KEYS]
        type_errors = []
        for key, (expected_type, _) in REQUIRED_KEYS.items():
            if key in parsed and not isinstance(parsed[key], expected_type):
                type_errors.append(f"{key}: esperado {expected_type.__name__}, recibido {type(parsed[key]).__name__}")

        cmd_issues = _validate_commands(parsed.get("commands", []))

        risk = parsed.get("risk_level", "")
        if risk not in VALID_RISK:
            type_errors.append(f"risk_level: '{risk}' no válido (use: {', '.join(VALID_RISK)})")

        phase = parsed.get("phase", "")
        if phase not in VALID_PHASE:
            type_errors.append(f"phase: '{phase}' no válida (use: {', '.join(VALID_PHASE)})")

        errors_total = len(missing_keys) + len(type_errors) + len(cmd_issues)
        status_icon = f"{GREEN}✅" if errors_total == 0 else f"{YELLOW}⚠️" if errors_total < 4 else f"{RED}❌"

        output = (
            f"{BOLD}{'╔══ RESPONSE VALIDATOR ═════════════════════════════════╗'}{R}\n"
            f"  {status_icon} Resultado: {errors_total} problema(s)\n"
            f"{'╚═════════════════════════════════════════════════════════╝'}{R}\n"
        )

        if parse_errors:
            output += f"\n  {YELLOW}⚠ Parse: {parse_errors[0]}{R}\n"

        if missing_keys:
            output += f"\n  {RED}❌ Claves faltantes:{R}\n"
            for k in missing_keys:
                output += f"    · {k} ({REQUIRED_KEYS[k][1]})\n"

        if type_errors:
            output += f"\n  {YELLOW}⚠️  Errores de tipo/valor:{R}\n"
            for e in type_errors:
                output += f"    · {e}\n"

        if cmd_issues:
            output += f"\n  {YELLOW}⚠️  Problemas en comandos:{R}\n"
            for ci in cmd_issues:
                output += f"    · [{ci['index']}] {ci['cmd'][:60]} — {ci['issue']}\n"

        if errors_total == 0:
            output += f"\n  {GREEN}✅ JSON válido y completo. Listo para ejecutar.{R}"

        findings = [{
            "type": "validation",
            "value": f"{errors_total} problemas",
            "severity": "info" if errors_total == 0 else "medium" if errors_total < 4 else "high",
            "description": f"Validación: {errors_total} problemas (faltan {len(missing_keys)} keys, "
                           f"{len(type_errors)} tipos, {len(cmd_issues)} comandos)",
        }]
        return {"success": True, "output": output, "findings": findings}

    # ── ACTION: ensure_keys ──────────────────────────────────────────────────
    elif action == "ensure_keys":
        if parsed is None:
            return {
                "success": False,
                "output": f"JSON inválido: {parse_errors[0] if parse_errors else 'desconocido'}",
                "findings": [],
            }

        missing = {k: (REQUIRED_KEYS[k][0]() if REQUIRED_KEYS[k][0] == list else
                       REQUIRED_KEYS[k][0]() if REQUIRED_KEYS[k][0] == str else
                       REQUIRED_KEYS[k][0]() if REQUIRED_KEYS[k][0] == bool else
                       "") for k in REQUIRED_KEYS if k not in parsed}

        if not missing:
            output = (
                f"{BOLD}{'╔══ ENSURE KEYS ═════════════════════════════════════════╗'}{R}\n"
                f"  {GREEN}✅ Todas las claves requeridas presentes{R}\n"
                f"{'╚═════════════════════════════════════════════════════════╝'}{R}\n"
            )
            return {"success": True, "output": output, "findings": []}

        output = (
            f"{BOLD}{'╔══ ENSURE KEYS ═════════════════════════════════════════╗'}{R}\n"
            f"  {YELLOW}⚠️  Agregando {len(missing)} clave(s) faltante(s):{R}\n"
            f"{'╚═════════════════════════════════════════════════════════╝'}{R}\n"
        )
        for k, v in missing.items():
            output += f"    · {k}: {REQUIRED_KEYS[k][1]} → default: {v}\n"

        return {
            "success": True,
            "output": output,
            "findings": [{
                "type": "keys_added",
                "value": str(list(missing.keys())),
                "severity": "info",
                "description": f"Claves faltantes añadidas: {list(missing.keys())}",
            }],
            "missing_keys": missing,
        }

    # ── ACTION: sanitize ─────────────────────────────────────────────────────
    elif action == "sanitize":
        if parsed is None:
            return {
                "success": False,
                "output": f"JSON inválido: {parse_errors[0] if parse_errors else 'desconocido'}",
                "findings": [],
            }

        commands = parsed.get("commands", [])
        sanitized = []
        changes = []

        for cmd in commands:
            if not isinstance(cmd, str):
                sanitized.append(str(cmd))
                changes.append(f"convertido a string: {cmd}")
                continue
            original = cmd
            # Remove placeholder variables
            cmd = re.sub(r'\{\{[^}]+\}\}', '<target>', cmd)
            if cmd != original:
                changes.append(f"placeholder reemplazado: {original[:50]}")
            # Replace absolute paths with references
            cmd = re.sub(r'(?<=[- ])/[^\s]{30,}', '<path>', cmd)
            # Ensure SKILL: names are lowercase
            if cmd.upper().startswith("SKILL:"):
                parts = cmd.split()
                if len(parts) >= 1:
                    skill_part = parts[0]
                    rest = parts[1:]
                    skill_name = skill_part[6:].strip().lower()
                    cmd = f"SKILL:{skill_name}"
                    if rest:
                        cmd += " " + " ".join(rest)
                    if cmd != original:
                        changes.append(f"skill name lowercase: {original[:50]}")
            sanitized.append(cmd)

        parsed["commands"] = sanitized

        output = (
            f"{BOLD}{'╔══ SANITIZE ═════════════════════════════════════════════╗'}{R}\n"
            f"  {GREEN}✅ {len(sanitized)} comando(s) sanitizados{R}\n"
            f"{'╚═════════════════════════════════════════════════════════╝'}{R}\n"
        )
        if changes:
            output += "\n  Cambios:\n"
            for c in changes[:10]:
                output += f"    · {c}\n"

        findings = [{
            "type": "sanitized",
            "value": f"{len(changes)} cambios",
            "severity": "info",
            "description": f"Comandos sanitizados: {len(changes)} cambios aplicados",
        }]
        return {"success": True, "output": output, "findings": findings}

    # ── ACTION: quality_score ────────────────────────────────────────────────
    elif action == "quality_score":
        if parsed is None:
            return {
                "success": False,
                "output": f"JSON inválido: {parse_errors[0] if parse_errors else 'desconocido'}",
                "findings": [],
            }

        quality = _quality_score(parsed)
        score = quality["score"]
        breakdown = quality["breakdown"]

        # Color based on score
        if score >= 80:
            s_col = GREEN
            grade = "EXCELENTE"
        elif score >= 60:
            s_col = YELLOW
            grade = "ACEPTABLE"
        else:
            s_col = RED
            grade = "DEFICIENTE"

        output = (
            f"{BOLD}{'╔══ QUALITY SCORE ════════════════════════════════════════╗'}{R}\n"
            f"  Puntuación : {s_col}{BOLD}{score}/100 ({grade}){R}\n"
            f"{'╚═════════════════════════════════════════════════════════╝'}{R}\n\n"
            f"  {BOLD}Desglose:{R}\n"
        )
        for key, val in breakdown.items():
            if val > 0:
                output += f"    {RED if val > 5 else YELLOW}· {key}: -{val} puntos{R}\n"
            else:
                output += f"    {GREEN}· {key}: correcto{R}\n"

        if score < 60:
            output += (
                f"\n  {YELLOW}💡 Para mejorar la calidad:{R}\n"
                f"    • Usa {CYAN}SKILL:prompt_engineer action=optimize{R}\n"
                f"    • Usa {CYAN}SKILL:llm_optimizer action=auto_tune{R}\n"
            )

        findings = [{
            "type": "quality_score",
            "value": f"{score}/100",
            "severity": "info" if score >= 60 else "medium",
            "description": f"Quality score: {score}/100 ({grade})",
        }]
        return {"success": True, "output": output, "findings": findings}

    else:
        return {
            "success": False,
            "output": (
                f"Acción '{action}' no reconocida.\n\n"
                "Acciones disponibles:\n"
                "  validate     — Valida una respuesta JSON\n"
                "  fix          — Corrige JSON malformado automáticamente\n"
                "  ensure_keys  — Verifica/agrega claves requeridas\n"
                "  sanitize     — Limpia comandos (placeholders, paths)\n"
                "  quality_score — Puntúa la calidad (0-100)\n\n"
                "Ej: SKILL:response_validator action=validate json='{\"commands\":[]}'"
            ),
            "findings": [],
        }
