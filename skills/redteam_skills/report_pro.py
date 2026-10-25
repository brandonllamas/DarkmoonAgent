"""
Skill: report_pro
Genera dos reportes profesionales en Markdown a partir de los findings del
proyecto (out/<proyecto>/project_state.json):

  • Resumen Ejecutivo  → negocio, riesgo global, recomendaciones
  • Reporte Técnico     → evidencia, hallazgos por severidad, remediación

Sigue el estilo PTES / OWASP de RedTeam Barranquilla (https://redteambq.co/).
Determinista: no requiere LLM ni red.
"""
import json
from pathlib import Path
from datetime import datetime

META = {
    "name": "report_pro",
    "category": "metodologia",
    "description": (
        "Genera reporte Ejecutivo + Técnico (Markdown, estilo PTES/OWASP) desde los "
        "findings del proyecto. Calcula riesgo global, agrupa por severidad y añade "
        "remediación. Uso: project=<nombre> (carpeta en out/)."
    ),
    "args": ["project", "target", "output_dir"],
    "example": "SKILL:report_pro project=mi_proyecto",
}

_BASE_DIR = Path(__file__).resolve().parents[2]
_OUT_DIR = _BASE_DIR / "out"

_SEV_ORDER = ["critical", "high", "medium", "low", "info"]
_SEV_LABEL = {"critical": "🔴 Crítico", "high": "🟠 Alto", "medium": "🟡 Medio",
              "low": "🔵 Bajo", "info": "⚪ Info"}

# Remediación genérica por palabra clave en el tipo de finding
_REMEDIATION = [
    (("sqli", "sql_injection", "sqlinjection"), "Usar consultas parametrizadas / ORM; validar y sanear entradas; WAF."),
    (("xss",), "Escapar salida según contexto (HTML/JS/URL); CSP estricta; sanitizar entradas."),
    (("lfi", "rfi", "path_traversal", "traversal"), "Validar rutas con allowlist; deshabilitar wrappers peligrosos; chroot."),
    (("cmdi", "command_injection", "rce"), "Evitar ejecución de shell; usar APIs seguras; allowlist de argumentos."),
    (("credential", "cred", "password", "leaked", "stealer"), "Rotar credenciales expuestas; MFA; monitoreo de fugas; política de contraseñas."),
    (("api_key", "secret", "token", "firebase", "aws"), "Revocar y rotar secretos; mover a gestor de secretos; nunca en cliente/repos."),
    (("smb", "null_session", "signing"), "Forzar firma SMB; deshabilitar sesiones nulas; segmentar red."),
    (("ldap", "kerberos", "ad_", "anonymous"), "Requerir firma LDAP; deshabilitar binds anónimos; hardening de DC."),
    (("cve", "exploit", "vuln"), "Aplicar parches del proveedor; mitigar según aviso; priorizar por explotabilidad."),
    (("sudo", "privesc", "escalation"), "Actualizar sudo; mínimo privilegio en sudoers; auditar binarios SUID."),
    (("ike", "psk", "ipsec"), "Deshabilitar aggressive mode IKE; PSK fuertes o migrar a certificados."),
    (("port", "risky_port", "exposed"), "Cerrar/segmentar puertos innecesarios; firewall; exponer solo lo requerido."),
    (("subdomain", "dns", "takeover"), "Eliminar registros DNS huérfanos; monitorear subdominios; CAA/DNSSEC."),
]


def _remediation_for(ftype: str) -> str:
    t = (ftype or "").lower()
    for keys, text in _REMEDIATION:
        if any(k in t for k in keys):
            return text
    return "Revisar el hallazgo, validar explotabilidad y aplicar hardening acorde."


def _risk_rating(counts: dict) -> tuple:
    c = counts.get("critical", 0); h = counts.get("high", 0)
    m = counts.get("medium", 0)
    if c > 0:
        return "CRÍTICO", ("Se identificaron vulnerabilidades críticas que permiten un compromiso "
                           "directo de los sistemas evaluados. Requiere acción inmediata.")
    if h > 0:
        return "ALTO", ("Existen vulnerabilidades de severidad alta que un atacante podría "
                        "encadenar para comprometer activos. Remediación prioritaria.")
    if m > 0:
        return "MEDIO", ("Se encontraron debilidades de severidad media que degradan la postura "
                         "de seguridad. Planificar remediación.")
    return "BAJO", ("No se identificaron vulnerabilidades de alto impacto en el alcance evaluado. "
                    "Mantener controles y monitoreo.")


def _load_state(project: str) -> dict:
    pdir = _OUT_DIR / project
    state_file = pdir / "project_state.json"
    if not state_file.exists():
        return {}
    try:
        return json.loads(state_file.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _counts(findings: list, declared: dict) -> dict:
    counts = {k: 0 for k in _SEV_ORDER}
    for f in findings:
        counts[f.get("severity", "info")] = counts.get(f.get("severity", "info"), 0) + 1
    if not findings and declared:
        for k in _SEV_ORDER:
            counts[k] = declared.get(k, 0)
    return counts


def _executive(project, target, counts, risk, risk_text, n, date) -> str:
    rows = "\n".join(f"| {_SEV_LABEL[k]} | {counts.get(k,0)} |" for k in _SEV_ORDER)
    return f"""# Evaluación de Seguridad — Resumen Ejecutivo

**Proyecto**: {project}
**Objetivo**: {target or '—'}
**Fecha**: {date}
**Clasificación**: CONFIDENCIAL
**Metodología**: PTES · OWASP — RedTeam Barranquilla (https://redteambq.co/)

---

## Resumen

Se realizó una evaluación de seguridad contra **{target or project}** para identificar
vulnerabilidades y evaluar la postura de seguridad de la organización. Se registraron
**{n} hallazgos** en total.

## Clasificación de Riesgo

**Riesgo global: {risk}**

{risk_text}

## Hallazgos por severidad

| Severidad | Cantidad |
|-----------|----------|
{rows}

## Recomendaciones clave

1. Priorizar la remediación de hallazgos **críticos** y **altos** en las próximas 72 h.
2. Aplicar parches del proveedor y rotar cualquier credencial/secreto expuesto.
3. Implementar monitoreo continuo y repetir la evaluación tras la remediación.

---
*Reporte generado automáticamente por HackerAgent · metodología RedTeam Barranquilla.*
"""


def _technical(project, target, counts, findings, risk, n, date) -> str:
    by_sev = {k: [f for f in findings if f.get("severity", "info") == k] for k in _SEV_ORDER}
    sections = []
    for k in _SEV_ORDER:
        items = by_sev[k]
        if not items:
            continue
        sections.append(f"\n### {_SEV_LABEL[k]} ({len(items)})\n")
        sections.append("| # | Tipo | Detalle | Origen | Remediación |")
        sections.append("|---|------|---------|--------|-------------|")
        for i, f in enumerate(items, 1):
            val = str(f.get("value", "")).replace("|", "\\|").replace("\n", " ")[:120]
            desc = str(f.get("description", "")).replace("|", "\\|").replace("\n", " ")[:140]
            sections.append(
                f"| {i} | `{f.get('type','')}` | {desc or val} | {f.get('source','')} "
                f"| {_remediation_for(f.get('type',''))} |"
            )
    body = "\n".join(sections) if sections else "\n_No se registraron hallazgos detallados._\n"
    rows = "\n".join(f"| {_SEV_LABEL[k]} | {counts.get(k,0)} |" for k in _SEV_ORDER)
    return f"""# Evaluación de Seguridad — Reporte Técnico

**Proyecto**: {project}
**Objetivo**: {target or '—'}
**Fecha**: {date}
**Riesgo global**: {risk}
**Total de hallazgos**: {n}
**Metodología**: PTES · OWASP — RedTeam Barranquilla (https://redteambq.co/)

---

## Resumen de severidades

| Severidad | Cantidad |
|-----------|----------|
{rows}

## Hallazgos detallados
{body}

---
*Reporte técnico generado por HackerAgent (skill `report_pro`).*
"""


def run(**kwargs) -> dict:
    project = (kwargs.get("project") or "").strip()
    target = (kwargs.get("target") or "").strip()
    if not project:
        return {"success": False,
                "output": "Falta 'project'. Uso: SKILL:report_pro project=<carpeta en out/>",
                "findings": []}

    state = _load_state(project)
    if not state:
        avail = [p.name for p in _OUT_DIR.iterdir() if (p / "project_state.json").exists()] \
            if _OUT_DIR.exists() else []
        return {"success": False,
                "output": f"No se encontró out/{project}/project_state.json. "
                          f"Proyectos disponibles: {avail}",
                "findings": []}

    findings = state.get("findings", []) or []
    target = target or state.get("target", "")
    counts = _counts(findings, state.get("sev_summary", {}) or {})
    n = len(findings) or sum(counts.values())
    risk, risk_text = _risk_rating(counts)
    date = datetime.now().strftime("%Y-%m-%d %H:%M")
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    out_dir = Path(kwargs.get("output_dir") or (_OUT_DIR / project / "reports"))
    out_dir.mkdir(parents=True, exist_ok=True)
    exec_path = out_dir / f"PTR-{stamp}_executive.md"
    tech_path = out_dir / f"PTR-{stamp}_technical.md"
    exec_path.write_text(_executive(project, target, counts, risk, risk_text, n, date), encoding="utf-8")
    tech_path.write_text(_technical(project, target, counts, findings, risk, n, date), encoding="utf-8")

    out = [
        f"✓ Reportes generados ({risk}) · {n} hallazgos",
        f"  🔴 {counts['critical']}  🟠 {counts['high']}  🟡 {counts['medium']}  🔵 {counts['low']}  ⚪ {counts['info']}",
        f"  📄 Ejecutivo : {exec_path}",
        f"  📄 Técnico   : {tech_path}",
    ]
    return {
        "success": True,
        "output": "\n".join(out),
        "findings": [
            {"type": "report_generated", "value": str(exec_path), "severity": "info",
             "description": f"Resumen ejecutivo ({risk})", "source": "report_pro"},
            {"type": "report_generated", "value": str(tech_path), "severity": "info",
             "description": f"Reporte técnico ({n} hallazgos)", "source": "report_pro"},
        ],
    }
