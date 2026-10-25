"""
Skill: ptes_methodology
Metodología PTES (Penetration Testing Execution Standard) adaptada al arsenal
de HackerAgent. Devuelve un plan estructurado fase-por-fase con el enfoque
"discover, don't assume": cada fase recomienda los SKILL: concretos a ejecutar.

Inspirado en la metodología de RedTeam Barranquilla (https://redteambq.co/).
No ejecuta herramientas: guía al agente para operar de forma sistemática.
"""
from datetime import datetime

META = {
    "name": "ptes_methodology",
    "category": "metodologia",
    "description": (
        "Plan de ataque estructurado según PTES (7 fases). Mapea cada fase a los "
        "skills de HackerAgent y aplica el principio 'descubrir, no asumir'. "
        "Úsalo al iniciar una auditoría para operar de forma metódica y robusta."
    ),
    "args": ["target", "phase", "scope"],
    "example": "SKILL:ptes_methodology target=example.com",
}

# Cada fase PTES → objetivo + skills de HackerAgent recomendados
_PHASES = [
    ("1. Pre-engagement", "Definir alcance, reglas y autorización.", [
        "Confirmar autorización por escrito y alcance (IPs/dominios permitidos).",
        "Definir ventana de tiempo y nivel de agresividad.",
    ]),
    ("2. Intelligence Gathering (Recon)", "Descubrir superficie de ataque sin tocar al objetivo.", [
        "SKILL:crtsh_enum domain={t}",
        "SKILL:subfinder_enum domain={t} verify_http=true",
        "SKILL:theharvester domain={t} sources=all limit=200",
        "SKILL:shodan_query target={t}",
        "SKILL:dns_full domain={t}",
        "SKILL:wayback_osint domain={t} check_secrets=true",
    ]),
    ("3. Threat Modeling", "Priorizar activos y vectores según valor/exposición.", [
        "Clasificar subdominios y servicios por criticidad.",
        "Identificar tecnologías con SKILL:tech_detect target=https://{t}",
    ]),
    ("4. Vulnerability Analysis", "Enumerar activamente y detectar vulnerabilidades.", [
        "SKILL:scan_red target={t} mode=quick",
        "SKILL:ike_enum target={t}            # IKE/IPSec si hay 500/UDP",
        "SKILL:nuclei_scan target=https://{t} severity=critical,high",
        "SKILL:web_attack target=https://{t} tests=sqli,xss,lfi,redirect,cmdi",
        "SKILL:gobuster_dir target=https://{t} extensions=php,html,txt",
        "SKILL:vuln_classifier input='<hallazgo>' source=web_attack",
    ]),
    ("5. Exploitation", "Ganar acceso con lo DESCUBIERTO (no asumido).", [
        "SKILL:exploit_db cve=<CVE descubierto>",
        "SKILL:metasploit mode=exploit target={t} module=<módulo> lhost=<IP>",
        "SKILL:sqli_scan target='https://{t}/item.php?id=1' dump=true",
        "SKILL:cred_stuff target=https://{t}/login domain={t}",
    ]),
    ("6. Post-Exploitation", "Escalar, persistir y recolectar evidencia.", [
        "SKILL:sudo_privesc version=<salida de sudo --version>",
        "Enumerar privilegios: sudo -l, SUID, capabilities, cron.",
        "Recolectar evidencia (flags, credenciales, rutas) para el reporte.",
    ]),
    ("7. Reporting", "Documentar impacto de negocio + detalle técnico.", [
        "SKILL:report_pro project=<nombre_proyecto> target={t}",
    ]),
]


def _render(target: str, only_phase: str = "") -> str:
    t = target or "{TARGET}"
    lines = [
        "═══════════════════════════════════════════════════════════════",
        f"            PLAN DE ATAQUE PTES — {t}",
        "═══════════════════════════════════════════════════════════════",
        f"  Objetivo    : {t}",
        f"  Metodología : PTES (Penetration Testing Execution Standard)",
        f"  Principio   : DESCUBRIR, NO ASUMIR — reporta lo que encuentras",
        f"  Comunidad   : RedTeam Barranquilla · https://redteambq.co/",
        "═══════════════════════════════════════════════════════════════",
        "",
    ]
    for name, goal, steps in _PHASES:
        if only_phase and only_phase.lower() not in name.lower():
            continue
        lines.append(f"▸ FASE {name}")
        lines.append(f"    🎯 {goal}")
        for s in steps:
            lines.append(f"      • {s.format(t=t)}")
        lines.append("")
    lines.append("⚠️  Comandos con sudo: NO se ejecutan directos. Muéstralos marcados")
    lines.append("    como «⚠️ REQUIERE SUDO» y pide la salida al operador.")
    return "\n".join(lines)


def run(**kwargs) -> dict:
    target = (kwargs.get("target") or "").strip()
    phase = (kwargs.get("phase") or "").strip()
    output = _render(target, phase)

    findings = [{
        "type": "methodology", "value": "PTES 7-phase plan",
        "severity": "info",
        "description": f"Plan PTES generado para {target or 'objetivo sin especificar'}"
                       + (f" (fase: {phase})" if phase else ""),
        "source": "ptes_methodology",
    }]
    # Recomendación de siguiente paso según haya o no target
    if not target:
        findings.append({
            "type": "methodology_hint", "value": "falta target",
            "severity": "low",
            "description": "Pasa target= para obtener comandos SKILL: listos para ejecutar.",
            "source": "ptes_methodology",
        })
    return {"success": True, "output": output, "findings": findings}
