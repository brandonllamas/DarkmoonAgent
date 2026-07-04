"""
Skill: email_osint
Investigación completa de un email: verificación de existencia en plataformas
(Holehe), breaches (HIBP + EmailRep), reputación, proveedor, MX records,
pattern inference para encontrar más correos del dominio, y búsqueda de
perfiles sociales asociados.
"""
import re
import json
import socket
import shutil
import subprocess
from pathlib import Path

try:
    import requests as _req
except ImportError:
    _req = None

META = {
    "name": "email_osint",
    "category": "osint",
    "description": (
        "Investiga un email: existencia en 120+ sitios (Holehe), breaches conocidos "
        "(HIBP, EmailRep.io), reputación, MX del dominio, patrón de emails de la empresa, "
        "perfiles sociales vinculados."
    ),
    "args": ["email", "domain", "find_pattern"],
    "example": "SKILL:email_osint email=john@example.com",
}

# Sitios verificables sin API key por cambios de estado de respuesta
_HOLEHE_SITES = [
    {"name": "GitHub",          "url": "https://api.github.com/search/users?q={email}+in:email", "json_check": "total_count", "nonzero": True},
    {"name": "Gravatar",        "url": "https://en.gravatar.com/{hash}", "check": "entry", "hash": True},
    {"name": "Adobe",           "method": "holehe"},
    {"name": "Amazon",          "method": "holehe"},
    {"name": "Discord",         "method": "holehe"},
    {"name": "Google",          "method": "holehe"},
    {"name": "Instagram",       "method": "holehe"},
    {"name": "LinkedIn",        "method": "holehe"},
    {"name": "Microsoft",       "method": "holehe"},
    {"name": "Netflix",         "method": "holehe"},
    {"name": "Twitter",         "method": "holehe"},
]


def _sh(cmd, timeout=90):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return (r.stdout or "") + (r.stderr or ""), r.returncode
    except Exception as e:
        return str(e), 1


def _md5(s: str) -> str:
    import hashlib
    return hashlib.md5(s.strip().lower().encode()).hexdigest()


def _run_holehe(email: str):
    binary = shutil.which("holehe")
    if not binary:
        return None, "not_found"
    out, _ = _sh(f'"{binary}" {email} --no-color 2>&1', timeout=120)
    return out, "ok"


def _run_h8mail(email: str):
    binary = shutil.which("h8mail")
    if not binary:
        return None, "not_found"
    out, _ = _sh(f'"{binary}" -t {email} 2>&1', timeout=60)
    return out, "ok"


def _hibp_check(email: str):
    """Have I Been Pwned — requiere API key en env HIBP_API_KEY."""
    if _req is None:
        return []
    key = __import__("os").environ.get("HIBP_API_KEY", "")
    headers = {"User-Agent": "HackerAgent-OSINT", "hibp-api-key": key} if key else {"User-Agent": "HackerAgent-OSINT"}
    try:
        r = _req.get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                     headers=headers, timeout=10)
        if r.status_code == 200:
            return r.json()
        return []
    except Exception:
        return []


def _emailrep_check(email: str):
    if _req is None:
        return {}
    try:
        r = _req.get(f"https://emailrep.io/{email}",
                     headers={"User-Agent": "HackerAgent-OSINT"}, timeout=10)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return {}


def _mx_lookup(domain: str):
    try:
        import dns.resolver
        mx = dns.resolver.resolve(domain, "MX")
        return sorted([(str(r.exchange), r.preference) for r in mx])
    except Exception:
        pass
    try:
        out, _ = _sh(f"dig +short MX {domain} 2>/dev/null || nslookup -type=MX {domain} 2>/dev/null", 10)
        return [(line.strip(), 0) for line in out.splitlines() if line.strip()][:5]
    except Exception:
        return []


def _gravatar_check(email: str):
    if _req is None:
        return None
    h = _md5(email)
    try:
        r = _req.get(f"https://www.gravatar.com/{h}.json", timeout=8,
                     headers={"User-Agent": "Mozilla/5.0"})
        if r.status_code == 200:
            data = r.json().get("entry", [{}])[0]
            return {
                "display_name": data.get("displayName", ""),
                "urls": [u.get("value", "") for u in data.get("urls", [])],
                "accounts": [a.get("domain", "") for a in data.get("accounts", [])],
            }
    except Exception:
        pass
    return None


def _hunter_domain_search(domain: str):
    """Hunter.io domain search (requiere HUNTER_API_KEY)."""
    if _req is None:
        return []
    key = __import__("os").environ.get("HUNTER_API_KEY", "")
    if not key:
        return []
    try:
        r = _req.get(f"https://api.hunter.io/v2/domain-search?domain={domain}&api_key={key}", timeout=12)
        if r.status_code == 200:
            data = r.json().get("data", {})
            return [e.get("value") for e in data.get("emails", []) if e.get("value")]
    except Exception:
        pass
    return []


def _infer_email_patterns(domain: str, names: list):
    """Genera posibles emails a partir de nombres y patrones comunes."""
    patterns = []
    for name in names[:5]:
        parts = name.lower().split()
        if len(parts) >= 2:
            f, l = parts[0], parts[-1]
            for fmt in [f"{f}.{l}", f"{f}{l}", f"{f[0]}{l}", f"{l}.{f}", f"{f[0]}.{l}"]:
                patterns.append(f"{fmt}@{domain}")
        elif parts:
            patterns.append(f"{parts[0]}@{domain}")
    return patterns


def run(email: str = "", domain: str = "", find_pattern: str = "false", **kwargs) -> dict:
    email = (email or kwargs.get("target") or "").strip().lower()
    if not email and not domain:
        return {"success": False, "findings": [],
                "output": 'Falta "email" o "domain". Ej: SKILL:email_osint email=john@corp.com'}

    if not email and domain:
        # Modo búsqueda de emails en dominio
        lines = [f"╔══ EMAIL OSINT — dominio {domain} ══╗", ""]
        findings = []
        em = _hunter_domain_search(domain)
        if em:
            for e in em:
                lines.append(f"  📧 {e}")
                findings.append({"type": "email", "value": e, "severity": "medium",
                                 "description": f"Email encontrado en {domain}: {e}"})
        else:
            lines.append("  ⚠ Sin HUNTER_API_KEY. Agrega: HUNTER_API_KEY=... en .env")
        return {"success": True, "output": "\n".join(lines), "findings": findings}

    # Extraer dominio del email
    parts = email.split("@")
    if len(parts) != 2:
        return {"success": False, "findings": [],
                "output": f"Email inválido: {email}"}
    local, dom = parts

    lines = [
        f"╔══ EMAIL OSINT — {email} {'═'*max(0,48-len(email))}╗",
        "╚" + "═"*70 + "╝", "",
    ]
    findings = []

    # ── 1. Holehe (existencia en plataformas) ─────────────────────────────────
    lines.append("  🔍 EXISTENCIA EN PLATAFORMAS")
    holehe_out, status = _run_holehe(email)
    if status == "ok" and holehe_out:
        lines.append("  ✅ Holehe (nativo)\n")
        for line in holehe_out.splitlines():
            lines.append(f"      {line}")
            if "[+]" in line or "✔" in line or "True" in line:
                site = re.search(r'\[\+\]\s*(\w[\w\.]+)', line)
                if site:
                    findings.append({"type": "account_found", "value": email,
                                     "severity": "high",
                                     "description": f"Email {email} tiene cuenta en {site.group(1)}"})
    else:
        lines.append("  ⚠ Holehe no instalado → pip3 install holehe")
        # Gravatar check sin API key
        grav = _gravatar_check(email)
        if grav:
            lines.append(f"  ✓ Gravatar: display_name={grav['display_name']}")
            if grav.get("accounts"):
                lines.append(f"    Accounts vinculadas: {', '.join(grav['accounts'])}")
            if grav.get("urls"):
                for u in grav["urls"]:
                    lines.append(f"    URL: {u}")
            findings.append({"type": "gravatar_profile", "value": email,
                             "severity": "medium",
                             "description": f"Perfil Gravatar encontrado para {email}"})
        else:
            lines.append("  ✗ Sin perfil Gravatar público")
    lines.append("")

    # ── 2. H8mail (breaches) ──────────────────────────────────────────────────
    lines.append("  💥 BREACHES / CREDENCIALES FILTRADAS")
    h8_out, h8_status = _run_h8mail(email)
    if h8_status == "ok" and h8_out:
        lines.append("  ✅ H8mail (nativo)\n")
        for line in h8_out.splitlines()[:30]:
            lines.append(f"      {line}")
        if "breach" in h8_out.lower() or "found" in h8_out.lower():
            findings.append({"type": "breach_found", "value": email,
                             "severity": "critical",
                             "description": f"Credenciales de {email} encontradas en breach"})
    else:
        if h8_status == "not_found":
            lines.append("  ⚠ H8mail no instalado → pip3 install h8mail")

        # HIBP fallback
        breaches = _hibp_check(email)
        if breaches:
            lines.append(f"  🔴 HIBP: {len(breaches)} breaches encontrados:")
            for b in breaches:
                name = b.get("Name", "?")
                date = b.get("BreachDate", "?")
                cnt  = b.get("PwnCount", 0)
                lines.append(f"      • {name} ({date}) — {cnt:,} cuentas afectadas")
                findings.append({"type": "hibp_breach", "value": name,
                                 "severity": "critical",
                                 "description": f"{email} en breach '{name}' ({date})"})
        elif breaches == []:
            lines.append("  ✓ HIBP: sin breaches conocidos")
        else:
            lines.append("  ⚠ HIBP: agrega HIBP_API_KEY en .env para verificar")
    lines.append("")

    # ── 3. EmailRep — reputación ──────────────────────────────────────────────
    lines.append("  📊 REPUTACIÓN")
    rep = _emailrep_check(email)
    if rep:
        score = rep.get("reputation", "unknown")
        suspicious = rep.get("suspicious", False)
        details = rep.get("details", {})
        lines.append(f"  EmailRep.io: reputación={score}  suspicious={suspicious}")
        for k, v in details.items():
            if v and k not in ("days_since_domain_creation",):
                lines.append(f"    {k}: {v}")
        if suspicious:
            findings.append({"type": "suspicious_email", "value": email,
                             "severity": "high",
                             "description": f"Email {email} marcado como sospechoso en EmailRep"})
    else:
        lines.append("  ⚠ EmailRep.io sin respuesta")
    lines.append("")

    # ── 4. MX del dominio ─────────────────────────────────────────────────────
    lines.append("  📡 DNS / MX")
    mx = _mx_lookup(dom)
    if mx:
        for host, prio in mx[:5]:
            lines.append(f"    MX: {host}  (prioridad {prio})")
        provider = " ".join(str(h) for h, _ in mx).lower()
        mail_svc = ("Google/Gmail" if "google" in provider
                    else "Microsoft/Office365" if "outlook" in provider or "protection.outlook" in provider
                    else "ProtonMail" if "protonmail" in provider
                    else "Zoho" if "zoho" in provider
                    else "Otro")
        lines.append(f"    Proveedor detectado: {mail_svc}")
        findings.append({"type": "mail_provider", "value": mail_svc,
                         "severity": "info",
                         "description": f"Dominio {dom} usa {mail_svc}"})
    lines.append("")

    # ── 5. Hunter.io — más emails del dominio ─────────────────────────────────
    if find_pattern.lower() in ("1", "true", "yes", "si"):
        lines.append("  📧 EMAILS DEL DOMINIO (Hunter.io)")
        more = _hunter_domain_search(dom)
        if more:
            for e in more[:20]:
                lines.append(f"    {e}")
                findings.append({"type": "email", "value": e, "severity": "medium",
                                 "description": f"Email de {dom}: {e}"})
        else:
            lines.append("  ⚠ Agrega HUNTER_API_KEY en .env para búsqueda de emails del dominio")
        lines.append("")

    lines.append(f"  ─── {len(findings)} hallazgos ───")
    if findings:
        lines.append(f"  ▶ Siguiente: SKILL:breach_search email={email}  |  SKILL:sherlock_osint username={local}")

    return {"success": True, "output": "\n".join(lines), "findings": findings,
            "email": email, "domain": dom}
