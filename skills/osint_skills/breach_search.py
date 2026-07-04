"""
Skill: breach_search
Búsqueda de credenciales filtradas / breaches para email, dominio o usuario.
Fuentes: HIBP (Have I Been Pwned), DeHashed, IntelX, LeakCheck,
BreachDirectory, Snusbase. Incluye H8mail si está instalado en Kali.
"""
import re
import os
import json
import shutil
import subprocess
from pathlib import Path
from datetime import datetime

try:
    import requests as _req
except ImportError:
    _req = None

META = {
    "name": "breach_search",
    "category": "osint",
    "description": (
        "Busca credenciales filtradas y breaches para email, dominio o username. "
        "Fuentes: HIBP, DeHashed, LeakCheck, BreachDirectory, IntelX, Snusbase. "
        "H8mail (Kali) si instalado. Detecta contraseñas, hashes y datos expuestos."
    ),
    "args": ["email", "domain", "username", "password"],
    "example": "SKILL:breach_search email=john@corp.com",
}


def _sh(cmd, timeout=90):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return (r.stdout or "") + (r.stderr or ""), r.returncode
    except Exception as e:
        return str(e), 1


def _get(url, headers=None, timeout=12, json_resp=True):
    if _req is None:
        return None
    try:
        r = _req.get(url, headers=headers or {"User-Agent": "HackerAgent-OSINT"}, timeout=timeout)
        if r.status_code == 200:
            return r.json() if json_resp else r.text
        return None
    except Exception:
        return None


# ── HIBP ─────────────────────────────────────────────────────────────────────
def _hibp_breaches(email: str):
    key = os.environ.get("HIBP_API_KEY", "")
    hdrs = {"User-Agent": "HackerAgent-OSINT"}
    if key:
        hdrs["hibp-api-key"] = key
    data = _get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false",
                headers=hdrs)
    return data or []


def _hibp_pastes(email: str):
    key = os.environ.get("HIBP_API_KEY", "")
    if not key:
        return []
    data = _get(f"https://haveibeenpwned.com/api/v3/pasteaccount/{email}",
                headers={"User-Agent": "HackerAgent-OSINT", "hibp-api-key": key})
    return data or []


def _hibp_all_breaches():
    return _get("https://haveibeenpwned.com/api/v3/breaches") or []


# ── LeakCheck ────────────────────────────────────────────────────────────────
def _leakcheck(query: str, qtype: str = "auto"):
    key = os.environ.get("LEAKCHECK_API_KEY", "")
    if not key or _req is None:
        return None
    data = _get(f"https://leakcheck.io/api/v2/query/{query}?type={qtype}",
                headers={"X-API-Key": key})
    return data


# ── DeHashed ──────────────────────────────────────────────────────────────────
def _dehashed(query: str, qtype: str = "email"):
    user = os.environ.get("DEHASHED_USER", "")
    key  = os.environ.get("DEHASHED_API_KEY", "")
    if not (user and key) or _req is None:
        return None
    try:
        r = _req.get(f"https://api.dehashed.com/search?query={qtype}:{query}&size=20",
                     auth=(user, key), timeout=12,
                     headers={"Accept": "application/json"})
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return None


# ── BreachDirectory (free) ────────────────────────────────────────────────────
def _breachdirectory(email: str):
    # Gratuito pero limitado
    key = os.environ.get("BREACHDIRECTORY_API_KEY", "")
    if not key or _req is None:
        return None
    data = _get(f"https://breachdirectory.org/api?func=auto&term={email}",
                headers={"X-Api-Key": key})
    return data


# ── IntelX ────────────────────────────────────────────────────────────────────
def _intelx(query: str):
    key = os.environ.get("INTELX_API_KEY", "")
    if not key or _req is None:
        return []
    try:
        # Search
        r = _req.post("https://2.intelx.io/intelligent/search",
                      json={"term": query, "maxresults": 20, "media": 0, "sort": 4},
                      headers={"x-key": key}, timeout=12)
        if r.status_code != 200:
            return []
        sid = r.json().get("id")
        if not sid:
            return []
        # Get results
        import time; time.sleep(1)
        rr = _req.get(f"https://2.intelx.io/intelligent/search/result?id={sid}&limit=20",
                      headers={"x-key": key}, timeout=12)
        if rr.status_code == 200:
            return rr.json().get("records", [])
    except Exception:
        pass
    return []


# ── Snusbase ──────────────────────────────────────────────────────────────────
def _snusbase(query: str, qtype: str = "email"):
    key = os.environ.get("SNUSBASE_API_KEY", "")
    if not key or _req is None:
        return None
    try:
        r = _req.post("https://api.snusbase.com/data/search",
                      json={"terms": [query], "types": [qtype]},
                      headers={"Auth": key, "Content-Type": "application/json"}, timeout=12)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return None


# ── H8mail nativo ──────────────────────────────────────────────────────────
def _run_h8mail(query: str):
    binary = shutil.which("h8mail")
    if not binary:
        return None
    out, _ = _sh(f'"{binary}" -t {query} 2>&1', timeout=90)
    return out if len(out) > 10 else None


# ── Phonebook.cz ─────────────────────────────────────────────────────────────
def _phonebook(domain: str):
    """Phonebook.cz: emails/dominios/URLs por dominio."""
    if _req is None:
        return []
    try:
        r = _req.get(f"https://phonebook.cz/api/?term={domain}&type=email",
                     headers={"User-Agent": "Mozilla/5.0"}, timeout=10)
        if r.status_code == 200:
            return r.json().get("data", [])[:30]
    except Exception:
        pass
    return []


def _format_breach(breach: dict) -> str:
    name = breach.get("Name", breach.get("name", "?"))
    date = breach.get("BreachDate", breach.get("date", "?"))
    cnt  = breach.get("PwnCount", breach.get("pwnCount", 0))
    data = ", ".join(breach.get("DataClasses", breach.get("data_classes", [])))
    return f"  • {name:<30} {date}  {cnt:>10,} cuentas  [{data[:60]}]"


def run(email: str = "", domain: str = "", username: str = "",
        password: str = "", **kwargs) -> dict:
    query = (email or domain or username or kwargs.get("target") or "").strip()
    if not query:
        return {"success": False, "findings": [],
                "output": "Falta email, domain o username. Ej: SKILL:breach_search email=user@corp.com"}

    qtype = "email" if "@" in query else "domain" if "." in query and "@" not in query else "username"
    ts = datetime.now().strftime("%H:%M:%S")

    lines = [
        f"╔══ BREACH SEARCH — {query} {'═'*max(0,50-len(query))}╗",
        f"  Tipo: {qtype}   Hora: {ts}",
        "╚" + "═"*70 + "╝", "",
    ]
    findings = []
    has_key = {
        "HIBP":   bool(os.environ.get("HIBP_API_KEY")),
        "LeakCheck": bool(os.environ.get("LEAKCHECK_API_KEY")),
        "DeHashed": bool(os.environ.get("DEHASHED_USER") and os.environ.get("DEHASHED_API_KEY")),
        "IntelX":  bool(os.environ.get("INTELX_API_KEY")),
        "Snusbase": bool(os.environ.get("SNUSBASE_API_KEY")),
        "BreachDirectory": bool(os.environ.get("BREACHDIRECTORY_API_KEY")),
    }

    # ── H8mail nativo ─────────────────────────────────────────────────────────
    h8_out = _run_h8mail(query)
    if h8_out:
        lines.append("  ✅ H8mail (Kali)\n")
        lines.append(h8_out[:3000])
        if "breach" in h8_out.lower() or "pwd:" in h8_out.lower():
            findings.append({"type": "breach_found", "value": query, "severity": "critical",
                             "description": f"H8mail encontró credenciales para {query}"})
        lines.append("")
    else:
        lines.append("  ⚠ H8mail no instalado → pip3 install h8mail\n")

    # ── HIBP ──────────────────────────────────────────────────────────────────
    lines.append("  📊 HAVE I BEEN PWNED")
    if qtype == "email":
        breaches = _hibp_breaches(query)
        if breaches:
            lines.append(f"  🔴 {len(breaches)} breach(es) encontrados:")
            for b in sorted(breaches, key=lambda x: x.get("BreachDate",""), reverse=True):
                lines.append(_format_breach(b))
                findings.append({"type": "hibp_breach", "value": b.get("Name","?"),
                                 "severity": "critical",
                                 "description": f"{query} en '{b.get('Name')}' ({b.get('BreachDate')})"})
            pastes = _hibp_pastes(query)
            if pastes:
                lines.append(f"\n  📋 {len(pastes)} paste(s):")
                for p in pastes[:5]:
                    lines.append(f"      {p.get('Source','?')} — {p.get('Title','?')} ({p.get('Date','?')})")
                    findings.append({"type": "paste_exposure", "value": p.get("Id",""),
                                     "severity": "high",
                                     "description": f"{query} expuesto en paste '{p.get('Title')}'"})
        elif breaches == [] and has_key["HIBP"]:
            lines.append("  ✓ HIBP: sin breaches conocidos")
        else:
            lines.append("  ⚠ HIBP: agrega HIBP_API_KEY en .env  (gratuito en haveibeenpwned.com)")
    else:
        all_b = _hibp_all_breaches()
        relevant = [b for b in all_b if query.lower() in b.get("Domain","").lower()] if qtype == "domain" else []
        if relevant:
            lines.append(f"  🔴 {len(relevant)} breaches del dominio {query}:")
            for b in relevant:
                lines.append(_format_breach(b))
                findings.append({"type": "domain_breach", "value": b.get("Name","?"),
                                 "severity": "critical",
                                 "description": f"Dominio {query} en breach '{b.get('Name')}'"})
        else:
            lines.append(f"  HIBP: sin breaches conocidos para {query}")
    lines.append("")

    # ── LeakCheck ─────────────────────────────────────────────────────────────
    lines.append("  🔑 LEAKCHECK")
    if has_key["LeakCheck"]:
        lc = _leakcheck(query, qtype)
        if lc and lc.get("found"):
            results = lc.get("result", [])
            lines.append(f"  🔴 {len(results)} registros:")
            for rec in results[:10]:
                email_val = rec.get("email", "")
                password_val = rec.get("password", "")
                source = rec.get("sources", ["?"])[0] if rec.get("sources") else "?"
                lines.append(f"      email={email_val}  pass={password_val}  src={source}")
                findings.append({"type": "leaked_credential", "value": f"{email_val}:{password_val}",
                                 "severity": "critical",
                                 "description": f"Credencial: {email_val} en {source}"})
        else:
            lines.append("  ✓ LeakCheck: sin resultados")
    else:
        lines.append("  ⚠ Agrega LEAKCHECK_API_KEY en .env  (leakcheck.io)")
    lines.append("")

    # ── DeHashed ──────────────────────────────────────────────────────────────
    lines.append("  🗂  DEHASHED")
    if has_key["DeHashed"]:
        dh = _dehashed(query, qtype)
        if dh and dh.get("total", 0) > 0:
            entries = dh.get("entries", [])
            lines.append(f"  🔴 {dh['total']} registros (mostrando {min(10, len(entries))}):")
            for e in entries[:10]:
                em  = e.get("email", "")
                pw  = e.get("password", e.get("hashed_password", ""))
                db  = e.get("database_name", "?")
                lines.append(f"      email={em}  pass={pw[:40]}  db={db}")
                findings.append({"type": "dehashed_credential", "value": f"{em}:{pw}",
                                 "severity": "critical",
                                 "description": f"DeHashed: {em} en {db}"})
        else:
            lines.append("  ✓ DeHashed: sin resultados")
    else:
        lines.append("  ⚠ Agrega DEHASHED_USER y DEHASHED_API_KEY en .env  (dehashed.com)")
    lines.append("")

    # ── IntelX ────────────────────────────────────────────────────────────────
    lines.append("  🌐 INTELLIGENCE X")
    if has_key["IntelX"]:
        ix = _intelx(query)
        if ix:
            lines.append(f"  🔴 {len(ix)} registros:")
            for rec in ix[:5]:
                lines.append(f"      {rec.get('name','?')}  [{rec.get('date','')}]")
                findings.append({"type": "intelx_record", "value": rec.get("name",""),
                                 "severity": "high",
                                 "description": f"IntelX: {query} en {rec.get('name')}"})
        else:
            lines.append("  ✓ IntelX: sin resultados")
    else:
        lines.append("  ⚠ Agrega INTELX_API_KEY en .env  (intelx.io)")
    lines.append("")

    # ── Phonebook.cz (dominio) ────────────────────────────────────────────────
    if qtype == "domain":
        lines.append("  📖 PHONEBOOK.CZ")
        pb = _phonebook(query)
        if pb:
            lines.append(f"  {len(pb)} emails/URLs encontrados:")
            for item in pb[:20]:
                val = item if isinstance(item, str) else item.get("value", str(item))
                lines.append(f"      {val}")
                findings.append({"type": "email", "value": val, "severity": "medium",
                                 "description": f"Phonebook.cz: {val}"})
        lines.append("")

    # ── Snusbase ──────────────────────────────────────────────────────────────
    lines.append("  🔍 SNUSBASE")
    if has_key["Snusbase"]:
        sn = _snusbase(query, qtype)
        if sn and sn.get("results"):
            total = sn.get("hits", 0)
            lines.append(f"  🔴 {total} registros:")
            for k, rows in sn["results"].items():
                for row in rows[:5]:
                    em = row.get("email", "")
                    pw = row.get("password", row.get("hash", ""))
                    lines.append(f"      {em}:{pw}  [{k}]")
                    findings.append({"type": "snusbase_credential", "value": f"{em}:{pw}",
                                     "severity": "critical",
                                     "description": f"Snusbase: {em} en {k}"})
        else:
            lines.append("  ✓ Snusbase: sin resultados")
    else:
        lines.append("  ⚠ Agrega SNUSBASE_API_KEY en .env  (snusbase.com)")
    lines.append("")

    # ── Resumen de API keys ───────────────────────────────────────────────────
    missing = [k for k, v in has_key.items() if not v]
    if missing:
        lines.append(f"  💡 APIs sin configurar: {', '.join(missing)}")
        lines.append("     Agregar en .env para más resultados\n")

    lines.append(f"  ─── {len(findings)} hallazgos ───")
    crit = sum(1 for f in findings if f.get("severity") == "critical")
    if crit:
        lines.append(f"  🔴 {crit} hallazgos CRÍTICOS — credenciales expuestas")

    return {"success": True, "output": "\n".join(lines), "findings": findings,
            "query": query, "query_type": qtype}
