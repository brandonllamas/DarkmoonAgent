"""
Skill: phone_osint
OSINT de número de teléfono: carrier, país, tipo, validez, línea fija vs celular,
VoIP detection, HLR lookup. PhoneInfoga (Kali), NumVerify, OpenCNAM, OSINT APIs.
"""
import re
import os
import json
import shutil
import subprocess

try:
    import requests as _req
except ImportError:
    _req = None

META = {
    "name": "phone_osint",
    "category": "osint",
    "description": (
        "OSINT de número de teléfono: carrier, país, tipo de línea (móvil/fijo/VoIP), "
        "validez, HLR lookup. PhoneInfoga (Kali) + NumVerify API + validación manual. "
        "Detecta números desechables y VoIP para correlación."
    ),
    "args": ["phone", "country"],
    "example": "SKILL:phone_osint phone=+521234567890",
}

_HEADERS = {"User-Agent": "HackerAgent-OSINT/1.0"}

# Prefijos de países comunes
_COUNTRY_CODES = {
    "1": "US/CA", "7": "RU/KZ", "20": "EG", "27": "ZA", "30": "GR",
    "31": "NL", "32": "BE", "33": "FR", "34": "ES", "36": "HU",
    "39": "IT", "40": "RO", "41": "CH", "43": "AT", "44": "GB",
    "45": "DK", "46": "SE", "47": "NO", "48": "PL", "49": "DE",
    "51": "PE", "52": "MX", "53": "CU", "54": "AR", "55": "BR",
    "56": "CL", "57": "CO", "58": "VE", "60": "MY", "61": "AU",
    "62": "ID", "63": "PH", "64": "NZ", "65": "SG", "66": "TH",
    "81": "JP", "82": "KR", "84": "VN", "86": "CN", "90": "TR",
    "91": "IN", "92": "PK", "93": "AF", "94": "LK", "95": "MM",
    "98": "IR", "212": "MA", "213": "DZ", "216": "TN", "218": "LY",
    "220": "GM", "221": "SN", "234": "NG", "254": "KE", "255": "TZ",
    "256": "UG", "260": "ZM", "263": "ZW",
}

# Prefijos VoIP conocidos (EE.UU.)
_VOIP_PREFIXES_US = {
    "202": "Washington DC VoIP range",
    "424": "Possible VoIP (LA area)",
    "929": "Possible VoIP (NY area)",
    "945": "Possible VoIP (TX)",
    "833": "Toll-free",
    "844": "Toll-free",
    "855": "Toll-free",
    "866": "Toll-free",
    "877": "Toll-free",
    "888": "Toll-free",
}

# Números desechables conocidos (prefijos)
_DISPOSABLE_PREFIXES = [
    "+1900", "+1976", "+1809",  # Premium rate
]


def _sh(cmd, timeout=60):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return (r.stdout or "") + (r.stderr or ""), r.returncode
    except Exception as e:
        return str(e), 1


def _normalize_phone(phone: str) -> str:
    """Normaliza a E.164."""
    clean = re.sub(r"[^\d+]", "", phone)
    if not clean.startswith("+"):
        clean = "+" + clean
    return clean


def _detect_country(e164: str) -> tuple:
    """Detecta país por prefijo. Retorna (country_code, country_name)."""
    num = e164.lstrip("+")
    for prefix in sorted(_COUNTRY_CODES.keys(), key=len, reverse=True):
        if num.startswith(prefix):
            return prefix, _COUNTRY_CODES[prefix]
    return "?", "Desconocido"


def _numverify(phone: str):
    key = os.environ.get("NUMVERIFY_API_KEY", "")
    if not key or _req is None:
        return None
    try:
        r = _req.get(f"http://apilayer.net/api/validate?access_key={key}&number={phone}",
                     headers=_HEADERS, timeout=10)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return None


def _abstract_phone(phone: str):
    key = os.environ.get("ABSTRACT_API_KEY", "")
    if not key or _req is None:
        return None
    try:
        r = _req.get(f"https://phonevalidation.abstractapi.com/v1/?api_key={key}&phone={phone}",
                     headers=_HEADERS, timeout=10)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return None


def _opencnam(phone: str):
    """OpenCNAM CNAM lookup (gratuito para lookups básicos)."""
    if _req is None:
        return None
    sid = os.environ.get("TWILIO_ACCOUNT_SID", "")
    token = os.environ.get("TWILIO_AUTH_TOKEN", "")
    if not (sid and token):
        return None
    try:
        r = _req.get(f"https://lookups.twilio.com/v1/PhoneNumbers/{phone}?Type=caller-name",
                     auth=(sid, token), timeout=10)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return None


def _run_phoneinfoga(phone: str):
    binary = shutil.which("phoneinfoga")
    if not binary:
        return None
    out, _ = _sh(f'"{binary}" scan -n {phone} 2>&1', timeout=90)
    return out if len(out) > 50 else None


def _holehe_phone_check(phone: str):
    """Algunos servicios de Holehe usan teléfono (WhatsApp, etc.)."""
    binary = shutil.which("holehe")
    if not binary:
        return None
    # Holehe no soporta phone directamente — skip silently
    return None


def _search_engine_phone(phone: str, clean: str):
    """Búsqueda en DuckDuckGo del número."""
    if _req is None:
        return []
    results = []
    queries = [
        f'"{phone}"',
        f'"{clean}"',
        f'"{phone}" site:truecaller.com OR site:whitepages.com OR site:spokeo.com',
    ]
    seen = set()
    for q in queries[:2]:
        try:
            r = _req.get(f"https://duckduckgo.com/html/?q={q}",
                         headers={"User-Agent": "Mozilla/5.0"}, timeout=10)
            urls = re.findall(r'result__url[^>]*>([^<]+)', r.text)
            for u in urls[:5]:
                u = u.strip()
                if u not in seen:
                    seen.add(u)
                    results.append(u)
        except Exception:
            pass
    return results[:10]


def run(phone: str = "", country: str = "", **kwargs) -> dict:
    phone = (phone or kwargs.get("target") or kwargs.get("number") or "").strip()
    if not phone:
        return {"success": False, "findings": [],
                "output": 'Falta "phone". Ej: SKILL:phone_osint phone=+521234567890'}

    e164 = _normalize_phone(phone)
    clean = e164.lstrip("+")
    cc, country_name = _detect_country(e164)

    lines = [
        f"╔══ PHONE OSINT — {e164} {'═'*max(0,52-len(e164))}╗",
        "╚" + "═"*70 + "╝", "",
        f"  Número:  {e164}",
        f"  País:    {country_name}  (prefix +{cc})",
        "",
    ]
    findings = []

    # Detección básica de tipo
    is_premium = any(e164.startswith(p) for p in _DISPOSABLE_PREFIXES)
    if is_premium:
        lines.append("  ⚠ Posible número premium/rate o desechable\n")
        findings.append({"type": "premium_number", "value": e164, "severity": "medium",
                         "description": f"Número {e164} parece ser premium/desechable"})

    # ── 1. PhoneInfoga nativo ─────────────────────────────────────────────────
    lines.append("  🔍 PHONEINFOGA")
    pf_out = _run_phoneinfoga(e164)
    if pf_out:
        lines.append("  ✅ PhoneInfoga (nativo) ejecutado\n")
        lines.append(pf_out[:5000])
        if "voip" in pf_out.lower():
            findings.append({"type": "voip_number", "value": e164, "severity": "medium",
                             "description": f"Número VoIP detectado: {e164}"})
        if "valid" in pf_out.lower() and "invalid" not in pf_out.lower():
            findings.append({"type": "valid_phone", "value": e164, "severity": "info",
                             "description": f"Número válido: {e164} ({country_name})"})
    else:
        lines.append("  ⚠ PhoneInfoga no instalado")
        lines.append("    Instalar: go install github.com/sundowndev/phoneinfoga/v2/cmd/phoneinfoga@latest")
        lines.append("")

    # ── 2. NumVerify API ──────────────────────────────────────────────────────
    lines.append("  📊 NUMVERIFY / ABSTRACT API")
    nv = _numverify(e164)
    if nv:
        lines.append(f"    valid      : {nv.get('valid', '?')}")
        lines.append(f"    type       : {nv.get('line_type', '?')}")
        lines.append(f"    carrier    : {nv.get('carrier', '?')}")
        lines.append(f"    country    : {nv.get('country_name', '?')}")
        lines.append(f"    location   : {nv.get('location', '?')}")
        ltype = nv.get("line_type", "").lower()
        carrier = nv.get("carrier", "")
        if nv.get("valid"):
            findings.append({"type": "valid_phone", "value": e164, "severity": "info",
                             "description": f"Número válido: {e164} | {ltype} | {carrier} | {nv.get('country_name')}"})
        if ltype == "voip":
            findings.append({"type": "voip_number", "value": e164, "severity": "medium",
                             "description": f"VoIP: {e164} ({carrier})"})
        if carrier:
            findings.append({"type": "carrier", "value": carrier, "severity": "info",
                             "description": f"Operador: {carrier} ({country_name})"})
    else:
        ab = _abstract_phone(e164)
        if ab:
            lines.append(f"    valid      : {ab.get('valid', '?')}")
            lines.append(f"    type       : {ab.get('type', '?')}")
            lines.append(f"    carrier    : {ab.get('carrier', {}).get('name', '?')}")
            lines.append(f"    country    : {ab.get('country', {}).get('name', '?')}")
            carrier = ab.get("carrier", {}).get("name", "")
            ltype = ab.get("type", "")
            if ab.get("valid"):
                findings.append({"type": "valid_phone", "value": e164, "severity": "info",
                                 "description": f"Número válido: {e164} | {ltype} | {carrier}"})
        else:
            lines.append("  ⚠ Agrega NUMVERIFY_API_KEY o ABSTRACT_API_KEY en .env")
            lines.append("    numverify.com (gratis 100/mes)  |  abstractapi.com (gratis 500/mes)")
    lines.append("")

    # ── 3. Twilio CNAM ────────────────────────────────────────────────────────
    cnam = _opencnam(e164)
    if cnam:
        name = cnam.get("caller_name", {}).get("caller_name", "")
        ctype = cnam.get("caller_name", {}).get("caller_type", "")
        if name:
            lines.append(f"  📋 CNAM: {name}  [{ctype}]")
            findings.append({"type": "caller_name", "value": name, "severity": "high",
                             "description": f"CNAM: número {e164} pertenece a '{name}'"})
        lines.append("")

    # ── 4. Búsqueda web ──────────────────────────────────────────────────────
    lines.append("  🌐 BÚSQUEDA WEB")
    web_results = _search_engine_phone(e164, clean)
    if web_results:
        lines.append("  Referencias en web:")
        for res in web_results[:8]:
            lines.append(f"    → {res[:100]}")
        findings.append({"type": "web_presence", "value": e164, "severity": "info",
                         "description": f"Número {e164} referenciado en {len(web_results)} fuentes web"})
    else:
        lines.append("  ✗ Sin referencias web")
    lines.append("")

    # ── 5. Links útiles ───────────────────────────────────────────────────────
    lines.append("  🔗 LINKS DE VERIFICACIÓN MANUAL")
    url_clean = e164.replace("+", "%2B")
    links = [
        f"TrueCaller   : https://www.truecaller.com/search/us/{clean}",
        f"WhoCalled    : https://whocalled.us/number/{clean}",
        f"Sync.me      : https://sync.me/search/?number={e164}",
        f"NumLookup    : https://www.numlookup.com/?number={e164}",
    ]
    for link in links:
        lines.append(f"    {link}")
    lines.append("")

    lines.append(f"  ─── {len(findings)} hallazgos ───")

    return {"success": True, "output": "\n".join(lines), "findings": findings,
            "phone": e164, "country": country_name}
