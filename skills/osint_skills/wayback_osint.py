"""
Skill: wayback_osint
Recon con Wayback Machine / Web Archive:
- Enumeración de URLs históricas (CDX API)
- Detección de endpoints borrados, JS antiguo, credenciales en código histórico
- Comparación de robots.txt histórico vs actual
- Subdominios históricos
"""
import re
import os
import json
import shutil
import subprocess
from urllib.parse import urlparse, urlencode

try:
    import requests as _req
except ImportError:
    _req = None

META = {
    "name": "wayback_osint",
    "category": "osint",
    "description": (
        "Wayback Machine OSINT: enumera URLs históricas (CDX API), detecta endpoints "
        "borrados, JS antiguo con secretos, robots.txt histórico, subdominios pasados "
        "y parámetros de inyección potenciales."
    ),
    "args": ["domain", "target", "limit", "check_secrets", "diff_robots"],
    "example": "SKILL:wayback_osint domain=example.com check_secrets=true",
}

_CDX_API = "https://web.archive.org/cdx/search/cdx"
_WAYBACK  = "https://web.archive.org/web"
_HEADERS  = {"User-Agent": "HackerAgent-OSINT"}

# Extensiones interesantes
_JUICY_EXTS = {
    "js":    "JavaScript (posibles secretos)",
    "json":  "Datos JSON expuestos",
    "xml":   "Configuración XML",
    "sql":   "Posible dump SQL",
    "bak":   "Backup expuesto",
    "env":   "Archivo .env",
    "conf":  "Archivo de configuración",
    "cfg":   "Archivo de configuración",
    "log":   "Archivo de log",
    "txt":   "Texto plano",
    "yaml":  "Configuración YAML",
    "yml":   "Configuración YAML",
    "php":   "Código PHP",
    "asp":   "Código ASP",
    "aspx":  "Código ASPX",
    "jsp":   "Código JSP",
    "git":   "Repositorio Git expuesto",
    "svn":   "SVN expuesto",
    "zip":   "Archivo comprimido",
    "tar":   "Archivo comprimido",
    "gz":    "Archivo comprimido",
}

_SECRET_PATTERNS = [
    (r'(?i)(api[_\-]?key|apikey)\s*[=:]\s*["\']([A-Za-z0-9_\-]{16,})["\']', "api_key"),
    (r'(?i)(secret[_\-]?key|secret)\s*[=:]\s*["\']([A-Za-z0-9_\-+/]{16,})["\']', "secret_key"),
    (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']([^"\']{4,})["\']', "password"),
    (r'(?i)(aws_access_key_id)\s*[=:]\s*["\']?(AKIA[A-Z0-9]{16})["\']?', "aws_key"),
    (r'(?i)(token)\s*[=:]\s*["\']([A-Za-z0-9_\-.]{20,})["\']', "token"),
    (r'(?i)Bearer\s+([A-Za-z0-9_\-\.]{20,})', "bearer_token"),
    (r'(?i)private[_\-]?key[_\-]?=\s*["\']?([A-Za-z0-9+/]{32,})', "private_key"),
    (r'["\']?(eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)["\']?', "jwt_token"),
]


def _sh(cmd, timeout=60):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return (r.stdout or "") + (r.stderr or ""), r.returncode
    except Exception as e:
        return str(e), 1


def _cdx_fetch(domain: str, limit: int = 5000, fl: str = "url,statuscode,timestamp,mimetype"):
    if _req is None:
        return []
    params = {
        "url": f"*.{domain}/*",
        "output": "json",
        "fl": fl,
        "limit": str(limit),
        "collapse": "urlkey",
        "filter": "statuscode:200",
    }
    try:
        r = _req.get(_CDX_API, params=params, headers=_HEADERS, timeout=30)
        if r.status_code == 200:
            rows = r.json()
            if rows and rows[0][0] == "url":
                rows = rows[1:]
            return rows
    except Exception:
        pass
    return []


def _get_wayback(url: str, timestamp: str = None):
    if _req is None:
        return ""
    wb_url = f"{_WAYBACK}/{timestamp or '*'}/{url}" if timestamp else f"{_WAYBACK}/{url}"
    try:
        r = _req.get(wb_url, headers=_HEADERS, timeout=12, allow_redirects=True)
        if r.status_code == 200:
            return r.text[:30000]
    except Exception:
        pass
    return ""


def _run_gau(domain: str):
    binary = shutil.which("gau") or shutil.which("getallurls")
    if not binary:
        return None
    out, _ = _sh(f'"{binary}" {domain} 2>&1 | head -2000', timeout=120)
    return out if len(out) > 50 else None


def _run_waybackurls(domain: str):
    binary = shutil.which("waybackurls")
    if not binary:
        return None
    out, _ = _sh(f'echo {domain} | "{binary}" 2>&1 | head -2000', timeout=120)
    return out if len(out) > 50 else None


def _scan_secrets(text: str, source_url: str) -> list:
    found = []
    for pattern, stype in _SECRET_PATTERNS:
        for m in re.finditer(pattern, text):
            val = m.group(2) if m.lastindex and m.lastindex >= 2 else m.group(1)
            found.append({"type": stype, "value": val[:60], "url": source_url})
    return found


def _get_robots_txt(domain: str, archived_ts: str = None):
    if _req is None:
        return "", ""
    url = f"https://{domain}/robots.txt"
    current = ""
    historical = ""
    try:
        r = _req.get(url, headers=_HEADERS, timeout=8)
        if r.status_code == 200:
            current = r.text
    except Exception:
        pass
    if archived_ts:
        historical = _get_wayback(url, archived_ts)
    return current, historical


def run(domain: str = "", target: str = "", limit: str = "5000",
        check_secrets: str = "false", diff_robots: str = "true", **kwargs) -> dict:
    domain = (domain or target or kwargs.get("url", "")).strip().lower()
    if not domain:
        return {"success": False, "findings": [],
                "output": 'Falta "domain". Ej: SKILL:wayback_osint domain=example.com'}
    domain = re.sub(r"^https?://", "", domain).split("/")[0]
    do_secrets = check_secrets.lower() in ("1", "true", "yes", "si")
    do_robots  = diff_robots.lower()   not in ("0", "false", "no")
    try:
        lim = min(int(limit), 10000)
    except Exception:
        lim = 5000

    lines = [
        f"╔══ WAYBACK OSINT — {domain} {'═'*max(0,50-len(domain))}╗",
        "╚" + "═"*70 + "╝", "",
    ]
    findings = []

    # ── 1. Herramientas nativas ───────────────────────────────────────────────
    all_urls = []
    native_used = False

    gau_out = _run_gau(domain)
    if gau_out:
        native_used = True
        urls_gau = [l.strip() for l in gau_out.splitlines() if l.startswith("http")]
        all_urls.extend(urls_gau)
        lines.append(f"  ✅ GAU: {len(urls_gau)} URLs encontradas")

    wb_out = _run_waybackurls(domain)
    if wb_out:
        native_used = True
        urls_wb = [l.strip() for l in wb_out.splitlines() if l.startswith("http")]
        all_urls.extend(urls_wb)
        lines.append(f"  ✅ waybackurls: {len(urls_wb)} URLs encontradas")

    if not native_used:
        lines.append("  ⚠ GAU / waybackurls no instalados:")
        lines.append("    go install github.com/lc/gau/v2/cmd/gau@latest")
        lines.append("    go install github.com/tomnomnom/waybackurls@latest")
        lines.append("  → Usando Wayback CDX API directamente…\n")

        lines.append(f"  📡 Consultando CDX API (límite {lim} URLs)…")
        rows = _cdx_fetch(domain, lim)
        if rows:
            all_urls = [r[0] for r in rows if r]
            lines.append(f"  ✅ CDX API: {len(all_urls)} URLs únicas\n")
        else:
            lines.append("  ✗ CDX API sin respuesta")
    lines.append("")

    # Dedup
    all_urls = sorted(set(all_urls))

    # ── 2. Clasificar por extensión ───────────────────────────────────────────
    lines.append("  📂 URLS POR TIPO")
    by_ext = {}
    params_urls = []
    for url in all_urls:
        parsed = urlparse(url)
        ext = parsed.path.rsplit(".", 1)[-1].lower().split("?")[0][:10] if "." in parsed.path else ""
        if ext in _JUICY_EXTS:
            by_ext.setdefault(ext, []).append(url)
        if "=" in parsed.query:
            params_urls.append(url)

    for ext, urls in sorted(by_ext.items()):
        lines.append(f"    .{ext:<8} {len(urls):>5}  ({_JUICY_EXTS[ext]})")
        if ext in ("sql", "bak", "env", "git", "svn"):
            for u in urls[:3]:
                lines.append(f"              🔴 {u[:90]}")
                findings.append({"type": "sensitive_file", "value": u, "severity": "critical",
                                 "description": f"Archivo sensible histórico: {u}"})
        elif ext in ("js", "json", "yaml", "yml", "conf", "cfg"):
            for u in urls[:5]:
                findings.append({"type": "config_file", "value": u, "severity": "high",
                                 "description": f"Config/JS histórico: {u}"})
    lines.append("")

    # ── 3. URLs con parámetros (SQLi/IDOR potencial) ─────────────────────────
    if params_urls:
        lines.append(f"  🎯 URLs CON PARÁMETROS ({len(params_urls)}) — candidatas para SQLi/IDOR")
        for u in params_urls[:20]:
            lines.append(f"    {u[:100]}")
        findings.append({"type": "parameter_urls", "value": f"{len(params_urls)} URLs",
                         "severity": "medium",
                         "description": f"URLs históricas con parámetros para fuzzing en {domain}"})
        lines.append("")

    # ── 4. Secretos en JS histórico ───────────────────────────────────────────
    if do_secrets and by_ext.get("js"):
        lines.append("  🔑 ESCANEO DE SECRETOS EN JS HISTÓRICO")
        js_urls = by_ext["js"][:10]
        all_secrets = []
        for js_url in js_urls:
            text = _get_wayback(js_url)
            if text:
                secrets = _scan_secrets(text, js_url)
                all_secrets.extend(secrets)
        if all_secrets:
            lines.append(f"  🔴 {len(all_secrets)} posibles secretos encontrados:")
            for s in all_secrets[:15]:
                lines.append(f"    [{s['type']}] {s['value'][:60]}  ({s['url'][:70]})")
                findings.append({"type": "secret_in_history", "value": s["value"],
                                 "severity": "critical",
                                 "description": f"Secreto en JS histórico: {s['type']} en {s['url']}"})
        else:
            lines.append("  ✓ Sin secretos detectados en JS histórico")
        lines.append("")

    # ── 5. Robots.txt histórico ───────────────────────────────────────────────
    if do_robots:
        lines.append("  🤖 ROBOTS.TXT — HISTÓRICO VS ACTUAL")
        current, hist = _get_robots_txt(domain)
        if current:
            disallowed_current = set(re.findall(r"Disallow:\s*(\S+)", current, re.I))
            lines.append(f"    Actual: {len(disallowed_current)} entradas Disallow")
            for d in sorted(disallowed_current)[:15]:
                lines.append(f"      {d}")
            if hist and hist != current:
                disallowed_hist = set(re.findall(r"Disallow:\s*(\S+)", hist, re.I))
                removed = disallowed_hist - disallowed_current
                if removed:
                    lines.append(f"\n    🔴 Rutas presentes en robots.txt antiguo (borradas del actual):")
                    for p in sorted(removed)[:20]:
                        lines.append(f"      {p}")
                        findings.append({"type": "deleted_path", "value": p, "severity": "high",
                                         "description": f"Ruta borrada de robots.txt: {p} en {domain}"})
        lines.append("")

    # ── 6. Subdominios históricos ─────────────────────────────────────────────
    hist_subs = set()
    for url in all_urls:
        try:
            host = urlparse(url).netloc.split(":")[0].lower()
            if host.endswith(f".{domain}") and host != domain:
                hist_subs.add(host)
        except Exception:
            pass
    if hist_subs:
        lines.append(f"  🌐 SUBDOMINIOS HISTÓRICOS ({len(hist_subs)})")
        for sub in sorted(hist_subs)[:30]:
            lines.append(f"    {sub}")
            findings.append({"type": "historical_subdomain", "value": sub, "severity": "info",
                             "description": f"Subdominio histórico: {sub}"})
        lines.append("")

    # ── Resumen ───────────────────────────────────────────────────────────────
    total = len(all_urls)
    lines.append(f"  ─── {len(findings)} hallazgos | {total} URLs totales ───")
    if params_urls:
        lines.append(f"  ▶ SKILL:web_attack target={domain}  (con URLs de parámetros históricos)")
    if findings:
        lines.append(f"  ▶ SKILL:spider_code target=https://{domain}")

    return {"success": True, "output": "\n".join(lines), "findings": findings,
            "total_urls": total, "domain": domain, "juicy_urls": len(by_ext),
            "param_urls": len(params_urls)}
