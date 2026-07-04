"""
Skill: theharvester
Wrapper de theHarvester (Kali Linux) + fallback Python puro.
Reúne emails, subdominios, hosts, empleados e IPs desde múltiples fuentes:
Google, Bing, DuckDuckGo, Yahoo, LinkedIn, GitHub, Hunter.io, Shodan, Censys,
crt.sh, URLScan, VirusTotal, SecurityTrails y más.
"""
import re
import json
import shutil
import subprocess
import os
from pathlib import Path

try:
    import requests as _req
except ImportError:
    _req = None

META = {
    "name": "theharvester",
    "category": "osint",
    "description": (
        "theHarvester: reúne emails, subdominios, hosts, empleados e IPs desde "
        "Google, Bing, LinkedIn, GitHub, Hunter.io, Shodan, Censys, crt.sh, URLScan, "
        "VirusTotal y más. Fallback Python si no está instalado."
    ),
    "args": ["domain", "sources", "limit", "dns_lookup", "screenshot"],
    "example": "SKILL:theharvester domain=example.com sources=google,bing,linkedin limit=200",
}

_DEFAULT_SOURCES = "baidu,bing,bingapi,certspotter,crtsh,dnsdumpster,duckduckgo,google,hackertarget,otx,rapiddns,sublist3r,threatminer,urlscan,vt"

# ── Fuentes sin API key (web scraping / APIs públicas) ─────────────────────
_FREE_APIS = {
    "hackertarget": "https://api.hackertarget.com/hostsearch/?q={domain}",
    "rapiddns":     "https://rapiddns.io/subdomain/{domain}?full=1",
    "dnsdumpster":  "https://api.hackertarget.com/dnslookup/?q={domain}",
    "crtsh":        "https://crt.sh/?q=%.{domain}&output=json",
    "otx":          "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
    "urlscan":      "https://urlscan.io/api/v1/search/?q=domain:{domain}&size=100",
    "threatminer":  "https://api.threatminer.org/v2/domain.php?q={domain}&rt=5",
}


def _sh(cmd, timeout=120):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return (r.stdout or "") + (r.stderr or ""), r.returncode
    except Exception as e:
        return str(e), 1


def _run_native(domain, sources, limit):
    """Intenta correr theHarvester nativo."""
    bin_names = ["theHarvester", "theharvester"]
    binary = next((shutil.which(b) for b in bin_names if shutil.which(b)), None)
    if not binary:
        return None, "not_found"
    cmd = f'"{binary}" -d {domain} -b {sources} -l {limit} -f /tmp/harvest_{domain} 2>&1'
    out, code = _sh(cmd, timeout=300)
    return out, "ok" if code == 0 or len(out) > 100 else "error"


def _fallback_crtsh(domain):
    if _req is None:
        return [], []
    try:
        r = _req.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=15)
        data = r.json()
        subs = set()
        for e in data:
            for n in (e.get("name_value", "") + "\n" + e.get("common_name", "")).splitlines():
                n = n.strip().lstrip("*.")
                if domain in n:
                    subs.add(n.lower())
        return sorted(subs), []
    except Exception:
        return [], []


def _fallback_hackertarget(domain):
    if _req is None:
        return [], []
    try:
        r = _req.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=15)
        hosts, emails = [], []
        for line in r.text.splitlines():
            if "," in line:
                host, ip = line.split(",", 1)
                hosts.append((host.strip(), ip.strip()))
        return hosts, []
    except Exception:
        return [], []


def _fallback_urlscan(domain):
    if _req is None:
        return []
    try:
        r = _req.get(f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=100",
                     timeout=15, headers={"User-Agent": "Mozilla/5.0"})
        urls = []
        for hit in r.json().get("results", []):
            pg = hit.get("page", {})
            u = pg.get("url", "")
            if u and domain in u:
                urls.append(u)
        return list(set(urls))[:50]
    except Exception:
        return []


def _fallback_otx(domain):
    if _req is None:
        return []
    try:
        r = _req.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
            timeout=15, headers={"X-OTX-API-KEY": os.environ.get("OTX_API_KEY", "")})
        subs = set()
        for rec in r.json().get("passive_dns", []):
            h = rec.get("hostname", "")
            if h and domain in h:
                subs.add(h.lower())
        return sorted(subs)
    except Exception:
        return []


def _extract_emails(text, domain):
    pattern = rf"[a-zA-Z0-9_.+\-]+@(?:[a-zA-Z0-9\-]+\.)*{re.escape(domain)}"
    return sorted(set(re.findall(pattern, text, re.I)))


def _fallback_search_emails(domain):
    """Google/DuckDuckGo scraping para emails."""
    if _req is None:
        return []
    emails = set()
    for url in [
        f"https://duckduckgo.com/html/?q=site:{domain}+%40{domain}",
        f"https://duckduckgo.com/html/?q=%22@{domain}%22",
    ]:
        try:
            r = _req.get(url, timeout=10,
                         headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
            emails.update(_extract_emails(r.text, domain))
        except Exception:
            pass
    return sorted(emails)


def run(domain: str = "", sources: str = "", limit: str = "200",
        dns_lookup: str = "true", screenshot: str = "false", **kwargs) -> dict:
    domain = (domain or kwargs.get("target") or "").strip().lower()
    if not domain:
        return {"success": False, "findings": [],
                "output": 'Falta "domain". Ej: SKILL:theharvester domain=example.com'}
    domain = re.sub(r"^https?://", "", domain).split("/")[0]
    sources = sources or _DEFAULT_SOURCES
    try:
        lim = int(limit)
    except Exception:
        lim = 200

    lines = [
        f"╔══ THEHARVESTER — {domain} {'═'*max(0,52-len(domain))}╗",
        f"  Fuentes : {sources[:80]}",
        f"  Límite  : {lim}",
        "╚" + "═"*70 + "╝", "",
    ]
    findings = []

    # ── 1. Intentar theHarvester nativo ──────────────────────────────────────
    native_out, status = _run_native(domain, sources, lim)
    if status == "ok" and native_out:
        lines.append("  ✅ theHarvester (nativo) ejecutado\n")
        lines.append(native_out[:6000])
        emails = _extract_emails(native_out, domain)
        subs = re.findall(rf"[\w\-\.]+\.{re.escape(domain)}", native_out)
        for e in emails:
            findings.append({"type": "email", "value": e, "severity": "medium",
                             "description": f"Email encontrado: {e}"})
        for s in set(subs):
            findings.append({"type": "subdomain", "value": s, "severity": "info",
                             "description": f"Subdominio: {s}"})
    else:
        if status == "not_found":
            lines.append("  ⚠ theHarvester no instalado → usando fallbacks Python")
            lines.append("    Instalar: sudo apt install theharvester  (Kali/Debian)\n")
        else:
            lines.append("  ⚠ theHarvester error → usando fallbacks Python\n")

        # ── 2. Fallbacks ──────────────────────────────────────────────────────
        all_subs = set()
        all_hosts = []
        all_urls = []
        all_emails = set()

        lines.append("  📡 crt.sh …")
        crt_subs, _ = _fallback_crtsh(domain)
        all_subs.update(crt_subs)
        lines.append(f"      → {len(crt_subs)} subdominios")

        lines.append("  📡 HackerTarget …")
        ht_hosts, _ = _fallback_hackertarget(domain)
        all_hosts.extend(ht_hosts)
        lines.append(f"      → {len(ht_hosts)} hosts")

        lines.append("  📡 URLScan …")
        urls = _fallback_urlscan(domain)
        all_urls.extend(urls)
        lines.append(f"      → {len(urls)} URLs")

        lines.append("  📡 OTX (AlienVault) …")
        otx = _fallback_otx(domain)
        all_subs.update(otx)
        lines.append(f"      → {len(otx)} subdominios")

        lines.append("  📡 Búsqueda de emails …")
        em = _fallback_search_emails(domain)
        all_emails.update(em)
        lines.append(f"      → {len(em)} emails\n")

        if all_subs:
            lines.append(f"  📂 SUBDOMINIOS ({len(all_subs)})")
            for s in sorted(all_subs)[:50]:
                lines.append(f"      {s}")
                findings.append({"type": "subdomain", "value": s, "severity": "info",
                                 "description": f"Subdominio: {s}"})
            lines.append("")

        if all_hosts:
            lines.append(f"  🖥  HOSTS ({len(all_hosts)})")
            for h, ip in all_hosts[:30]:
                lines.append(f"      {h:<40} {ip}")
                findings.append({"type": "host", "value": h, "severity": "info",
                                 "description": f"Host {h} → {ip}"})
            lines.append("")

        if all_emails:
            lines.append(f"  📧 EMAILS ({len(all_emails)})")
            for e in sorted(all_emails)[:30]:
                lines.append(f"      {e}")
                findings.append({"type": "email", "value": e, "severity": "medium",
                                 "description": f"Email: {e}"})
            lines.append("")

        if all_urls:
            lines.append(f"  🔗 URLs ({len(all_urls)})")
            for u in all_urls[:20]:
                lines.append(f"      {u}")
            lines.append("")

    lines.append(f"  ─────── {len(findings)} hallazgos totales ───────")
    return {"success": True, "output": "\n".join(lines), "findings": findings}
