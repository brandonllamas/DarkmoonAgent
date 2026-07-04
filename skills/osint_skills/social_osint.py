"""
Skill: social_osint
Inteligencia de redes sociales: Twitter/X, LinkedIn (sin scraping agresivo),
Reddit, Telegram public channels, Instagram, Facebook pages.
Detecta empleados de empresa, publicaciones sobre seguridad/infraestructura,
leaks de datos operacionales en redes sociales.
"""
import re
import os
import json
import shutil
import subprocess
from datetime import datetime

try:
    import requests as _req
except ImportError:
    _req = None

META = {
    "name": "social_osint",
    "category": "osint",
    "description": (
        "OSINT de redes sociales: busca empleados, infraestructura, tecnologías e "
        "información sensible mencionada en Twitter/X, Reddit, LinkedIn, Telegram. "
        "Sin scraping agresivo — APIs públicas + búsquedas dorks."
    ),
    "args": ["company", "domain", "username", "keyword"],
    "example": "SKILL:social_osint company=Acme domain=acme.com",
}

_HEADERS = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0"}

_SECURITY_KEYWORDS = [
    "password", "contraseña", "clave", "token", "secret", "api key",
    "breach", "hack", "vulnerability", "CVE", "RCE", "exploit",
    "database", "server", "internal", "confidential", "leak",
    "login", "admin", "root", "aws", "s3 bucket", "firebase",
    "github", "gitlab", "jenkins", "exposed", "public",
]

_INTEL_DORKS = {
    "Twitter/X": [
        '{company} password',
        '{company} internal server',
        '{company} vulnerability',
        'from:{domain_base} -site:{domain}',
        '"{domain}" "api key" OR "token" OR "secret"',
    ],
    "Reddit": [
        'site:reddit.com "{company}"',
        'site:reddit.com "{domain}"',
        'site:reddit.com "{company}" security',
        'site:reddit.com "{company}" hack OR breach OR vulnerability',
    ],
    "LinkedIn": [
        'site:linkedin.com/in "{company}"',
        'site:linkedin.com/in "{company}" IT OR developer OR engineer OR admin',
        'site:linkedin.com/in "{company}" security',
    ],
    "Pastebin": [
        'site:pastebin.com "{domain}"',
        'site:pastebin.com "{company}" password',
        'site:pastebin.com "{company}"',
    ],
    "GitHub": [
        'site:github.com "{domain}" password OR secret OR token',
        'site:github.com "{company}" api_key OR api-key OR apikey',
        'site:github.com "{domain}" .env OR config OR credentials',
    ],
    "Telegram": [
        'site:t.me "{company}"',
        'site:t.me "{domain}"',
    ],
}


def _sh(cmd, timeout=30):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return (r.stdout or "") + (r.stderr or ""), r.returncode
    except Exception as e:
        return str(e), 1


def _ddg_search(query: str, limit: int = 10):
    """DuckDuckGo HTML search."""
    if _req is None:
        return []
    try:
        r = _req.get(f"https://duckduckgo.com/html/?q={query.replace(' ', '+')}",
                     headers=_HEADERS, timeout=12)
        urls = re.findall(r'result__url[^>]*>([^<]+)', r.text)
        titles = re.findall(r'result__title[^>]*>.*?<a[^>]*>([^<]+)', r.text, re.S)
        snippets = re.findall(r'result__snippet[^>]*>([^<]+)', r.text)
        results = []
        for i in range(min(limit, len(urls))):
            results.append({
                "url": urls[i].strip(),
                "title": titles[i].strip() if i < len(titles) else "",
                "snippet": snippets[i].strip()[:200] if i < len(snippets) else "",
            })
        return results
    except Exception:
        return []


def _twitter_search(query: str):
    """Twitter/X via búsqueda web (sin API)."""
    if _req is None:
        return []
    results = _ddg_search(f"site:twitter.com OR site:x.com {query}", limit=8)
    return results


def _reddit_api(query: str, subreddit: str = ""):
    """Reddit Pushshift / search API (gratuito)."""
    if _req is None:
        return []
    endpoint = f"https://www.reddit.com/search.json?q={query.replace(' ', '+')}&sort=new&limit=10"
    if subreddit:
        endpoint = f"https://www.reddit.com/r/{subreddit}/search.json?q={query.replace(' ', '+')}&restrict_sr=1&sort=new&limit=10"
    try:
        r = _req.get(endpoint, headers={"User-Agent": "HackerAgent-OSINT/1.0"}, timeout=12)
        if r.status_code == 200:
            posts = r.json().get("data", {}).get("children", [])
            return [{"title": p["data"].get("title", ""),
                     "url": p["data"].get("url", ""),
                     "selftext": p["data"].get("selftext", "")[:200],
                     "score": p["data"].get("score", 0)} for p in posts]
    except Exception:
        pass
    return []


def _github_secret_search(domain: str, company: str):
    """Busca secretos en GitHub públicos."""
    if _req is None:
        return []
    token = os.environ.get("GITHUB_TOKEN", "")
    headers = {"User-Agent": "HackerAgent-OSINT"}
    if token:
        headers["Authorization"] = f"token {token}"
    results = []
    queries = [
        f'"{domain}" password',
        f'"{domain}" api_key',
        f'"{domain}" secret',
    ]
    if company:
        queries.append(f'"{company}" api_key OR secret OR password')

    for q in queries[:2]:
        try:
            r = _req.get(f"https://api.github.com/search/code?q={q}&per_page=5",
                         headers=headers, timeout=12)
            if r.status_code == 200:
                for item in r.json().get("items", []):
                    results.append({
                        "repo": item.get("repository", {}).get("full_name", ""),
                        "file": item.get("path", ""),
                        "url": item.get("html_url", ""),
                    })
        except Exception:
            pass
    return results[:10]


def _linkedin_search(company: str):
    results = _ddg_search(f'site:linkedin.com/in "{company}" engineer OR developer OR IT OR admin OR security', limit=10)
    return results


def _pastebin_search(domain: str, company: str):
    results = []
    for q in [f'site:pastebin.com "{domain}"', f'site:pastebin.com "{company}" password']:
        results.extend(_ddg_search(q, limit=5))
    return results


def _detect_sensitive_content(text: str) -> list:
    """Detecta menciones de contenido sensible en texto."""
    found = []
    for kw in _SECURITY_KEYWORDS:
        if kw.lower() in text.lower():
            found.append(kw)
    return found


def run(company: str = "", domain: str = "", username: str = "",
        keyword: str = "", **kwargs) -> dict:
    company = (company or kwargs.get("org", "")).strip()
    domain  = (domain  or kwargs.get("target", "")).strip().lower()
    username = (username or "").strip()
    keyword  = (keyword  or "").strip()

    if not any([company, domain, username, keyword]):
        return {"success": False, "findings": [],
                "output": 'Falta company, domain, username o keyword.\n'
                          'Ej: SKILL:social_osint company=Acme domain=acme.com'}

    domain = re.sub(r"^https?://", "", domain).split("/")[0] if domain else ""
    domain_base = domain.split(".")[0] if domain else ""
    query_base = company or domain_base or username or keyword

    lines = [
        f"╔══ SOCIAL OSINT — {query_base} {'═'*max(0,51-len(query_base))}╗",
        "╚" + "═"*70 + "╝", "",
    ]
    findings = []

    # ── 1. GitHub — secretos públicos ─────────────────────────────────────────
    if domain or company:
        lines.append("  🐙 GITHUB — SECRETOS PÚBLICOS")
        gh_secrets = _github_secret_search(domain, company)
        if gh_secrets:
            lines.append(f"  🔴 {len(gh_secrets)} archivos con posibles secretos:")
            for s in gh_secrets:
                lines.append(f"    {s['repo']}/{s['file']}")
                lines.append(f"    → {s['url']}")
                findings.append({"type": "github_secret", "value": s["url"], "severity": "critical",
                                 "description": f"Posible secreto en GitHub: {s['repo']}/{s['file']}"})
        else:
            lines.append("  ✓ Sin secretos evidentes en GitHub público")
            if not os.environ.get("GITHUB_TOKEN"):
                lines.append("  ⚠ Agrega GITHUB_TOKEN en .env para más resultados (rate limit mayor)")
        lines.append("")

    # ── 2. Reddit ─────────────────────────────────────────────────────────────
    lines.append("  💬 REDDIT")
    reddit_results = []
    for q in [company, domain, keyword]:
        if q:
            reddit_results.extend(_reddit_api(q)[:5])
    if reddit_results:
        reddit_results.sort(key=lambda x: x.get("score", 0), reverse=True)
        lines.append(f"  {len(reddit_results)} publicaciones:")
        for post in reddit_results[:8]:
            score = post.get("score", 0)
            title = post.get("title", "")[:80]
            url = post.get("url", "")[:80]
            lines.append(f"    [{score:>5}⬆] {title}")
            lines.append(f"           {url}")
            sensitive = _detect_sensitive_content(post.get("selftext", "") + title)
            if sensitive:
                lines.append(f"           ⚠ Keywords sensibles: {', '.join(sensitive[:4])}")
                findings.append({"type": "social_leak", "value": url, "severity": "high",
                                 "description": f"Reddit post con contenido sensible: {title[:80]}"})
            else:
                findings.append({"type": "social_mention", "value": url, "severity": "info",
                                 "description": f"Mención en Reddit: {title[:80]}"})
    else:
        lines.append("  ✗ Sin menciones en Reddit")
    lines.append("")

    # ── 3. Twitter/X ──────────────────────────────────────────────────────────
    lines.append("  🐦 TWITTER / X")
    if company or domain:
        tw_results = _twitter_search(f'"{company or domain}" security OR hack OR vulnerability OR leak')
        tw_general = _twitter_search(f'"{domain_base or company}"')
        all_tw = tw_results[:5] + tw_general[:5]
        if all_tw:
            lines.append(f"  {len(all_tw)} tweets/perfiles referenciados:")
            for item in all_tw[:8]:
                url = item.get("url", "")
                title = item.get("title", "")[:80]
                snippet = item.get("snippet", "")[:120]
                lines.append(f"    {title}")
                lines.append(f"    {url}")
                if snippet:
                    lines.append(f"    {snippet}")
                sensitive = _detect_sensitive_content(title + " " + snippet)
                if sensitive:
                    findings.append({"type": "twitter_leak", "value": url, "severity": "high",
                                     "description": f"Tweet con info sensible: {title[:80]}"})
                else:
                    findings.append({"type": "twitter_mention", "value": url, "severity": "info",
                                     "description": f"Mención en Twitter: {title[:80]}"})
        else:
            lines.append("  ✗ Sin resultados en Twitter/X")
        twitter_key = os.environ.get("TWITTER_BEARER_TOKEN", "")
        if not twitter_key:
            lines.append("  ⚠ Agrega TWITTER_BEARER_TOKEN en .env para acceso a Twitter API v2")
    lines.append("")

    # ── 4. LinkedIn — empleados ───────────────────────────────────────────────
    if company:
        lines.append("  💼 LINKEDIN — EMPLEADOS")
        li_results = _linkedin_search(company)
        if li_results:
            lines.append(f"  {len(li_results)} perfiles encontrados:")
            for item in li_results[:8]:
                title = item.get("title", "")[:80]
                url = item.get("url", "")[:80]
                lines.append(f"    {title}")
                lines.append(f"    {url}")
                findings.append({"type": "employee", "value": title, "severity": "medium",
                                 "description": f"Empleado en LinkedIn: {title[:80]}"})
        else:
            lines.append("  ✗ Sin perfiles LinkedIn encontrados")
        lines.append("")

    # ── 5. Pastebin / pastebins ────────────────────────────────────────────────
    if domain or company:
        lines.append("  📋 PASTEBIN / PASTES")
        paste_results = _pastebin_search(domain, company)
        if paste_results:
            lines.append(f"  🔴 {len(paste_results)} pastes encontrados:")
            for item in paste_results[:5]:
                url = item.get("url", "")
                title = item.get("title", "")[:80]
                lines.append(f"    {title}")
                lines.append(f"    → {url}")
                findings.append({"type": "paste_leak", "value": url, "severity": "critical",
                                 "description": f"Paste con datos de {company or domain}: {title[:80]}"})
        else:
            lines.append("  ✓ Sin pastes detectados")
        lines.append("")

    # ── 6. Dorks informativos ─────────────────────────────────────────────────
    lines.append("  🔎 DORKS DE BÚSQUEDA ADICIONALES")
    lines.append("  Ejecutar manualmente para ampliar reconocimiento:\n")
    for platform, dorks in _INTEL_DORKS.items():
        lines.append(f"    {platform}:")
        for d in dorks[:2]:
            filled = d.format(company=company or "TARGET", domain=domain or "target.com",
                              domain_base=domain_base or "target")
            lines.append(f"      {filled}")
    lines.append("")

    lines.append(f"  ─── {len(findings)} hallazgos ───")
    crit = sum(1 for f in findings if f.get("severity") == "critical")
    if crit:
        lines.append(f"  🔴 {crit} hallazgos críticos — revisar de inmediato")
    if findings:
        lines.append(f"  ▶ SKILL:email_osint domain={domain}")
        lines.append(f"  ▶ SKILL:breach_search domain={domain}")

    return {"success": True, "output": "\n".join(lines), "findings": findings,
            "company": company, "domain": domain}
