"""
Skill: sherlock_osint
Username OSINT: Sherlock + Maigret (Kali) + fallback Python propio.
Busca un username en 400+ redes sociales, foros, plataformas tech,
comunidades de gaming, dating sites, etc. Devuelve perfiles encontrados
con URL, status y contexto.
"""
import re
import json
import shutil
import subprocess
import concurrent.futures
from pathlib import Path

try:
    import requests as _req
except ImportError:
    _req = None

META = {
    "name": "sherlock_osint",
    "category": "osint",
    "description": (
        "Búsqueda de username en 400+ plataformas: redes sociales, foros, gaming, "
        "tech, dating, crypto. Usa Sherlock/Maigret (Kali) con fallback Python propio. "
        "Detecta perfiles activos con URL directa."
    ),
    "args": ["username", "timeout", "sites"],
    "example": "SKILL:sherlock_osint username=johndoe",
}

# Plataformas con verificación directa (sin depender de herramientas externas)
_PLATFORMS = [
    # Social / General
    {"name": "GitHub",        "url": "https://github.com/{}",              "check": "type=\"profile\""},
    {"name": "GitLab",        "url": "https://gitlab.com/{}",              "check": "\"user\""},
    {"name": "Twitter/X",     "url": "https://twitter.com/{}",             "check": "\"description\""},
    {"name": "Instagram",     "url": "https://www.instagram.com/{}/",      "check": "\"username\""},
    {"name": "TikTok",        "url": "https://www.tiktok.com/@{}",         "check": "uniqueId"},
    {"name": "YouTube",       "url": "https://www.youtube.com/@{}",        "check": "\"canonicalBaseUrl\""},
    {"name": "Reddit",        "url": "https://www.reddit.com/user/{}/",    "check": "\"is_employee\""},
    {"name": "Pinterest",     "url": "https://www.pinterest.com/{}/",      "check": "\"username\""},
    {"name": "Tumblr",        "url": "https://{}.tumblr.com",              "check": "tumblr"},
    {"name": "Flickr",        "url": "https://www.flickr.com/people/{}",   "check": "\"nsid\""},
    {"name": "Mastodon",      "url": "https://mastodon.social/@{}",        "check": "\"preferredUsername\""},
    # Tech / Dev
    {"name": "HackerNews",    "url": "https://news.ycombinator.com/user?id={}", "check": "\"user\""},
    {"name": "Dev.to",        "url": "https://dev.to/{}",                  "check": "\"username\""},
    {"name": "Hashnode",      "url": "https://hashnode.com/@{}",           "check": "username"},
    {"name": "Medium",        "url": "https://medium.com/@{}",             "check": "\"@{}\""},
    {"name": "Codepen",       "url": "https://codepen.io/{}",              "check": "\"username\""},
    {"name": "Replit",        "url": "https://replit.com/@{}",             "check": "username"},
    {"name": "Stack Overflow","url": "https://stackoverflow.com/users/{}",  "check": "\"display_name\""},
    {"name": "Keybase",       "url": "https://keybase.io/{}",              "check": "\"basics\""},
    {"name": "Docker Hub",    "url": "https://hub.docker.com/u/{}",        "check": "\"username\""},
    {"name": "NPM",           "url": "https://www.npmjs.com/~{}",          "check": "\"username\""},
    {"name": "PyPI",          "url": "https://pypi.org/user/{}/",          "check": "username"},
    {"name": "HackTheBox",    "url": "https://www.hackthebox.com/profile/{}", "check": "profile"},
    {"name": "TryHackMe",     "url": "https://tryhackme.com/p/{}",         "check": "\"username\""},
    # Gaming
    {"name": "Steam",         "url": "https://steamcommunity.com/id/{}",   "check": "\"personaname\""},
    {"name": "Twitch",        "url": "https://www.twitch.tv/{}",           "check": "\"login\""},
    {"name": "Chess.com",     "url": "https://www.chess.com/member/{}",    "check": "\"username\""},
    # Music / Art
    {"name": "SoundCloud",    "url": "https://soundcloud.com/{}",          "check": "\"permalink\""},
    {"name": "Spotify",       "url": "https://open.spotify.com/user/{}",   "check": "\"display_name\""},
    {"name": "Last.fm",       "url": "https://www.last.fm/user/{}",        "check": "\"name\""},
    {"name": "Bandcamp",      "url": "https://{}.bandcamp.com",            "check": "bandcamp"},
    # Content / Video
    {"name": "Vimeo",         "url": "https://vimeo.com/{}",               "check": "\"user\""},
    {"name": "Dailymotion",   "url": "https://www.dailymotion.com/{}",     "check": "\"username\""},
    {"name": "Rumble",        "url": "https://rumble.com/user/{}",         "check": "\"username\""},
    # Professional
    {"name": "Gravatar",      "url": "https://en.gravatar.com/{}",         "check": "\"entry\""},
    {"name": "About.me",      "url": "https://about.me/{}",                "check": "\"username\""},
    {"name": "Crunchbase",    "url": "https://www.crunchbase.com/person/{}","check": "\"identifier\""},
    # Crypto
    {"name": "Bitcointalk",   "url": "https://bitcointalk.org/index.php?action=profile;u={}", "check": "\"member\""},
    # Misc
    {"name": "Pastebin",      "url": "https://pastebin.com/u/{}",          "check": "\"user\""},
    {"name": "Imgur",         "url": "https://imgur.com/user/{}",          "check": "\"url\""},
    {"name": "Disqus",        "url": "https://disqus.com/by/{}/",          "check": "\"username\""},
    {"name": "Quora",         "url": "https://www.quora.com/profile/{}",   "check": "\"profile\""},
    {"name": "ProductHunt",   "url": "https://www.producthunt.com/@{}",    "check": "\"username\""},
    {"name": "Giphy",         "url": "https://giphy.com/{}",               "check": "username"},
]


def _sh(cmd, timeout=120):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return (r.stdout or "") + (r.stderr or ""), r.returncode
    except Exception as e:
        return str(e), 1


def _run_sherlock(username, tout):
    binary = shutil.which("sherlock")
    if not binary:
        return None, "not_found"
    out, code = _sh(f'"{binary}" {username} --timeout {tout} --print-found 2>&1', timeout=tout + 30)
    return out, "ok"


def _run_maigret(username, tout):
    binary = shutil.which("maigret")
    if not binary:
        return None, "not_found"
    out, code = _sh(
        f'"{binary}" {username} --timeout {tout} --no-color -a 2>&1 | head -200',
        timeout=tout + 30)
    return out, "ok"


def _check_platform(platform, username, tout):
    if _req is None:
        return None
    url = platform["url"].format(username)
    check = platform["check"].format(username)
    try:
        r = _req.get(url, timeout=tout,
                     headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64)"},
                     allow_redirects=True)
        if r.status_code == 200 and check.lower() in r.text.lower():
            return {"name": platform["name"], "url": url, "status": "found"}
    except Exception:
        pass
    return None


def run(username: str = "", timeout: str = "8", sites: str = "", **kwargs) -> dict:
    username = (username or kwargs.get("user") or "").strip()
    if not username:
        return {"success": False, "findings": [],
                "output": 'Falta "username". Ej: SKILL:sherlock_osint username=johndoe'}
    try:
        tout = int(timeout)
    except Exception:
        tout = 8

    lines = [
        f"╔══ SHERLOCK OSINT — @{username} {'═'*max(0,50-len(username))}╗",
        f"  Buscando en {len(_PLATFORMS)} plataformas  timeout={tout}s",
        "╚" + "═"*70 + "╝", "",
    ]
    findings = []
    found_profiles = []

    # ── 1. Sherlock nativo ────────────────────────────────────────────────────
    sherlock_out, s_status = _run_sherlock(username, tout * 3)
    if s_status == "ok" and sherlock_out:
        lines.append("  ✅ Sherlock (nativo) ejecutado\n")
        for line in sherlock_out.splitlines():
            if "[+]" in line or "http" in line.lower():
                lines.append(f"  {line}")
                url_m = re.search(r'https?://\S+', line)
                if url_m:
                    found_profiles.append(url_m.group(0))
                    findings.append({"type": "social_profile", "value": url_m.group(0),
                                     "severity": "medium",
                                     "description": f"Perfil encontrado: {url_m.group(0)}"})
    else:
        # ── 2. Maigret nativo ──────────────────────────────────────────────
        maigret_out, m_status = _run_maigret(username, tout * 3)
        if m_status == "ok" and maigret_out:
            lines.append("  ✅ Maigret (nativo) ejecutado\n")
            for line in maigret_out.splitlines():
                if "+" in line or "http" in line.lower():
                    lines.append(f"  {line}")
                    url_m = re.search(r'https?://\S+', line)
                    if url_m:
                        found_profiles.append(url_m.group(0))
                        findings.append({"type": "social_profile", "value": url_m.group(0),
                                         "severity": "medium",
                                         "description": f"Perfil encontrado: {url_m.group(0)}"})
        else:
            lines.append("  ⚠ Sherlock/Maigret no instalados → verificación directa")
            lines.append("    Instalar: pip3 install sherlock-project  |  pip3 install maigret\n")

            # ── 3. Fallback propio (paralelo) ──────────────────────────────
            plats = _PLATFORMS
            if sites:
                wanted = {s.strip().lower() for s in sites.split(",")}
                plats = [p for p in plats if p["name"].lower() in wanted]

            lines.append(f"  🔍 Verificando {len(plats)} plataformas en paralelo…\n")
            results = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
                futs = {ex.submit(_check_platform, p, username, tout): p for p in plats}
                for fut in concurrent.futures.as_completed(futs):
                    res = fut.result()
                    if res:
                        results.append(res)

            results.sort(key=lambda x: x["name"])
            if results:
                lines.append(f"  ✅ {len(results)} perfiles encontrados:\n")
                for r in results:
                    lines.append(f"      ✓ {r['name']:<20} {r['url']}")
                    found_profiles.append(r["url"])
                    findings.append({"type": "social_profile", "value": r["url"],
                                     "severity": "medium",
                                     "description": f"Perfil @{username} en {r['name']}: {r['url']}"})
            else:
                lines.append("  ✗ No se encontraron perfiles con este username.")
            lines.append("")

    lines.append(f"  ─── {len(found_profiles)} perfiles encontrados ───")
    if found_profiles:
        lines.append(f"  ▶ Siguiente: SKILL:email_osint  |  SKILL:social_osint username={username}")

    return {"success": True, "output": "\n".join(lines), "findings": findings,
            "profiles": found_profiles, "username": username}
