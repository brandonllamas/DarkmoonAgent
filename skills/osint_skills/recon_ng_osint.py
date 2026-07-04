"""
Skill: recon_ng_osint
Wrapper de Recon-ng (Kali Linux) con ejecución automatizada de módulos
de reconocimiento por dominio/empresa/contacto. Incluye fallback Python
para los mismos datos sin Recon-ng instalado.
"""
import re
import os
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

try:
    import requests as _req
except ImportError:
    _req = None

META = {
    "name": "recon_ng_osint",
    "category": "osint",
    "description": (
        "Recon-ng automatizado: ejecuta módulos de reconocimiento por dominio o empresa. "
        "whois_pocs, bing_domain_web, google_site_web, shodan_hostname, "
        "brute_hosts, certificate_transparency, hackertarget y más. "
        "Fallback Python si no está instalado."
    ),
    "args": ["domain", "company", "modules"],
    "example": "SKILL:recon_ng_osint domain=example.com",
}

_MODULE_SETS = {
    "recon/domains-hosts/certificate_transparency": "subdomain",
    "recon/domains-hosts/brute_hosts": "subdomain",
    "recon/domains-hosts/hackertarget": "host",
    "recon/domains-hosts/bing_domain_web": "host",
    "recon/domains-contacts/whois_pocs": "contact",
    "recon/domains-contacts/pgp_search": "contact",
    "recon/domains-vulnerabilities/xssed": "vulnerability",
    "recon/domains-vulnerabilities/punkspider": "vulnerability",
    "recon/companies-multi/github_miner": "repo",
    "recon/profiles-profiles/namechk": "profile",
    "recon/hosts-hosts/resolve": "ip",
    "recon/hosts-hosts/reverse_resolve": "ptr",
    "recon/netblocks-hosts/shodan_net": "host",
}


def _sh(cmd, timeout=120):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return (r.stdout or "") + (r.stderr or ""), r.returncode
    except Exception as e:
        return str(e), 1


def _run_recon_ng(domain: str, company: str, modules_requested: list, workdir: str):
    binary = shutil.which("recon-ng") or shutil.which("recon_ng")
    if not binary:
        return None

    # Construir script de Recon-ng
    script_lines = [
        f"workspaces create {re.sub(r'[^\\w]', '_', domain or company)[:20]}",
        f"db insert domains {domain}" if domain else "",
        f"db insert companies {company}" if company else "",
    ]

    available_modules = modules_requested or list(_MODULE_SETS.keys())[:8]
    for mod in available_modules:
        script_lines.append(f"modules load {mod}")
        if domain:
            script_lines.append(f"options set SOURCE {domain}")
        script_lines.append("run")

    script_lines.extend([
        "show hosts",
        "show contacts",
        "show vulnerabilities",
        "exit",
    ])

    rc_path = Path(workdir) / "recon_script.rc"
    rc_path.write_text("\n".join(l for l in script_lines if l))

    out, code = _sh(f'"{binary}" -r "{rc_path}" 2>&1', timeout=300)
    return out if len(out) > 50 else None


def _parse_recon_ng_output(output: str) -> dict:
    """Extrae hosts, contactos y vulns del output de Recon-ng."""
    result = {"hosts": [], "contacts": [], "vulnerabilities": []}

    # Hosts table
    host_section = re.search(r"HOSTS\s*\n[-\s]+\n(.*?)(?:\n\n|\Z)", output, re.S)
    if host_section:
        for line in host_section.group(1).splitlines():
            parts = [p.strip() for p in line.split("|") if p.strip() and p.strip() != "None"]
            if parts:
                result["hosts"].append(parts[0])

    # Contacts
    cont_section = re.search(r"CONTACTS\s*\n[-\s]+\n(.*?)(?:\n\n|\Z)", output, re.S)
    if cont_section:
        for line in cont_section.group(1).splitlines():
            parts = [p.strip() for p in line.split("|") if p.strip() and p.strip() != "None"]
            if len(parts) >= 2:
                result["contacts"].append({"name": parts[0], "email": parts[1] if "@" in parts[1] else ""})

    # Vulnerabilities
    vuln_section = re.search(r"VULNERABILITIES\s*\n[-\s]+\n(.*?)(?:\n\n|\Z)", output, re.S)
    if vuln_section:
        for line in vuln_section.group(1).splitlines():
            parts = [p.strip() for p in line.split("|") if p.strip() and p.strip() != "None"]
            if parts:
                result["vulnerabilities"].append(parts[0])

    return result


def _fallback_whois(domain: str):
    binary = shutil.which("whois")
    if not binary or not domain:
        return {}
    out, _ = _sh(f'"{binary}" {domain} 2>&1', timeout=20)
    result = {}
    for line in out.splitlines():
        for field in ("Registrant", "Admin Email", "Tech Email", "Registrar", "Creation Date", "Updated Date", "Name Server"):
            if field.lower() in line.lower() and ":" in line:
                k, v = line.split(":", 1)
                result[k.strip()] = v.strip()[:120]
    return result


def _fallback_dns_brute(domain: str):
    """Brute-force DNS básico."""
    import socket
    subs = ["www", "mail", "ftp", "smtp", "dev", "api", "admin", "vpn",
            "staging", "test", "app", "m", "cdn", "static", "assets",
            "portal", "dashboard", "git", "jenkins", "wiki", "docs"]
    found = []
    for sub in subs:
        fqdn = f"{sub}.{domain}"
        try:
            ips = socket.gethostbyname_ex(fqdn)[2]
            if ips:
                found.append({"host": fqdn, "ips": ips})
        except Exception:
            pass
    return found


def _fallback_hackertarget(domain: str):
    if _req is None:
        return []
    try:
        r = _req.get(f"https://api.hackertarget.com/hostsearch/?q={domain}",
                     timeout=15, headers={"User-Agent": "HackerAgent-OSINT"})
        hosts = []
        for line in r.text.splitlines():
            if "," in line:
                host, ip = line.split(",", 1)
                hosts.append({"host": host.strip(), "ip": ip.strip()})
        return hosts[:50]
    except Exception:
        return []


def _fallback_github_search(company: str, domain: str):
    """Busca repos y empleados en GitHub."""
    if _req is None:
        return {}
    result = {"repos": [], "users": []}
    token = os.environ.get("GITHUB_TOKEN", "")
    headers = {"User-Agent": "HackerAgent-OSINT"}
    if token:
        headers["Authorization"] = f"token {token}"

    # Buscar organización
    query = company or domain.split(".")[0]
    try:
        r = _req.get(f"https://api.github.com/search/repositories?q=org:{query}&per_page=10",
                     headers=headers, timeout=10)
        if r.status_code == 200:
            for item in r.json().get("items", []):
                result["repos"].append({"name": item.get("full_name"), "url": item.get("html_url"),
                                        "stars": item.get("stargazers_count", 0)})
    except Exception:
        pass

    # Buscar usuarios
    if domain:
        try:
            r = _req.get(f"https://api.github.com/search/users?q={query}+in:email&per_page=10",
                         headers=headers, timeout=10)
            if r.status_code == 200:
                for user in r.json().get("items", []):
                    result["users"].append({"login": user.get("login"), "url": user.get("html_url")})
        except Exception:
            pass
    return result


def run(domain: str = "", company: str = "", modules: str = "", **kwargs) -> dict:
    domain  = (domain  or kwargs.get("target", "")).strip().lower()
    company = (company or kwargs.get("org",    "")).strip()
    if not domain and not company:
        return {"success": False, "findings": [],
                "output": 'Falta "domain" o "company". Ej: SKILL:recon_ng_osint domain=example.com'}
    domain = re.sub(r"^https?://", "", domain).split("/")[0] if domain else ""
    modules_list = [m.strip() for m in modules.split(",") if m.strip()] if modules else []

    lines = [
        f"╔══ RECON-NG OSINT — {domain or company} {'═'*max(0,48-len(domain or company))}╗",
        "╚" + "═"*70 + "╝", "",
    ]
    findings = []

    # ── 1. Recon-ng nativo ────────────────────────────────────────────────────
    with tempfile.TemporaryDirectory() as tmpdir:
        rn_out = _run_recon_ng(domain, company, modules_list, tmpdir)

    if rn_out:
        lines.append("  ✅ Recon-ng (nativo) ejecutado\n")
        lines.append(rn_out[:8000])
        parsed = _parse_recon_ng_output(rn_out)
        for host in parsed["hosts"][:20]:
            findings.append({"type": "subdomain", "value": host, "severity": "info",
                             "description": f"Recon-ng host: {host}"})
        for contact in parsed["contacts"][:20]:
            name = contact.get("name", "")
            email = contact.get("email", "")
            findings.append({"type": "contact", "value": f"{name} {email}".strip(),
                             "severity": "medium",
                             "description": f"Contacto: {name} <{email}>"})
        for vuln in parsed["vulnerabilities"]:
            findings.append({"type": "vulnerability", "value": vuln, "severity": "high",
                             "description": f"Recon-ng vuln: {vuln}"})
        lines.append("")
    else:
        lines.append("  ⚠ Recon-ng no instalado → sudo apt install recon-ng (Kali)")
        lines.append("    Usando fallbacks Python…\n")

        # ── 2. Fallback: WHOIS ────────────────────────────────────────────────
        if domain:
            lines.append("  📋 WHOIS")
            whois_data = _fallback_whois(domain)
            if whois_data:
                for k, v in whois_data.items():
                    lines.append(f"    {k}: {v}")
                    if "email" in k.lower() and "@" in v:
                        findings.append({"type": "email", "value": v.split()[-1], "severity": "medium",
                                         "description": f"Email WHOIS ({k}): {v}"})
                    elif "registrant" in k.lower() and v:
                        findings.append({"type": "registrant", "value": v, "severity": "info",
                                         "description": f"Registrante: {v}"})
                    elif "name server" in k.lower():
                        findings.append({"type": "nameserver", "value": v, "severity": "info",
                                         "description": f"Nameserver: {v}"})
            lines.append("")

        # ── 3. Fallback: DNS brute ────────────────────────────────────────────
        if domain:
            lines.append("  🔍 DNS BRUTEFORCE (subconjunto)")
            dns_hosts = _fallback_dns_brute(domain)
            lines.append(f"    {len(dns_hosts)} subdominios resolvibles:")
            for h in dns_hosts:
                ips = ", ".join(h["ips"][:3])
                lines.append(f"      {h['host']:<45} → {ips}")
                findings.append({"type": "subdomain", "value": h["host"], "severity": "info",
                                 "description": f"Subdominio: {h['host']} → {ips}"})
            lines.append("")

        # ── 4. Fallback: HackerTarget ─────────────────────────────────────────
        if domain:
            lines.append("  📡 HACKERTARGET")
            ht_hosts = _fallback_hackertarget(domain)
            if ht_hosts:
                lines.append(f"    {len(ht_hosts)} hosts:")
                for h in ht_hosts[:20]:
                    lines.append(f"      {h['host']:<45} {h['ip']}")
                    findings.append({"type": "host", "value": h["host"], "severity": "info",
                                     "description": f"Host: {h['host']} → {h['ip']}"})
            lines.append("")

        # ── 5. Fallback: GitHub ───────────────────────────────────────────────
        lines.append("  🐙 GITHUB")
        gh = _fallback_github_search(company, domain)
        if gh["repos"]:
            lines.append(f"  {len(gh['repos'])} repos encontrados:")
            for repo in gh["repos"][:10]:
                lines.append(f"    ⭐{repo['stars']:>5}  {repo['name']}  {repo['url']}")
                findings.append({"type": "github_repo", "value": repo["url"], "severity": "medium",
                                 "description": f"Repo público: {repo['name']}"})
        if gh["users"]:
            lines.append(f"  {len(gh['users'])} usuarios:")
            for u in gh["users"][:5]:
                lines.append(f"    @{u['login']}  {u['url']}")
                findings.append({"type": "github_user", "value": u["login"], "severity": "medium",
                                 "description": f"Empleado en GitHub: @{u['login']}"})
        if not gh["repos"] and not gh["users"]:
            lines.append("  ✗ Sin repos/usuarios encontrados en GitHub")
        lines.append("")

    lines.append(f"  ─── {len(findings)} hallazgos ───")
    if findings:
        lines.append(f"  ▶ SKILL:theharvester domain={domain}")
        if domain:
            lines.append(f"  ▶ SKILL:dns_full domain={domain}")

    return {"success": True, "output": "\n".join(lines), "findings": findings,
            "domain": domain, "company": company}
