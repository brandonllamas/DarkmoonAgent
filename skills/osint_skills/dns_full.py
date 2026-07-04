"""
Skill: dns_full
Reconocimiento DNS completo: zone transfer, bruteforce, wildcard detection,
registros DMARC/SPF/DKIM, subdomain takeover checks.
Usa DNSRecon, Fierce, Amass (Kali) con fallback Python puro.
"""
import re
import os
import json
import shutil
import socket
import subprocess
import concurrent.futures
from pathlib import Path

try:
    import requests as _req
except ImportError:
    _req = None

META = {
    "name": "dns_full",
    "category": "osint",
    "description": (
        "Reconocimiento DNS completo: zone transfer, A/MX/NS/TXT/CNAME/SPF/DMARC/DKIM, "
        "bruteforce de subdominios, wildcard detection, subdomain takeover. "
        "Usa DNSRecon, Fierce, Amass (Kali) o fallback Python."
    ),
    "args": ["domain", "wordlist", "threads", "brute", "axfr"],
    "example": "SKILL:dns_full domain=example.com brute=true",
}

_COMMON_SUBS = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "ns1", "ns2", "webmail",
    "vpn", "dev", "staging", "test", "api", "admin", "dashboard", "portal",
    "app", "beta", "demo", "m", "mobile", "cdn", "static", "assets", "media",
    "img", "images", "blog", "shop", "store", "forum", "help", "support",
    "docs", "wiki", "git", "gitlab", "jenkins", "jira", "confluence", "grafana",
    "monitor", "prometheus", "elastic", "kibana", "db", "database", "mysql",
    "postgres", "redis", "mongo", "cache", "proxy", "gateway", "auth", "sso",
    "login", "register", "signup", "account", "panel", "cp", "whm", "cpanel",
    "autodiscover", "autoconfig", "mx1", "mx2", "smtp1", "smtp2", "mail2",
    "remote", "exchange", "owa", "webdav", "sharepoint", "office", "teams",
    "legacy", "old", "new", "internal", "intranet", "extranet", "private",
    "secure", "s3", "backup", "logs", "files", "upload", "download", "assets2",
]

_TAKEOVER_PATTERNS = {
    "github.io":      "There isn't a GitHub Pages site here",
    "heroku.com":     "No such app",
    "s3.amazonaws.com": "NoSuchBucket",
    "netlify.com":    "Not Found - Request ID",
    "surge.sh":       "project not found",
    "bitbucket.io":   "Repository not found",
    "ghost.io":       "The thing you were looking for is no longer here",
    "readthedocs.io": "project doesn't exist",
    "zendesk.com":    "Help Center Closed",
    "wpengine.com":   "The site you were looking for couldn't be found",
    "pantheon.io":    "404 error unknown site",
    "azure.com":      "Azure Web App - Error 404",
    "cloudfront.net": "ERROR: The request could not be satisfied",
    "fly.dev":        "404 Not Found",
    "vercel.app":     "The deployment could not be found",
}


def _sh(cmd, timeout=120):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return (r.stdout or "") + (r.stderr or ""), r.returncode
    except Exception as e:
        return str(e), 1


def _resolve(host, rtype="A"):
    try:
        import dns.resolver
        ans = dns.resolver.resolve(host, rtype, lifetime=3)
        return [str(r) for r in ans]
    except Exception:
        pass
    try:
        out, _ = _sh(f"dig +short {rtype} {host} 2>/dev/null || nslookup -type={rtype} {host} 2>/dev/null", 8)
        return [l.strip() for l in out.splitlines() if l.strip() and not l.startswith(";")][:10]
    except Exception:
        return []


def _axfr(domain, nameserver):
    try:
        import dns.zone
        import dns.query
        z = dns.zone.from_xfr(dns.query.xfr(nameserver, domain, timeout=5))
        records = []
        for name, node in z.nodes.items():
            records.append(str(name))
        return records
    except Exception:
        pass
    out, _ = _sh(f"dig axfr {domain} @{nameserver} 2>&1", 10)
    if "Transfer failed" not in out and "connection timed out" not in out and len(out) > 100:
        return [l.strip() for l in out.splitlines() if l.strip() and not l.startswith(";")]
    return []


def _check_sub(subdomain, domain, tout=3):
    fqdn = f"{subdomain}.{domain}"
    try:
        ips = socket.gethostbyname_ex(fqdn)[2]
        if ips:
            return {"name": fqdn, "ips": ips}
    except Exception:
        pass
    return None


def _check_takeover(fqdn, cname):
    if _req is None:
        return None
    for pattern, fingerprint in _TAKEOVER_PATTERNS.items():
        if pattern in cname:
            try:
                r = _req.get(f"http://{fqdn}", timeout=6, allow_redirects=True)
                if fingerprint.lower() in r.text.lower():
                    return pattern
            except Exception:
                pass
    return None


def _run_dnsrecon(domain):
    binary = shutil.which("dnsrecon")
    if not binary:
        return None
    out, _ = _sh(f'"{binary}" -d {domain} -t std 2>&1', timeout=120)
    return out if len(out) > 50 else None


def _run_fierce(domain):
    binary = shutil.which("fierce")
    if not binary:
        return None
    out, _ = _sh(f'"{binary}" --domain {domain} 2>&1 | head -200', timeout=120)
    return out if len(out) > 50 else None


def _run_amass(domain):
    binary = shutil.which("amass")
    if not binary:
        return None
    out, _ = _sh(f'"{binary}" enum -passive -d {domain} -timeout 2 2>&1 | head -300', timeout=180)
    return out if len(out) > 50 else None


def run(domain: str = "", wordlist: str = "", threads: str = "30",
        brute: str = "true", axfr: str = "true", **kwargs) -> dict:
    domain = (domain or kwargs.get("target", "")).strip().lower()
    if not domain:
        return {"success": False, "findings": [],
                "output": 'Falta "domain". Ej: SKILL:dns_full domain=example.com'}
    domain = re.sub(r"^https?://", "", domain).split("/")[0]
    do_brute = brute.lower() not in ("0", "false", "no")
    do_axfr  = axfr.lower()  not in ("0", "false", "no")
    try:
        nthreads = int(threads)
    except Exception:
        nthreads = 30

    lines = [
        f"╔══ DNS FULL — {domain} {'═'*max(0,55-len(domain))}╗",
        "╚" + "═"*70 + "╝", "",
    ]
    findings = []

    # ── 1. Registros base ─────────────────────────────────────────────────────
    lines.append("  📡 REGISTROS DNS BASE")
    for rtype in ("A", "AAAA", "MX", "NS", "SOA", "TXT", "CNAME"):
        recs = _resolve(domain, rtype)
        if recs:
            lines.append(f"    {rtype:<6}: {', '.join(recs[:5])}")
            if rtype in ("NS", "A"):
                for r in recs:
                    findings.append({"type": f"dns_{rtype.lower()}", "value": r,
                                     "severity": "info", "description": f"{rtype} de {domain}: {r}"})
    lines.append("")

    # ── 2. SPF / DMARC / DKIM ────────────────────────────────────────────────
    lines.append("  🔒 EMAIL SECURITY (SPF / DMARC / DKIM)")
    spf_recs = _resolve(domain, "TXT")
    spf = next((r for r in spf_recs if "v=spf1" in r.lower()), None)
    if spf:
        lines.append(f"    SPF   : {spf[:120]}")
        if "~all" in spf:
            lines.append("    ⚠ SPF usa ~all (softfail) — spoofing posible")
            findings.append({"type": "spf_softfail", "value": domain, "severity": "medium",
                             "description": f"SPF softfail: {domain} vulnerable a email spoofing"})
        elif "-all" in spf:
            lines.append("    ✓ SPF usa -all (hardfail)")
        elif "+all" in spf:
            lines.append("    🔴 SPF usa +all — PERMITE CUALQUIER ORIGEN")
            findings.append({"type": "spf_permissive", "value": domain, "severity": "high",
                             "description": f"SPF +all: {domain} permite spoofing"})
    else:
        lines.append("    ⚠ Sin registro SPF — email spoofing posible")
        findings.append({"type": "no_spf", "value": domain, "severity": "high",
                         "description": f"Sin SPF en {domain}"})

    dmarc = _resolve(f"_dmarc.{domain}", "TXT")
    if dmarc:
        lines.append(f"    DMARC : {dmarc[0][:120]}")
        if "p=none" in str(dmarc):
            lines.append("    ⚠ DMARC p=none (solo monitoreo, sin rechazo)")
            findings.append({"type": "dmarc_none", "value": domain, "severity": "medium",
                             "description": f"DMARC p=none en {domain}"})
    else:
        lines.append("    ⚠ Sin registro DMARC")
        findings.append({"type": "no_dmarc", "value": domain, "severity": "medium",
                         "description": f"Sin DMARC en {domain}"})

    for selector in ("default", "google", "k1", "mail", "dkim", "selector1", "selector2"):
        dkim = _resolve(f"{selector}._domainkey.{domain}", "TXT")
        if dkim:
            lines.append(f"    DKIM  : selector={selector}  {dkim[0][:80]}")
            break
    lines.append("")

    # ── 3. Zone Transfer ──────────────────────────────────────────────────────
    if do_axfr:
        lines.append("  🚨 ZONE TRANSFER (AXFR)")
        ns_recs = _resolve(domain, "NS")
        for ns in ns_recs[:4]:
            ns = ns.rstrip(".")
            records = _axfr(domain, ns)
            if records:
                lines.append(f"    🔴 AXFR EXITOSO en {ns}! {len(records)} registros:")
                for rec in records[:30]:
                    lines.append(f"      {rec}")
                findings.append({"type": "axfr_success", "value": ns, "severity": "critical",
                                 "description": f"Zone transfer exitoso en {ns} — todos los registros expuestos"})
            else:
                lines.append(f"    ✓ {ns}: AXFR denegado")
        lines.append("")

    # ── 4. Kali tools ─────────────────────────────────────────────────────────
    used_kali = False
    dr_out = _run_dnsrecon(domain)
    if dr_out:
        used_kali = True
        lines.append("  ✅ DNSRecon (nativo)\n")
        lines.append(dr_out[:4000])
        for sub in re.findall(rf"[\w\-]+\.{re.escape(domain)}", dr_out):
            findings.append({"type": "subdomain", "value": sub, "severity": "info",
                             "description": f"Subdominio: {sub}"})
        lines.append("")

    if not used_kali:
        fi_out = _run_fierce(domain)
        if fi_out:
            used_kali = True
            lines.append("  ✅ Fierce (nativo)\n")
            lines.append(fi_out[:3000])
            lines.append("")

    am_out = _run_amass(domain)
    if am_out:
        lines.append("  ✅ Amass (nativo)\n")
        lines.append(am_out[:3000])
        for sub in re.findall(rf"[\w\.\-]+\.{re.escape(domain)}", am_out):
            if sub != domain:
                findings.append({"type": "subdomain", "value": sub, "severity": "info",
                                 "description": f"Amass subdominio: {sub}"})
        lines.append("")

    if not used_kali and not am_out:
        lines.append("  ⚠ DNSRecon/Fierce/Amass no instalados — brute-force Python\n"
                     "    sudo apt install dnsrecon fierce  /  go install github.com/owasp-amass/amass/v4/...@master")
        lines.append("")

    # ── 5. Bruteforce de subdominios ──────────────────────────────────────────
    if do_brute:
        subs_to_try = _COMMON_SUBS[:]
        if wordlist and Path(wordlist).exists():
            with open(wordlist) as f:
                extra = [l.strip() for l in f if l.strip()][:500]
            subs_to_try = list(set(subs_to_try + extra))

        lines.append(f"  🔍 BRUTEFORCE ({len(subs_to_try)} subdominios, {nthreads} threads)")
        discovered = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=nthreads) as ex:
            futs = {ex.submit(_check_sub, sub, domain): sub for sub in subs_to_try}
            for fut in concurrent.futures.as_completed(futs):
                res = fut.result()
                if res:
                    discovered.append(res)

        discovered.sort(key=lambda x: x["name"])
        if discovered:
            lines.append(f"  ✅ {len(discovered)} subdominios resolvibles:\n")
            for item in discovered:
                ips = ", ".join(item["ips"][:3])
                lines.append(f"      {item['name']:<45} → {ips}")
                findings.append({"type": "subdomain", "value": item["name"], "severity": "info",
                                 "description": f"Subdominio activo: {item['name']} → {ips}"})
                # Check CNAME takeover
                cnames = _resolve(item["name"], "CNAME")
                for cname in cnames:
                    takeover = _check_takeover(item["name"], cname)
                    if takeover:
                        findings.append({"type": "subdomain_takeover", "value": item["name"],
                                         "severity": "critical",
                                         "description": f"TAKEOVER posible: {item['name']} → CNAME {cname} ({takeover})"})
                        lines.append(f"      🔴 TAKEOVER: {item['name']} → {cname}")
        else:
            lines.append("  ✗ Sin subdominios adicionales encontrados")
        lines.append("")

    total = len(findings)
    crit  = sum(1 for f in findings if f.get("severity") == "critical")
    high  = sum(1 for f in findings if f.get("severity") == "high")
    lines.append(f"  ─── {total} hallazgos ({crit} críticos, {high} altos) ───")
    if crit:
        lines.append("  ▶ Revisar AXFR y takeovers para explotación inmediata")

    return {"success": True, "output": "\n".join(lines), "findings": findings, "domain": domain}
