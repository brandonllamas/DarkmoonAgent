"""
Skill: ad_audit  v2.1 — Infalible Active Directory Scanner & Auditor
======================================================================
Descubre Domain Controllers en rangos IP, dominios o hosts individuales
y audita los vectores de ataque más comunes en entornos AD:

  ✓ LDAP Anonymous Bind / Search (enumeración sin credenciales)
  ✓ LDAP Signing (signing NOT required → NTLM Relay)
  ✓ LDAPS Certificate validity
  ✓ Global Catalog (puerto 3268)
  ✓ SMB Signing (signing NOT required → SMB/NTLM Relay)
  ✓ SMB Null Session / IPC$ anonymous access
  ✓ Kerberos (puerto 88 — AS-REP Roasting, Kerberoasting)
  ✓ RPC Endpoint Mapper

Metodología:
  - DNS SRV lookup para resolución automática de DCs
  - Escaneo de puertos PARALELO (ThreadPoolExecutor)
  - LDAP con ldap3; SMB con socket raw (sin herramientas externas)
  - Auto-instalación de dependencias (ldap3, dnspython)
  - Retry logic y fallbacks para entornos ruidosos/lentos
  - Deduplicación de hallazgos, resumen por severidad

Uso:
  SKILL:ad_audit target=192.168.1.10
  SKILL:ad_audit target=corp.local
  SKILL:ad_audit target=10.10.0.0/24 timeout=1.5 threads=50
"""

from __future__ import annotations

import socket
import ssl
import struct
import subprocess
import sys
import uuid
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from ipaddress import ip_network

# ── Auto-install dependencies ──────────────────────────────────────────────────
def _ensure_pkg(pip_name: str, import_as: str | None = None) -> bool:
    """Install a Python package if not present. Returns True if available."""
    imp = import_as or pip_name
    try:
        __import__(imp)
        return True
    except ImportError:
        pass
    try:
        subprocess.run(
            [sys.executable, "-m", "pip", "install", pip_name, "-q",
             "--disable-pip-version-check"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=60,
        )
        __import__(imp)
        return True
    except Exception as exc:
        print(f"[ad_audit] WARN: No se pudo instalar {pip_name}: {exc}")
        return False


_HAS_LDAP3 = _ensure_pkg("ldap3")
_HAS_DNS   = _ensure_pkg("dnspython", "dns.resolver")

if _HAS_LDAP3:
    import ldap3
    from ldap3.core import exceptions as _ldap3_exc

if _HAS_DNS:
    import dns.resolver
    import dns.exception

# ── Skill metadata ─────────────────────────────────────────────────────────────
META = {
    "name":        "ad_audit",
    "category":    "vuln_scan",
    "description": (
        "Escanea e identifica Domain Controllers de Active Directory. "
        "Audita LDAP signing/anonymous, SMB signing/null session, LDAPS, Kerberos y Global Catalog."
    ),
    "args": ["target", "timeout", "threads"],
    "example": "SKILL:ad_audit target=192.168.1.0/24",
}

# ── AD Port definitions ────────────────────────────────────────────────────────
AD_PORTS: dict[int, str] = {
    53:   "DNS",
    88:   "Kerberos",
    135:  "RPC Endpoint Mapper",
    139:  "NetBIOS Session",
    389:  "LDAP",
    445:  "SMB",
    464:  "Kerberos PW Change",
    593:  "RPC over HTTP",
    636:  "LDAPS",
    3268: "LDAP Global Catalog",
    3269: "LDAPS Global Catalog",
    5985: "WinRM HTTP",
    5986: "WinRM HTTPS",
    9389: "AD Web Services",
}

# Ports that together strongly indicate a Domain Controller
_DC_INDICATORS = {88, 389, 3268, 464, 636}

# ── Severity ordering ──────────────────────────────────────────────────────────
_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# ══════════════════════════════════════════════════════════════════════════════
# Target parsing
# ══════════════════════════════════════════════════════════════════════════════

def _parse_targets(target_str: str, max_hosts: int = 512) -> list[str]:
    """
    Parse target string into a list of IPs/hostnames.
    Accepts: single IP, CIDR, comma-separated list, hostname, or domain.
    """
    targets: list[str] = []
    seen: set[str] = set()

    for raw in target_str.split(","):
        part = raw.strip()
        if not part:
            continue
        if "/" in part:
            try:
                net = ip_network(part, strict=False)
                for ip in list(net.hosts())[:max_hosts]:
                    s = str(ip)
                    if s not in seen:
                        seen.add(s)
                        targets.append(s)
            except ValueError:
                if part not in seen:
                    seen.add(part)
                    targets.append(part)
        else:
            if part not in seen:
                seen.add(part)
                targets.append(part)

    return targets


def _is_domain_name(s: str) -> bool:
    """Return True if the string looks like a domain name, not an IP or CIDR."""
    if "/" in s or "," in s:
        return False
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", s):
        return False
    return "." in s


# ══════════════════════════════════════════════════════════════════════════════
# DNS SRV DC discovery
# ══════════════════════════════════════════════════════════════════════════════

def _resolve_dc_srv(domain: str, timeout: float = 6.0) -> list[dict]:
    """
    Resolve Domain Controllers for a given domain via DNS SRV records.
    Returns list of {hostname, ip, source}.
    Falls back to nslookup if dnspython is unavailable.
    """
    dcs: list[dict] = []
    seen: set[str] = set()

    srv_names = [
        f"_ldap._tcp.dc._msdcs.{domain}",
        f"_kerberos._tcp.dc._msdcs.{domain}",
        f"_ldap._tcp.{domain}",
    ]

    def _add_dc(host: str, source: str):
        host = host.rstrip(".")
        key = host.lower()
        if key in seen:
            return
        seen.add(key)
        ip = None
        try:
            ip = socket.gethostbyname(host)
        except Exception:
            pass
        dcs.append({"hostname": host, "ip": ip, "source": source})

    if _HAS_DNS:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = timeout
        for q in srv_names:
            try:
                for rdata in resolver.resolve(q, "SRV"):
                    _add_dc(str(rdata.target), q)
            except Exception:
                pass
    else:
        # Fallback: nslookup (cross-platform)
        for q in srv_names:
            try:
                proc = subprocess.run(
                    ["nslookup", "-type=SRV", q],
                    capture_output=True, text=True, timeout=timeout,
                    encoding="utf-8", errors="replace"
                )
                for m in re.finditer(r"svr hostname\s*=\s*(\S+)", proc.stdout, re.I):
                    _add_dc(m.group(1), q)
            except Exception:
                pass

    # Final fallback: A-record lookup of the domain itself
    if not dcs:
        try:
            ip = socket.gethostbyname(domain)
            dcs.append({"hostname": domain, "ip": ip, "source": "A record"})
        except Exception:
            pass

    return dcs


# ══════════════════════════════════════════════════════════════════════════════
# Parallel port scanner
# ══════════════════════════════════════════════════════════════════════════════

def _scan_ports_parallel(ip: str, timeout: float = 1.5,
                          max_workers: int = 30) -> dict[int, str]:
    """
    Probe all AD-relevant ports in parallel.
    Returns {port: service_name} for open ports.
    """
    open_ports: dict[int, str] = {}

    def _probe(port: int):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((ip, port)) == 0:
                    return port, AD_PORTS[port]
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(_probe, p): p for p in AD_PORTS}
        # Total wait: each probe has 'timeout' seconds; give 3s grace
        wait_timeout = timeout + 3.0
        for fut in as_completed(futures, timeout=wait_timeout):
            try:
                res = fut.result()
                if res:
                    open_ports[res[0]] = res[1]
            except Exception:
                pass

    return dict(sorted(open_ports.items()))


# ══════════════════════════════════════════════════════════════════════════════
# SMB signing / null session
# ══════════════════════════════════════════════════════════════════════════════

def _build_smb2_negotiate() -> bytes:
    """Build a minimal SMB2 NEGOTIATE request (raw bytes)."""
    client_guid = uuid.uuid4().bytes
    dialects = [0x0202, 0x0210, 0x0300, 0x0302]
    dialect_count = len(dialects)

    # SMB2 header (64 bytes)
    header = b"\xfeSMB"                    # ProtocolId
    header += struct.pack("<H", 64)        # StructureSize
    header += struct.pack("<H", 0)         # CreditCharge
    header += struct.pack("<I", 0)         # Status
    header += struct.pack("<H", 0)         # Command = NEGOTIATE (0)
    header += struct.pack("<H", 31)        # CreditRequest
    header += struct.pack("<I", 0)         # Flags
    header += struct.pack("<I", 0)         # NextCommand
    header += struct.pack("<Q", 0)         # MessageId
    header += struct.pack("<I", 0)         # Reserved
    header += struct.pack("<I", 0)         # TreeId
    header += struct.pack("<Q", 0)         # SessionId
    header += b"\x00" * 16                # Signature

    # SMB2 NEGOTIATE body
    body  = struct.pack("<H", 36)          # StructureSize
    body += struct.pack("<H", dialect_count)
    body += struct.pack("<H", 0)           # SecurityMode (client: signing not required)
    body += struct.pack("<H", 0)           # Reserved
    body += struct.pack("<I", 0x7F)        # Capabilities
    body += client_guid                   # ClientGuid (16 bytes)
    body += struct.pack("<Q", 0)           # ClientStartTime / NegotiateContextOffset area
    body += b"".join(struct.pack("<H", d) for d in dialects)

    msg = header + body
    # NetBIOS session message framing
    nb_header = b"\x00" + struct.pack(">I", len(msg))[1:]
    return nb_header + msg


def _recv_smb2_response(sock: socket.socket, timeout: float) -> bytes:
    """Receive a complete SMB2 response with NetBIOS framing."""
    sock.settimeout(timeout)
    nb = b""
    while len(nb) < 4:
        chunk = sock.recv(4 - len(nb))
        if not chunk:
            raise ConnectionError("Connection closed before NetBIOS header")
        nb += chunk
    if nb[0] != 0x00:
        raise ValueError(f"Unexpected NetBIOS type: {nb[0]:#x}")
    msg_len = int.from_bytes(b"\x00" + nb[1:4], "big")
    data, remaining = b"", msg_len
    while remaining > 0:
        chunk = sock.recv(min(remaining, 8192))
        if not chunk:
            raise ConnectionError("Connection closed mid-response")
        data    += chunk
        remaining -= len(chunk)
    return nb + data


def check_smb_signing(ip: str, port: int = 445,
                       timeout: float = 3.0, retries: int = 2) -> dict:
    """
    Probe SMB2 NEGOTIATE to determine whether signing is:
      - required (SecurityMode bit 1 set) → safe
      - enabled but not required (bit 0 set) → warning
      - disabled → critical
    Returns {success, enabled, required, error}.
    """
    result = {"success": False, "enabled": None, "required": None, "error": None}
    req = _build_smb2_negotiate()

    for attempt in range(retries + 1):
        try:
            with socket.create_connection((ip, port), timeout=timeout) as s:
                s.sendall(req)
                resp = _recv_smb2_response(s, timeout)
                # Payload starts at byte 4 (skip NetBIOS header)
                payload = resp[4:]
                if len(payload) < 68 or payload[:4] != b"\xfeSMB":
                    raise ValueError("Not a valid SMB2 response")
                # Command must be NEGOTIATE response (0x0000)
                cmd = struct.unpack_from("<H", payload, 12)[0]
                if cmd != 0:
                    raise ValueError(f"Unexpected SMB2 command: {cmd:#x}")
                # SecurityMode is in the NEGOTIATE response body at offset 2 (body starts at 64)
                body = payload[64:]
                # body: StructureSize (2) + SecurityMode (2) + ...
                if len(body) < 4:
                    raise ValueError("SMB2 NEGOTIATE body too short")
                sec_mode = struct.unpack_from("<H", body, 2)[0]
                result.update({
                    "success":  True,
                    "enabled":  bool(sec_mode & 0x0001),
                    "required": bool(sec_mode & 0x0002),
                })
                return result
        except (ConnectionRefusedError, TimeoutError, OSError) as e:
            result["error"] = str(e)
            if attempt < retries:
                time.sleep(0.5 * (attempt + 1))
        except Exception as e:
            result["error"] = str(e)[:120]
            if attempt < retries:
                time.sleep(0.3)
    return result


def check_smb_null_session(ip: str, timeout: float = 5.0) -> tuple[bool | None, str]:
    """
    Test SMB Null Session (IPC$ anonymous).
    Windows: uses net use.
    Linux: reports that rpcclient/smbclient is needed (no external tools required for check).
    Returns (vulnerable_or_None, detail_string).
    """
    if sys.platform == "win32":
        share = f"\\\\{ip}\\IPC$"
        # Clean up any existing connection first
        subprocess.run(["net", "use", share, "/delete", "/y"],
                       capture_output=True, timeout=timeout)
        try:
            res = subprocess.run(
                ["net", "use", share, "", "/u:", ""],
                capture_output=True, text=True, timeout=timeout,
                encoding="utf-8", errors="replace"
            )
            vuln = res.returncode == 0
            if vuln:
                subprocess.run(["net", "use", share, "/delete", "/y"],
                               capture_output=True, timeout=3)
            return vuln, (res.stdout + res.stderr).strip()[:300]
        except Exception as e:
            return None, str(e)
    else:
        # On Linux, attempt to connect and check if 445 is responsive
        try:
            with socket.create_connection((ip, 445), timeout=timeout):
                pass
            return None, (
                f"Puerto 445 abierto. Prueba manual:\n"
                f"  rpcclient -U '' -N {ip} -c 'enumdomusers'\n"
                f"  smbclient -L //{ip}/ -N\n"
                f"  enum4linux -a {ip}"
            )
        except Exception as e:
            return None, str(e)


# ══════════════════════════════════════════════════════════════════════════════
# LDAP audit
# ══════════════════════════════════════════════════════════════════════════════

def _func_level(val) -> str:
    """Map AD functional level integer to human-readable Windows Server version."""
    _MAP = {
        "0": "Windows 2000",
        "1": "Windows Server 2003 Interim",
        "2": "Windows Server 2003",
        "3": "Windows Server 2008",
        "4": "Windows Server 2008 R2",
        "5": "Windows Server 2012",
        "6": "Windows Server 2012 R2",
        "7": "Windows Server 2016",
        "8": "Windows Server 2019",
        "9": "Windows Server 2022",
    }
    return _MAP.get(str(val), str(val)) if val is not None else "Desconocido"


def _get_other_attr(other: dict, key: str, default=None):
    """Safely extract first element of a list attribute from Root DSE 'other' dict."""
    val = other.get(key)
    if isinstance(val, list):
        return val[0] if val else default
    return val if val is not None else default


def audit_ldap(ip: str, port: int = 389,
               use_ssl: bool = False, timeout: float = 4.0) -> dict:
    """
    Perform full LDAP security audit using ldap3.
    Tests: Root DSE enumeration, anonymous bind, anonymous search, LDAP signing.
    """
    result: dict = {
        "is_ad":                    False,
        "root_dse":                 {},
        "anonymous_bind":           False,
        "anonymous_search_vuln":    False,
        "ldap_signing_required":    None,  # None = could not determine
        "error":                    None,
    }

    if not _HAS_LDAP3:
        result["error"] = "ldap3 no disponible. Intenta: pip install ldap3"
        return result

    # ── 1. Root DSE via unauthenticated connection ──────────────────────────
    try:
        tls = ldap3.Tls(validate=ssl.CERT_NONE) if use_ssl else None
        server = ldap3.Server(
            ip, port=port, use_ssl=use_ssl, tls=tls,
            get_info=ldap3.ALL, connect_timeout=timeout,
        )
        with ldap3.Connection(server, receive_timeout=timeout) as conn:
            try:
                conn.open()
            except Exception:
                pass  # get_info still works even if bind fails

        info = server.info
        if info is None:
            result["error"] = "No se pudo obtener Root DSE del servidor LDAP"
            return result

        other: dict = getattr(info, "other", {}) or {}
        caps    = other.get("supportedCapabilities", []) or []
        default_nc = _get_other_attr(other, "defaultNamingContext")

        is_ad = (
            "1.2.840.113556.1.4.800" in caps   # LDAP_CAP_ACTIVE_DIRECTORY_OID
            or default_nc is not None
        )
        result["is_ad"] = is_ad

        result["root_dse"] = {
            "naming_contexts":        other.get("namingContexts", []),
            "default_naming_context": default_nc,
            "dns_hostname":           _get_other_attr(other, "dnsHostName"),
            "server_name":            _get_other_attr(other, "serverName"),
            "forest_functionality":   _func_level(_get_other_attr(other, "forestFunctionality")),
            "domain_functionality":   _func_level(_get_other_attr(other, "domainFunctionality")),
            "dc_functionality":       _func_level(_get_other_attr(other, "domainControllerFunctionality")),
            "supported_sasl":         other.get("supportedSASLMechanisms", []),
            "supported_extensions":   other.get("supportedExtension", []),
        }
    except Exception as e:
        result["error"] = str(e)[:200]
        return result

    # ── 2. Anonymous bind + search ──────────────────────────────────────────
    default_nc = result["root_dse"].get("default_naming_context")
    if default_nc:
        try:
            tls = ldap3.Tls(validate=ssl.CERT_NONE) if use_ssl else None
            anon_srv = ldap3.Server(ip, port=port, use_ssl=use_ssl, tls=tls,
                                    connect_timeout=timeout)
            with ldap3.Connection(anon_srv, auto_bind=False,
                                  receive_timeout=timeout) as ac:
                ac.open()
                bound = ac.bind()
                result["anonymous_bind"] = bool(bound)
                if bound:
                    try:
                        ok = ac.search(
                            search_base=default_nc,
                            search_filter="(objectClass=user)",
                            search_scope=ldap3.SUBTREE,
                            attributes=["sAMAccountName", "distinguishedName"],
                            size_limit=5,
                        )
                        result["anonymous_search_vuln"] = bool(ok and len(ac.entries) > 0)
                    except Exception:
                        pass
        except Exception:
            pass

    # ── 3. LDAP Signing check (plain LDAP only) ─────────────────────────────
    if not use_ssl:
        # Strategy: send a SIMPLE bind with a fabricated DN & wrong password.
        # If signing is NOT required: server returns result 49 (invalidCredentials)
        # If signing IS required:    server returns result 8 (strongAuthRequired)
        try:
            tls2  = None
            srv2  = ldap3.Server(ip, port=port, use_ssl=False,
                                 connect_timeout=timeout)
            probe_dn  = f"CN=_probe_{uuid.uuid4().hex[:6]},DC=probe,DC=invalid"
            probe_pwd = uuid.uuid4().hex
            with ldap3.Connection(
                srv2,
                user=probe_dn,
                password=probe_pwd,
                authentication=ldap3.SIMPLE,
                receive_timeout=timeout,
                auto_bind=False,
            ) as sc:
                sc.open()
                sc.bind()
                code = sc.result.get("result", -1)
                desc = sc.result.get("description", "").lower()

                if code == 8 or "strongauthreq" in desc or "strong auth" in desc:
                    result["ldap_signing_required"] = True
                elif code == 49:
                    # Server processed the request (signing not required)
                    result["ldap_signing_required"] = False
                elif code == 0:
                    # Unexpected success — treat as not required
                    result["ldap_signing_required"] = False
                else:
                    result["ldap_signing_required"] = None
        except Exception as e:
            err_s = str(e).lower()
            if "strong" in err_s or "signing" in err_s:
                result["ldap_signing_required"] = True
            # else leave as None (undetermined)
    else:
        # LDAPS always encrypts → signing implicit
        result["ldap_signing_required"] = True

    return result


# ══════════════════════════════════════════════════════════════════════════════
# LDAPS certificate check
# ══════════════════════════════════════════════════════════════════════════════

def check_ldaps_cert(ip: str, port: int = 636, timeout: float = 5.0) -> dict:
    """
    Verify LDAPS TLS certificate.
    Returns {available, cert_valid, cert_info, error}.
    """
    result = {
        "available":  False,
        "cert_valid": None,
        "cert_info":  {},
        "error":      None,
    }
    ctx_strict = ssl.create_default_context()
    ctx_strict.check_hostname = False  # we verify manually

    try:
        with socket.create_connection((ip, port), timeout=timeout) as raw_sock:
            try:
                with ctx_strict.wrap_socket(raw_sock, server_hostname=ip) as ssl_sock:
                    cert = ssl_sock.getpeercert()
                    result["available"]  = True
                    result["cert_valid"] = True
                    result["cert_info"]  = {
                        "subject":   dict(x[0] for x in cert.get("subject",  [])),
                        "issuer":    dict(x[0] for x in cert.get("issuer",   [])),
                        "not_after": cert.get("notAfter", "N/A"),
                        "san":       cert.get("subjectAltName", []),
                    }
            except ssl.SSLCertVerificationError:
                # Port is open but cert is invalid (self-signed or expired)
                result["available"]  = True
                result["cert_valid"] = False
                # Try again without verification to get cert details
                ctx_nv = ssl.create_default_context()
                ctx_nv.check_hostname  = False
                ctx_nv.verify_mode     = ssl.CERT_NONE
                try:
                    with socket.create_connection((ip, port), timeout=timeout) as rs2:
                        with ctx_nv.wrap_socket(rs2) as ss2:
                            cert = ss2.getpeercert(binary_form=False)
                            result["cert_info"] = {
                                "subject":   dict(x[0] for x in (cert or {}).get("subject",  [])),
                                "issuer":    dict(x[0] for x in (cert or {}).get("issuer",   [])),
                                "not_after": (cert or {}).get("notAfter", "N/A"),
                            }
                except Exception:
                    pass
                result["error"] = "Certificado no válido (self-signed, expirado o CN incorrecto)"
    except (ConnectionRefusedError, TimeoutError, OSError) as e:
        result["error"] = f"Puerto LDAPS no accesible: {e}"
    except Exception as e:
        result["error"] = str(e)[:120]
    return result


# ══════════════════════════════════════════════════════════════════════════════
# Kerberos port check
# ══════════════════════════════════════════════════════════════════════════════

def check_kerberos_port(ip: str, timeout: float = 3.0) -> dict:
    """Check if Kerberos TCP/88 is open and accepting connections."""
    result = {"open": False, "error": None}
    try:
        with socket.create_connection((ip, 88), timeout=timeout):
            result["open"] = True
    except (ConnectionRefusedError, TimeoutError, OSError) as e:
        result["error"] = str(e)
    return result


# ══════════════════════════════════════════════════════════════════════════════
# Main run function
# ══════════════════════════════════════════════════════════════════════════════

def run(target: str = "", timeout: str = "2.0",
        threads: str = "30", **kwargs) -> dict:
    """
    Entry point for the ad_audit skill.

    Args:
        target  : IP, CIDR, hostname or domain to audit
        timeout : Per-port timeout in seconds (default: 2.0)
        threads : Worker threads for parallel port scan (default: 30)
    Returns:
        {"success": bool, "output": str, "findings": list}
    """
    if not target:
        return {
            "success": False,
            "output":  "ERROR: Debes especificar un target. Ej: SKILL:ad_audit target=10.10.0.1",
            "findings": [],
        }

    try:
        timeout_f = float(timeout)
    except ValueError:
        timeout_f = 2.0
    try:
        threads_i = int(threads)
    except ValueError:
        threads_i = 30

    findings:  list[dict] = []
    out:       list[str]  = []
    ts         = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    out += [
        "═" * 68,
        "  ██████╗ ██████╗   ACTIVE DIRECTORY AUDIT — HackerAgent v2.1",
        f"  Target  : {target}",
        f"  Timeout : {timeout_f}s per port   Threads: {threads_i}",
        f"  Date    : {ts}",
        "═" * 68, "",
    ]

    # ── Resolve targets ────────────────────────────────────────────────────────
    ips_to_scan: list[str] = []

    if _is_domain_name(target):
        out.append(f"[*] Dominio detectado: {target}")
        out.append("[*] Resolviendo DCs via DNS SRV (_ldap._tcp.dc._msdcs)...")
        dcs = _resolve_dc_srv(target, timeout=timeout_f * 2)
        if dcs:
            out.append(f"[+] {len(dcs)} Domain Controller(s) descubiertos:")
            for dc in dcs:
                ip_s = dc.get("ip") or "(no resuelto)"
                out.append(f"    ✓ {dc['hostname']}  →  {ip_s}  [{dc['source']}]")
                if dc.get("ip") and dc["ip"] not in ips_to_scan:
                    ips_to_scan.append(dc["ip"])
        else:
            out.append("[!] Sin SRV records. Tratando como hostname directo...")
            ips_to_scan = _parse_targets(target)
    else:
        ips_to_scan = _parse_targets(target)

    if not ips_to_scan:
        msg = "[!] ERROR: No se pudieron resolver IPs válidas para escanear."
        out.append(msg)
        return {"success": False, "output": "\n".join(out), "findings": []}

    preview = ", ".join(ips_to_scan[:8])
    if len(ips_to_scan) > 8:
        preview += f" … y {len(ips_to_scan) - 8} más"
    out.append(f"\n[*] {len(ips_to_scan)} host(s) a escanear: {preview}\n")

    # ── Scan each host ─────────────────────────────────────────────────────────
    for ip in ips_to_scan:
        out += ["─" * 60, f"  HOST: {ip}", "─" * 60]

        # 1. Port scan (parallel)
        out.append(f"[*] Escaneando {len(AD_PORTS)} puertos AD en paralelo (timeout={timeout_f}s)...")
        open_ports = _scan_ports_parallel(ip, timeout=timeout_f, max_workers=threads_i)

        if not open_ports:
            out.append("[-] Sin puertos AD abiertos — host no es DC o está filtrado.")
            out.append("")
            continue

        out.append(f"[+] Puertos abiertos ({len(open_ports)}):")
        for p, svc in open_ports.items():
            out.append(f"    {p:<6} {svc}")

        # Is it likely a DC?
        indicator_count = len(_DC_INDICATORS & set(open_ports.keys()))
        if indicator_count >= 2:
            out.append(f"\n[+] ✅ DOMAIN CONTROLLER identificado ({indicator_count} indicadores clave)")
            findings.append({
                "type":     "dc_identified",
                "value":    ip,
                "severity": "info",
                "detail":   f"{indicator_count} AD indicator ports open: {sorted(_DC_INDICATORS & set(open_ports.keys()))}",
            })
        else:
            out.append(f"\n[*] No parece ser un DC ({indicator_count} indicadores — se continúa auditoría)")

        # ── LDAP / LDAPS ────────────────────────────────────────────────────────
        ldap_open  = 389  in open_ports
        ldaps_open = 636  in open_ports
        gc_open    = 3268 in open_ports
        smb_open   = 445  in open_ports
        krb_open   = 88   in open_ports

        if ldap_open or ldaps_open:
            audit_port = 389 if ldap_open else 636
            use_ssl    = not ldap_open
            proto_str  = "LDAP" if ldap_open else "LDAPS"
            out.append(f"\n[*] Auditoría {proto_str} (puerto {audit_port})...")

            lr = audit_ldap(ip, port=audit_port, use_ssl=use_ssl, timeout=timeout_f)

            if lr.get("error") and not lr.get("root_dse"):
                out.append(f"[-] Error LDAP: {lr['error']}")
            else:
                dse = lr.get("root_dse", {})
                if lr.get("is_ad"):
                    out.append(f"[+] ✅ Active Directory confirmado")
                    out.append(f"    DNS Hostname  : {dse.get('dns_hostname',  'N/A')}")
                    out.append(f"    Default NC    : {dse.get('default_naming_context', 'N/A')}")
                    out.append(f"    Forest Level  : {dse.get('forest_functionality', 'N/A')}")
                    out.append(f"    Domain Level  : {dse.get('domain_functionality', 'N/A')}")
                    out.append(f"    DC Level      : {dse.get('dc_functionality', 'N/A')}")
                    findings.append({
                        "type":     "ad_confirmed",
                        "value":    f"{ip} ({dse.get('dns_hostname', ip)})",
                        "severity": "info",
                        "detail":   (
                            f"Domain: {dse.get('default_naming_context', 'N/A')} | "
                            f"Level: {dse.get('domain_functionality', 'N/A')}"
                        ),
                    })
                else:
                    out.append("[*] LDAP disponible pero no parece AD estándar")

                # Anonymous search
                if lr.get("anonymous_search_vuln"):
                    out.append(f"\n[!] 🔴 ALTO: Anonymous LDAP Search PERMITIDA")
                    out.append(f"    Puedes enumerar usuarios/grupos sin credenciales:")
                    out.append(f"    ldapsearch -x -H ldap://{ip} -b '{dse.get('default_naming_context','')}' '(objectClass=user)'")
                    findings.append({
                        "type":     "ldap_anonymous_search",
                        "value":    f"{ip}:{audit_port}",
                        "severity": "high",
                        "detail":   "Anonymous bind + búsqueda de usuarios sin credenciales posible",
                    })
                elif lr.get("anonymous_bind"):
                    out.append(f"\n[!] 🟡 MEDIO: Anonymous Bind permitido (búsqueda restringida)")
                    findings.append({
                        "type":     "ldap_anonymous_bind",
                        "value":    f"{ip}:{audit_port}",
                        "severity": "low",
                        "detail":   "Anonymous bind aceptado pero la búsqueda de directorio está restringida",
                    })
                else:
                    out.append(f"[+] Anonymous Bind: DENEGADO ✓")

                # LDAP Signing
                signing = lr.get("ldap_signing_required")
                if signing is True:
                    out.append(f"[+] LDAP Signing: REQUERIDO ✓")
                elif signing is False:
                    out.append(f"\n[!] 🟠 MEDIO: LDAP Signing NO requerido")
                    out.append(f"    Autenticación SIMPLE sin cifrado permitida → NTLM Relay posible")
                    out.append(f"    Herramientas: Responder + ntlmrelayx | SKILL:metasploit")
                    findings.append({
                        "type":     "ldap_signing_not_required",
                        "value":    f"{ip}:{audit_port}",
                        "severity": "medium",
                        "detail":   "LDAP SIMPLE bind sin firma ni cifrado permitido — vulnerable a MITM/Relay",
                    })
                else:
                    out.append(f"[*] LDAP Signing: No determinado (respuesta ambigua)")

                if lr.get("error"):
                    out.append(f"    (Aviso: {lr['error']})")

        # ── LDAPS cert ─────────────────────────────────────────────────────────
        if ldaps_open:
            out.append(f"\n[*] Verificando certificado LDAPS (puerto 636)...")
            cr = check_ldaps_cert(ip, port=636, timeout=timeout_f * 2)
            if cr["available"]:
                if cr["cert_valid"]:
                    ci = cr.get("cert_info", {})
                    exp = ci.get("not_after", "N/A")
                    subj = ci.get("subject", {}).get("commonName", "N/A")
                    out.append(f"[+] LDAPS disponible — Certificado VÁLIDO")
                    out.append(f"    Subject: {subj}  |  Expira: {exp}")
                else:
                    out.append(f"[!] 🔵 BAJO: LDAPS disponible pero certificado inválido")
                    out.append(f"    {cr.get('error', '')}")
                    findings.append({
                        "type":     "ldaps_invalid_cert",
                        "value":    f"{ip}:636",
                        "severity": "low",
                        "detail":   cr.get("error", "Self-signed o expirado"),
                    })
            else:
                out.append(f"[-] LDAPS: {cr.get('error', 'no accesible')}")

        # ── Global Catalog ──────────────────────────────────────────────────────
        if gc_open:
            out.append(f"\n[+] 🌐 Global Catalog (puerto 3268) abierto")
            out.append(f"    Este DC tiene acceso a todos los objetos del bosque AD")
            findings.append({
                "type":     "ldap_global_catalog",
                "value":    f"{ip}:3268",
                "severity": "info",
                "detail":   "Global Catalog disponible — enumeración de bosque AD completo posible",
            })

        # ── Kerberos ────────────────────────────────────────────────────────────
        if krb_open:
            kc = check_kerberos_port(ip, timeout=timeout_f)
            if kc["open"]:
                out.append(f"\n[*] 🎟 Kerberos (puerto 88) activo")
                out.append(f"    Vectores: AS-REP Roasting, Kerberoasting, Pass-the-Ticket")
                out.append(f"    Tools: impacket GetNPUsers.py | GetUserSPNs.py | Rubeus")
                findings.append({
                    "type":     "kerberos_active",
                    "value":    f"{ip}:88",
                    "severity": "info",
                    "detail":   "Kerberos activo. Verifica cuentas sin PREAUTH (AS-REP Roasting) y SPNs (Kerberoasting)",
                })

        # ── SMB Signing ─────────────────────────────────────────────────────────
        if smb_open:
            out.append(f"\n[*] Auditoría SMB (puerto 445)...")
            sr = check_smb_signing(ip, timeout=timeout_f)
            if sr["success"]:
                if sr["required"]:
                    out.append(f"[+] SMB Signing: REQUERIDO ✓")
                elif sr["enabled"]:
                    out.append(f"[!] 🟠 MEDIO: SMB Signing habilitado pero NO requerido")
                    out.append(f"    Vulnerable a SMB/NTLM Relay si el cliente no lo exige")
                    findings.append({
                        "type":     "smb_signing_not_required",
                        "value":    f"{ip}:445",
                        "severity": "medium",
                        "detail":   "SMB Signing no obligatorio — SMB Relay posible si ambos extremos no lo exigen",
                    })
                else:
                    out.append(f"[!] 🔴 ALTO: SMB Signing DESHABILITADO")
                    out.append(f"    Herramientas: Responder.py + ntlmrelayx.py")
                    out.append(f"    SKILL:metasploit (smb_relay / psexec_ntdsgrab)")
                    findings.append({
                        "type":     "smb_signing_disabled",
                        "value":    f"{ip}:445",
                        "severity": "high",
                        "detail":   "SMB Signing completamente deshabilitado — SMB Relay / NTLM Relay trivial",
                    })
            else:
                out.append(f"[-] SMB Signing: No determinado ({sr.get('error', 'timeout')})")

            # Null Session
            out.append(f"[*] Probando Null Session (IPC$)...")
            ns_vuln, ns_detail = check_smb_null_session(ip, timeout=timeout_f * 2)
            if ns_vuln is True:
                out.append(f"[!] 🔴 ALTO: Null Session IPC$ PERMITIDA")
                out.append(f"    Enumeración anónima: enum4linux -a {ip}")
                findings.append({
                    "type":     "smb_null_session",
                    "value":    f"{ip}:445 (IPC$)",
                    "severity": "high",
                    "detail":   "Null Session a IPC$ permitida — enumeración LSA/SAM posible sin credenciales",
                })
            elif ns_vuln is False:
                out.append(f"[+] Null Session: DENEGADA ✓")
            else:
                out.append(f"[*] Null Session: {ns_detail}")

        out.append("")

    # ── Summary ────────────────────────────────────────────────────────────────
    out += ["═" * 68, "  RESUMEN DE HALLAZGOS", "═" * 68]

    findings_sorted = sorted(findings, key=lambda f: _SEV_RANK.get(f.get("severity", "info"), 4))
    sev_counts: dict = {}
    for f in findings_sorted:
        s = f.get("severity", "info")
        sev_counts[s] = sev_counts.get(s, 0) + 1

    icons = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
    if not any(v for s, v in sev_counts.items() if s not in ("info",)):
        out.append("[+] Sin vulnerabilidades activas en los hosts escaneados.")
    else:
        for sev in ["critical", "high", "medium", "low", "info"]:
            cnt = sev_counts.get(sev, 0)
            if cnt:
                out.append(f"  {icons[sev]} {sev.upper():<10}: {cnt} hallazgo(s)")

    out.append("\n[Siguientes Pasos Recomendados]")
    ftypes = {f["type"] for f in findings_sorted}

    if "smb_signing_disabled" in ftypes or "smb_signing_not_required" in ftypes:
        out.append("  → SMB/NTLM Relay: python Responder.py -I eth0 & python ntlmrelayx.py -t smb://<DC>")
    if "ldap_anonymous_search" in ftypes:
        out.append("  → Enumera AD anónimamente: ldapsearch -x -H ldap://<dc> -b '<base_dn>'")
    if "smb_null_session" in ftypes:
        out.append("  → Null Session enum: enum4linux -a <ip> | rpcclient -U '' -N <ip>")
    if "kerberos_active" in ftypes:
        out.append("  → AS-REP Roasting: impacket-GetNPUsers domain/ -no-pass -usersfile users.txt")
        out.append("  → Kerberoasting:   impacket-GetUserSPNs domain/user:pass -request")
    if "ldap_signing_not_required" in ftypes:
        out.append("  → LDAP Relay:      python ntlmrelayx.py -t ldap://<dc> --escalate-user <user>")

    out += [
        "",
        f"  Total hallazgos: {len(findings_sorted)} | "
        f"Critical: {sev_counts.get('critical',0)} | "
        f"High: {sev_counts.get('high',0)} | "
        f"Medium: {sev_counts.get('medium',0)} | "
        f"Low: {sev_counts.get('low',0)}",
        "═" * 68,
    ]

    return {
        "success":  True,
        "output":   "\n".join(out),
        "findings": findings_sorted,
    }
