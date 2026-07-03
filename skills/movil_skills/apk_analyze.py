"""
Skill: apk_analyze
Ingeniería inversa ESTÁTICA de un APK Android. Decompila (jadx / apktool),
parsea el AndroidManifest (permisos, componentes exportados, debuggable,
cleartext, SSL pinning config), extrae credenciales/API keys/URLs/secretos del
código y recursos, y localiza la lógica de la app (login, cripto, root detection).

Requiere alguno de: jadx, apktool (fallback: unzip + strings + aapt).
"""
import os
import re
import shutil
import subprocess
from pathlib import Path
from datetime import datetime

META = {
    "name": "apk_analyze",
    "category": "movil",
    "description": (
        "RE estático de APK: decompila (jadx/apktool), parsea el manifest (permisos, "
        "componentes exportados, debuggable, cleartext, SSL pinning), extrae credenciales/"
        "API keys/URLs/secretos y localiza la lógica (login, cripto, root detection)."
    ),
    "args": ["target", "output_dir", "decompiler"],
    "example": "SKILL:apk_analyze target=/ruta/app.apk",
}

# ── Patrones de secretos ──────────────────────────────────────────────────────
_SECRET_PATTERNS = [
    (r'AIza[0-9A-Za-z_\-]{35}',                              "Google/Firebase API Key", "critical"),
    (r'AKIA[0-9A-Z]{16}',                                    "AWS Access Key ID",        "critical"),
    (r'6L[0-9A-Za-z_\-]{38}',                                "reCAPTCHA key",            "low"),
    (r'ya29\.[0-9A-Za-z_\-]+',                               "Google OAuth token",       "critical"),
    (r'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}', "JWT",          "high"),
    (r'(?:sk|pk)_(?:live|test)_[0-9A-Za-z]{16,}',            "Stripe key",               "critical"),
    (r'xox[baprs]-[0-9A-Za-z\-]{10,}',                       "Slack token",              "high"),
    (r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----',       "Private Key PEM",          "critical"),
    (r'(?:firebaseio\.com|firebase[a-z]*\.googleapis\.com)[^\s"\'<>]*', "Firebase URL",  "high"),
    (r'(?:https?://[a-z0-9\-.]+/[^\s"\'<>]{0,80})',          "URL/endpoint",             "info"),
    (r'(?i)(?:password|passwd|pwd|clave)\s*[=:]\s*["\']([^"\']{4,60})["\']', "Password hardcodeada", "critical"),
    (r'(?i)(?:api[_-]?key|apikey|secret|token|auth)\s*[=:]\s*["\']([^"\']{8,80})["\']', "Secreto/token", "high"),
    (r'(?i)(?:mongodb|mysql|postgres(?:ql)?|redis)://[^\s"\'<>]+', "URI de base de datos", "critical"),
]
_SECRET_SKIP = {"true", "false", "null", "example", "changeme", "your_api_key", "xxxx"}

_DANGEROUS_PERMS = {
    "READ_SMS", "SEND_SMS", "RECEIVE_SMS", "READ_CONTACTS", "RECORD_AUDIO",
    "CAMERA", "ACCESS_FINE_LOCATION", "READ_CALL_LOG", "READ_PHONE_STATE",
    "WRITE_EXTERNAL_STORAGE", "READ_EXTERNAL_STORAGE", "SYSTEM_ALERT_WINDOW",
    "REQUEST_INSTALL_PACKAGES", "BIND_ACCESSIBILITY_SERVICE", "QUERY_ALL_PACKAGES",
    "PACKAGE_USAGE_STATS", "MANAGE_EXTERNAL_STORAGE", "READ_PHONE_NUMBERS",
}

# Pistas de lógica sensible en el código
_LOGIC_HINTS = [
    (r'CertificatePinner|setCertificatePinner|pinning|X509TrustManager|checkServerTrusted', "SSL pinning", "info"),
    (r'network_security_config|networkSecurityConfig',                "Network Security Config", "info"),
    (r'(?i)\b(login|signin|authenticate|doLogin|checkCredentials)\b', "Función de login", "medium"),
    (r'(?i)(AES|DES|RSA|Cipher\.getInstance|SecretKeySpec|encrypt|decrypt)', "Criptografía", "medium"),
    (r'(?i)(RootBeer|/system/bin/su|isRooted|test-keys|Superuser\.apk)', "Detección de root", "info"),
    (r'(?i)(getSharedPreferences|SharedPreferences\.Editor)',         "SharedPreferences (posibles secretos)", "low"),
    (r'(?i)(WebView|addJavascriptInterface|setJavaScriptEnabled)',    "WebView / JS bridge", "medium"),
    (r'(?i)(sqlite|\.db\b|SQLiteDatabase)',                           "Base de datos local", "low"),
]

_TEXT_EXT = {".java", ".xml", ".smali", ".json", ".kt", ".txt", ".js", ".properties", ".yml", ".yaml"}


def _run(cmd: str, tout: int = 600) -> tuple:
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=tout)
        return ((r.stdout or "") + (r.stderr or "")).strip(), r.returncode
    except subprocess.TimeoutExpired:
        return f"Timeout ({tout}s)", 1
    except Exception as e:
        return str(e), 1


def _decompile(apk: str, outdir: Path, decompiler: str) -> tuple:
    """Decompila el APK. Retorna (dir_resultado, herramienta_usada, log)."""
    log = []
    jadx = shutil.which("jadx")
    apktool = shutil.which("apktool")
    want = decompiler.lower()

    if jadx and want in ("auto", "jadx"):
        dst = outdir / "jadx"
        out, code = _run(f'jadx -d "{dst}" "{apk}"', 900)
        log.append(f"jadx → exit {code}")
        if dst.exists() and any(dst.rglob("*")):
            return dst, "jadx", log
    if apktool and want in ("auto", "apktool", "jadx"):
        dst = outdir / "apktool"
        out, code = _run(f'apktool d -f -o "{dst}" "{apk}"', 900)
        log.append(f"apktool → exit {code}")
        if dst.exists():
            return dst, "apktool", log
    # Fallback: unzip + strings
    dst = outdir / "unzip"
    dst.mkdir(parents=True, exist_ok=True)
    _run(f'cd "{dst}" && unzip -o "{apk}" >/dev/null 2>&1', 300)
    if shutil.which("aapt"):
        badging, _ = _run(f'aapt dump badging "{apk}"', 60)
        (dst / "_aapt_badging.txt").write_text(badging, encoding="utf-8", errors="replace")
    log.append("fallback unzip + aapt (instala jadx/apktool para RE completa)")
    return dst, "unzip", log


def _parse_manifest(text: str) -> dict:
    info = {}
    m = re.search(r'package="([^"]+)"', text)
    info["package"] = m.group(1) if m else "?"
    m = re.search(r'(?:android:)?versionName="([^"]+)"', text)
    info["version"] = m.group(1) if m else "?"
    for key, pat in [("minSdk", r'minSdkVersion="?(\d+)'), ("targetSdk", r'targetSdkVersion="?(\d+)')]:
        mm = re.search(pat, text)
        info[key] = mm.group(1) if mm else "?"
    info["debuggable"] = 'android:debuggable="true"' in text
    info["allowBackup"] = 'android:allowBackup="true"' in text
    info["cleartext"] = 'usesCleartextTraffic="true"' in text or 'cleartextTrafficPermitted="true"' in text
    info["perms"] = sorted(set(re.findall(r'uses-permission[^>]*android:name="android\.permission\.([A-Z_]+)"', text)))
    # componentes exportados
    exported = []
    for comp in re.finditer(r'<(activity|service|receiver|provider)\b([^>]*)>', text):
        block = comp.group(0) + text[comp.end():comp.end()+400]
        attrs = comp.group(2)
        name_m = re.search(r'android:name="([^"]+)"', attrs)
        name = name_m.group(1) if name_m else "?"
        is_exp = 'android:exported="true"' in attrs
        has_filter = "<intent-filter" in block and 'android:exported="false"' not in attrs
        if is_exp or has_filter:
            exported.append(f"{comp.group(1)}:{name}")
    info["exported"] = exported[:40]
    return info


def _extract_secrets(text: str, source: str) -> list:
    out = []
    for pat, label, sev in _SECRET_PATTERNS:
        for m in re.finditer(pat, text):
            val = (m.group(1) if m.lastindex else m.group(0)).strip()
            if len(val) < 4 or val.lower() in _SECRET_SKIP:
                continue
            out.append({"type": "apk_secret", "label": label, "value": val[:160],
                        "severity": sev, "source": source})
    return out


def run(target: str = "", output_dir: str = "", decompiler: str = "auto", **kwargs) -> dict:
    target = (target or kwargs.get("apk") or "").strip()
    if not target:
        return {"success": False, "findings": [], "output": "Falta 'target' (ruta al .apk)."}
    apk = Path(target)
    if not apk.exists():
        return {"success": False, "findings": [], "output": f"No existe: {target}"}

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    if not output_dir:
        output_dir = f"/tmp/apk_{apk.stem}_{ts}"
    outdir = Path(output_dir)
    outdir.mkdir(parents=True, exist_ok=True)

    lines = [
        "╔═══ APK_ANALYZE — RE estático de Android ══════════════╗",
        f"  APK    : {target}  ({round(apk.stat().st_size/1024/1024,1)} MB)",
        f"  Salida : {output_dir}",
        "╚═══════════════════════════════════════════════════════╝",
        "",
        "▶ [1/4] Decompilando…",
    ]
    src_dir, tool, dlog = _decompile(target, outdir, decompiler)
    for l in dlog:
        lines.append(f"    {l}")
    lines.append(f"    herramienta: {tool}   →  {src_dir}")

    findings, secrets, logic = [], [], []

    # ── Manifest ──────────────────────────────────────────────────────────────
    lines.append("\n▶ [2/4] AndroidManifest…")
    manifest_txt = ""
    for mf in src_dir.rglob("AndroidManifest.xml"):
        try:
            t = mf.read_text(encoding="utf-8", errors="replace")
            if "<manifest" in t or "uses-permission" in t:
                manifest_txt = t
                break
        except Exception:
            pass
    if manifest_txt:
        mi = _parse_manifest(manifest_txt)
        lines.append(f"    Paquete: {mi['package']}  v{mi['version']}  "
                     f"(minSdk {mi['minSdk']} / targetSdk {mi['targetSdk']})")
        flags = []
        if mi["debuggable"]: flags.append("debuggable"); findings.append(
            {"type": "apk_misconfig", "value": "android:debuggable=true", "severity": "high",
             "description": "APK debuggable → permite depurar/inyectar en runtime"})
        if mi["allowBackup"]: flags.append("allowBackup"); findings.append(
            {"type": "apk_misconfig", "value": "allowBackup=true", "severity": "medium",
             "description": "allowBackup=true → adb backup puede extraer datos de la app"})
        if mi["cleartext"]: flags.append("cleartextTraffic"); findings.append(
            {"type": "apk_misconfig", "value": "usesCleartextTraffic=true", "severity": "medium",
             "description": "Permite tráfico HTTP en claro"})
        lines.append(f"    Flags: {', '.join(flags) or 'ninguna insegura'}")
        dperms = [p for p in mi["perms"] if p in _DANGEROUS_PERMS]
        lines.append(f"    Permisos: {len(mi['perms'])} ({len(dperms)} peligrosos)")
        for p in dperms:
            findings.append({"type": "apk_permission", "value": p, "severity": "medium",
                             "description": f"Permiso peligroso: {p}"})
        if mi["exported"]:
            lines.append(f"    Componentes expuestos ({len(mi['exported'])}):")
            for c in mi["exported"][:12]:
                lines.append(f"      · {c}")
                findings.append({"type": "apk_exported", "value": c, "severity": "high",
                                 "description": f"Componente exportado (atacable vía intents): {c}"})
        (outdir / "AndroidManifest.xml").write_text(manifest_txt, encoding="utf-8", errors="replace")
    else:
        lines.append("    ⚠ No pude leer el manifest (instala jadx/apktool para decodificarlo).")

    # ── Secretos + lógica ─────────────────────────────────────────────────────
    lines.append("\n▶ [3/4] Buscando credenciales/secretos y lógica…")
    scanned = 0
    for f in src_dir.rglob("*"):
        if not f.is_file() or f.suffix.lower() not in _TEXT_EXT:
            continue
        if scanned > 8000:
            break
        try:
            if f.stat().st_size > 2_000_000:
                continue
            content = f.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        scanned += 1
        rel = str(f.relative_to(src_dir))
        secrets.extend(_extract_secrets(content, rel))
        for pat, label, sev in _LOGIC_HINTS:
            if re.search(pat, content):
                logic.append({"label": label, "file": rel, "severity": sev})

    # dedup secretos
    seen, dedup = set(), []
    for s in secrets:
        k = (s["label"], s["value"][:60])
        if k not in seen:
            seen.add(k); dedup.append(s)
    secrets = dedup
    # priorizar no-info y limitar
    secrets.sort(key=lambda s: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(s["severity"], 5))

    crit = [s for s in secrets if s["severity"] in ("critical", "high")]
    lines.append(f"    Archivos escaneados: {scanned}")
    lines.append(f"    Secretos: {len(secrets)}  (críticos/altos: {len(crit)})")
    for s in secrets[:25]:
        lines.append(f"      [{s['severity'].upper():>8}] {s['label']}: {s['value'][:70]}   ({s['source']})")
        findings.append({"type": "apk_secret", "value": f"{s['label']}: {s['value'][:80]}",
                         "severity": s["severity"], "description": f"{s['label']} en {s['source']}"})

    # dedup lógica por label
    seenl, logic_dedup = set(), []
    for l in logic:
        if l["label"] not in seenl:
            seenl.add(l["label"]); logic_dedup.append(l)
    if logic_dedup:
        lines.append(f"\n    Lógica detectada:")
        for l in logic_dedup:
            lines.append(f"      · {l['label']}   (ej: {l['file']})")
            findings.append({"type": "apk_logic", "value": l["label"], "severity": l["severity"],
                             "description": f"{l['label']} detectado (ej: {l['file']})"})

    ssl_present = any(l["label"] == "SSL pinning" for l in logic_dedup)

    # ── Resumen ───────────────────────────────────────────────────────────────
    lines.append("\n▶ [4/4] Resumen")
    lines.append(f"{'═'*60}")
    lines.append(f"  Decompilado : {src_dir}")
    lines.append(f"  Secretos    : {len(secrets)}   Hallazgos totales: {len(findings)}")
    if ssl_present:
        lines.append(f"  🔒 SSL PINNING detectado → para runtime usa: SKILL:apk_dynamic action=ssl-unpin target=<paquete>")
    lines.append(f"  ▶ Análisis dinámico: SKILL:apk_dynamic action=hook target=<paquete>")
    lines.append(f"{'═'*60}")

    return {
        "success": True,
        "output": "\n".join(lines),
        "findings": findings,
        "decompiled_dir": str(src_dir),
        "tool": tool,
        "secrets_count": len(secrets),
        "ssl_pinning": ssl_present,
        "output_dir": str(outdir),
    }
