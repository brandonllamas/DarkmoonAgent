"""
Skill: apk_dynamic
Análisis DINÁMICO de apps Android con Frida/objection: bypass de SSL pinning
(SSL unpinning universal), hooks de credenciales/criptografía en runtime, y
comandos listos para interceptar el tráfico. Genera los scripts .js y, si hay
un dispositivo/emulador con frida-server, intenta ejecutarlos.

Requiere (en Kali/host): frida-tools (`pip install frida-tools`), opcional objection
y adb. En el dispositivo/emulador: frida-server corriendo (root) o app instrumentada.
"""
import re
import shutil
import subprocess
from pathlib import Path
from datetime import datetime

META = {
    "name": "apk_dynamic",
    "category": "movil",
    "description": (
        "Análisis dinámico Android con Frida: bypass de SSL pinning (unpinning universal), "
        "hooks de login/credenciales/cripto en runtime y comandos para interceptar tráfico. "
        "Genera scripts .js y los ejecuta si hay dispositivo con frida-server."
    ),
    "args": ["target", "action", "device", "run", "output_dir"],
    "example": "SKILL:apk_dynamic action=ssl-unpin target=com.ejemplo.app run=true",
}

# ── Frida: SSL unpinning universal (OkHttp/TrustManager/WebView/Conscrypt) ─────
_SSL_UNPIN_JS = r"""// SSL Unpinning universal — Frida. Uso: frida -U -f <pkg> -l ssl_unpin.js --no-pause
Java.perform(function () {
    console.log("[+] SSL unpinning activo");

    // 1) TrustManager que acepta todo
    try {
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        var TM = Java.registerClass({
            name: 'com.bypass.TM',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function () {},
                checkServerTrusted: function () {},
                getAcceptedIssuers: function () { return []; }
            }
        });
        var initInject = SSLContext.init.overload(
            '[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom');
        initInject.implementation = function (km, tm, sr) {
            initInject.call(this, km, [TM.$new()], sr);
        };
        console.log("[+] TrustManager global inyectado");
    } catch (e) { console.log("[-] TrustManager: " + e); }

    // 2) OkHttp CertificatePinner
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function () {
            console.log("[+] OkHttp CertificatePinner.check() bypass");
            return;
        };
    } catch (e) {}

    // 3) TrustManagerImpl (Android N+)
    try {
        var TMImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TMImpl.verifyChain.implementation = function (certs, host) {
            console.log("[+] Conscrypt verifyChain bypass: " + host);
            return certs;
        };
    } catch (e) {}

    // 4) WebViewClient onReceivedSslError
    try {
        var WVClient = Java.use('android.webkit.WebViewClient');
        WVClient.onReceivedSslError.implementation = function (view, handler, error) {
            handler.proceed();
        };
    } catch (e) {}
});
"""

# ── Frida: hooks de credenciales / criptografía ───────────────────────────────
_HOOKS_JS = r"""// Hooks de credenciales y cripto — Frida.
Java.perform(function () {
    console.log("[+] Hooks de credenciales/cripto activos");

    // Cipher (AES/DES/RSA) — muestra clave y datos
    try {
        var Cipher = Java.use('javax.crypto.Cipher');
        Cipher.doFinal.overload('[B').implementation = function (data) {
            var out = this.doFinal(data);
            console.log("[CIPHER] " + this.getAlgorithm() + " in=" + bytes2str(data));
            return out;
        };
    } catch (e) {}

    // MessageDigest (MD5/SHA) — hashing de contraseñas
    try {
        var MD = Java.use('java.security.MessageDigest');
        MD.digest.overload('[B').implementation = function (data) {
            console.log("[HASH] " + this.getAlgorithm() + " <- " + bytes2str(data));
            return this.digest(data);
        };
    } catch (e) {}

    // SharedPreferences — dónde guardan tokens/credenciales
    try {
        var SP = Java.use('android.app.SharedPreferencesImpl');
        SP.getString.implementation = function (k, d) {
            var v = this.getString(k, d);
            console.log("[PREF] " + k + " = " + v);
            return v;
        };
    } catch (e) {}

    // EditText.getText — captura lo que se escribe (usuario/clave)
    try {
        var EditText = Java.use('android.widget.EditText');
        EditText.getText.implementation = function () {
            var t = this.getText();
            console.log("[INPUT] " + t.toString());
            return t;
        };
    } catch (e) {}

    function bytes2str(b) {
        try { return Java.use('java.lang.String').$new(b); } catch (e) { return "<bin>"; }
    }
});
"""


def _run(cmd: str, tout: int = 30) -> tuple:
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=tout)
        return ((r.stdout or "") + (r.stderr or "")).strip(), r.returncode
    except subprocess.TimeoutExpired:
        return f"Timeout ({tout}s)", 1
    except Exception as e:
        return str(e), 1


def run(target: str = "", action: str = "all", device: str = "usb",
        run: str = "false", output_dir: str = "", **kwargs) -> dict:
    target = (target or kwargs.get("package") or kwargs.get("pkg") or "").strip()
    action = (action or "all").strip().lower()
    do_run = str(run).lower() in ("1", "true", "yes", "si", "sí", "y")

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    if not output_dir:
        output_dir = f"/tmp/apk_dyn_{ts}"
    outdir = Path(output_dir)
    outdir.mkdir(parents=True, exist_ok=True)

    has_frida = shutil.which("frida") is not None
    has_obj   = shutil.which("objection") is not None
    has_adb   = shutil.which("adb") is not None

    lines = [
        "╔═══ APK_DYNAMIC — análisis dinámico (Frida) ═══════════╗",
        f"  Target : {target or '(paquete no indicado)'}",
        f"  Acción : {action}   Ejecutar: {do_run}",
        f"  Tools  : frida={'✓' if has_frida else '✗'} objection={'✓' if has_obj else '✗'} adb={'✓' if has_adb else '✗'}",
        "╚═══════════════════════════════════════════════════════╝",
        "",
    ]
    findings, artifacts = [], {}
    dev_flag = "-U" if device in ("usb", "u", "") else f"-D {device}"

    # ── Generar scripts ───────────────────────────────────────────────────────
    if action in ("all", "ssl-unpin", "sslpinning", "ssl"):
        p = outdir / "ssl_unpin.js"
        p.write_text(_SSL_UNPIN_JS, encoding="utf-8")
        artifacts["ssl_unpin"] = str(p)
        lines.append(f"✓ SSL unpinning  → {p}")
        findings.append({"type": "mobile_artifact", "value": str(p), "severity": "info",
                         "description": "Script Frida de SSL unpinning universal"})
    if action in ("all", "hook", "dump", "creds", "trace"):
        p = outdir / "hooks.js"
        p.write_text(_HOOKS_JS, encoding="utf-8")
        artifacts["hooks"] = str(p)
        lines.append(f"✓ Hooks creds/cripto → {p}")
        findings.append({"type": "mobile_artifact", "value": str(p), "severity": "info",
                         "description": "Script Frida de hooks de credenciales/criptografía"})

    # ── Comandos listos ───────────────────────────────────────────────────────
    lines.append("\n▶ Comandos (dispositivo/emulador con frida-server corriendo):")
    if not has_frida:
        lines.append("  ⚠ frida no instalado →  pip install frida-tools")
    if target:
        if artifacts.get("ssl_unpin"):
            lines.append(f"  # Bypass SSL pinning + lanzar app:")
            lines.append(f"  frida {dev_flag} -f {target} -l {artifacts['ssl_unpin']} --no-pause")
        if artifacts.get("hooks"):
            lines.append(f"  # Capturar credenciales/cripto (app ya abierta):")
            lines.append(f"  frida {dev_flag} -n {target} -l {artifacts['hooks']}")
        if has_obj:
            lines.append(f"  # Alternativa con objection (unpin + explorar):")
            lines.append(f"  objection -g {target} explore --startup-command 'android sslpinning disable'")
    else:
        lines.append("  (indica target=<nombre.paquete> para comandos concretos)")
    lines.append("  # Intercepta el tráfico con Burp/mitmproxy (proxy del dispositivo + CA instalada).")

    # ── Utilidades: listar dispositivos / apps ────────────────────────────────
    if action == "list" or do_run:
        if has_frida:
            out, _ = _run(f"frida-ls-devices", 20)
            lines.append("\n▶ Dispositivos Frida:\n" + (out or "(ninguno)"))
        if has_adb:
            out, _ = _run("adb devices", 15)
            lines.append("\n▶ adb:\n" + out)

    # ── Ejecución best-effort ─────────────────────────────────────────────────
    launched = False
    if do_run and has_frida and target and artifacts.get("ssl_unpin"):
        lines.append(f"\n▶ Ejecutando SSL unpinning (10s de muestra)…")
        out, code = _run(
            f"timeout 12 frida {dev_flag} -f {target} -l {artifacts['ssl_unpin']} --no-pause -q", 20)
        lines.append("  " + "\n  ".join(out.splitlines()[:25]) if out else "  (sin salida)")
        launched = "unpinning activo" in out or "TrustManager" in out
        if launched:
            findings.append({"type": "ssl_unpin_active", "value": target, "severity": "high",
                             "description": f"SSL pinning bypasseado en runtime para {target}"})
        elif "unable to find" in out.lower() or "failed to spawn" in out.lower() or "no device" in out.lower():
            lines.append("  ⚠ No hay dispositivo/frida-server o el paquete no está instalado.")

    lines.append(f"\n{'═'*60}")
    lines.append(f"  Scripts en: {output_dir}")
    lines.append(f"  {'✓ unpinning ejecutado' if launched else '· scripts listos para ejecutar manualmente'}")
    lines.append(f"{'═'*60}")

    return {
        "success": True,
        "output": "\n".join(lines),
        "findings": findings,
        "artifacts": artifacts,
        "launched": launched,
        "output_dir": str(outdir),
    }
