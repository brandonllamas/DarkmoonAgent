"""
Skill: metadata_osint
Extrae metadatos de documentos e imágenes: ExifTool, Metagoofil (Kali).
Busca documentos públicos (PDF, DOCX, XLSX, PPT, ODP) de un dominio,
los descarga y extrae usuarios, software, paths internos, GPS coords, etc.
"""
import re
import os
import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlparse

try:
    import requests as _req
except ImportError:
    _req = None

META = {
    "name": "metadata_osint",
    "category": "osint",
    "description": (
        "Extrae metadatos de documentos e imágenes públicos de un dominio. "
        "ExifTool + Metagoofil (Kali) para PDF/DOCX/XLS/PPT. "
        "Revela usuarios, software, paths internos, GPS, fechas de creación."
    ),
    "args": ["domain", "target", "file_types", "limit"],
    "example": "SKILL:metadata_osint domain=example.com file_types=pdf,docx,xlsx",
}

_DEFAULT_TYPES = "pdf,docx,xlsx,pptx,doc,xls,ppt,odt"
_SEARCH_ENGINES = [
    "https://duckduckgo.com/html/?q=site:{domain}+filetype:{ext}",
    "https://www.bing.com/search?q=site:{domain}+filetype:{ext}",
]
_HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0",
}


def _sh(cmd, timeout=120):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return (r.stdout or "") + (r.stderr or ""), r.returncode
    except Exception as e:
        return str(e), 1


def _run_metagoofil(domain, file_types, limit, out_dir):
    binary = shutil.which("metagoofil")
    if not binary:
        return None
    types = file_types.replace(",", ",")
    cmd = f'"{binary}" -d {domain} -t {types} -l {limit} -o "{out_dir}" -f /dev/null 2>&1'
    out, _ = _sh(cmd, timeout=300)
    return out if len(out) > 50 else None


def _run_exiftool(path):
    binary = shutil.which("exiftool")
    if not binary:
        return None
    out, _ = _sh(f'"{binary}" -json "{path}" 2>&1', timeout=30)
    try:
        data = json.loads(out)
        return data[0] if data else {}
    except Exception:
        return {"raw": out[:2000]}


def _find_urls_in_html(html, domain, ext):
    """Extrae URLs de documentos en HTML de resultados de búsqueda."""
    pattern = rf'https?://[^\s"\'<>]*\.{re.escape(ext)}(?:\?[^\s"\'<>]*)?'
    urls = set()
    for url in re.findall(pattern, html, re.I):
        if domain in url:
            urls.add(url.rstrip(".,)>"))
    return sorted(urls)[:10]


def _search_docs(domain, ext):
    if _req is None:
        return []
    urls = set()
    for tmpl in _SEARCH_ENGINES:
        url = tmpl.format(domain=domain, ext=ext)
        try:
            r = _req.get(url, headers=_HEADERS, timeout=10, allow_redirects=True)
            urls.update(_find_urls_in_html(r.text, domain, ext))
        except Exception:
            pass
    return sorted(urls)[:5]


def _download(url, dest_dir):
    if _req is None:
        return None
    try:
        r = _req.get(url, headers=_HEADERS, timeout=20, stream=True)
        if r.status_code == 200:
            ext = url.rsplit(".", 1)[-1].split("?")[0][:10]
            fname = re.sub(r"[^\w\-.]", "_", urlparse(url).path.rsplit("/", 1)[-1])[:80]
            path = Path(dest_dir) / fname
            with open(path, "wb") as f:
                for chunk in r.iter_content(8192):
                    f.write(chunk)
            return str(path)
    except Exception:
        pass
    return None


def _parse_exif(data: dict) -> dict:
    """Extrae campos interesantes del output de exiftool."""
    interesting = {}
    keys_of_interest = [
        "Author", "Creator", "Producer", "LastModifiedBy", "Manager",
        "Company", "Application", "Software", "GeneratorIdentifier",
        "CreatorTool", "CreateDate", "ModifyDate", "MetadataDate",
        "GPSLatitude", "GPSLongitude", "GPSPosition",
        "OriginalFileName", "Template", "SourceFile",
        "LinuxPath", "OriginalDocumentID",
        "RightsManagement", "Keywords", "Subject",
    ]
    for k in keys_of_interest:
        for dk, dv in data.items():
            if k.lower() in dk.lower() and dv:
                interesting[dk] = str(dv)[:200]
    return interesting


def _extract_users_from_exif(data: dict) -> list:
    users = set()
    user_fields = ["author", "creator", "lastmodifiedby", "manager",
                   "createdby", "modifiedby", "contributor"]
    for k, v in data.items():
        if any(f in k.lower() for f in user_fields) and v:
            for token in re.split(r"[;,|/\\]", str(v)):
                token = token.strip()
                if 2 < len(token) < 80 and not token.startswith("http"):
                    users.add(token)
    return sorted(users)


def run(domain: str = "", target: str = "", file_types: str = "",
        limit: str = "25", **kwargs) -> dict:
    domain = (domain or target or kwargs.get("url", "")).strip().lower()
    if not domain:
        return {"success": False, "findings": [],
                "output": 'Falta "domain". Ej: SKILL:metadata_osint domain=example.com'}
    domain = re.sub(r"^https?://", "", domain).split("/")[0]
    file_types = file_types or _DEFAULT_TYPES
    types_list = [t.strip().lstrip(".") for t in file_types.split(",")]
    try:
        lim = int(limit)
    except Exception:
        lim = 25

    lines = [
        f"╔══ METADATA OSINT — {domain} {'═'*max(0,49-len(domain))}╗",
        f"  Tipos: {', '.join(types_list)}   Límite: {lim}",
        "╚" + "═"*70 + "╝", "",
    ]
    findings = []
    all_users = set()
    all_software = set()
    all_paths = set()

    with tempfile.TemporaryDirectory() as tmpdir:
        # ── 1. Metagoofil nativo ──────────────────────────────────────────────
        meta_out = _run_metagoofil(domain, file_types, lim, tmpdir)
        if meta_out:
            lines.append("  ✅ Metagoofil (nativo) ejecutado\n")
            lines.append(meta_out[:5000])
            users = re.findall(r"Users found:\s*(.*?)(?:\n|$)", meta_out, re.I)
            for u in users:
                for uu in u.split(","):
                    uu = uu.strip()
                    if uu:
                        all_users.add(uu)
            sw = re.findall(r"Software:\s*(.*?)(?:\n|$)", meta_out, re.I)
            for s in sw:
                all_software.add(s.strip()[:80])
            lines.append("")
        else:
            lines.append("  ⚠ Metagoofil no instalado → pip3 install metagoofil  /  sudo apt install metagoofil")
            lines.append("  → Buscando documentos manualmente…\n")

            # ── 2. Búsqueda manual + ExifTool ────────────────────────────────
            all_doc_urls = []
            for ext in types_list[:5]:
                doc_urls = _search_docs(domain, ext)
                if doc_urls:
                    lines.append(f"  📄 .{ext}: {len(doc_urls)} documentos encontrados")
                    all_doc_urls.extend(doc_urls)

            if not all_doc_urls:
                lines.append("  ✗ Sin documentos públicos encontrados")
            else:
                lines.append(f"\n  📥 Descargando {min(10, len(all_doc_urls))} documentos para análisis…\n")
                for doc_url in all_doc_urls[:10]:
                    lines.append(f"    → {doc_url[:80]}")
                    local = _download(doc_url, tmpdir)
                    if not local:
                        lines.append("       ✗ Descarga fallida")
                        continue

                    exif = _run_exiftool(local)
                    if exif:
                        parsed = _parse_exif(exif)
                        users = _extract_users_from_exif(exif)
                        all_users.update(users)
                        sw = exif.get("Software", exif.get("CreatorTool", exif.get("Producer", "")))
                        if sw:
                            all_software.add(str(sw)[:80])
                        # Internal paths
                        for v in exif.values():
                            v_str = str(v)
                            if re.search(r"[A-Z]:\\|/home/|/var/|/opt/", v_str):
                                all_paths.add(v_str[:120])
                        if parsed:
                            lines.append(f"       ExifTool:")
                            for k, v in list(parsed.items())[:8]:
                                lines.append(f"         {k}: {v[:80]}")
                    else:
                        if not shutil.which("exiftool"):
                            lines.append("       ⚠ ExifTool no instalado: sudo apt install libimage-exiftool-perl")
                lines.append("")

        # ── 3. ExifTool en archivos descargados por metagoofil ─────────────────
        downloaded_files = list(Path(tmpdir).iterdir()) if Path(tmpdir).exists() else []
        if downloaded_files and shutil.which("exiftool"):
            lines.append(f"  🔬 ANÁLISIS EXIFTOOL ({len(downloaded_files)} archivos)")
            for fp in downloaded_files[:20]:
                exif = _run_exiftool(str(fp))
                if exif:
                    users = _extract_users_from_exif(exif)
                    all_users.update(users)
                    sw = exif.get("Software", exif.get("CreatorTool", ""))
                    if sw:
                        all_software.add(str(sw)[:80])
            lines.append("")

    # ── 4. Resumen ─────────────────────────────────────────────────────────────
    if all_users:
        lines.append(f"  👤 USUARIOS ENCONTRADOS ({len(all_users)})")
        for u in sorted(all_users)[:30]:
            lines.append(f"      {u}")
            findings.append({"type": "username", "value": u, "severity": "high",
                             "description": f"Usuario en metadatos de {domain}: {u}"})
        lines.append("")

    if all_software:
        lines.append(f"  🖥  SOFTWARE IDENTIFICADO ({len(all_software)})")
        for sw in sorted(all_software)[:20]:
            lines.append(f"      {sw}")
            findings.append({"type": "software", "value": sw, "severity": "medium",
                             "description": f"Software interno: {sw}"})
        lines.append("")

    if all_paths:
        lines.append(f"  📂 PATHS INTERNOS ({len(all_paths)})")
        for p in sorted(all_paths)[:10]:
            lines.append(f"      {p}")
            findings.append({"type": "internal_path", "value": p, "severity": "medium",
                             "description": f"Path interno en metadatos: {p}"})
        lines.append("")

    lines.append(f"  ─── {len(findings)} hallazgos ───")
    if all_users:
        user_list = ", ".join(list(all_users)[:5])
        lines.append(f"  ▶ Siguiente: SKILL:sherlock_osint username=<usuario>")
        lines.append(f"              SKILL:email_osint email=usuario@{domain}")

    return {"success": True, "output": "\n".join(lines), "findings": findings,
            "users": sorted(all_users), "software": sorted(all_software), "domain": domain}
