"""
HackerAgent Skills — módulos de herramientas especializadas.
Cada skill tiene META (descripción/args/category) y run(**kwargs) -> dict.
Carga desde skills/*.py y skills/<subdir>/*.py automáticamente.
"""
import importlib.util
import sys
from pathlib import Path

_SKILLS: dict = {}

CATEGORY_LABELS = {
    "recon_pasivo": "🔍 RECONOCIMIENTO PASIVO",
    "recon_activo": "⚡ RECONOCIMIENTO ACTIVO",
    "vuln_scan":    "🎯 ESCANEO DE VULNERABILIDADES",
    "analisis":     "🔬 ANÁLISIS DE CÓDIGO / CONTENIDO",
    "ing_inversa":  "🔬 INGENIERÍA INVERSA",
    "ataque":       "💥 ATAQUE / EXPLOTACIÓN",
    "desarrollo":   "🛠  DESARROLLO DE CÓDIGO / MALWARE",
    "otros":        "⚙  OTROS",
}

CATEGORY_ORDER = [
    "recon_pasivo", "recon_activo", "vuln_scan",
    "analisis", "ing_inversa", "ataque", "desarrollo", "otros",
]


def load_skills() -> dict:
    """
    Carga dinámicamente todos los skills desde:
      - skills/*.py  (raíz)
      - skills/<subdir>/*.py  (un nivel de subdirectorios)
    Cada módulo debe tener META dict y run() function.
    """
    global _SKILLS
    _SKILLS = {}
    skills_dir = Path(__file__).parent

    # Recopilar archivos: raíz primero, luego subdirectorios
    skill_files: list[Path] = []
    for f in sorted(skills_dir.glob("*.py")):
        if not f.stem.startswith("_"):
            skill_files.append(f)
    for subdir in sorted(skills_dir.iterdir()):
        if subdir.is_dir() and not subdir.name.startswith(("_", ".")):
            for f in sorted(subdir.glob("*.py")):
                if not f.stem.startswith("_"):
                    skill_files.append(f)

    for f in skill_files:
        try:
            mod_name = f"_skill_{f.parent.stem}_{f.stem}"
            spec = importlib.util.spec_from_file_location(mod_name, f)
            if spec and spec.loader:
                mod = importlib.util.module_from_spec(spec)
                sys.modules[mod_name] = mod
                spec.loader.exec_module(mod)
                if hasattr(mod, "META") and hasattr(mod, "run"):
                    _SKILLS[mod.META["name"]] = mod
        except Exception as e:
            print(f"[skills] Error cargando {f.name}: {e}", file=sys.stderr)

    return _SKILLS


def run_skill(name: str, **kwargs) -> dict:
    """Ejecuta un skill por nombre. Retorna dict con success, output, findings."""
    if not _SKILLS:
        load_skills()
    mod = _SKILLS.get(name)
    if not mod:
        avail = list(_SKILLS.keys())
        return {
            "success": False,
            "output": f"Skill '{name}' no existe. Disponibles: {avail}",
            "findings": [],
        }
    try:
        return mod.run(**kwargs)
    except Exception as e:
        return {"success": False, "output": f"Error en skill {name}: {e}", "findings": []}


def skill_names() -> list:
    """Retorna lista ordenada de nombres de skills disponibles."""
    if not _SKILLS:
        load_skills()
    return sorted(_SKILLS.keys())


def skills_by_category(enabled: list = None) -> dict:
    """
    Retorna dict {category: [(name, description, module)]} agrupado por categoría.
    Si `enabled` es una lista, solo incluye esos skills.
    """
    if not _SKILLS:
        load_skills()
    result = {}
    for name, mod in _SKILLS.items():
        if enabled is not None and name not in enabled:
            continue
        cat = mod.META.get("category", "otros")
        result.setdefault(cat, []).append((name, mod.META.get("description", ""), mod))
    for cat in result:
        result[cat].sort(key=lambda x: x[0])
    return result


def skills_context(enabled: list = None) -> str:
    """
    Genera el bloque de texto de skills para el system prompt, agrupado por categoría.
    Si `enabled` es lista, solo muestra esos skills.
    """
    if not _SKILLS:
        load_skills()
    if not _SKILLS:
        return ""

    by_cat = skills_by_category(enabled)
    if not by_cat:
        return ""

    lines = [
        "\nSKILLS PYTHON DISPONIBLES (úsalos en vez de comandos crudos cuando sea posible):",
        "Sintaxis en el campo 'commands': SKILL:<nombre> clave1=valor1 clave2=valor2",
    ]
    all_cats = list(CATEGORY_ORDER) + [c for c in by_cat if c not in CATEGORY_ORDER]
    for cat in all_cats:
        items = by_cat.get(cat, [])
        if not items:
            continue
        lines.append(f"\n  {CATEGORY_LABELS.get(cat, cat)}:")
        for name, desc, mod in items:
            m = mod.META
            args = " ".join(f"[{a}]" for a in m.get("args", []))
            lines.append(f"    SKILL:{name} {args}")
            lines.append(f"      → {desc[:80]}")
            if m.get("example"):
                lines.append(f"      Ej: {m['example']}")
    lines.append("\nNOTA: Los skills manejan timeouts, JSON parsing y detección de paths internamente.")
    return "\n".join(lines)
