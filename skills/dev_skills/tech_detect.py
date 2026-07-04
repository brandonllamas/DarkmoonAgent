"""
Skill: tech_detect
Identifica el stack tecnológico completo de un target (URL o directorio local):
frameworks frontend/backend, bases de datos, Firebase, autenticación, cloud,
APIs, persistencia, infraestructura. Alimenta al agente con contexto exacto
para que el código que genere sea compatible con el sistema real.
"""
import os
import re
import json
from pathlib import Path
from urllib.parse import urlparse

try:
    import requests as _req
except ImportError:
    _req = None

META = {
    "name": "tech_detect",
    "category": "desarrollo",
    "description": (
        "Detecta el stack tecnológico de un target (URL o directorio): frameworks, "
        "bases de datos, Firebase, auth, cloud, APIs, persistencia, infraestructura. "
        "Da al agente el contexto exacto para generar código compatible."
    ),
    "args": ["target", "deep", "timeout"],
    "example": "SKILL:tech_detect target=https://example.com",
}

# ─────────────────────────────────────────────────────────────────────────────
# FIRMAS DE TECNOLOGÍAS
# ─────────────────────────────────────────────────────────────────────────────

_SIGS = {
    # ── Firebase ──────────────────────────────────────────────────────────────
    "firebase":          {"cat": "cloud/baas",    "sev": "high",
                          "keys": ["firebaseapp.com", "firebase.google.com", "firebase.json",
                                   "__firebase__", "firebaseConfig", "initializeApp",
                                   "firebase-admin", "@firebase/app"]},
    "firestore":         {"cat": "database/nosql", "sev": "high",
                          "keys": ["firestore()", "collection(", "getDocs", "addDoc",
                                   "firestore.googleapis.com", "cloud.firestore"]},
    "firebase_rtdb":     {"cat": "database/realtime", "sev": "high",
                          "keys": [".firebaseio.com", "getDatabase(", "ref(", "onValue(",
                                   "DatabaseReference", "firebase/database"]},
    "firebase_auth":     {"cat": "auth",           "sev": "high",
                          "keys": ["getAuth(", "signInWithEmailAndPassword", "createUserWith",
                                   "onAuthStateChanged", "GoogleAuthProvider", "firebase/auth"]},
    "firebase_storage":  {"cat": "storage",        "sev": "medium",
                          "keys": ["getStorage(", "uploadBytes", "getDownloadURL",
                                   "storageRef", "firebase/storage"]},
    "firebase_functions":{"cat": "serverless",     "sev": "medium",
                          "keys": ["functions.httpsCallable", "onRequest(", "cloudfunctions.net",
                                   "firebase-functions", "functions.region("]},

    # ── Bases de datos ────────────────────────────────────────────────────────
    "mongodb":           {"cat": "database/nosql", "sev": "high",
                          "keys": ["mongodb://", "mongodb+srv://", "mongoose", "MongoClient",
                                   "pymongo", "motor", "db.collection(", "ObjectId("]},
    "postgresql":        {"cat": "database/sql",   "sev": "high",
                          "keys": ["postgresql://", "postgres://", "psycopg2", "asyncpg",
                                   "pg.Pool(", "Sequelize.*postgres", "prisma.*postgresql",
                                   "DATABASE_URL.*postgres", "pg_connect"]},
    "mysql":             {"cat": "database/sql",   "sev": "high",
                          "keys": ["mysql://", "mysql2", "pymysql", "MySQLdb",
                                   "createConnection.*mysql", "MYSQL_HOST", "mysql.connector"]},
    "sqlite":            {"cat": "database/sql",   "sev": "medium",
                          "keys": ["sqlite3", "SQLite", ".db\b", "sqlite://",
                                   "better-sqlite3", "aiosqlite"]},
    "redis":             {"cat": "cache/database", "sev": "high",
                          "keys": ["redis://", "REDIS_URL", "ioredis", "redis.StrictRedis",
                                   "aioredis", "RedisClient", "redis.createClient"]},
    "elasticsearch":     {"cat": "database/search","sev": "high",
                          "keys": ["elasticsearch://", "elastic.co", "Elasticsearch(",
                                   "@elastic/elasticsearch", "elasticsearch-py"]},
    "supabase":          {"cat": "database/baas",  "sev": "high",
                          "keys": ["supabase.co", "createClient.*supabase", "@supabase/supabase-js",
                                   "supabase-py", "SUPABASE_URL"]},
    "dynamodb":          {"cat": "database/nosql", "sev": "high",
                          "keys": ["DynamoDB(", "dynamodb.amazonaws.com", "boto3.*dynamodb",
                                   "DocumentClient", "@aws-sdk/client-dynamodb"]},
    "prisma":            {"cat": "orm",            "sev": "medium",
                          "keys": ["PrismaClient", "prisma.schema", "@prisma/client",
                                   "prisma migrate", "prisma generate"]},
    "typeorm":           {"cat": "orm",            "sev": "medium",
                          "keys": ["TypeORM", "createConnection", "getRepository(",
                                   "typeorm", "@Entity(", "@Column("]},
    "sqlalchemy":        {"cat": "orm",            "sev": "medium",
                          "keys": ["SQLAlchemy", "declarative_base", "sessionmaker",
                                   "Column(", "relationship(", "from sqlalchemy"]},

    # ── Frontend frameworks ───────────────────────────────────────────────────
    "react":             {"cat": "frontend",       "sev": "info",
                          "keys": ["react.js", "react.min.js", "ReactDOM", "__REACT",
                                   "react-dom", "useState(", "useEffect(", "jsx"]},
    "nextjs":            {"cat": "frontend/ssr",   "sev": "info",
                          "keys": ["_next/static", "__NEXT_DATA__", "next/router",
                                   "next.config.js", "next.config.mjs", "getServerSideProps"]},
    "vue":               {"cat": "frontend",       "sev": "info",
                          "keys": ["vue.js", "vue.min.js", "__vue__", "new Vue(",
                                   "createApp(", "v-bind:", "v-model", "vue-router"]},
    "nuxtjs":            {"cat": "frontend/ssr",   "sev": "info",
                          "keys": ["__nuxt", "_nuxt/", "nuxt.config.js", "$nuxt",
                                   "useNuxtApp", "useRoute", "@nuxt/"]},
    "angular":           {"cat": "frontend",       "sev": "info",
                          "keys": ["ng-version=", "angular.js", "@angular/core",
                                   "NgModule", "zone.js", "ng-app"]},
    "svelte":            {"cat": "frontend",       "sev": "info",
                          "keys": ["svelte.js", "SvelteComponent", "__svelte",
                                   "svelte/store", ".svelte"]},
    "astro":             {"cat": "frontend/ssg",   "sev": "info",
                          "keys": ["astro-island", "@astrojs/", "astro.build", ".astro"]},

    # ── Backend frameworks ────────────────────────────────────────────────────
    "express":           {"cat": "backend",        "sev": "info",
                          "keys": ["express()", "app.listen(", "app.use(", "express.Router",
                                   "X-Powered-By: Express", "res.json("]},
    "fastapi":           {"cat": "backend",        "sev": "info",
                          "keys": ["FastAPI(", "uvicorn", "@app.get(", "@app.post(",
                                   "fastapi", "pydantic"]},
    "django":            {"cat": "backend",        "sev": "info",
                          "keys": ["Django", "django.conf", "INSTALLED_APPS", "urls.py",
                                   "django.db", "manage.py", "WSGI_APPLICATION"]},
    "flask":             {"cat": "backend",        "sev": "info",
                          "keys": ["Flask(__name__)", "from flask import", "@app.route",
                                   "flask.run(", "render_template("]},
    "laravel":           {"cat": "backend",        "sev": "info",
                          "keys": ["laravel", "Illuminate\\\\", "artisan", "composer.json",
                                   "App\\\\Http\\\\", "blade.php"]},
    "rails":             {"cat": "backend",        "sev": "info",
                          "keys": ["Rails", "ActiveRecord", "ActionController",
                                   "config/routes.rb", "Gemfile", "rails server"]},
    "spring":            {"cat": "backend",        "sev": "info",
                          "keys": ["springframework", "@SpringBootApplication", "pom.xml",
                                   "@RestController", "@RequestMapping", "application.yml"]},
    "nestjs":            {"cat": "backend",        "sev": "info",
                          "keys": ["@nestjs/core", "@Module(", "@Controller(",
                                   "NestFactory", "@Injectable(", "nestjs"]},
    "gin":               {"cat": "backend",        "sev": "info",
                          "keys": ["gin.Default()", "gin.New(", "go-gin", "github.com/gin-gonic"]},

    # ── Autenticación ─────────────────────────────────────────────────────────
    "jwt":               {"cat": "auth",           "sev": "high",
                          "keys": ["jsonwebtoken", "jwt.sign(", "jwt.verify(", "PyJWT",
                                   "Authorization: Bearer", "eyJhbGci", "JWT_SECRET"]},
    "oauth2":            {"cat": "auth",           "sev": "medium",
                          "keys": ["oauth2", "grant_type=", "access_token", "refresh_token",
                                   "client_id", "client_secret", "/oauth/token"]},
    "auth0":             {"cat": "auth",           "sev": "medium",
                          "keys": ["auth0.com", "@auth0/", "auth0-spa-js", "AUTH0_DOMAIN"]},
    "keycloak":          {"cat": "auth",           "sev": "medium",
                          "keys": ["keycloak", "KeycloakInstance", "keycloak-js", "auth/realms"]},
    "passport":          {"cat": "auth",           "sev": "medium",
                          "keys": ["passport.js", "passport.use(", "passport.authenticate",
                                   "PassportStrategy"]},

    # ── Cloud / Infraestructura ───────────────────────────────────────────────
    "aws":               {"cat": "cloud",          "sev": "high",
                          "keys": ["amazonaws.com", "AWS_ACCESS_KEY", "aws-sdk", "boto3",
                                   "@aws-sdk/", "s3.amazonaws.com", "ec2.amazonaws.com"]},
    "gcp":               {"cat": "cloud",          "sev": "high",
                          "keys": ["googleapis.com", "google-cloud", "GCP_PROJECT",
                                   "GOOGLE_APPLICATION_CREDENTIALS", "gcloud", "appspot.com"]},
    "azure":             {"cat": "cloud",          "sev": "high",
                          "keys": ["azure.com", "azurewebsites.net", "@azure/",
                                   "AZURE_", "Microsoft.Azure", "blob.core.windows.net"]},
    "cloudflare":        {"cat": "cdn/proxy",      "sev": "medium",
                          "keys": ["cloudflare", "CF-Ray", "workers.dev", "__cf_bm",
                                   "cf-connecting-ip"]},
    "vercel":            {"cat": "hosting",        "sev": "info",
                          "keys": ["vercel.com", "vercel.app", "VERCEL_", "x-vercel-id"]},
    "netlify":           {"cat": "hosting",        "sev": "info",
                          "keys": ["netlify.app", "netlify.com", "NETLIFY_", "x-nf-request-id"]},
    "heroku":            {"cat": "hosting",        "sev": "info",
                          "keys": ["heroku", ".herokuapp.com", "DYNO", "PORT=5000"]},

    # ── APIs ──────────────────────────────────────────────────────────────────
    "graphql":           {"cat": "api",            "sev": "medium",
                          "keys": ["/graphql", "graphql-tag", "ApolloClient", "gql`",
                                   "GraphQLSchema", "__schema", "graphene", "strawberry"]},
    "grpc":              {"cat": "api",            "sev": "medium",
                          "keys": ["grpc", "proto3", ".proto", "@grpc/grpc-js",
                                   "grpcio", "channel.credentials"]},
    "websocket":         {"cat": "api/realtime",   "sev": "medium",
                          "keys": ["WebSocket(", "socket.io", "ws://", "wss://",
                                   "io.connect(", "socketio", "websockets"]},
    "trpc":              {"cat": "api",            "sev": "info",
                          "keys": ["@trpc/", "initTRPC", "createTRPCRouter", "trpc.router"]},

    # ── Persistencia / Estado ─────────────────────────────────────────────────
    "redux":             {"cat": "state",          "sev": "info",
                          "keys": ["redux", "createStore(", "useSelector(", "useDispatch(",
                                   "@reduxjs/toolkit", "combineReducers"]},
    "zustand":           {"cat": "state",          "sev": "info",
                          "keys": ["zustand", "create((set", "useStore("]},
    "mobx":              {"cat": "state",          "sev": "info",
                          "keys": ["mobx", "observable(", "action(", "computed(", "makeObservable"]},
    "celery":            {"cat": "queue/tasks",    "sev": "medium",
                          "keys": ["celery", "Celery(", "@app.task", "CELERY_BROKER",
                                   "beat_schedule", "chord("]},
    "rabbitmq":          {"cat": "queue",          "sev": "medium",
                          "keys": ["amqp://", "pika", "rabbitmq", "amqplib",
                                   "RABBITMQ_URL", "channel.queue_declare"]},
    "kafka":             {"cat": "queue",          "sev": "medium",
                          "keys": ["kafka", "KafkaConsumer", "KafkaProducer",
                                   "confluent_kafka", "KAFKA_BOOTSTRAP"]},

    # ── Mobile ────────────────────────────────────────────────────────────────
    "react_native":      {"cat": "mobile",         "sev": "info",
                          "keys": ["react-native", "RCTRootView", "AppRegistry",
                                   "StyleSheet.create", "Platform.OS"]},
    "flutter":           {"cat": "mobile",         "sev": "info",
                          "keys": ["flutter", "dart", "pubspec.yaml", "MaterialApp(",
                                   "StatefulWidget", "BuildContext"]},
    "expo":              {"cat": "mobile",         "sev": "info",
                          "keys": ["expo", "expo-sdk", "Expo.Constants", "app.json",
                                   "expo start", "@expo/"]},
}

# Rutas de prueba para detección activa
_PROBE_PATHS = [
    "/api", "/api/health", "/api/v1", "/api/v2",
    "/graphql", "/.well-known/openid-configuration",
    "/swagger.json", "/openapi.json", "/api-docs",
    "/admin", "/wp-admin", "/wp-json",
    "/.env", "/config.json", "/robots.txt", "/sitemap.xml",
    "/package.json", "/composer.json",
]

# Archivos locales relevantes para análisis de directorio
_LOCAL_FILES = [
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "requirements.txt", "Pipfile", "pyproject.toml", "setup.py",
    "Gemfile", "composer.json", "go.mod", "Cargo.toml", "pom.xml",
    "build.gradle", ".env", ".env.example", ".env.local",
    "firebase.json", ".firebaserc", "firestore.rules",
    "docker-compose.yml", "docker-compose.yaml", "Dockerfile",
    "next.config.js", "next.config.mjs", "nuxt.config.js",
    "angular.json", "svelte.config.js", "astro.config.mjs",
    "prisma/schema.prisma", "config/database.yml",
    "src/main.ts", "src/main.py", "src/app.py", "src/index.js",
    "src/index.ts", "app.py", "main.py", "server.js", "server.ts",
    "manage.py", "wsgi.py", "asgi.py",
]


def _match(text: str, keys: list) -> list:
    text = text.lower()
    return [k for k in keys if k.lower() in text]


def _detect_in_text(text: str) -> dict:
    detected = {}
    for tech, sig in _SIGS.items():
        hits = _match(text, sig["keys"])
        if hits:
            detected[tech] = {**sig, "evidence": hits[:3]}
    return detected


def _fetch(url: str, timeout: int = 10) -> tuple:
    if _req is None:
        return "", {}
    try:
        r = _req.get(url, timeout=timeout,
                     headers={"User-Agent": "Mozilla/5.0 (compatible; TechDetect/1.0)"},
                     verify=False, allow_redirects=True)
        return r.text, dict(r.headers)
    except Exception:
        return "", {}


def _analyze_url(target: str, deep: bool, timeout: int) -> tuple:
    """Analiza un target HTTP/HTTPS."""
    import warnings
    try:
        from urllib3.exceptions import InsecureRequestWarning
        warnings.filterwarnings("ignore", category=InsecureRequestWarning)
    except Exception:
        pass

    found: dict = {}
    probe_results = []

    base = target.rstrip("/")
    body, headers = _fetch(base, timeout)
    all_text = body + " " + " ".join(f"{k}: {v}" for k, v in headers.items())
    found.update(_detect_in_text(all_text))

    # Analizar headers HTTP específicamente
    srv = headers.get("Server", headers.get("server", ""))
    powered = headers.get("X-Powered-By", headers.get("x-powered-by", ""))
    tech_header = headers.get("X-Tech-Stack", "")
    if srv:
        probe_results.append(f"Server: {srv}")
    if powered:
        probe_results.append(f"X-Powered-By: {powered}")
        all_text += " " + powered
        found.update(_detect_in_text(powered))

    if deep:
        for path in _PROBE_PATHS:
            pb, ph = _fetch(base + path, timeout=max(4, timeout // 3))
            if pb:
                probe_results.append(f"  {path} → {len(pb)} bytes")
                found.update(_detect_in_text(pb + " " + " ".join(ph.values())))

        # Intentar leer JS sources referenciadas
        js_urls = re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', body)
        for js in js_urls[:8]:
            jurl = js if js.startswith("http") else base + ("" if js.startswith("/") else "/") + js
            jb, _ = _fetch(jurl, timeout=max(4, timeout // 3))
            if jb:
                found.update(_detect_in_text(jb))

    return found, probe_results, headers


def _analyze_dir(path: Path) -> tuple:
    """Analiza un directorio local."""
    found: dict = {}
    scanned = []

    # Leer archivos de configuración conocidos
    for fname in _LOCAL_FILES:
        fpath = path / fname
        if fpath.exists():
            try:
                text = fpath.read_text(encoding="utf-8", errors="ignore")
                hits = _detect_in_text(text)
                if hits:
                    scanned.append(f"  {fname} → {len(hits)} techs")
                    found.update(hits)
            except Exception:
                pass

    # Escaneo recursivo de código fuente (primeros 200 archivos)
    code_exts = {".js", ".ts", ".jsx", ".tsx", ".py", ".go", ".rs",
                 ".java", ".cs", ".php", ".rb", ".vue", ".svelte"}
    count = 0
    for f in path.rglob("*"):
        if count >= 200:
            break
        if f.suffix.lower() in code_exts and f.is_file():
            try:
                text = f.read_text(encoding="utf-8", errors="ignore")[:8000]
                found.update(_detect_in_text(text))
                count += 1
            except Exception:
                pass

    return found, scanned


def _format_report(detected: dict, probe_results: list, target: str, headers: dict) -> tuple:
    by_cat: dict = {}
    for tech, info in detected.items():
        cat = info.get("cat", "other")
        by_cat.setdefault(cat, []).append((tech, info))

    _CAT_ICONS = {
        "cloud/baas": "☁️", "database/nosql": "🍃", "database/sql": "🗄",
        "database/realtime": "⚡", "database/baas": "⚡", "database/search": "🔍",
        "cache/database": "⚡", "auth": "🔐", "frontend": "🌐",
        "frontend/ssr": "⚛", "frontend/ssg": "📄", "backend": "⚙️",
        "orm": "🔗", "api": "📡", "api/realtime": "🔌",
        "cloud": "☁️", "cdn/proxy": "🛡", "hosting": "🏠",
        "state": "🧠", "queue/tasks": "📋", "queue": "📋",
        "serverless": "λ", "storage": "💾", "mobile": "📱",
    }

    lines = [
        f"╔══ TECH DETECT — {target[:60]} {'═'*max(0,58-len(target))}╗",
        f"  {len(detected)} tecnologías identificadas",
        "╚" + "═"*70 + "╝",
        "",
    ]
    findings = []

    if not detected:
        lines.append("  ⚠ No se detectaron tecnologías conocidas.")
        return "\n".join(lines), findings

    # Sección por categoría
    for cat, items in sorted(by_cat.items()):
        icon = _CAT_ICONS.get(cat, "◆")
        lines.append(f"  {icon}  {cat.upper()}")
        for tech, info in sorted(items, key=lambda x: x[1].get("sev","info")):
            ev = ", ".join(info.get("evidence", []))[:60]
            sev = info.get("sev", "info")
            sev_marker = {"high": "🔴", "medium": "🟡", "info": "⚪"}.get(sev, "⚪")
            lines.append(f"      {sev_marker} {tech:<22} [{ev}]")
            findings.append({
                "type": f"tech_{tech}",
                "value": tech,
                "severity": sev,
                "category": cat,
                "evidence": ev,
                "description": f"{cat} — {tech} detectado en {target}",
            })
        lines.append("")

    if probe_results:
        lines.append("  📡  ENDPOINTS PROBADOS")
        for pr in probe_results[:20]:
            lines.append(f"      {pr}")
        lines.append("")

    if headers:
        notable = {k: v for k, v in headers.items()
                   if k.lower() in ("server", "x-powered-by", "x-frame-options",
                                    "content-security-policy", "x-content-type-options",
                                    "strict-transport-security", "cf-ray", "x-vercel-id")}
        if notable:
            lines.append("  🔒  HEADERS NOTABLES")
            for k, v in notable.items():
                lines.append(f"      {k}: {v[:80]}")
            lines.append("")

    # Resumen para el agente
    techs = sorted(detected.keys())
    lines.append("─" * 60)
    lines.append(f"  STACK DETECTADO: {', '.join(techs)}")
    lines.append("─" * 60)

    return "\n".join(lines), findings


def run(target: str = "", deep: str = "false", timeout: str = "10", **kwargs) -> dict:
    target = (target or kwargs.get("url") or kwargs.get("path") or "").strip()
    if not target:
        return {"success": False, "findings": [],
                "output": 'Falta "target". Ej: SKILL:tech_detect target=https://example.com'}

    do_deep = str(deep).lower() in ("1", "true", "yes", "si", "sí", "y")
    try:
        tout = int(timeout)
    except Exception:
        tout = 10

    headers: dict = {}
    probe_results: list = []

    # Detectar si es URL o path local
    is_url = target.startswith("http://") or target.startswith("https://")
    local_path = Path(target) if not is_url else None

    if is_url:
        detected, probe_results, headers = _analyze_url(target, do_deep, tout)
    elif local_path and local_path.exists():
        if local_path.is_file():
            try:
                text = local_path.read_text(encoding="utf-8", errors="ignore")
                detected = _detect_in_text(text)
            except Exception:
                detected = {}
        else:
            detected, probe_results = _analyze_dir(local_path)
    else:
        # Intenta como URL sin esquema
        target_url = "https://" + target
        detected, probe_results, headers = _analyze_url(target_url, do_deep, tout)
        if not detected:
            target_url = "http://" + target
            detected, probe_results2, headers2 = _analyze_url(target_url, do_deep, tout)
            if detected:
                headers = headers2
                probe_results = probe_results2

    output, findings = _format_report(detected, probe_results, target, headers)

    # Lista plana de tecnologías para que el agente la use como contexto
    tech_list = sorted(detected.keys())
    cats = sorted({info.get("cat", "other") for info in detected.values()})

    return {
        "success": True,
        "output": output,
        "findings": findings,
        "technologies": tech_list,
        "categories": cats,
        "stack_summary": ", ".join(tech_list),
    }
