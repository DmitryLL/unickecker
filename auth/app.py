import base64
import hashlib
import hmac
import json
import os
import sqlite3
import time
from datetime import datetime

from flask import Flask, g, jsonify, make_response, request

try:
    import pymssql
except Exception:
    pymssql = None

from cryptography.fernet import Fernet, InvalidToken

app = Flask(__name__)

ADMIN_USER_INIT = os.environ["ADMIN_USER"]
ADMIN_PASSWORD_HASH_INIT = os.environ["ADMIN_PASSWORD_HASH"]
SESSION_SECRET = os.environ["SESSION_SECRET"].encode()
DB_PATH = os.environ.get("DB_PATH", "/data/users.db")
DB_SETTINGS_PATH = os.environ.get("DB_SETTINGS_PATH", "/data/db_settings.json")
SETTINGS_KEY_PATH = os.environ.get("SETTINGS_KEY_PATH", "/data/.settings_key")
ENC_PREFIX = "enc:"

COOKIE_NAME = "sc_session"
SESSION_TTL = 60 * 60 * 24 * 7

# ===== MSSQL settings =====

# ===== Route registry =====
ROUTES = [
    {"key": "operations",    "title": "Статусы операций",  "group": "main"},
    {"key": "users",         "title": "Пользователи",      "group": "settings", "admin_only": True},
    {"key": "db_connection", "title": "Подключение к БД",  "group": "settings", "admin_only": True},
    {"key": "about",         "title": "О программе",       "group": "settings", "always": True},
]
ROUTE_KEYS = {r["key"] for r in ROUTES}
ALWAYS_ALLOWED = {r["key"] for r in ROUTES if r.get("always")}
ADMIN_ONLY = {r["key"] for r in ROUTES if r.get("admin_only")}
ASSIGNABLE = [r["key"] for r in ROUTES if not r.get("always") and not r.get("admin_only")]


# ===== Password =====
def hash_password(pw):
    salt = os.urandom(16)
    dk = hashlib.scrypt(pw.encode(), salt=salt, n=16384, r=8, p=1, dklen=32)
    return f"scrypt${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def verify_password(pw, hashed):
    try:
        scheme, salt_b64, dk_b64 = hashed.split("$")
        if scheme != "scrypt":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(dk_b64)
        dk = hashlib.scrypt(pw.encode(), salt=salt, n=16384, r=8, p=1, dklen=32)
        return hmac.compare_digest(dk, expected)
    except Exception:
        return False


# ===== Session =====
def sign_session(user_id):
    payload = f"{user_id}|{int(time.time())}"
    sig = hmac.new(SESSION_SECRET, payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}|{sig}"


def parse_session(token):
    try:
        uid, ts, sig = token.split("|")
        payload = f"{uid}|{ts}"
        expected = hmac.new(SESSION_SECRET, payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        if int(time.time()) - int(ts) > SESSION_TTL:
            return None
        return int(uid)
    except Exception:
        return None


# ===== SQLite (users) =====
def db():
    if "db" not in g:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def init_db():
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK (role IN ('admin', 'user')),
            permissions TEXT NOT NULL DEFAULT '[]',
            created_at INTEGER NOT NULL
        )
    """)
    n = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    if n == 0:
        conn.execute(
            "INSERT INTO users (username, password_hash, role, permissions, created_at) "
            "VALUES (?, ?, 'admin', '*', ?)",
            (ADMIN_USER_INIT, ADMIN_PASSWORD_HASH_INIT, int(time.time())),
        )
    conn.commit()
    conn.close()


init_db()


# ===== User helpers =====
def current_user():
    token = request.cookies.get(COOKIE_NAME, "")
    if not token:
        return None
    uid = parse_session(token)
    if uid is None:
        return None
    return db().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()


def user_allowed_routes(row):
    if row is None:
        return []
    if row["role"] == "admin" or row["permissions"] == "*":
        return [r["key"] for r in ROUTES]
    try:
        perms = set(json.loads(row["permissions"] or "[]"))
    except Exception:
        perms = set()
    allowed = (perms | ALWAYS_ALLOWED) - ADMIN_ONLY
    return [r["key"] for r in ROUTES if r["key"] in allowed]


def serialize_user(row):
    perms = "*" if row["permissions"] == "*" else json.loads(row["permissions"] or "[]")
    return {
        "id": row["id"], "username": row["username"], "role": row["role"],
        "permissions": perms, "created_at": row["created_at"],
        "role_locked": row["username"] == ADMIN_USER_INIT,
    }


def require_admin():
    u = current_user()
    if u is None: return None, ("", 401)
    if u["role"] != "admin":
        return None, (jsonify({"error": "Доступ запрещён"}), 403)
    return u, None


def require_route(key):
    u = current_user()
    if u is None: return None, ("", 401)
    if key not in set(user_allowed_routes(u)):
        return None, (jsonify({"error": "Доступ запрещён"}), 403)
    return u, None


# ===== Auth endpoints =====
@app.get("/_auth/verify")
def verify_endpoint():
    return ("", 204) if current_user() else ("", 401)


@app.post("/api/login")
def login():
    data = request.get_json(silent=True) or request.form
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    row = db().execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if not row or not verify_password(password, row["password_hash"]):
        return jsonify({"error": "Неверный логин или пароль"}), 401
    token = sign_session(row["id"])
    resp = make_response(jsonify({"ok": True}))
    resp.set_cookie(COOKIE_NAME, token, max_age=SESSION_TTL, httponly=True, samesite="Lax", path="/")
    return resp


@app.post("/api/logout")
def logout():
    resp = make_response(jsonify({"ok": True}))
    resp.delete_cookie(COOKIE_NAME, path="/")
    return resp


@app.get("/api/me")
def me():
    u = current_user()
    if u is None: return "", 401
    data = serialize_user(u)
    data["allowed_routes"] = user_allowed_routes(u)
    return jsonify(data)


@app.get("/api/routes")
def routes_endpoint():
    if current_user() is None: return "", 401
    return jsonify({"routes": ROUTES, "assignable": ASSIGNABLE})


# ===== Users CRUD =====
@app.get("/api/users")
def list_users():
    _, err = require_admin()
    if err: return err
    rows = db().execute(
        "SELECT id, username, role, permissions, created_at FROM users ORDER BY id"
    ).fetchall()
    return jsonify({"users": [serialize_user(r) for r in rows]})


@app.post("/api/users")
def create_user():
    _, err = require_admin()
    if err: return err
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    role = data.get("role") or "user"
    perms_in = data.get("permissions") or []

    if len(username) < 2:
        return jsonify({"error": "Логин должен быть не короче 2 символов"}), 400
    if len(password) < 6:
        return jsonify({"error": "Пароль должен быть не короче 6 символов"}), 400
    if role not in ("admin", "user"):
        return jsonify({"error": "Недопустимая роль"}), 400

    if role == "admin":
        perms_stored = "*"
    else:
        if not isinstance(perms_in, list):
            return jsonify({"error": "permissions должен быть массивом"}), 400
        filtered = [p for p in perms_in if p in ROUTE_KEYS and p in ASSIGNABLE]
        perms_stored = json.dumps(filtered)

    try:
        cur = db().execute(
            "INSERT INTO users (username, password_hash, role, permissions, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (username, hash_password(password), role, perms_stored, int(time.time())),
        )
        db().commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "Пользователь с таким логином уже существует"}), 409

    row = db().execute("SELECT * FROM users WHERE id = ?", (cur.lastrowid,)).fetchone()
    return jsonify(serialize_user(row)), 201


@app.patch("/api/users/<int:uid>")
def update_user(uid):
    actor, err = require_admin()
    if err: return err
    target = db().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    if target is None:
        return jsonify({"error": "Пользователь не найден"}), 404

    data = request.get_json(silent=True) or {}
    sets, args = [], []

    if data.get("password"):
        if target["username"] == ADMIN_USER_INIT:
            return jsonify({"error": "Пароль учётной записи admin меняется только через .env"}), 400
        pw = data["password"]
        if len(pw) < 6:
            return jsonify({"error": "Пароль должен быть не короче 6 символов"}), 400
        sets.append("password_hash = ?"); args.append(hash_password(pw))

    new_role = target["role"]
    if "role" in data:
        new_role = data["role"]
        if new_role not in ("admin", "user"):
            return jsonify({"error": "Недопустимая роль"}), 400
        if target["username"] == ADMIN_USER_INIT and new_role != "admin":
            return jsonify({"error": "Роль учётной записи admin изменить нельзя"}), 400
        if target["id"] == actor["id"] and new_role != "admin":
            n = db().execute("SELECT COUNT(*) FROM users WHERE role='admin'").fetchone()[0]
            if n <= 1:
                return jsonify({"error": "Нельзя понизить единственного администратора"}), 400
        sets.append("role = ?"); args.append(new_role)

    if "permissions" in data or "role" in data:
        if new_role == "admin":
            sets.append("permissions = ?"); args.append("*")
        else:
            perms_in = data.get("permissions", [])
            if not isinstance(perms_in, list):
                return jsonify({"error": "permissions должен быть массивом"}), 400
            filtered = [p for p in perms_in if p in ROUTE_KEYS and p in ASSIGNABLE]
            sets.append("permissions = ?"); args.append(json.dumps(filtered))

    if not sets:
        return jsonify(serialize_user(target))

    args.append(uid)
    db().execute(f"UPDATE users SET {', '.join(sets)} WHERE id = ?", args)
    db().commit()
    row = db().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    return jsonify(serialize_user(row))


@app.delete("/api/users/<int:uid>")
def delete_user(uid):
    actor, err = require_admin()
    if err: return err
    if uid == actor["id"]:
        return jsonify({"error": "Нельзя удалить самого себя"}), 400
    target = db().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    if target is None:
        return jsonify({"error": "Пользователь не найден"}), 404
    if target["username"] == ADMIN_USER_INIT:
        return jsonify({"error": "Учётную запись admin удалить нельзя"}), 400
    if target["role"] == "admin":
        n = db().execute("SELECT COUNT(*) FROM users WHERE role='admin'").fetchone()[0]
        if n <= 1:
            return jsonify({"error": "Нельзя удалить единственного администратора"}), 400
    db().execute("DELETE FROM users WHERE id = ?", (uid,))
    db().commit()
    return jsonify({"ok": True})


# ===== MSSQL + operation parsing =====
STATUS_LABELS = {
    1: "Created (Создана)",
    2: "Accepted (Принят)",
    3: "Confirmed (Подтверждён)",
    4: "Completed (Успешна)",
    5: "Corrupted (Повреждён)",
    6: "Failed (Неуспешен)",
    7: "Canceled (Отменён)",
}
# Статусы из USDB.dbo.Transfer.Transfer_Status
USDB_STATUS_LABELS = {
    40: "40 (Принят)",
    50: "50 (Выдан)",
    60: "60 (Отозван)",
    65: "65 (Аннулирован)",
}
STATUS_WAIT = {1, 2, 3}
STATUS_OK = {4}
# всё остальное (5, 6, 7 и неизвестные) — ошибочные/завершённые не успехом
CURRENCY_SIGNS = {"RUB": "₽", "USD": "$", "EUR": "€", "KZT": "₸", "TJS": "SM"}


_DB_SETTINGS_KEYS = ("host", "port", "database", "user", "password")


# ===== Шифрование чувствительных значений at-rest =====
_FERNET_INSTANCE = None


def _load_or_create_encryption_key():
    """Ключ берём из env SETTINGS_ENCRYPTION_KEY (предпочтительно),
    иначе автоматически генерируем и кладём в файл с правами 600.
    Файл-с-ключом должен лежать на томе, к которому есть доступ только у процесса.
    Идеально — вынести в env / Docker secret и удалить файл."""
    env_key = (os.environ.get("SETTINGS_ENCRYPTION_KEY") or "").strip()
    if env_key:
        return env_key.encode("ascii")
    try:
        with open(SETTINGS_KEY_PATH, "rb") as f:
            return f.read().strip()
    except FileNotFoundError:
        key = Fernet.generate_key()
        os.makedirs(os.path.dirname(SETTINGS_KEY_PATH) or ".", exist_ok=True)
        with open(SETTINGS_KEY_PATH, "wb") as f:
            f.write(key)
        try:
            os.chmod(SETTINGS_KEY_PATH, 0o600)
        except Exception:
            pass
        app.logger.warning(
            "Generated new encryption key at %s. For production move it to env "
            "SETTINGS_ENCRYPTION_KEY (Docker secret) and delete the file.",
            SETTINGS_KEY_PATH,
        )
        return key


def _fernet():
    global _FERNET_INSTANCE
    if _FERNET_INSTANCE is None:
        _FERNET_INSTANCE = Fernet(_load_or_create_encryption_key())
    return _FERNET_INSTANCE


def encrypt_secret(plaintext):
    if not plaintext:
        return ""
    if isinstance(plaintext, str) and plaintext.startswith(ENC_PREFIX):
        return plaintext  # уже зашифровано
    token = _fernet().encrypt(str(plaintext).encode("utf-8")).decode("ascii")
    return ENC_PREFIX + token


def decrypt_secret(stored):
    if not stored:
        return ""
    if not isinstance(stored, str) or not stored.startswith(ENC_PREFIX):
        # plaintext-формат (legacy) — вернём как есть, мигрируется при следующем сохранении
        return stored
    try:
        return _fernet().decrypt(stored[len(ENC_PREFIX):].encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError, Exception) as e:
        app.logger.error("Failed to decrypt stored secret: %s", e)
        return ""


DB_CONNECTIONS_SPEC = [
    {
        "key": "cpl",
        "title": "CPL — Статусы операций",
        "subtitle": "Поиск операций по КНП (таблица OperationModel).",
        "defaults": {},
    },
    {
        "key": "usdb",
        "title": "USDB",
        "subtitle": "Дополнительные проверки по операциям.",
        "defaults": {
            "host": "USDB-RC.uniservers.ru",
            "user": "unistream.processing.integration",
        },
    },
]
DB_CONNECTION_KEYS = [c["key"] for c in DB_CONNECTIONS_SPEC]
DB_CONNECTIONS_SPEC_MAP = {c["key"]: c for c in DB_CONNECTIONS_SPEC}


def _empty_conn():
    return {k: "" for k in _DB_SETTINGS_KEYS}


def _env_db_settings_for(name):
    """Читает env vars MSSQL_<NAME>_HOST / _PORT / _DATABASE / _USER / _PASSWORD.
    Для обратной совместимости cpl дополнительно подхватывает старые MSSQL_*
    без префикса (если новые с префиксом не заданы)."""
    prefix = f"MSSQL_{name.upper()}_"
    s = {
        "host":     (os.environ.get(prefix + "HOST") or "").strip(),
        "port":     (os.environ.get(prefix + "PORT") or "").strip(),
        "database": (os.environ.get(prefix + "DATABASE") or "").strip(),
        "user":     (os.environ.get(prefix + "USER") or "").strip(),
        "password":  os.environ.get(prefix + "PASSWORD") or "",
    }
    if name == "cpl":
        legacy = {
            "host":     (os.environ.get("MSSQL_HOST") or "").strip(),
            "port":     (os.environ.get("MSSQL_PORT") or "").strip(),
            "database": (os.environ.get("MSSQL_DATABASE") or "").strip(),
            "user":     (os.environ.get("MSSQL_USER") or "").strip(),
            "password":  os.environ.get("MSSQL_PASSWORD") or "",
        }
        # MSSQL_CPL_* перекрывает legacy MSSQL_*
        for k, v in legacy.items():
            if v and not s[k]:
                s[k] = v
    return s


def _load_raw_db_settings():
    """Сырое содержимое файла; миграция со старой плоской схемы → {'cpl': {...}}."""
    try:
        with open(DB_SETTINGS_PATH, "r", encoding="utf-8") as f:
            saved = json.load(f) or {}
    except FileNotFoundError:
        return {}
    except Exception:
        app.logger.warning("Failed to read %s", DB_SETTINGS_PATH, exc_info=True)
        return {}
    if any(k in saved for k in _DB_SETTINGS_KEYS) and "cpl" not in saved:
        saved = {"cpl": {k: saved.get(k, "") for k in _DB_SETTINGS_KEYS}}
    return saved


def load_db_connection(name):
    """Эффективные настройки одного подключения: spec defaults < env < файл."""
    conn = _empty_conn()
    spec = DB_CONNECTIONS_SPEC_MAP.get(name) or {}
    for k, v in (spec.get("defaults") or {}).items():
        if v:
            conn[k] = v
    for k, v in _env_db_settings_for(name).items():
        if v:
            conn[k] = v
    saved = _load_raw_db_settings().get(name) or {}
    for k in _DB_SETTINGS_KEYS:
        v = saved.get(k)
        if v is not None:
            conn[k] = str(v)
    # Расшифровываем пароль (если он сохранён зашифрованным).
    if conn.get("password"):
        conn["password"] = decrypt_secret(conn["password"])
    return conn


def save_db_connection(name, data):
    raw = _load_raw_db_settings()
    payload = {k: str(data.get(k, "")) for k in _DB_SETTINGS_KEYS}
    # Шифруем пароль перед записью на диск.
    if payload["password"]:
        payload["password"] = encrypt_secret(payload["password"])
    raw[name] = payload
    os.makedirs(os.path.dirname(DB_SETTINGS_PATH) or ".", exist_ok=True)
    tmp = DB_SETTINGS_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(raw, f, ensure_ascii=False, indent=2)
    os.replace(tmp, DB_SETTINGS_PATH)
    try:
        os.chmod(DB_SETTINGS_PATH, 0o600)
    except Exception:
        pass


def migrate_db_settings_encryption():
    """Один раз при старте: переписать существующие plaintext-пароли в зашифрованные."""
    raw = _load_raw_db_settings()
    if not raw:
        return
    changed = False
    for name, conn in raw.items():
        pwd = (conn or {}).get("password")
        if pwd and not (isinstance(pwd, str) and pwd.startswith(ENC_PREFIX)):
            conn["password"] = encrypt_secret(pwd)
            changed = True
    if changed:
        tmp = DB_SETTINGS_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(raw, f, ensure_ascii=False, indent=2)
        os.replace(tmp, DB_SETTINGS_PATH)
        try:
            os.chmod(DB_SETTINGS_PATH, 0o600)
        except Exception:
            pass
        app.logger.info("Migrated %s: plaintext passwords encrypted at rest", DB_SETTINGS_PATH)


def mssql_configured(name="cpl"):
    s = load_db_connection(name)
    return bool(s["host"] and s["user"] and s["password"] and s["database"])


def get_usdb_status(knp):
    """Возвращает (kind, text) для поля «Статус в главной базе» по КНП.
    kind ∈ {'ok', 'not_found', 'not_configured', 'error'}.
    'not_configured' и 'error' = USDB недоступна; 'ok'/'not_found' = соединение есть."""
    if not knp:
        return ("error", "—")
    if not mssql_configured("usdb"):
        return ("not_configured", "USDB не настроена")
    try:
        conn = mssql_connect("usdb")
    except Exception as e:
        app.logger.warning("USDB connect failed: %s", e)
        return ("error", f"ошибка подключения к USDB: {e}")
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT TOP 1 [Transfer_Status] "
            "FROM [USDB].[dbo].[Transfer] "
            "WHERE Alter_Control = %s",
            (str(knp),),
        )
        row = cur.fetchone()
    except Exception as e:
        app.logger.warning("USDB query failed for %s: %s", knp, e)
        return ("error", f"ошибка запроса в USDB: {e}")
    finally:
        try: conn.close()
        except Exception: pass
    if not row:
        return ("not_found", "не найдено в USDB")
    code = row[0]
    try:
        code_int = int(code)
    except Exception:
        return ("ok", f"Код {code}")
    return ("ok", USDB_STATUS_LABELS.get(code_int, f"Код {code_int}"))


def get_usdb_status_text(knp):
    """Wrapper для совместимости — отдаёт только текст."""
    return get_usdb_status(knp)[1]


def mssql_connect(name="cpl"):
    if pymssql is None:
        raise RuntimeError("pymssql не установлен в контейнере")
    s = load_db_connection(name)
    kwargs = dict(
        server=s["host"],
        user=s["user"], password=s["password"], database=s["database"],
        login_timeout=5, timeout=15, charset="UTF-8",
    )
    if s["port"]:
        kwargs["port"] = int(s["port"])
    return pymssql.connect(**kwargs)


def format_money(value, _currency=None):
    if value is None:
        return None
    try:
        v = float(value)
    except Exception:
        return str(value)
    return str(int(v)) if v == int(v) else f"{v:.2f}"


def format_regdate(s):
    if not s:
        return None
    try:
        return datetime.strptime(s, "%d.%m.%Y_%H:%M:%S").strftime("%d.%m.%Y %H:%M:%S")
    except Exception:
        return s


def format_iso_dt(s):
    """Parse ISO datetime like '2026-04-16T20:17:31.6548848[+03:00]' → '16.04.2026 20:17:31'."""
    if not s:
        return None
    try:
        raw = s.strip()
        # Strip trailing TZ (we display local wall time)
        for sep in ("+", "Z"):
            idx = raw.find(sep, 10)
            if idx > 0:
                raw = raw[:idx]
                break
        # Trim fractional seconds to ≤6 digits (Python datetime limit)
        if "." in raw:
            head, frac = raw.split(".", 1)
            raw = head + "." + frac[:6]
        dt = datetime.fromisoformat(raw)
        return dt.strftime("%d.%m.%Y %H:%M:%S")
    except Exception:
        return s


def _coalesce_json(val):
    """Return parsed JSON object, accepting either dict or JSON string."""
    if val is None:
        return {}
    if isinstance(val, (dict, list)):
        return val
    if isinstance(val, (bytes, bytearray)):
        val = val.decode("utf-8", errors="replace")
    if isinstance(val, str) and val:
        try:
            return json.loads(val)
        except Exception:
            return {}
    return {}


def parse_operation(row):
    """row: dict with columns Id, AlterControl, Date, Status, OperationType, AgentId,
    PointOfServiceId, JsonData. JsonData — whole record as JSON string."""
    data = _coalesce_json(row.get("JsonData"))
    status = row.get("Status") if row.get("Status") is not None else data.get("Status")
    op_type = row.get("OperationType") or data.get("OperationType")
    iv = _coalesce_json(data.get("InputValues"))
    ov = _coalesce_json(data.get("OperationValues"))
    custom = ov.get("Custom") or {}
    params = custom.get("Parameters") or {}

    result = {
        "knp": row.get("AlterControl") or data.get("AlterControl"),
        "status_code": status,
        "status_label": STATUS_LABELS.get(status, f"Код {status}"),
        "status_ok": status == 4,
        "operation_type": op_type,
        "supported": False,
        "sections": [],
    }

    if op_type not in ("PhoneTransfer", "SbpTransfer", "Arca", "Compass_Mir"):
        result["message"] = f"Тип операции «{op_type}» пока не поддерживается."
        return result

    gate = iv.get("gate")
    integration = iv.get("Integration")
    if op_type == "SbpTransfer" and not gate:
        gate = "sbp"  # synthetic gate для СБП C2C (PaymentType="sbp", без поля gate)
    if op_type == "Arca" and not gate:
        gate = "arca"  # synthetic gate для пополнения карт через KWIKPAY (Армения)
    if op_type == "Compass_Mir" and not gate:
        gate = "compass"  # synthetic gate для пополнения карт МИР через КомпассПлюс
    SUPPORTED_GATES = ("unigate", "alif", "sbpb2c", "expresspay", "sbp", "arca", "compass")
    if gate not in SUPPORTED_GATES:
        result["message"] = f"Шлюз «{gate}» пока не поддерживается."
        result["gate"] = gate
        result["integration"] = integration
        return result

    result["supported"] = True
    result["gate"] = gate
    # У alif параметр Integration пустой — партнёром считаем сам шлюз (или BankName)
    partner = integration or iv.get("BankName") or gate
    result["integration"] = partner

    # Дата операции — момент создания операции у нас (Москва), top-level Date
    op_date = (format_iso_dt(row.get("Date"))
               or format_iso_dt(data.get("Date")) or "—")

    def find_bank_name(bank_id):
        if bank_id is None:
            return None
        for key in ("SenderBank", "SenderAgentBank", "RecipientBank", "RecipientAgentBank"):
            b = ov.get(key) or {}
            if b.get("Id") == bank_id:
                return b.get("Name") or b.get("ShortName")
        return None

    def with_name(id_value, name):
        if id_value is None:
            return "—"
        return f"{id_value} {name}" if name else str(id_value)

    agent_id = row.get("AgentId") if row.get("AgentId") is not None else data.get("AgentId")
    pos_id = row.get("PointOfServiceId") if row.get("PointOfServiceId") is not None else data.get("PointOfServiceId")
    accepted_currency = iv.get("AcceptedCurrency") or iv.get("FeeCurrency")
    withdraw_currency = iv.get("WithdrawCurrency") or accepted_currency
    fee_currency = iv.get("FeeCurrency") or accepted_currency
    total_fee = ov.get("AcceptedTotalFeeAmount")
    if total_fee is None:
        total_fee = params.get("AcceptedTotalFee")

    sender_rows = [
        ["Статус в CP",             result["status_label"]],
        ["Статус в ПОЮ",            get_usdb_status_text(result["knp"])],
        ["Тип операции",            op_type],
    ]
    if gate not in ("arca", "compass"):
        sender_rows += [
            ["Шлюз",            gate],
            ["Партнёр",         partner or "—"],
        ]
    sender_rows += [
        ["Страна получения",   iv.get("Country") or iv.get("CardCountryCode") or ("RUS" if gate == "sbp" else "—")],
        ["Банк-отправитель",   with_name(agent_id, find_bank_name(agent_id))],
        ["Точка-отправитель",  with_name(pos_id,   find_bank_name(pos_id))],
    ]
    recipient_name = (custom.get("RecipientDisplayName")
                      or (custom.get("UniGateCheckResponse") or {}).get("FIO")
                      or "—")
    if isinstance(recipient_name, str):
        recipient_name = recipient_name.strip() or "—"

    rows = [
        ["Дата операции",      op_date],
        ["КНП",                result["knp"] or "—"],
        ["Отправитель",        (iv.get("Sender") or {}).get("FullName") or "—"],
    ]
    if gate in ("arca", "compass"):
        rec = ov.get("Recipient") or {}
        card_recipient = (iv.get("CardEnprintedName")
                          or " ".join(filter(None, [rec.get("LastName"), rec.get("FirstName"), rec.get("MiddleName")])).strip()
                          or "—")
        rows.append(["Получатель на карте", card_recipient])
        rows.append(["Карта",              iv.get("MaskedCardNumber") or "—"])
    else:
        if integration not in ("VASL", "oriyonbonk", "arvand", "vtb", "telcell", "spitamenbank", "ibt", "matin", "amonat") and gate not in ("expresspay", "sbp"):
            rows.append(["Получатель", recipient_name])
        rows.append(["Телефон получателя", iv.get("PhoneNumber") or "—"])
    rows += [
        ["Сумма принята",      format_money(ov.get("AcceptedAmount"), accepted_currency) or "—"],
        ["Сумма к выдаче",     format_money(iv.get("Amount"), withdraw_currency) or "—"],
        ["Комиссия",           (lambda v: "" if v in (None, "0", "0.00") else v)(format_money(total_fee, fee_currency))],
    ]
    if gate == "alif":
        txnid = custom.get("txnid") or params.get("txnid")
        if txnid:
            rows.append(["txnid", str(txnid)])
    elif gate == "sbpb2c":
        sbp_id = (params.get("SbpOperationId")
                  or custom.get("SbpOperationId")
                  or ov.get("SbpOperationId") or "—")
        rows.append(["Код платежа в СБП", str(sbp_id)])
    elif gate == "sbp":
        sbp_id = (custom.get("PaymentId")
                  or ov.get("PaymentId") or "—")
        rows.append(["Код платежа в СБП", str(sbp_id)])
        rrn = (ov.get("BpcTransactionData") or {}).get("Rrn")
        if rrn:
            rows.append(["RRN", str(rrn)])
    elif gate == "expresspay":
        pass  # expresspay не получает строку с id операции
    elif gate in ("arca", "compass"):
        partner_op_id = (params.get("ProviderPaymentId")
                         or ov.get("ProviderPaymentId")
                         or params.get("G3RequestId") or "—")
        rows.append(["Id операции у партнёра", str(partner_op_id)])
    else:  # all unigate get the partner-id row
        partner_op_id = (params.get("G3RequestId")
                         or params.get("UniGateRequestId")
                         or data.get("Id") or row.get("Id") or "—")
        rows.append(["Id операции у партнёра", str(partner_op_id)])

    result["sender_rows"] = sender_rows
    result["rows"] = rows

    partner_hint = None
    if integration == "eskhata":
        partner_hint = ("Если нужно уточнить статус на стороне партнёра, "
                        "напишите запрос в Telegram-канал с партнером «Эсхата Банк-Юнистрим Банк».")
    elif integration == "VASL":
        partner_hint = ("Если нужно уточнить статус и получить чек подтверждения на стороне партнёра, "
                        "напишите запрос в Telegram-канал с партнером «Юнистрим - Васл (проверка статуса платежа)».")
    elif integration == "oriyonbonk":
        partner_hint = ("Если нужно уточнить статус на стороне партнёра, "
                        "напишите запрос в Telegram-канал с партнером «ОРИЁНБАНК - ЮНИСТРИМ (переводы по номеру телефона)».")
    elif integration == "arvand":
        partner_hint = ("Если нужно уточнить статус на стороне партнёра, "
                        "напишите запрос в Telegram-канал с партнером «Юнистрим - Арванд (переводы на карты и номеру телефона)».")
    elif integration == "vtb":
        partner_hint = ("Если нужно уточнить статус на стороне партнёра, "
                        "напишите запрос в Telegram-канал с партнером «ВТБ Армения Юни (Тех.Группа)».")
    elif integration == "telcell":
        partner_hint = ("Если нужно уточнить статус на стороне партнёра, "
                        "напишите запрос в Telegram-канал с партнером «Unistream-Telcell phone trans».")
    elif integration == "spitamenbank":
        partner_hint = ("Если нужно уточнить статус на стороне партнёра, "
                        "напишите запрос в Telegram-канал с партнером «Юнистрим - Спитамен (интеграция по номеру телефона)».")
    elif integration == "ibt":
        partner_hint = ("Если нужно уточнить статус на стороне партнёра, "
                        "напишите запрос в Telegram-канал с партнером «IBT - Юнистрим».")
    elif integration == "matin":
        partner_hint = ("Если нужно уточнить статус на стороне партнёра, "
                        "напишите запрос в Telegram-канал с партнером «Юнистрим - Matin».")
    elif integration == "amonat":
        partner_hint = ("Если нужно уточнить статус на стороне партнёра, "
                        "напишите запрос в Telegram-канал с партнером «Амонатбанк - Юнистрим (Перевод по номеру телефона)».")
    elif gate == "alif":
        partner_hint = ("Если нужно уточнить статус и RRN на стороне партнёра, "
                        "напишите запрос в Telegram-канал с партнером «ЮНИСТРИМ - АЛИФ».")
    elif gate in ("sbpb2c", "sbp"):
        partner_hint = ("Если нужно уточнить статус на стороне партнёра, "
                        "оформите запрос в Диспуте.")
    elif gate == "arca":
        partner_hint = ("Если нужно уточнить статус на стороне партнёра, "
                        "смотрите в Реестре Arca — проверять по дате и времени "
                        "(время Армении +1 час от МСК), маске карты и сумме.")
    elif gate == "expresspay":
        partner_hint = ("Если нужно уточнить статус на стороне партнёра, "
                        "отправьте КНП в Telegram-бот @dc_getstatus_bot или на почту bakhtiyor@dc.tj")

    if status == 4:
        tone = "ok"
    elif status in (1, 2, 3):
        tone = "wait"
    else:
        tone = "err"

    error_msg = ov.get("ErrorMessage")
    events = data.get("Events") or []
    last_event = events[-1] if events else {}
    op_originator = (last_event.get("Originator") or "").strip()
    op_ticket = (last_event.get("Comment") or "").strip()
    op_login = op_originator.split("\\", 1)[1] if "\\" in op_originator else op_originator
    operator_cancelled = bool(op_login) and last_event.get("Status") in (5, 6, 7)

    status_line = [
        {"text": "На нашей стороне платеж в статусе «"},
        {"text": result["status_label"], "tone": tone},
        {"text": "»."},
    ]

    if status != 4 and (error_msg or operator_cancelled):
        plate_lines = [status_line]
        if error_msg:
            prefix = "Ошибка на шаге создания платежа в БПЦ: «" if "БПЦ" in error_msg else "Ошибка: «"
            plate_lines.append([
                {"text": prefix},
                {"text": error_msg},
                {"text": "»."},
            ])
        bpc_err = ov.get("BpcErrorMessage")
        if bpc_err:
            plate_lines.append([
                {"text": "Ответ БПЦ: "},
                {"text": str(bpc_err), "code": True},
                {"text": "."},
            ])
        if operator_cancelled:
            cancel = [
                {"text": "Операция закрыта вручную оператором "},
                {"text": op_login, "code": True},
            ]
            if op_ticket:
                cancel += [
                    {"text": " по тикету "},
                    {"text": op_ticket, "code": True},
                ]
            cancel.append({"text": "."})
            plate_lines.append(cancel)
        result["info_notes"] = [{
            "title": "Статус операции",
            "tone": "err" if status in (5, 6, 7) else "wait",
            "lines": plate_lines,
        }]
    elif partner_hint:
        plate_lines = [status_line]
        note = {"title": "Статус операции", "lines": plate_lines}
        if result["status_ok"]:
            note["title"] = "Уточнение статуса у партнёра"
            plate_lines.append([{"text": partner_hint}])
            # TG-шаблон — только если есть кому отправлять.
            # Для arca (поиск в реестре, никому не пишем) шаблон не нужен.
            if gate != "arca":
                if gate in ("sbpb2c", "sbp"):
                    tg_intro = "Коллеги, прошу уточнить статус платежа в Диспуте:"
                else:
                    tg_intro = "Коллеги, прошу уточнить статус платежа на вашей стороне:"
                tg_lines = [tg_intro]
                for k, v in rows:
                    tg_lines.append(f"{k}: {v}")
                note["tg_template"] = "\n".join(tg_lines)
        result["info_notes"] = [note]

    return result


# ===== Operation lookup endpoint =====
@app.get("/api/operations/lookup")
def op_lookup():
    _, err = require_route("operations")
    if err: return err
    knp = (request.args.get("knp") or "").strip()
    if not knp:
        return jsonify({"error": "Укажите номер КНП"}), 400
    if not knp.isdigit() or len(knp) > 20:
        return jsonify({"error": "КНП должен состоять только из цифр (до 20 знаков)"}), 400

    cpl_message = None
    cpl_unreachable = False  # True для config/connect/query-проблем (НЕ для «нет записи»)
    parsed = None

    if not mssql_configured("cpl"):
        cpl_unreachable = True
        cpl_message = "CPL не настроена — заполните параметры подключения в разделе «Подключение к БД»."
    else:
        row = None
        try:
            conn = mssql_connect("cpl")
        except Exception as e:
            app.logger.warning("CPL connect failed: %s", e)
            cpl_unreachable = True
            cpl_message = f"Не удалось подключиться к CPL: {e}"
        else:
            try:
                cur = conn.cursor(as_dict=True)
                cur.execute(
                    "SELECT TOP 1 [AlterControl], [JsonData] "
                    "FROM [dbo].[OperationModel] "
                    "WHERE [AlterControl] = %s "
                    "ORDER BY [Id] DESC",
                    (knp,),
                )
                row = cur.fetchone()
            except Exception as e:
                app.logger.warning("CPL query failed: %s", e)
                cpl_unreachable = True
                cpl_message = f"Ошибка запроса в CPL: {e}"
            finally:
                try: conn.close()
                except Exception: pass

        if row and not cpl_message:
            try:
                parsed = parse_operation(row)
            except Exception as e:
                app.logger.exception("Parse error")
                cpl_message = f"Ошибка разбора JsonData из CPL: {e}"
        elif not cpl_message:
            cpl_message = f"В CPL.OperationModel нет записи с AlterControl = {knp}."

    usdb_kind, usdb_text = get_usdb_status(knp)
    usdb_unreachable = usdb_kind in ("not_configured", "error")

    # Обе базы недоступны — карточку не показываем, отдаём 503-ошибку.
    if parsed is None and cpl_unreachable and usdb_unreachable:
        return jsonify({
            "status": "db_unreachable",
            "error": "Не удалось соединиться с CPL и USDB. Проверьте настройки в разделе «Подключение к БД».",
        }), 503

    # CPL не дала карточку, но USDB жива — собираем минимальный «обрубок»
    # с тем, что есть из USDB, и сообщением про CPL.
    if parsed is None:
        parsed = {
            "knp": knp,
            "status_code": None,
            "status_label": "—",
            "status_ok": False,
            "operation_type": None,
            "supported": False,
            "message": cpl_message,
            "sender_rows": [
                ["Статус в CP",  "—"],
                ["Статус в ПОЮ", usdb_text],
            ],
            "rows": [
                ["КНП", knp],
            ],
        }
    elif usdb_unreachable:
        # CPL дала полную карточку, но USDB сейчас недоступна —
        # покажем плашку, чтобы кассир видел, что «Статус в главной базе» не достоверен.
        parsed["message"] = ("USDB сейчас недоступна — поле «Статус в ПОЮ» "
                             "получить не удалось. Данные ниже — только из CPL.")

    return jsonify({"status": "ok", "result": parsed})


# ===== DB connection settings (admin) =====
@app.get("/api/db/settings")
def api_db_settings_get():
    _, err = require_admin()
    if err: return err
    out = []
    for spec in DB_CONNECTIONS_SPEC:
        s = load_db_connection(spec["key"])
        out.append({
            "key":          spec["key"],
            "title":        spec["title"],
            "subtitle":     spec.get("subtitle", ""),
            "host":         s["host"],
            "port":         s["port"],
            "database":     s["database"],
            "user":         s["user"],
            "password":     "",
            "password_set": bool(s["password"]),
            "configured":   mssql_configured(spec["key"]),
        })
    return jsonify({"connections": out})


@app.post("/api/db/settings")
def api_db_settings_post():
    _, err = require_admin()
    if err: return err
    body = request.get_json(silent=True) or {}
    name = (body.get("name") or "").strip()
    if name not in DB_CONNECTION_KEYS:
        return jsonify({"error": "Неизвестное подключение"}), 400
    host     = (body.get("host") or "").strip()
    port     = (body.get("port") or "").strip()
    database = (body.get("database") or "").strip()
    user     = (body.get("user") or "").strip()
    password = body.get("password")
    if password is None:
        password = ""
    if port and not port.isdigit():
        return jsonify({"error": "Порт должен быть числом"}), 400
    if not password:
        password = load_db_connection(name)["password"]
    save_db_connection(name, {
        "host": host, "port": port,
        "database": database, "user": user, "password": password,
    })
    return jsonify({"status": "ok"})


@app.post("/api/db/test")
def api_db_test():
    _, err = require_admin()
    if err: return err
    body = request.get_json(silent=True) or {}
    name = (body.get("name") or "cpl").strip()
    if name not in DB_CONNECTION_KEYS:
        return jsonify({"status": "fail", "error": "Неизвестное подключение"})
    if not mssql_configured(name):
        return jsonify({
            "status": "fail",
            "error": "Не заполнены HOST / DATABASE / USER / PASSWORD",
        })
    try:
        conn = mssql_connect(name)
        try:
            cur = conn.cursor()
            cur.execute("SELECT 1")
            cur.fetchone()
        finally:
            try: conn.close()
            except Exception: pass
        return jsonify({"status": "ok"})
    except Exception as e:
        return jsonify({"status": "fail", "error": str(e)})


@app.get("/healthz")
def healthz():
    return "ok\n", 200


# При старте: убедиться, что все сохранённые пароли БД лежат в зашифрованном виде.
try:
    migrate_db_settings_encryption()
except Exception:
    app.logger.exception("DB settings encryption migration failed")
