import base64
import hashlib
import hmac
import json
import os
import re
import sqlite3
import time
from datetime import datetime

from flask import Flask, g, jsonify, make_response, request

try:
    import pymssql
except Exception:
    pymssql = None

try:
    import winrm
except Exception:
    winrm = None

try:
    import requests
    from requests_ntlm import HttpNtlmAuth
except Exception:
    requests = None
    HttpNtlmAuth = None

try:
    import paramiko
except Exception:
    paramiko = None

import shlex
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed

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
    {"key": "services",      "title": "Службы",            "group": "main"},
    {"key": "Balancer",      "title": "Балансировка",      "group": "main"},
    {"key": "stunnel",       "title": "Stunnel",           "group": "main"},
    {"key": "users",            "title": "Пользователи",         "group": "settings", "admin_only": True},
    {"key": "db_connection",    "title": "Подключение к БД",     "group": "settings"},
    {"key": "ms_catalog",       "title": "Каталог микросервисов","group": "settings"},
    {"key": "nodes_catalog",    "title": "Каталог нод для микросервисов", "group": "settings"},
    {"key": "api_settings",     "title": "Настройка API",         "group": "settings"},
    {"key": "balancer_creds",   "title": "Учётки",                 "group": "settings"},
    {"key": "about",            "title": "О программе",          "group": "settings"},
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


# ===== Microservices catalog seed =====
# (имя сервиса, список путей nginx-конфига, ноды). Если paths пуст — сервис не балансируется.
_NODES_GATE = ["sr-itlgate101", "sr-itlgate102", "sr-itlgate103", "sr-itlgate104"]
_NODES_ITL = [
    "sr-itl100", "sr-itl101", "sr-itl102", "sr-itl103", "sr-itl104", "sr-itl105",
    "sr-itl110", "sr-itl111", "sr-itl112", "sr-itl113", "sr-itl114", "sr-itl115",
]
_NODES_ITLR = ["sr-itlr100", "sr-itlr101", "sr-itlr102", "sr-itlr103"]
_NODES_BTL  = ["sr-btlapp101"]

MS_CATALOG_SEED = [
    # GATE
    ("Gates.GenericPayments",          ["/etc/nginx/conf.d/prod.gpg.conf"], _NODES_GATE),
    ("Gates.RussianStandardBank",      [], _NODES_GATE),
    ("Gates.TinkoffCreditSystems",     [], _NODES_GATE),
    ("Gates.UniversalPaymentTransfer", [], ["sr-itlgate101"]),
    ("MerchantApi",                    [], _NODES_GATE),
    ("PaySystem.CurrencyLots.Api",     [], ["sr-itlgate101"]),
    ("ProcessingGateService",          [], ["sr-itlgate101"]),
    ("Unistream.Gates.BpcGateway",     [], _NODES_GATE),
    ("Unistream.Intersystem.Sync",     [], ["sr-itlgate101"]),
    ("Unistream.Recognition.Gateway",  [], ["sr-itlgate101"]),
    # ITL
    ("Accounts",                            ["/etc/nginx/conf.d/prod.accounts.conf"],          _NODES_ITL),
    ("CashDesk.Backend",                    ["/etc/nginx/conf.d/prod.CashDeskBackendApi.conf"],_NODES_ITL),
    ("CashReportMaker",                     ["/etc/nginx/conf.d/prod.cashreportmaker.conf"],   _NODES_ITL),
    ("ControlPanel.Api",                    ["/etc/nginx/conf.d/prod.controlpanelapi.conf"],   _NODES_ITL),
    ("DocumentStore",                       ["/etc/nginx/conf.d/prod.documentstore.conf"],     _NODES_ITL),
    ("Gates.Flextera",                      [], _NODES_ITL),
    ("Gates.RiaGateway",                    [], _NODES_ITL),
    ("Integration.PaymentCenterModerator",  ["/etc/nginx/conf.d/prod.moderator.conf"],         _NODES_ITL),
    ("ListsApi",                            [], _NODES_ITL),
    ("OperationDefinitionStore",            ["/etc/nginx/conf.d/prod.definitions.conf"],       _NODES_ITL),
    ("Operations.Api",                      ["/etc/nginx/conf.d/prod.operationsapi.conf"],     _NODES_ITL),
    ("Operations.Callbacks",                [], _NODES_ITL),
    ("Operations.Catalog",                  ["/etc/nginx/conf.d/prod.operationscatalog.conf"], _NODES_ITL),
    ("Operations.Sagas",                    [], _NODES_ITL),
    ("PaymentCenterHooks.AntiFraud",        [], _NODES_ITL),
    ("Processing.AccountPaymentOrderApi",   [], _NODES_ITL),
    ("SequenceProviderApi",                 [], _NODES_ITL),
    ("TransferControlNumberGenerator",      [], _NODES_ITL),
    # CryptoApi есть и в GATE (на 101 и 103), и на всех ITL-нодах
    ("Unistream.CryptoApi",                 [], _NODES_ITL + ["sr-itlgate101", "sr-itlgate103"]),
    ("Unistream.FeeCalculationProviderApi", [
        "/etc/nginx/conf.d/prod.feecalculation-p1.conf",
        "/etc/nginx/conf.d/prod.feecalculation-p2.conf",
        "/etc/nginx/conf.d/prod.feecalculation-p3.conf",
        "/etc/nginx/conf.d/prod.feecalculation-p4.conf",
    ], _NODES_ITL),
    ("Unistream.Processing.Integration",    ["/etc/nginx/conf.d/prod.integration.conf"],       _NODES_ITL),
    ("Unistream.Processing.Operations",     [], _NODES_ITL),
    # ITLR
    ("CashDashboard",   [], ["sr-itlr100"]),
    ("Clients",         ["/etc/nginx/conf.d/prod.clients.conf"],         _NODES_ITLR),
    ("InfoApi",         ["/etc/nginx/conf.d/prod.infoApi.conf"],         _NODES_ITLR),
    ("Raven3",          [], _NODES_ITLR),
    ("SecurityManager", ["/etc/nginx/conf.d/prod.securitymanager.conf"], _NODES_ITLR),
    # BTL
    ("Messenger.Backend",   [], _NODES_BTL),
    ("SmsAndBonusAdapter",  [], _NODES_BTL),
]


# ===== Microservices: default nodes =====
# Группы и порядок дублируют MS_GROUPS на клиенте. Если клиент добавит/уберёт
# группу — синхронизируйте здесь. Сами ноды можно потом удалять/добавлять
# через UI, но при пустой БД эти подставятся как seed.
MS_GROUPS_WHITELIST = ("gate", "itl1", "itl2", "itlr", "btl")
MS_DEFAULT_NODES = [
    ("gate", "sr-itlgate101"),
    ("gate", "sr-itlgate102"),
    ("gate", "sr-itlgate103"),
    ("gate", "sr-itlgate104"),
    ("itl1", "sr-itl100"),
    ("itl1", "sr-itl101"),
    ("itl1", "sr-itl102"),
    ("itl1", "sr-itl103"),
    ("itl1", "sr-itl104"),
    ("itl1", "sr-itl105"),
    ("itl2", "sr-itl110"),
    ("itl2", "sr-itl111"),
    ("itl2", "sr-itl112"),
    ("itl2", "sr-itl113"),
    ("itl2", "sr-itl114"),
    ("itl2", "sr-itl115"),
    ("itlr", "sr-itlr100"),
    ("itlr", "sr-itlr101"),
    ("itlr", "sr-itlr102"),
    ("itlr", "sr-itlr103"),
    ("btl",  "sr-btlapp101"),
]


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
    conn.execute("""
        CREATE TABLE IF NOT EXISTS ms_console (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts INTEGER NOT NULL,
            level TEXT NOT NULL,
            message TEXT NOT NULL,
            username TEXT
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ms_console_id ON ms_console(id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ms_console_ts ON ms_console(ts)")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS ms_node_settings (
            node_key   TEXT PRIMARY KEY,
            host       TEXT,
            service    TEXT,
            updated_at INTEGER NOT NULL
        )
    """)
    existing_cols = {r[1] for r in conn.execute("PRAGMA table_info(ms_node_settings)").fetchall()}
    if 'group_key' not in existing_cols:
        conn.execute("ALTER TABLE ms_node_settings ADD COLUMN group_key TEXT")
    if 'position' not in existing_cols:
        conn.execute("ALTER TABLE ms_node_settings ADD COLUMN position INTEGER NOT NULL DEFAULT 0")
    if 'created_at' not in existing_cols:
        conn.execute("ALTER TABLE ms_node_settings ADD COLUMN created_at INTEGER NOT NULL DEFAULT 0")
    if 'role' not in existing_cols:
        conn.execute("ALTER TABLE ms_node_settings ADD COLUMN role TEXT")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ms_node_group ON ms_node_settings(group_key, position, node_key)")
    # Seed default nodes (idempotent: insert if missing, backfill group/position for legacy rows).
    _now = int(time.time())
    for _pos, (_gk, _nk) in enumerate(MS_DEFAULT_NODES):
        conn.execute(
            "INSERT OR IGNORE INTO ms_node_settings (node_key, group_key, position, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (_nk, _gk, _pos, _now, _now),
        )
        conn.execute(
            "UPDATE ms_node_settings SET group_key = ?, position = ? "
            "WHERE node_key = ? AND (group_key IS NULL OR group_key = '')",
            (_gk, _pos, _nk),
        )

    # Логи оркестратора
    conn.execute("""
        CREATE TABLE IF NOT EXISTS svc_console (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            ts        INTEGER NOT NULL,
            kind      TEXT NOT NULL,        -- 'action' | 'error'
            level     TEXT NOT NULL,        -- info | ok | warn | err
            message   TEXT NOT NULL,
            username  TEXT,
            run_id    TEXT
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_svc_console_id ON svc_console(id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_svc_console_ts ON svc_console(ts)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_svc_console_kind_id ON svc_console(kind, id)")

    # Глобальный замок оркестратора
    conn.execute("""
        CREATE TABLE IF NOT EXISTS svc_run_lock (
            id               INTEGER PRIMARY KEY CHECK (id = 1),
            run_id           TEXT,
            username         TEXT,
            action           TEXT,
            started_at       INTEGER,
            stopped_at       INTEGER,
            cancel_requested INTEGER NOT NULL DEFAULT 0
        )
    """)
    conn.execute("INSERT OR IGNORE INTO svc_run_lock (id) VALUES (1)")
    # Миграция: поля отсечки UI-лога для текущего прогона
    _lock_cols = {r[1] for r in conn.execute("PRAGMA table_info(svc_run_lock)").fetchall()}
    for _c, _ddl in [
        ("log_cutoff_action", "INTEGER NOT NULL DEFAULT 0"),
        ("log_cutoff_error",  "INTEGER NOT NULL DEFAULT 0"),
        ("progress_done",     "INTEGER NOT NULL DEFAULT 0"),
        ("progress_total",    "INTEGER NOT NULL DEFAULT 0"),
    ]:
        if _c not in _lock_cols:
            conn.execute(f"ALTER TABLE svc_run_lock ADD COLUMN {_c} {_ddl}")

    # Учётки для балансировки и Inceptum
    conn.execute("""
        CREATE TABLE IF NOT EXISTS balancer_credentials (
            id           INTEGER PRIMARY KEY CHECK (id = 1),
            ssh_host     TEXT NOT NULL DEFAULT '',
            ssh_port     INTEGER NOT NULL DEFAULT 22,
            ssh_login    TEXT NOT NULL DEFAULT '',
            ssh_password TEXT NOT NULL DEFAULT '',
            ssh_sudo_pwd TEXT NOT NULL DEFAULT '',
            win_login    TEXT NOT NULL DEFAULT '',
            win_password TEXT NOT NULL DEFAULT '',
            updated_at   INTEGER NOT NULL DEFAULT 0,
            updated_by   TEXT
        )
    """)
    # Миграция: добавляем поля для stunnel-сервера и внешнего nginx-балансировщика
    _bc_cols = {r[1] for r in conn.execute("PRAGMA table_info(balancer_credentials)").fetchall()}
    for _c, _ddl in [
        ("stunnel_host",     "TEXT NOT NULL DEFAULT ''"),
        ("stunnel_port",     "INTEGER NOT NULL DEFAULT 22"),
        ("stunnel_login",    "TEXT NOT NULL DEFAULT ''"),
        ("stunnel_password", "TEXT NOT NULL DEFAULT ''"),
        ("stunnel_sudo_pwd", "TEXT NOT NULL DEFAULT ''"),
        ("ext_ssh_host",     "TEXT NOT NULL DEFAULT ''"),
        ("ext_ssh_port",     "INTEGER NOT NULL DEFAULT 22"),
        ("ext_ssh_login",    "TEXT NOT NULL DEFAULT ''"),
        ("ext_ssh_password", "TEXT NOT NULL DEFAULT ''"),
        ("ext_ssh_sudo_pwd", "TEXT NOT NULL DEFAULT ''"),
        # Второй stunnel-сервер (nginx BRS); первый стал «nginx SBP» по UI.
        ("stunnel_brs_host",     "TEXT NOT NULL DEFAULT ''"),
        ("stunnel_brs_port",     "INTEGER NOT NULL DEFAULT 22"),
        ("stunnel_brs_login",    "TEXT NOT NULL DEFAULT ''"),
        ("stunnel_brs_password", "TEXT NOT NULL DEFAULT ''"),
        ("stunnel_brs_sudo_pwd", "TEXT NOT NULL DEFAULT ''"),
    ]:
        if _c not in _bc_cols:
            conn.execute(f"ALTER TABLE balancer_credentials ADD COLUMN {_c} {_ddl}")
    conn.execute(
        "INSERT OR IGNORE INTO balancer_credentials (id, updated_at) VALUES (1, ?)",
        (_now,),
    )

    # Страница «О программе» (одна запись, редактирует только admin)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS about_page (
            id         INTEGER PRIMARY KEY CHECK (id = 1),
            content    TEXT NOT NULL DEFAULT '',
            updated_at INTEGER NOT NULL DEFAULT 0,
            updated_by TEXT
        )
    """)
    conn.execute(
        "INSERT OR IGNORE INTO about_page (id, content, updated_at) VALUES (1, '', ?)",
        (_now,),
    )

    # Группы (плечи)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS ms_groups (
            group_key  TEXT PRIMARY KEY,
            title      TEXT NOT NULL,
            position   INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        )
    """)
    _default_groups = [("gate", "GATE"), ("itl1", "ITL 1 плечо"), ("itl2", "ITL 2 плечо"),
                       ("itlr", "ITLR"), ("btl", "BTL")]
    for _pos, (_gk, _title) in enumerate(_default_groups):
        conn.execute(
            "INSERT OR IGNORE INTO ms_groups (group_key, title, position, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (_gk, _title, _pos, _now, _now),
        )

    # Каталог микросервисов
    conn.execute("""
        CREATE TABLE IF NOT EXISTS ms_catalog (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            name          TEXT UNIQUE NOT NULL,
            balancer_paths TEXT NOT NULL DEFAULT '[]',
            position      INTEGER NOT NULL DEFAULT 0,
            created_at    INTEGER NOT NULL,
            updated_at    INTEGER NOT NULL
        )
    """)
    # Миграция: пути внешнего nginx-балансировщика
    _msc_cols = {r[1] for r in conn.execute("PRAGMA table_info(ms_catalog)").fetchall()}
    if "balancer_paths_ext" not in _msc_cols:
        conn.execute("ALTER TABLE ms_catalog ADD COLUMN balancer_paths_ext TEXT NOT NULL DEFAULT '[]'")
    # Записи API-балансировки (внешний nginx, без Inceptum). Один файл = одна запись.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS api_balancer_entries (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT UNIQUE NOT NULL,
            path        TEXT NOT NULL,
            search_keys TEXT NOT NULL DEFAULT '[]',
            position    INTEGER NOT NULL DEFAULT 0,
            created_at  INTEGER NOT NULL,
            updated_at  INTEGER NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS ms_catalog_nodes (
            catalog_id INTEGER NOT NULL,
            node_key   TEXT NOT NULL,
            PRIMARY KEY (catalog_id, node_key),
            FOREIGN KEY (catalog_id) REFERENCES ms_catalog(id) ON DELETE CASCADE
        )
    """)
    # Убираем «осиротевшие» строки маппинга — для нод, которых уже нет в реестре.
    conn.execute(
        "DELETE FROM ms_catalog_nodes "
        "WHERE node_key NOT IN (SELECT node_key FROM ms_node_settings)"
    )
    seeded_count = conn.execute("SELECT COUNT(*) FROM ms_catalog").fetchone()[0]
    if seeded_count == 0:
        for _pos, (_name, _paths, _nodes) in enumerate(MS_CATALOG_SEED):
            cur = conn.execute(
                "INSERT INTO ms_catalog (name, balancer_paths, position, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (_name, json.dumps(_paths), _pos, _now, _now),
            )
            cid = cur.lastrowid
            for _nk in _nodes:
                conn.execute(
                    "INSERT OR IGNORE INTO ms_catalog_nodes (catalog_id, node_key) VALUES (?, ?)",
                    (cid, _nk),
                )
    # Миграция: переименование route key microservices → Balancer в permissions пользователей
    rows = conn.execute("SELECT id, permissions FROM users WHERE permissions LIKE '%microservices%'").fetchall()
    for r in rows:
        try:
            perms = json.loads(r[1] or "[]")
        except Exception:
            continue
        if "microservices" in perms:
            perms = ["Balancer" if p == "microservices" else p for p in perms]
            conn.execute("UPDATE users SET permissions = ? WHERE id = ?", (json.dumps(perms), r[0]))
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
    _, err = require_route("db_connection")
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
    _, err = require_route("db_connection")
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
    _, err = require_route("db_connection")
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


# ===== Microservices console log (shared, 7-day retention, 50k-row hard cap) =====
MS_CONSOLE_RETENTION_SEC = 7 * 24 * 3600
MS_CONSOLE_MAX_ROWS      = 50_000

def ms_console_append(level, message, username=None):
    try:
        conn = sqlite3.connect(DB_PATH)
        try:
            now = int(time.time())
            conn.execute(
                "INSERT INTO ms_console (ts, level, message, username) VALUES (?, ?, ?, ?)",
                (now, level, message, username),
            )
            conn.execute(
                "DELETE FROM ms_console WHERE ts < ?",
                (now - MS_CONSOLE_RETENTION_SEC,),
            )
            # Жёсткий cap по числу строк — на случай всплеска логирования,
            # когда ретеншн по времени ещё не сработал.
            conn.execute(
                "DELETE FROM ms_console WHERE id NOT IN ("
                "  SELECT id FROM ms_console ORDER BY id DESC LIMIT ?"
                ")",
                (MS_CONSOLE_MAX_ROWS,),
            )
            conn.commit()
        finally:
            conn.close()
    except Exception:
        app.logger.exception("ms_console_append failed")


@app.get("/api/ms/console")
def ms_console_get():
    _, err = require_route("services")
    if err: return err
    try:
        since = int(request.args.get("since") or 0)
    except ValueError:
        since = 0
    try:
        limit = int(request.args.get("limit") or 500)
    except ValueError:
        limit = 500
    limit = max(1, min(limit, 2000))
    rows = db().execute(
        "SELECT id, ts, level, message, username FROM ms_console "
        "WHERE id > ? ORDER BY id ASC LIMIT ?",
        (since, limit),
    ).fetchall()
    return jsonify({"entries": [dict(r) for r in rows]})


# ===== Microservices (Windows services via WinRM) =====
MS_WINRM_USER = os.environ.get("MS_WINRM_USER", "")
MS_WINRM_PASSWORD = os.environ.get("MS_WINRM_PASSWORD", "")
MS_WINRM_TRANSPORT = os.environ.get("MS_WINRM_TRANSPORT", "ntlm")
MS_WINRM_PORT = int(os.environ.get("MS_WINRM_PORT", "5985"))
MS_WINRM_SCHEME = os.environ.get("MS_WINRM_SCHEME", "http")
MS_WINRM_TIMEOUT = int(os.environ.get("MS_WINRM_TIMEOUT", "10"))
MS_NODE_DOMAIN = os.environ.get("MS_NODE_DOMAIN", "")
MS_DEFAULT_SERVICE = "Inceptum.AppServer.3.0"

# DNS names, IPv4, IPv6 — alphanumerics, dot, dash, underscore, colon for v6
MS_HOST_RE     = re.compile(r"^[A-Za-z0-9._:\-]{1,253}$")
MS_SERVICE_RE  = re.compile(r"^[A-Za-z0-9._\- ]{1,128}$")
MS_NODE_KEY_RE = re.compile(r"^[A-Za-z0-9._\-]{1,64}$")
MS_GROUP_RE    = re.compile(r"^[a-z0-9_\-]{1,32}$")

_MS_STATUS_MAP = {
    "Running": "running",
    "Stopped": "stopped",
    "StartPending": "starting",
    "StopPending": "stopping",
    "Paused": "stopped",
    "PausePending": "stopping",
    "ContinuePending": "starting",
}


def _ms_default_host(node_key):
    return f"{node_key}.{MS_NODE_DOMAIN}" if MS_NODE_DOMAIN else node_key


def ms_node_config(node_key):
    """Return (host, service) for an existing node, or None if not registered."""
    row = db().execute(
        "SELECT host, service FROM ms_node_settings WHERE node_key = ?",
        (node_key,),
    ).fetchone()
    if not row:
        return None
    host    = row["host"]    or _ms_default_host(node_key)
    service = row["service"] or MS_DEFAULT_SERVICE
    return host, service


def _ms_resolve_winrm_creds():
    """Берём NTLM-учётку из «Учёток» (UI) → fallback на env. Должно вызываться
    в Flask-контексте (request handler), не из worker-потоков."""
    creds = None
    try:
        creds = get_balancer_creds()
    except Exception:
        creds = None
    user = (creds.get("win_login")    if creds else "") or MS_WINRM_USER
    pwd  = (creds.get("win_password") if creds else "") or MS_WINRM_PASSWORD
    return user, pwd


def _ms_session(host, user=None, pwd=None):
    if winrm is None:
        raise RuntimeError("pywinrm не установлен")
    # Если user/pwd не переданы (legacy-вызов) — попробуем разрешить из контекста.
    if user is None or pwd is None:
        user, pwd = _ms_resolve_winrm_creds()
    if not user or not pwd:
        raise RuntimeError("NTLM-учётка не заполнена в «Учётках»")
    url = f"{MS_WINRM_SCHEME}://{host}:{MS_WINRM_PORT}/wsman"
    return winrm.Session(
        url,
        auth=(user, pwd),
        transport=MS_WINRM_TRANSPORT,
        read_timeout_sec=MS_WINRM_TIMEOUT + 5,
        operation_timeout_sec=MS_WINRM_TIMEOUT,
    )


# ===== Inceptum REST API (HTTP NTLM) =====
INCEPTUM_PORT = 9223
INCEPTUM_TIMEOUT = 10  # секунды на одну HTTP-операцию

# Маппинг строкового статуса Inceptum → внутренний цветовой статус
_INCEPTUM_STATUS_MAP = {
    "Started":  "running",
    "Starting": "starting",
    "Stopped":  "stopped",
    "Stopping": "stopping",
}


def _inceptum_url(host, suffix=""):
    return f"http://{host}:{INCEPTUM_PORT}/api/instances{suffix}"


def _inceptum_auth(creds):
    if not creds or HttpNtlmAuth is None:
        return None
    if not creds.get("win_login") or not creds.get("win_password"):
        return None
    return HttpNtlmAuth(creds["win_login"], creds["win_password"])


def _inceptum_get_instances(host, auth):
    """GET http://<host>:9223/api/instances → list of instance dicts (или None при ошибке)."""
    if requests is None or auth is None:
        return None
    try:
        r = requests.get(_inceptum_url(host), auth=auth,
                         timeout=INCEPTUM_TIMEOUT,
                         headers={"Accept": "application/json"})
        if r.status_code != 200:
            return None
        return r.json()
    except Exception as e:
        app.logger.warning("Inceptum GET %s: %s", host, e)
        return None


# ===== SSH к балансировщику nginx =====
NGINX_SEARCH_LINES = 35   # ищем ключ ноды только в первых N строках конфига
SSH_TIMEOUT_CONNECT = 10
SSH_TIMEOUT_CMD = 30


class BalancerError(Exception):
    pass


def _strip_node_prefix(node_key):
    """Отрезаем ведущий 'sr-' (любой регистр) — поиск в конфиге идёт по суффиксу."""
    nk = node_key.strip()
    if nk.lower().startswith("sr-"):
        return nk[3:]
    return nk


def _ssh_connect(host, port, login, password):
    """Generic SSH-коннект с обработкой ошибок."""
    if paramiko is None:
        raise BalancerError("paramiko не установлен")
    if not host or not login:
        raise BalancerError("Хост или логин SSH не заданы")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=host,
            port=int(port or 22),
            username=login,
            password=password or None,
            timeout=SSH_TIMEOUT_CONNECT,
            allow_agent=False,
            look_for_keys=False,
        )
    except Exception as e:
        raise BalancerError(f"SSH connect {host}: {e}")
    return client


def _ssh_open(creds):
    """SSH к внутреннему балансировщику nginx (использует ssh_* поля)."""
    if not creds or not creds.get("ssh_host") or not creds.get("ssh_login"):
        raise BalancerError("SSH-учётка внутреннего балансировщика не настроена")
    return _ssh_connect(creds["ssh_host"], creds.get("ssh_port"),
                        creds["ssh_login"], creds.get("ssh_password"))


def _ext_ssh_open(creds):
    """SSH к внешнему балансировщику nginx (использует ext_ssh_* поля)."""
    if not creds or not creds.get("ext_ssh_host") or not creds.get("ext_ssh_login"):
        raise BalancerError("SSH-учётка внешнего балансировщика не настроена")
    return _ssh_connect(creds["ext_ssh_host"], creds.get("ext_ssh_port"),
                        creds["ext_ssh_login"], creds.get("ext_ssh_password"))


def _stunnel_ssh_open(creds):
    """SSH к stunnel «nginx SBP» (использует stunnel_* поля)."""
    if not creds or not creds.get("stunnel_host") or not creds.get("stunnel_login"):
        raise BalancerError("SSH-учётка stunnel SBP не настроена")
    return _ssh_connect(creds["stunnel_host"], creds.get("stunnel_port"),
                        creds["stunnel_login"], creds.get("stunnel_password"))


def _stunnel_brs_ssh_open(creds):
    """SSH к stunnel «nginx BRS» (использует stunnel_brs_* поля)."""
    if not creds or not creds.get("stunnel_brs_host") or not creds.get("stunnel_brs_login"):
        raise BalancerError("SSH-учётка stunnel BRS не настроена")
    return _ssh_connect(creds["stunnel_brs_host"], creds.get("stunnel_brs_port"),
                        creds["stunnel_brs_login"], creds.get("stunnel_brs_password"))


# Реестр stunnel-серверов: kind → (open_fn, host_field, sudo_field)
STUNNEL_KINDS = {
    "sbp": (_stunnel_ssh_open,     "stunnel_host",     "stunnel_sudo_pwd",     "nginx SBP"),
    "brs": (_stunnel_brs_ssh_open, "stunnel_brs_host", "stunnel_brs_sudo_pwd", "nginx BRS"),
}


def _filter_shell_noise(text):
    """Убирает обычный мусор из stderr/stdout SSH:
    tput-предупреждения о $TERM, прочие баннеры от /etc/profile.d.
    """
    if not text:
        return text
    out = []
    for line in text.split("\n"):
        ls = line.strip()
        if not ls:
            continue
        if ls.startswith("tput:"):
            continue
        if ls.startswith("[sudo] password"):
            continue
        out.append(line)
    return "\n".join(out)


def _ssh_run(client, cmd, timeout=SSH_TIMEOUT_CMD):
    """Возвращает (rc, stdout, stderr). Не выполняет sudo сам.
    TERM=dumb подавляет tput-warning'и от шеловских профилей."""
    full = f"TERM=dumb {cmd}"
    stdin, stdout, stderr = client.exec_command(full, timeout=timeout)
    out = stdout.read().decode("utf-8", "replace")
    err = stderr.read().decode("utf-8", "replace")
    rc = stdout.channel.recv_exit_status()
    return rc, _filter_shell_noise(out), _filter_shell_noise(err)


def _ssh_run_sudo(client, sudo_pwd, cmd, timeout=SSH_TIMEOUT_CMD):
    """Запуск с sudo. Если sudo_pwd пустой — пробуем sudo -n (NOPASSWD)."""
    if sudo_pwd:
        full = f"TERM=dumb sudo -S -p '' {cmd}"
        stdin, stdout, stderr = client.exec_command(full, timeout=timeout)
        try:
            stdin.write(sudo_pwd + "\n")
            stdin.flush()
        except Exception:
            pass
        try:
            stdin.channel.shutdown_write()
        except Exception:
            pass
        out = stdout.read().decode("utf-8", "replace")
        err = stderr.read().decode("utf-8", "replace")
        rc = stdout.channel.recv_exit_status()
        return rc, _filter_shell_noise(out), _filter_shell_noise(err)
    else:
        return _ssh_run(client, f"sudo -n {cmd}", timeout=timeout)


def _nginx_test(client, sudo_pwd):
    rc, out, err = _ssh_run_sudo(client, sudo_pwd, "nginx -t")
    msg = (err or out).strip()
    if rc != 0:
        raise BalancerError(f"nginx -t failed:\n{msg}")
    return msg or "nginx -t ok"


def _nginx_reload(client, sudo_pwd):
    rc, out, err = _ssh_run_sudo(client, sudo_pwd, "nginx -s reload")
    msg = (err or out).strip()
    if rc != 0:
        raise BalancerError(f"nginx -s reload failed:\n{msg}")
    return msg or "nginx -s reload ok"


def _balancer_apply(client, sudo_pwd, path, host_keys, direction):
    """Drain или Return: правит файл path, в первых NGINX_SEARCH_LINES строках
    комментирует/раскомментирует строки, содержащие любой ключ из host_keys
    (с отрезанным префиксом 'sr-').
    Возвращает {changed: bool, modified_lines: [номера, начиная с 1]}.
    direction: 'drain' или 'return'.
    """
    if direction not in ("drain", "return"):
        raise BalancerError(f"Неверное направление: {direction}")
    needles = [_strip_node_prefix(k).lower() for k in host_keys if k]
    if not needles:
        return {"changed": False, "modified_lines": []}

    # Читаем файл
    rc, content, err = _ssh_run_sudo(client, sudo_pwd, f"cat {shlex.quote(path)}")
    if rc != 0:
        raise BalancerError(f"cat {path}: {(err or content).strip()}")
    lines = content.split("\n")
    new_lines = list(lines)
    modified = []

    # Регекс: ищем нужный ключ как «слово» (граница перед/после)
    needle_res = [re.compile(r"\b" + re.escape(n) + r"\b", re.IGNORECASE) for n in needles]

    for i in range(min(NGINX_SEARCH_LINES, len(new_lines))):
        line = new_lines[i]
        if not any(rgx.search(line) for rgx in needle_res):
            continue
        if direction == "drain":
            stripped = line.lstrip()
            if not stripped.startswith("#"):
                indent = line[: len(line) - len(stripped)]
                new_lines[i] = indent + "#" + stripped
                modified.append(i + 1)
        else:  # return
            # Убираем только '#' (без съедания пробелов после них),
            # чтобы сохранить исходное форматирование строки.
            m = re.match(r"^(\s*)#+", line)
            if m:
                new_lines[i] = m.group(1) + line[m.end():]
                modified.append(i + 1)

    if not modified:
        return {"changed": False, "modified_lines": [], "original": content}

    # Pre-flight: при drain убеждаемся, что в файле останется хотя бы одна
    # активная строка 'server ...'. Иначе upstream окажется пустым и nginx
    # свалится на reload с 'no servers are inside upstream'.
    new_content = "\n".join(new_lines)
    if direction == "drain":
        server_active_re = re.compile(r"^\s*server\s+\S+", re.MULTILINE)
        if not server_active_re.search(new_content):
            raise BalancerError(
                f"{path}: после drain все серверы окажутся закомментированы — "
                "upstream будет пустым и nginx не примет reload "
                "('no servers are inside upstream'). "
                "Оставь хотя бы одну ноду в ротации."
            )

    # Записываем через SFTP во временный файл и sudo cp
    tmp_path = f"/tmp/balancer_{int(time.time() * 1000)}_{os.getpid()}.tmp"
    sftp = client.open_sftp()
    try:
        with sftp.file(tmp_path, "w") as fh:
            fh.write(new_content)
        sftp.chmod(tmp_path, 0o644)
    finally:
        try: sftp.close()
        except Exception: pass

    rc2, out2, err2 = _ssh_run_sudo(
        client, sudo_pwd, f"cp {shlex.quote(tmp_path)} {shlex.quote(path)}"
    )
    # очистим tmp в любом случае
    try:
        _ssh_run(client, f"rm -f {shlex.quote(tmp_path)}")
    except Exception:
        pass
    if rc2 != 0:
        raise BalancerError(f"sudo cp в {path}: {(err2 or out2).strip()}")
    return {"changed": True, "modified_lines": modified, "original": content}


# ===== Тестовый эндпойнт: проверка SSH-учётки + nginx -t =====
@app.post("/api/svc/test-balancer")
def svc_test_balancer():
    _, err = require_route("balancer_creds")
    if err: return err
    creds = get_balancer_creds()
    if not creds or not creds.get("ssh_host"):
        return jsonify({"ok": False, "error": "SSH-учётка внутреннего балансировщика не настроена"}), 400
    try:
        client = _ssh_open(creds)
    except BalancerError as e:
        return jsonify({"ok": False, "error": str(e)}), 500
    try:
        out = _nginx_test(client, creds.get("ssh_sudo_pwd") or "")
        return jsonify({"ok": True, "output": out, "host": creds["ssh_host"]})
    except BalancerError as e:
        return jsonify({"ok": False, "error": str(e)}), 502
    finally:
        try: client.close()
        except Exception: pass


@app.post("/api/svc/test-ext-balancer")
def svc_test_ext_balancer():
    _, err = require_route("balancer_creds")
    if err: return err
    creds = get_balancer_creds()
    if not creds or not creds.get("ext_ssh_host"):
        return jsonify({"ok": False, "error": "SSH-учётка внешнего балансировщика не настроена"}), 400
    try:
        client = _ext_ssh_open(creds)
    except BalancerError as e:
        return jsonify({"ok": False, "error": str(e)}), 500
    try:
        out = _nginx_test(client, creds.get("ext_ssh_sudo_pwd") or "")
        return jsonify({"ok": True, "output": out, "host": creds["ext_ssh_host"]})
    except BalancerError as e:
        return jsonify({"ok": False, "error": str(e)}), 502
    finally:
        try: client.close()
        except Exception: pass


@app.post("/api/svc/test-ntlm")
def svc_test_ntlm():
    """Тест NTLM-учётки: запрос /api/instances на первую ноду из реестра."""
    _, err = require_route("balancer_creds")
    if err: return err
    creds = get_balancer_creds()
    if not creds or not creds.get("win_login"):
        return jsonify({"ok": False, "error": "NTLM-учётка не заполнена"}), 400
    auth = _inceptum_auth(creds)
    if auth is None:
        return jsonify({"ok": False, "error": "NTLM-учётка пуста"}), 400
    row = db().execute(
        "SELECT node_key, host FROM ms_node_settings "
        "ORDER BY group_key, position, node_key LIMIT 1"
    ).fetchone()
    if not row:
        return jsonify({"ok": False, "error": "В реестре нет ни одной ноды для теста"}), 400
    host = row["host"] or _ms_default_host(row["node_key"])
    if requests is None:
        return jsonify({"ok": False, "error": "requests не установлен"}), 500
    try:
        r = requests.get(_inceptum_url(host), auth=auth,
                         timeout=INCEPTUM_TIMEOUT,
                         headers={"Accept": "application/json"})
    except Exception as e:
        return jsonify({"ok": False, "host": host, "error": f"сеть/таймаут: {e}"}), 502
    if r.status_code != 200:
        return jsonify({
            "ok": False, "host": host,
            "error": f"HTTP {r.status_code}: {(r.text or '')[:200]}",
        }), 502
    try:
        instances = r.json()
        count = len(instances) if isinstance(instances, list) else 0
        return jsonify({
            "ok": True, "host": host, "node": row["node_key"],
            "output": f"получено {count} микросервисов",
        })
    except Exception:
        return jsonify({"ok": True, "host": host, "output": "OK (ответ не JSON)"})


def _do_test_stunnel(kind):
    if kind not in STUNNEL_KINDS:
        return jsonify({"ok": False, "error": "Неизвестный stunnel"}), 400
    open_fn, host_field, _, label = STUNNEL_KINDS[kind]
    creds = get_balancer_creds()
    if not creds or not creds.get(host_field):
        return jsonify({"ok": False, "error": f"stunnel SSH-учётка «{label}» не настроена"}), 400
    try:
        client = open_fn(creds)
    except BalancerError as e:
        return jsonify({"ok": False, "error": str(e)}), 502
    try:
        rc, out, err_o = _ssh_run(client, "whoami && hostname")
        if rc != 0:
            return jsonify({"ok": False, "error": (err_o or out).strip() or f"exit={rc}"}), 502
        rc2, out2, _ = _ssh_run(client, f"systemctl is-active {STUNNEL_SERVICE_NAME} 2>/dev/null || true")
        active_now = (out2 or "").strip() or "?"
        return jsonify({
            "ok": True,
            "host": creds[host_field],
            "output": f"{out.strip()}\nstunnel сейчас: {active_now}",
        })
    finally:
        try: client.close()
        except Exception: pass


@app.post("/api/svc/test-stunnel")
def svc_test_stunnel():
    """Тест stunnel «nginx SBP» (legacy-роут, по умолчанию SBP)."""
    _, err = require_route("balancer_creds")
    if err: return err
    return _do_test_stunnel("sbp")


@app.post("/api/svc/test-stunnel-brs")
def svc_test_stunnel_brs():
    """Тест stunnel «nginx BRS»."""
    _, err = require_route("balancer_creds")
    if err: return err
    return _do_test_stunnel("brs")


# ===== Stunnel: статус и управление =====
STUNNEL_SERVICE_NAME = "stunnel"

def _stunnel_run(client, sudo_pwd, cmd, timeout=SSH_TIMEOUT_CMD):
    return _ssh_run_sudo(client, sudo_pwd, cmd, timeout=timeout)


def _do_stunnel_status(kind):
    if kind not in STUNNEL_KINDS:
        return jsonify({"error": "Неизвестный stunnel"}), 400
    open_fn, host_field, sudo_field, label = STUNNEL_KINDS[kind]
    creds = get_balancer_creds()
    if not creds or not creds.get(host_field):
        return jsonify({"error": f"stunnel «{label}» не настроен в учётках"}), 400
    try:
        client = open_fn(creds)
    except BalancerError as e:
        return jsonify({"error": str(e)}), 502
    try:
        sudo_pwd = creds.get(sudo_field) or ""
        _, out_active, err_active = _stunnel_run(
            client, sudo_pwd, f"systemctl is-active {STUNNEL_SERVICE_NAME}"
        )
        return jsonify({
            "host": creds[host_field],
            "label": label,
            "is_active": (out_active or err_active or "").strip() or "unknown",
        })
    finally:
        try: client.close()
        except Exception: pass


def _do_stunnel_action(kind, action):
    if action not in ("start", "stop", "restart"):
        return jsonify({"error": "Неизвестное действие"}), 400
    if kind not in STUNNEL_KINDS:
        return jsonify({"error": "Неизвестный stunnel"}), 400
    open_fn, host_field, sudo_field, label = STUNNEL_KINDS[kind]
    creds = get_balancer_creds()
    if not creds or not creds.get(host_field):
        return jsonify({"error": f"stunnel «{label}» не настроен в учётках"}), 400
    try:
        client = open_fn(creds)
    except BalancerError as e:
        return jsonify({"error": str(e)}), 502
    try:
        sudo_pwd = creds.get(sudo_field) or ""
        rc, out, err_o = _stunnel_run(
            client, sudo_pwd,
            f"systemctl {action} {STUNNEL_SERVICE_NAME}",
            timeout=20,
        )
        if rc != 0:
            return jsonify({
                "ok": False,
                "error": (err_o or out).strip() or f"exit={rc}",
            }), 502
        _, out_active, err_active = _stunnel_run(
            client, sudo_pwd, f"systemctl is-active {STUNNEL_SERVICE_NAME}"
        )
        return jsonify({
            "ok": True,
            "is_active": (out_active or err_active or "").strip() or "unknown",
            "output": (out + ("\n" + err_o if err_o else "")).strip(),
        })
    finally:
        try: client.close()
        except Exception: pass


@app.get("/api/stunnel/status")
def stunnel_status():
    _, err = require_route("stunnel")
    if err: return err
    return _do_stunnel_status("sbp")


@app.get("/api/stunnel-brs/status")
def stunnel_brs_status():
    _, err = require_route("stunnel")
    if err: return err
    return _do_stunnel_status("brs")


@app.post("/api/stunnel/<action>")
def stunnel_action(action):
    u, err = require_route("stunnel")
    if err: return err
    return _do_stunnel_action("sbp", action)


@app.post("/api/stunnel-brs/<action>")
def stunnel_brs_action(action):
    u, err = require_route("stunnel")
    if err: return err
    return _do_stunnel_action("brs", action)


def _ms_query_status(host, service, user=None, pwd=None):
    try:
        sess = _ms_session(host, user, pwd)
        ps = f"(Get-Service -Name '{service}' -ErrorAction Stop).Status"
        r = sess.run_ps(ps)
        if r.status_code != 0:
            err = (r.std_err or b"").decode("utf-8", "replace").strip()
            if "Cannot find any service" in err or "ObjectNotFound" in err:
                return "not_found"
            return "unreachable"
        out = (r.std_out or b"").decode("utf-8", "replace").strip()
        return _MS_STATUS_MAP.get(out, "unknown")
    except Exception as e:
        app.logger.warning("WinRM status %s: %s", host, e)
        return "unreachable"


def _ms_query_status_and_version(host, service, user=None, pwd=None):
    """Возвращает (state, version_str) — обоими одним WinRM-запросом."""
    try:
        sess = _ms_session(host, user, pwd)
        ps = (
            f"$n='{service}'; "
            "$svc = Get-CimInstance Win32_Service -Filter \"Name='$n'\" -ErrorAction SilentlyContinue; "
            "if (-not $svc) { Write-Output 'NOT_FOUND|'; exit 0 }; "
            "$st = (Get-Service -Name $n -ErrorAction Stop).Status; "
            "$ver = ''; "
            "try { "
            "  $p = ($svc.PathName -replace '^\"','' -replace '\".*$','').Trim(); "
            "  if ($p -and (Test-Path $p)) { $ver = (Get-Item $p).VersionInfo.FileVersion } "
            "} catch {}; "
            "Write-Output ($st.ToString() + '|' + $ver)"
        )
        r = sess.run_ps(ps)
        if r.status_code != 0:
            err = (r.std_err or b"").decode("utf-8", "replace").strip()
            if "Cannot find any service" in err or "ObjectNotFound" in err:
                return ("not_found", "")
            return ("unreachable", "")
        out = (r.std_out or b"").decode("utf-8", "replace").strip()
        if out.startswith("NOT_FOUND|"):
            return ("not_found", "")
        if "|" in out:
            st_raw, ver = out.split("|", 1)
            return (_MS_STATUS_MAP.get(st_raw.strip(), "unknown"), ver.strip())
        return (_MS_STATUS_MAP.get(out, "unknown"), "")
    except Exception as e:
        app.logger.warning("WinRM status+ver %s: %s", host, e)
        return ("unreachable", "")


def _ms_run_action(host, service, action, user=None, pwd=None):
    cmd_map = {
        "start":   f"Start-Service -Name '{service}' -ErrorAction Stop",
        "stop":    f"Stop-Service  -Name '{service}' -Force -ErrorAction Stop",
        "restart": f"Restart-Service -Name '{service}' -Force -ErrorAction Stop",
    }
    if action not in cmd_map:
        return {"ok": False, "error": "Неизвестное действие"}
    try:
        sess = _ms_session(host, user, pwd)
        r = sess.run_ps(cmd_map[action])
        if r.status_code == 0:
            return {"ok": True, "message": f"{action} ok"}
        err = (r.std_err or b"").decode("utf-8", "replace").strip()
        return {"ok": False, "error": err or f"exit={r.status_code}"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def _ms_resolve_configs(node_keys):
    """{key: (host, service)} for those that exist; missing keys omitted."""
    return {n: cfg for n in node_keys if (cfg := ms_node_config(n)) is not None}


def _ms_short_error(err):
    """Сжимает технические ошибки WinRM/pywinrm в короткую читабельную метку."""
    e = (err or "").lower()
    if "ntlm-учётка не заполнена" in e or "ms_winrm_user" in e or "pywinrm не установлен" in e:
        return "NTLM-учётка не заполнена в «Учётках»"
    if "cannot find any service" in e or "objectnotfound" in e:
        return "Служба не найдена"
    if "unauthorized" in e or "401" in e or "authentication failed" in e or "access is denied" in e:
        return "Не авторизован (учётка/права)"
    if "max retries exceeded" in e or "connection refused" in e or "no route to host" in e \
            or "unreachable" in e or "timed out" in e or "timeout" in e:
        return "Хост недоступен"
    if "name or service not known" in e or "getaddrinfo" in e or "nodename nor servname" in e:
        return "Имя хоста не резолвится"
    if "service is already running" in e:
        return "Служба уже запущена"
    if "service has not been started" in e or "service is not started" in e:
        return "Служба остановлена"
    return (err[:80] + "…") if err and len(err) > 80 else (err or "ошибка")


@app.post("/api/ms/all-status")
def ms_all_status():
    """Батч: статусы и версии нескольких сервисов сразу через Inceptum REST.
    body: {queries: [{service, nodes: [...]}]}
    return: {results: {service: {node_key: state}}, versions: {svc: {node_key: ver}}, process_ids: {svc: {node_key: pid}}}
    """
    _, err = require_route("Balancer")
    if err: return err
    data = request.get_json(silent=True) or {}
    queries = data.get("queries") or []
    if not isinstance(queries, list) or not queries:
        return jsonify({"error": "queries должен быть непустым списком"}), 400
    pairs = []
    needed_node_keys = set()
    for q in queries:
        svc = (q.get("service") or "").strip()
        nodes = q.get("nodes") or []
        if not svc or not MS_SERVICE_RE.match(svc):
            continue
        if not isinstance(nodes, list):
            continue
        for n in nodes:
            n = str(n).strip()
            if MS_NODE_KEY_RE.match(n):
                needed_node_keys.add(n)
                pairs.append((svc, n))
    if not pairs:
        return jsonify({"error": "Нет валидных (service, node) пар"}), 400
    pairs = pairs[:2000]
    placeholders = ",".join(["?"] * len(needed_node_keys))
    rows = db().execute(
        f"SELECT node_key, host FROM ms_node_settings WHERE node_key IN ({placeholders})",
        list(needed_node_keys),
    ).fetchall()
    hosts_map = {r["node_key"]: (r["host"] or _ms_default_host(r["node_key"])) for r in rows}
    for n in needed_node_keys:
        if n not in hosts_map:
            hosts_map[n] = _ms_default_host(n)

    creds = get_balancer_creds()
    auth = _inceptum_auth(creds)

    # 1) Опрашиваем каждую ноду один раз — получаем массив микросервисов
    instances_by_node = {}
    def fetch_node(node_key):
        return node_key, _inceptum_get_instances(hosts_map[node_key], auth)
    if auth and needed_node_keys:
        with ThreadPoolExecutor(max_workers=min(16, len(needed_node_keys))) as ex:
            for node_key, instances in ex.map(fetch_node, needed_node_keys):
                instances_by_node[node_key] = instances

    # 2) Извлекаем по каждой паре (svc, node) статус/версию/pid
    results, versions, pids = {}, {}, {}
    for svc, node_key in pairs:
        instances = instances_by_node.get(node_key)
        if instances is None:
            results.setdefault(svc, {})[node_key] = "unreachable"
            continue
        # ищем по name (точное совпадение)
        match = next((i for i in instances if i.get("name") == svc), None)
        if not match:
            results.setdefault(svc, {})[node_key] = "not_found"
            continue
        raw_status = match.get("status", "")
        results.setdefault(svc, {})[node_key] = _INCEPTUM_STATUS_MAP.get(raw_status, "unknown")
        versions.setdefault(svc, {})[node_key] = match.get("actualVersion") or match.get("version") or ""
        pid = match.get("processId")
        if pid:
            pids.setdefault(svc, {})[node_key] = pid
    return jsonify({"results": results, "versions": versions, "process_ids": pids})


@app.post("/api/ms/svc-status")
def ms_svc_status():
    """Опрос произвольного микросервиса по списку нод через Inceptum REST."""
    _, err = require_route("Balancer")
    if err: return err
    data = request.get_json(silent=True) or {}
    service = (data.get("service") or "").strip()
    nodes = data.get("nodes") or []
    if not service or not MS_SERVICE_RE.match(service):
        return jsonify({"error": "Имя сервиса обязательно"}), 400
    if not isinstance(nodes, list) or not nodes:
        return jsonify({"error": "Список nodes пуст"}), 400
    nodes = [str(n).strip() for n in nodes if MS_NODE_KEY_RE.match(str(n).strip())][:64]
    if not nodes:
        return jsonify({"error": "Нет валидных ключей нод"}), 400
    placeholders = ",".join(["?"] * len(nodes))
    rows = db().execute(
        f"SELECT node_key, host FROM ms_node_settings WHERE node_key IN ({placeholders})",
        nodes,
    ).fetchall()
    hosts_map = {r["node_key"]: (r["host"] or _ms_default_host(r["node_key"])) for r in rows}
    for n in nodes:
        if n not in hosts_map:
            hosts_map[n] = _ms_default_host(n)

    creds = get_balancer_creds()
    auth = _inceptum_auth(creds)

    statuses, versions = {}, {}

    def fetch(n):
        if auth is None:
            return n, None
        return n, _inceptum_get_instances(hosts_map[n], auth)

    if auth:
        with ThreadPoolExecutor(max_workers=min(16, len(nodes))) as ex:
            for n, instances in ex.map(fetch, nodes):
                if instances is None:
                    statuses[n] = "unreachable"
                    versions[n] = ""
                    continue
                match = next((i for i in instances if i.get("name") == service), None)
                if not match:
                    statuses[n] = "not_found"
                    versions[n] = ""
                else:
                    statuses[n] = _INCEPTUM_STATUS_MAP.get(match.get("status", ""), "unknown")
                    versions[n] = match.get("actualVersion") or match.get("version") or ""
    else:
        for n in nodes:
            statuses[n] = "unreachable"
            versions[n] = ""
    return jsonify({"statuses": statuses, "versions": versions})


@app.post("/api/ms/status")
def ms_status():
    _, err = require_route("services")
    if err: return err
    data = request.get_json(silent=True) or {}
    nodes = data.get("nodes") or []
    if not isinstance(nodes, list) or not nodes:
        return jsonify({"error": "Список nodes пуст"}), 400
    nodes = [str(n).strip() for n in nodes if MS_NODE_KEY_RE.match(str(n).strip())][:64]
    configs = _ms_resolve_configs(nodes)
    statuses = {n: "not_found" for n in nodes if n not in configs}
    valid = list(configs.keys())
    # резолвим NTLM-учётку в request-контексте, чтобы worker-потоки её не дёргали
    user, pwd = _ms_resolve_winrm_creds()
    def query(n):
        host, service = configs[n]
        return _ms_query_status(host, service, user, pwd)
    if valid:
        # 32 потока — чтобы 30 нод проходили в одном батче, а не в двух
        with ThreadPoolExecutor(max_workers=min(32, len(valid))) as ex:
            for n, st in zip(valid, ex.map(query, valid)):
                statuses[n] = st
    return jsonify({"statuses": statuses})


@app.post("/api/ms/action")
def ms_action():
    u, err = require_route("services")
    if err: return err
    data = request.get_json(silent=True) or {}
    action = (data.get("action") or "").strip()
    nodes = data.get("nodes") or []
    if action not in {"start", "stop", "restart"}:
        return jsonify({"error": "Неизвестное действие"}), 400
    if not isinstance(nodes, list) or not nodes:
        return jsonify({"error": "Список nodes пуст"}), 400
    nodes = [str(n).strip() for n in nodes if MS_NODE_KEY_RE.match(str(n).strip())][:32]
    configs = _ms_resolve_configs(nodes)
    if not configs:
        return jsonify({"error": "Все указанные ноды отсутствуют в реестре"}), 404
    username = u["username"]
    label = {"start": "Запуск", "stop": "Остановка", "restart": "Перезагрузка"}[action]
    services_set = sorted({s for _, s in configs.values()})
    svc_label = ", ".join(services_set) if len(services_set) <= 3 else f"{len(services_set)} разных служб"
    targeted = list(configs.keys())
    ms_console_append("info", f"{label} {svc_label} — {len(targeted)} {'хост' if len(targeted) == 1 else 'хостов'}", username)
    results = {}
    user, pwd = _ms_resolve_winrm_creds()
    def run(n):
        host, service = configs[n]
        return _ms_run_action(host, service, action, user, pwd)
    ok_nodes = []
    err_groups = {}
    with ThreadPoolExecutor(max_workers=min(16, len(targeted))) as ex:
        for n, r in zip(targeted, ex.map(run, targeted)):
            results[n] = r
            if r.get("ok"):
                ok_nodes.append(n)
            else:
                key = _ms_short_error(r.get("error", ""))
                err_groups.setdefault(key, []).append(n)
    if ok_nodes:
        ms_console_append("ok", f"  ✓ {', '.join(ok_nodes)}", username)
    for err, nodes_with_err in err_groups.items():
        ms_console_append("err", f"  ✗ {err}: {', '.join(nodes_with_err)}", username)
    for n in nodes:
        if n not in configs:
            results[n] = {"ok": False, "error": "Нода не зарегистрирована"}
    return jsonify({"results": results})


@app.get("/api/ms/nodes")
def ms_nodes_list():
    _, err = require_route("services")
    if err: return err
    rows = db().execute(
        "SELECT node_key, group_key, host, service, role FROM ms_node_settings "
        "ORDER BY group_key, position, node_key"
    ).fetchall()
    out = []
    for r in rows:
        out.append({
            "key": r["node_key"],
            "group": r["group_key"] or "",
            "host":    r["host"]    or _ms_default_host(r["node_key"]),
            "service": r["service"] or MS_DEFAULT_SERVICE,
            "role": r["role"] or "",
            "host_default":    _ms_default_host(r["node_key"]),
            "service_default": MS_DEFAULT_SERVICE,
            "host_overridden":    bool(r["host"]),
            "service_overridden": bool(r["service"]),
        })
    return jsonify({"nodes": out})


@app.get("/api/ms/nodes/<key>")
def ms_node_get(key):
    _, err = require_route("services")
    if err: return err
    if not MS_NODE_KEY_RE.match(key):
        return jsonify({"error": "Недопустимый ключ ноды"}), 400
    cfg = ms_node_config(key)
    if cfg is None:
        return jsonify({"error": "Нода не найдена"}), 404
    host, service = cfg
    role_row = db().execute("SELECT role FROM ms_node_settings WHERE node_key = ?", (key,)).fetchone()
    return jsonify({
        "key": key,
        "host": host,
        "service": service,
        "role": (role_row["role"] if role_row else "") or "",
        "host_default": _ms_default_host(key),
        "service_default": MS_DEFAULT_SERVICE,
    })


@app.post("/api/ms/nodes")
def ms_node_create():
    u, err = require_route("services")
    if err: return err
    data = request.get_json(silent=True) or {}
    key       = (data.get("key")     or "").strip()
    group_key = (data.get("group")   or "").strip()
    host      = (data.get("host")    or "").strip()
    service   = (data.get("service") or "").strip() or MS_DEFAULT_SERVICE
    role      = (data.get("role")    or "").strip().lower() or None
    if not key or not host or not role:
        return jsonify({"error": "Заполните все поля: ключ, хост, роль"}), 400
    if role not in ("master", "slave"):
        return jsonify({"error": "Роль: master или slave"}), 400
    if not MS_NODE_KEY_RE.match(key):
        return jsonify({"error": "Ключ ноды: латиница, цифры, точка, дефис, подчёркивание (до 64 символов)"}), 400
    if not MS_GROUP_RE.match(group_key):
        return jsonify({"error": "Ключ группы: маленькие латиница, цифры, дефис, подчёркивание (до 32 символов)"}), 400
    if not db().execute("SELECT 1 FROM ms_groups WHERE group_key = ?", (group_key,)).fetchone():
        return jsonify({"error": f"Группа «{group_key}» не зарегистрирована"}), 400
    if not MS_HOST_RE.match(host):
        return jsonify({"error": "Хост: допустимы латиница, цифры, точка, дефис, подчёркивание (или IP)"}), 400
    if not MS_SERVICE_RE.match(service):
        return jsonify({"error": "Имя службы: допустимы латиница, цифры, пробел, точка, дефис, подчёркивание (до 128 символов)"}), 400
    conn = db()
    if conn.execute("SELECT 1 FROM ms_node_settings WHERE node_key = ?", (key,)).fetchone():
        return jsonify({"error": f"Хост с ключом «{key}» уже существует"}), 409
    if role == "master":
        existing_master = conn.execute(
            "SELECT node_key FROM ms_node_settings WHERE role = 'master' AND group_key = ?",
            (group_key,),
        ).fetchone()
        if existing_master:
            return jsonify({"error": f"Master в этой группе уже занят нодой «{existing_master['node_key']}». Сначала смените её роль на Slave."}), 409
    pos_row = conn.execute(
        "SELECT COALESCE(MAX(position), -1) + 1 FROM ms_node_settings WHERE group_key = ?",
        (group_key,),
    ).fetchone()
    pos = pos_row[0] if pos_row else 0
    now = int(time.time())
    conn.execute(
        "INSERT INTO ms_node_settings (node_key, group_key, host, service, role, position, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (key, group_key, host, service, role, pos, now, now),
    )
    conn.commit()
    return jsonify({"ok": True, "key": key})


@app.patch("/api/ms/nodes/<key>")
def ms_node_set(key):
    _, err = require_route("services")
    if err: return err
    if not MS_NODE_KEY_RE.match(key):
        return jsonify({"error": "Недопустимый ключ ноды"}), 400
    data = request.get_json(silent=True) or {}
    new_key = (data.get("key")     or "").strip() or key
    host    = (data.get("host")    or "").strip()
    role    = (data.get("role")    or "").strip().lower()
    if not new_key or not host or not role:
        return jsonify({"error": "Заполните все поля: ключ, хост, роль"}), 400
    if not MS_NODE_KEY_RE.match(new_key):
        return jsonify({"error": "Ключ ноды: латиница, цифры, точка, дефис, подчёркивание (до 64 символов)"}), 400
    if not MS_HOST_RE.match(host):
        return jsonify({"error": "Хост: допустимы латиница, цифры, точка, дефис, подчёркивание (или IP)"}), 400
    if role not in ("master", "slave"):
        return jsonify({"error": "Роль: master или slave"}), 400
    cur_svc_row = db().execute("SELECT service FROM ms_node_settings WHERE node_key = ?", (key,)).fetchone()
    service = (data.get("service") or "").strip() or (cur_svc_row["service"] if cur_svc_row and cur_svc_row["service"] else MS_DEFAULT_SERVICE)
    if not MS_SERVICE_RE.match(service):
        return jsonify({"error": "Имя службы: допустимы латиница, цифры, пробел, точка, дефис, подчёркивание (до 128 символов)"}), 400
    conn = db()
    if new_key != key:
        if conn.execute("SELECT 1 FROM ms_node_settings WHERE node_key = ?", (new_key,)).fetchone():
            return jsonify({"error": f"Нода с ключом «{new_key}» уже существует"}), 409
    if role == "master":
        # узнаём group_key редактируемой ноды
        cur_group_row = conn.execute("SELECT group_key FROM ms_node_settings WHERE node_key = ?", (key,)).fetchone()
        cur_group = cur_group_row["group_key"] if cur_group_row else None
        if cur_group:
            existing_master = conn.execute(
                "SELECT node_key FROM ms_node_settings WHERE role = 'master' AND group_key = ? AND node_key != ?",
                (cur_group, key),
            ).fetchone()
            if existing_master:
                return jsonify({"error": f"Master в этой группе уже занят нодой «{existing_master['node_key']}». Сначала смените её роль на Slave."}), 409
    res = conn.execute(
        "UPDATE ms_node_settings SET node_key = ?, host = ?, service = ?, role = ?, updated_at = ? WHERE node_key = ?",
        (new_key, host, service, role, int(time.time()), key),
    )
    if res.rowcount == 0:
        return jsonify({"error": "Нода не найдена"}), 404
    conn.commit()
    return jsonify({"ok": True, "key": new_key})


@app.delete("/api/ms/nodes/<key>")
def ms_node_delete(key):
    u, err = require_route("services")
    if err: return err
    if not MS_NODE_KEY_RE.match(key):
        return jsonify({"error": "Недопустимый ключ ноды"}), 400
    conn = db()
    res = conn.execute("DELETE FROM ms_node_settings WHERE node_key = ?", (key,))
    if res.rowcount == 0:
        return jsonify({"error": "Нода не найдена"}), 404
    # Каскадно убираем ноду из всех привязок к микросервисам в каталоге
    conn.execute("DELETE FROM ms_catalog_nodes WHERE node_key = ?", (key,))
    conn.commit()
    ms_console_append("warn", f"- удалён хост {key}", u["username"])
    return jsonify({"ok": True})


# ===== Microservices catalog (admin only) =====
MS_CATALOG_NAME_RE = re.compile(r"^[A-Za-z0-9._\-]{1,128}$")
MS_PATH_RE = re.compile(r"^/[A-Za-z0-9._\-/]{1,255}$")


def _serialize_catalog_row(row, nodes):
    try:
        paths = json.loads(row["balancer_paths"] or "[]")
    except Exception:
        paths = []
    try:
        paths_ext = json.loads(row["balancer_paths_ext"] or "[]")
    except Exception:
        paths_ext = []
    return {
        "id": row["id"],
        "name": row["name"],
        "paths": paths,
        "paths_ext": paths_ext,
        "nodes": nodes,
        "balanced": bool(paths),
        "balanced_ext": bool(paths_ext),
    }


@app.get("/api/catalog/microservices")
def ms_catalog_list():
    # Чтение доступно любому, у кого есть права на «Микросервисы»
    # (запись по-прежнему только админу).
    _, err = require_route("Balancer")
    if err: return err
    rows = db().execute(
        "SELECT id, name, balancer_paths, balancer_paths_ext, position FROM ms_catalog "
        "ORDER BY position, name"
    ).fetchall()
    nodes_by_id = {}
    for r in db().execute("SELECT catalog_id, node_key FROM ms_catalog_nodes ORDER BY node_key"):
        nodes_by_id.setdefault(r["catalog_id"], []).append(r["node_key"])
    return jsonify({"microservices": [
        _serialize_catalog_row(r, nodes_by_id.get(r["id"], [])) for r in rows
    ]})


@app.post("/api/catalog/microservices")
def ms_catalog_create():
    _, err = require_route("ms_catalog")
    if err: return err
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    paths = data.get("paths") or []
    paths_ext = data.get("paths_ext") or []
    nodes = data.get("nodes") or []
    if not MS_CATALOG_NAME_RE.match(name):
        return jsonify({"error": "Имя: латиница, цифры, точка, дефис, подчёркивание (до 128 символов)"}), 400
    if not isinstance(paths, list) or not all(isinstance(p, str) for p in paths):
        return jsonify({"error": "paths должен быть списком строк"}), 400
    if not isinstance(paths_ext, list) or not all(isinstance(p, str) for p in paths_ext):
        return jsonify({"error": "paths_ext должен быть списком строк"}), 400
    paths = [p.strip() for p in paths if p.strip()]
    paths_ext = [p.strip() for p in paths_ext if p.strip()]
    for p in paths:
        if not MS_PATH_RE.match(p):
            return jsonify({"error": f"Недопустимый путь (внутр.): {p}"}), 400
    for p in paths_ext:
        if not MS_PATH_RE.match(p):
            return jsonify({"error": f"Недопустимый путь (внеш.): {p}"}), 400
    if not isinstance(nodes, list):
        return jsonify({"error": "nodes должен быть списком"}), 400
    nodes = [str(n).strip() for n in nodes if MS_NODE_KEY_RE.match(str(n).strip())]
    conn = db()
    if conn.execute("SELECT 1 FROM ms_catalog WHERE name = ?", (name,)).fetchone():
        return jsonify({"error": f"Микросервис «{name}» уже существует"}), 409
    pos_row = conn.execute("SELECT COALESCE(MAX(position), -1) + 1 FROM ms_catalog").fetchone()
    pos = pos_row[0] if pos_row else 0
    now = int(time.time())
    cur = conn.execute(
        "INSERT INTO ms_catalog (name, balancer_paths, balancer_paths_ext, position, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (name, json.dumps(paths), json.dumps(paths_ext), pos, now, now),
    )
    cid = cur.lastrowid
    for n in nodes:
        conn.execute(
            "INSERT OR IGNORE INTO ms_catalog_nodes (catalog_id, node_key) VALUES (?, ?)",
            (cid, n),
        )
    conn.commit()
    return jsonify({"ok": True, "id": cid})


@app.patch("/api/catalog/microservices/<int:cid>")
def ms_catalog_update(cid):
    _, err = require_route("ms_catalog")
    if err: return err
    data = request.get_json(silent=True) or {}
    conn = db()
    row = conn.execute("SELECT id, name FROM ms_catalog WHERE id = ?", (cid,)).fetchone()
    if not row:
        return jsonify({"error": "Не найдено"}), 404
    fields = []
    args = []
    if "name" in data:
        name = (data.get("name") or "").strip()
        if not MS_CATALOG_NAME_RE.match(name):
            return jsonify({"error": "Имя: латиница, цифры, точка, дефис, подчёркивание (до 128 символов)"}), 400
        if name != row["name"]:
            if conn.execute("SELECT 1 FROM ms_catalog WHERE name = ? AND id <> ?", (name, cid)).fetchone():
                return jsonify({"error": f"Микросервис «{name}» уже существует"}), 409
        fields.append("name = ?"); args.append(name)
    if "paths" in data:
        paths = data.get("paths") or []
        if not isinstance(paths, list) or not all(isinstance(p, str) for p in paths):
            return jsonify({"error": "paths должен быть списком строк"}), 400
        paths = [p.strip() for p in paths if p.strip()]
        for p in paths:
            if not MS_PATH_RE.match(p):
                return jsonify({"error": f"Недопустимый путь (внутр.): {p}"}), 400
        fields.append("balancer_paths = ?"); args.append(json.dumps(paths))
    if "paths_ext" in data:
        paths_ext = data.get("paths_ext") or []
        if not isinstance(paths_ext, list) or not all(isinstance(p, str) for p in paths_ext):
            return jsonify({"error": "paths_ext должен быть списком строк"}), 400
        paths_ext = [p.strip() for p in paths_ext if p.strip()]
        for p in paths_ext:
            if not MS_PATH_RE.match(p):
                return jsonify({"error": f"Недопустимый путь (внеш.): {p}"}), 400
        fields.append("balancer_paths_ext = ?"); args.append(json.dumps(paths_ext))
    if fields:
        fields.append("updated_at = ?"); args.append(int(time.time()))
        args.append(cid)
        conn.execute(f"UPDATE ms_catalog SET {', '.join(fields)} WHERE id = ?", args)
    if "nodes" in data:
        nodes = data.get("nodes") or []
        if not isinstance(nodes, list):
            return jsonify({"error": "nodes должен быть списком"}), 400
        nodes = [str(n).strip() for n in nodes if MS_NODE_KEY_RE.match(str(n).strip())]
        conn.execute("DELETE FROM ms_catalog_nodes WHERE catalog_id = ?", (cid,))
        for n in nodes:
            conn.execute(
                "INSERT OR IGNORE INTO ms_catalog_nodes (catalog_id, node_key) VALUES (?, ?)",
                (cid, n),
            )
    conn.commit()
    return jsonify({"ok": True})


@app.delete("/api/catalog/microservices/<int:cid>")
def ms_catalog_delete(cid):
    _, err = require_route("ms_catalog")
    if err: return err
    conn = db()
    res = conn.execute("DELETE FROM ms_catalog WHERE id = ?", (cid,))
    if res.rowcount == 0:
        return jsonify({"error": "Не найдено"}), 404
    conn.execute("DELETE FROM ms_catalog_nodes WHERE catalog_id = ?", (cid,))
    conn.commit()
    return jsonify({"ok": True})


# ===== API-балансировка: записи (внешний nginx, без Inceptum) =====
API_ENTRY_NAME_RE = re.compile(r"^[A-Za-zА-Яа-яЁё0-9 ._\-]{1,128}$")
API_ENTRY_KEY_RE  = re.compile(r"^[A-Za-z0-9._\-]{1,64}$")


def _api_keys_parse(raw):
    """Из значения колонки search_keys → словарь {group_key: [{key, alias}, ...]}.
    Поддерживает три исторических варианта хранения:
      - list[str]       (старый-старый: «без плеча», без алиасов)
      - dict[gk: list[str]]            («плечи», без алиасов)
      - dict[gk: list[{key, alias}]]   (текущий формат)
    """
    try:
        v = json.loads(raw or "{}")
    except Exception:
        return {}

    def _norm_one(item):
        if isinstance(item, str):
            s = item.strip()
            return {"key": s, "alias": ""} if s else None
        if isinstance(item, dict):
            k = str(item.get("key") or "").strip()
            a = str(item.get("alias") or "").strip()
            return {"key": k, "alias": a} if k else None
        return None

    if isinstance(v, list):
        items = [x for x in (_norm_one(it) for it in v) if x]
        return {"": items} if items else {}
    if isinstance(v, dict):
        out = {}
        for gk, items in v.items():
            if not isinstance(items, list): continue
            cleaned = [x for x in (_norm_one(it) for it in items) if x]
            if cleaned:
                out[str(gk)] = cleaned
        return out
    return {}


def _api_keys_flatten_keys(grouped):
    """Плоский список одних только key-строк (для оркестратора/ротации)."""
    flat = []
    for gk in sorted(grouped.keys(), key=lambda x: (x == "", x)):
        for it in grouped[gk]:
            flat.append(it["key"])
    return flat


def _api_entry_serialize(row):
    grouped = _api_keys_parse(row["search_keys"])
    return {
        "id":   row["id"],
        "name": row["name"],
        "path": row["path"],
        # search_keys — плоский список самих ключей (для совместимости)
        "search_keys": _api_keys_flatten_keys(grouped),
        # search_keys_grouped — словарь плечо → [{key, alias}, ...]
        "search_keys_grouped": grouped,
        "position":    row["position"],
    }


@app.get("/api/api-balancer/entries")
def api_balancer_list():
    # Чтение доступно тем, у кого есть Balancer (т.к. вкладка API там же).
    _, err = require_route("Balancer")
    if err: return err
    rows = db().execute(
        "SELECT id, name, path, search_keys, position "
        "FROM api_balancer_entries ORDER BY position, name"
    ).fetchall()
    return jsonify({"entries": [_api_entry_serialize(r) for r in rows]})


API_ENTRY_ALIAS_RE = re.compile(r"^.{0,64}$")  # алиас — любой текст до 64 символов


def _api_keys_validate(value, conn):
    """Принимает dict {group_key: list[str|{key, alias}]} или legacy list.
    Возвращает (grouped, error_str), где grouped — каноничный
    {group_key: [{key, alias}, ...]}."""
    def _coerce_item(it):
        if isinstance(it, str):
            return it.strip(), ""
        if isinstance(it, dict):
            return str(it.get("key") or "").strip(), str(it.get("alias") or "").strip()
        return None, None

    if isinstance(value, list):
        items = []
        for it in value:
            k, a = _coerce_item(it)
            if k is None: continue
            if not k: continue
            if not API_ENTRY_KEY_RE.match(k):
                return None, f"Недопустимый ключ поиска: {k}"
            if a and not API_ENTRY_ALIAS_RE.match(a):
                return None, f"Недопустимый алиас: {a}"
            items.append({"key": k, "alias": a})
        return ({"": items} if items else {}), None
    if not isinstance(value, dict):
        return None, "search_keys должен быть списком или объектом {плечо: [ключи]}"
    valid_groups = {r[0] for r in conn.execute("SELECT group_key FROM ms_groups").fetchall()}
    valid_groups.add("")  # пустой = «без плеча»
    grouped = {}
    for gk, items in value.items():
        gk = str(gk)
        if gk not in valid_groups:
            return None, f"Неизвестное плечо: «{gk}»"
        if not isinstance(items, list):
            return None, f"Ключи плеча «{gk}» должны быть списком"
        cleaned = []
        for it in items:
            k, a = _coerce_item(it)
            if k is None: continue
            if not k: continue
            if not API_ENTRY_KEY_RE.match(k):
                return None, f"Недопустимый ключ поиска: {k}"
            if a and not API_ENTRY_ALIAS_RE.match(a):
                return None, f"Недопустимый алиас: {a}"
            cleaned.append({"key": k, "alias": a})
        if cleaned:
            grouped[gk] = cleaned
    return grouped, None


@app.post("/api/api-balancer/entries")
def api_balancer_create():
    _, err = require_route("api_settings")
    if err: return err
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    path = (data.get("path") or "").strip()
    if not API_ENTRY_NAME_RE.match(name):
        return jsonify({"error": "Имя: 1..128 символов, латиница/кириллица, цифры, пробел, точка, дефис, подчёркивание"}), 400
    if not MS_PATH_RE.match(path):
        return jsonify({"error": "Недопустимый путь nginx-конфига"}), 400
    conn = db()
    grouped, err_msg = _api_keys_validate(data.get("search_keys") or {}, conn)
    if err_msg:
        return jsonify({"error": err_msg}), 400
    if conn.execute("SELECT 1 FROM api_balancer_entries WHERE name = ?", (name,)).fetchone():
        return jsonify({"error": f"Запись «{name}» уже существует"}), 409
    pos_row = conn.execute("SELECT COALESCE(MAX(position), -1) + 1 FROM api_balancer_entries").fetchone()
    pos = pos_row[0] if pos_row else 0
    now = int(time.time())
    cur = conn.execute(
        "INSERT INTO api_balancer_entries (name, path, search_keys, position, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (name, path, json.dumps(grouped), pos, now, now),
    )
    conn.commit()
    return jsonify({"ok": True, "id": cur.lastrowid})


@app.patch("/api/api-balancer/entries/<int:eid>")
def api_balancer_update(eid):
    _, err = require_route("api_settings")
    if err: return err
    data = request.get_json(silent=True) or {}
    conn = db()
    row = conn.execute("SELECT id, name FROM api_balancer_entries WHERE id = ?", (eid,)).fetchone()
    if not row:
        return jsonify({"error": "Не найдено"}), 404
    fields = []
    args = []
    if "name" in data:
        name = (data.get("name") or "").strip()
        if not API_ENTRY_NAME_RE.match(name):
            return jsonify({"error": "Имя: 1..128 символов, латиница/кириллица, цифры, пробел, точка, дефис, подчёркивание"}), 400
        if name != row["name"] and conn.execute(
                "SELECT 1 FROM api_balancer_entries WHERE name = ? AND id <> ?",
                (name, eid)).fetchone():
            return jsonify({"error": f"Запись «{name}» уже существует"}), 409
        fields.append("name = ?"); args.append(name)
    if "path" in data:
        path = (data.get("path") or "").strip()
        if not MS_PATH_RE.match(path):
            return jsonify({"error": "Недопустимый путь nginx-конфига"}), 400
        fields.append("path = ?"); args.append(path)
    if "search_keys" in data:
        grouped, err_msg = _api_keys_validate(data.get("search_keys") or {}, conn)
        if err_msg:
            return jsonify({"error": err_msg}), 400
        fields.append("search_keys = ?"); args.append(json.dumps(grouped))
    if not fields:
        return jsonify({"ok": True, "noop": True})
    fields.append("updated_at = ?"); args.append(int(time.time()))
    args.append(eid)
    conn.execute(f"UPDATE api_balancer_entries SET {', '.join(fields)} WHERE id = ?", args)
    conn.commit()
    return jsonify({"ok": True})


@app.delete("/api/api-balancer/entries/<int:eid>")
def api_balancer_delete(eid):
    _, err = require_route("api_settings")
    if err: return err
    conn = db()
    res = conn.execute("DELETE FROM api_balancer_entries WHERE id = ?", (eid,))
    if res.rowcount == 0:
        return jsonify({"error": "Не найдено"}), 404
    conn.commit()
    return jsonify({"ok": True})


@app.post("/api/api-balancer/rotation")
def api_balancer_rotation():
    """Реальное состояние «в ротации» по API-записям, на ВНЕШНЕМ nginx.
    body: {entry_ids?: [id, ...]} — если пусто, опрашиваются все записи.
    Возвращает: {results: {entry_id: {key: True/False/null}}, paths: {entry_id: path}}.
    """
    _, err = require_route("Balancer")
    if err: return err
    data = request.get_json(silent=True) or {}
    requested = data.get("entry_ids")
    rows = db().execute(
        "SELECT id, name, path, search_keys FROM api_balancer_entries ORDER BY position, name"
    ).fetchall()
    if isinstance(requested, list) and requested:
        wanted = {int(x) for x in requested if isinstance(x, int) or (isinstance(x, str) and x.isdigit())}
        rows = [r for r in rows if r["id"] in wanted]
    if not rows:
        return jsonify({"results": {}, "paths": {}})

    creds = get_balancer_creds()
    if not creds or not creds.get("ext_ssh_host"):
        return jsonify({"error": "SSH внешнего балансировщика не настроен"}), 400
    try:
        ssh = _ext_ssh_open(creds)
    except BalancerError as e:
        return jsonify({"error": str(e)}), 502
    sudo = creds.get("ext_ssh_sudo_pwd") or ""

    file_cache = {}
    def get_first_lines(path):
        if path in file_cache: return file_cache[path]
        rc, content, _err = _ssh_run_sudo(ssh, sudo,
                                          f"head -n {NGINX_SEARCH_LINES} {shlex.quote(path)}")
        if rc != 0:
            file_cache[path] = None
            return None
        file_cache[path] = content.split("\n")[:NGINX_SEARCH_LINES]
        return file_cache[path]

    results = {}
    paths_out = {}
    try:
        for r in rows:
            keys = _api_keys_flatten_keys(_api_keys_parse(r["search_keys"]))
            paths_out[str(r["id"])] = r["path"]
            results[str(r["id"])] = {}
            lines = get_first_lines(r["path"])
            for k in keys:
                if not lines:
                    results[str(r["id"])][k] = None
                    continue
                stripped = k.lower()
                rgx = re.compile(r"\b" + re.escape(stripped) + r"\b", re.IGNORECASE)
                found_un = False
                found_co = False
                for ln in lines:
                    if rgx.search(ln):
                        if ln.lstrip().startswith("#"):
                            found_co = True
                        else:
                            found_un = True
                        break
                if found_un:
                    results[str(r["id"])][k] = True
                elif found_co:
                    results[str(r["id"])][k] = False
                else:
                    results[str(r["id"])][k] = None
    finally:
        try: ssh.close()
        except Exception: pass

    return jsonify({"results": results, "paths": paths_out})


# ===== Учётки для балансировки =====
@app.get("/api/balancer-credentials")
def balancer_creds_get():
    _, err = require_route("balancer_creds")
    if err: return err
    row = db().execute("SELECT * FROM balancer_credentials WHERE id = 1").fetchone()
    if not row:
        return jsonify({})
    return jsonify({
        "ssh_host":    row["ssh_host"]   or "",
        "ssh_port":    row["ssh_port"]   or 22,
        "ssh_login":   row["ssh_login"]  or "",
        "ssh_password_set": bool(row["ssh_password"]),
        "ssh_sudo_pwd_set": bool(row["ssh_sudo_pwd"]),
        "ext_ssh_host":    row["ext_ssh_host"]   or "",
        "ext_ssh_port":    row["ext_ssh_port"]   or 22,
        "ext_ssh_login":   row["ext_ssh_login"]  or "",
        "ext_ssh_password_set": bool(row["ext_ssh_password"]),
        "ext_ssh_sudo_pwd_set": bool(row["ext_ssh_sudo_pwd"]),
        "win_login":   row["win_login"]  or "",
        "win_password_set": bool(row["win_password"]),
        "stunnel_host":    row["stunnel_host"]   or "",
        "stunnel_port":    row["stunnel_port"]   or 22,
        "stunnel_login":   row["stunnel_login"]  or "",
        "stunnel_password_set": bool(row["stunnel_password"]),
        "stunnel_sudo_pwd_set": bool(row["stunnel_sudo_pwd"]),
        "stunnel_brs_host":    row["stunnel_brs_host"]   or "",
        "stunnel_brs_port":    row["stunnel_brs_port"]   or 22,
        "stunnel_brs_login":   row["stunnel_brs_login"]  or "",
        "stunnel_brs_password_set": bool(row["stunnel_brs_password"]),
        "stunnel_brs_sudo_pwd_set": bool(row["stunnel_brs_sudo_pwd"]),
        "updated_at":  row["updated_at"] or 0,
        "updated_by":  row["updated_by"] or "",
    })


@app.post("/api/balancer-credentials")
def balancer_creds_set():
    u, err = require_route("balancer_creds")
    if err: return err
    data = request.get_json(silent=True) or {}
    conn = db()
    cur = conn.execute("SELECT * FROM balancer_credentials WHERE id = 1").fetchone()
    fields = []
    args = []
    def upd(name, val):
        fields.append(f"{name} = ?")
        args.append(val)
    if "ssh_host" in data:    upd("ssh_host",  (data["ssh_host"]  or "").strip())
    if "ssh_port" in data:
        try:
            p = int(data["ssh_port"]); assert 1 <= p <= 65535
        except Exception:
            return jsonify({"error": "ssh_port должен быть числом 1..65535"}), 400
        upd("ssh_port", p)
    if "ssh_login" in data:   upd("ssh_login", (data["ssh_login"] or "").strip())
    if "ext_ssh_host" in data:  upd("ext_ssh_host",  (data["ext_ssh_host"] or "").strip())
    if "ext_ssh_login" in data: upd("ext_ssh_login", (data["ext_ssh_login"] or "").strip())
    if "ext_ssh_port" in data:
        try:
            ep = int(data["ext_ssh_port"]); assert 1 <= ep <= 65535
        except Exception:
            return jsonify({"error": "ext_ssh_port должен быть числом 1..65535"}), 400
        upd("ext_ssh_port", ep)
    if "win_login" in data:   upd("win_login", (data["win_login"] or "").strip())
    if "stunnel_host" in data:  upd("stunnel_host",  (data["stunnel_host"] or "").strip())
    if "stunnel_login" in data: upd("stunnel_login", (data["stunnel_login"] or "").strip())
    if "stunnel_port" in data:
        try:
            sp = int(data["stunnel_port"]); assert 1 <= sp <= 65535
        except Exception:
            return jsonify({"error": "stunnel_port должен быть числом 1..65535"}), 400
        upd("stunnel_port", sp)
    if "stunnel_brs_host" in data:  upd("stunnel_brs_host",  (data["stunnel_brs_host"] or "").strip())
    if "stunnel_brs_login" in data: upd("stunnel_brs_login", (data["stunnel_brs_login"] or "").strip())
    if "stunnel_brs_port" in data:
        try:
            sbp = int(data["stunnel_brs_port"]); assert 1 <= sbp <= 65535
        except Exception:
            return jsonify({"error": "stunnel_brs_port должен быть числом 1..65535"}), 400
        upd("stunnel_brs_port", sbp)
    # Пароли: если поле прислано пустой строкой — оставляем как есть (не затираем).
    # Если непустое — шифруем и пишем.
    for fld in ("ssh_password", "ssh_sudo_pwd",
                "ext_ssh_password", "ext_ssh_sudo_pwd",
                "win_password",
                "stunnel_password", "stunnel_sudo_pwd",
                "stunnel_brs_password", "stunnel_brs_sudo_pwd"):
        if fld in data and (data[fld] or "") != "":
            upd(fld, encrypt_secret(data[fld]))
    if not fields:
        return jsonify({"ok": True, "noop": True})
    fields.append("updated_at = ?"); args.append(int(time.time()))
    fields.append("updated_by = ?"); args.append(u["username"])
    args.append(1)
    conn.execute(f"UPDATE balancer_credentials SET {', '.join(fields)} WHERE id = ?", args)
    conn.commit()
    return jsonify({"ok": True})


ABOUT_MAX_BYTES = 512 * 1024


@app.get("/api/about")
def about_get():
    _, err = require_route("about")
    if err: return err
    row = db().execute(
        "SELECT content, updated_at, updated_by FROM about_page WHERE id = 1"
    ).fetchone()
    if not row:
        return jsonify({"content": "", "updated_at": 0, "updated_by": None})
    return jsonify({
        "content":    row["content"] or "",
        "updated_at": row["updated_at"] or 0,
        "updated_by": row["updated_by"],
    })


@app.post("/api/about")
def about_set():
    u, err = require_admin()
    if err: return err
    data = request.get_json(silent=True) or {}
    content = data.get("content", "")
    if not isinstance(content, str):
        return jsonify({"error": "Поле content должно быть строкой"}), 400
    if len(content.encode("utf-8")) > ABOUT_MAX_BYTES:
        return jsonify({"error": f"Превышен лимит {ABOUT_MAX_BYTES // 1024} KB"}), 400
    now = int(time.time())
    db().execute(
        "UPDATE about_page SET content = ?, updated_at = ?, updated_by = ? WHERE id = 1",
        (content, now, u["username"]),
    )
    db().commit()
    return jsonify({"ok": True, "updated_at": now, "updated_by": u["username"]})


def get_balancer_creds():
    """Внутренняя функция — расшифровывает все поля и возвращает dict.
    Используется оркестратором; в API наружу не отдаётся."""
    row = db().execute("SELECT * FROM balancer_credentials WHERE id = 1").fetchone()
    if not row:
        return None
    return {
        "ssh_host":     row["ssh_host"]   or "",
        "ssh_port":     row["ssh_port"]   or 22,
        "ssh_login":    row["ssh_login"]  or "",
        "ssh_password": decrypt_secret(row["ssh_password"]),
        "ssh_sudo_pwd": decrypt_secret(row["ssh_sudo_pwd"]),
        "ext_ssh_host":     row["ext_ssh_host"]   or "",
        "ext_ssh_port":     row["ext_ssh_port"]   or 22,
        "ext_ssh_login":    row["ext_ssh_login"]  or "",
        "ext_ssh_password": decrypt_secret(row["ext_ssh_password"]),
        "ext_ssh_sudo_pwd": decrypt_secret(row["ext_ssh_sudo_pwd"]),
        "win_login":    row["win_login"]  or "",
        "win_password": decrypt_secret(row["win_password"]),
        "stunnel_host":     row["stunnel_host"]   or "",
        "stunnel_port":     row["stunnel_port"]   or 22,
        "stunnel_login":    row["stunnel_login"]  or "",
        "stunnel_password": decrypt_secret(row["stunnel_password"]),
        "stunnel_sudo_pwd": decrypt_secret(row["stunnel_sudo_pwd"]),
        "stunnel_brs_host":     row["stunnel_brs_host"]   or "",
        "stunnel_brs_port":     row["stunnel_brs_port"]   or 22,
        "stunnel_brs_login":    row["stunnel_brs_login"]  or "",
        "stunnel_brs_password": decrypt_secret(row["stunnel_brs_password"]),
        "stunnel_brs_sudo_pwd": decrypt_secret(row["stunnel_brs_sudo_pwd"]),
    }


# ===== Группы (плечи) =====
MS_GROUP_TITLE_RE = re.compile(r"^[A-Za-zА-Яа-яЁё0-9 ._\-]{1,64}$")


@app.get("/api/ms/groups")
def ms_groups_list():
    _, err = require_route("services")
    if err: return err
    rows = db().execute(
        "SELECT g.group_key, g.title, g.position, "
        "       (SELECT COUNT(*) FROM ms_node_settings n WHERE n.group_key = g.group_key) AS nodes_count "
        "FROM ms_groups g ORDER BY g.position, g.group_key"
    ).fetchall()
    return jsonify({"groups": [
        {"key": r["group_key"], "title": r["title"], "position": r["position"], "nodes_count": r["nodes_count"]}
        for r in rows
    ]})


@app.post("/api/ms/groups")
def ms_groups_create():
    _, err = require_route("nodes_catalog")
    if err: return err
    data = request.get_json(silent=True) or {}
    key   = (data.get("key")   or "").strip().lower()
    title = (data.get("title") or "").strip()
    if not key or not title:
        return jsonify({"error": "Заполните ключ и название группы"}), 400
    if not MS_GROUP_RE.match(key):
        return jsonify({"error": "Ключ: маленькая латиница, цифры, дефис, подчёркивание (до 32 символов)"}), 400
    if not MS_GROUP_TITLE_RE.match(title):
        return jsonify({"error": "Название: латиница/кириллица, цифры, пробел, точка, дефис, подчёркивание (до 64 символов)"}), 400
    conn = db()
    if conn.execute("SELECT 1 FROM ms_groups WHERE group_key = ?", (key,)).fetchone():
        return jsonify({"error": f"Группа «{key}» уже существует"}), 409
    pos_row = conn.execute("SELECT COALESCE(MAX(position), -1) + 1 FROM ms_groups").fetchone()
    pos = pos_row[0] if pos_row else 0
    now = int(time.time())
    conn.execute(
        "INSERT INTO ms_groups (group_key, title, position, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (key, title, pos, now, now),
    )
    conn.commit()
    return jsonify({"ok": True, "key": key})


@app.delete("/api/ms/groups/<key>")
def ms_groups_delete(key):
    _, err = require_route("nodes_catalog")
    if err: return err
    if not MS_GROUP_RE.match(key):
        return jsonify({"error": "Недопустимый ключ"}), 400
    conn = db()
    cnt = conn.execute("SELECT COUNT(*) FROM ms_node_settings WHERE group_key = ?", (key,)).fetchone()[0]
    if cnt > 0:
        return jsonify({"error": f"В группе ещё {cnt} нод. Сначала удалите или перенесите их."}), 409
    res = conn.execute("DELETE FROM ms_groups WHERE group_key = ?", (key,))
    if res.rowcount == 0:
        return jsonify({"error": "Группа не найдена"}), 404
    conn.commit()
    return jsonify({"ok": True})


# ============================================================
# ===== Оркестратор микросервисов =============================
# ============================================================

SVC_CONSOLE_RETENTION_SEC = 7 * 24 * 3600
SVC_CONSOLE_MAX_ROWS_PER_KIND = 50_000  # hard cap: 50k для 'action' и столько же для 'error'
INCEPTUM_POLL_INTERVAL = 3       # секунды между опросами /api/instances
INCEPTUM_BALANCE_WAIT  = 60      # пауза для разбалансировки nginx между шагами
INCEPTUM_HANG_WARN_SEC = 60      # через сколько начинаем писать «зависло»
INCEPTUM_STOP_WAIT      = 90     # ждём Stopped после Stop, потом Kill
INCEPTUM_KILL_WAIT      = 90     # ждём Stopped после Kill
INCEPTUM_START_WAIT     = 90     # ждём Started после Start (на одну попытку)
INCEPTUM_TIMEOUT_ACTION = 120    # HTTP read-timeout для POST Stop/Start/Kill


def svc_log(kind, level, message, run_id=None, username=None):
    """Запись в общий лог оркестратора. Безопасна из любого потока."""
    try:
        conn = sqlite3.connect(DB_PATH)
        try:
            now = int(time.time())
            conn.execute(
                "INSERT INTO svc_console (ts, kind, level, message, username, run_id) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (now, kind, level, message, username, run_id),
            )
            conn.execute(
                "DELETE FROM svc_console WHERE ts < ?",
                (now - SVC_CONSOLE_RETENTION_SEC,),
            )
            # Жёсткий cap по числу строк отдельно для каждого kind ('action' / 'error'),
            # на случай всплеска логирования, когда ретеншн по времени ещё не сработал.
            conn.execute(
                "DELETE FROM svc_console WHERE kind = ? AND id NOT IN ("
                "  SELECT id FROM svc_console WHERE kind = ? ORDER BY id DESC LIMIT ?"
                ")",
                (kind, kind, SVC_CONSOLE_MAX_ROWS_PER_KIND),
            )
            conn.commit()
        finally:
            conn.close()
    except Exception:
        app.logger.exception("svc_log failed")


def _orch_acquire(action, username):
    """Взять глобальный замок. (ok, run_id, current_state_dict_if_busy).
    При успехе также сохраняет в замке максимальные id svc_console (action/error),
    чтобы все клиенты по этой отсечке почистили UI-лог при смене run_id."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute("SELECT * FROM svc_run_lock WHERE id = 1").fetchone()
        if row and row["run_id"]:
            return False, None, dict(row)
        run_id = str(uuid.uuid4())
        cut_action = conn.execute(
            "SELECT COALESCE(MAX(id), 0) FROM svc_console WHERE kind='action'"
        ).fetchone()[0] or 0
        cut_error = conn.execute(
            "SELECT COALESCE(MAX(id), 0) FROM svc_console WHERE kind='error'"
        ).fetchone()[0] or 0
        conn.execute(
            "UPDATE svc_run_lock SET run_id=?, username=?, action=?, "
            "started_at=?, stopped_at=NULL, cancel_requested=0, "
            "log_cutoff_action=?, log_cutoff_error=?, "
            "progress_done=0, progress_total=0 WHERE id=1",
            (run_id, username, action, int(time.time()), cut_action, cut_error),
        )
        conn.commit()
        return True, run_id, None
    finally:
        conn.close()


def _orch_release(run_id):
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            "UPDATE svc_run_lock SET run_id=NULL, stopped_at=?, cancel_requested=0 "
            "WHERE id=1 AND run_id=?",
            (int(time.time()), run_id),
        )
        conn.commit()
    finally:
        conn.close()


def _orch_state():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute("SELECT * FROM svc_run_lock WHERE id = 1").fetchone()
        if not row:
            return {"busy": False, "log_cutoff_action": 0, "log_cutoff_error": 0}
        common = {
            # Эти отсечки нужны фронту даже после завершения прогона,
            # чтобы не подтягивать в UI логи предыдущих операций.
            "log_cutoff_action": row["log_cutoff_action"] or 0,
            "log_cutoff_error":  row["log_cutoff_error"]  or 0,
        }
        if row["run_id"]:
            return {
                "busy": True,
                "run_id": row["run_id"],
                "username": row["username"],
                "action": row["action"],
                "started_at": row["started_at"],
                "cancel_requested": bool(row["cancel_requested"]),
                "progress_done":     row["progress_done"]  or 0,
                "progress_total":    row["progress_total"] or 0,
                **common,
            }
        return {"busy": False, **common}
    finally:
        conn.close()


def _orch_progress_set_total(run_id, total):
    try:
        conn = sqlite3.connect(DB_PATH)
        try:
            conn.execute(
                "UPDATE svc_run_lock SET progress_total=?, progress_done=0 "
                "WHERE id=1 AND run_id=?",
                (int(total), run_id),
            )
            conn.commit()
        finally:
            conn.close()
    except Exception:
        app.logger.exception("progress_set_total failed")


def _orch_progress_inc(run_id, n=1):
    if n <= 0:
        return
    try:
        conn = sqlite3.connect(DB_PATH)
        try:
            conn.execute(
                "UPDATE svc_run_lock "
                "SET progress_done = MIN(COALESCE(progress_done,0) + ?, "
                "                        COALESCE(progress_total,0)) "
                "WHERE id=1 AND run_id=?",
                (int(n), run_id),
            )
            conn.commit()
        finally:
            conn.close()
    except Exception:
        app.logger.exception("progress_inc failed")


def _orch_request_cancel(run_id):
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            "UPDATE svc_run_lock SET cancel_requested=1 WHERE id=1 AND run_id=?",
            (run_id,),
        )
        conn.commit()
    finally:
        conn.close()


def _orch_is_cancelled(run_id):
    """Проверяется в worker-потоке. Используем DB-флаг, чтобы работало
    между gunicorn-воркерами (worker A держит поток, worker B обработал /cancel)."""
    try:
        conn = sqlite3.connect(DB_PATH)
        try:
            row = conn.execute(
                "SELECT cancel_requested FROM svc_run_lock WHERE id=1 AND run_id=?",
                (run_id,),
            ).fetchone()
            return bool(row and row[0])
        finally:
            conn.close()
    except Exception:
        return False


# ===== Inceptum REST: команды =====
def _inceptum_post(host, app_name, action, auth):
    """POST /api/Instances/<app>/<Stop|Start|Kill>. Возвращает (rc, text).
    rc > 0 — код ответа от Inceptum.
    rc = -1 — read-timeout: HTTP-ответа не дождались, но запрос ушёл.
              Дальше надо проверять результат через polling /api/instances.
    rc = 0  — прочие ошибки (connect failed, библиотека отсутствует).
    """
    if requests is None or auth is None:
        return 0, "no-auth"
    url = f"http://{host}:{INCEPTUM_PORT}/api/Instances/{app_name}/{action}"
    try:
        r = requests.post(url, auth=auth,
                          timeout=(10, INCEPTUM_TIMEOUT_ACTION),
                          headers={"Content-Type": "application/json"}, data="")
        return r.status_code, (r.text or "")[:300]
    except requests.exceptions.ReadTimeout as e:
        return -1, f"read timeout: {e}"
    except Exception as e:
        return 0, str(e)


def _inceptum_wait_status(host, app_name, target, auth, run_id, label, deadline_sec=None):
    """Опрашивает /api/instances каждые ~3с пока статус не станет target.
    Возвращает True, если дождались target.
    Возвращает False при: cancel пользователем либо истечении deadline_sec.
    Если deadline_sec=None — ждём без ограничения (только по cancel).
    """
    last_status = None
    started = time.time()
    last_warn_ts = 0
    while not _orch_is_cancelled(run_id):
        instances = _inceptum_get_instances(host, auth)
        if instances is None:
            now = time.time()
            if now - last_warn_ts > 30:
                svc_log("action", "warn", f"{label}: нода не отвечает, повторяю", run_id)
                last_warn_ts = now
            if deadline_sec is not None and (time.time() - started) >= deadline_sec:
                return False
            time.sleep(INCEPTUM_POLL_INTERVAL)
            continue
        match = next((i for i in instances if i.get("name") == app_name), None)
        if not match:
            now = time.time()
            if now - last_warn_ts > 30:
                svc_log("action", "warn", f"{label}: сервис не найден в инстансах", run_id)
                last_warn_ts = now
            if deadline_sec is not None and (time.time() - started) >= deadline_sec:
                return False
            time.sleep(INCEPTUM_POLL_INTERVAL)
            continue
        status = match.get("status", "")
        if status != last_status:
            svc_log("action", "info", f"{label} → {status}", run_id)
            last_status = status
        if status == target:
            return True
        elapsed = time.time() - started
        if deadline_sec is not None and elapsed >= deadline_sec:
            return False
        if elapsed > INCEPTUM_HANG_WARN_SEC and (time.time() - last_warn_ts) > 60:
            svc_log("error", "warn",
                    f"{label}: в статусе «{status}» уже {int(elapsed)}с (ждём {target}). "
                    "Прервать вручную или дождаться.", run_id)
            last_warn_ts = time.time()
        time.sleep(INCEPTUM_POLL_INTERVAL)
    return False  # отмена


# ===== Главный воркер =====
def _orch_load_context(pairs):
    """По списку (host_key, service_name) собирает справочную инфу из БД:
       - nodes_map: {key: {group, host, role}}
       - svc_paths_int: {service_name: [paths]} — пути внутреннего балансера
       - svc_paths_ext: {service_name: [paths]} — пути внешнего балансера
       - groups:    [{key, title, position}] в порядке.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        node_keys = sorted({hk for hk, _ in pairs})
        if node_keys:
            ph = ",".join(["?"] * len(node_keys))
            rows = conn.execute(
                f"SELECT node_key, group_key, host, role FROM ms_node_settings WHERE node_key IN ({ph})",
                node_keys,
            ).fetchall()
            nodes_map = {r["node_key"]: dict(r) for r in rows}
        else:
            nodes_map = {}
        svc_names = sorted({s for _, s in pairs})
        if svc_names:
            ph2 = ",".join(["?"] * len(svc_names))
            rows = conn.execute(
                f"SELECT name, balancer_paths, balancer_paths_ext FROM ms_catalog WHERE name IN ({ph2})",
                svc_names,
            ).fetchall()
            svc_paths_int = {r["name"]: json.loads(r["balancer_paths"]     or "[]") for r in rows}
            svc_paths_ext = {r["name"]: json.loads(r["balancer_paths_ext"] or "[]") for r in rows}
        else:
            svc_paths_int = {}
            svc_paths_ext = {}
        groups = [dict(r) for r in conn.execute(
            "SELECT group_key, title, position FROM ms_groups ORDER BY position, group_key"
        ).fetchall()]
    finally:
        conn.close()
    return nodes_map, svc_paths_int, svc_paths_ext, groups


def _orch_group_pairs(pairs, nodes_map):
    """Группирует пары по плечам и роли. {group_key: {'master': [...], 'slaves': [...]}}"""
    grouped = {}
    for hk, svc in pairs:
        nd = nodes_map.get(hk)
        if not nd:
            continue
        gk = nd["group_key"]
        bucket = grouped.setdefault(gk, {"master": [], "slaves": []})
        entry = {"host_key": hk, "host": nd["host"] or hk, "service": svc}
        (bucket["master"] if (nd.get("role") or "").lower() == "master" else bucket["slaves"]).append(entry)
    return grouped


def _orch_rollback_files(client, sudo_pwd, backups, run_id, plecho_title):
    """Восстанавливает исходное содержимое файлов (path -> original text).
    Вызывается при падении nginx -t / reload, либо при ошибке посреди drain/return,
    чтобы не оставлять сломанный конфиг на диске."""
    if not backups:
        return
    for path, original in backups.items():
        try:
            tmp_path = f"/tmp/balancer_rb_{int(time.time() * 1000)}_{os.getpid()}.tmp"
            sftp = client.open_sftp()
            try:
                with sftp.file(tmp_path, "w") as fh:
                    fh.write(original)
                sftp.chmod(tmp_path, 0o644)
            finally:
                try: sftp.close()
                except Exception: pass
            rc, out, err = _ssh_run_sudo(
                client, sudo_pwd, f"cp {shlex.quote(tmp_path)} {shlex.quote(path)}"
            )
            try: _ssh_run(client, f"rm -f {shlex.quote(tmp_path)}")
            except Exception: pass
            if rc == 0:
                svc_log("action", "warn",
                        f"[{plecho_title}] откат {path}: исходный конфиг восстановлен",
                        run_id)
            else:
                svc_log("error", "err",
                        f"[{plecho_title}] ОТКАТ {path} НЕ УДАЛСЯ: {(err or out).strip()}. "
                        "Восстанови вручную, nginx reload сейчас ОПАСЕН.",
                        run_id)
        except Exception as e:
            svc_log("error", "err",
                    f"[{plecho_title}] исключение при откате {path}: {e}. "
                    "Восстанови вручную, nginx reload сейчас ОПАСЕН.",
                    run_id)


_DIR_RU = {"drain": "вывод из ротации", "return": "ввод в ротацию"}


def _orch_apply_balancing(entries, svc_paths, ssh, sudo_pwd, run_id,
                          plecho_title, direction, bal_tag="int"):
    """Drain/Return для всех (host, svc) этого плеча на ОДНОМ балансере.
    bal_tag: "int" или "ext" — попадает в префикс логов.
    Группирует по path (одна правка файла за всех нод сразу).
    Возвращает True (что-то изменилось), False (всё уже было), None (ошибка).
    Если на этом балансере для всех сервисов в entries нет путей — возвращает False
    (no-op), без ошибки и без вызова nginx -t."""
    pre = f"[{bal_tag}][{plecho_title}]"
    dir_ru = _DIR_RU.get(direction, direction)

    path_to_keys = {}
    for e in entries:
        paths = svc_paths.get(e["service"], [])
        if not paths:
            continue
        for p in paths:
            path_to_keys.setdefault(p, set()).add(e["host_key"])

    if not path_to_keys:
        # Балансер не задействован для этой группы — тихо выходим.
        return False

    try:
        _nginx_test(ssh, sudo_pwd)
    except BalancerError as e:
        svc_log("error", "err", f"{pre} {e}\nSTOP", run_id)
        return None

    backups = {}   # path -> original content (для отката, если что-то упадёт)
    any_changed = False
    for path, keys_set in path_to_keys.items():
        keys = sorted(keys_set)
        try:
            res = _balancer_apply(ssh, sudo_pwd, path, keys, direction)
        except BalancerError as e:
            svc_log("error", "err", f"{pre} {dir_ru} {path}: {e}\nSTOP", run_id)
            _orch_rollback_files(ssh, sudo_pwd, backups, run_id, f"{bal_tag}|{plecho_title}")
            return None
        if res["changed"]:
            any_changed = True
            backups[path] = res["original"]
            svc_log("action", "ok",
                    f"{pre} {dir_ru} {path}: {len(res['modified_lines'])} стр. ({', '.join(keys)})",
                    run_id)
        else:
            svc_log("action", "info",
                    f"{pre} {dir_ru} {path}: уже в нужном состоянии ({', '.join(keys)})",
                    run_id)

    if any_changed:
        try:
            _nginx_test(ssh, sudo_pwd)
            _nginx_reload(ssh, sudo_pwd)
        except BalancerError as e:
            svc_log("error", "err", f"{pre} {e}", run_id)
            _orch_rollback_files(ssh, sudo_pwd, backups, run_id, f"{bal_tag}|{plecho_title}")
            svc_log("error", "err", f"{pre} STOP", run_id)
            return None
        svc_log("action", "ok", f"{pre} nginx -t ok, reload ok", run_id)
    return any_changed


def _orch_apply_balancing_both(entries, svc_paths_int, svc_paths_ext,
                               ssh_int, sudo_int, ssh_ext, sudo_ext,
                               run_id, plecho_title, direction):
    """Применяет drain/return сразу на обоих балансерах (если есть пути на ext
    и ext-SSH открыт). Возвращает True/False/None как _orch_apply_balancing.
    None означает что хоть один балансер упал — оркестратор должен прерваться."""
    res_int = _orch_apply_balancing(entries, svc_paths_int, ssh_int, sudo_int,
                                    run_id, plecho_title, direction, "int")
    if res_int is None:
        return None

    needs_ext = ssh_ext is not None and any(
        svc_paths_ext.get(e["service"]) for e in entries
    )
    if not needs_ext:
        return res_int

    res_ext = _orch_apply_balancing(entries, svc_paths_ext, ssh_ext, sudo_ext,
                                    run_id, plecho_title, direction, "ext")
    if res_ext is None:
        # Внутренний уже применён — внешний упал. Не откатываем int автоматически,
        # просто прекращаем серию: оркестратор зафиксирует STOP, оператор разберётся.
        svc_log("error", "err",
                f"[ext][{plecho_title}] STOP — внутренний балансер уже изменён, "
                "внешний — нет. Разбирайся вручную.",
                run_id)
        return None
    return bool(res_int or res_ext)


def _orch_restart_one(entry, auth, run_id, plecho_title, role_label):
    """Полный TZ-флоу для одной пары (host, service):
      Stop → ждём Stopped (до INCEPTUM_STOP_WAIT)
         не остановился → Kill → ждём Stopped (до INCEPTUM_KILL_WAIT)
      Start → ждём Started (до INCEPTUM_START_WAIT)
         не стартанул → Kill + Start → ждём Started (до INCEPTUM_START_WAIT)
         всё равно не стартанул → ошибка.
    Возвращает True только если пара в финале в Started.
    """
    host, app_name, hk = entry["host"], entry["service"], entry["host_key"]
    label = f"[{plecho_title}] {role_label} {hk} :: {app_name}"

    def _send(action):
        svc_log("action", "info", f"{label}: посылаю {action}", run_id)
        rc, body = _inceptum_post(host, app_name, action, auth)
        # rc > 0 и не 2xx — настоящая ошибка Inceptum
        if rc > 0 and (rc < 200 or rc >= 300):
            svc_log("error", "err", f"{label}: {action} HTTP {rc}: {body}", run_id)
            return False
        # rc == 0 — сетевой сбой до отправки (connect/DNS)
        if rc == 0:
            svc_log("error", "err", f"{label}: {action} не отправлен: {body}", run_id)
            return False
        # rc == -1 — read-timeout: запрос ушёл, Inceptum ещё обрабатывает; ок, проверим статус
        if rc == -1:
            svc_log("action", "info", f"{label}: {action} — HTTP-ответа не дождались за {INCEPTUM_TIMEOUT_ACTION}с, проверяю статус", run_id)
        return True

    # === STOP ===
    if not _send("Stop"):
        return False
    if not _inceptum_wait_status(host, app_name, "Stopped", auth, run_id, label,
                                  deadline_sec=INCEPTUM_STOP_WAIT):
        if _orch_is_cancelled(run_id):
            return False
        svc_log("action", "warn",
                f"{label}: не остановился за {INCEPTUM_STOP_WAIT}с, посылаю Kill", run_id)
        if not _send("Kill"):
            return False
        if not _inceptum_wait_status(host, app_name, "Stopped", auth, run_id, label,
                                      deadline_sec=INCEPTUM_KILL_WAIT):
            svc_log("error", "err",
                    f"{label}: не остановился даже после Kill за {INCEPTUM_KILL_WAIT}с, STOP", run_id)
            return False

    if _orch_is_cancelled(run_id):
        return False

    # === START, попытка 1 ===
    if not _send("Start"):
        return False
    if _inceptum_wait_status(host, app_name, "Started", auth, run_id, label,
                              deadline_sec=INCEPTUM_START_WAIT):
        svc_log("action", "ok", f"{label}: перезагрузка готова", run_id)
        return True

    if _orch_is_cancelled(run_id):
        return False

    # === Не стартанул за 90с → Kill + Start, попытка 2 ===
    svc_log("action", "warn",
            f"{label}: не стартанул за {INCEPTUM_START_WAIT}с, Kill + повтор Start", run_id)
    # Kill здесь — «на всякий случай» (приложение могло зависнуть в Starting).
    # Ошибку Kill не считаем фатальной: если процесс уже Stopped, Inceptum может вернуть не-2xx.
    _inceptum_post(host, app_name, "Kill", auth)
    _inceptum_wait_status(host, app_name, "Stopped", auth, run_id, label,
                          deadline_sec=INCEPTUM_KILL_WAIT)

    if _orch_is_cancelled(run_id):
        return False

    if not _send("Start"):
        return False
    if not _inceptum_wait_status(host, app_name, "Started", auth, run_id, label,
                                  deadline_sec=INCEPTUM_START_WAIT):
        svc_log("error", "err",
                f"{label}: не стартанул даже после Kill+Start, STOP", run_id)
        return False
    svc_log("action", "ok", f"{label}: перезагрузка готова (со 2-й попытки)", run_id)
    return True


def _orch_simple_one(entry, auth, run_id, plecho_title, action_kind, target):
    """Для start/stop: одна команда + ожидание целевого статуса."""
    host, app_name, hk = entry["host"], entry["service"], entry["host_key"]
    label = f"[{plecho_title}] {hk} :: {app_name}"
    rest_action = "Stop" if action_kind == "stop" else "Start"
    svc_log("action", "info", f"{label}: посылаю {rest_action}", run_id)
    rc, body = _inceptum_post(host, app_name, rest_action, auth)
    if rc < 200 or rc >= 300:
        svc_log("error", "err", f"{label}: {rest_action} HTTP {rc}: {body}", run_id)
        return False
    ok = _inceptum_wait_status(host, app_name, target, auth, run_id, label)
    if ok:
        verb_ru = "запуск готов" if action_kind == "start" else "остановка готова"
        svc_log("action", "ok", f"{label}: {verb_ru}", run_id)
    return ok


def _orch_sleep_with_cancel(seconds, run_id):
    """Спим N секунд, проверяя cancel каждую секунду."""
    for _ in range(int(seconds)):
        if _orch_is_cancelled(run_id):
            return False
        time.sleep(1)
    return True


def _orch_run(action, pairs, balance_wait_sec, run_id, username):
    """Главный поток. Никаких exception — всё в лог.
    balance_wait_sec — пауза после nginx reload (drain/return)."""
    # Фоновый поток не имеет flask request/app-контекста; оборачиваем явно,
    # чтобы помощники типа get_balancer_creds() (использующие db()) работали.
    try:
        ctx = app.app_context()
        ctx.push()
    except Exception:
        ctx = None
    try:
        creds = get_balancer_creds()
        auth = _inceptum_auth(creds)

        # Проверяем учётки
        if action in ("restart", "restart_raw", "start", "stop"):
            if auth is None:
                svc_log("error", "err",
                        "NTLM-учётка не настроена. Зайдите в «Учётки для балансировки».",
                        run_id, username)
                return
        if action in ("restart", "drain", "return"):
            if not creds or not creds.get("ssh_host"):
                svc_log("error", "err",
                        "SSH внутреннего балансировщика не настроен. Зайдите в «Учётки для балансировки».",
                        run_id, username)
                return

        nodes_map, svc_paths_int, svc_paths_ext, groups = _orch_load_context(pairs)
        plechos = _orch_group_pairs(pairs, nodes_map)
        if not plechos:
            svc_log("error", "err", "Нет валидных нод для обработки", run_id)
            return

        # Какие сервисы реально задействованы в этом прогоне
        active_svcs = {s for _, s in pairs}
        # Нужен ли внешний балансер хотя бы одному из них?
        ext_needed = (
            action in ("restart", "drain", "return")
            and any(svc_paths_ext.get(s) for s in active_svcs)
        )
        ext_has_creds = bool(creds and creds.get("ext_ssh_host") and creds.get("ext_ssh_login"))
        if ext_needed and not ext_has_creds:
            svc_log("error", "err",
                    "Для одного из сервисов задан внешний nginx, но SSH-учётка внешнего "
                    "балансировщика не настроена. Зайдите в «Учётки».",
                    run_id, username)
            return

        group_order = [g["group_key"] for g in groups]
        group_titles = {g["group_key"]: g["title"] for g in groups}

        # Открыть SSH если нужно
        ssh_int = None
        ssh_ext = None
        if action in ("restart", "drain", "return"):
            try:
                ssh_int = _ssh_open(creds)
            except BalancerError as e:
                svc_log("error", "err", str(e), run_id)
                return
            if ext_needed:
                try:
                    ssh_ext = _ext_ssh_open(creds)
                except BalancerError as e:
                    svc_log("error", "err", str(e), run_id)
                    try: ssh_int.close()
                    except Exception: pass
                    return

        try:
            verb_map = {
                "restart":     "Перезагрузка с балансировкой",
                "restart_raw": "Перезагрузка без балансировки",
                "start":       "Включение",
                "stop":        "Выключение",
                "drain":       "Вывод из ротации",
                "return":      "Ввод в ротацию",
            }
            total = sum(len(p["master"]) + len(p["slaves"]) for p in plechos.values())
            _orch_progress_set_total(run_id, total)
            bal_scope = (
                "внутр.+внеш." if ssh_ext is not None
                else "внутр." if ssh_int is not None
                else "без nginx"
            )
            svc_log("action", "info",
                    f"=== {verb_map[action]}: {len(plechos)} плеч, {total} пар, "
                    f"балансер: {bal_scope} (запустил {username}) ===",
                    run_id, username)

            sudo_int = (creds or {}).get("ssh_sudo_pwd") or ""
            sudo_ext = (creds or {}).get("ext_ssh_sudo_pwd") or ""
            plecho_keys = [g for g in group_order if g in plechos]

            # ---- Upfront nginx -t: до любых правок ----
            if ssh_int is not None:
                try:
                    _nginx_test(ssh_int, sudo_int)
                    svc_log("action", "info", "[int] nginx -t ok — можно начинать", run_id)
                except BalancerError as e:
                    svc_log("error", "err", f"[int] nginx -t упал до начала операций: {e}\nSTOP", run_id)
                    return
            if ssh_ext is not None:
                try:
                    _nginx_test(ssh_ext, sudo_ext)
                    svc_log("action", "info", "[ext] nginx -t ok — можно начинать", run_id)
                except BalancerError as e:
                    svc_log("error", "err", f"[ext] nginx -t упал до начала операций: {e}\nSTOP", run_id)
                    return

            # ---- DRAIN-only ----
            if action == "drain":
                for gk in plecho_keys:
                    if _orch_is_cancelled(run_id): break
                    title = group_titles.get(gk, gk)
                    plecho = plechos[gk]
                    all_entries = plecho["master"] + plecho["slaves"]
                    if _orch_apply_balancing_both(
                            all_entries, svc_paths_int, svc_paths_ext,
                            ssh_int, sudo_int, ssh_ext, sudo_ext,
                            run_id, title, "drain") is None:
                        return
                    _orch_progress_inc(run_id, len(all_entries))
                return

            # ---- RETURN-only ----
            if action == "return":
                for gk in plecho_keys:
                    if _orch_is_cancelled(run_id): break
                    title = group_titles.get(gk, gk)
                    plecho = plechos[gk]
                    all_entries = plecho["master"] + plecho["slaves"]
                    if _orch_apply_balancing_both(
                            all_entries, svc_paths_int, svc_paths_ext,
                            ssh_int, sudo_int, ssh_ext, sudo_ext,
                            run_id, title, "return") is None:
                        return
                    _orch_progress_inc(run_id, len(all_entries))
                return

            # ---- START / STOP (без балансировки) ----
            if action in ("start", "stop"):
                target = "Started" if action == "start" else "Stopped"
                for gk in plecho_keys:
                    if _orch_is_cancelled(run_id): break
                    title = group_titles.get(gk, gk)
                    plecho = plechos[gk]
                    all_entries = plecho["master"] + plecho["slaves"]
                    with ThreadPoolExecutor(max_workers=min(16, len(all_entries))) as ex:
                        futs = [ex.submit(_orch_simple_one, e, auth, run_id, title, action, target)
                                for e in all_entries]
                        for f in as_completed(futs):
                            f.result()
                            _orch_progress_inc(run_id)
                return

            # ---- RESTART RAW ----
            if action == "restart_raw":
                for gk in plecho_keys:
                    if _orch_is_cancelled(run_id): break
                    title = group_titles.get(gk, gk)
                    plecho = plechos[gk]
                    # Master сначала
                    for e in plecho["master"]:
                        if _orch_is_cancelled(run_id): break
                        if not _orch_restart_one(e, auth, run_id, title, "master"):
                            svc_log("error", "err", f"[{title}] master {e['host_key']} :: {e['service']} провалился, продолжаю", run_id)
                        _orch_progress_inc(run_id)
                    # Slaves параллельно
                    if plecho["slaves"] and not _orch_is_cancelled(run_id):
                        with ThreadPoolExecutor(max_workers=min(16, len(plecho["slaves"]))) as ex:
                            futs = [ex.submit(_orch_restart_one, e, auth, run_id, title, "slave")
                                    for e in plecho["slaves"]]
                            for f in as_completed(futs):
                                f.result()
                                _orch_progress_inc(run_id)
                return

            # ---- RESTART С БАЛАНСИРОВКОЙ ----
            # Логика per-сервис, сервисы обрабатываются последовательно.
            # Для балансируемого сервиса с 2+ плечами — плечо за плечом целиком:
            #   1) drain всего плеча (master + ВСЕ slaves одним апдейтом nginx) → пауза;
            #   2) restart master последовательно;
            #   3) restart slaves параллельно;
            #   4) return в ротацию ТОЛЬКО тех, кто поднялся в Started
            #      (упавшие — в лог ошибок, в ротацию НЕ возвращаются);
            #   → следующее плечо (даже если в этом кто-то не поднялся).
            # Для балансируемого сервиса с 1 плечом — нода за нодой: master, затем
            #   каждый slave отдельно — (drain ноды → пауза → restart → return ноды →
            #   пауза).
            # Для не балансируемого сервиса — master последовательно, slaves
            #   последовательно. Никаких nginx-правок.
            services_order = []
            services_by_name = {}
            for gk, buckets in plechos.items():
                for role_key, entries in (("master", buckets["master"]),
                                          ("slaves", buckets["slaves"])):
                    for e in entries:
                        svc_name = e["service"]
                        if svc_name not in services_by_name:
                            services_by_name[svc_name] = {}
                            services_order.append(svc_name)
                        svc_plechos = services_by_name[svc_name]
                        bucket = svc_plechos.setdefault(gk, {"master": [], "slaves": []})
                        bucket[role_key].append(e)

            for svc_name in services_order:
                if _orch_is_cancelled(run_id): break
                svc_plechos = services_by_name[svc_name]
                has_int = bool(svc_paths_int.get(svc_name))
                has_ext = bool(svc_paths_ext.get(svc_name)) and ssh_ext is not None
                is_balanced = has_int or has_ext
                plechos_in_order = [g for g in plecho_keys if g in svc_plechos]

                if has_int and has_ext: bal_lbl = "балансируемый: внутр.+внеш."
                elif has_int:           bal_lbl = "балансируемый: внутр."
                elif has_ext:           bal_lbl = "балансируемый: внеш."
                else:                   bal_lbl = "не балансируется"

                svc_log("action", "info",
                        f"=== Сервис {svc_name} ({bal_lbl}, плеч: {len(plechos_in_order)}) ===",
                        run_id)

                if not is_balanced:
                    # Ветка: не балансируемый → просто мастер+слейвы sequential, без nginx
                    for gk in plechos_in_order:
                        if _orch_is_cancelled(run_id): break
                        plecho = svc_plechos[gk]
                        title = group_titles.get(gk, gk)
                        for e in plecho["master"]:
                            if _orch_is_cancelled(run_id): break
                            if not _orch_restart_one(e, auth, run_id, title, "master"):
                                svc_log("error", "err",
                                        f"[{title}] master {e['host_key']} :: {e['service']} провалился, продолжаю",
                                        run_id)
                            _orch_progress_inc(run_id)
                        for e in plecho["slaves"]:
                            if _orch_is_cancelled(run_id): break
                            if not _orch_restart_one(e, auth, run_id, title, "slave"):
                                svc_log("error", "err",
                                        f"[{title}] slave {e['host_key']} :: {e['service']} провалился, продолжаю",
                                        run_id)
                            _orch_progress_inc(run_id)
                    continue

                # Балансируемый
                # Для каждого сервиса делаем срез путей: внешний — только если для
                # него реально что-то задано, иначе апдейт пропустится сам.
                svc_paths_int_one = {svc_name: svc_paths_int.get(svc_name, [])}
                svc_paths_ext_one = {svc_name: svc_paths_ext.get(svc_name, [])}

                if len(plechos_in_order) >= 2:
                    # 2+ плеча: плечо за плечом целиком.
                    # Для каждого плеча: drain всего плеча → restart master →
                    # restart slaves параллельно → return в ротацию только тех,
                    # кто поднялся в Started. Упавшие ноды (master или slave)
                    # — в лог ошибок, в ротацию не возвращаем, переходим к
                    # следующему плечу.
                    for gk in plechos_in_order:
                        if _orch_is_cancelled(run_id): break
                        plecho = svc_plechos[gk]
                        title = group_titles.get(gk, gk)
                        master_entries = plecho["master"]
                        slave_entries = plecho["slaves"]
                        all_entries = master_entries + slave_entries
                        if not all_entries:
                            continue

                        svc_log("action", "info",
                                f"=== [{svc_name}] Плечо {title} ===", run_id)

                        # 1) drain всего плеча одним апдейтом nginx
                        drained = _orch_apply_balancing_both(
                            all_entries, svc_paths_int_one, svc_paths_ext_one,
                            ssh_int, sudo_int, ssh_ext, sudo_ext,
                            run_id, title, "drain")
                        if drained is None: return
                        if _orch_is_cancelled(run_id): break
                        if drained:
                            svc_log("action", "info",
                                    f"[{title}] жду {balance_wait_sec}с разбалансировки nginx", run_id)
                            if not _orch_sleep_with_cancel(balance_wait_sec, run_id): break

                        failed_nodes = []

                        # 2) restart master(ов) последовательно
                        for e in master_entries:
                            if _orch_is_cancelled(run_id): break
                            if not _orch_restart_one(e, auth, run_id, title, "master"):
                                failed_nodes.append((e["host_key"], e["service"]))
                            _orch_progress_inc(run_id)
                        if _orch_is_cancelled(run_id): break

                        # 3) restart slaves параллельно
                        if slave_entries:
                            with ThreadPoolExecutor(max_workers=min(16, len(slave_entries))) as ex:
                                futs = {ex.submit(_orch_restart_one, e, auth, run_id, title, "slave"): e
                                        for e in slave_entries}
                                for f in as_completed(futs):
                                    e = futs[f]
                                    if not f.result():
                                        failed_nodes.append((e["host_key"], e["service"]))
                                    _orch_progress_inc(run_id)
                        if _orch_is_cancelled(run_id): break

                        if failed_nodes:
                            bad = ", ".join(f"{hk}::{svc}" for hk, svc in failed_nodes)
                            svc_log("error", "err",
                                    f"[{title}] не вернулись в Started: {bad} — НЕ возвращаю их в ротацию",
                                    run_id)

                        # 4) return в ротацию только поднявшихся
                        failed_set = set(failed_nodes)
                        nodes_to_return = [e for e in all_entries
                                           if (e["host_key"], e["service"]) not in failed_set]
                        if nodes_to_return:
                            returned = _orch_apply_balancing_both(
                                nodes_to_return, svc_paths_int_one, svc_paths_ext_one,
                                ssh_int, sudo_int, ssh_ext, sudo_ext,
                                run_id, title, "return")
                            if returned is None: return
                            if _orch_is_cancelled(run_id): break
                            if returned:
                                svc_log("action", "info",
                                        f"[{title}] жду {balance_wait_sec}с возврата балансировки", run_id)
                                if not _orch_sleep_with_cancel(balance_wait_sec, run_id): break
                    continue

                # 1 плечо балансируемого: нода за нодой
                gk = plechos_in_order[0]
                plecho = svc_plechos[gk]
                title = group_titles.get(gk, gk)
                nodes_in_order = plecho["master"] + plecho["slaves"]
                for e in nodes_in_order:
                    if _orch_is_cancelled(run_id): break
                    role_label = "master" if e in plecho["master"] else "slave"
                    node_lbl = f"{e['host_key']} :: {e['service']}"
                    svc_log("action", "info",
                            f"=== [{svc_name}] {title} :: {role_label} {node_lbl} (1 плечо, нода за нодой) ===",
                            run_id)

                    # drain одной ноды
                    drained = _orch_apply_balancing_both(
                        [e], svc_paths_int_one, svc_paths_ext_one,
                        ssh_int, sudo_int, ssh_ext, sudo_ext,
                        run_id, title, "drain")
                    if drained is None: return
                    if _orch_is_cancelled(run_id): break
                    if drained:
                        svc_log("action", "info",
                                f"[{title}] жду {balance_wait_sec}с разбалансировки nginx", run_id)
                        if not _orch_sleep_with_cancel(balance_wait_sec, run_id): break

                    # restart
                    ok_restart = _orch_restart_one(e, auth, run_id, title, role_label)
                    _orch_progress_inc(run_id)
                    if _orch_is_cancelled(run_id): break

                    if not ok_restart:
                        svc_log("error", "err",
                                f"[{title}] {role_label} {node_lbl} не вернулся в Started — не возвращаю в ротацию, "
                                "перехожу к следующей ноде",
                                run_id)
                        continue   # остаётся drained, трогаем следующую ноду

                    # return
                    returned = _orch_apply_balancing_both(
                        [e], svc_paths_int_one, svc_paths_ext_one,
                        ssh_int, sudo_int, ssh_ext, sudo_ext,
                        run_id, title, "return")
                    if returned is None: return
                    if _orch_is_cancelled(run_id): break
                    if returned:
                        svc_log("action", "info",
                                f"[{title}] жду {balance_wait_sec}с возврата балансировки", run_id)
                        if not _orch_sleep_with_cancel(balance_wait_sec, run_id): break

        finally:
            if ssh_int:
                try: ssh_int.close()
                except Exception: pass
            if ssh_ext:
                try: ssh_ext.close()
                except Exception: pass

        if _orch_is_cancelled(run_id):
            svc_log("action", "warn", "=== ПРЕРВАНО ПОЛЬЗОВАТЕЛЕМ ===", run_id, username)
        else:
            svc_log("action", "ok", "=== Готово ===", run_id, username)
    except Exception as e:
        app.logger.exception("orchestrator crashed")
        svc_log("error", "err", f"Сценарий упал с непредвиденной ошибкой: {e}", run_id, username)
    finally:
        _orch_release(run_id)
        if ctx is not None:
            try: ctx.pop()
            except Exception: pass


# ===== Воркер для API-балансировки (без Inceptum) =====
def _orch_run_api(action, ops, run_id, username):
    """Прогон drain/return по API-записям на ВНЕШНЕМ nginx.
    ops — список {entry_id, name, path, keys: [...]} (предвалидированный).
    """
    try:
        ctx = app.app_context()
        ctx.push()
    except Exception:
        ctx = None
    try:
        creds = get_balancer_creds()
        if not creds or not creds.get("ext_ssh_host"):
            svc_log("error", "err",
                    "SSH внешнего балансировщика не настроен. Зайдите в «Учётки».",
                    run_id, username)
            return

        if not ops:
            svc_log("error", "err", "Нет валидных операций", run_id)
            return

        total = sum(len(o["keys"]) for o in ops)
        _orch_progress_set_total(run_id, total)
        verb = {
            "api_drain":  "Вывод из ротации (API)",
            "api_return": "Ввод в ротацию (API)",
        }.get(action, action)
        svc_log("action", "info",
                f"=== {verb}: {len(ops)} файл(ов), {total} ключей "
                f"(запустил {username}) ===",
                run_id, username)

        try:
            ssh = _ext_ssh_open(creds)
        except BalancerError as e:
            svc_log("error", "err", str(e), run_id)
            return
        sudo = creds.get("ext_ssh_sudo_pwd") or ""

        try:
            try:
                _nginx_test(ssh, sudo)
                svc_log("action", "info", "[ext] nginx -t ok — можно начинать", run_id)
            except BalancerError as e:
                svc_log("error", "err", f"[ext] nginx -t упал до начала: {e}\nSTOP", run_id)
                return

            direction = "drain" if action == "api_drain" else "return"
            dir_ru = _DIR_RU.get(direction, direction)

            backups = {}
            any_changed = False
            for op in ops:
                if _orch_is_cancelled(run_id): break
                pre = f"[ext][{op['name']}]"
                try:
                    res = _balancer_apply(ssh, sudo, op["path"], op["keys"], direction)
                except BalancerError as e:
                    svc_log("error", "err",
                            f"{pre} {dir_ru} {op['path']}: {e}\nSTOP", run_id)
                    _orch_rollback_files(ssh, sudo, backups, run_id, f"ext|{op['name']}")
                    return
                if res["changed"]:
                    any_changed = True
                    backups[op["path"]] = res["original"]
                    svc_log("action", "ok",
                            f"{pre} {dir_ru} {op['path']}: "
                            f"{len(res['modified_lines'])} стр. ({', '.join(op['keys'])})",
                            run_id)
                else:
                    svc_log("action", "info",
                            f"{pre} {dir_ru} {op['path']}: "
                            f"уже в нужном состоянии ({', '.join(op['keys'])})",
                            run_id)
                _orch_progress_inc(run_id, len(op["keys"]))

            if any_changed and not _orch_is_cancelled(run_id):
                try:
                    _nginx_test(ssh, sudo)
                    _nginx_reload(ssh, sudo)
                    svc_log("action", "ok", "[ext] nginx -t ok, reload ok", run_id)
                except BalancerError as e:
                    svc_log("error", "err", f"[ext] {e}", run_id)
                    _orch_rollback_files(ssh, sudo, backups, run_id, "ext|api")
                    svc_log("error", "err", "[ext] STOP", run_id)
                    return
        finally:
            try: ssh.close()
            except Exception: pass

        if _orch_is_cancelled(run_id):
            svc_log("action", "warn", "=== ПРЕРВАНО ПОЛЬЗОВАТЕЛЕМ ===", run_id, username)
        else:
            svc_log("action", "ok", "=== Готово ===", run_id, username)
    except Exception as e:
        app.logger.exception("api orchestrator crashed")
        svc_log("error", "err",
                f"API-сценарий упал с непредвиденной ошибкой: {e}", run_id, username)
    finally:
        _orch_release(run_id)
        if ctx is not None:
            try: ctx.pop()
            except Exception: pass


# ===== Endpoints оркестратора =====
@app.post("/api/svc/orchestrate")
def svc_orchestrate():
    u, err = require_route("Balancer")
    if err: return err
    data = request.get_json(silent=True) or {}
    action = (data.get("action") or "").strip()
    nodes = data.get("nodes") or []
    if action not in ("restart", "restart_raw", "start", "stop", "drain", "return"):
        return jsonify({"error": "Неизвестное действие"}), 400
    if not isinstance(nodes, list) or not nodes:
        return jsonify({"error": "Список nodes пуст"}), 400

    # Пауза после reload nginx (drain/return). Клиент может переопределить,
    # но клемимся на разумный диапазон.
    try:
        balance_wait_sec = int(data.get("balance_wait_sec") or 30)
    except (TypeError, ValueError):
        balance_wait_sec = 30
    balance_wait_sec = max(1, min(balance_wait_sec, 999))

    pairs = []
    for n in nodes:
        if not isinstance(n, dict):
            continue
        h = (n.get("host") or "").strip()
        s = (n.get("service") or "").strip()
        if MS_NODE_KEY_RE.match(h) and MS_SERVICE_RE.match(s):
            pairs.append((h, s))
    pairs = pairs[:512]
    if not pairs:
        return jsonify({"error": "Нет валидных пар"}), 400

    ok, run_id, current = _orch_acquire(action, u["username"])
    if not ok:
        return jsonify({"error": "Уже идёт операция", "current": current}), 409

    # Снимаем текущие максимумы id в svc_console ДО старта воркера —
    # фронт использует это как «отсечку» UI-лога: всё, что с большим id,
    # гарантированно относится к новому прогону.
    try:
        cur_max_action = db().execute(
            "SELECT COALESCE(MAX(id), 0) FROM svc_console WHERE kind = 'action'"
        ).fetchone()[0] or 0
        cur_max_error = db().execute(
            "SELECT COALESCE(MAX(id), 0) FROM svc_console WHERE kind = 'error'"
        ).fetchone()[0] or 0
    except Exception:
        cur_max_action = 0
        cur_max_error = 0

    t = threading.Thread(
        target=_orch_run,
        args=(action, pairs, balance_wait_sec, run_id, u["username"]),
        daemon=True,
    )
    t.start()
    return jsonify({
        "ok": True,
        "run_id": run_id,
        "log_cutoff_action": cur_max_action,
        "log_cutoff_error":  cur_max_error,
    })


@app.post("/api/api-balancer/orchestrate")
def api_balancer_orchestrate():
    """Запуск drain/return по API-записям. Тот же глобальный замок, что и у
    микросервисов: нельзя запустить параллельно с обычной операцией."""
    u, err = require_route("Balancer")
    if err: return err
    data = request.get_json(silent=True) or {}
    action = (data.get("action") or "").strip()
    items = data.get("items") or []
    if action not in ("api_drain", "api_return"):
        return jsonify({"error": "Неизвестное действие"}), 400
    if not isinstance(items, list) or not items:
        return jsonify({"error": "items пуст"}), 400

    # Загружаем записи и валидируем переданные ключи
    rows = db().execute(
        "SELECT id, name, path, search_keys FROM api_balancer_entries"
    ).fetchall()
    by_id = {r["id"]: r for r in rows}
    ops = []
    for it in items:
        if not isinstance(it, dict): continue
        try:
            eid = int(it.get("entry_id"))
        except (TypeError, ValueError):
            continue
        e = by_id.get(eid)
        if not e: continue
        allowed = set(_api_keys_flatten_keys(_api_keys_parse(e["search_keys"])))
        keys = it.get("keys") or []
        if not isinstance(keys, list): continue
        keys = [str(k).strip() for k in keys
                if str(k).strip() in allowed and API_ENTRY_KEY_RE.match(str(k).strip())]
        if not keys: continue
        ops.append({
            "entry_id": eid,
            "name":     e["name"],
            "path":     e["path"],
            "keys":     keys,
        })
    if not ops:
        return jsonify({"error": "Нет валидных операций"}), 400

    ok, run_id, current = _orch_acquire(action, u["username"])
    if not ok:
        return jsonify({"error": "Уже идёт операция", "current": current}), 409

    try:
        cur_max_action = db().execute(
            "SELECT COALESCE(MAX(id), 0) FROM svc_console WHERE kind = 'action'"
        ).fetchone()[0] or 0
        cur_max_error = db().execute(
            "SELECT COALESCE(MAX(id), 0) FROM svc_console WHERE kind = 'error'"
        ).fetchone()[0] or 0
    except Exception:
        cur_max_action = 0
        cur_max_error = 0

    t = threading.Thread(
        target=_orch_run_api,
        args=(action, ops, run_id, u["username"]),
        daemon=True,
    )
    t.start()
    return jsonify({
        "ok": True,
        "run_id": run_id,
        "log_cutoff_action": cur_max_action,
        "log_cutoff_error":  cur_max_error,
    })


@app.get("/api/svc/orchestrate/state")
def svc_orchestrate_state():
    _, err = require_route("Balancer")
    if err: return err
    return jsonify(_orch_state())


@app.post("/api/svc/orchestrate/force-unlock")
def svc_orchestrate_force_unlock():
    """Принудительное снятие замка (на случай умершего worker'а)."""
    _, err = require_admin()
    if err: return err
    st = _orch_state()
    if not st.get("busy"):
        return jsonify({"ok": True, "noop": True})
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            "UPDATE svc_run_lock SET run_id=NULL, stopped_at=?, cancel_requested=0 WHERE id=1",
            (int(time.time()),),
        )
        conn.commit()
    finally:
        conn.close()
    svc_log("error", "warn",
            f"Замок принудительно снят админом (был run_id={st.get('run_id')}, "
            f"user={st.get('username')}, action={st.get('action')})",
            None, None)
    return jsonify({"ok": True})


def _rotation_scan_balancer(ssh, sudo_pwd, paths_by_svc, needed_keys_per_svc):
    """Просканировать nginx-конфиги одного балансера и вернуть
    {svc: {host_key: {path: True/False/None}}}.
    Значение по path:
      True  — упоминание ключа найдено и не закомментировано (в ротации в этом файле);
      False — упоминание есть, но закомментировано (выведено из ротации в этом файле);
      None  — упоминание не найдено / файл не прочитался.
    Если для сервиса нет путей — out[svc][host] = {} (пустой словарь)."""
    file_cache = {}  # path -> [first NGINX_SEARCH_LINES lines] | None
    def get_first_lines(path):
        if path in file_cache: return file_cache[path]
        rc, content, _err = _ssh_run_sudo(ssh, sudo_pwd,
                                          f"head -n {NGINX_SEARCH_LINES} {shlex.quote(path)}")
        if rc != 0:
            file_cache[path] = None
            return None
        file_cache[path] = content.split("\n")[:NGINX_SEARCH_LINES]
        return file_cache[path]

    out = {}
    for svc, keys in needed_keys_per_svc.items():
        paths = paths_by_svc.get(svc, [])
        out[svc] = {}
        for k in keys:
            out[svc][k] = {}
            if not paths:
                continue
            stripped = _strip_node_prefix(k).lower()
            rgx = re.compile(r"\b" + re.escape(stripped) + r"\b", re.IGNORECASE)
            for p in paths:
                lines = get_first_lines(p)
                if not lines:
                    out[svc][k][p] = None
                    continue
                found_un = False
                found_co = False
                for ln in lines:
                    if rgx.search(ln):
                        if ln.lstrip().startswith("#"):
                            found_co = True
                        else:
                            found_un = True
                        break
                if found_un:
                    out[svc][k][p] = True
                elif found_co:
                    out[svc][k][p] = False
                else:
                    out[svc][k][p] = None
    return out


@app.post("/api/svc/rotation")
def svc_rotation():
    """Реальное состояние «в ротации» по nginx-конфигам внутреннего и внешнего балансеров.
    body: {queries: [{service, hosts: [...]}]}
    Возвращает: {results: {service: {host_key: {int: T/F/null, ext: T/F/null}}}}.
    int/ext = null означает «не балансируется на этом балансере».
    """
    _, err = require_route("Balancer")
    if err: return err
    data = request.get_json(silent=True) or {}
    queries = data.get("queries") or []
    if not isinstance(queries, list) or not queries:
        return jsonify({"results": {}})

    needed_keys_per_svc = {}
    svc_names = []
    for q in queries:
        if not isinstance(q, dict): continue
        svc = (q.get("service") or "").strip()
        hosts = q.get("hosts") or []
        if not svc or not MS_SERVICE_RE.match(svc): continue
        if not isinstance(hosts, list): continue
        keys = {h.strip() for h in hosts if isinstance(h, str) and MS_NODE_KEY_RE.match(h.strip())}
        if not keys: continue
        needed_keys_per_svc[svc] = keys
        svc_names.append(svc)
    if not svc_names:
        return jsonify({"results": {}})

    ph = ",".join(["?"] * len(svc_names))
    rows = db().execute(
        f"SELECT name, balancer_paths, balancer_paths_ext FROM ms_catalog WHERE name IN ({ph})",
        svc_names,
    ).fetchall()
    paths_int_by_svc = {r["name"]: json.loads(r["balancer_paths"]     or "[]") for r in rows}
    paths_ext_by_svc = {r["name"]: json.loads(r["balancer_paths_ext"] or "[]") for r in rows}

    creds = get_balancer_creds()
    if not creds or not creds.get("ssh_host"):
        return jsonify({"error": "SSH внутреннего балансировщика не настроен"}), 400

    # есть ли смысл лезть на внешний — хоть один сервис с ext-путями?
    has_ext_paths = any(paths_ext_by_svc.get(s) for s in svc_names)
    has_ext_creds = bool(creds.get("ext_ssh_host") and creds.get("ext_ssh_login"))

    # Внутренний — обязательно
    try:
        ssh_int = _ssh_open(creds)
    except BalancerError as e:
        return jsonify({"error": str(e)}), 502
    sudo_int = creds.get("ssh_sudo_pwd") or ""

    # Внешний — лениво
    ssh_ext = None
    sudo_ext = ""
    ext_err = None
    if has_ext_paths and has_ext_creds:
        try:
            ssh_ext = _ext_ssh_open(creds)
            sudo_ext = creds.get("ext_ssh_sudo_pwd") or ""
        except BalancerError as e:
            ext_err = str(e)

    try:
        int_res = _rotation_scan_balancer(ssh_int, sudo_int, paths_int_by_svc, needed_keys_per_svc)
        ext_res = (_rotation_scan_balancer(ssh_ext, sudo_ext, paths_ext_by_svc, needed_keys_per_svc)
                   if ssh_ext is not None else
                   {s: {k: {} for k in needed_keys_per_svc[s]} for s in svc_names})

        results = {}
        for svc in svc_names:
            results[svc] = {}
            for k in needed_keys_per_svc[svc]:
                int_paths = int_res.get(svc, {}).get(k) or {}
                ext_paths = ext_res.get(svc, {}).get(k) or {}
                # Пустой словарь (нет путей у этого балансера) → null,
                # чтобы фронт ясно видел «балансер не задействован».
                results[svc][k] = {
                    "int": int_paths if int_paths else None,
                    "ext": ext_paths if ext_paths else None,
                }
        out = {
            "results": results,
            # Список путей по сервисам — фронт по нему рисует колонки.
            "paths_by_svc": {
                s: {
                    "int": list(paths_int_by_svc.get(s, [])),
                    "ext": list(paths_ext_by_svc.get(s, [])),
                }
                for s in svc_names
            },
        }
        if ext_err:
            out["ext_warning"] = ext_err
        return jsonify(out)
    finally:
        try: ssh_int.close()
        except Exception: pass
        if ssh_ext is not None:
            try: ssh_ext.close()
            except Exception: pass


@app.post("/api/svc/orchestrate/cancel")
def svc_orchestrate_cancel():
    u, err = require_route("Balancer")
    if err: return err
    state = _orch_state()
    if not state.get("busy"):
        return jsonify({"ok": True, "noop": True})
    if state.get("username") != u["username"] and u["role"] != "admin":
        return jsonify({"error": "Прервать может только запустивший пользователь или админ"}), 403
    _orch_request_cancel(state["run_id"])
    svc_log("action", "warn",
            f"Запрошено прерывание пользователем {u['username']}",
            state.get("run_id"), u["username"])
    return jsonify({"ok": True})


@app.get("/api/svc/console")
def svc_console_get():
    _, err = require_route("Balancer")
    if err: return err
    try:
        since_action = int(request.args.get("since_action") or 0)
        since_error  = int(request.args.get("since_error")  or 0)
        limit = max(1, min(int(request.args.get("limit") or 500), 2000))
    except ValueError:
        return jsonify({"error": "bad params"}), 400
    actions = db().execute(
        "SELECT id, ts, level, message, username, run_id FROM svc_console "
        "WHERE kind = 'action' AND id > ? ORDER BY id ASC LIMIT ?",
        (since_action, limit),
    ).fetchall()
    errors = db().execute(
        "SELECT id, ts, level, message, username, run_id FROM svc_console "
        "WHERE kind = 'error' AND id > ? ORDER BY id ASC LIMIT ?",
        (since_error, limit),
    ).fetchall()
    return jsonify({
        "actions": [dict(r) for r in actions],
        "errors":  [dict(r) for r in errors],
    })


@app.get("/healthz")
def healthz():
    return "ok\n", 200


# При старте: убедиться, что все сохранённые пароли БД лежат в зашифрованном виде.
try:
    migrate_db_settings_encryption()
except Exception:
    app.logger.exception("DB settings encryption migration failed")
