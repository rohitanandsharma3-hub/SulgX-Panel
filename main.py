import asyncio
import json
import os
import hashlib
import secrets
import time
import re
import base64
import ipaddress
import socket
import uuid as uuid_lib
from datetime import datetime, timezone, timedelta
from urllib.parse import quote
from collections import deque, defaultdict
from typing import Optional, Dict, Any

from fastapi import FastAPI, Request, HTTPException, WebSocket, WebSocketDisconnect, Depends
from fastapi.responses import Response, HTMLResponse, JSONResponse, StreamingResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

import uvicorn
import httpx
import psutil
import bcrypt
from jose import jwt, JWTError
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import aiosqlite
import logging
import logging.config
import yaml
import html
import aiofiles
import anyio
from starlette.background import BackgroundTask
try:
    import uvloop
    uvloop.install()
except ImportError:
    pass

try:
    import asyncpg
    HAS_POSTGRES = True
except ImportError:
    HAS_POSTGRES = False

LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "json": {
            "()": "pythonjsonlogger.jsonlogger.JsonFormatter",
            "format": "%(asctime)s %(levelname)s %(name)s %(message)s",
        }
    },
    "handlers": {"json_console": {"class": "logging.StreamHandler", "formatter": "json"}},
    "root": {"level": "INFO", "handlers": ["json_console"]},
}
logging.config.dictConfig(LOGGING_CONFIG)
logger = logging.getLogger("SulgX")
print("--- APPLICATION IS STARTING ---")
BLOCKED_DOMAINS: set = set()

# -------------------- Rate Limiting IP extraction --------------------
def get_real_remote_address(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    cf_ip = request.headers.get("cf-connecting-ip")
    if cf_ip:
        return cf_ip.strip()
    return request.client.host if request.client else "unknown"

limiter = Limiter(key_func=get_real_remote_address, default_limits=["100/minute"])
_tunnel_error_suppress: dict = {}
_domain_ip_cache: Dict[str, Optional[str]] = {}

async def resolve_domain_to_ip(host: str) -> Optional[str]:
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    if host in _domain_ip_cache:
        return _domain_ip_cache[host]
    try:
        loop = asyncio.get_event_loop()
        addrs = await asyncio.wait_for(
            loop.getaddrinfo(host, 443, family=socket.AF_INET),
            timeout=3.0
        )
        if addrs:
            ip = addrs[0][4][0]
            _domain_ip_cache[host] = ip
            return ip
    except (asyncio.TimeoutError, Exception):
        pass
    _domain_ip_cache[host] = None
    return None
# -------------------- Configuration --------------------
CONFIG = {
    "port": int(os.environ.get("PORT", 8000)),
    "secret_key": os.environ.get("SECRET_KEY", secrets.token_urlsafe(32)),
    "jwt_algorithm": "HS256",
    "jwt_expire_minutes": 10080,
    "db_path": os.environ.get("DB_PATH", "/data/panel.db"),
    "admin_password": os.environ.get("ADMIN_PASSWORD", "admin"),
    "database_url": os.environ.get("DATABASE_URL", ""),
}

PANEL_PREFIX = os.environ.get("PANEL_PREFIX", "").strip("/")
STEALTH_MODE = os.environ.get("STEALTH_MODE", "").lower() in ("1", "true", "yes")
LANDING_REDIRECT = os.environ.get("LANDING_REDIRECT", "").strip()
CAMOUFLAGE_URL = os.environ.get("CAMOUFLAGE_URL", "").strip()
SUB_FILENAME = os.environ.get("SUB_FILENAME", "").strip()

if HAS_POSTGRES:
    ADDRESS_INTEGRITY_ERRORS = (aiosqlite.IntegrityError, asyncpg.exceptions.UniqueViolationError)
else:
    ADDRESS_INTEGRITY_ERRORS = (aiosqlite.IntegrityError,)

db_conn: Optional[aiosqlite.Connection] = None
db_lock = asyncio.Lock()
ENABLE_LOGGING = True
KEEP_ALIVE_INTERVAL = 300
TIMEZONE_OFFSET = 0.0
KEEP_ALIVE_ENABLED = True
KEEP_ALIVE_MODE = "simple"

traffic_buffer_lock = asyncio.Lock()
traffic_buffer = {
    "hourly": defaultdict(int),
    "daily": defaultdict(int),
}

LINKS: dict = {}
LINKS_LOCK = asyncio.Lock()
CUSTOM_ADDRESSES: list = ["www.speedtest.net"]
CUSTOM_ADDRESSES_LOCK = asyncio.Lock()

_scan_lock = asyncio.Lock()

IP_PROFILES: dict = {}
IP_PROFILES_LOCK = asyncio.Lock()
DOH_UPSTREAMS: list = [
    "https://dns.cloudflare.com/dns-query",
    "https://dns.google/dns-query",
    "https://dns.quad9.net/dns-query",
    "https://doh.opendns.com/dns-query"
]
DOH_ENABLED: bool = True

IP_FLAG_CACHE: Dict[str, str] = {}
IP_FLAG_CACHE_LOCK = asyncio.Lock()
IP_FLAG_CACHE_MAX = 1024
flag_semaphore = asyncio.Semaphore(5)

DEFAULT_PATH = "/ws/{uid}"
DEFAULT_XHTTP_PATH = "/xhttp"

SUBS: dict = {}
SUBS_LOCK = asyncio.Lock()
SUBS_FILE = os.path.join(os.path.dirname(os.environ.get("DB_PATH", "/data/panel.db")), "subs_state.json")

# -------------------- Block Domains --------------------
def is_domain_blocked(host: str) -> bool:
    if not host or not BLOCKED_DOMAINS:
        return False
    host_lower = host.lower()
    for blocked in BLOCKED_DOMAINS:
        if blocked.startswith("*."):
            if host_lower.endswith(blocked[1:]) or host_lower == blocked[2:]:
                return True
        elif host_lower == blocked:
            return True
    return False

# ── Quota Gate (Adaptive) ──────────────────────────────────────────────────
class QuotaGate:
    def __init__(self, uid: str):
        self.uid = uid
        self.pending = 0
        self.ok = True
        self.last_check = time.monotonic()
        self.batch = 64 * 1024
        self.rate_ewma = 0.0

    async def add(self, n: int) -> bool:
        if not self.ok:
            return False
        self.pending += n
        now = time.monotonic()
        if self.pending >= self.batch or (now - self.last_check) > 0.2:
            flush, self.pending = self.pending, 0
            self.ok = await check_quota(self.uid, flush)
            if self.ok:
                await add_usage(self.uid, flush)
                local_now = datetime.now(timezone.utc) + timedelta(hours=TIMEZONE_OFFSET)
                hour = local_now.strftime("%Y-%m-%d %H:00")
                day = local_now.strftime("%Y-%m-%d")
                await add_traffic_to_buffer(hour, day, flush, self.uid)
                elapsed = now - self.last_check
                if elapsed > 0:
                    inst_rate = flush / elapsed
                    self.rate_ewma = inst_rate if self.rate_ewma == 0 else (0.7 * self.rate_ewma + 0.3 * inst_rate)
                    target = int(self.rate_ewma * 0.2)
                    self.batch = max(32 * 1024, min(1024 * 1024, target or 64 * 1024))
            self.last_check = now
            return self.ok
        return True

    async def check(self) -> bool:
        if self.pending:
            flush, self.pending = self.pending, 0
            ok = await check_quota(self.uid, flush)
            if ok:
                await add_usage(self.uid, flush)
                local_now = datetime.now(timezone.utc) + timedelta(hours=TIMEZONE_OFFSET)
                hour = local_now.strftime("%Y-%m-%d %H:00")
                day = local_now.strftime("%Y-%m-%d")
                await add_traffic_to_buffer(hour, day, flush, self.uid)
                self.ok = True
                return True
            else:
                self.ok = False
                return False
        return self.ok

    async def flush(self) -> bool:
        if self.pending:
            flush, self.pending = self.pending, 0
            self.ok = self.ok and await check_quota(self.uid, flush)
            if self.ok:
                await add_usage(self.uid, flush)
                local_now = datetime.now(timezone.utc) + timedelta(hours=TIMEZONE_OFFSET)
                hour = local_now.strftime("%Y-%m-%d %H:00")
                day = local_now.strftime("%Y-%m-%d")
                await add_traffic_to_buffer(hour, day, flush, self.uid)
        return self.ok

# ── Socket tuning ─────────────────────────────────────────────────────────
def tune_socket(writer):
    sock = writer.get_extra_info('socket')
    if sock:
        import socket as _socket
        try:
            sock.setsockopt(_socket.IPPROTO_TCP, _socket.TCP_NODELAY, 1)
            sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_SNDBUF, 2 * 1024 * 1024)
            sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_RCVBUF, 2 * 1024 * 1024)
        except OSError:
            pass

# ── IP limit check ─────────────────────────────────────────────────────────
def is_ip_allowed(link, uuid: str, ip: str) -> bool:
    if not link:
        return False
    limit = int(link.get('ip_limit', 0) or 0)
    if limit <= 0:
        return True
    current_ips = {c.get('ip') for c in connections.values() if c.get('uuid') == uuid}
    if ip in current_ips:
        return True
    return len(current_ips) < limit

# ── Extended VLESS header parser (supports UDP command) ────────────────────
async def parse_vless_header_extended(chunk: bytes):
    if len(chunk) < 24:
        raise ValueError("VLESS header too small")
    pos = 1
    pos += 16
    addon_len = chunk[pos]; pos += 1 + addon_len
    if len(chunk) < pos + 3:
        raise ValueError("Malformed header")
    command = chunk[pos]; pos += 1
    port = int.from_bytes(chunk[pos:pos+2], "big"); pos += 2
    addr_type = chunk[pos]; pos += 1
    if addr_type == 1:
        if len(chunk) < pos + 4: raise ValueError("Incomplete IPv4")
        address = ".".join(str(b) for b in chunk[pos:pos+4]); pos += 4
    elif addr_type == 2:
        if len(chunk) < pos + 1: raise ValueError("Missing domain length")
        dlen = chunk[pos]; pos += 1
        if len(chunk) < pos + dlen: raise ValueError("Incomplete domain")
        address = chunk[pos:pos+dlen].decode("utf-8", errors="ignore"); pos += dlen
    elif addr_type == 3:
        if len(chunk) < pos + 16: raise ValueError("Incomplete IPv6")
        ab = chunk[pos:pos+16]; pos += 16
        address = ":".join(f"{ab[i]:02x}{ab[i+1]:02x}" for i in range(0, 16, 2))
    else:
        raise ValueError(f"Unknown address type: {addr_type}")
    return command, address, port, chunk[pos:]
async def parse_vless_header_with_uuid(chunk: bytes):
    if len(chunk) < 24:
        raise ValueError("VLESS header too small")
    pos = 1
    uuid_bytes = chunk[pos:pos+16]
    uid = str(uuid_lib.UUID(bytes=uuid_bytes))
    pos += 16
    addon_len = chunk[pos]
    pos += 1 + addon_len
    if len(chunk) < pos + 3:
        raise ValueError("Malformed header")
    command = chunk[pos]; pos += 1
    port = int.from_bytes(chunk[pos:pos+2], "big"); pos += 2
    addr_type = chunk[pos]; pos += 1
    if addr_type == 1:
        if len(chunk) < pos + 4: raise ValueError("Incomplete IPv4")
        address = ".".join(str(b) for b in chunk[pos:pos+4]); pos += 4
    elif addr_type == 2:
        if len(chunk) < pos + 1: raise ValueError("Missing domain length")
        dlen = chunk[pos]; pos += 1
        if len(chunk) < pos + dlen: raise ValueError("Incomplete domain")
        address = chunk[pos:pos+dlen].decode("utf-8", errors="ignore"); pos += dlen
    elif addr_type == 3:
        if len(chunk) < pos + 16: raise ValueError("Incomplete IPv6")
        ab = chunk[pos:pos+16]; pos += 16
        address = ":".join(f"{ab[i]:02x}{ab[i+1]:02x}" for i in range(0, 16, 2))
    else:
        raise ValueError(f"Unknown address type: {addr_type}")
    return uid, command, address, port, chunk[pos:]

# -------------------- Database backend selection --------------------
if CONFIG["database_url"] and HAS_POSTGRES:
    DB_BACKEND = "postgresql"
    pg_pool: Optional[asyncpg.Pool] = None

    async def ensure_column_pg(table: str, column: str, col_type: str):
        try:
            async with pg_pool.acquire() as conn:
                exists = await conn.fetchval(
                    "SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name=$1 AND column_name=$2)",
                    table, column)
                if not exists:
                    await conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}")
        except Exception as e:
            logger.error(f"Failed to ensure column {table}.{column}: {e}")

    async def init_pg():
        global pg_pool
        pg_pool = await asyncpg.create_pool(CONFIG["database_url"], min_size=2, max_size=10)
        async with pg_pool.acquire() as conn:
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS links (
                    uid TEXT PRIMARY KEY, label TEXT NOT NULL,
                    limit_bytes BIGINT DEFAULT 0, used_bytes BIGINT DEFAULT 0,
                    max_connections INT DEFAULT 0, created_at TEXT NOT NULL,
                    active BOOLEAN DEFAULT TRUE, expires_at TEXT,
                    custom_path TEXT DEFAULT '', custom_sni TEXT DEFAULT '',
                    custom_host TEXT DEFAULT '', custom_fp TEXT DEFAULT 'chrome',
                    color TEXT DEFAULT '#39ff14',
                    flag TEXT DEFAULT '',
                    fragment TEXT DEFAULT '',
                    ip_profile_id TEXT DEFAULT '',
                    naming_mode TEXT DEFAULT 'default',
                    tfo BOOLEAN DEFAULT FALSE,
                    ech_enabled BOOLEAN DEFAULT FALSE,
                    ech_sni TEXT DEFAULT '',
                    ech_doh TEXT DEFAULT '',
                    fragment_mode TEXT DEFAULT 'off',
                    fragment_length TEXT DEFAULT '100-200',
                    fragment_interval TEXT DEFAULT '10-20',
                    allow_insecure BOOLEAN DEFAULT FALSE,
                    random_path BOOLEAN DEFAULT FALSE,
                    enable_ipv6 BOOLEAN DEFAULT TRUE,
                    smux_enabled BOOLEAN DEFAULT FALSE,
                    ip_limit INTEGER DEFAULT 0,
                    protocol TEXT DEFAULT 'vless-ws',
                    fingerprint TEXT DEFAULT 'chrome',
                    alpn TEXT DEFAULT '',
                    port INTEGER DEFAULT 443
                );
                CREATE TABLE IF NOT EXISTS hourly_traffic (hour TEXT PRIMARY KEY, bytes BIGINT DEFAULT 0);
                CREATE TABLE IF NOT EXISTS daily_traffic (day TEXT PRIMARY KEY, bytes BIGINT DEFAULT 0, uid TEXT DEFAULT '');
                CREATE TABLE IF NOT EXISTS custom_addresses (
                    id SERIAL PRIMARY KEY,
                    address TEXT NOT NULL UNIQUE,
                    flag TEXT DEFAULT ''
                );
                CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
                CREATE TABLE IF NOT EXISTS login_logs (
                    id SERIAL PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    ip TEXT,
                    success BOOLEAN DEFAULT TRUE,
                    user_agent TEXT DEFAULT '',
                    path TEXT DEFAULT '',
                    browser TEXT DEFAULT '',
                    os TEXT DEFAULT ''
                );
                CREATE TABLE IF NOT EXISTS ip_profiles (
                    id TEXT PRIMARY KEY, name TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS profile_addresses (
                    id SERIAL PRIMARY KEY,
                    profile_id TEXT REFERENCES ip_profiles(id) ON DELETE CASCADE,
                    address TEXT NOT NULL,
                    flag TEXT DEFAULT '',
                    name TEXT DEFAULT '',
                    sort_number INTEGER DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS doh_upstreams (
                    id SERIAL PRIMARY KEY, url TEXT NOT NULL
                );
            """)
            for col, col_type in [
                ("tfo", "BOOLEAN DEFAULT FALSE"),
                ("ech_enabled", "BOOLEAN DEFAULT FALSE"),
                ("ech_sni", "TEXT DEFAULT ''"),
                ("ech_doh", "TEXT DEFAULT ''"),
                ("fragment_mode", "TEXT DEFAULT 'off'"),
                ("fragment_length", "TEXT DEFAULT '100-200'"),
                ("fragment_interval", "TEXT DEFAULT '10-20'"),
                ("allow_insecure", "BOOLEAN DEFAULT FALSE"),
                ("random_path", "BOOLEAN DEFAULT FALSE"),
                ("enable_ipv6", "BOOLEAN DEFAULT TRUE"),
                ("flag", "TEXT DEFAULT ''"),
                ("fragment", "TEXT DEFAULT ''"),
                ("ip_profile_id", "TEXT DEFAULT ''"),
                ("naming_mode", "TEXT DEFAULT 'default'"),
                ("smux_enabled", "BOOLEAN DEFAULT FALSE"),
                ("ip_limit", "INTEGER DEFAULT 0"),
                ("protocol", "TEXT DEFAULT 'vless-ws'"),
                ("fingerprint", "TEXT DEFAULT 'chrome'"),
                ("alpn", "TEXT DEFAULT ''"),
                ("port", "INTEGER DEFAULT 443"),
            ]:
                await ensure_column_pg("links", col, col_type)
                await ensure_column_pg("daily_traffic", "uid", "TEXT DEFAULT ''")
                await ensure_column_pg("custom_addresses", "flag", "TEXT DEFAULT ''")
                await ensure_column_pg("profile_addresses", "flag", "TEXT DEFAULT ''")
                await ensure_column_pg("login_logs", "browser", "TEXT DEFAULT ''")
                await ensure_column_pg("login_logs", "os", "TEXT DEFAULT ''")
                await ensure_column_pg("profile_addresses", "name", "TEXT DEFAULT ''")
                await ensure_column_pg("profile_addresses", "sort_number", "INTEGER DEFAULT 0")
                await ensure_column_pg("login_logs", "country", "TEXT DEFAULT ''")
                await ensure_column_pg("login_logs", "city", "TEXT DEFAULT ''")
                await ensure_column_pg("login_logs", "isp", "TEXT DEFAULT ''")
                await ensure_column_pg("login_logs", "org", "TEXT DEFAULT ''")

    async def db_execute(sqlite_q: str, pg_q: str, params: tuple = ()):
        async with pg_pool.acquire() as conn:
            await conn.execute(pg_q, *params)

    async def db_fetchall(sqlite_q: str, pg_q: str, params: tuple = ()) -> list:
        async with pg_pool.acquire() as conn:
            rows = await conn.fetch(pg_q, *params)
            return [dict(r) for r in rows]

    async def db_fetchone(sqlite_q: str, pg_q: str, params: tuple = ()) -> Optional[dict]:
        async with pg_pool.acquire() as conn:
            row = await conn.fetchrow(pg_q, *params)
            return dict(row) if row else None

    async def get_db():
        return None
else:
    DB_BACKEND = "sqlite"

    async def ensure_column_sqlite(table: str, column: str, col_def: str):
        try:
            async with db_lock:
                cur = await db_conn.execute(f"PRAGMA table_info({table})")
                rows = await cur.fetchall()
                if not any(r[1] == column for r in rows):
                    await db_conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_def}")
        except Exception as e:
            logger.error(f"Failed to ensure column {table}.{column}: {e}")

    async def init_db():
        global db_conn
        db_path = CONFIG["db_path"]
        try:
            test_file = os.path.join(os.path.dirname(db_path), ".write_test")
            with open(test_file, "w") as f:
                f.write("ok")
            os.remove(test_file)
        except Exception:
            logger.warning(f"Cannot write to {db_path}, falling back to /tmp/panel.db")
            CONFIG["db_path"] = "/tmp/panel.db"
            db_path = "/tmp/panel.db"
        db_conn = await aiosqlite.connect(db_path)
        db_conn.row_factory = aiosqlite.Row
        await db_conn.execute("PRAGMA journal_mode=WAL")
        await db_conn.executescript("""
            CREATE TABLE IF NOT EXISTS links (
                uid TEXT PRIMARY KEY, label TEXT NOT NULL,
                limit_bytes INTEGER DEFAULT 0, used_bytes INTEGER DEFAULT 0,
                max_connections INTEGER DEFAULT 0, created_at TEXT NOT NULL,
                active INTEGER DEFAULT 1, expires_at TEXT,
                custom_path TEXT DEFAULT '', custom_sni TEXT DEFAULT '',
                custom_host TEXT DEFAULT '', custom_fp TEXT DEFAULT 'chrome',
                color TEXT DEFAULT '#39ff14',
                flag TEXT DEFAULT '',
                fragment TEXT DEFAULT '',
                ip_profile_id TEXT DEFAULT '',
                naming_mode TEXT DEFAULT 'default',
                tfo INTEGER DEFAULT 0,
                ech_enabled INTEGER DEFAULT 0,
                ech_sni TEXT DEFAULT '',
                ech_doh TEXT DEFAULT '',
                fragment_mode TEXT DEFAULT 'off',
                fragment_length TEXT DEFAULT '100-200',
                fragment_interval TEXT DEFAULT '10-20',
                allow_insecure INTEGER DEFAULT 0,
                random_path INTEGER DEFAULT 0,
                enable_ipv6 INTEGER DEFAULT 1,
                smux_enabled INTEGER DEFAULT 0,
                ip_limit INTEGER DEFAULT 0,
                protocol TEXT DEFAULT 'vless-ws',
                fingerprint TEXT DEFAULT 'chrome',
                alpn TEXT DEFAULT '',
                port INTEGER DEFAULT 443
            );
            CREATE TABLE IF NOT EXISTS hourly_traffic (hour TEXT PRIMARY KEY, bytes INTEGER DEFAULT 0);
            CREATE TABLE IF NOT EXISTS daily_traffic (day TEXT PRIMARY KEY, bytes INTEGER DEFAULT 0, uid TEXT DEFAULT '');
            CREATE TABLE IF NOT EXISTS custom_addresses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                address TEXT NOT NULL UNIQUE,
                flag TEXT DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
            CREATE TABLE IF NOT EXISTS login_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                ip TEXT,
                success INTEGER DEFAULT 1,
                user_agent TEXT DEFAULT '',
                path TEXT DEFAULT '',
                browser TEXT DEFAULT '',
                os TEXT DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS ip_profiles (
                id TEXT PRIMARY KEY, name TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS profile_addresses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                profile_id TEXT REFERENCES ip_profiles(id) ON DELETE CASCADE,
                address TEXT NOT NULL,
                flag TEXT DEFAULT '',
                name TEXT DEFAULT '',
                sort_number INTEGER DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS doh_upstreams (
                id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT NOT NULL
            );
        """)
        await db_conn.commit()

        extended_columns = [
            ("smux_enabled", "INTEGER DEFAULT 0"),
            ("ip_limit", "INTEGER DEFAULT 0"),
            ("protocol", "TEXT DEFAULT 'vless-ws'"),
            ("fingerprint", "TEXT DEFAULT 'chrome'"),
            ("alpn", "TEXT DEFAULT ''"),
            ("port", "INTEGER DEFAULT 443"),
        ]
        for col, col_def in extended_columns:
            await ensure_column_sqlite("links", col, col_def)

        legacy_columns = [
            ("tfo", "INTEGER DEFAULT 0"),
            ("ech_enabled", "INTEGER DEFAULT 0"),
            ("ech_sni", "TEXT DEFAULT ''"),
            ("ech_doh", "TEXT DEFAULT ''"),
            ("fragment_mode", "TEXT DEFAULT 'off'"),
            ("fragment_length", "TEXT DEFAULT '100-200'"),
            ("fragment_interval", "TEXT DEFAULT '10-20'"),
            ("allow_insecure", "INTEGER DEFAULT 0"),
            ("random_path", "INTEGER DEFAULT 0"),
            ("enable_ipv6", "INTEGER DEFAULT 1"),
            ("flag", "TEXT DEFAULT ''"),
            ("fragment", "TEXT DEFAULT ''"),
            ("ip_profile_id", "TEXT DEFAULT ''"),
            ("naming_mode", "TEXT DEFAULT 'default'"),
        ]
        for col, col_def in legacy_columns:
            await ensure_column_sqlite("links", col, col_def)

        await ensure_column_sqlite("daily_traffic", "uid", "TEXT DEFAULT ''")
        await ensure_column_sqlite("custom_addresses", "flag", "TEXT DEFAULT ''")
        await ensure_column_sqlite("profile_addresses", "flag", "TEXT DEFAULT ''")
        await ensure_column_sqlite("login_logs", "browser", "TEXT DEFAULT ''")
        await ensure_column_sqlite("login_logs", "os", "TEXT DEFAULT ''")
        await ensure_column_sqlite("profile_addresses", "name", "TEXT DEFAULT ''")
        await ensure_column_sqlite("profile_addresses", "sort_number", "INTEGER DEFAULT 0")
        await ensure_column_sqlite("login_logs", "country", "TEXT DEFAULT ''")
        await ensure_column_sqlite("login_logs", "city", "TEXT DEFAULT ''")
        await ensure_column_sqlite("login_logs", "isp", "TEXT DEFAULT ''")
        await ensure_column_sqlite("login_logs", "org", "TEXT DEFAULT ''")

        await db_conn.commit()

    async def db_execute(sqlite_q: str, pg_q: str = "", params: tuple = ()):
        async with db_lock:
            await db_conn.execute(sqlite_q, params)
            await db_conn.commit()

    async def db_fetchall(sqlite_q: str, pg_q: str = "", params: tuple = ()) -> list:
        async with db_lock:
            cur = await db_conn.execute(sqlite_q, params)
            rows = await cur.fetchall()
        return [dict(r) for r in rows]

    async def db_fetchone(sqlite_q: str, pg_q: str = "", params: tuple = ()) -> Optional[dict]:
        async with db_lock:
            cur = await db_conn.execute(sqlite_q, params)
            row = await cur.fetchone()
        return dict(row) if row else None

    async def get_db():
        return db_conn

# -------------------- Session cookie helper --------------------
async def get_session_cookie_name() -> str:
    stealth_row = await db_fetchone("SELECT value FROM settings WHERE key='stealth_mode'",
                                    "SELECT value FROM settings WHERE key='stealth_mode'")
    stealth_mode = stealth_row["value"] == "1" if stealth_row else False
    return "x-session-id" if stealth_mode else "SulgX_session"

# -------------------- Background tasks --------------------
async def flush_traffic_buffer():
    while True:
        await asyncio.sleep(10)
        try:
            async with traffic_buffer_lock:
                if not traffic_buffer["hourly"] and not traffic_buffer["daily"]:
                    continue
                for hour, bytes_val in traffic_buffer["hourly"].items():
                    await db_execute(
                        "INSERT INTO hourly_traffic (hour, bytes) VALUES (?,?) ON CONFLICT(hour) DO UPDATE SET bytes = bytes + ?",
                        "INSERT INTO hourly_traffic (hour, bytes) VALUES ($1,$2) ON CONFLICT (hour) DO UPDATE SET bytes = hourly_traffic.bytes + $2",
                        (hour, bytes_val, bytes_val)
                    )
                for day, bytes_val in traffic_buffer["daily"].items():
                    await db_execute(
                        "INSERT INTO daily_traffic (day, bytes) VALUES (?,?) ON CONFLICT(day) DO UPDATE SET bytes = bytes + ?",
                        "INSERT INTO daily_traffic (day, bytes) VALUES ($1,$2) ON CONFLICT (day) DO UPDATE SET bytes = daily_traffic.bytes + $2",
                        (day, bytes_val, bytes_val)
                    )
                traffic_buffer["hourly"].clear()
                traffic_buffer["daily"].clear()
        except Exception as e:
            logger.error(f"flush_traffic_buffer error: {e}", exc_info=True)

async def add_traffic_to_buffer(hour: str, day: str, size: int, uid: str = ""):
    async with traffic_buffer_lock:
        traffic_buffer["hourly"][hour] += size
        traffic_buffer["daily"][day] += size
        if uid:
            await db_execute(
                "INSERT INTO daily_traffic (day, bytes, uid) VALUES (?,?,?) ON CONFLICT(day) DO UPDATE SET bytes = bytes + ?",
                "INSERT INTO daily_traffic (day, bytes, uid) VALUES ($1,$2,$3) ON CONFLICT (day) DO UPDATE SET bytes = daily_traffic.bytes + $2",
                (day, size, uid, size)
            )

async def sync_usage_to_db():
    while True:
        await asyncio.sleep(30)
        try:
            async with LINKS_LOCK:
                for uid, link in LINKS.items():
                    await db_execute(
                        "UPDATE links SET used_bytes = ? WHERE uid = ?",
                        "UPDATE links SET used_bytes = $1 WHERE uid = $2",
                        (link["used_bytes"], uid)
                    )
        except Exception as e:
            logger.error(f"sync_usage_to_db error: {e}", exc_info=True)

async def load_subs():
    global SUBS
    try:
        if os.path.exists(SUBS_FILE):
            async with aiofiles.open(SUBS_FILE, "r") as f:
                data = await f.read()
                SUBS = json.loads(data)
    except:
        SUBS = {}

async def save_subs():
    try:
        async with aiofiles.open(SUBS_FILE, "w") as f:
            await f.write(json.dumps(SUBS, ensure_ascii=False, indent=2))
    except:
        pass

async def load_initial_data():
    global DEFAULT_PATH, DOH_ENABLED, DEFAULT_XHTTP_PATH
    rows = await db_fetchall("SELECT * FROM links", "SELECT * FROM links")
    async with LINKS_LOCK:
        for r in rows:
            LINKS[r["uid"]] = dict(r)
    addr_rows = await db_fetchall("SELECT address, flag FROM custom_addresses", "SELECT address, flag FROM custom_addresses")
    async with CUSTOM_ADDRESSES_LOCK:
        CUSTOM_ADDRESSES[:] = [r["address"] for r in addr_rows]
        async with IP_FLAG_CACHE_LOCK:
            for r in addr_rows:
                if r["flag"]:
                    IP_FLAG_CACHE[r["address"]] = r["flag"]
    if not CUSTOM_ADDRESSES:
        CUSTOM_ADDRESSES.append("www.speedtest.net")
    if not LINKS:
        default_uuid = str(uuid_lib.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        default_link = {
            "uid": default_uuid, "label": "This Server is Free", "limit_bytes": 0, "used_bytes": 0,
            "max_connections": 0, "created_at": now, "active": 1, "expires_at": None,
            "custom_path": "", "custom_sni": "", "custom_host": "", "custom_fp": "chrome",
            "color": "#39ff14", "flag": "", "fragment": "", "ip_profile_id": "", "naming_mode": "default",
            "tfo": 0, "ech_enabled": 0, "ech_sni": "", "ech_doh": "",
            "fragment_mode": "off", "fragment_length": "100-200", "fragment_interval": "10-20",
            "allow_insecure": 0, "random_path": 0, "enable_ipv6": 1,
            "smux_enabled": 0, "ip_limit": 0, "protocol": "vless-ws",
            "fingerprint": "chrome", "alpn": "", "port": 443
        }
        async with LINKS_LOCK:
            LINKS[default_uuid] = default_link
        await db_execute(
            "INSERT INTO links (uid, label, limit_bytes, used_bytes, max_connections, created_at, active, expires_at, custom_path, custom_sni, custom_host, custom_fp, color, flag, fragment, ip_profile_id, naming_mode, tfo, ech_enabled, ech_sni, ech_doh, fragment_mode, fragment_length, fragment_interval, allow_insecure, random_path, enable_ipv6, smux_enabled, ip_limit, protocol, fingerprint, alpn, port) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            "INSERT INTO links (uid, label, limit_bytes, used_bytes, max_connections, created_at, active, expires_at, custom_path, custom_sni, custom_host, custom_fp, color, flag, fragment, ip_profile_id, naming_mode, tfo, ech_enabled, ech_sni, ech_doh, fragment_mode, fragment_length, fragment_interval, allow_insecure, random_path, enable_ipv6, smux_enabled, ip_limit, protocol, fingerprint, alpn, port) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33)",
            (default_uuid, "This Server is Free", 0, 0, 0, now, 1, None,
             "", "", "", "chrome",
             "#39ff14", "", "", "", "default",
             0, 0, "", "",
             "off", "100-200", "10-20",
             0, 0, 1,
             0, 0, "vless-ws",
             "chrome", "", 443),
        )
    total_usage = sum(link.get("used_bytes", 0) for link in LINKS.values())
    stats["total_bytes"] = total_usage
    profiles = await db_fetchall("SELECT * FROM ip_profiles", "SELECT * FROM ip_profiles")
    async with IP_PROFILES_LOCK:
        IP_PROFILES.clear()
        for p in profiles:
            pid = p["id"]
            addrs = await db_fetchall("SELECT address, flag FROM profile_addresses WHERE profile_id = ?", "SELECT address, flag FROM profile_addresses WHERE profile_id = $1", (pid,))
            IP_PROFILES[pid] = {"name": p["name"], "addresses": [a["address"] for a in addrs]}
            async with IP_FLAG_CACHE_LOCK:
                for a in addrs:
                    if a["flag"]:
                        IP_FLAG_CACHE[a["address"]] = a["flag"]
    global DOH_UPSTREAMS
    rows = await db_fetchall("SELECT url FROM doh_upstreams", "SELECT url FROM doh_upstreams")
    if rows:
        DOH_UPSTREAMS = [r["url"] for r in rows]
    else:
        DOH_UPSTREAMS = [
            "https://dns.cloudflare.com/dns-query",
            "https://dns.google/dns-query",
            "https://dns.quad9.net/dns-query",
            "https://doh.opendns.com/dns-query"
        ]
    def_path_row = await db_fetchone("SELECT value FROM settings WHERE key='default_path'", "SELECT value FROM settings WHERE key='default_path'")
    if def_path_row and def_path_row["value"]:
        DEFAULT_PATH = def_path_row["value"]
        # ---- XHTTP default path ----
    xhttp_path_row = await db_fetchone(
        "SELECT value FROM settings WHERE key='default_xhttp_path'",
        "SELECT value FROM settings WHERE key='default_xhttp_path'"
    )
    if xhttp_path_row and xhttp_path_row["value"]:
        DEFAULT_XHTTP_PATH = xhttp_path_row["value"]
    else:
        await db_execute(
            "INSERT OR IGNORE INTO settings (key, value) VALUES ('default_xhttp_path', ?)",
            "INSERT INTO settings (key, value) VALUES ('default_xhttp_path', $1) ON CONFLICT (key) DO NOTHING",
            (DEFAULT_XHTTP_PATH,)
        )
    doh_enabled_row = await db_fetchone("SELECT value FROM settings WHERE key='doh_enabled'", "SELECT value FROM settings WHERE key='doh_enabled'")
    if doh_enabled_row:
        DOH_ENABLED = doh_enabled_row["value"] == "1"
    else:
        DOH_ENABLED = True
    await load_subs()

async def fetch_ip_flag(ip: str) -> str:
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return ""
    async with IP_FLAG_CACHE_LOCK:
        if ip in IP_FLAG_CACHE:
            return IP_FLAG_CACHE[ip]
    async with flag_semaphore:
        code = ""
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                resp = await client.get(f"http://ip-api.com/json/{ip}")
                if resp.status_code == 200:
                    data = resp.json()
                    code = data.get("countryCode", "")
        except Exception:
            pass
        if not code:
            try:
                async with httpx.AsyncClient(timeout=3.0) as client:
                    resp = await client.get(f"https://ipapi.co/{ip}/country/")
                    if resp.status_code == 200:
                        code = resp.text.strip().upper()
                        if len(code) != 2:
                            code = ""
            except Exception:
                pass
        if not code:
            try:
                async with httpx.AsyncClient(timeout=3.0) as client:
                    resp = await client.get(f"https://ipinfo.io/{ip}/country")
                    if resp.status_code == 200:
                        code = resp.text.strip().upper()
                        if len(code) != 2:
                            code = ""
            except Exception:
                pass
        if code:
            async with IP_FLAG_CACHE_LOCK:
                if len(IP_FLAG_CACHE) >= IP_FLAG_CACHE_MAX:
                    IP_FLAG_CACHE.pop(next(iter(IP_FLAG_CACHE)))
                IP_FLAG_CACHE[ip] = code
            return code
    return ""

async def _keepalive_simple_loop():
    global KEEP_ALIVE_INTERVAL, KEEP_ALIVE_ENABLED, KEEP_ALIVE_MODE
    while True:
        await asyncio.sleep(KEEP_ALIVE_INTERVAL)
        if not KEEP_ALIVE_ENABLED or KEEP_ALIVE_MODE != "simple":
            continue
        domain = get_domain(request)
        if domain == "localhost":
            continue
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(f"https://{domain}/health")
                if resp.status_code == 200:
                    logger.info(f"Simple keep-alive successful: {domain}/health")
        except Exception:
            pass

async def _keepalive_advanced_loop():
    global KEEP_ALIVE_INTERVAL, KEEP_ALIVE_ENABLED, KEEP_ALIVE_MODE
    await asyncio.sleep(30)
    while True:
        if not KEEP_ALIVE_ENABLED or KEEP_ALIVE_MODE != "advanced":
            await asyncio.sleep(KEEP_ALIVE_INTERVAL)
            continue
        domain = os.environ.get("DOMAIN", "").strip()
        port = os.environ.get("PORT", "8000")
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9,fa;q=0.8",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
        }
        target_urls = []
        if domain:
            if not domain.startswith(("http://", "https://")):
                target_urls.append(f"https://{domain}/login")
                target_urls.append(f"http://{domain}/login")
            else:
                target_urls.append(f"{domain}/login")
        target_urls.append(f"http://127.0.0.1:{port}/login")
        async with httpx.AsyncClient(verify=False, timeout=15.0, headers=headers) as client:
            success = False
            for url in target_urls:
                try:
                    final_url = url + ("&" if "?" in url else "?") + f"_nocache={secrets.token_hex(4)}"
                    resp = await client.get(final_url, follow_redirects=True)
                    if resp.status_code == 200:
                        logger.info(f"Advanced keep-alive successful: {url}")
                        success = True
                        break
                except Exception as e:
                    logger.debug(f"Advanced keep-alive attempt failed for {url}: {e}")
            if not success:
                logger.warning("Advanced keep-alive: all attempts failed.")
        await asyncio.sleep(KEEP_ALIVE_INTERVAL)

async def cleanup_link_cache():
    while True:
        await asyncio.sleep(600)
        now = time.time()
        expired = [k for k, v in link_cache.items() if v["expires"] <= now]
        for k in expired:
            del link_cache[k]

# -------------------- Telegram helpers --------------------
TELEGRAM_USER_CREATE_STEPS = {}
telegram_create_timestamps = {}
TELEGRAM_CREATE_TIMEOUT = 600
user_tg_langs = {}
default_tg_lang = "en"

async def cleanup_telegram_create_steps():
    while True:
        await asyncio.sleep(120)
        now = time.time()
        stale = [chat_id for chat_id, ts in telegram_create_timestamps.items() if now - ts > TELEGRAM_CREATE_TIMEOUT]
        for chat_id in stale:
            TELEGRAM_USER_CREATE_STEPS.pop(chat_id, None)
            telegram_create_timestamps.pop(chat_id, None)

async def set_telegram_webhook():
    try:
        token_row = await db_fetchone("SELECT value FROM settings WHERE key = 'tg_bot_token'", "SELECT value FROM settings WHERE key = 'tg_bot_token'")
        if not token_row or not token_row["value"]:
            return
        token = token_row["value"]
        domain = get_domain(request)
        webhook_url = f"https://{domain}/api/tg-webhook"
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(f"https://api.telegram.org/bot{token}/setWebhook", json={"url": webhook_url})
            data = resp.json()
            if data.get("ok"):
                logger.info(f"Telegram webhook set to {webhook_url}")
            else:
                logger.warning(f"Failed to set webhook: {data.get('description')}")
    except Exception as e:
        logger.error(f"Error setting Telegram webhook: {e}")

async def send_telegram_message(chat_id, text, reply_markup=None):
    token_row = await db_fetchone("SELECT value FROM settings WHERE key = 'tg_bot_token'", "SELECT value FROM settings WHERE key = 'tg_bot_token'")
    if not token_row or not token_row["value"]:
        return
    token = token_row["value"]
    payload = {"chat_id": chat_id, "text": text}
    if reply_markup:
        payload["reply_markup"] = reply_markup
    async with httpx.AsyncClient(timeout=10.0) as client:
        await client.post(f"https://api.telegram.org/bot{token}/sendMessage", json=payload)

async def answer_callback(callback_id):
    token_row = await db_fetchone("SELECT value FROM settings WHERE key = 'tg_bot_token'", "SELECT value FROM settings WHERE key = 'tg_bot_token'")
    if not token_row or not token_row["value"]:
        return
    token = token_row["value"]
    async with httpx.AsyncClient(timeout=5.0) as client:
        await client.post(f"https://api.telegram.org/bot{token}/answerCallbackQuery", json={"callback_query_id": callback_id})

async def handle_telegram_stats(chat_id):
    lang = user_tg_langs.get(chat_id, default_tg_lang)
    msg = get_stats_message(lang)
    await send_telegram_message(chat_id, msg)

async def handle_telegram_users(chat_id):
    async with LINKS_LOCK:
        items = list(LINKS.values())
    lang = user_tg_langs.get(chat_id, default_tg_lang)
    if not items:
        msg = "No inbounds found." if lang == "en" else "هیچ اینباندی یافت نشد."
        await send_telegram_message(chat_id, msg)
        return
    keyboard = {"inline_keyboard": []}
    for link in items[:20]:
        label = link["label"]
        uid = link["uid"][:8]
        used = round(link["used_bytes"] / 1_073_741_824, 2)
        limit = round(link["limit_bytes"] / 1_073_741_824, 2) if link["limit_bytes"] else "∞"
        active = "✅" if link["active"] else "❌"
        btn_text = f"{active} {label} ({uid})"
        keyboard["inline_keyboard"].append([{"text": btn_text, "callback_data": f"userinfo_{link['uid']}"}])
    msg = "📋 Inbounds:" if lang == "en" else "📋 اینباندها:"
    await send_telegram_message(chat_id, msg, reply_markup=keyboard)

async def handle_telegram_user_info(chat_id, uid):
    async with LINKS_LOCK:
        link = LINKS.get(uid)
    lang = user_tg_langs.get(chat_id, default_tg_lang)
    if not link:
        msg = "Inbound not found." if lang == "en" else "اینباند یافت نشد."
        await send_telegram_message(chat_id, msg)
        return
    used = round(link["used_bytes"] / 1_073_741_824, 2)
    limit = round(link["limit_bytes"] / 1_073_741_824, 2) if link["limit_bytes"] else "∞"
    expires = link.get("expires_at") or "∞"
    if lang == "fa":
        msg = f"📡 {link['label']}\nUUID: {uid}\nترافیک: {used} GB / {limit} GB\nانقضا: {expires}\nفعال: {bool(link['active'])}"
    else:
        msg = f"📡 {link['label']}\nUUID: {uid}\nTraffic: {used} GB / {limit} GB\nExpires: {expires}\nActive: {bool(link['active'])}"
    await send_telegram_message(chat_id, msg)

def get_stats_message(lang: str) -> str:
    if lang == "fa":
        return (
            f"📊 آمار پنل SulgX\n"
            f"🕒 زمان فعالیت: {uptime()}\n"
            f"🔗 اتصالات فعال: {len(connections)}\n"
            f"📦 ترافیک کل: {round(stats['total_bytes'] / (1024 * 1024), 2)} MB\n"
            f"📡 درخواست‌ها: {stats['total_requests']}\n"
            f"❌ خطاها: {stats['total_errors']}"
        )
    return (
        f"📊 SulgX Panel Stats\n"
        f"🕒 Uptime: {uptime()}\n"
        f"🔗 Conns: {len(connections)}\n"
        f"📦 Traffic: {round(stats['total_bytes'] / (1024 * 1024), 2)} MB\n"
        f"📡 Requests: {stats['total_requests']}\n"
        f"❌ Errors: {stats['total_errors']}"
    )

def get_help_message(lang: str) -> str:
    if lang == "fa":
        return (
            "📚 دستورات ربات SulgX:\n\n"
            "/start - نمایش منوی اصلی\n"
            "/stats - آمار سرور\n"
            "/users - لیست اینباندها\n"
            "/create - ساخت اینباند جدید\n"
            "/help - راهنما\n\n"
            "دکمه‌های inline:\n"
            "- Stats: آمار لحظه‌ای\n"
            "- Inbounds: لیست صفحه‌بندی شده\n"
            "- Create: ساخت گام‌به‌گام\n"
            "- Delete: حذف اینباند\n"
            "- Change Language: تغییر زبان"
        )
    return (
        "📚 SulgX Bot Commands:\n\n"
        "/start - Show main menu\n"
        "/stats - Server statistics\n"
        "/users - List all inbounds\n"
        "/create - Create a new inbound\n"
        "/help - This help message\n\n"
        "Inline buttons:\n"
        "- Stats: instant stats\n"
        "- Inbounds: paginated list\n"
        "- Create: guided creation\n"
        "- Delete: select inbound to delete\n"
        "- Change Language: switch language"
    )
def get_welcome_message(lang: str) -> str:
    if lang == "fa":
        return "به ربات مدیریت SulgX خوش آمدید.\nلطفاً یکی از گزینه‌های زیر را انتخاب کنید:"
    return "Welcome to SulgX management bot.\nPlease choose an option:"
async def send_main_menu(chat_id: int, lang: str):
    help_text = get_help_message(lang)
    keyboard = {
        "inline_keyboard": [
            [{"text": ("📊 Stats" if lang == "en" else "📊 آمار"), "callback_data": "stats"}],
            [{"text": ("📋 Inbounds" if lang == "en" else "📋 اینباندها"), "callback_data": "users"}],
            [{"text": ("➕ Create" if lang == "en" else "➕ ایجاد"), "callback_data": "create_inbound"}],
            [{"text": ("❌ Delete" if lang == "en" else "❌ حذف"), "callback_data": "delete_user"}],
            [{"text": ("🌐 Change Language" if lang == "en" else "🌐 تغییر زبان"), "callback_data": "change_lang"}],
            [{"text": ("ℹ️ Help" if lang == "en" else "ℹ️ راهنما"), "callback_data": "help"}]
        ]
    }
    await send_telegram_message(chat_id, help_text, reply_markup=keyboard)

# -------------------- Lifespan --------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    global TIMEZONE_OFFSET, KEEP_ALIVE_ENABLED, KEEP_ALIVE_INTERVAL, KEEP_ALIVE_MODE, DOH_UPSTREAMS, DEFAULT_PATH, DOH_ENABLED
    global STEALTH_MODE, LANDING_REDIRECT, CAMOUFLAGE_URL, SUB_FILENAME, default_tg_lang
    if DB_BACKEND == "postgresql":
        await init_pg()
    else:
        await init_db()
    await load_initial_data()

    sk = await db_fetchone(
        "SELECT value FROM settings WHERE key = 'jwt_secret_key'",
        "SELECT value FROM settings WHERE key = 'jwt_secret_key'"
    )
    if sk:
        CONFIG["secret_key"] = sk["value"]
    else:
        await db_execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES ('jwt_secret_key', ?)",
            "INSERT INTO settings (key, value) VALUES ('jwt_secret_key', $1) ON CONFLICT (key) DO UPDATE SET value = $1",
            (CONFIG["secret_key"],)
        )

    hash_row = await db_fetchone(
        "SELECT value FROM settings WHERE key = 'admin_password_hash'",
        "SELECT value FROM settings WHERE key = 'admin_password_hash'",
    )
    global ADMIN_PASSWORD_HASH
    if hash_row:
        ADMIN_PASSWORD_HASH = hash_row["value"]
    else:
        ADMIN_PASSWORD_HASH = bcrypt.hashpw(CONFIG["admin_password"].encode(), bcrypt.gensalt()).decode()
        await db_execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES ('admin_password_hash', ?)",
            "INSERT INTO settings (key, value) VALUES ('admin_password_hash', $1) ON CONFLICT (key) DO UPDATE SET value = $1",
            (ADMIN_PASSWORD_HASH,),
        )

    log_row = await db_fetchone(
        "SELECT value FROM settings WHERE key = 'log_enabled'",
        "SELECT value FROM settings WHERE key = 'log_enabled'"
    )
    global ENABLE_LOGGING
    ENABLE_LOGGING = (log_row and log_row["value"] == "1") if log_row else True

    tz_row = await db_fetchone(
        "SELECT value FROM settings WHERE key='timezone_offset'",
        "SELECT value FROM settings WHERE key='timezone_offset'"
    )
    if tz_row and tz_row["value"]:
        try:
            TIMEZONE_OFFSET = float(tz_row["value"])
        except:
            TIMEZONE_OFFSET = 0.0

    ke_row = await db_fetchone(
        "SELECT value FROM settings WHERE key='keep_alive_enabled'",
        "SELECT value FROM settings WHERE key='keep_alive_enabled'"
    )
    if ke_row and ke_row["value"] is not None:
        KEEP_ALIVE_ENABLED = (ke_row["value"] == "1")

    km_row = await db_fetchone(
        "SELECT value FROM settings WHERE key='keep_alive_mode'",
        "SELECT value FROM settings WHERE key='keep_alive_mode'"
    )
    if km_row and km_row["value"]:
        KEEP_ALIVE_MODE = km_row["value"]

    interval_row = await db_fetchone(
        "SELECT value FROM settings WHERE key='keep_alive_interval'",
        "SELECT value FROM settings WHERE key='keep_alive_interval'"
    )
    if interval_row and interval_row["value"]:
        try:
            KEEP_ALIVE_INTERVAL = max(60, int(interval_row["value"]))
        except:
            pass

    def_path_row = await db_fetchone("SELECT value FROM settings WHERE key='default_path'", "SELECT value FROM settings WHERE key='default_path'")
    if def_path_row and def_path_row["value"]:
        DEFAULT_PATH = def_path_row["value"]

    doh_enabled_row = await db_fetchone("SELECT value FROM settings WHERE key='doh_enabled'", "SELECT value FROM settings WHERE key='doh_enabled'")
    if doh_enabled_row:
        DOH_ENABLED = doh_enabled_row["value"] == "1"
    else:
        DOH_ENABLED = True

    stealth_row = await db_fetchone("SELECT value FROM settings WHERE key='stealth_mode'", "SELECT value FROM settings WHERE key='stealth_mode'")
    if stealth_row:
        STEALTH_MODE = stealth_row["value"] == "1"
    lr_row = await db_fetchone("SELECT value FROM settings WHERE key='landing_redirect'", "SELECT value FROM settings WHERE key='landing_redirect'")
    if lr_row:
        LANDING_REDIRECT = lr_row["value"].strip()
    cm_row = await db_fetchone("SELECT value FROM settings WHERE key='camouflage_url'", "SELECT value FROM settings WHERE key='camouflage_url'")
    if cm_row:
        CAMOUFLAGE_URL = cm_row["value"].strip()
    sf_row = await db_fetchone("SELECT value FROM settings WHERE key='sub_filename'", "SELECT value FROM settings WHERE key='sub_filename'")
    if sf_row:
        SUB_FILENAME = sf_row["value"].strip()
    prefix_row = await db_fetchone("SELECT value FROM settings WHERE key='panel_prefix'",
                               "SELECT value FROM settings WHERE key='panel_prefix'")
    global PANEL_PREFIX
    if prefix_row and prefix_row["value"].strip():
        PANEL_PREFIX = prefix_row["value"].strip()

    tg_lang_row = await db_fetchone("SELECT value FROM settings WHERE key='telegram_lang'",
                                    "SELECT value FROM settings WHERE key='telegram_lang'")
    global default_tg_lang
    if tg_lang_row:
        default_tg_lang = tg_lang_row["value"] if tg_lang_row["value"] in ("en","fa") else "en"
    blocked_row = await db_fetchone("SELECT value FROM settings WHERE key='blocked_domains'",
                                "SELECT value FROM settings WHERE key='blocked_domains'")
    BLOCKED_DOMAINS = set()
    if blocked_row and blocked_row["value"]:
        BLOCKED_DOMAINS = set(d.strip().lower() for d in blocked_row["value"].split(",") if d.strip())

    asyncio.create_task(set_telegram_webhook())
    asyncio.create_task(_keepalive_simple_loop())
    asyncio.create_task(_keepalive_advanced_loop())
    asyncio.create_task(cleanup_idle_connections())
    asyncio.create_task(telegram_reporter())
    asyncio.create_task(flush_traffic_buffer())
    asyncio.create_task(sync_usage_to_db())
    asyncio.create_task(auto_disable_expired_links())
    asyncio.create_task(cleanup_link_cache())
    asyncio.create_task(cleanup_telegram_create_steps())
    yield
    if DB_BACKEND == "sqlite" and db_conn:
        await db_conn.close()

app = FastAPI(title="SulgX Panel", lifespan=lifespan, docs_url=None, redoc_url=None)

from starlette.types import ASGIApp, Scope, Receive, Send

class PanelPrefixMiddleware:
    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        prefix_row = await db_fetchone(
            "SELECT value FROM settings WHERE key='panel_prefix'",
            "SELECT value FROM settings WHERE key='panel_prefix'"
        )
        current_prefix = prefix_row["value"].strip() if prefix_row and prefix_row["value"].strip() else ""

        if current_prefix:
            prefix = f"/{current_prefix}"
            request_path = scope.get("path", "")
            if request_path.startswith(prefix):
                new_path = request_path[len(prefix):]
                if not new_path.startswith("/"):
                    new_path = "/" + new_path
                scope["path"] = new_path
                scope["root_path"] = prefix

        await self.app(scope, receive, send)

app.add_middleware(PanelPrefixMiddleware)
@app.post("/api/tg-webhook")
async def telegram_webhook(request: Request):
    try:
        update = await request.json()
    except Exception:
        return {"ok": False}

    if "message" in update:
        msg = update["message"]
        chat_id = msg.get("chat", {}).get("id")
        text = msg.get("text", "")
        if not chat_id:
            return {"ok": False}

        admin_chat_row = await db_fetchone("SELECT value FROM settings WHERE key = 'tg_chat_id'",
                                           "SELECT value FROM settings WHERE key = 'tg_chat_id'")
        if not admin_chat_row or str(chat_id) != admin_chat_row["value"]:
            await send_telegram_message(chat_id, "⛔ No access.")
            return {"ok": True}

        lang = user_tg_langs.get(chat_id, default_tg_lang)

        if text.startswith("/start"):
            lang = user_tg_langs.get(chat_id, default_tg_lang)
            await send_telegram_message(chat_id, get_welcome_message(lang))
            await send_main_menu(chat_id, lang)
            return {"ok": True}

        elif text.startswith("/stats"):
            msg_text = get_stats_message(lang)
            await send_telegram_message(chat_id, msg_text)

        elif text.startswith("/users"):
            await handle_telegram_users(chat_id)

        elif text.startswith("/create"):
            TELEGRAM_USER_CREATE_STEPS[chat_id] = {"step": "name", "data": {}}
            telegram_create_timestamps[chat_id] = time.time()
            prompt = "Enter inbound name:" if lang == "en" else "نام اینباند را وارد کنید:"
            await send_telegram_message(chat_id, prompt)

        elif text.startswith("/help"):
            await send_telegram_message(chat_id, get_help_message(lang))

        else:
            if chat_id in TELEGRAM_USER_CREATE_STEPS:
                step = TELEGRAM_USER_CREATE_STEPS[chat_id]
                if step["step"] == "name":
                    step["data"]["label"] = text
                    step["step"] = "limit"
                    msg_prompt = "Enter limit (GB, 0 = unlimited):" if lang == "en" else "حجم را وارد کنید (گیگابایت، 0 = نامحدود):"
                    await send_telegram_message(chat_id, msg_prompt)
                elif step["step"] == "limit":
                    try:
                        limit = float(text)
                    except:
                        limit = 0
                    step["data"]["limit"] = limit
                    step["step"] = "days"
                    msg_prompt = "Enter validity days (0 = unlimited):" if lang == "en" else "تعداد روز اعتبار را وارد کنید (0 = نامحدود):"
                    await send_telegram_message(chat_id, msg_prompt)
                elif step["step"] == "days":
                    try:
                        days = int(text)
                    except:
                        days = 0
                    step["data"]["days"] = days
                    label = step["data"]["label"]
                    limit = step["data"]["limit"]
                    uid = str(uuid_lib.uuid4())
                    now = datetime.now(timezone.utc).isoformat()
                    expires = None
                    if days > 0:
                        expires = (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()
                    
                    link_data = {
                        "uid": uid, "label": label, "limit_bytes": int(limit*1073741824) if limit else 0, "used_bytes": 0,
                        "max_connections": 0, "created_at": now, "active": 1, "expires_at": expires,
                        "custom_path": "", "custom_sni": "", "custom_host": "", "custom_fp": "chrome",
                        "color": "#39ff14", "flag": "", "fragment": "", "ip_profile_id": "", "naming_mode": "default",
                        "tfo": 0, "ech_enabled": 0, "ech_sni": "", "ech_doh": "",
                        "fragment_mode": "off", "fragment_length": "100-200", "fragment_interval": "10-20",
                        "allow_insecure": 0, "random_path": 0, "enable_ipv6": 1,
                        "smux_enabled": 0, "ip_limit": 0, "protocol": "vless-ws",
                        "fingerprint": "chrome", "alpn": "", "port": 443
                    }
                    async with LINKS_LOCK:
                        LINKS[uid] = link_data
                    
                    await db_execute(
                        "INSERT INTO links (uid, label, limit_bytes, used_bytes, max_connections, created_at, active, expires_at, custom_path, custom_sni, custom_host, custom_fp, color, flag, fragment, ip_profile_id, naming_mode, tfo, ech_enabled, ech_sni, ech_doh, fragment_mode, fragment_length, fragment_interval, allow_insecure, random_path, enable_ipv6, smux_enabled, ip_limit, protocol, fingerprint, alpn, port) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        "INSERT INTO links (uid, label, limit_bytes, used_bytes, max_connections, created_at, active, expires_at, custom_path, custom_sni, custom_host, custom_fp, color, flag, fragment, ip_profile_id, naming_mode, tfo, ech_enabled, ech_sni, ech_doh, fragment_mode, fragment_length, fragment_interval, allow_insecure, random_path, enable_ipv6, smux_enabled, ip_limit, protocol, fingerprint, alpn, port) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33)",
                        (uid, label, link_data["limit_bytes"], link_data["used_bytes"], link_data["max_connections"], now, link_data["active"], expires,
                         link_data["custom_path"], link_data["custom_sni"], link_data["custom_host"], link_data["custom_fp"],
                         link_data["color"], link_data["flag"], link_data["fragment"], link_data["ip_profile_id"], link_data["naming_mode"],
                         link_data["tfo"], link_data["ech_enabled"], link_data["ech_sni"], link_data["ech_doh"],
                         link_data["fragment_mode"], link_data["fragment_length"], link_data["fragment_interval"],
                         link_data["allow_insecure"], link_data["random_path"], link_data["enable_ipv6"],
                         link_data["smux_enabled"], link_data["ip_limit"], link_data["protocol"],
                         link_data["fingerprint"], link_data["alpn"], link_data["port"])
                    )
                    
                    del TELEGRAM_USER_CREATE_STEPS[chat_id]
                    telegram_create_timestamps.pop(chat_id, None)
                    success_msg = f"✅ Inbound created: {label}" if lang == "en" else f"✅ اینباند ساخته شد: {label}"
                    await send_telegram_message(chat_id, success_msg)
                return {"ok": True}

            await send_telegram_message(chat_id, "Unknown command. Try /help" if lang=="en" else "دستور ناشناخته. /help را امتحان کنید.")

    elif "callback_query" in update:
        query = update["callback_query"]
        chat_id = query.get("message", {}).get("chat", {}).get("id")
        data = query.get("data")
        if not chat_id or not data:
            return {"ok": False}

        await answer_callback(query.get("id"))
        lang = user_tg_langs.get(chat_id, default_tg_lang)

        if data in ("lang_en", "lang_fa"):
            chosen = "en" if data == "lang_en" else "fa"
            user_tg_langs[chat_id] = chosen
            await send_main_menu(chat_id, chosen)
            return {"ok": True}

        if data == "change_lang":
            await send_telegram_message(chat_id,
                "🌐 Please select your language / لطفاً زبان خود را انتخاب کنید:",
                reply_markup={"inline_keyboard": [
                    [{"text": "English", "callback_data": "lang_en"},
                     {"text": "فارسی", "callback_data": "lang_fa"}]
                ]})
            return {"ok": True}

        if data == "stats":
            await send_telegram_message(chat_id, get_stats_message(lang))
        elif data == "users":
            await handle_telegram_users(chat_id)
        elif data == "create_inbound":
            TELEGRAM_USER_CREATE_STEPS[chat_id] = {"step": "name", "data": {}}
            telegram_create_timestamps[chat_id] = time.time()
            prompt = "Enter inbound name:" if lang == "en" else "نام اینباند را وارد کنید:"
            await send_telegram_message(chat_id, prompt)
        elif data.startswith("userinfo_"):
            uid = data.replace("userinfo_", "")
            await handle_telegram_user_info(chat_id, uid)
        elif data == "delete_user":
            msg = "Please use /users and select an inbound to delete." if lang == "en" else "لطفاً از /users استفاده کنید و یک اینباند را برای حذف انتخاب کنید."
            await send_telegram_message(chat_id, msg)
        elif data == "help":
            await send_telegram_message(chat_id, get_help_message(lang))
        else:
            await send_telegram_message(chat_id, "Unknown action." if lang=="en" else "عملیات ناشناخته.")

    return {"ok": True}

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    return response

@app.middleware("http")
async def stealth_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Server"] = "nginx"
    try:
        del response.headers["x-powered-by"]
    except KeyError:
        pass
    return response

# -------------------- Application state --------------------
connections: dict = {}
connections_lock = asyncio.Lock()
connection_sockets: dict = {}
link_ip_map: dict = defaultdict(set)
stats = {
    "total_bytes": 0,
    "total_requests": 0,
    "total_errors": 0,
    "start_time": time.time(),
    "upload_bytes": 0,
    "download_bytes": 0,
}
error_logs: deque = deque(maxlen=2000)

CACHE_TTL = 60
link_cache: dict = {}

UNLIMITED_QUOTA_BYTES = 53687091200000

ADMIN_PASSWORD_HASH: str = ""
ENABLE_LOGGING: bool = True
KEEP_ALIVE_ENABLED: bool = True
KEEP_ALIVE_MODE: str = "simple"
DEFAULT_PATH = "/ws/{uid}"
DOH_ENABLED: bool = True

# -------------------- Utility functions --------------------
def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())

def create_jwt_token(data: dict, expires_delta: timedelta = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=CONFIG["jwt_expire_minutes"]))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, CONFIG["secret_key"], algorithm=CONFIG["jwt_algorithm"])

def decode_jwt_token(token: str) -> Optional[dict]:
    try:
        return jwt.decode(token, CONFIG["secret_key"], algorithms=[CONFIG["jwt_algorithm"]])
    except JWTError:
        return None

async def require_auth(request: Request):
    token = None
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
    if not token:
        cookie_name = await get_session_cookie_name()
        token = request.cookies.get(cookie_name)
    if not token or not decode_jwt_token(token):
        raise HTTPException(status_code=401, detail="unauthorized")
    return token

async def cleanup_idle_connections():
    while True:
        await asyncio.sleep(60)
        now = time.time()
        async with connections_lock:
            idle = [cid for cid, info in connections.items() if now - info.get("last_active", 0) > 300]
        for cid in idle:
            ws = connection_sockets.get(cid)
            if ws:
                try:
                    await ws.close(code=1000, reason="idle timeout")
                except Exception:
                    pass
            async with connections_lock:
                connections.pop(cid, None)
            connection_sockets.pop(cid, None)

async def auto_disable_expired_links():
    while True:
        await asyncio.sleep(60)
        try:
            row = await db_fetchone("SELECT value FROM settings WHERE key='auto_disable_enabled'", "SELECT value FROM settings WHERE key='auto_disable_enabled'")
            if row and row["value"] != "1":
                continue
            now = datetime.now(timezone.utc)
            async with LINKS_LOCK:
                for uid, link in LINKS.items():
                    if link.get("active") and link.get("expires_at"):
                        exp = parse_expires_at(link["expires_at"])
                        if exp and exp < now:
                            link["active"] = 0
                            await db_execute("UPDATE links SET active = 0 WHERE uid = ?", "UPDATE links SET active = FALSE WHERE uid = $1", (uid,))
                            log_event("Auto", f"Expired inbound {link['label']} auto-disabled")
        except Exception as e:
            logger.error(f"auto_disable_expired_links error: {e}", exc_info=True)

telegram_report_lock = asyncio.Lock()

async def telegram_reporter():
    while True:
        interval_hours = 1
        row = await db_fetchone("SELECT value FROM settings WHERE key = 'telegram_interval'",
                                "SELECT value FROM settings WHERE key = 'telegram_interval'")
        if row and row["value"]:
            try:
                interval_hours = float(row["value"])
            except:
                interval_hours = 1
        await asyncio.sleep(3600 * interval_hours)

        en_row = await db_fetchone("SELECT value FROM settings WHERE key='telegram_report_enabled'",
                                   "SELECT value FROM settings WHERE key='telegram_report_enabled'")
        if not en_row or en_row["value"] != "1":
            continue

        async with telegram_report_lock:
            token_row = await db_fetchone("SELECT value FROM settings WHERE key = 'tg_bot_token'",
                                          "SELECT value FROM settings WHERE key = 'tg_bot_token'")
            chat_row = await db_fetchone("SELECT value FROM settings WHERE key = 'tg_chat_id'",
                                         "SELECT value FROM settings WHERE key = 'tg_chat_id'")
            if not token_row or not chat_row or not token_row["value"] or not chat_row["value"]:
                continue

            total_bytes = stats["total_bytes"]
            total_requests = stats["total_requests"]
            if total_bytes == 0 and total_requests == 0:
                continue

            msg = (
                f"📊 SulgX Panel Stats\n"
                f"🕒 Uptime: {uptime()}\n"
                f"🔗 Conns: {len(connections)}\n"
                f"📦 Traffic: {round(total_bytes/(1024*1024),2)} MB\n"
                f"📡 Requests: {total_requests}\n"
                f"❌ Errors: {stats['total_errors']}"
            )
            url = f"https://api.telegram.org/bot{token_row['value']}/sendMessage"
            try:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    await client.post(url, json={"chat_id": chat_row["value"], "text": msg})
            except Exception:
                pass

def get_domain(request: Optional[Request] = None) -> str:
    if request and request.headers.get("host"):
        host = request.headers["host"].split(":")[0]
        if host not in ("localhost", "127.0.0.1", "0.0.0.0", "::1"):
            return host
    for var in ("DOMAIN", "RAILWAY_PUBLIC_DOMAIN", "RENDER_EXTERNAL_URL"):
        val = os.environ.get(var)
        if val:
            return val.replace("https://", "").replace("http://", "").rstrip("/")
    return "localhost"

def validate_address(addr: str) -> bool:
    try:
        ipaddress.ip_address(addr.strip('[]'))
        return True
    except ValueError:
        pass
    try:
        ipaddress.ip_network(addr.strip('[]'), strict=False)
        return True
    except ValueError:
        pass
    return re.match(r'^[a-zA-Z0-9\-_.%]+$', addr) is not None

def format_host_port(host: str, port: int = 443) -> str:
    host = host.strip('[]')
    try:
        ipaddress.IPv6Address(host)
        return f"[{host}]:{port}"
    except ipaddress.AddressValueError:
        return f"{host}:{port}"

def code_to_flag(code: str) -> str:
    if not code or len(code) != 2:
        return ""
    code = code.upper()
    try:
        return chr(ord(code[0]) + 127397) + chr(ord(code[1]) + 127397)
    except:
        return ""

def get_effective_path(link: dict) -> str:
    custom = link.get("custom_path", "")
    if custom:
        return custom
    return DEFAULT_PATH if DEFAULT_PATH else "/ws/{uid}"

def generate_vless_link(uid: str, remark: str = "SulgX", address: str = None, extra: dict = None, server_domain: str = None) -> str:
    domain = server_domain or get_domain()
    cache_key = f"{uid}:{remark}:{address}:{domain}:" + (json.dumps(extra) if extra else '')
    if cache_key in link_cache and link_cache[cache_key]["expires"] > time.time():
        return link_cache[cache_key]["link"]
    addr = address if address else domain
    path = get_effective_path(extra) if extra else DEFAULT_PATH
    path = path.replace("{uid}", uid)
    if extra and extra.get("random_path", False):
        path = "/" + secrets.token_hex(4) + path
    sni = (extra.get("custom_sni") or domain) if extra else domain
    host = (extra.get("custom_host") or domain) if extra else domain
    fragment = extra.get("fragment", "") if extra else ""
    allow_insecure = extra.get("allow_insecure", False) if extra else False
    ech_enabled = extra.get("ech_enabled", False) if extra else False
    ech_sni = extra.get("ech_sni", "") if extra else ""
    ech_doh = extra.get("ech_doh", "") if extra else ""
    protocol = extra.get("protocol", "vless-ws") if extra else "vless-ws"
    fp_raw = (extra.get("fingerprint") or extra.get("custom_fp") or "").strip() if extra else ""
    fingerprint = None if (not fp_raw or fp_raw.lower() == "none") else fp_raw
    alpn_raw = (extra.get("alpn") or "").strip() if extra else ""
    alpn = None if not alpn_raw else alpn_raw
    port = extra.get("port", 443) if extra else 443

    if protocol == "vless-ws":
        path = get_effective_path(extra) if extra else DEFAULT_PATH
        path = path.replace("{uid}", uid)
        if extra and extra.get("random_path", False):
            path = "/" + secrets.token_hex(4) + path
        params = {
            "encryption": "none", "security": "tls", "type": "ws",
            "host": host, "path": path, "sni": sni
        }
        if fingerprint:
            params["fp"] = fingerprint
        if alpn:
            params["alpn"] = alpn
    else:
        base_path = extra.get("custom_path") if extra and extra.get("custom_path") else DEFAULT_XHTTP_PATH
        if not base_path.startswith("/"):
            base_path = "/" + base_path
        if base_path.endswith("/"):
            base_path = base_path[:-1]

        mode = protocol.replace("xhttp-", "")

        if mode not in ("stream-one", "auto"):
            base_path = f"{base_path}/{mode}/{uid}"

        params = {
            "encryption": "none", "security": "tls", "type": "xhttp",
            "mode": mode, "host": host, "path": base_path, "sni": sni
        }
        if fingerprint:
            params["fp"] = fingerprint
        if alpn:
            params["alpn"] = alpn
        else:
            params["alpn"] = "http/1.1"

    if fragment:
        params["fragment"] = fragment
    if allow_insecure:
        params["pinnedPeerCertificateChainSha256"] = quote(json.dumps([""]))
    if ech_enabled and ech_sni:
        ech_param = ech_sni
        if ech_doh:
            ech_param += "+" + ech_doh
        params["ech"] = ech_param

    query = "&".join(f"{k}={quote(str(v))}" for k, v in params.items())
    link = f"vless://{uid}@{format_host_port(addr, port)}?{query}#{quote(remark)}"
    link_cache[cache_key] = {"link": link, "expires": time.time() + CACHE_TTL}
    return link

def uptime() -> str:
    secs = int(time.time() - stats["start_time"])
    h, m, s = secs // 3600, (secs % 3600) // 60, secs % 60
    return f"{h:02d}:{m:02d}:{s:02d}"

def parse_size_to_bytes(value: float, unit: str) -> int:
    u = unit.upper()
    if u == "GB":
        return int(value * 1024**3)
    if u == "MB":
        return int(value * 1024**2)
    if u == "KB":
        return int(value * 1024)
    return int(value)

def parse_expires_at(raw: Optional[str]) -> Optional[datetime]:
    if not raw:
        return None
    try:
        s = raw.replace("Z", "+00:00")
        dt = datetime.fromisoformat(s)
        return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt
    except Exception:
        return None

def seconds_until_expiry(expires_at_str: Optional[str]) -> Optional[int]:
    exp = parse_expires_at(expires_at_str)
    if exp is None:
        return None
    return max(0, int((exp - datetime.now(timezone.utc)).total_seconds()))

async def count_connections_for_link(uid: str) -> int:
    async with connections_lock:
        return sum(1 for info in connections.values() if info.get("uuid") == uid)

async def close_connections_for_link(uid: str):
    async with connections_lock:
        to_close = [cid for cid, info in connections.items() if info.get("uuid") == uid]
    for cid in to_close:
        ws = connection_sockets.get(cid)
        if ws:
            try:
                await ws.close(code=1000, reason="link deleted/blocked")
            except Exception:
                pass
        async with connections_lock:
            connections.pop(cid, None)
        connection_sockets.pop(cid, None)
    async with connections_lock:
        link_ip_map.pop(uid, None)

def log_event(etype: str, message: str, ip: str = "", ua: str = ""):
    error_logs.append({
        "time": datetime.now(timezone.utc).isoformat(),
        "type": etype,
        "error": message or "(no detail)",
        "ip": ip,
        "ua": ua,
    })

def parse_user_agent(ua: str) -> tuple:
    browser, os_name = "", ""
    if "Windows NT" in ua:
        os_name = "Windows"
    elif "Mac OS X" in ua:
        os_name = "macOS"
    elif "Linux" in ua and "Android" not in ua:
        os_name = "Linux"
    elif "Android" in ua:
        os_name = "Android"
    elif "iPhone" in ua or "iPad" in ua:
        os_name = "iOS"
    else:
        os_name = "Unknown"
    if "Firefox" in ua:
        browser = "Firefox"
    elif "Edg/" in ua:
        browser = "Edge"
    elif "Chrome" in ua and "Safari" in ua:
        browser = "Chrome"
    elif "Safari" in ua:
        browser = "Safari"
    elif "MSIE" in ua or "Trident" in ua:
        browser = "IE"
    else:
        browser = "Unknown"
    return browser, os_name

LANDING_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<title>SulgX - Welcome</title>
<link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@700;900&family=Inter:wght@400;500;600;700&family=Vazirmatn:wght@400;600;700;800&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{
  --primary:#39ff14; --primary-dim:rgba(57,255,20,0.20); --primary-glass:rgba(57,255,20,0.10);
  --bg:#09090b; --bg2:#111113; --bg3:#18181b;
  --surface:rgba(18,18,20,0.8); --surface2:rgba(24,24,27,0.92); --surface3:rgba(30,30,35,0.88);
  --border:rgba(57,255,20,0.14); --border2:rgba(57,255,20,0.30);
  --text:#f0f0f4; --text2:#a1a1aa; --text3:#71717a;
  --green:#4ade80; --red:#f87171; --yellow:#fbbf24;
  --header-h:68px; --footer-h:52px;
  --radius-sm:12px; --radius-md:18px; --radius-lg:26px;
  --shadow:0 12px 40px rgba(0,0,0,0.6);
  --shadow-soft:0 6px 24px rgba(0,0,0,0.35);
  --shadow-glow:0 0 35px var(--primary-dim);
  --transition:0.3s cubic-bezier(0.20,0.80,0.40,1);
  --halo-color-1:rgba(57,255,20,0.22); --halo-color-2:rgba(57,255,20,0.10); --halo-color-3:rgba(57,255,20,0.05);
}
body.light-mode {
  --primary:#2e7d32; --primary-dim:rgba(46,125,50,0.20); --primary-glass:rgba(46,125,50,0.10);
  --bg:#f5f9f5; --bg2:#ffffff; --bg3:#eaf1ea;
  --surface:rgba(255,255,255,0.8); --surface2:rgba(255,255,255,0.94); --surface3:rgba(245,250,245,0.90);
  --border:rgba(0,0,0,0.12); --border2:rgba(0,0,0,0.22);
  --text:#1a1a1a; --text2:#4a4a4a; --text3:#888;
  --shadow:0 12px 36px rgba(0,0,0,0.10); --shadow-soft:0 6px 20px rgba(0,0,0,0.06); --shadow-glow:0 0 30px rgba(46,125,50,0.25);
  --halo-color-1:rgba(46,125,50,0.20); --halo-color-2:rgba(46,125,50,0.10); --halo-color-3:rgba(46,125,50,0.05);
}
body.blue-mode {
  --primary:#3b82f6; --primary-dim:rgba(59,130,246,0.20); --primary-glass:rgba(59,130,246,0.10);
  --bg:#0f172a; --bg2:#1e293b; --bg3:#1e293b;
  --surface:rgba(30,41,59,0.82); --surface2:rgba(30,41,59,0.94); --surface3:rgba(51,65,85,0.90);
  --border:rgba(59,130,246,0.14); --border2:rgba(59,130,246,0.34);
  --text:#e2e8f0; --text2:#94a3b8; --text3:#64748b;
  --shadow:0 12px 40px rgba(0,0,0,0.5); --shadow-soft:0 6px 24px rgba(0,0,0,0.3); --shadow-glow:0 0 35px rgba(59,130,246,0.35);
  --halo-color-1:rgba(59,130,246,0.22); --halo-color-2:rgba(59,130,246,0.10); --halo-color-3:rgba(59,130,246,0.05);
}
html,body{height:100%;overflow-x:hidden}
body{
  font-family:'Inter','Vazirmatn',sans-serif; color:var(--text); display:flex; flex-direction:column;
  background:var(--bg); transition:background 0.5s,color 0.5s; position:relative; line-height:1.65;
  -webkit-font-smoothing:antialiased;
}
body::before{
  content:''; position:fixed; top:-50%; left:-30%; width:90%; height:110%;
  background:radial-gradient(ellipse at 35% 45%,var(--halo-color-1) 0%,transparent 60%);
  animation:haloFloat1 28s infinite alternate ease-in-out; z-index:0; pointer-events:none;
  filter:blur(70px); mix-blend-mode:screen; opacity:0.85;
}
body::after{
  content:''; position:fixed; bottom:-50%; right:-30%; width:90%; height:110%;
  background:radial-gradient(ellipse at 65% 55%,var(--halo-color-2) 0%,transparent 60%);
  animation:haloFloat2 32s infinite alternate ease-in-out; z-index:0; pointer-events:none;
  filter:blur(90px); mix-blend-mode:screen; opacity:0.85;
}
@keyframes haloFloat1{0%{transform:translate(0,0) scale(1)}100%{transform:translate(8%,10%) scale(1.15)}}
@keyframes haloFloat2{0%{transform:translate(0,0) scale(1)}100%{transform:translate(-8%,-10%) scale(1.15)}}
body[dir="rtl"]{direction:rtl;text-align:right}
a{text-decoration:none;color:inherit}
.header{
  min-height:var(--header-h); background:var(--surface); border-bottom:1px solid var(--border);
  display:flex; align-items:center; justify-content:center; padding:0 28px;
  backdrop-filter:blur(30px) saturate(150%); position:sticky; top:0; z-index:101;
  box-shadow:0 2px 20px rgba(0,0,0,0.2);
}
.header-inner{display:flex;align-items:center;justify-content:space-between;width:100%;max-width:1440px;flex-wrap:nowrap;gap:16px}
.logo{
  font-family:'Orbitron',sans-serif; font-size:1.9rem; font-weight:900; color:var(--primary);
  letter-spacing:2px; text-shadow:0 0 20px var(--primary-dim); transition:text-shadow 0.3s,transform 0.3s; flex-shrink:0
}
.logo:hover{text-shadow:0 0 38px var(--primary-dim);transform:scale(1.04)}
.header-right{display:flex;align-items:center;gap:10px;flex-wrap:nowrap;flex-shrink:0}
.lang-switch{display:flex;gap:2px;background:var(--surface3);border-radius:var(--radius-sm);padding:3px;backdrop-filter:blur(8px)}
.lang-btn{
  padding:6px 14px;border:none;background:transparent;color:var(--text3);font-size:0.8rem;font-weight:700;
  border-radius:8px;cursor:pointer;font-family:inherit;transition:all var(--transition)
}
.lang-btn.active{background:var(--primary);color:#000;box-shadow:0 0 16px var(--primary-dim)}
.btn-icon{
  background:var(--surface3);border:1px solid var(--border);color:var(--text3);border-radius:var(--radius-sm);
  padding:10px;cursor:pointer;transition:all var(--transition);font-size:1.1rem;backdrop-filter:blur(8px);
  display:inline-flex;align-items:center;justify-content:center;flex-shrink:0;position:relative;overflow:hidden
}
.btn-icon:hover{color:var(--primary);border-color:transparent;background:var(--primary-glass);transform:translateY(-2px)}
.main{flex:1;display:flex;align-items:center;justify-content:center;padding:36px 24px;position:relative;z-index:1}
.card{
  background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-lg);
  padding:42px 28px;max-width:520px;width:100%;box-shadow:var(--shadow),0 0 45px var(--primary-dim);
  backdrop-filter:blur(20px) saturate(110%);text-align:center;position:relative;overflow:hidden
}
.card::before{
  content:'';position:absolute;inset:0;border-radius:inherit;padding:1px;
  pointer-events: none;
  background:conic-gradient(from var(--angle,0deg),transparent,var(--primary),transparent);
  -webkit-mask:linear-gradient(#fff 0 0) content-box,linear-gradient(#fff 0 0);
  mask:linear-gradient(#fff 0 0) content-box,linear-gradient(#fff 0 0);
  -webkit-mask-composite:xor;mask-composite:exclude;
  animation:borderRotate 5s linear infinite paused;opacity:0;transition:opacity 0.4s
}
.card:hover::before{opacity:1;animation-play-state:running}
@property --angle{syntax:'<angle>';initial-value:0deg;inherits:false}
@keyframes borderRotate{from{--angle:0deg}to{--angle:360deg}}
h1{font-family:'Orbitron',sans-serif;color:var(--primary);font-size:2.2rem;margin-bottom:12px;text-shadow:0 0 20px var(--primary-dim)}
.subtitle{color:var(--text3);font-size:0.95rem;margin-bottom:32px;min-height:2em;line-height:1.5}
.steps{text-align:left;margin-bottom:24px}
.step{
  display:flex;align-items:flex-start;gap:12px;margin-bottom:16px;padding:14px;
  background:var(--surface3);border-radius:var(--radius-sm);border:1px solid var(--border);
  backdrop-filter:blur(8px);transition:all var(--transition)
}
.step:hover{border-color:var(--primary);background:var(--primary-glass)}
.step-num{font-size:1.2rem;font-weight:900;color:var(--primary);min-width:32px;text-align:center}
.step-text{font-size:0.9rem;color:var(--text);line-height:1.5}
.btn{
  font-family:inherit;font-size:0.9rem;font-weight:700;border-radius:var(--radius-sm);
  padding:12px 26px;cursor:pointer;display:inline-flex;align-items:center;justify-content:center;
  gap:8px;border:none;transition:all var(--transition);backdrop-filter:blur(10px);
  position:relative;overflow:hidden;letter-spacing:0.3px;margin:6px
}
.btn::after{
  content:'';position:absolute;top:0;left:0;width:100%;height:100%;
  background:linear-gradient(45deg,transparent,rgba(255,255,255,0.2),transparent);
  transform:translateX(-100%);transition:transform 0.8s
}
.btn:hover::after{transform:translateX(100%)}
.btn-primary{
  background:linear-gradient(135deg,var(--primary),color-mix(in srgb,var(--primary) 80%,black));
  color:#000;box-shadow:0 6px 28px var(--primary-dim);border:1px solid transparent
}
.btn-primary:hover{filter:brightness(1.2);box-shadow:0 10px 40px var(--primary-dim);transform:translateY(-3px)}
.footer{
  height:var(--footer-h);display:flex;align-items:center;justify-content:center;font-size:0.85rem;
  color:var(--text3);border-top:1px solid var(--border);background:var(--surface);backdrop-filter:blur(10px);margin-top:auto
}
.footer-inner{display:flex;align-items:center;justify-content:center;gap:36px;flex-wrap:wrap}
.footer-inner a{color:var(--primary);text-decoration:none;font-weight:600;transition:all var(--transition)}
.footer-inner a:hover{text-shadow:0 0 18px var(--primary)}
@media(max-width:500px){
  .header{padding:10px 18px;min-height:auto}
  .logo{font-size:1.5rem}
  .card{padding:28px 16px}
  h1{font-size:1.6rem}
  .btn{padding:10px 18px}
}
</style>
</head>
<body>
<div class="header">
  <div class="header-inner">
    <span class="logo">SulgX</span>
    <div class="header-right">
      <div class="lang-switch">
        <button class="lang-btn lang-en active" onclick="setLang('en')">EN</button>
        <button class="lang-btn lang-fa" onclick="setLang('fa')">FA</button>
      </div>
      <button class="btn-icon" id="theme-toggle-btn" onclick="toggleTheme()" title="Toggle theme">🌙</button>
    </div>
  </div>
</div>
<div class="main">
  <div class="card">
    <h1>SulgX</h1>
    <div class="subtitle" data-en="Welcome to our platform – your reliable cloud partner." data-fa="به پلتفرم ما خوش آمدید – شریک ابری قابل اعتماد شما.">Welcome to our platform – your reliable cloud partner.</div>
    <div class="steps">
      <div class="step">
        <div class="step-num">1</div>
        <div class="step-text" data-en="Use Stealth Mode for enhanced security." data-fa="برای امنیت بیشتر از حالت استتار استفاده کنید.">Use Stealth Mode for enhanced security.</div>
      </div>
      <div class="step">
        <div class="step-num">2</div>
        <div class="step-text" data-en="Do not use the scanner on free services." data-fa="در سرویس‌های رایگان از اسکنر استفاده نکنید.">Do not use the scanner on free services.</div>
      </div>
      <div class="step">
        <div class="step-num">3</div>
        <div class="step-text" data-en="Always configure a Landing Page and Redirect URL." data-fa="حتماً از صفحه فرود و تغییر مسیر استفاده کنید.">Always configure a Landing Page and Redirect URL.</div>
      </div>
    </div>
    <div style="margin-top:16px;">
      <button class="btn btn-primary" id="login-btn" onclick="window.location.href='/login'"><span data-en="Login" data-fa="ورود">Login</span></button>
    </div>
  </div>
</div>
<div class="footer">
  <div class="footer-inner">
    <a href="https://t.me/SulgX" target="_blank">Telegram</a>
    <a href="https://github.com/SulgX" target="_blank">GitHub</a>
  </div>
</div>
<script>
let lang = localStorage.getItem('ll') || 'en';
let theme = localStorage.getItem('theme') || 'dark';
function setLang(l){
  lang = l;
  document.querySelectorAll('.lang-btn').forEach(b=>b.classList.remove('active'));
  document.querySelectorAll(`.lang-${l}`).forEach(b=>b.classList.add('active'));
  document.body.dir = l==='fa' ? 'rtl' : 'ltr';
  document.querySelectorAll('[data-en]').forEach(el=>{ const v = el.getAttribute('data-'+l); if(v) el.innerHTML = v; });
  localStorage.setItem('ll', l);
}
function setTheme(t){
  theme = t;
  document.body.classList.toggle('light-mode', t==='light');
  document.body.classList.toggle('blue-mode', t==='blue-dark');
  localStorage.setItem('theme', t);
  const themeBtn = document.getElementById('theme-toggle-btn');
  if (themeBtn) themeBtn.textContent = t==='light'?'☀️':(t==='blue-dark'?'🌌':'🌙');
}
function toggleTheme(){
  const themes = ['dark','light','blue-dark'];
  const idx = themes.indexOf(theme);
  setTheme(themes[(idx+1)%themes.length]);
}
setTheme(theme);
setLang(lang);
</script>
</body>
</html>"""

@app.api_route("/", methods=["GET", "HEAD"])
async def root(request: Request):
    if CAMOUFLAGE_URL:
        try:
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
                headers = {
                    "User-Agent": request.headers.get("user-agent", "Mozilla/5.0"),
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.5",
                }
                resp = await client.get(CAMOUFLAGE_URL, headers=headers)
                return Response(content=resp.text, media_type=resp.headers.get("content-type", "text/html"))
        except Exception:
            pass
    if LANDING_REDIRECT:
        return RedirectResponse(LANDING_REDIRECT, status_code=302)
    return HTMLResponse(content=LANDING_HTML)

@app.get("/health")
async def health():
    async with connections_lock:
        cnt = len(connections)
    return {"status": "ok", "connections": cnt, "uptime": uptime()}

@app.get("/favicon.ico")
async def favicon():
    return Response(content=b"", media_type="image/x-icon", status_code=204)

@app.get("/api/public-settings")
async def public_settings():
    rows = await db_fetchall("SELECT key, value FROM settings WHERE key IN ('footer_text')",
                             "SELECT key, value FROM settings WHERE key IN ('footer_text')")
    result = {}
    for r in rows:
        result[r["key"]] = r["value"]
    return result

@app.get("/api/domain")
async def get_panel_domain():
    return {"domain": get_domain()}
@app.get("/api/panel-info")
async def panel_info():
    return {
        "stealth": STEALTH_MODE,
        "prefix": PANEL_PREFIX,
        "domain": get_domain()
    }
@app.post("/api/login")
@limiter.limit("5/minute")
async def api_login(request: Request):
    body = await request.json()
    password = str(body.get("password") or "")
    ip = get_real_remote_address(request)
    user_agent = request.headers.get("user-agent", "")
    success = verify_password(password, ADMIN_PASSWORD_HASH)
    asyncio.create_task(log_login(ip, success, user_agent, "/api/login"))
    if not success:
        log_event("Auth", f"Failed login attempt from {ip}", ip, user_agent)
        raise HTTPException(status_code=401, detail="Invalid password")
    log_event("Auth", f"Successful panel login from {ip}", ip, user_agent)
    token = create_jwt_token({"sub": "admin"})
    resp = JSONResponse({"ok": True})
    forwarded_proto = request.headers.get("x-forwarded-proto", "")
    is_secure = forwarded_proto == "https" or request.url.scheme == "https"
    cookie_name = await get_session_cookie_name()
    resp.set_cookie(
        key=cookie_name,
        value=token,
        max_age=CONFIG["jwt_expire_minutes"] * 60,
        httponly=True,
        samesite="lax",
        secure=is_secure,
        path="/"
    )
    await asyncio.sleep(0)
    return resp
async def log_login(ip: str, success: bool, ua: str, path: str):
    log_row = await db_fetchone(
        "SELECT value FROM settings WHERE key='log_enabled'",
        "SELECT value FROM settings WHERE key='log_enabled'"
    )
    if log_row and log_row["value"] != "1":
        return
    try:
        browser, os_name = parse_user_agent(ua)
        await db_execute(
            "INSERT INTO login_logs (timestamp, ip, success, user_agent, path, browser, os) VALUES (?,?,?,?,?,?,?)",
            "INSERT INTO login_logs (timestamp, ip, success, user_agent, path, browser, os) VALUES ($1,$2,$3,$4,$5,$6,$7)",
            (datetime.now(timezone.utc).isoformat(), ip, 1 if success else 0, ua, path, browser, os_name)
        )
        asyncio.create_task(update_login_location(ip))
        if success:
            asyncio.create_task(notify_telegram_login(ip, ua))
    except Exception as e:
        logger.error(f"log_login error: {e}")

async def log_logout(ip: str, ua: str, path: str):
    log_row = await db_fetchone(
        "SELECT value FROM settings WHERE key='log_enabled'",
        "SELECT value FROM settings WHERE key='log_enabled'"
    )
    if log_row and log_row["value"] != "1":
        return
    try:
        browser, os_name = parse_user_agent(ua)
        loc = await get_ip_location(ip)
        await db_execute(
            "INSERT INTO login_logs (timestamp, ip, success, user_agent, path, browser, os, country, city, isp, org) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            "INSERT INTO login_logs (timestamp, ip, success, user_agent, path, browser, os, country, city, isp, org) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
            (datetime.now(timezone.utc).isoformat(), ip, 1, ua, path, browser, os_name, loc.get('country',''), loc.get('city',''), loc.get('isp',''), loc.get('org',''))
        )
    except Exception as e:
        logger.error(f"log_logout error: {e}")

async def update_login_location(ip: str):
    loc = await get_ip_location(ip)
    if any(loc.values()):
        await db_execute(
            "UPDATE login_logs SET country = ?, city = ?, isp = ?, org = ? WHERE ip = ? ORDER BY id DESC LIMIT 1",
            "UPDATE login_logs SET country = $1, city = $2, isp = $3, org = $4 WHERE ip = $5 AND id = (SELECT MAX(id) FROM login_logs WHERE ip = $5)",
            (loc["country"], loc["city"], loc["isp"], loc["org"], ip)
        )

async def notify_telegram_login(ip: str, ua: str):
    notif_row = await db_fetchone(
        "SELECT value FROM settings WHERE key='telegram_notify_enabled'",
        "SELECT value FROM settings WHERE key='telegram_notify_enabled'"
    )
    if notif_row and notif_row["value"] != "1":
        return

    events_row = await db_fetchone(
        "SELECT value FROM settings WHERE key='telegram_events'",
        "SELECT value FROM settings WHERE key='telegram_events'"
    )
    if events_row and "login" not in (events_row["value"] or "").split(","):
        return

    token_row = await db_fetchone(
        "SELECT value FROM settings WHERE key = 'tg_bot_token'",
        "SELECT value FROM settings WHERE key = 'tg_bot_token'"
    )
    chat_row = await db_fetchone(
        "SELECT value FROM settings WHERE key = 'tg_chat_id'",
        "SELECT value FROM settings WHERE key = 'tg_chat_id'"
    )
    if not token_row or not chat_row or not token_row["value"] or not chat_row["value"]:
        return

    lang = 'en'
    lang_row = await db_fetchone(
        "SELECT value FROM settings WHERE key='telegram_lang'",
        "SELECT value FROM settings WHERE key='telegram_lang'"
    )
    if lang_row and lang_row["value"] == 'fa':
        lang = 'fa'

    templates_key = f'telegram_templates_{lang}'
    tmpl_row = await db_fetchone(
        f"SELECT value FROM settings WHERE key='{templates_key}'",
        f"SELECT value FROM settings WHERE key='{templates_key}'"
    )
    templates = {}
    if tmpl_row and tmpl_row["value"]:
        try:
            templates = json.loads(tmpl_row["value"])
        except:
            pass

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")

    loc = await get_ip_location(ip)
    location_str = f"{loc['city']}, {loc['country']}" if loc.get('city') else loc.get('country', 'Unknown')
    isp_str = loc.get('isp', 'N/A')
    org_str = loc.get('org', 'N/A')
    browser, os_name = parse_user_agent(ua)

    if lang == 'fa':
        default_login = (
            f"🔐 ورود به پنل\n"
            f"🌐 IP: {ip}\n"
            f"📍 موقعیت: {location_str}\n"
            f"🏢 ISP: {isp_str}\n"
            f"🏛️ سازمان: {org_str}\n"
            f"🖥️ مرورگر: {browser}\n"
            f"💻 سیستم‌عامل: {os_name}\n"
            f"🤖 UA: {ua}\n"
            f"📅 {now_str}"
        )
    else:
        default_login = (
            f"🔐 Panel login\n"
            f"🌐 IP: {ip}\n"
            f"📍 Location: {location_str}\n"
            f"🏢 ISP: {isp_str}\n"
            f"🏛️ Org: {org_str}\n"
            f"🖥️ Browser: {browser}\n"
            f"💻 OS: {os_name}\n"
            f"🤖 UA: {ua}\n"
            f"📅 {now_str}"
        )

    msg = templates.get('login', default_login)
    msg = msg.replace("{ip}", ip).replace("{ua}", ua).replace("{time}", now_str)
    msg = msg.replace("{location}", location_str).replace("{isp}", isp_str).replace("{org}", org_str)
    msg = msg.replace("{browser}", browser).replace("{os}", os_name)

    prefix_row = await db_fetchone(
        "SELECT value FROM settings WHERE key='panel_prefix'",
        "SELECT value FROM settings WHERE key='panel_prefix'"
    )
    prefix_val = prefix_row["value"].strip() if prefix_row and prefix_row["value"].strip() else ""
    prefix = f"/{prefix_val}" if prefix_val else ""
    panel_url = f"https://{get_domain()}{prefix}/panel"
    msg += f'\n\n<a href="{panel_url}">Open SulgX Panel</a>'

    url = f"https://api.telegram.org/bot{token_row['value']}/sendMessage"
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            await client.post(url, json={
                "chat_id": chat_row["value"],
                "text": msg,
                "parse_mode": "HTML"
            })
    except Exception:
        pass

@app.post("/api/logout")
async def api_logout(request: Request):
    ip = get_real_remote_address(request)
    ua = request.headers.get("user-agent", "")
    await log_logout(ip, ua, "/api/logout")

    cookie_name = await get_session_cookie_name()

    resp = JSONResponse({"ok": True})
    is_secure = request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https"

    resp.delete_cookie(
        key=cookie_name,
        path="/",
        secure=is_secure,
        samesite="lax",
        httponly=True
    )
    resp.set_cookie(
        key=cookie_name,
        value="",
        max_age=0,
        expires=0,
        path="/",
        secure=is_secure,
        samesite="lax",
        httponly=True
    )

    return resp

@app.get("/api/me")
async def api_me(_: str = Depends(require_auth)):
    return {"authenticated": True}

@app.post("/api/change-password")
@limiter.limit("3/minute")
async def api_change_password(request: Request, _=Depends(require_auth)):
    global ADMIN_PASSWORD_HASH
    body = await request.json()
    current = str(body.get("current_password") or "")
    new = str(body.get("new_password") or "")
    if not verify_password(current, ADMIN_PASSWORD_HASH):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    if len(new) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    if not re.search(r'[A-Z]', new) or not re.search(r'[a-z]', new) or not re.search(r'[0-9]', new):
        raise HTTPException(status_code=400, detail="Password must contain uppercase, lowercase, and digit")
    new_hash = bcrypt.hashpw(new.encode(), bcrypt.gensalt()).decode()
    ADMIN_PASSWORD_HASH = new_hash
    await db_execute(
        "INSERT OR REPLACE INTO settings (key, value) VALUES ('admin_password_hash', ?)",
        "INSERT INTO settings (key, value) VALUES ('admin_password_hash', $1) ON CONFLICT (key) DO UPDATE SET value = $1",
        (new_hash,),
    )
    log_event("Security", "Admin password changed")
    return {"ok": True}

@app.get("/api/settings")
async def get_settings(_=Depends(require_auth)):
    keys = ['tg_bot_token', 'max_scan_ips', 'tg_chat_id', 'footer_text', 'default_path', 'log_enabled', 'timezone_offset',
            'default_limit_bytes', 'default_expiry_days', 'default_max_connections',
            'telegram_events', 'telegram_interval', 'keep_alive_interval', 'keep_alive_enabled', 'keep_alive_mode',
            'log_max_entries', 'scanner_timeout', 'theme_color',
            'telegram_templates_en', 'telegram_templates_fa', 'telegram_lang', 'default_lang',
            'auto_disable_enabled', 'telegram_report_enabled', 'telegram_notify_enabled',
            'monthly_limit_gb', 'naming_mode', 'default_ip_profile_id', 'doh_enabled',
            'stealth_mode', 'landing_redirect', 'camouflage_url', 'sub_filename', 'panel_prefix']
    result = {}
    for k in keys:
        row = await db_fetchone("SELECT value FROM settings WHERE key = ?", "SELECT value FROM settings WHERE key = $1", (k,))
        result[k] = row["value"] if row else ""
    return result

@app.post("/api/settings")
async def save_settings(request: Request, _=Depends(require_auth)):
    global ENABLE_LOGGING, TIMEZONE_OFFSET, KEEP_ALIVE_ENABLED, KEEP_ALIVE_INTERVAL, KEEP_ALIVE_MODE, DEFAULT_PATH, DOH_ENABLED
    global STEALTH_MODE, LANDING_REDIRECT, CAMOUFLAGE_URL, SUB_FILENAME
    body = await request.json()
    for k in ('tg_bot_token', 'tg_chat_id', 'max_scan_ips', 'footer_text', 'default_path', 'log_enabled', 'timezone_offset',
              'default_limit_bytes', 'default_expiry_days', 'default_max_connections',
              'telegram_events', 'telegram_interval', 'keep_alive_interval', 'keep_alive_enabled', 'keep_alive_mode',
              'log_max_entries', 'scanner_timeout', 'theme_color',
              'telegram_templates_en', 'telegram_templates_fa', 'telegram_lang', 'default_lang',
              'auto_disable_enabled', 'telegram_report_enabled', 'telegram_notify_enabled',
              'monthly_limit_gb', 'naming_mode', 'default_ip_profile_id', 'doh_enabled',
              'stealth_mode', 'landing_redirect', 'camouflage_url', 'sub_filename', 'panel_prefix'):
        if k in body:
            val = str(body[k]).strip()
            await db_execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                "INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2",
                (k, val),
            )
    if 'log_enabled' in body:
        ENABLE_LOGGING = body['log_enabled'] == '1'
    if 'keep_alive_enabled' in body:
        KEEP_ALIVE_ENABLED = body['keep_alive_enabled'] == '1'
    if 'keep_alive_mode' in body:
        KEEP_ALIVE_MODE = body['keep_alive_mode']
    if 'keep_alive_interval' in body:
        try:
            KEEP_ALIVE_INTERVAL = max(60, int(body['keep_alive_interval']))
        except:
            pass
    if 'timezone_offset' in body:
        try:
            TIMEZONE_OFFSET = float(body['timezone_offset'])
        except:
            TIMEZONE_OFFSET = 0.0
    if 'default_path' in body:
        new_path = str(body['default_path']).strip()
        if not new_path:
            new_path = "/ws/{uid}"
        DEFAULT_PATH = new_path
        await db_execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES ('default_path', ?)",
            "INSERT INTO settings (key, value) VALUES ('default_path', $1) ON CONFLICT (key) DO UPDATE SET value = $1",
            (new_path,)
        )
    if 'default_xhttp_path' in body:
        new_xpath = str(body['default_xhttp_path']).strip()
        if not new_xpath:
            new_xpath = "/xhttp"
        DEFAULT_XHTTP_PATH = new_xpath
        await db_execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES ('default_xhttp_path', ?)",
            "INSERT INTO settings (key, value) VALUES ('default_xhttp_path', $1) ON CONFLICT (key) DO UPDATE SET value = $1",
            (new_xpath,)
        )
    if 'doh_enabled' in body:
        DOH_ENABLED = body['doh_enabled'] == '1'
    if 'stealth_mode' in body:
        STEALTH_MODE = body['stealth_mode'] == '1'
    if 'landing_redirect' in body:
        LANDING_REDIRECT = body['landing_redirect']
    if 'camouflage_url' in body:
        CAMOUFLAGE_URL = body['camouflage_url']
    if 'sub_filename' in body:
        SUB_FILENAME = body['sub_filename']
    if 'panel_prefix' in body:
        new_prefix = str(body['panel_prefix']).strip()
        PANEL_PREFIX = new_prefix
        await db_execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES ('panel_prefix', ?)",
            "INSERT INTO settings (key, value) VALUES ('panel_prefix', $1) ON CONFLICT (key) DO UPDATE SET value = $1",
            (new_prefix,)
        )
    asyncio.create_task(set_telegram_webhook())
    return {"ok": True}

@app.post("/api/settings/reset")
@limiter.limit("3/minute")
async def reset_settings(request: Request, _=Depends(require_auth)):
    PROTECTED_KEYS = {'jwt_secret_key', 'admin_password_hash'}
    all_keys = await db_fetchall("SELECT key FROM settings", "SELECT key FROM settings")
    for row in all_keys:
        k = row["key"]
        if k not in PROTECTED_KEYS:
            await db_execute("DELETE FROM settings WHERE key = ?", "DELETE FROM settings WHERE key = $1", (k,))
    global ENABLE_LOGGING, KEEP_ALIVE_INTERVAL, TIMEZONE_OFFSET, KEEP_ALIVE_ENABLED, KEEP_ALIVE_MODE, DEFAULT_PATH, DOH_ENABLED
    global STEALTH_MODE, LANDING_REDIRECT, CAMOUFLAGE_URL, SUB_FILENAME
    ENABLE_LOGGING = True
    KEEP_ALIVE_INTERVAL = 300
    TIMEZONE_OFFSET = 0.0
    KEEP_ALIVE_ENABLED = True
    KEEP_ALIVE_MODE = "simple"
    DEFAULT_PATH = "/ws/{uid}"
    DOH_ENABLED = True
    STEALTH_MODE = False
    LANDING_REDIRECT = ""
    CAMOUFLAGE_URL = ""
    SUB_FILENAME = ""
    PANEL_PREFIX = ""
    log_event("Settings", "All settings reset to defaults")
    return {"ok": True}

@app.get("/api/sse/stats-live")
async def sse_stats_live(token: str = ""):
    if not token or not decode_jwt_token(token):
        raise HTTPException(status_code=401)
    async def event_stream():
        while True:
            async with connections_lock: conn_count = len(connections)
            data = {
                "active_connections": conn_count,
                "total_traffic_mb": round(stats["total_bytes"]/(1024*1024),2),
                "total_requests": stats["total_requests"],
                "total_errors": stats["total_errors"],
                "uptime": uptime(),
            }
            yield f"data: {json.dumps(data)}\n\n"
            await asyncio.sleep(3)
    return StreamingResponse(event_stream(), media_type="text/event-stream")

@app.get("/stats")
async def get_stats(_=Depends(require_auth)):
    global TIMEZONE_OFFSET
    async with connections_lock:
        conn_count = len(connections)
    cpu = 0.0
    try:
        cpu = await asyncio.to_thread(psutil.cpu_percent, 0.1)
        if cpu == 0.0:
            try:
                with open('/proc/loadavg', 'r') as f:
                    cpu = float(f.readline().split()[0]) * 10
            except:
                cpu = None
    except:
        try:
            with open('/proc/loadavg', 'r') as f:
                cpu = float(f.readline().split()[0]) * 10
        except:
            cpu = None
    mem_percent = 0
    try:
        mem_percent = psutil.virtual_memory().percent
    except:
        pass
    disk_percent = 0
    disk_free = 0.0
    try:
        disk = psutil.disk_usage("/")
        disk_percent = disk.percent
        disk_free = round(disk.free / (1024**3), 1)
    except:
        pass
    now = datetime.now(timezone.utc) + timedelta(hours=TIMEZONE_OFFSET)
    today_str = now.strftime("%Y-%m-%d")
    rows = await db_fetchall(
        "SELECT hour, bytes FROM hourly_traffic WHERE hour LIKE ? ORDER BY hour ASC",
        "SELECT hour, bytes FROM hourly_traffic WHERE hour LIKE $1 ORDER BY hour ASC",
        (today_str + '%',)
    )
    hourly_dict = {f"{h:02d}:00": 0 for h in range(24)}
    for r in rows:
        hour_part = r["hour"][-5:] if len(r["hour"]) >= 5 else r["hour"]
        if hour_part in hourly_dict:
            hourly_dict[hour_part] = r["bytes"]
    async with traffic_buffer_lock:
        for h_key, b_val in traffic_buffer["hourly"].items():
            hour_part = h_key[-5:] if len(h_key) >= 5 else h_key
            if hour_part in hourly_dict:
                hourly_dict[hour_part] += b_val
    sorted_hours = [f"{h:02d}:00" for h in range(24)]
    hourly_data = {h: hourly_dict[h] for h in sorted_hours}
    month_start = now.strftime("%Y-%m") + "-01"
    monthly_bytes = 0
    month_rows = await db_fetchall(
        "SELECT SUM(bytes) as total FROM daily_traffic WHERE day >= ?",
        "SELECT SUM(bytes) as total FROM daily_traffic WHERE day >= $1",
        (month_start,)
    )
    if month_rows and month_rows[0]["total"]:
        monthly_bytes = month_rows[0]["total"]
    monthly_limit = 0
    limit_row = await db_fetchone("SELECT value FROM settings WHERE key='monthly_limit_gb'", "SELECT value FROM settings WHERE key='monthly_limit_gb'")
    if limit_row and limit_row["value"]:
        try:
            monthly_limit = float(limit_row["value"]) * 1024**3
        except:
            pass
    return {
        "active_connections": conn_count,
        "total_traffic_mb": round(stats["total_bytes"]/(1024*1024), 2),
        "total_requests": stats["total_requests"],
        "total_errors": stats["total_errors"],
        "uptime": uptime(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "recent_errors": list(error_logs)[-20:],
        "links_count": len(LINKS),
        "domain": get_domain(),
        "cpu_percent": cpu,
        "memory_percent": mem_percent,
        "disk_percent": disk_percent,
        "disk_free_gb": disk_free,
        "hourly_traffic": hourly_data,
        "hourly_labels": sorted_hours,
        "upload_bytes": stats["upload_bytes"],
        "download_bytes": stats["download_bytes"],
        "monthly_usage_bytes": monthly_bytes,
        "monthly_limit_bytes": int(monthly_limit),
    }

@app.get("/stats/detailed")
async def get_detailed_stats(_=Depends(require_auth)):
    async with LINKS_LOCK:
        links = list(LINKS.values())
    active = sum(1 for l in links if l["active"])
    inactive = sum(1 for l in links if not l["active"])
    expired = 0
    now = datetime.now(timezone.utc)
    for l in links:
        if l.get("expires_at"):
            exp = parse_expires_at(l["expires_at"])
            if exp and exp < now:
                expired += 1
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    today_row = await db_fetchone("SELECT bytes FROM daily_traffic WHERE day = ?", "SELECT bytes FROM daily_traffic WHERE day = $1", (today,))
    today_bytes = today_row["bytes"] if today_row else 0
    daily_rows = await db_fetchall("SELECT day, bytes FROM daily_traffic ORDER BY day DESC LIMIT 7",
                                   "SELECT day, bytes FROM daily_traffic ORDER BY day DESC LIMIT 7")
    daily_traffic = {row["day"]: row["bytes"] for row in daily_rows}
    return {
        "total_links": len(links),
        "active_links": active,
        "inactive_links": inactive,
        "expired_links": expired,
        "today_traffic_bytes": today_bytes,
        "daily_traffic": daily_traffic,
    }

@app.get("/api/login-logs")
async def get_login_logs(_=Depends(require_auth)):
    rows = await db_fetchall(
        "SELECT timestamp, ip, success, user_agent, path, browser, os, country, city, isp, org FROM login_logs ORDER BY timestamp DESC LIMIT 20",
        "SELECT timestamp, ip, success, user_agent, path, browser, os, country, city, isp, org FROM login_logs ORDER BY timestamp DESC LIMIT 20"
    )
    return {"logs": [dict(r) for r in rows]}

@app.get("/api/logs")
async def get_logs(_=Depends(require_auth)):
    return {"logs": list(error_logs)}

@app.delete("/api/logs/clear")
async def clear_logs(request: Request, _=Depends(require_auth)):
    ip = request.client.host
    error_logs.clear()
    await db_execute("DELETE FROM login_logs", "DELETE FROM login_logs")
    log_event("Admin", "All logs cleared", ip=ip)
    return {"ok": True}

@app.get("/api/logs/size")
async def logs_size(_=Depends(require_auth)):
    total_chars = sum(len(json.dumps(log)) for log in error_logs)
    return {"count": len(error_logs), "size_kb": round(total_chars / 1024, 2)}

@app.get("/api/backup/full")
async def full_backup(_=Depends(require_auth)):
    async with LINKS_LOCK:
        links = list(LINKS.values())
    async with CUSTOM_ADDRESSES_LOCK:
        addrs = list(CUSTOM_ADDRESSES)
    rows = await db_fetchall("SELECT key, value FROM settings", "SELECT key, value FROM settings")
    settings = {r["key"]: r["value"] for r in rows}
    backup = {"links": links, "addresses": addrs, "settings": settings}
    return backup

MAX_RESTORE_SIZE = 5 * 1024 * 1024

@app.post("/api/restore")
@limiter.limit("3/minute")
async def restore_backup(request: Request, _=Depends(require_auth)):
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > MAX_RESTORE_SIZE:
        raise HTTPException(status_code=413, detail="Backup file too large")
    body = await request.json()
    if "settings" in body:
        for k, v in body["settings"].items():
            await db_execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                "INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2",
                (k, str(v))
            )
    if "addresses" in body:
        await db_execute("DELETE FROM custom_addresses", "DELETE FROM custom_addresses")
        async with CUSTOM_ADDRESSES_LOCK:
            CUSTOM_ADDRESSES[:] = []
            for a in body["addresses"]:
                addr = str(a).strip()
                if addr and validate_address(addr):
                    CUSTOM_ADDRESSES.append(addr)
                    flag = await fetch_ip_flag(addr)
                    try:
                        await db_execute(
                            "INSERT INTO custom_addresses (address, flag) VALUES (?, ?)",
                            "INSERT INTO custom_addresses (address, flag) VALUES ($1, $2)",
                            (addr, flag)
                        )
                    except ADDRESS_INTEGRITY_ERRORS:
                        pass
    if "links" in body:
        await db_execute("DELETE FROM links", "DELETE FROM links")
        async with LINKS_LOCK:
            LINKS.clear()
        for link in body["links"]:
            uid = link.get("uid") or str(uuid_lib.uuid4())
            label = link.get("label", "Restored")
            limit_bytes = int(link.get("limit_bytes", 0))
            used_bytes = int(link.get("used_bytes", 0))
            max_conn = int(link.get("max_connections", 0))
            created_at = link.get("created_at") or datetime.now(timezone.utc).isoformat()
            active = 1 if link.get("active", True) else 0
            expires_at = link.get("expires_at")
            custom_path = link.get("custom_path", "")
            custom_sni = link.get("custom_sni", "")
            custom_host = link.get("custom_host", "")
            custom_fp = link.get("custom_fp", "chrome")
            color = link.get("color", "#39ff14")
            flag = link.get("flag", "")
            fragment = link.get("fragment", "")
            ip_profile_id = link.get("ip_profile_id", "")
            naming_mode = link.get("naming_mode", "default")
            tfo = 1 if link.get("tfo") else 0
            ech_enabled = 1 if link.get("ech_enabled") else 0
            ech_sni = link.get("ech_sni", "")
            ech_doh = link.get("ech_doh", "")
            fragment_mode = link.get("fragment_mode", "off")
            fragment_length = link.get("fragment_length", "100-200")
            fragment_interval = link.get("fragment_interval", "10-20")
            allow_insecure = 1 if link.get("allow_insecure") else 0
            random_path = 1 if link.get("random_path") else 0
            enable_ipv6 = 1 if link.get("enable_ipv6", True) else 0
            smux_enabled = 1 if link.get("smux_enabled") else 0
            ip_limit = int(link.get("ip_limit") or 0)
            protocol = link.get("protocol", "vless-ws")
            fingerprint = link.get("fingerprint", "chrome")
            alpn = link.get("alpn", "")
            port = int(link.get("port") or 443)
            await db_execute(
    "INSERT INTO links (uid, label, limit_bytes, used_bytes, max_connections, created_at, active, expires_at, custom_path, custom_sni, custom_host, custom_fp, color, flag, fragment, ip_profile_id, naming_mode, tfo, ech_enabled, ech_sni, ech_doh, fragment_mode, fragment_length, fragment_interval, allow_insecure, random_path, enable_ipv6, smux_enabled, ip_limit, protocol, fingerprint, alpn, port) VALUES (?,?,?,?,?,?,1,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
    "INSERT INTO links (uid, label, limit_bytes, used_bytes, max_connections, created_at, active, expires_at, custom_path, custom_sni, custom_host, custom_fp, color, flag, fragment, ip_profile_id, naming_mode, tfo, ech_enabled, ech_sni, ech_doh, fragment_mode, fragment_length, fragment_interval, allow_insecure, random_path, enable_ipv6, smux_enabled, ip_limit, protocol, fingerprint, alpn, port) VALUES ($1,$2,$3,$4,$5,$6,TRUE,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32)",
    (uid, label, limit_bytes, 0, max_conn, now, expires_at, custom_path, custom_sni, custom_host, custom_fp, color, flag, fragment, ip_profile_id, naming_mode, tfo, ech_enabled, ech_sni, ech_doh, fragment_mode, fragment_length, fragment_interval, allow_insecure, random_path, enable_ipv6, smux_enabled, ip_limit, protocol, fingerprint, alpn, port),
)
            async with LINKS_LOCK:
                LINKS[uid] = {
                    "uid": uid, "label": label, "limit_bytes": limit_bytes, "used_bytes": used_bytes,
                    "max_connections": max_conn, "created_at": created_at, "active": active,
                    "expires_at": expires_at, "custom_path": custom_path, "custom_sni": custom_sni,
                    "custom_host": custom_host, "custom_fp": custom_fp, "color": color, "flag": flag, "fragment": fragment,
                    "ip_profile_id": ip_profile_id, "naming_mode": naming_mode,
                    "tfo": tfo, "ech_enabled": ech_enabled, "ech_sni": ech_sni, "ech_doh": ech_doh,
                    "fragment_mode": fragment_mode, "fragment_length": fragment_length, "fragment_interval": fragment_interval,
                    "allow_insecure": allow_insecure, "random_path": random_path, "enable_ipv6": enable_ipv6,
                    "smux_enabled": smux_enabled, "ip_limit": ip_limit,
                    "protocol": protocol, "fingerprint": fingerprint, "alpn": alpn, "port": port,
                }
    return {"ok": True}
@app.post("/api/links")
@limiter.limit("10/minute")
async def create_link(request: Request, _=Depends(require_auth)):
    body = await request.json()
    label = (body.get("label") or "").strip()[:60]
    if not label:
        label = "User-" + secrets.token_hex(4)
    uuid_input = (body.get("uuid") or "").strip()
    if not re.match(r'^[a-zA-Z0-9\-_. ]+$', label):
        raise HTTPException(status_code=400, detail="Remark must contain only English letters, numbers, and characters: - _ . space")
    if uuid_input:
        try:
            uuid_lib.UUID(uuid_input)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid UUID format")
        uid = uuid_input
    else:
        uid = str(uuid_lib.uuid4())
    async with LINKS_LOCK:
        if uid in LINKS:
            raise HTTPException(status_code=400, detail="An inbound with this UUID already exists")
    default_limit = 0
    def_limit_row = await db_fetchone("SELECT value FROM settings WHERE key='default_limit_bytes'", "SELECT value FROM settings WHERE key='default_limit_bytes'")
    if def_limit_row and def_limit_row["value"]:
        default_limit = int(def_limit_row["value"])
    default_expiry_days = 0
    def_exp_row = await db_fetchone("SELECT value FROM settings WHERE key='default_expiry_days'", "SELECT value FROM settings WHERE key='default_expiry_days'")
    if def_exp_row and def_exp_row["value"]:
        default_expiry_days = int(def_exp_row["value"])
    default_max_conn = 0
    def_conn_row = await db_fetchone("SELECT value FROM settings WHERE key='default_max_connections'", "SELECT value FROM settings WHERE key='default_max_connections'")
    if def_conn_row and def_conn_row["value"]:
        default_max_conn = int(def_conn_row["value"])

    limit_val = float(body.get("limit_value") or default_limit)
    limit_unit = body.get("limit_unit") or "GB"
    limit_bytes = 0 if limit_val <= 0 else parse_size_to_bytes(limit_val, limit_unit)
    max_conn = int(body.get("max_connections") or default_max_conn)
    if max_conn < 0:
        max_conn = 0
    days_valid = body.get("days_valid") if body.get("days_valid") is not None else default_expiry_days
    expires_at = None
    try:
        days_valid = int(days_valid)
        if days_valid > 0:
            expires_at = (datetime.now(timezone.utc) + timedelta(days=days_valid)).isoformat()
    except (ValueError, TypeError):
        pass
    now = datetime.now(timezone.utc).isoformat()
    custom_path = body.get("custom_path", "")
    custom_sni = body.get("custom_sni", "")
    custom_host = body.get("custom_host", "")
    custom_fp = body.get("custom_fp", "chrome")
    color = body.get("color", "#39ff14")
    flag = body.get("flag", "")
    fragment = body.get("fragment", "")
    ip_profile_id = body.get("ip_profile_id", "")
    naming_mode = body.get("naming_mode", "default")
    tfo = 1 if body.get("tfo") else 0
    ech_enabled = 1 if body.get("ech_enabled") else 0
    ech_sni = body.get("ech_sni", "")
    ech_doh = body.get("ech_doh", "")
    fragment_mode = body.get("fragment_mode", "off")
    fragment_length = body.get("fragment_length", "100-200")
    fragment_interval = body.get("fragment_interval", "10-20")
    allow_insecure = 1 if body.get("allow_insecure") else 0
    random_path = 1 if body.get("random_path") else 0
    enable_ipv6 = 1 if body.get("enable_ipv6", True) else 0
    smux_enabled = 1 if body.get("smux_enabled") else 0
    ip_limit = int(body.get("ip_limit") or 0)
    if ip_limit < 0: ip_limit = 0
    protocol = body.get("protocol", "vless-ws")
    fingerprint = body.get("fingerprint", "chrome")
    alpn = body.get("alpn", "")
    port = int(body.get("port") or 443)

    if flag:
        flag = flag.strip()[:2]
        if not re.match(r'^[a-zA-Z]{2}$', flag):
            flag = ""
        else:
            flag = flag.upper()
    if fragment:
        fragment = fragment.strip()[:50]
        if fragment and not re.match(r'^(\d+\-\d+|tlshello)$', fragment):
            raise HTTPException(status_code=400, detail="Fragment must be a range like 1000-2000 or 'tlshello'")
    link_data = {
        "uid": uid, "label": label, "limit_bytes": limit_bytes, "used_bytes": 0,
        "max_connections": max_conn, "created_at": now, "active": 1,
        "expires_at": expires_at,
        "custom_path": custom_path, "custom_sni": custom_sni,
        "custom_host": custom_host, "custom_fp": custom_fp, "color": color,
        "flag": flag, "fragment": fragment, "ip_profile_id": ip_profile_id, "naming_mode": naming_mode,
        "tfo": tfo, "ech_enabled": ech_enabled, "ech_sni": ech_sni, "ech_doh": ech_doh,
        "fragment_mode": fragment_mode, "fragment_length": fragment_length, "fragment_interval": fragment_interval,
        "allow_insecure": allow_insecure, "random_path": random_path, "enable_ipv6": enable_ipv6,
        "smux_enabled": smux_enabled, "ip_limit": ip_limit,
        "protocol": protocol, "fingerprint": fingerprint, "alpn": alpn, "port": port,
    }
    async with LINKS_LOCK:
        LINKS[uid] = link_data
    await db_execute(
        "INSERT INTO links (uid, label, limit_bytes, used_bytes, max_connections, created_at, active, expires_at, custom_path, custom_sni, custom_host, custom_fp, color, flag, fragment, ip_profile_id, naming_mode, tfo, ech_enabled, ech_sni, ech_doh, fragment_mode, fragment_length, fragment_interval, allow_insecure, random_path, enable_ipv6, smux_enabled, ip_limit, protocol, fingerprint, alpn, port) VALUES (?,?,?,?,?,?,1,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        "INSERT INTO links (uid, label, limit_bytes, used_bytes, max_connections, created_at, active, expires_at, custom_path, custom_sni, custom_host, custom_fp, color, flag, fragment, ip_profile_id, naming_mode, tfo, ech_enabled, ech_sni, ech_doh, fragment_mode, fragment_length, fragment_interval, allow_insecure, random_path, enable_ipv6, smux_enabled, ip_limit, protocol, fingerprint, alpn, port) VALUES ($1,$2,$3,$4,$5,$6,TRUE,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33)",
        (uid, label, limit_bytes, 0, max_conn, now, expires_at, custom_path, custom_sni, custom_host, custom_fp, color, flag, fragment, ip_profile_id, naming_mode, tfo, ech_enabled, ech_sni, ech_doh, fragment_mode, fragment_length, fragment_interval, allow_insecure, random_path, enable_ipv6, smux_enabled, ip_limit, protocol, fingerprint, alpn, port),
    )
    extra = {"custom_path": custom_path, "custom_sni": custom_sni, "custom_host": custom_host, "custom_fp": custom_fp, "fragment": fragment,
             "tfo": tfo, "ech_enabled": ech_enabled, "ech_sni": ech_sni, "ech_doh": ech_doh,
             "fragment_mode": fragment_mode, "fragment_length": fragment_length, "fragment_interval": fragment_interval,
             "allow_insecure": allow_insecure, "random_path": random_path, "enable_ipv6": enable_ipv6,
             "smux_enabled": smux_enabled, "ip_limit": ip_limit,
             "protocol": protocol, "fingerprint": fingerprint, "alpn": alpn, "port": port}
    log_event("Inbound", f"Created inbound {label} ({uid})")
    domain = get_domain(request)
    return {
        "uuid": uid, "label": label, "limit_bytes": limit_bytes, "used_bytes": 0,
        "max_connections": max_conn, "active": True, "created_at": now,
        "expires_at": expires_at, "color": color, "flag": flag, "fragment": fragment,
        "ip_profile_id": ip_profile_id, "naming_mode": naming_mode,
        "tfo": bool(tfo), "ech_enabled": bool(ech_enabled), "ech_sni": ech_sni, "ech_doh": ech_doh,
        "fragment_mode": fragment_mode, "fragment_length": fragment_length, "fragment_interval": fragment_interval,
        "allow_insecure": bool(allow_insecure), "random_path": bool(random_path), "enable_ipv6": bool(enable_ipv6),
        "smux_enabled": bool(smux_enabled), "ip_limit": ip_limit,
        "protocol": protocol, "fingerprint": fingerprint, "alpn": alpn, "port": port,
        "vless_link": generate_vless_link(uid, remark=f"SulgX-{label}", extra=extra, server_domain=domain),
    }


@app.get("/api/links")
async def list_links(request: Request, _=Depends(require_auth)):
    async with LINKS_LOCK:
        items = list(LINKS.values())
    items.sort(key=lambda x: x["created_at"], reverse=True)
    domain = get_domain(request)
    result = []
    for row in items:
        uid = row["uid"]
        extra = {
            "custom_path": row.get("custom_path", ""),
            "custom_sni": row.get("custom_sni", ""),
            "custom_host": row.get("custom_host", ""),
            "custom_fp": row.get("custom_fp", "chrome"),
            "fragment": row.get("fragment", ""),
            "tfo": row.get("tfo", False),
            "ech_enabled": row.get("ech_enabled", False),
            "ech_sni": row.get("ech_sni", ""),
            "ech_doh": row.get("ech_doh", ""),
            "fragment_mode": row.get("fragment_mode", "off"),
            "fragment_length": row.get("fragment_length", "100-200"),
            "fragment_interval": row.get("fragment_interval", "10-20"),
            "allow_insecure": row.get("allow_insecure", False),
            "random_path": row.get("random_path", False),
            "enable_ipv6": row.get("enable_ipv6", True),
            "smux_enabled": row.get("smux_enabled", False),
            "ip_limit": row.get("ip_limit", 0),
            "protocol": row.get("protocol", "vless-ws"),
            "fingerprint": row.get("fingerprint", "chrome"),
            "alpn": row.get("alpn", ""),
            "port": row.get("port", 443),
        }
        result.append({
            "uuid": uid,
            "label": row["label"],
            "limit_bytes": row["limit_bytes"],
            "used_bytes": row["used_bytes"],
            "max_connections": row["max_connections"],
            "active": bool(row["active"]),
            "created_at": row["created_at"],
            "expires_at": row.get("expires_at"),
            "custom_path": extra["custom_path"],
            "custom_sni": extra["custom_sni"],
            "custom_host": extra["custom_host"],
            "custom_fp": extra["custom_fp"],
            "color": row.get("color", "#39ff14"),
            "flag": row.get("flag", ""),
            "fragment": extra["fragment"],
            "ip_profile_id": row.get("ip_profile_id", ""),
            "naming_mode": row.get("naming_mode", "default"),
            "current_connections": await count_connections_for_link(uid),
            "vless_link": generate_vless_link(uid, remark=f"SulgX-{row['label']}", extra=extra, server_domain=domain),
            "tfo": bool(extra["tfo"]),
            "ech_enabled": bool(extra["ech_enabled"]),
            "ech_sni": extra["ech_sni"],
            "ech_doh": extra["ech_doh"],
            "fragment_mode": extra["fragment_mode"],
            "fragment_length": extra["fragment_length"],
            "fragment_interval": extra["fragment_interval"],
            "allow_insecure": bool(extra["allow_insecure"]),
            "random_path": bool(extra["random_path"]),
            "enable_ipv6": bool(extra["enable_ipv6"]),
            "smux_enabled": bool(extra["smux_enabled"]),
            "ip_limit": extra["ip_limit"],
            "protocol": extra["protocol"],
            "fingerprint": extra["fingerprint"],
            "alpn": extra["alpn"],
            "port": extra["port"],
        })
    return {"links": result}

@app.get("/api/export-links")
async def export_links(_=Depends(require_auth)):
    async with LINKS_LOCK:
        links = list(LINKS.values())
    return JSONResponse(content=links)

@app.post("/api/import-links")
async def import_links(request: Request, _=Depends(require_auth)):
    body = await request.json()
    imported = 0
    if not isinstance(body, list):
        raise HTTPException(status_code=400, detail="Expected a list of links")
    for item in body:
        if not isinstance(item, dict):
            continue
        uid_input = item.get("uid") or str(uuid_lib.uuid4())
        try:
            uuid_lib.UUID(uid_input)
        except ValueError:
            continue
        label = item.get("label", "Imported")[:60]
        if not re.match(r'^[a-zA-Z0-9\-_. ]+$', label):
            continue
        limit_bytes = int(item.get("limit_bytes", 0))
        used_bytes = int(item.get("used_bytes", 0))
        max_conn = int(item.get("max_connections", 0))
        created_at = item.get("created_at") or datetime.now(timezone.utc).isoformat()
        active = 1 if item.get("active", True) else 0
        expires_at = item.get("expires_at")
        custom_path = item.get("custom_path", "")
        custom_sni = item.get("custom_sni", "")
        custom_host = item.get("custom_host", "")
        custom_fp = item.get("custom_fp", "chrome")
        color = item.get("color", "#39ff14")
        flag = item.get("flag", "")
        fragment = item.get("fragment", "")
        ip_profile_id = item.get("ip_profile_id", "")
        naming_mode = item.get("naming_mode", "default")
        tfo = 1 if item.get("tfo") else 0
        ech_enabled = 1 if item.get("ech_enabled") else 0
        ech_sni = item.get("ech_sni", "")
        ech_doh = item.get("ech_doh", "")
        fragment_mode = item.get("fragment_mode", "off")
        fragment_length = item.get("fragment_length", "100-200")
        fragment_interval = item.get("fragment_interval", "10-20")
        allow_insecure = 1 if item.get("allow_insecure") else 0
        random_path = 1 if item.get("random_path") else 0
        enable_ipv6 = 1 if item.get("enable_ipv6", True) else 0
        smux_enabled = 1 if item.get("smux_enabled") else 0
        ip_limit = int(item.get("ip_limit") or 0)
        if ip_limit < 0: ip_limit = 0
        protocol = item.get("protocol", "vless-ws")
        fingerprint = item.get("fingerprint", "chrome")
        alpn = item.get("alpn", "")
        port = int(item.get("port") or 443)

        if flag:
            flag = flag.strip()[:2]
            if not re.match(r'^[a-zA-Z]{2}$', flag):
                flag = ""
            else:
                flag = flag.upper()
        async with LINKS_LOCK:
            if uid_input in LINKS:
                continue
            LINKS[uid_input] = {
                "uid": uid_input, "label": label, "limit_bytes": limit_bytes, "used_bytes": used_bytes,
                "max_connections": max_conn, "created_at": created_at, "active": active,
                "expires_at": expires_at, "custom_path": custom_path, "custom_sni": custom_sni,
                "custom_host": custom_host, "custom_fp": custom_fp, "color": color, "flag": flag, "fragment": fragment,
                "ip_profile_id": ip_profile_id, "naming_mode": naming_mode,
                "tfo": tfo, "ech_enabled": ech_enabled, "ech_sni": ech_sni, "ech_doh": ech_doh,
                "fragment_mode": fragment_mode, "fragment_length": fragment_length, "fragment_interval": fragment_interval,
                "allow_insecure": allow_insecure, "random_path": random_path, "enable_ipv6": enable_ipv6,
                "smux_enabled": smux_enabled, "ip_limit": ip_limit,
                "protocol": protocol, "fingerprint": fingerprint, "alpn": alpn, "port": port,
            }
        await db_execute(
            "INSERT INTO links (uid, label, limit_bytes, used_bytes, max_connections, created_at, active, expires_at, custom_path, custom_sni, custom_host, custom_fp, color, flag, fragment, ip_profile_id, naming_mode, tfo, ech_enabled, ech_sni, ech_doh, fragment_mode, fragment_length, fragment_interval, allow_insecure, random_path, enable_ipv6, smux_enabled, ip_limit, protocol, fingerprint, alpn, port) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            "INSERT INTO links (uid, label, limit_bytes, used_bytes, max_connections, created_at, active, expires_at, custom_path, custom_sni, custom_host, custom_fp, color, flag, fragment, ip_profile_id, naming_mode, tfo, ech_enabled, ech_sni, ech_doh, fragment_mode, fragment_length, fragment_interval, allow_insecure, random_path, enable_ipv6, smux_enabled, ip_limit, protocol, fingerprint, alpn, port) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32)",
            (uid_input, label, limit_bytes, used_bytes, max_conn, created_at, active, expires_at, custom_path, custom_sni, custom_host, custom_fp, color, flag, fragment, ip_profile_id, naming_mode, tfo, ech_enabled, ech_sni, ech_doh, fragment_mode, fragment_length, fragment_interval, allow_insecure, random_path, enable_ipv6, smux_enabled, ip_limit, protocol, fingerprint, alpn, port),
        )
        imported += 1
    return {"ok": True, "imported": imported}

@app.patch("/api/links/batch")
async def batch_links(request: Request, _=Depends(require_auth)):
    body = await request.json()
    uids = body.get("uids", [])
    action = body.get("action", "")
    async with LINKS_LOCK:
        for uid in uids:
            link = LINKS.get(uid)
            if not link:
                continue
            if action == "activate":
                link["active"] = 1
                await db_execute("UPDATE links SET active=1 WHERE uid=?", "UPDATE links SET active=TRUE WHERE uid=$1", (uid,))
            elif action == "deactivate":
                link["active"] = 0
                await db_execute("UPDATE links SET active=0 WHERE uid=?", "UPDATE links SET active=FALSE WHERE uid=$1", (uid,))
                await close_connections_for_link(uid)
            elif action == "reset_usage":
                link["used_bytes"] = 0
                await db_execute("UPDATE links SET used_bytes=0 WHERE uid=?", "UPDATE links SET used_bytes=0 WHERE uid=$1", (uid,))
            elif action == "delete":
                if link.get("label") == "This Server is Free":
                    continue
                await db_execute("DELETE FROM links WHERE uid=?", "DELETE FROM links WHERE uid=$1", (uid,))
                LINKS.pop(uid, None)
                await close_connections_for_link(uid)
    return {"ok": True}

@app.post("/api/links/{uid}/new-uuid")
async def regenerate_uuid(uid: str, _=Depends(require_auth)):
    async with LINKS_LOCK:
        if uid not in LINKS:
            raise HTTPException(status_code=404, detail="link not found")
        if LINKS[uid].get("label") == "This Server is Free":
            raise HTTPException(status_code=400, detail="Cannot regenerate UUID for the default inbound.")
        new_uid = str(uuid_lib.uuid4())
        while new_uid in LINKS:
            new_uid = str(uuid_lib.uuid4())
        link = LINKS.pop(uid)
        link["uid"] = new_uid
        LINKS[new_uid] = link
        await db_execute("UPDATE links SET uid=? WHERE uid=?", "UPDATE links SET uid=$1 WHERE uid=$2", (new_uid, uid))
        async with connections_lock:
            to_update = [(cid, info) for cid, info in connections.items() if info.get("uuid") == uid]
            for cid, info in to_update:
                info["uuid"] = new_uid
            if uid in link_ip_map:
                link_ip_map[new_uid] = link_ip_map.pop(uid)
        log_event("Inbound", f"UUID regenerated for {link['label']}: {uid} -> {new_uid}")
        return {"new_uuid": new_uid}

@app.post("/api/links/{uid}/disconnect")
async def disconnect_link(uid: str, _=Depends(require_auth)):
    await close_connections_for_link(uid)
    log_event("Inbound", f"Disconnected all connections for {uid}")
    return {"ok": True}

@app.patch("/api/links/{uid}")
async def toggle_link(uid: str, request: Request, _=Depends(require_auth)):
    body = await request.json()
    logger.info(f"PATCH /api/links/{uid} body={json.dumps(body)}")

    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if not link:
            raise HTTPException(status_code=404, detail="link not found")
        if link.get("label") == "This Server is Free":
            if "label" in body and body["label"].strip() != "This Server is Free":
                raise HTTPException(status_code=400, detail="Cannot rename the default system inbound.")

    updates = {}
    # --- collect all supported fields ---
    field_map = {
        "active": ("active", int),
        "limit_value": None,
        "reset_usage": None,
        "label": ("label", str),
        "max_connections": ("max_connections", int),
        "days_valid": None,
        "custom_path": ("custom_path", str),
        "custom_sni": ("custom_sni", str),
        "custom_host": ("custom_host", str),
        "custom_fp": ("fingerprint", str),
        "color": ("color", str),
        "flag": ("flag", str),
        "fragment": ("fragment", str),
        "ip_profile_id": ("ip_profile_id", str),
        "naming_mode": ("naming_mode", str),
        "tfo": ("tfo", lambda x: 1 if x else 0),
        "ech_enabled": ("ech_enabled", lambda x: 1 if x else 0),
        "ech_sni": ("ech_sni", str),
        "ech_doh": ("ech_doh", str),
        "fragment_mode": ("fragment_mode", str),
        "fragment_length": ("fragment_length", str),
        "fragment_interval": ("fragment_interval", str),
        "allow_insecure": ("allow_insecure", lambda x: 1 if x else 0),
        "random_path": ("random_path", lambda x: 1 if x else 0),
        "enable_ipv6": ("enable_ipv6", lambda x: 1 if x else 0),
        "smux_enabled": ("smux_enabled", lambda x: 1 if x else 0),
        "ip_limit": ("ip_limit", int),
        "protocol": ("protocol", str),
        "fingerprint": ("fingerprint", str),
        "alpn": ("alpn", str),
        "port": ("port", int),
    }

    for key, mapping in field_map.items():
        if key not in body:
            continue
        value = body[key]
        if key == "limit_value":
            limit_val = float(value or 0)
            unit = body.get("limit_unit") or "GB"
            updates["limit_bytes"] = 0 if limit_val <= 0 else parse_size_to_bytes(limit_val, unit)
        elif key == "reset_usage" and value:
            updates["used_bytes"] = 0
        elif key == "days_valid":
            try:
                dv = int(value)
                if dv > 0:
                    updates["expires_at"] = (datetime.now(timezone.utc) + timedelta(days=dv)).isoformat()
                else:
                    updates["expires_at"] = None
            except (ValueError, TypeError):
                pass
        elif key == "flag":
            flag_val = str(value).strip()[:2]
            if not re.match(r'^[a-zA-Z]{2}$', flag_val):
                flag_val = ""
            else:
                flag_val = flag_val.upper()
            updates["flag"] = flag_val
        elif key == "fragment":
            fragment_val = str(value).strip()[:50]
            if fragment_val and not re.match(r'^(\d+\-\d+|tlshello)$', fragment_val):
                raise HTTPException(status_code=400, detail="Fragment must be a range like 1000-2000 or 'tlshello'")
            updates["fragment"] = fragment_val
        else:
            col_name, transform = mapping
            try:
                updates[col_name] = transform(value)
            except (ValueError, TypeError):
                raise HTTPException(status_code=400, detail=f"Invalid value for {key}")

    if not updates:
        return {"ok": True, "message": "no changes"}

    logger.info(f"Applying updates to {uid}: {updates}")

    async with LINKS_LOCK:
        link.update(updates)

    try:
        if DB_BACKEND == "sqlite":
            set_clause = ", ".join(f"{k} = ?" for k in updates.keys())
            values = list(updates.values()) + [uid]
            await db_execute(f"UPDATE links SET {set_clause} WHERE uid = ?", "", tuple(values))
        else:
            set_clause = ", ".join(f"{k} = ${i+1}" for i, k in enumerate(updates.keys()))
            values = list(updates.values()) + [uid]
            await db_execute("", f"UPDATE links SET {set_clause} WHERE uid = ${len(values)}", tuple(values))
    except Exception as e:
        logger.error(f"DB update failed for {uid}: {e}")
        original = await db_fetchone("SELECT * FROM links WHERE uid = ?", "SELECT * FROM links WHERE uid = $1", (uid,))
        if original:
            async with LINKS_LOCK:
                LINKS[uid] = dict(original)
        raise HTTPException(status_code=500, detail=f"Database update failed: {e}")

    refreshed = await db_fetchone("SELECT * FROM links WHERE uid = ?", "SELECT * FROM links WHERE uid = $1", (uid,))
    if refreshed:
        async with LINKS_LOCK:
            LINKS[uid] = dict(refreshed)

    log_event("Inbound", f"Updated inbound {uid}")
    return {"ok": True}

@app.delete("/api/links/{uid}")
async def delete_link(uid: str, _=Depends(require_auth)):
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if link and link.get("label") == "This Server is Free":
            raise HTTPException(status_code=400, detail="Default inbound (This Server is Free) cannot be deleted.")
    await db_execute("DELETE FROM links WHERE uid = ?", "DELETE FROM links WHERE uid = $1", (uid,))
    async with LINKS_LOCK:
        LINKS.pop(uid, None)
    await close_connections_for_link(uid)
    log_event("Inbound", f"Deleted inbound {uid}")
    return {"ok": True}

@app.post("/api/links/{uid}/clone")
async def clone_link(uid: str, _=Depends(require_auth)):
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if not link:
            raise HTTPException(status_code=404, detail="link not found")
        new_uid = str(uuid_lib.uuid4())
        while new_uid in LINKS:
            new_uid = str(uuid_lib.uuid4())
        new_link = dict(link)
        new_link["uid"] = new_uid
        new_link["used_bytes"] = 0
        new_link["created_at"] = datetime.now(timezone.utc).isoformat()
        LINKS[new_uid] = new_link
        await db_execute(
            "INSERT INTO links (uid, label, limit_bytes, used_bytes, max_connections, created_at, active, expires_at, custom_path, custom_sni, custom_host, custom_fp, color, flag, fragment, ip_profile_id, naming_mode, tfo, ech_enabled, ech_sni, ech_doh, fragment_mode, fragment_length, fragment_interval, allow_insecure, random_path, enable_ipv6, smux_enabled, ip_limit, protocol, fingerprint, alpn, port) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            "INSERT INTO links (uid, label, limit_bytes, used_bytes, max_connections, created_at, active, expires_at, custom_path, custom_sni, custom_host, custom_fp, color, flag, fragment, ip_profile_id, naming_mode, tfo, ech_enabled, ech_sni, ech_doh, fragment_mode, fragment_length, fragment_interval, allow_insecure, random_path, enable_ipv6, smux_enabled, ip_limit, protocol, fingerprint, alpn, port) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32)",
            (new_uid, new_link["label"], new_link["limit_bytes"], 0, new_link["max_connections"], new_link["created_at"], 1, new_link.get("expires_at"), new_link.get("custom_path", ""), new_link.get("custom_sni", ""), new_link.get("custom_host", ""), new_link.get("custom_fp", "chrome"), new_link.get("color", "#39ff14"), new_link.get("flag", ""), new_link.get("fragment", ""), new_link.get("ip_profile_id", ""), new_link.get("naming_mode", "default"), new_link.get("tfo", 0), new_link.get("ech_enabled", 0), new_link.get("ech_sni", ""), new_link.get("ech_doh", ""), new_link.get("fragment_mode", "off"), new_link.get("fragment_length", "100-200"), new_link.get("fragment_interval", "10-20"), new_link.get("allow_insecure", 0), new_link.get("random_path", 0), new_link.get("enable_ipv6", 1), new_link.get("smux_enabled", 0), new_link.get("ip_limit", 0), new_link.get("protocol", "vless-ws"), new_link.get("fingerprint", "chrome"), new_link.get("alpn", ""), new_link.get("port", 443)),
        )
        log_event("Inbound", f"Cloned inbound {uid} -> {new_uid}")
        return {"new_uuid": new_uid, "label": new_link["label"]}

# ------------------ Clean IP Addresses ------------------
@app.get("/api/addresses")
async def list_addresses(_=Depends(require_auth)):
    async with CUSTOM_ADDRESSES_LOCK:
        return {"addresses": list(CUSTOM_ADDRESSES)}

@app.post("/api/addresses")
@limiter.limit("10/minute")
async def add_address(request: Request, _=Depends(require_auth)):
    body = await request.json()
    addr = (body.get("address") or "").strip()
    if not addr or not validate_address(addr):
        raise HTTPException(status_code=400, detail="Invalid address format")
    async with CUSTOM_ADDRESSES_LOCK:
        if addr in CUSTOM_ADDRESSES:
            raise HTTPException(status_code=400, detail="Address already exists")
        CUSTOM_ADDRESSES.append(addr)
    flag = await fetch_ip_flag(addr)
    try:
        await db_execute(
            "INSERT INTO custom_addresses (address, flag) VALUES (?, ?)",
            "INSERT INTO custom_addresses (address, flag) VALUES ($1, $2)",
            (addr, flag)
        )
    except ADDRESS_INTEGRITY_ERRORS:
        pass
    log_event("Clean IP", f"Added address {addr} (flag: {flag})")
    return {"ok": True, "addresses": list(CUSTOM_ADDRESSES)}

@app.patch("/api/addresses/{index}")
async def edit_address(index: int, request: Request, _=Depends(require_auth)):
    body = await request.json()
    new_addr = (body.get("address") or "").strip()
    if not new_addr or not validate_address(new_addr):
        raise HTTPException(status_code=400, detail="Invalid address format")
    async with CUSTOM_ADDRESSES_LOCK:
        if 0 <= index < len(CUSTOM_ADDRESSES):
            old = CUSTOM_ADDRESSES[index]
            if new_addr in CUSTOM_ADDRESSES and new_addr != old:
                raise HTTPException(status_code=400, detail="Address already exists")
            CUSTOM_ADDRESSES[index] = new_addr
            await db_execute("DELETE FROM custom_addresses WHERE address = ?", "DELETE FROM custom_addresses WHERE address = $1", (old,))
            flag = await fetch_ip_flag(new_addr)
            await db_execute(
                "INSERT INTO custom_addresses (address, flag) VALUES (?, ?)",
                "INSERT INTO custom_addresses (address, flag) VALUES ($1, $2)",
                (new_addr, flag)
            )
        else:
            raise HTTPException(status_code=404, detail="Address not found")
    log_event("Clean IP", f"Edited address from {old} to {new_addr}")
    return {"ok": True, "addresses": list(CUSTOM_ADDRESSES)}

@app.post("/api/addresses/batch")
@limiter.limit("5/minute")
async def add_addresses_batch(request: Request, _=Depends(require_auth)):
    body = await request.json()
    addresses = body.get("addresses", [])
    added = 0
    errors = 0
    new_addrs = []
    for addr in addresses:
        if isinstance(addr, str):
            addr = addr.strip()
            if not addr or not validate_address(addr):
                errors += 1
                continue
            async with CUSTOM_ADDRESSES_LOCK:
                if addr not in CUSTOM_ADDRESSES:
                    CUSTOM_ADDRESSES.append(addr)
                    new_addrs.append(addr)
                    added += 1
                else:
                    errors += 1
    if new_addrs:
        for addr in new_addrs:
            try:
                await db_execute(
                    "INSERT INTO custom_addresses (address, flag) VALUES (?, '')",
                    "INSERT INTO custom_addresses (address, flag) VALUES ($1, '')",
                    (addr,)
                )
            except ADDRESS_INTEGRITY_ERRORS:
                pass
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                queries = [{"query": ip, "fields": "status,countryCode"} for ip in new_addrs]
                resp = await client.post("http://ip-api.com/batch?fields=status,countryCode", json=queries)
                if resp.status_code == 200:
                    data = resp.json()
                    for i, addr in enumerate(new_addrs):
                        item = data[i] if i < len(data) else {}
                        code = item.get("countryCode", "") if item.get("status") == "success" else ""
                        if code:
                            await db_execute(
                                "UPDATE custom_addresses SET flag = ? WHERE address = ?",
                                "UPDATE custom_addresses SET flag = $1 WHERE address = $2",
                                (code, addr)
                            )
                            async with IP_FLAG_CACHE_LOCK:
                                if len(IP_FLAG_CACHE) >= IP_FLAG_CACHE_MAX:
                                    IP_FLAG_CACHE.pop(next(iter(IP_FLAG_CACHE)))
                                IP_FLAG_CACHE[addr] = code
        except Exception:
            pass
        log_event("Clean IP", f"Batch added {added} addresses")
    return {"ok": True, "added": added, "errors": errors}

@app.delete("/api/addresses/{index}")
async def delete_address(index: int, _=Depends(require_auth)):
    async with CUSTOM_ADDRESSES_LOCK:
        if 0 <= index < len(CUSTOM_ADDRESSES):
            addr = CUSTOM_ADDRESSES.pop(index)
            await db_execute("DELETE FROM custom_addresses WHERE address = ?", "DELETE FROM custom_addresses WHERE address = $1", (addr,))
        else:
            raise HTTPException(status_code=404, detail="Address not found")
    log_event("Clean IP", f"Deleted address {addr}")
    return {"ok": True, "addresses": list(CUSTOM_ADDRESSES)}

@app.delete("/api/addresses")
async def delete_all_addresses(_=Depends(require_auth)):
    async with CUSTOM_ADDRESSES_LOCK:
        CUSTOM_ADDRESSES[:] = ["www.speedtest.net"]
    await db_execute("DELETE FROM custom_addresses", "DELETE FROM custom_addresses")
    log_event("Clean IP", "All addresses deleted")
    return {"ok": True}

@app.post("/api/addresses/bulk-delete")
async def bulk_delete_addresses(request: Request, _=Depends(require_auth)):
    body = await request.json()
    indices = body.get("indices", [])
    async with CUSTOM_ADDRESSES_LOCK:
        for idx in sorted(indices, reverse=True):
            if 0 <= idx < len(CUSTOM_ADDRESSES):
                addr = CUSTOM_ADDRESSES.pop(idx)
                await db_execute("DELETE FROM custom_addresses WHERE address = ?", "DELETE FROM custom_addresses WHERE address = $1", (addr,))
    log_event("Clean IP", "Bulk deleted addresses")
    return {"ok": True}

# ------------------ IP Profiles ------------------
@app.get("/api/ip-profiles")
async def get_ip_profiles(_=Depends(require_auth)):
    async with IP_PROFILES_LOCK:
        profiles = []
        for pid, pdata in IP_PROFILES.items():
            profiles.append({"id": pid, "name": pdata["name"], "address_count": len(pdata["addresses"])})
    return profiles

async def get_ip_location(ip: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,isp,org")
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    return {
                        "country": data.get("country", ""),
                        "city": data.get("city", ""),
                        "isp": data.get("isp", ""),
                        "org": data.get("org", "")
                    }
    except Exception:
        pass
    return {"country": "", "city": "", "isp": "", "org": ""}

@app.post("/api/ip-profiles")
async def create_ip_profile(request: Request, _=Depends(require_auth)):
    body = await request.json()
    name = body.get("name", "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="Name required")
    pid = str(uuid_lib.uuid4())
    async with IP_PROFILES_LOCK:
        IP_PROFILES[pid] = {"name": name, "addresses": []}
        await db_execute("INSERT INTO ip_profiles (id, name) VALUES (?,?)", "INSERT INTO ip_profiles (id, name) VALUES ($1,$2)", (pid, name))
    return {"id": pid, "name": name}

@app.put("/api/ip-profiles/{pid}")
async def update_ip_profile(pid: str, request: Request, _=Depends(require_auth)):
    body = await request.json()
    name = body.get("name", "").strip()
    async with IP_PROFILES_LOCK:
        if pid not in IP_PROFILES:
            raise HTTPException(status_code=404, detail="Profile not found")
        IP_PROFILES[pid]["name"] = name
        await db_execute("UPDATE ip_profiles SET name = ? WHERE id = ?", "UPDATE ip_profiles SET name = $1 WHERE id = $2", (name, pid))
    return {"ok": True}

@app.delete("/api/ip-profiles/{pid}")
async def delete_ip_profile(pid: str, _=Depends(require_auth)):
    async with IP_PROFILES_LOCK:
        if pid not in IP_PROFILES:
            raise HTTPException(status_code=404, detail="Profile not found")
        del IP_PROFILES[pid]
        await db_execute("DELETE FROM ip_profiles WHERE id = ?", "DELETE FROM ip_profiles WHERE id = $1", (pid,))
        await db_execute("DELETE FROM profile_addresses WHERE profile_id = ?", "DELETE FROM profile_addresses WHERE profile_id = $1", (pid,))
    return {"ok": True}

@app.get("/api/ip-profiles/{pid}/addresses")
async def get_profile_addresses(pid: str, _=Depends(require_auth)):
    async with IP_PROFILES_LOCK:
        if pid not in IP_PROFILES:
            raise HTTPException(status_code=404, detail="Profile not found")
        rows = await db_fetchall(
            "SELECT address, flag, name, sort_number FROM profile_addresses WHERE profile_id = ? ORDER BY sort_number ASC",
            "SELECT address, flag, name, sort_number FROM profile_addresses WHERE profile_id = $1 ORDER BY sort_number ASC",
            (pid,))
        return [dict(r) for r in rows]

@app.put("/api/ip-profiles/{pid}/addresses")
async def set_profile_addresses(pid: str, request: Request, _=Depends(require_auth)):
    body = await request.json()
    new_lines = body.get("addresses", [])
    async with IP_PROFILES_LOCK:
        if pid not in IP_PROFILES:
            raise HTTPException(status_code=404, detail="Profile not found")
        await db_execute("DELETE FROM profile_addresses WHERE profile_id = ?",
                         "DELETE FROM profile_addresses WHERE profile_id = $1", (pid,))
        entries = [parse_address_entry(line) for line in new_lines if line.strip()]
        if entries:
            if DB_BACKEND == "sqlite":
                async with db_lock:
                    await db_conn.executemany(
                        "INSERT INTO profile_addresses (profile_id, address, flag, name, sort_number) VALUES (?,?,?,?,?)",
                        [(pid, e["address"], e["flag"], e["name"], e["sort_number"]) for e in entries])
                    await db_conn.commit()
            else:
                async with pg_pool.acquire() as conn:
                    await conn.executemany(
                        "INSERT INTO profile_addresses (profile_id, address, flag, name, sort_number) VALUES ($1,$2,$3,$4,$5)",
                        [(pid, e["address"], e["flag"], e["name"], e["sort_number"]) for e in entries])
        IP_PROFILES[pid]["addresses"] = [e["address"] for e in entries]
    return {"ok": True}

@app.post("/api/ip-profiles/{pid}/addresses")
async def add_profile_address(pid: str, request: Request, _=Depends(require_auth)):
    body = await request.json()
    addr = body.get("address", "").strip()
    if not addr or not validate_address(addr):
        raise HTTPException(status_code=400, detail="Invalid address")
    async with IP_PROFILES_LOCK:
        if pid not in IP_PROFILES:
            raise HTTPException(status_code=404, detail="Profile not found")
        if addr in IP_PROFILES[pid]["addresses"]:
            raise HTTPException(status_code=400, detail="Address already in profile")
        IP_PROFILES[pid]["addresses"].append(addr)
        flag = await fetch_ip_flag(addr)
        await db_execute(
            "INSERT INTO profile_addresses (profile_id, address, flag) VALUES (?,?,?)",
            "INSERT INTO profile_addresses (profile_id, address, flag) VALUES ($1,$2,$3)",
            (pid, addr, flag)
        )
    return {"ok": True}

@app.delete("/api/ip-profiles/{pid}/addresses")
async def remove_profile_address(pid: str, request: Request, _=Depends(require_auth)):
    body = await request.json()
    addr = body.get("address", "").strip()
    async with IP_PROFILES_LOCK:
        if pid not in IP_PROFILES:
            raise HTTPException(status_code=404, detail="Profile not found")
        if addr not in IP_PROFILES[pid]["addresses"]:
            raise HTTPException(status_code=404, detail="Address not found in profile")
        IP_PROFILES[pid]["addresses"].remove(addr)
        await db_execute(
            "DELETE FROM profile_addresses WHERE profile_id = ? AND address = ?",
            "DELETE FROM profile_addresses WHERE profile_id = $1 AND address = $2",
            (pid, addr)
        )
    return {"ok": True}

# ------------------ Flag & DoH ------------------
@app.get("/api/auto-flag/{ip}")
async def auto_flag(ip: str):
    flag = await fetch_ip_flag(ip)
    return {"flag": flag}

@app.post("/api/resolve-flags")
async def resolve_flags(request: Request):
    body = await request.json()
    ips = body.get("ips", [])
    results = {}
    if ips:
        queries = [{"query": ip, "fields": "status,countryCode,country,city"} for ip in ips]
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post("http://ip-api.com/batch?fields=status,countryCode,country,city", json=queries)
                if resp.status_code == 200:
                    data = resp.json()
                    for i, item in enumerate(data):
                        ip = ips[i]
                        if item.get("status") == "success":
                            code = item.get("countryCode", "")
                            city = item.get("city", "")
                            country = item.get("country", "")
                            if code:
                                async with IP_FLAG_CACHE_LOCK:
                                    if len(IP_FLAG_CACHE) >= IP_FLAG_CACHE_MAX:
                                        IP_FLAG_CACHE.pop(next(iter(IP_FLAG_CACHE)))
                                    IP_FLAG_CACHE[ip] = code
                            results[ip] = {"countryCode": code, "city": city, "country": country}
                        else:
                            results[ip] = {"countryCode": "", "city": "", "country": ""}
        except Exception:
            pass
    return results

@app.post("/api/resolve-flags-and-update")
async def resolve_flags_and_update(request: Request, _=Depends(require_auth)):
    async with CUSTOM_ADDRESSES_LOCK:
        ips_to_resolve = [addr for addr in CUSTOM_ADDRESSES if re.match(r'^\d+\.\d+\.\d+\.\d+$', addr) or ':' in addr]
        async with IP_FLAG_CACHE_LOCK:
            unresolved = [ip for ip in ips_to_resolve if ip not in IP_FLAG_CACHE or not IP_FLAG_CACHE[ip]]
    if not unresolved:
        return {"resolved": 0, "message": "All addresses already flagged."}
    queries = [{"query": ip, "fields": "status,countryCode"} for ip in unresolved]
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post("http://ip-api.com/batch?fields=status,countryCode", json=queries)
            if resp.status_code != 200:
                raise HTTPException(status_code=502, detail="Flag API failed")
            data = resp.json()
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Flag API request error: {e}")
    updated = 0
    for i, ip in enumerate(unresolved):
        item = data[i] if i < len(data) else {}
        code = item.get("countryCode", "").upper() if item.get("status") == "success" else ""
        if code:
            async with IP_FLAG_CACHE_LOCK:
                if len(IP_FLAG_CACHE) >= IP_FLAG_CACHE_MAX:
                    IP_FLAG_CACHE.pop(next(iter(IP_FLAG_CACHE)))
                IP_FLAG_CACHE[ip] = code
            await db_execute(
                "UPDATE custom_addresses SET flag = ? WHERE address = ?",
                "UPDATE custom_addresses SET flag = $1 WHERE address = $2",
                (code, ip)
            )
            updated += 1
    return {"resolved": updated, "total": len(unresolved)}

@app.get("/api/doh-upstreams")
async def get_doh_upstreams(_=Depends(require_auth)):
    return {"upstreams": DOH_UPSTREAMS, "enabled": DOH_ENABLED}

@app.get("/api/doh-ping")
async def doh_ping(_=Depends(require_auth)):
    results = {}
    for url in DOH_UPSTREAMS:
        start = time.time()
        try:
            async with httpx.AsyncClient(timeout=3) as client:
                resp = await client.get(url)
            latency = round((time.time() - start) * 1000)
            results[url] = {"latency_ms": latency, "status": resp.status_code}
        except Exception:
            results[url] = {"latency_ms": None, "status": "failed"}
    return results

@app.post("/api/doh-upstreams")
async def save_doh_upstreams(request: Request, _=Depends(require_auth)):
    body = await request.json()
    upstreams = body.get("upstreams", [])
    global DOH_UPSTREAMS, DOH_ENABLED
    DOH_UPSTREAMS = [u for u in upstreams if isinstance(u, str) and u.strip().startswith("http")]
    await db_execute("DELETE FROM doh_upstreams", "DELETE FROM doh_upstreams")
    for u in DOH_UPSTREAMS:
        await db_execute("INSERT INTO doh_upstreams (url) VALUES (?)", "INSERT INTO doh_upstreams (url) VALUES ($1)", (u,))
    if "enabled" in body:
        DOH_ENABLED = body["enabled"]
        await db_execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES ('doh_enabled', ?)",
            "INSERT INTO settings (key, value) VALUES ('doh_enabled', $1) ON CONFLICT (key) DO UPDATE SET value = $2",
            (str(int(DOH_ENABLED)), str(int(DOH_ENABLED)))
        )
    return {"ok": True}

@app.get("/dns-query")
@app.post("/dns-query")
async def doh_handler(request: Request):
    if not DOH_ENABLED:
        return Response("DoH disabled", status_code=503)
    dns_raw = None
    if request.method == "GET":
        dns_param = request.query_params.get("dns")
        if dns_param:
            padding = (4 - len(dns_param) % 4) % 4
            dns_param += "=" * padding
            try:
                dns_raw = base64.urlsafe_b64decode(dns_param)
            except Exception:
                pass
    else:
        dns_raw = await request.body()
    if not dns_raw:
        return Response("No DNS query", status_code=400)

    async def query_upstream(upstream):
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.post(
                    upstream,
                    content=dns_raw,
                    headers={"Content-Type": "application/dns-message"}
                )
                if resp.status_code == 200:
                    return resp.content
        except Exception:
            pass
        return None

    tasks = [asyncio.create_task(query_upstream(up)) for up in DOH_UPSTREAMS]
    done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    for t in done:
        result = t.result()
        if result is not None:
            for p in pending:
                p.cancel()
            return Response(content=result, media_type="application/dns-message")
    return Response("All upstreams failed", status_code=502)

# ------------------ HTTP Proxy (Secure + Streaming) ------------------
_HOP_BY_HOP = {"connection","keep-alive","proxy-authenticate","proxy-authorization",
               "te","trailers","transfer-encoding","upgrade","content-encoding","content-length"}

http_proxy_client = httpx.AsyncClient(timeout=30.0, follow_redirects=True)

PROXY_WHITELIST = set(
    d.strip() for d in os.environ.get("PROXY_WHITELIST", "").split(",") if d.strip()
) if os.environ.get("PROXY_WHITELIST") else None

async def _is_safe_target(url: str) -> bool:
    """Block private / loopback / link‑local IPs and enforce optional whitelist."""
    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        return False
    try:
        ip = socket.gethostbyname(hostname)
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
            return False
    except socket.gaierror:
        return False
    if PROXY_WHITELIST is not None:
        return any(hostname.endswith(d) for d in PROXY_WHITELIST)
    return True

@app.api_route("/proxy/{target_url:path}", methods=["GET","POST","PUT","DELETE","PATCH","HEAD","OPTIONS"])
@limiter.limit("30/minute")
async def http_proxy(target_url: str, request: Request, _=Depends(require_auth)):
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url

    if not await _is_safe_target(target_url):
        raise HTTPException(status_code=403, detail="Target URL is not allowed")

    headers = {
        k: v for k, v in request.headers.items()
        if k.lower() not in _HOP_BY_HOP and k.lower() != "host"
    }

    try:
        req = http_proxy_client.build_request(
            method=request.method,
            url=target_url,
            headers=headers,
            content=request.stream(),
        )
        resp = await http_proxy_client.send(req, stream=True)
        stats["total_requests"] += 1

        async def response_streamer():
            async for chunk in resp.aiter_bytes():
                stats["total_bytes"] += len(chunk)
                stats["download_bytes"] += len(chunk)
                yield chunk

        response_headers = {
            k: v for k, v in resp.headers.items()
            if k.lower() not in _HOP_BY_HOP
        }
        return StreamingResponse(
            response_streamer(),
            status_code=resp.status_code,
            headers=response_headers,
        )
    except httpx.RequestError as e:
        stats["total_errors"] += 1
        error_logs.append({
            "time": datetime.now(timezone.utc).isoformat(),
            "error": f"Proxy error: {e}",
            "url": target_url,
            "type": "Proxy",
        })
        raise HTTPException(status_code=502, detail=f"Proxy error: {e}")
    except Exception as e:
        stats["total_errors"] += 1
        error_logs.append({
            "time": datetime.now(timezone.utc).isoformat(),
            "error": f"Proxy error: {e}",
            "url": target_url,
            "type": "Proxy",
        })
        raise HTTPException(status_code=502, detail=f"Proxy error: {e}")

# ------------------ Blocked Domains API ------------------
@app.get("/api/blocked-domains")
async def get_blocked_domains(_=Depends(require_auth)):
    row = await db_fetchone("SELECT value FROM settings WHERE key='blocked_domains'",
                            "SELECT value FROM settings WHERE key='blocked_domains'")
    domains = row["value"] if row else ""
    return {"domains": [d.strip() for d in domains.split(",") if d.strip()]}

@app.post("/api/blocked-domains")
async def update_blocked_domains(request: Request, _=Depends(require_auth)):
    body = await request.json()
    domains = body.get("domains", [])
    domain_str = ",".join(domains)
    await db_execute(
        "INSERT OR REPLACE INTO settings (key, value) VALUES ('blocked_domains', ?)",
        "INSERT INTO settings (key, value) VALUES ('blocked_domains', $1) ON CONFLICT (key) DO UPDATE SET value = $1",
        (domain_str,)
    )
    BLOCKED_DOMAINS.clear()
    BLOCKED_DOMAINS.update(d.strip().lower() for d in domains if d.strip())
    return {"ok": True}

# ------------------ Subscription Groups (SUBS) ------------------
@app.post("/api/subs")
async def create_sub(request: Request, _=Depends(require_auth)):
    body = await request.json()
    name = (body.get("name") or "Group").strip()[:60]
    desc = (body.get("desc") or "").strip()[:200]
    password = (body.get("password") or "").strip()
    sub_id = str(uuid_lib.uuid4())
    async with SUBS_LOCK:
        SUBS[sub_id] = {
            "name": name,
            "desc": desc,
            "password_hash": bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode() if password else None,
            "uuid_key": secrets.token_urlsafe(16),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "link_ids": [],
        }
    await save_subs()
    host = get_domain(request)
    return {
        "sub_id": sub_id,
        **SUBS[sub_id],
        "public_url": f"https://{host}/sub-group/{SUBS[sub_id]['uuid_key']}",
        "sub_url": f"https://{host}/sub-group/{SUBS[sub_id]['uuid_key']}",
    }

@app.get("/api/subs")
async def list_subs(_=Depends(require_auth)):
    async with SUBS_LOCK:
        return {"subs": [{"sub_id": sid, **s} for sid, s in SUBS.items()]}

@app.patch("/api/subs/{sub_id}")
async def update_sub(sub_id: str, request: Request, _=Depends(require_auth)):
    body = await request.json()
    async with SUBS_LOCK:
        if sub_id not in SUBS:
            raise HTTPException(status_code=404, detail="not found")
        s = SUBS[sub_id]
        if "name" in body: s["name"] = str(body["name"])[:60]
        if "desc" in body: s["desc"] = str(body["desc"])[:200]
        if "password" in body:
            pw = str(body["password"]).strip()
            s["password_hash"] = bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode() if pw else None
        if "link_ids" in body:
            s["link_ids"] = list(body["link_ids"])
    await save_subs()
    return {"ok": True}

@app.delete("/api/subs/{sub_id}")
async def delete_sub(sub_id: str, _=Depends(require_auth)):
    async with SUBS_LOCK:
        if sub_id not in SUBS:
            raise HTTPException(status_code=404, detail="not found")
        del SUBS[sub_id]
    await save_subs()
    return {"ok": True}

@app.get("/sub-group/{uuid_key}")
async def sub_group_subscription(uuid_key: str, request: Request):
    async with SUBS_LOCK:
        sub = next((s for s in SUBS.values() if s.get("uuid_key") == uuid_key), None)
    if not sub:
        raise HTTPException(status_code=404, detail="not found")
    pw = request.query_params.get("pw", "")
    if sub.get("password_hash"):
        if not pw or not bcrypt.checkpw(pw.encode(), sub["password_hash"].encode()):
            raise HTTPException(status_code=403, detail="wrong password")
    host = get_domain(request)
    lines = []
    for lid in sub.get("link_ids", []):
        async with LINKS_LOCK:
            link = LINKS.get(lid)
        if link and link["active"]:
            lines.append(generate_vless_link(lid, remark=link["label"], extra=link, server_domain=host))
    content = base64.b64encode("\n".join(lines).encode()).decode()
    return Response(content=content, media_type="text/plain")

# ------------------ User Dashboard & Subscription ------------------
@app.get("/user/{uid}")
async def user_dashboard(uid: str, request: Request):
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if not link or not link["active"]:
            raise HTTPException(status_code=404, detail="User not found or disabled")
        link = dict(link)
    expires = parse_expires_at(link.get("expires_at"))
    if expires and expires < datetime.now(timezone.utc):
        raise HTTPException(status_code=403, detail="User expired")
    status = "Active ✅"
    if link.get("limit_bytes") > 0 and link["used_bytes"] >= link["limit_bytes"]:
        status = "Quota Exceeded 🚫"
    elif expires and expires < datetime.now(timezone.utc):
        status = "Expired ⏰"
    elif not link["active"]:
        status = "Blocked 🔒"
    used = link["used_bytes"]
    limit = link["limit_bytes"]
    usage_percent = 0 if limit == 0 else min(100, round(used / limit * 100, 1))
    usage_bar_color = "#4ade80" if usage_percent < 80 else ("#fbbf24" if usage_percent < 95 else "#f87171")

    domain = get_domain(request)

    vless_link = generate_vless_link(uid, remark=link["label"], server_domain=domain)
    sub_url = f"https://{domain}/sub/{uid}"
    clash_url = f"https://{domain}/sub/{uid}/clash"
    singbox_url = f"https://{domain}/sub/{uid}/singbox"
    auto_url = f"https://{domain}/sub/{uid}/auto"
    qr_url = f"https://api.qrserver.com/v1/create-qr-code/?size=250x250&data={quote(sub_url)}"
    expiry_str = "Unlimited ∞" if not expires else expires.strftime("%Y-%m-%d %H:%M (UTC)")
    daily_usage = await db_fetchall(
        "SELECT day, bytes FROM daily_traffic WHERE uid = ? ORDER BY day DESC LIMIT 7",
        "SELECT day, bytes FROM daily_traffic WHERE uid = $1 ORDER BY day DESC LIMIT 7",
        (uid,)
    )
    daily_data = [{"day": d["day"], "mb": round(d["bytes"]/1048576, 1)} for d in daily_usage]
    label_esc = html.escape(link['label'])
    status_esc = html.escape(status)
    expiry_str_esc = html.escape(expiry_str)
    vless_link_esc = html.escape(vless_link)
    sub_url_esc = html.escape(sub_url)
    clash_url_esc = html.escape(clash_url)
    singbox_url_esc = html.escape(singbox_url)
    qr_url_esc = html.escape(qr_url)
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<title>Dashboard | {label_esc}</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&family=Vazirmatn:wght@400;600;700;800&display=swap" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.js"></script>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
:root{{
  --primary:#39ff14; --primary-dim:rgba(57,255,20,0.20); --primary-glass:rgba(57,255,20,0.10);
  --bg:#09090b; --bg2:#111113; --bg3:#18181b;
  --surface:rgba(18,18,20,0.8); --surface2:rgba(24,24,27,0.92); --surface3:rgba(30,30,35,0.88);
  --border:rgba(57,255,20,0.14); --border2:rgba(57,255,20,0.30);
  --text:#f0f0f4; --text2:#a1a1aa; --text3:#71717a;
  --green:#4ade80; --red:#f87171; --yellow:#fbbf24;
  --radius-sm:12px; --radius-md:18px; --radius-lg:26px;
  --shadow:0 12px 40px rgba(0,0,0,0.6);
  --shadow-soft:0 6px 24px rgba(0,0,0,0.35);
  --shadow-glow:0 0 35px var(--primary-dim);
  --transition:0.3s cubic-bezier(0.20,0.80,0.40,1);
  --halo-color-1:rgba(57,255,20,0.22); --halo-color-2:rgba(57,255,20,0.10); --halo-color-3:rgba(57,255,20,0.05);
}}
body{{
  font-family:'Inter','Vazirmatn',sans-serif; background:var(--bg); color:var(--text);
  display:flex; align-items:center; justify-content:center; min-height:100vh; padding:20px;
  position:relative; overflow-x:hidden;
}}
body[dir="rtl"]{{direction:rtl;text-align:right}}
body::before{{
  content:''; position:fixed; top:-40%; left:-30%; width:80%; height:90%;
  background:radial-gradient(ellipse at 30% 50%,var(--halo-color-1) 0%,transparent 60%);
  animation:haloFloat1 28s infinite alternate ease-in-out; z-index:0; pointer-events:none; filter:blur(60px);
}}
body::after{{
  content:''; position:fixed; bottom:-40%; right:-30%; width:80%; height:90%;
  background:radial-gradient(ellipse at 65% 55%,var(--halo-color-2) 0%,transparent 60%);
  animation:haloFloat2 32s infinite alternate ease-in-out; z-index:0; pointer-events:none; filter:blur(70px);
}}
@keyframes haloFloat1{{0%{{transform:translate(0,0) scale(1)}} 100%{{transform:translate(8%,10%) scale(1.1)}}}}
@keyframes haloFloat2{{0%{{transform:translate(0,0) scale(1)}} 100%{{transform:translate(-8%,-10%) scale(1.1)}}}}
.card{{
  background:var(--surface2); border:1px solid var(--border); border-radius:var(--radius-lg);
  padding:32px 28px; max-width:800px; width:100%; box-shadow:var(--shadow),var(--shadow-glow);
  backdrop-filter:blur(20px) saturate(110%); position:relative; z-index:1; text-align:center;
}}
.card::before{{
  content:'';position:absolute;inset:0;border-radius:inherit;padding:1px;
  background:conic-gradient(from var(--angle,0deg),transparent,var(--primary),transparent);
  pointer-events: none;
  -webkit-mask:linear-gradient(#fff 0 0) content-box,linear-gradient(#fff 0 0);
  mask:linear-gradient(#fff 0 0) content-box,linear-gradient(#fff 0 0);
  -webkit-mask-composite:xor;mask-composite:exclude;
  animation:borderRotate 5s linear infinite paused;opacity:0;transition:opacity 0.4s;
}}
.card:hover::before{{opacity:1;animation-play-state:running}}
@property --angle{{syntax:'<angle>';initial-value:0deg;inherits:false}}
@keyframes borderRotate{{from{{--angle:0deg}}to{{--angle:360deg}}}}
.header-row{{
  display:flex; justify-content:space-between; align-items:center; margin-bottom:20px;
}}
h1{{color:var(--primary); font-size:1.8rem; font-weight:800; letter-spacing:-0.5px;}}
.lang-switch{{display:flex; gap:2px; background:var(--surface3); border-radius:var(--radius-sm); padding:3px;}}
.lang-btn{{padding:6px 14px; border:none; background:transparent; color:var(--text3); font-size:0.8rem; font-weight:700; border-radius:8px; cursor:pointer; font-family:inherit; transition:all var(--transition);}}
.lang-btn.active{{background:var(--primary); color:#000; box-shadow:0 0 16px var(--primary-dim);}}
.info-box{{
  background:var(--surface3); border-radius:var(--radius-md); padding:20px; margin-bottom:20px;
  display:grid; grid-template-columns:1fr 1fr; gap:12px 24px; text-align:left;
  border:1px solid var(--border); backdrop-filter:blur(8px);
}}
.info-box .row{{display:flex; flex-direction:column; padding:8px 0; border-bottom:1px solid var(--border);}}
.info-box .row:last-child{{border-bottom:none;}}
.label{{color:var(--text3); font-weight:600; font-size:0.85rem;}}
.value{{color:var(--text); font-weight:600; font-size:1rem;}}
.progress-bar-bg{{height:8px; background:var(--border); border-radius:4px; margin-top:12px; overflow:hidden; grid-column:span 2;}}
.progress-bar-fill{{height:100%; width:{usage_percent}%; background:{usage_bar_color}; border-radius:4px; transition:width 0.3s;}}
.progress-text{{font-size:0.8rem; color:var(--text2); margin-top:4px; text-align:right; grid-column:span 2;}}
.qr{{background:#fff; padding:12px; border-radius:16px; display:inline-block; margin-bottom:20px;}}
.qr img{{display:block; border-radius:8px;}}
.actions-grid{{display:grid; grid-template-columns:1fr 1fr; gap:10px; margin-bottom:10px;}}
.btn{{
  display:flex; align-items:center; justify-content:center; padding:12px;
  background:linear-gradient(135deg,var(--primary),color-mix(in srgb,var(--primary) 80%,black));
  color:#000; font-weight:800; border-radius:var(--radius-sm); text-decoration:none;
  transition:all var(--transition); border:1px solid transparent; cursor:pointer; font-family:inherit; font-size:0.95rem;
  box-shadow:0 6px 28px var(--primary-dim); position:relative; overflow:hidden;
}}
.btn::after{{
  content:'';position:absolute;top:0;left:0;width:100%;height:100%;
  background:linear-gradient(45deg,transparent,rgba(255,255,255,0.2),transparent);
  transform:translateX(-100%);transition:transform 0.8s;
}}
.btn:hover::after{{transform:translateX(100%)}}
.btn:hover{{filter:brightness(1.2); box-shadow:0 10px 40px var(--primary-dim); transform:translateY(-2px);}}
.btn-outline{{background:var(--surface3); color:var(--text); border:1px solid var(--border);}}
.btn-outline:hover{{background:var(--primary-glass); border-color:var(--primary); color:var(--primary); box-shadow:0 0 28px var(--primary-dim);}}
#toast{{position:fixed; bottom:40px; left:50%; transform:translateX(-50%); background:var(--surface); color:var(--text); border:1px solid var(--border2); border-radius:var(--radius-md); padding:14px 30px; font-weight:600; opacity:0; transition:all 0.45s ease; z-index:999; backdrop-filter:blur(30px); box-shadow:var(--shadow-soft); pointer-events:none;}}
#toast.show{{opacity:1; transform:translateX(-50%) translateY(0); pointer-events:auto;}}
.daily-chart{{margin-top:16px; grid-column:span 2;}}
@media(max-width:600px){{
  .card{{padding:24px 16px;}}
  .actions-grid{{grid-template-columns:1fr;}}
  .header-row{{flex-direction:column; gap:8px;}}
  h1{{font-size:1.5rem;}}
}}
</style>
</head>
<body>
<div class="card">
  <div class="header-row">
    <h1>{label_esc}</h1>
    <div class="lang-switch">
      <button class="lang-btn lang-en active" onclick="setLang('en')">EN</button>
      <button class="lang-btn lang-fa" onclick="setLang('fa')">FA</button>
    </div>
  </div>
  <div class="info-box">
    <div class="row"><span class="label" data-en="Status" data-fa="وضعیت">Status</span><span class="value">{status_esc}</span></div>
    <div class="row"><span class="label" data-en="Expiration" data-fa="انقضا">Expiration</span><span class="value">{expiry_str_esc}</span></div>
    <div class="row" style="grid-column:span 2;"><span class="label" data-en="Data Usage" data-fa="مصرف داده">Data Usage</span><span class="value">{_fmt_bytes(used)} / {'∞' if limit == 0 else _fmt_bytes(limit)}</span></div>
    <div class="progress-bar-bg"><div class="progress-bar-fill"></div></div>
    <div class="progress-text" data-en="{usage_percent}% used" data-fa="{usage_percent}% مصرف">{usage_percent}% used</div>
    <div class="daily-chart" id="daily-chart"><canvas id="dailyCanvas"></canvas></div>
  </div>
  <div class="qr">
    <img src="{qr_url_esc}" alt="Scan to Import" width="200" height="200">
  </div>
  <div class="actions-grid">
    <button class="btn btn-outline" onclick="copyToClip('{sub_url_esc}', t('sub_copied'))">🔗 <span data-en="Copy Sub" data-fa="کپی اشتراک">Copy Sub</span></button>
    <button class="btn btn-outline" onclick="copyToClip('{clash_url_esc}', t('clash_copied'))">🐱 <span data-en="Copy Clash" data-fa="کپی کلش">Copy Clash</span></button>
    <button class="btn btn-outline" onclick="copyToClip('{singbox_url_esc}', t('singbox_copied'))">🧩 <span data-en="Copy Sing‑Box" data-fa="کپی سینگ‌باکس">Copy Sing‑Box</span></button>
    <button class="btn btn-outline" onclick="copyToClip('{vless_link_esc}', t('vless_copied'))">📋 <span data-en="Copy VLESS" data-fa="کپی وی‌لس">Copy VLESS</span></button>
  </div>
</div>
<div id="toast">Copied!</div>
<script>
var lang = localStorage.getItem('ll') || 'en';
var i18n = {{
  en:{{ sub_copied:'Subscription Link Copied!', clash_copied:'Clash Link Copied!', singbox_copied:'Sing‑Box Link Copied!', vless_copied:'VLESS Link Copied!' }},
  fa:{{ sub_copied:'لینک اشتراک کپی شد!', clash_copied:'لینک کلش کپی شد!', singbox_copied:'لینک سینگ‌باکس کپی شد!', vless_copied:'لینک VLESS کپی شد!' }}
}};
function t(key){{ return (i18n[lang] && i18n[lang][key]) || i18n['en'][key] || key; }}
function setLang(l){{
  lang=l;
  document.querySelectorAll('.lang-btn').forEach(b=>b.classList.remove('active'));
  document.querySelectorAll('.lang-'+l).forEach(b=>b.classList.add('active'));
  document.body.dir = l==='fa' ? 'rtl' : 'ltr';
  document.querySelectorAll('[data-en]').forEach(el=>{{
    var v = el.getAttribute('data-'+l);
    if(v) el.textContent = v;
  }});
  localStorage.setItem('ll', l);
}}
setLang(lang);

function copyToClipboard(text) {{
    if (!text) {{ toast('Nothing to copy', true); return; }}
    if (navigator.clipboard && navigator.clipboard.writeText) {{
        navigator.clipboard.writeText(text).then(function() {{
            toast(t('sub_copied'));
        }}, function() {{
            fallbackCopy(text);
        }});
    }} else {{
        fallbackCopy(text);
    }}
}}

function fallbackCopy(text) {{
    var textArea = document.createElement("textarea");
    textArea.value = text;
    textArea.style.top = "0"; textArea.style.left = "0"; textArea.style.position = "fixed"; textArea.style.opacity = "0";
    document.body.appendChild(textArea);
    textArea.focus(); textArea.select();
    try {{
        var successful = document.execCommand('copy');
        toast(successful ? t('sub_copied') : 'Failed to copy');
    }} catch (err) {{
        toast('Failed to copy', true);
    }}
    document.body.removeChild(textArea);
}}

function copyToClip(text, msg) {{
    if (navigator.clipboard && navigator.clipboard.writeText) {{
        navigator.clipboard.writeText(text).then(function() {{
            var t = document.getElementById('toast');
            t.innerText = msg;
            t.classList.add('show');
            setTimeout(function() {{ t.classList.remove('show'); }}, 2500);
        }}, function() {{
            fallbackCopyDashboard(text, msg);
        }});
    }} else {{
        fallbackCopyDashboard(text, msg);
    }}
}}

function fallbackCopyDashboard(text, msg) {{
    var textArea = document.createElement("textarea");
    textArea.value = text;
    textArea.style.top = "0"; textArea.style.left = "0"; textArea.style.position = "fixed"; textArea.style.opacity = "0";
    document.body.appendChild(textArea);
    textArea.focus(); textArea.select();
    try {{
        var ok = document.execCommand('copy');
        var t = document.getElementById('toast');
        t.innerText = ok ? msg : 'Copy failed';
        t.classList.add('show');
        setTimeout(function() {{ t.classList.remove('show'); }}, 2500);
    }} catch (e) {{
        var t = document.getElementById('toast');
        t.innerText = 'Copy failed';
        t.classList.add('show');
        setTimeout(function() {{ t.classList.remove('show'); }}, 2500);
    }}
    document.body.removeChild(textArea);
}}

function toast(msg, err) {{
    var t = document.getElementById('toast');
    t.innerText = msg;
    t.classList.add('show');
    if (err) t.style.background = '#f87171';
    else t.style.background = 'var(--primary)';
    clearTimeout(t._hide);
    t._hide = setTimeout(function() {{ t.classList.remove('show'); }}, 2500);
}}

var dailyData = {json.dumps(daily_data)};
if (dailyData.length > 0) {{
    var ctx = document.getElementById('dailyCanvas').getContext('2d');
    new Chart(ctx, {{
        type: 'bar',
        data: {{
            labels: dailyData.map(d => d.day),
            datasets: [{{
                label: 'MB',
                data: dailyData.map(d => d.mb),
                backgroundColor: '#39ff14'
            }}]
        }},
        options: {{ responsive: true, plugins: {{ legend: {{ display: false }} }} }}
    }});
}}
</script>
</body>
</html>"""
    return HTMLResponse(content=html_content)

@app.get("/user/{uid}/sub")
@limiter.limit("10/minute")
async def user_subscription(uid: str, request: Request):
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if not link or not link["active"]:
            raise HTTPException(status_code=404, detail="link not found or disabled")
        link = dict(link)
    expires = parse_expires_at(link.get("expires_at"))
    if expires and expires < datetime.now(timezone.utc):
        raise HTTPException(status_code=403, detail="link expired")
    status = "active"
    if link.get("limit_bytes") > 0 and link["used_bytes"] >= link["limit_bytes"]:
        status = "quota_exceeded"
    elif expires and expires < datetime.now(timezone.utc):
        status = "expired"
    elif not link["active"]:
        status = "blocked"
    ip_profile_id = link.get("ip_profile_id")
    if ip_profile_id:
        async with IP_PROFILES_LOCK:
            if ip_profile_id in IP_PROFILES:
                rows = await db_fetchall(
                    "SELECT address, flag, name, sort_number FROM profile_addresses WHERE profile_id = ? ORDER BY sort_number ASC",
                    "SELECT address, flag, name, sort_number FROM profile_addresses WHERE profile_id = $1 ORDER BY sort_number ASC",
                    (ip_profile_id,)
                )
                addresses = [dict(r) for r in rows] if rows else []
            else:
                addresses = []
    else:
        async with CUSTOM_ADDRESSES_LOCK:
            addresses = list(CUSTOM_ADDRESSES)
    extra = {
        "custom_path": link.get("custom_path", ""),
        "custom_sni": link.get("custom_sni", ""),
        "custom_host": link.get("custom_host", ""),
        "custom_fp": link.get("custom_fp", "chrome"),
        "fragment": link.get("fragment", ""),
        "tfo": link.get("tfo", False),
        "ech_enabled": link.get("ech_enabled", False),
        "ech_sni": link.get("ech_sni", ""),
        "ech_doh": link.get("ech_doh", ""),
        "fragment_mode": link.get("fragment_mode", "off"),
        "fragment_length": link.get("fragment_length", "100-200"),
        "fragment_interval": link.get("fragment_interval", "10-20"),
        "allow_insecure": link.get("allow_insecure", False),
        "random_path": link.get("random_path", False),
        "enable_ipv6": link.get("enable_ipv6", True),
        "smux_enabled": link.get("smux_enabled", False),
        "ip_limit": link.get("ip_limit", 0),
        "protocol": link.get("protocol", "vless-ws"),
        "fingerprint": link.get("fingerprint", "chrome"),
        "alpn": link.get("alpn", ""),
        "port": link.get("port", 443),
    }
    domain = get_domain(request)
    sub_content = await generate_subscription_content(link, uid, addresses, extra, status, server_domain=domain)
    encoded = base64.b64encode(sub_content.encode()).decode()
    total_bytes = link["limit_bytes"] if link["limit_bytes"] > 0 else UNLIMITED_QUOTA_BYTES
    expire_ts = int(expires.timestamp()) if expires else 0
    if STEALTH_MODE or SUB_FILENAME:
        filename = SUB_FILENAME if SUB_FILENAME else "update.txt"
    else:
        usage_str = f"{_fmt_bytes(link['used_bytes'])}" if link['limit_bytes'] == 0 else f"{_fmt_bytes(link['used_bytes'])} of {_fmt_bytes(link['limit_bytes'])}"
        expiry_str = "Unlimited" if not link.get("expires_at") else f"{seconds_until_expiry(link['expires_at'])//86400}d left" if seconds_until_expiry(link['expires_at']) else "Expired"
        filename = f"{link['label']} - {usage_str} - {expiry_str}.txt"
        filename = re.sub(r'[\\/*?:"<>|]', "_", filename)
    headers = {
        "Content-Type": "text/plain; charset=utf-8",
        "Content-Disposition": f'attachment; filename="{filename}"',
        "profile-update-interval": "6",
        "subscription-userinfo": f"upload={link['used_bytes']}; download=0; total={total_bytes}; expire={expire_ts}",
        "X-Status": status,
    }
    log_event("Subscription", f"Subscription accessed for {link['label']} ({uid}) status={status}", ip=request.client.host)
    return Response(content=encoded, headers=headers)


@app.get("/sub/{uid}")
@limiter.limit("10/minute")
async def subscription_endpoint(uid: str, request: Request):
    return await user_subscription(uid, request)


@app.get("/sub/{uid}/clash")
async def clash_subscription(uid: str, request: Request):
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if not link or not link["active"]:
            raise HTTPException(status_code=404, detail="link not found or disabled")
        link = dict(link)
    domain = get_domain(request)
    ip_profile_id = link.get("ip_profile_id")
    if ip_profile_id:
        async with IP_PROFILES_LOCK:
            if ip_profile_id in IP_PROFILES:
                rows = await db_fetchall(
                    "SELECT address, flag, name, sort_number FROM profile_addresses WHERE profile_id = ? ORDER BY sort_number ASC",
                    "SELECT address, flag, name, sort_number FROM profile_addresses WHERE profile_id = $1 ORDER BY sort_number ASC",
                    (ip_profile_id,)
                )
                address_entries = [dict(r) for r in rows] if rows else []
            else:
                address_entries = []
    else:
        async with CUSTOM_ADDRESSES_LOCK:
            addresses = list(CUSTOM_ADDRESSES)
        if addresses:
            if DB_BACKEND == "sqlite":
                placeholders = ",".join(["?"]*len(addresses))
                rows = await db_fetchall(
                    f"SELECT address, flag FROM custom_addresses WHERE address IN ({placeholders})",
                    f"SELECT address, flag FROM custom_addresses WHERE address = ANY($1)",
                    tuple(addresses)
                )
            else:
                rows = await db_fetchall("", "SELECT address, flag FROM custom_addresses WHERE address = ANY($1)", (addresses,))
            flag_map = {r["address"]: r.get("flag", "") for r in rows}
        else:
            flag_map = {}
        address_entries = [{"address": a, "flag": flag_map.get(a, ""), "name": "", "sort_number": 0} for a in addresses]

    for entry in address_entries:
        if '/' in entry["address"]:
            entry["address"] = entry["address"].split('/')[0]

    used_str = f"Used: {round(link['used_bytes']/1_073_741_824,2)} GB"
    limit_str = f"{round(link['limit_bytes']/1_073_741_824,2)} GB" if link['limit_bytes'] else "∞"
    expiry_str = "Never"
    if link.get("expires_at"):
        exp = parse_expires_at(link["expires_at"])
        if exp:
            days_left = max(0, (exp - datetime.now(timezone.utc)).days)
            expiry_str = f"{days_left} Days Left"

    proxies = []
    fragment_str = link.get("fragment", "")
    fragment_obj = parse_fragment_for_clash(fragment_str) if fragment_str else None
    naming_mode = link.get("naming_mode", "default")
    tfo = link.get("tfo", False)
    ech_enabled = link.get("ech_enabled", False)
    ech_sni = link.get("ech_sni", "")
    ech_doh = link.get("ech_doh", "")
    allow_insecure = link.get("allow_insecure", False) or request.query_params.get("insecure", "false").lower() == "true"
    random_path = link.get("random_path", False)
    flag_emoji_link = code_to_flag(link.get("flag", ""))
    smux_enabled = link.get("smux_enabled", False)
    fingerprint = link.get("fingerprint", "chrome")
    alpn = link.get("alpn", "http/1.1")
    if not fingerprint or fingerprint.lower() == "none":
        fingerprint = None
    if not alpn:
        alpn = None
    port = link.get("port", 443)

    for i, entry in enumerate(address_entries):
        addr = entry["address"]
        flag_code = entry.get("flag", "")
        addr_flag_emoji = code_to_flag(flag_code) if flag_code else ""
        if naming_mode == "short":
            if entry.get("name"):
                name = f"{addr_flag_emoji} {entry['name']}" if addr_flag_emoji else entry["name"]
            else:
                name = f"SXP {i+1}"
                if addr_flag_emoji:
                    name = f"{addr_flag_emoji} SXP {i+1}"
                elif flag_emoji_link:
                    name = f"{flag_emoji_link} SXP {i+1}"
        else:
            if entry.get("name"):
                name = entry["name"]
                if addr_flag_emoji:
                    name = f"{addr_flag_emoji} {name}"
                elif flag_emoji_link:
                    name = f"{flag_emoji_link} {name}"
            else:
                name = f"SulgX-{link['label']}-Server{i+1}"
                if addr_flag_emoji:
                    name = f"{addr_flag_emoji} {name}"
                elif flag_emoji_link:
                    name = f"{flag_emoji_link} {name}"

        path = get_effective_path(link).replace("{uid}", uid)
        if random_path:
            path = "/" + secrets.token_hex(4) + path

        proxy = {
            "name": name,
            "type": "vless",
            "server": addr,
            "port": port,
            "uuid": uid,
            "network": "ws",
            "ws-opts": {
                "path": path,
                "headers": {"Host": link.get("custom_host") or domain}
            },
            "tls": True,
            "sni": link.get("custom_sni") or domain,
            "skip-cert-verify": allow_insecure,
            "packet-encoding": "xudp",
            "udp": True
        }
        if fingerprint:
            proxy["client-fingerprint"] = fingerprint
        if alpn:
            proxy["alpn"] = [alpn]

        custom_host = link.get("custom_host")
        if custom_host and custom_host != domain:
            proxy["servername"] = custom_host
        if tfo:
            proxy["tfo"] = True
        if ech_enabled and ech_sni:
            proxy["ech"] = {"enable": True, "sni": ech_sni}
            if ech_doh:
                proxy["ech"]["doh"] = ech_doh
        if fragment_obj:
            proxy["fragment"] = fragment_obj
        if smux_enabled:
            proxy["smux"] = {
                "enabled": True,
                "protocol": "smux",
                "max-connections": 5,
                "min-streams": 4,
                "max-streams": 0
            }
        proxies.append(proxy)

    proxy_names = [p["name"] for p in proxies]
    proxy_groups = [
        {
            "name": "🚀 Select",
            "type": "select",
            "proxies": ["♻️ Auto", "DIRECT"] + proxy_names
        },
        {
            "name": "♻️ Auto",
            "type": "url-test",
            "proxies": proxy_names,
            "url": "http://www.gstatic.com/generate_204",
            "interval": 300,
            "tolerance": 50
        }
    ]

    clash_config = {
        "mixed-port": 7890,
        "mode": "rule",
        "log-level": "info",
        "dns": {
            "enable": True,
            "nameserver": ["https://dns.alidns.com/dns-query", "https://doh.pub/dns-query"],
            "fallback": ["https://dns.cloudflare.com/dns-query", "https://dns.google/dns-query"],
            "enhanced-mode": "fake-ip"
        },
        "proxies": proxies,
        "proxy-groups": proxy_groups,
        "rules": [
            "DOMAIN-SUFFIX,ir,DIRECT",
            "GEOIP,IR,DIRECT",
            "MATCH,🚀 Select"
        ]
    }

    if request.query_params.get("adblock", "0") == "1":
        clash_config["rule-providers"] = {
            "category-ads-all": {
                "type": "http",
                "format": "text",
                "behavior": "domain",
                "path": "./ruleset/ads.txt",
                "interval": 86400,
                "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/category-ads-all.txt"
            }
        }
        clash_config["rules"] = ["RULE-SET,category-ads-all,REJECT"] + clash_config["rules"]

    def none_filter(d):
        return {k: v for k, v in d.items() if v is not None}
    clean_config = {k: none_filter(v) if isinstance(v, dict) else v for k, v in clash_config.items()}
    yaml_content = yaml.dump(clean_config, allow_unicode=True, default_flow_style=False)
    return Response(content=yaml_content, media_type="text/plain")


@app.get("/sub/{uid}/singbox")
async def singbox_subscription(uid: str, request: Request):
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if not link or not link["active"]:
            raise HTTPException(status_code=404, detail="link not found or disabled")
        link = dict(link)

    domain = get_domain(request)
    ip_profile_id = link.get("ip_profile_id")
    if ip_profile_id:
        async with IP_PROFILES_LOCK:
            if ip_profile_id in IP_PROFILES:
                rows = await db_fetchall(
                    "SELECT address, flag, name, sort_number FROM profile_addresses WHERE profile_id = ? ORDER BY sort_number ASC",
                    "SELECT address, flag, name, sort_number FROM profile_addresses WHERE profile_id = $1 ORDER BY sort_number ASC",
                    (ip_profile_id,)
                )
                address_entries = [dict(r) for r in rows] if rows else []
            else:
                address_entries = []
    else:
        async with CUSTOM_ADDRESSES_LOCK:
            addresses = list(CUSTOM_ADDRESSES)
        if addresses:
            if DB_BACKEND == "sqlite":
                placeholders = ",".join(["?"]*len(addresses))
                rows = await db_fetchall(
                    f"SELECT address, flag FROM custom_addresses WHERE address IN ({placeholders})",
                    f"SELECT address, flag FROM custom_addresses WHERE address = ANY($1)",
                    tuple(addresses)
                )
            else:
                rows = await db_fetchall("", "SELECT address, flag FROM custom_addresses WHERE address = ANY($1)", (addresses,))
            flag_map = {r["address"]: r.get("flag", "") for r in rows}
        else:
            flag_map = {}
        address_entries = [{"address": a, "flag": flag_map.get(a, ""), "name": "", "sort_number": 0} for a in addresses]

    for entry in address_entries:
        if '/' in entry["address"]:
            entry["address"] = entry["address"].split('/')[0]

    used_str = f"Used: {round(link['used_bytes']/1_073_741_824,2)} GB"
    limit_str = f"{round(link['limit_bytes']/1_073_741_824,2)} GB" if link['limit_bytes'] else "∞"
    expiry_str = "Never"
    if link.get("expires_at"):
        exp = parse_expires_at(link["expires_at"])
        if exp:
            days_left = max(0, (exp - datetime.now(timezone.utc)).days)
            expiry_str = f"{days_left} Days Left"

    outbounds = []
    naming_mode = link.get("naming_mode", "default")
    tfo = link.get("tfo", False)
    ech_enabled = link.get("ech_enabled", False)
    ech_sni = link.get("ech_sni", "")
    ech_doh = link.get("ech_doh", "")
    allow_insecure = link.get("allow_insecure", False) or request.query_params.get("insecure", "false").lower() == "true"
    random_path = link.get("random_path", False)
    smux_enabled = link.get("smux_enabled", False)

    fingerprint = link.get("fingerprint", "chrome")
    alpn = link.get("alpn", "http/1.1")
    if not fingerprint or fingerprint.lower() == "none":
        fingerprint = None
    if not alpn:
        alpn = None

    port = link.get("port", 443)

    for i, entry in enumerate(address_entries):
        addr = entry["address"]
        if naming_mode == "short":
            if entry.get("name"):
                name = entry["name"]
            else:
                name = f"SXP {i+1}"
        else:
            if entry.get("name"):
                name = entry["name"]
            else:
                name = f"SulgX-{link['label']}-Server{i+1}"

        path = get_effective_path(link).replace("{uid}", uid)
        if random_path:
            path = "/" + secrets.token_hex(4) + path

        proxy = {
            "type": "vless",
            "tag": name,
            "server": addr,
            "server_port": port,
            "uuid": uid,
            "packet_encoding": "xudp",
            "tls": {
                "enabled": True,
                "server_name": link.get("custom_sni") or domain,
                "insecure": allow_insecure,
            },
            "transport": {
                "type": "ws",
                "path": path,
                "headers": {"Host": link.get("custom_host") or domain}
            }
        }

        if fingerprint:
            proxy["tls"]["utls"] = {
                "enabled": True,
                "fingerprint": fingerprint
            }
        else:
            proxy["tls"]["utls"] = {"enabled": False}

        if tfo:
            proxy["tcp_fast_open"] = True
        if ech_enabled and ech_sni:
            proxy["tls"]["ech"] = {"enabled": True, "sni": ech_sni}
            if ech_doh:
                proxy["tls"]["ech"]["doh"] = ech_doh
        if smux_enabled:
            proxy["multiplex"] = {
                "enabled": True,
                "protocol": "smux",
                "max_connections": 5,
                "min_streams": 4,
                "max_streams": 0
            }
        outbounds.append(proxy)

    proxy_tags = [o["tag"] for o in outbounds]

    full_config = {
        "dns": {
            "servers": [
                {"tag": "dns-remote", "address": "https://1.1.1.1/dns-query", "detour": "🚀 Select"},
                {"tag": "dns-direct", "address": "h3://dns.alidns.com/dns-query", "detour": "direct"}
            ],
            "rules": [
                {"rule_set": "geosite-ir", "server": "dns-direct"},
                {"rule_set": "geosite-category-ads-all", "action": "reject"}
            ],
            "final": "dns-remote"
        },
        "inbounds": [
            {
                "type": "tun",
                "tag": "tun-in",
                "address": ["172.19.0.1/30"],
                "mtu": 9000,
                "auto_route": True,
                "strict_route": True,
                "stack": "mixed"
            },
            {
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "127.0.0.1",
                "listen_port": 2080
            }
        ],
        "outbounds": [
            {
                "type": "selector",
                "tag": "🚀 Select",
                "outbounds": ["♻️ Auto", "direct"] + proxy_tags
            },
            {
                "type": "urltest",
                "tag": "♻️ Auto",
                "outbounds": proxy_tags,
                "url": "https://www.gstatic.com/generate_204",
                "interval": "30s"
            },
            {
                "type": "direct",
                "tag": "direct"
            }
        ] + outbounds,
        "route": {
            "rules": [
                {"clash_mode": "Direct", "outbound": "direct"},
                {"protocol": "dns", "action": "hijack-dns"},
                {"rule_set": "geosite-category-ads-all", "action": "reject"},
                {"rule_set": "geosite-ir", "outbound": "direct"},
                {"rule_set": "geoip-ir", "outbound": "direct"},
                {"ip_is_private": True, "outbound": "direct"},
                {"network": "udp", "action": "reject"}
            ],
            "rule_set": [
                {
                    "type": "remote",
                    "tag": "geosite-ir",
                    "format": "binary",
                    "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-ir.srs",
                    "download_detour": "direct"
                },
                {
                    "type": "remote",
                    "tag": "geosite-category-ads-all",
                    "format": "binary",
                    "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-category-ads-all.srs",
                    "download_detour": "direct"
                },
                {
                    "type": "remote",
                    "tag": "geoip-ir",
                    "format": "binary",
                    "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geoip-ir.srs",
                    "download_detour": "direct"
                }
            ],
            "auto_detect_interface": True,
            "final": "🚀 Select"
        },
        "experimental": {
            "cache_file": {"enabled": True},
            "clash_api": {
                "external_controller": "127.0.0.1:9090",
                "default_mode": "Rule"
            }
        }
    }

    return full_config


@app.get("/sub/{uid}/auto")
async def auto_subscription(uid: str, request: Request):
    ua = request.headers.get("user-agent", "").lower()
    if any(k in ua for k in ("clash.meta", "mihomo", "stash", "verge")):
        return await clash_subscription(uid, request)
    elif any(k in ua for k in ("sing-box", "singbox")):
        return await singbox_subscription(uid, request)
    else:
        return await user_subscription(uid, request)


def parse_fragment_for_clash(frag: str) -> Optional[Dict[str, str]]:
    if not frag:
        return None
    if frag == "tlshello":
        return {"packets": "tlshello", "interval": "10-20"}
    match = re.match(r'^(\d+)-(\d+)$', frag)
    if match:
        return {
            "length": f"{match.group(1)}-{match.group(2)}",
            "interval": "10-20"
        }
    return {"length": frag, "interval": "10-20"}


def parse_address_entry(entry: str) -> dict:
    parts = entry.strip().split('#', 1)
    ip = parts[0].strip()
    name = ""
    flag = ""
    sort_num = 0
    if len(parts) == 2:
        meta = parts[1].strip()
        meta_parts = meta.split('+')
        if meta_parts:
            name = meta_parts[0].strip()
        if len(meta_parts) > 1:
            flag = meta_parts[1].strip()
            if flag and len(flag) != 2:
                flag = ""
        if len(meta_parts) > 2:
            try:
                sort_num = int(meta_parts[2].strip())
            except ValueError:
                sort_num = 0
    return {"address": ip, "name": name, "flag": flag, "sort_number": sort_num}


async def generate_subscription_content(link: dict, uid: str, addresses: list, extra: dict = None, status: str = "active", server_domain: str = None) -> str:
    used = link["used_bytes"]; limit = link["limit_bytes"]
    usage_str = f"{_fmt_bytes(used)} / ∞" if limit == 0 else f"{_fmt_bytes(used)} / {_fmt_bytes(limit)}"
    secs_left = seconds_until_expiry(link.get("expires_at"))
    expiry_str = "∞" if secs_left is None else ("Expired" if secs_left == 0 else f"{secs_left//86400} Days Left")
    status_remark = ""
    if status == "quota_exceeded":
        status_remark = "🚫 Quota Exceeded"
    elif status == "expired":
        status_remark = "⏰ Expired"
    elif status == "blocked":
        status_remark = "🔒 Blocked"
    full_remark = f"📊 {usage_str} | ⏳ {expiry_str}"
    if status_remark:
        full_remark += f" | {status_remark}"
    flag_emoji = code_to_flag(link.get("flag", ""))
    if flag_emoji:
        full_remark = flag_emoji + " " + full_remark
    naming_mode = link.get("naming_mode", "default")

    address_entries = []
    if addresses and isinstance(addresses[0], dict):
        address_entries = addresses
    else:
        if addresses:
            if DB_BACKEND == "sqlite":
                placeholders = ",".join(["?"]*len(addresses))
                rows = await db_fetchall(
                    f"SELECT address, flag FROM custom_addresses WHERE address IN ({placeholders})",
                    f"SELECT address, flag FROM custom_addresses WHERE address = ANY($1)",
                    tuple(addresses)
                )
            else:
                rows = await db_fetchall("", "SELECT address, flag FROM custom_addresses WHERE address = ANY($1)", (addresses,))
            flag_map = {r["address"]: r.get("flag", "") for r in rows}
        else:
            flag_map = {}
        for addr in addresses:
            address_entries.append({
                "address": addr,
                "flag": flag_map.get(addr, ""),
                "name": "",
                "sort_number": 0
            })

    for entry in address_entries:
        if '/' in entry["address"]:
            entry["address"] = entry["address"].split('/')[0]

    status_node = generate_vless_link(uid, remark=full_remark, address="0.0.0.0", extra=extra, server_domain=server_domain)
    server_node = generate_vless_link(uid, remark=f"{flag_emoji}This Service is Free" if flag_emoji else "This Service is Free", extra=extra, server_domain=server_domain)
    links = [status_node, server_node]

    for i, entry in enumerate(address_entries):
        addr = entry["address"]
        flag_code = entry.get("flag", "")
        addr_flag_emoji = code_to_flag(flag_code) if flag_code else ""
        if naming_mode == "short":
            if entry.get("name"):
                remark = f"{addr_flag_emoji} {entry['name']}" if addr_flag_emoji else entry["name"]
            else:
                remark = f"SXP {i+1}"
                if addr_flag_emoji:
                    remark = f"{addr_flag_emoji} SXP {i+1}"
                elif flag_emoji:
                    remark = f"{flag_emoji} SXP {i+1}"
        else:
            if entry.get("name"):
                remark = entry["name"]
                if addr_flag_emoji:
                    remark = f"{addr_flag_emoji} {remark}"
                elif flag_emoji:
                    remark = f"{flag_emoji} {remark}"
            else:
                remark = f"SulgX-{link['label']}-Server {i+1}"
                if addr_flag_emoji:
                    remark = f"{addr_flag_emoji} {remark}"
                elif flag_emoji:
                    remark = f"{flag_emoji} {remark}"
        links.append(generate_vless_link(uid, remark=remark, address=addr, extra=extra, server_domain=server_domain))
    return "\n".join(links)

def _fmt_bytes(b: int) -> str:
    if b >= 1_073_741_824: return f"{b/1_073_741_824:.1f}GB"
    if b >= 1_048_576: return f"{b/1_048_576:.1f}MB"
    return f"{b/1024:.1f}KB"

# -------------------- Scanner WebSocket --------------------
@app.websocket("/ws/scanner")
async def scanner_ws(websocket: WebSocket):
    if STEALTH_MODE:
        await websocket.close(code=1008, reason="disabled")
        return
    await websocket.accept()
    tasks = []
    try:
        data = await websocket.receive_json()
        items = data.get("ips", [])
        if not isinstance(items, list) or len(items) == 0:
            await websocket.close()
            return
        max_ips = 256
        max_row = await db_fetchone("SELECT value FROM settings WHERE key='max_scan_ips'", "SELECT value FROM settings WHERE key='max_scan_ips'")
        if max_row and max_row["value"]:
            try: max_ips = int(max_row["value"])
            except: pass
        if len(items) > max_ips:
            await websocket.send_json({"done": True, "error": f"Maximum {max_ips} IPs allowed."})
            return
        timeout_str = "4"
        row = await db_fetchone("SELECT value FROM settings WHERE key='scanner_timeout'", "SELECT value FROM settings WHERE key='scanner_timeout'")
        if row and row["value"]:
            timeout_str = row["value"]
        try:
            timeout = float(timeout_str)
            if timeout <= 0: timeout = 4
        except:
            timeout = 4
        sem = asyncio.Semaphore(20)
        async def scan_one(item):
            async with sem:
                ip_str = str(item).strip()
                try:
                    ip_obj = ipaddress.ip_address(ip_str)
                    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                        await websocket.send_json({"ip": ip_str, "ok": False, "latency": None})
                        return
                except ValueError:
                    pass
                try:
                    start = time.time()
                    try:
                        async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
                            resp = await client.get(f"https://{ip_str}:443", follow_redirects=True)
                        tcp_latency = round((time.time() - start) * 1000)
                        start2 = time.time()
                        async with httpx.AsyncClient(timeout=timeout, verify=False) as client2:
                            await client2.get(f"https://{ip_str}:443", follow_redirects=True)
                        https_latency = round((time.time() - start2) * 1000)
                        result = {"ip": ip_str, "ok": True, "tcp_latency": tcp_latency, "https_latency": https_latency}
                    except:
                        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip_str, 443), timeout=timeout)
                        latency = round((time.time() - start) * 1000)
                        writer.close()
                        result = {"ip": ip_str, "ok": True, "tcp_latency": latency, "https_latency": None}
                except Exception:
                    result = {"ip": ip_str, "ok": False, "latency": None}
                await websocket.send_json(result)
        tasks = [asyncio.create_task(scan_one(item)) for item in items]
        await asyncio.gather(*tasks)
        await websocket.send_json({"done": True})
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.error(f"Scanner WS error: {e}")
        error_logs.append({"time": datetime.now(timezone.utc).isoformat(), "error": f"Scanner WS: {e}", "type": "Scanner"})
    finally:
        for t in tasks:
            if not t.done():
                t.cancel()
        try:
            await websocket.close()
        except Exception:
            pass

@app.post("/api/ip-profiles/from-scanner")
@limiter.limit("5/minute")
async def create_profile_from_scanner(request: Request, _=Depends(require_auth)):
    body = await request.json()
    name = body.get("name", "").strip()
    raw_ips = body.get("ips", [])
    if not name or not raw_ips:
        raise HTTPException(status_code=400, detail="Name and IPs required")

    seen = set()
    clean_ips = []
    for ip in raw_ips:
        ip = ip.strip()
        if ip and validate_address(ip) and ip not in seen:
            seen.add(ip)
            clean_ips.append(ip)

    if not clean_ips:
        raise HTTPException(status_code=400, detail="No valid IP addresses provided")

    pid = str(uuid_lib.uuid4())

    flags = {}
    async def resolve_single(ip: str):
        try:
            flag = await fetch_ip_flag(ip)
        except Exception:
            flag = ""
        return ip, flag

    sem = asyncio.Semaphore(5)
    async def limited_resolve(ip):
        async with sem:
            return await resolve_single(ip)

    tasks = [asyncio.create_task(limited_resolve(ip)) for ip in clean_ips]
    for coro in asyncio.as_completed(tasks):
        ip, flag = await coro
        flags[ip] = flag

    if DB_BACKEND == "sqlite":
        async with db_lock:
            await db_execute("INSERT INTO ip_profiles (id, name) VALUES (?,?)", "", (pid, name))
            await db_conn.executemany(
                "INSERT INTO profile_addresses (profile_id, address, flag) VALUES (?,?,?)",
                [(pid, ip, flags[ip]) for ip in clean_ips]
            )
            await db_conn.commit()
    else:
        async with pg_pool.acquire() as conn:
            await conn.execute("INSERT INTO ip_profiles (id, name) VALUES ($1,$2)", pid, name)
            await conn.executemany(
                "INSERT INTO profile_addresses (profile_id, address, flag) VALUES ($1,$2,$3)",
                [(pid, ip, flags[ip]) for ip in clean_ips]
            )

    async with IP_PROFILES_LOCK:
        IP_PROFILES[pid] = {
            "name": name,
            "addresses": clean_ips,
        }
        async with IP_FLAG_CACHE_LOCK:
            for ip, flag in flags.items():
                if flag:
                    IP_FLAG_CACHE[ip] = flag

    return {
        "ok": True,
        "id": pid,
        "address_count": len(clean_ips),
        "flags_resolved": sum(1 for f in flags.values() if f)
    }


@app.post("/api/links/{uid}/test")
async def test_inbound(uid: str, request: Request, _=Depends(require_auth)):
    async with LINKS_LOCK:
        link = LINKS.get(uid)
    if not link:
        raise HTTPException(status_code=404, detail="Link not found")

    ip_profile_id = link.get("ip_profile_id")
    if ip_profile_id:
        async with IP_PROFILES_LOCK:
            profile = IP_PROFILES.get(ip_profile_id)
            addresses = profile["addresses"] if profile else []
    else:
        async with CUSTOM_ADDRESSES_LOCK:
            addresses = list(CUSTOM_ADDRESSES)

    max_test = min(
        int(request.query_params.get("count", "10")),
        len(addresses)
    )
    test_addresses = addresses[:max_test]

    async def check_single(addr: str):
        try:
            host = addr.split(':')[0]
            start = time.time()
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, 443), timeout=5
            )
            latency = round((time.time() - start) * 1000)
            writer.close()
            return {"address": addr, "reachable": True, "latency_ms": latency}
        except Exception:
            return {"address": addr, "reachable": False, "latency_ms": None}

    results = await asyncio.gather(*(check_single(addr) for addr in test_addresses))

    reachable = [r for r in results if r["reachable"]]
    unreachable = [r for r in results if not r["reachable"]]
    reachable.sort(key=lambda x: x["latency_ms"] or float("inf"))
    sorted_results = reachable + unreachable

    return {
        "tested": len(test_addresses),
        "reachable_count": len(reachable),
        "results": sorted_results
    }
# ═══════════════════════════════════════════════════════════════
# XHTTP session management
# ═══════════════════════════════════════════════════════════════

RELAY_BUF = 512 * 1024
XHTTP_BUF = 65536
DOWNLINK_QUEUE_MAX = 256
SESSION_IDLE_TIMEOUT = 30
REAPER_INTERVAL = 10
TCP_CONNECT_TIMEOUT = 10.0

xhttp_sessions: dict = {}
XHTTP_LOCK = asyncio.Lock()

async def _teardown_xhttp(session_id: str):
    async with XHTTP_LOCK:
        sess = xhttp_sessions.pop(session_id, None)
    if not sess:
        return
    sess["closed"] = True
    for t in ("uplink_task", "downlink_task"):
        task = sess.get(t)
        if task and not task.done():
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
    writer = sess.get("writer")
    if writer:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
    down_q = sess.get("down_q")
    if down_q:
        while True:
            try:
                down_q.put_nowait(None)
                break
            except asyncio.QueueFull:
                try:
                    down_q.get_nowait()
                except asyncio.QueueEmpty:
                    pass
    connections.pop(sess.get("conn_id"), None)
    logger.info(f"XHTTP session [{session_id[:8]}] closed")


async def _xhttp_reaper():
    while True:
        await asyncio.sleep(REAPER_INTERVAL)
        now = time.time()
        async with XHTTP_LOCK:
            stale = [
                sid for sid, s in xhttp_sessions.items()
                if (now - s["last_seen"] > SESSION_IDLE_TIMEOUT and not s.get("tcp_open"))
                or (now - s["last_seen"] > 2 * SESSION_IDLE_TIMEOUT)
            ]
        for sid in stale:
            await _teardown_xhttp(sid)

_xhttp_reaper_started = False

def ensure_xhttp_reaper():
    global _xhttp_reaper_started
    if not _xhttp_reaper_started:
        asyncio.create_task(_xhttp_reaper())
        _xhttp_reaper_started = True


async def _open_tcp_from_header(first_chunk: bytes):
    command, address, port, payload = await parse_vless_header_extended(first_chunk)
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(address, port), timeout=TCP_CONNECT_TIMEOUT
    )
    tune_socket(writer)
    if payload:
        writer.write(payload)
        await writer.drain()
    return reader, writer, address, port


async def parse_vless_header(first_chunk: bytes):
    if len(first_chunk) < 24:
        raise ValueError("VLESS header chunk too small for parsing")
    pos = 1 + 16
    addon_len = first_chunk[pos]
    pos += 1 + addon_len
    if len(first_chunk) < pos + 3:
        raise ValueError("Malformed VLESS header structure")
    command = first_chunk[pos]
    pos += 1
    port = int.from_bytes(first_chunk[pos:pos+2], "big")
    pos += 2
    addr_type = first_chunk[pos]
    pos += 1
    if addr_type == 1:
        if len(first_chunk) < pos + 4:
            raise ValueError("Incomplete IPv4 address bytes")
        addr_bytes = first_chunk[pos:pos+4]
        pos += 4
        address = ".".join(str(b) for b in addr_bytes)
    elif addr_type == 2:
        if len(first_chunk) < pos + 1:
            raise ValueError("Missing domain name length indicator")
        domain_len = first_chunk[pos]
        pos += 1
        if len(first_chunk) < pos + domain_len:
            raise ValueError("Incomplete domain name bytes")
        address = first_chunk[pos:pos+domain_len].decode("utf-8", errors="ignore")
        pos += domain_len
    elif addr_type == 3:
        if len(first_chunk) < pos + 16:
            raise ValueError("Incomplete IPv6 address bytes")
        addr_bytes = first_chunk[pos:pos+16]
        pos += 16
        address = ":".join(f"{addr_bytes[i]:02x}{addr_bytes[i+1]:02x}" for i in range(0, 16, 2))
    else:
        raise ValueError(f"Unsupported VLESS address type identifier: {addr_type}")
    return command, address, port, first_chunk[pos:]


async def check_quota(uid: str, extra_bytes: int) -> bool:
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if not link or not link["active"]:
            return False
        if link["limit_bytes"] == 0:
            return True
        return (link["used_bytes"] + extra_bytes) <= link["limit_bytes"]


async def add_usage(uid: str, n: int):
    async with LINKS_LOCK:
        if uid in LINKS:
            link = LINKS[uid]
            link["used_bytes"] += n
            limit = link["limit_bytes"]
            if limit > 0 and link["used_bytes"] >= limit * 0.9 and (link["used_bytes"] - n) < limit * 0.9:
                log_event("Warning", f"Inbound {link['label']} ({uid}) has used over 90% of quota")
                await notify_telegram_event("quota_90", link["label"], uid)
            elif limit > 0 and link["used_bytes"] >= limit * 0.8 and (link["used_bytes"] - n) < limit * 0.8:
                log_event("Warning", f"Inbound {link['label']} ({uid}) has used over 80% of quota")

async def notify_telegram_event(event: str, label: str, uid: str):
    notif_row = await db_fetchone("SELECT value FROM settings WHERE key='telegram_notify_enabled'", "SELECT value FROM settings WHERE key='telegram_notify_enabled'")
    if notif_row and notif_row["value"] != "1":
        return
    token_row = await db_fetchone("SELECT value FROM settings WHERE key = 'tg_bot_token'", "SELECT value FROM settings WHERE key = 'tg_bot_token'")
    chat_row = await db_fetchone("SELECT value FROM settings WHERE key = 'tg_chat_id'", "SELECT value FROM settings WHERE key = 'tg_chat_id'")
    if not token_row or not chat_row or not token_row["value"] or not chat_row["value"]:
        return
    lang = 'en'
    lang_row = await db_fetchone("SELECT value FROM settings WHERE key='telegram_lang'", "SELECT value FROM settings WHERE key='telegram_lang'")
    if lang_row and lang_row["value"] == 'fa':
        lang = 'fa'
    templates_key = f'telegram_templates_{lang}'
    tmpl_row = await db_fetchone(f"SELECT value FROM settings WHERE key='{templates_key}'", f"SELECT value FROM settings WHERE key='{templates_key}'")
    templates = {}
    if tmpl_row and tmpl_row["value"]:
        try: templates = json.loads(tmpl_row["value"])
        except: pass
    if lang == 'fa':
        default_msg = f"رویداد: {event} برای {label}"
    else:
        default_msg = f"Event: {event} for {label}"
    msg = templates.get(event, default_msg)
    msg = msg.replace("{label}", label).replace("{uid}", uid)
    prefix = f"/{PANEL_PREFIX}" if PANEL_PREFIX else ""
    panel_url = f"https://{get_domain()}{prefix}/panel"
    msg += f'\n\n<a href="{panel_url}">Open SulgX Panel</a>'
    url = f"https://api.telegram.org/bot{token_row['value']}/sendMessage"
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            await client.post(url, json={"chat_id": chat_row["value"], "text": msg, "parse_mode": "HTML"})
    except: pass

async def ws_to_tcp(websocket, writer, conn_id, link_uid, gate=None):
    try:
        while True:
            msg = await websocket.receive()
            if msg["type"] == "websocket.disconnect": break
            data = msg.get("bytes") or (msg.get("text") or "").encode()
            if not data: continue
            size = len(data)
            if gate:
                await gate.add(size)
                if not await gate.check():
                    try: await websocket.send_text("Quota exceeded")
                    except: pass
                    await websocket.close(code=1008, reason="quota exceeded")
                    log_event("Tunnel", f"Quota exceeded for {link_uid}")
                    break
            else:
                if not await check_quota(link_uid, size):
                    try: await websocket.send_text("Quota exceeded")
                    except: pass
                    await websocket.close(code=1008, reason="quota exceeded")
                    log_event("Tunnel", f"Quota exceeded for {link_uid}")
                    break
                await add_usage(link_uid, size)
            stats["total_bytes"] += size; stats["upload_bytes"] += size
            async with connections_lock:
                if conn_id in connections:
                    connections[conn_id]["bytes"] += size
            local_now = datetime.now(timezone.utc) + timedelta(hours=TIMEZONE_OFFSET)
            hour = local_now.strftime("%Y-%m-%d %H:00")
            day = local_now.strftime("%Y-%m-%d")
            await add_traffic_to_buffer(hour, day, size, link_uid)
            try:
                writer.write(data); await writer.drain()
            except Exception: break
    except WebSocketDisconnect: pass
    except Exception as e:
        logger.error(f"ws_to_tcp error {conn_id}: {e}", exc_info=True)
        error_logs.append({"time": datetime.now(timezone.utc).isoformat(), "error": f"ws_to_tcp {conn_id}: {e}", "type": "Tunnel"})
    finally:
        try:
            if writer and not writer.is_closing(): writer.write_eof()
        except Exception: pass

async def tcp_to_ws(websocket, reader, conn_id, link_uid, gate=None):
    first = True
    try:
        while True:
            data = await reader.read(RELAY_BUF)
            if not data: break
            size = len(data)
            if gate:
                await gate.add(size)
                if not await gate.check():
                    try: await websocket.send_text("Quota exceeded")
                    except: pass
                    await websocket.close(code=1008, reason="quota exceeded")
                    log_event("Tunnel", f"Quota exceeded for {link_uid}")
                    break
            else:
                if not await check_quota(link_uid, size):
                    try: await websocket.send_text("Quota exceeded")
                    except: pass
                    await websocket.close(code=1008, reason="quota exceeded")
                    log_event("Tunnel", f"Quota exceeded for {link_uid}")
                    break
                await add_usage(link_uid, size)
            stats["total_bytes"] += size; stats["download_bytes"] += size
            async with connections_lock:
                if conn_id in connections:
                    connections[conn_id]["bytes"] += size
            local_now = datetime.now(timezone.utc) + timedelta(hours=TIMEZONE_OFFSET)
            hour = local_now.strftime("%Y-%m-%d %H:00")
            day = local_now.strftime("%Y-%m-%d")
            await add_traffic_to_buffer(hour, day, size, link_uid)
            try:
                await websocket.send_bytes((b"\x00\x00" + data) if first else data)
                first = False
            except Exception: break
    except Exception as e:
        logger.error(f"tcp_to_ws error {conn_id}: {e}", exc_info=True)
        error_logs.append({"time": datetime.now(timezone.utc).isoformat(), "error": f"tcp_to_ws {conn_id}: {e}", "type": "Tunnel"})

async def udp_relay(websocket, udp_sock, conn_id, uid):
    try:
        while True:
            msg = await websocket.receive()
            if msg["type"] == "websocket.disconnect": break
            data = msg.get("bytes") or (msg.get("text") or "").encode()
            if not data: continue
            if not await check_quota(uid, len(data)):
                await websocket.close(code=1008, reason="quota exceeded")
                break
            stats["total_bytes"] += len(data); stats["upload_bytes"] += len(data)
            await add_usage(uid, len(data))
            try:
                udp_sock.send(data)
            except Exception:
                break
    except WebSocketDisconnect:
        pass
    except Exception as e:
        error_logs.append({"time": datetime.now(timezone.utc).isoformat(),
                           "error": f"UDP relay error {conn_id}: {e}", "type": "Tunnel"})

async def udp_from_socket(websocket, udp_sock, conn_id, uid):
    first = True
    try:
        while True:
            data, addr = await asyncio.get_event_loop().run_in_executor(None, udp_sock.recvfrom, 65535)
            if not data: break
            if not await check_quota(uid, len(data)):
                await websocket.close(code=1008, reason="quota exceeded")
                break
            stats["total_bytes"] += len(data); stats["download_bytes"] += len(data)
            await add_usage(uid, len(data))
            try:
                payload = (b"\x00\x00" + data) if first else data
                first = False
                await websocket.send_bytes(payload)
            except Exception:
                break
    except Exception as e:
        error_logs.append({"time": datetime.now(timezone.utc).isoformat(),
                           "error": f"UDP from socket error {conn_id}: {e}", "type": "Tunnel"})

def get_client_ip(websocket: WebSocket) -> str:
    forwarded = websocket.headers.get("x-forwarded-for")
    if forwarded: return forwarded.split(",")[0].strip()
    if websocket.client: return websocket.client.host
    return "unknown"

@app.websocket("/ws/{uuid}")
async def websocket_tunnel(websocket: WebSocket, uuid: str):
    await websocket.accept()
    logger.info(f"WS accepted {uuid}")
    writer = None; conn_id = None; client_ip = get_client_ip(websocket)
    udp_sock = None
    try:
        async with LINKS_LOCK:
            link = LINKS.get(uuid)
            if not link or not link["active"]:
                await websocket.close(code=1008, reason="not found or disabled")
                log_event("Tunnel", f"Inactive/not found uuid {uuid}", ip=client_ip)
                return
            max_conn = link.get("max_connections", 0)
        expires = parse_expires_at(link.get("expires_at"))
        if expires and expires < datetime.now(timezone.utc):
            await websocket.close(code=1008, reason="expired")
            log_event("Tunnel", f"Expired uuid {uuid}", ip=client_ip)
            return
        if max_conn > 0:
            if await count_connections_for_link(uuid) >= max_conn:
                await websocket.close(code=1008, reason="connection limit")
                log_event("Tunnel", f"Connection limit reached for {uuid}", ip=client_ip)
                return
        if not is_ip_allowed(link, uuid, client_ip):
            await websocket.close(code=1008, reason="ip limit")
            log_event("Tunnel", f"IP limit reached for {uuid} from {client_ip}", ip=client_ip)
            return
        first_msg = await asyncio.wait_for(websocket.receive(), timeout=15.0)
        if first_msg["type"] == "websocket.disconnect": return
        first_chunk = first_msg.get("bytes") or (first_msg.get("text") or "").encode()
        if not first_chunk: return

        if len(first_chunk) < 24:
            await websocket.close(code=1002, reason="invalid request")
            return

        try:
            command, address, port, initial_payload = await parse_vless_header_extended(first_chunk)
        except ValueError as e:
            now = time.time()
            key = f"badhdr:{client_ip}"
            last_ts, _ = _tunnel_error_suppress.get(key, (0, 0))
            if now - last_ts > 30:
                _tunnel_error_suppress[key] = (now, 0)
                logger.warning(f"Invalid VLESS header from {client_ip}: {e}")
                error_logs.append({
                    "time": datetime.now(timezone.utc).isoformat(),
                    "error": f"Invalid header from {client_ip}: {e}",
                    "type": "Tunnel"
                })
            await websocket.close(code=1002, reason="invalid header")
            return

        if is_domain_blocked(address):
            await websocket.close(code=1008, reason="blocked domain")
            return

        # ---------- SSRF Protection (added) ----------
        try:
            ip_addr = await resolve_domain_to_ip(address)
            if ip_addr:
                ip_obj = ipaddress.ip_address(ip_addr)
                if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                    await websocket.close(code=1008, reason="access to private network denied")
                    log_event("Tunnel", f"Blocked SSRF attempt to {address} from {client_ip}", ip=client_ip)
                    return
        except ValueError:
            pass
        # -------------------------------------------

        conn_id = secrets.token_urlsafe(8)
        now = time.time()
        async with connections_lock:
            connections[conn_id] = {
                "uuid": uuid, "ip": client_ip,
                "connected_at": datetime.now(timezone.utc).isoformat(),
                "bytes": 0, "last_active": now
            }
            connection_sockets[conn_id] = websocket
            link_ip_map[uuid].add(client_ip)
        stats["total_requests"] += 1

        if command == 2:
            loop = asyncio.get_event_loop()
            if ':' in address:
                udp_sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            else:
                udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_sock.setblocking(False)
            up_task = asyncio.create_task(udp_relay(websocket, udp_sock, conn_id, uuid))
            down_task = asyncio.create_task(udp_from_socket(websocket, udp_sock, conn_id, uuid))
            done, pending = await asyncio.wait({up_task, down_task}, return_when=asyncio.FIRST_COMPLETED)
            for t in pending: t.cancel()
        else:
            gate = QuotaGate(uuid)
            if initial_payload:
                await gate.add(len(initial_payload))
                if not await gate.check():
                    await websocket.close(code=1008, reason="quota exceeded")
                    return
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(address, port), timeout=10.0)
            tune_socket(writer)
            if initial_payload:
                writer.write(initial_payload)
                await writer.drain()
            up_task = asyncio.create_task(ws_to_tcp(websocket, writer, conn_id, uuid, gate))
            down_task = asyncio.create_task(tcp_to_ws(websocket, reader, conn_id, uuid, gate))
            done, pending = await asyncio.wait({up_task, down_task}, return_when=asyncio.FIRST_COMPLETED)
            for t in pending: t.cancel()
    except WebSocketDisconnect: pass
    except Exception as exc:
        stats["total_errors"] += 1
        error_logs.append({"time": datetime.now(timezone.utc).isoformat(),
                           "error": f"Tunnel {uuid}: {exc}", "type": "WebSocket"})
        logger.exception("WS error")
    finally:
        if writer:
            try: writer.close(); await writer.wait_closed()
            except: pass
        if udp_sock:
            try: udp_sock.close()
            except: pass
        if conn_id:
            async with connections_lock:
                info = connections.pop(conn_id, None)
                connection_sockets.pop(conn_id, None)
                if info:
                    uid = info.get("uuid"); ip = info.get("ip")
                    if uid and ip:
                        if not any(c.get("uuid")==uid and c.get("ip")==ip for c in connections.values()):
                            if uid in link_ip_map:
                                link_ip_map[uid].discard(ip)
                                if not link_ip_map[uid]: link_ip_map.pop(uid, None)

@app.websocket("/{rand}/ws/{uuid}")
async def websocket_tunnel_random(websocket: WebSocket, rand: str, uuid: str):
    await websocket_tunnel(websocket, uuid)

# ═══════════════════════════════════════════════════════════════
# XHTTP Endpoints – Unified handshake via down_q, no separate queue
# ═══════════════════════════════════════════════════════════════
from starlette.types import Scope, Receive, Send

class RawDownlinkResponse:
    def __init__(self, session_id: str, sess: dict):
        self.session_id = session_id
        self.sess = sess

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        headers = [
            (b"content-type", b"text/event-stream"),
            (b"cache-control", b"no-store"),
            (b"x-accel-buffering", b"no"),
            (b"connection", b"close"),
            (b"access-control-allow-origin", b"*"),
            (b"access-control-allow-methods", b"GET, POST"),
        ]
        await send({
            "type": "http.response.start",
            "status": 200,
            "headers": headers,
        })

        while not self.sess.get("tcp_open") and not self.sess.get("closed"):
            await asyncio.sleep(0.1)

        if self.sess.get("closed"):
            await send({"type": "http.response.body", "body": b"", "more_body": False})
            return

        await send({
            "type": "http.response.body",
            "body": b"\x00\x00",
            "more_body": True,
        })

        down_q = self.sess["down_q"]
        try:
            while True:
                chunk = await down_q.get()
                if chunk is None:
                    break
                await send({
                    "type": "http.response.body",
                    "body": chunk,
                    "more_body": True,
                })
        except Exception:
            pass
        finally:
            await send({"type": "http.response.body", "body": b"", "more_body": False})
            await _teardown_xhttp(self.session_id)

@app.get("/xhttp/{session_id}")
async def xhttp_downlink(session_id: str, request: Request):
    ensure_xhttp_reaper()
    ip = get_real_remote_address(request)

    async with XHTTP_LOCK:
        sess = xhttp_sessions.get(session_id)
        if sess is None:
            conn_id = secrets.token_urlsafe(6)
            connections[conn_id] = {
                "uuid": None, "ip": ip,
                "connected_at": datetime.now(timezone.utc).isoformat(),
                "bytes": 0, "transport": "xhttp"
            }
            sess = {
                "uuid": None,
                "writer": None, "reader": None,
                "downlink_task": None, "uplink_task": None,
                "down_q": asyncio.Queue(maxsize=DOWNLINK_QUEUE_MAX),
                "last_seen": time.time(), "conn_id": conn_id,
                "tcp_open": False, "closed": False,
                "seq_buf": {}, "next_seq": 0,
                "tunnel_ready": asyncio.Event(),
                "handshake_sent": False,
            }
            xhttp_sessions[session_id] = sess
        else:
            sess["last_seen"] = time.time()

    async def downlink_gen():
        try:
            try:
                await asyncio.wait_for(sess["tunnel_ready"].wait(), timeout=SESSION_IDLE_TIMEOUT)
            except asyncio.TimeoutError:
                logger.warning(f"XHTTP downlink timeout waiting for tunnel [{session_id[:8]}]")
                return

            if sess.get("closed"):
                return

            if not sess["handshake_sent"]:
                yield b"\x00\x00"
                sess["handshake_sent"] = True

            while True:
                chunk = await sess["down_q"].get()
                if chunk is None:
                    break
                sess["last_seen"] = time.time()
                yield chunk
        except asyncio.CancelledError:
            pass
        except Exception:
            pass
        finally:
            await _teardown_xhttp(session_id)

    resp_headers = {
        "Content-Type": "application/octet-stream",
        "Cache-Control": "no-store, no-cache, must-revalidate",
        "X-Accel-Buffering": "no",
        "Connection": "keep-alive",
    }
    return StreamingResponse(downlink_gen(), headers=resp_headers, media_type="application/octet-stream")

@app.post("/xhttp/{session_id}/{seq}")
async def xhttp_packet_up(session_id: str, seq: int, request: Request):
    ensure_xhttp_reaper()
    ip = get_real_remote_address(request)
    body = await request.body()
    if not body:
        return {"ok": True}

    async with XHTTP_LOCK:
        sess = xhttp_sessions.get(session_id)
        if sess is None:
            conn_id = secrets.token_urlsafe(6)
            connections[conn_id] = {
                "uuid": None, "ip": ip,
                "connected_at": datetime.now(timezone.utc).isoformat(),
                "bytes": 0, "transport": "xhttp-packet-up"
            }
            sess = {
                "uuid": None,
                "writer": None, "reader": None,
                "downlink_task": None, "uplink_task": None,
                "down_q": asyncio.Queue(maxsize=DOWNLINK_QUEUE_MAX),
                "last_seen": time.time(), "conn_id": conn_id,
                "tcp_open": False, "closed": False,
                "seq_buf": {}, "next_seq": 0,
                "tunnel_ready": asyncio.Event(),
                "handshake_sent": False,
            }
            xhttp_sessions[session_id] = sess
        else:
            sess["last_seen"] = time.time()

    if not sess["tcp_open"]:
        try:
            user_uuid, command, target_addr, target_port, payload = await parse_vless_header_with_uuid(body)
        except ValueError as e:
            logger.warning(f"XHTTP packet-up invalid VLESS header from {ip}: {e}")
            await _teardown_xhttp(session_id)
            raise HTTPException(status_code=400, detail="invalid VLESS header")

        async with LINKS_LOCK:
            link = LINKS.get(user_uuid)
        if not link or not link["active"]:
            await _teardown_xhttp(session_id)
            raise HTTPException(status_code=403, detail="inactive or unknown UUID")
        if not is_ip_allowed(link, user_uuid, ip):
            await _teardown_xhttp(session_id)
            raise HTTPException(status_code=403, detail="ip limit reached")

        # SSRF protection
        try:
            ip_addr = await resolve_domain_to_ip(target_addr)
            if ip_addr and ipaddress.ip_address(ip_addr).is_private:
                await _teardown_xhttp(session_id)
                raise HTTPException(status_code=403, detail="access to private network denied")
        except ValueError:
            pass

        sess["uuid"] = user_uuid
        connections[sess["conn_id"]]["uuid"] = user_uuid

        gate = QuotaGate(user_uuid)
        if payload:
            if not await gate.add(len(payload)):
                await _teardown_xhttp(session_id)
                raise HTTPException(status_code=403, detail="quota exceeded")
        sess["quota_gate"] = gate
        sess["seq_lock"] = asyncio.Lock()

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target_addr, target_port), timeout=TCP_CONNECT_TIMEOUT
            )
            tune_socket(writer)
            sess["reader"] = reader
            sess["writer"] = writer
            sess["tcp_open"] = True

            sess["tunnel_ready"].set()
            sess["downlink_task"] = asyncio.create_task(
                _pump_tcp_to_queue(session_id, user_uuid, reader, sess["down_q"])
            )
            stats["total_requests"] += 1

            if payload:
                stats["total_bytes"] += len(payload)
                stats["upload_bytes"] += len(payload)
                writer.write(payload)
                await writer.drain()

            logger.info(f"XHTTP packet-up session [{session_id[:8]}] uid={user_uuid[:8]} -> {target_addr}:{target_port}")
        except Exception as e:
            logger.error(f"XHTTP packet-up open error: {e}")
            await _teardown_xhttp(session_id)
            raise HTTPException(status_code=502, detail=str(e))
    else:
        gate = sess.get("quota_gate")
        if gate and not await gate.add(len(body)):
            await _teardown_xhttp(session_id)
            raise HTTPException(status_code=403, detail="quota exceeded")
        seq_lock = sess["seq_lock"]
        async with seq_lock:
            if seq == sess["next_seq"]:
                stats["total_bytes"] += len(body)
                stats["upload_bytes"] += len(body)
                sess["writer"].write(body)
                await sess["writer"].drain()
                sess["next_seq"] += 1
                while sess["next_seq"] in sess["seq_buf"]:
                    pending = sess["seq_buf"].pop(sess["next_seq"])
                    stats["total_bytes"] += len(pending)
                    stats["upload_bytes"] += len(pending)
                    sess["writer"].write(pending)
                    await sess["writer"].drain()
                    sess["next_seq"] += 1
            else:
                if len(sess["seq_buf"]) >= 30:
                    await _teardown_xhttp(session_id)
                    raise HTTPException(status_code=400, detail="too many out-of-order packets")
                sess["seq_buf"][seq] = body

    return Response(status_code=200)

@app.post("/xhttp/{session_id}")
async def xhttp_stream_up(session_id: str, request: Request):
    ensure_xhttp_reaper()
    ip = get_real_remote_address(request)
    gate = None

    async with XHTTP_LOCK:
        sess = xhttp_sessions.get(session_id)
        if sess is None:
            conn_id = secrets.token_urlsafe(6)
            connections[conn_id] = {
                "uuid": None, "ip": ip,
                "connected_at": datetime.now(timezone.utc).isoformat(),
                "bytes": 0, "transport": "xhttp-stream-up"
            }
            sess = {
                "uuid": None,
                "writer": None, "reader": None,
                "downlink_task": None, "uplink_task": None,
                "down_q": asyncio.Queue(maxsize=DOWNLINK_QUEUE_MAX),
                "last_seen": time.time(), "conn_id": conn_id,
                "tcp_open": False, "closed": False,
                "tunnel_ready": asyncio.Event(),
                "handshake_sent": False,
            }
            xhttp_sessions[session_id] = sess
        else:
            sess["last_seen"] = time.time()

    async for chunk in request.stream():
        if not chunk:
            continue
        sess["last_seen"] = time.time()

        if not sess["tcp_open"]:
            try:
                user_uuid, command, target_addr, target_port, payload = await parse_vless_header_with_uuid(chunk)
            except ValueError as e:
                logger.warning(f"XHTTP stream-up invalid VLESS header from {ip}: {e}")
                await _teardown_xhttp(session_id)
                raise HTTPException(status_code=400, detail="invalid VLESS header")

            async with LINKS_LOCK:
                link = LINKS.get(user_uuid)
            if not link or not link["active"]:
                await _teardown_xhttp(session_id)
                raise HTTPException(status_code=403, detail="inactive or unknown UUID")
            if not is_ip_allowed(link, user_uuid, ip):
                await _teardown_xhttp(session_id)
                raise HTTPException(status_code=403, detail="ip limit reached")

            # SSRF protection
            try:
                ip_addr = await resolve_domain_to_ip(target_addr)
                if ip_addr and ipaddress.ip_address(ip_addr).is_private:
                    await _teardown_xhttp(session_id)
                    raise HTTPException(status_code=403, detail="access to private network denied")
            except ValueError:
                pass

            sess["uuid"] = user_uuid
            connections[sess["conn_id"]]["uuid"] = user_uuid
            gate = QuotaGate(user_uuid)
            sess["quota_gate"] = gate

            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(target_addr, target_port), timeout=TCP_CONNECT_TIMEOUT
                )
                tune_socket(writer)
                sess["reader"] = reader
                sess["writer"] = writer
                sess["tcp_open"] = True
                sess["tunnel_ready"].set()
                sess["downlink_task"] = asyncio.create_task(
                    _pump_tcp_to_queue(session_id, user_uuid, reader, sess["down_q"])
                )

                actual_payload_len = len(payload)
                if not await check_quota(user_uuid, actual_payload_len):
                    await _teardown_xhttp(session_id)
                    raise HTTPException(status_code=403, detail="quota")
                await add_usage(user_uuid, actual_payload_len)
                stats["total_bytes"] += actual_payload_len
                stats["upload_bytes"] += actual_payload_len

                stats["total_requests"] += 1
                logger.info(f"XHTTP stream-up session [{session_id[:8]}] uid={user_uuid[:8]} -> {target_addr}:{target_port}")

                if payload:
                    writer.write(payload)
                    await writer.drain()
                continue
            except Exception as e:
                logger.error(f"XHTTP stream-up open error: {e}")
                await _teardown_xhttp(session_id)
                raise HTTPException(status_code=502, detail=str(e))
        else:
            if not await check_quota(sess["uuid"], len(chunk)):
                await _teardown_xhttp(session_id)
                raise HTTPException(status_code=403, detail="quota")
            await add_usage(sess["uuid"], len(chunk))
            stats["total_bytes"] += len(chunk)
            stats["upload_bytes"] += len(chunk)
            sess["writer"].write(chunk)
            await sess["writer"].drain()

    return Response(status_code=200)


@app.post("/{base_path:path}/")
async def xhttp_stream_one(base_path: str, request: Request):
    ensure_xhttp_reaper()
    ip = get_real_remote_address(request)

    valid = False
    async with LINKS_LOCK:
        for uid, link in LINKS.items():
            if not link.get("active"):
                continue
            proto = link.get("protocol", "vless-ws")
            if proto == "xhttp-stream-one":
                bp = link.get("custom_path") or DEFAULT_XHTTP_PATH
                if bp.strip("/") == base_path.strip("/"):
                    valid = True
                    break
    if not valid and DEFAULT_XHTTP_PATH.strip("/") != base_path.strip("/"):
        raise HTTPException(status_code=404)

    body = await request.body()
    if not body:
        raise HTTPException(status_code=400, detail="empty body")

    try:
        user_uuid, command, target_addr, target_port, payload = await parse_vless_header_with_uuid(body)
    except ValueError as e:
        raise HTTPException(status_code=400, detail="invalid VLESS header")

    async with LINKS_LOCK:
        link = LINKS.get(user_uuid)
    if not link or not link["active"]:
        raise HTTPException(status_code=403, detail="inactive or unknown UUID")
    if not is_ip_allowed(link, user_uuid, ip):
        raise HTTPException(status_code=403, detail="ip limit reached")

    # SSRF protection
    try:
        ip_addr = await resolve_domain_to_ip(target_addr)
        if ip_addr and ipaddress.ip_address(ip_addr).is_private:
            raise HTTPException(status_code=403, detail="access to private network denied")
    except ValueError:
        pass

    gate = QuotaGate(user_uuid)
    if payload:
        if not await gate.add(len(payload)):
            raise HTTPException(status_code=403, detail="quota exceeded")

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target_addr, target_port), timeout=TCP_CONNECT_TIMEOUT
        )
        tune_socket(writer)
        if payload:
            stats["total_bytes"] += len(payload)
            stats["upload_bytes"] += len(payload)
            writer.write(payload)
            await writer.drain()
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))

    session_id = secrets.token_urlsafe(16)
    conn_id = secrets.token_urlsafe(6)
    connections[conn_id] = {
        "uuid": user_uuid, "ip": ip,
        "connected_at": datetime.now(timezone.utc).isoformat(),
        "bytes": 0, "transport": "xhttp-stream-one"
    }
    down_q = asyncio.Queue(maxsize=DOWNLINK_QUEUE_MAX)
    sess = {
        "uuid": user_uuid,
        "writer": writer, "reader": reader,
        "downlink_task": None, "uplink_task": None,
        "down_q": down_q,
        "last_seen": time.time(), "conn_id": conn_id,
        "tcp_open": True, "closed": False,
        "quota_gate": gate,
        "handshake_sent": False,
    }
    async with XHTTP_LOCK:
        xhttp_sessions[session_id] = sess

    sess["downlink_task"] = asyncio.create_task(
        _pump_tcp_to_queue(session_id, user_uuid, reader, down_q)
    )
    stats["total_requests"] += 1

    async def downlink_gen():
        try:
            if not sess["handshake_sent"]:
                yield b"\x00\x00"
                sess["handshake_sent"] = True
            while True:
                chunk = await down_q.get()
                if chunk is None:
                    break
                yield chunk
        except asyncio.CancelledError:
            pass
        except Exception:
            pass
        finally:
            await _teardown_xhttp(session_id)

    resp_headers = {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-store",
        "X-Accel-Buffering": "no",
        "Connection": "close",
        "Transfer-Encoding": "chunked",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST",
    }
    return StreamingResponse(downlink_gen(), headers=resp_headers)


async def _pump_tcp_to_queue(session_id: str, uuid: str, reader: asyncio.StreamReader, down_q: asyncio.Queue):
    gate = QuotaGate(uuid)
    try:
        while True:
            data = await reader.read(XHTTP_BUF)
            if not data:
                break
            if not await gate.add(len(data)):
                break
            await gate.flush()
            stats["total_bytes"] += len(data)
            stats["download_bytes"] += len(data)
            async with XHTTP_LOCK:
                sess = xhttp_sessions.get(session_id)
            if sess:
                c = connections.get(sess["conn_id"])
                if c:
                    c["bytes"] += len(data)
            await down_q.put(data)
    except (asyncio.CancelledError, Exception):
        pass
    finally:
        await gate.flush()
        await down_q.put(None)
        await _teardown_xhttp(session_id)

PANEL_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<title>SulgX Panel</title>
<link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@700;900&family=Inter:wght@400;500;600;700&family=Vazirmatn:wght@400;600;700;800&display=swap" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.js"></script>
<style>
* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}

:root {
  --primary: #39ff14;
  --primary-dim: rgba(57, 255, 20, 0.18);
  --primary-glass: rgba(57, 255, 20, 0.08);
  --bg: #09090b;
  --bg2: #111113;
  --bg3: #18181b;
  --surface: rgba(18, 18, 20, 0.75);
  --surface2: rgba(24, 24, 27, 0.9);
  --surface3: rgba(30, 30, 35, 0.85);
  --border: rgba(57, 255, 20, 0.1);
  --border2: rgba(57, 255, 20, 0.25);
  --text: #f0f0f4;
  --text2: #a1a1aa;
  --text3: #71717a;
  --green: #4ade80;
  --red: #f87171;
  --yellow: #fbbf24;
  --header-h: 68px;
  --footer-h: 52px;
  --radius-sm: 12px;
  --radius-md: 18px;
  --radius-lg: 26px;
  --shadow: 0 12px 40px rgba(0, 0, 0, 0.6);
  --shadow-soft: 0 6px 24px rgba(0, 0, 0, 0.35);
  --shadow-glow: 0 0 35px var(--primary-dim);
  --transition: 0.3s cubic-bezier(0.2, 0.9, 0.4, 1);
  --halo-color-1: rgba(57, 255, 20, 0.2);
  --halo-color-2: rgba(57, 255, 20, 0.1);
  --halo-color-3: rgba(57, 255, 20, 0.05);
}

body.light-mode {
  --primary: #2e7d32;
  --primary-dim: rgba(46, 125, 50, 0.18);
  --primary-glass: rgba(46, 125, 50, 0.08);
  --bg: #f5f9f5;
  --bg2: #ffffff;
  --bg3: #eaf1ea;
  --surface: rgba(255, 255, 255, 0.8);
  --surface2: rgba(255, 255, 255, 0.94);
  --surface3: rgba(245, 250, 245, 0.9);
  --border: rgba(0, 0, 0, 0.1);
  --border2: rgba(0, 0, 0, 0.18);
  --text: #1a1a1a;
  --text2: #4a4a4a;
  --text3: #888;
  --shadow: 0 12px 36px rgba(0, 0, 0, 0.08);
  --shadow-soft: 0 6px 20px rgba(0, 0, 0, 0.04);
  --shadow-glow: 0 0 30px rgba(46, 125, 50, 0.25);
  --halo-color-1: rgba(46, 125, 50, 0.18);
  --halo-color-2: rgba(46, 125, 50, 0.1);
  --halo-color-3: rgba(46, 125, 50, 0.05);
}

body.blue-mode {
  --primary: #3b82f6;
  --primary-dim: rgba(59, 130, 246, 0.18);
  --primary-glass: rgba(59, 130, 246, 0.08);
  --bg: #0f172a;
  --bg2: #1e293b;
  --bg3: #1e293b;
  --surface: rgba(30, 41, 59, 0.8);
  --surface2: rgba(30, 41, 59, 0.94);
  --surface3: rgba(51, 65, 85, 0.9);
  --border: rgba(59, 130, 246, 0.12);
  --border2: rgba(59, 130, 246, 0.3);
  --text: #e2e8f0;
  --text2: #94a3b8;
  --text3: #64748b;
  --shadow: 0 12px 40px rgba(0, 0, 0, 0.5);
  --shadow-soft: 0 6px 24px rgba(0, 0, 0, 0.3);
  --shadow-glow: 0 0 35px rgba(59, 130, 246, 0.35);
  --halo-color-1: rgba(59, 130, 246, 0.2);
  --halo-color-2: rgba(59, 130, 246, 0.1);
  --halo-color-3: rgba(59, 130, 246, 0.05);
}

html, body {
  height: 100%;
  overflow-x: hidden;
}

body {
  font-family: 'Inter', 'Vazirmatn', sans-serif;
  color: var(--text);
  display: flex;
  flex-direction: column;
  background: var(--bg);
  transition: background 0.5s, color 0.5s;
  position: relative;
  line-height: 1.65;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  -webkit-tap-highlight-color: transparent;
}

body::before {
  content: '';
  position: fixed;
  top: -45%;
  left: -25%;
  width: 85%;
  height: 100%;
  background: radial-gradient(ellipse at 35% 45%, var(--halo-color-1) 0%, transparent 65%);
  animation: haloFloat1 28s infinite alternate ease-in-out;
  z-index: 0;
  pointer-events: none;
  filter: blur(65px);
  mix-blend-mode: screen;
}

body::after {
  content: '';
  position: fixed;
  bottom: -50%;
  right: -25%;
  width: 85%;
  height: 100%;
  background: radial-gradient(ellipse at 65% 55%, var(--halo-color-2) 0%, transparent 65%);
  animation: haloFloat2 32s infinite alternate ease-in-out;
  z-index: 0;
  pointer-events: none;
  filter: blur(85px);
  mix-blend-mode: screen;
}

html::before {
  content: '';
  position: fixed;
  top: 20%;
  left: 20%;
  width: 60%;
  height: 60%;
  background: radial-gradient(circle at 50% 50%, var(--halo-color-3) 0%, transparent 70%);
  animation: haloSpin 45s infinite linear;
  z-index: 0;
  pointer-events: none;
  filter: blur(110px);
  mix-blend-mode: screen;
}

@keyframes haloFloat1 {
  0% { transform: translate(0, 0) scale(1); }
  100% { transform: translate(8%, 10%) scale(1.15); }
}
@keyframes haloFloat2 {
  0% { transform: translate(0, 0) scale(1); }
  100% { transform: translate(-8%, -10%) scale(1.15); }
}
@keyframes haloSpin {
  from { transform: rotate(0deg) scale(1); }
  to { transform: rotate(360deg) scale(1.3); }
}

.header, .main, .footer, .mo, .toast, #login-page, #dashboard-page {
  position: relative;
  z-index: 1;
}

body[dir="rtl"] {
  direction: rtl;
  text-align: right;
}
body[dir="rtl"] .fl,
body[dir="rtl"] label {
  float: right !important;
  text-align: right !important;
  margin-bottom: 6px;
}
body[dir="rtl"] .fi,
body[dir="rtl"] select,
body[dir="rtl"] input {
  direction: ltr !important;
  text-align: left !important;
}
body[dir="rtl"] .glass-btn-group {
  direction: rtl !important;
}

a { text-decoration: none; color: inherit; }

::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: var(--surface); border-radius: 10px; }
::-webkit-scrollbar-thumb { background: var(--border2); border-radius: 10px; transition: background 0.3s; }
::-webkit-scrollbar-thumb:hover { background: var(--primary-glass); }
* { scrollbar-width: thin; scrollbar-color: var(--border2) var(--surface); }

::selection {
  background: var(--primary);
  color: #000;
}

.header {
  min-height: var(--header-h);
  background: var(--surface);
  border-bottom: 1px solid var(--border);
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 0 28px;
  backdrop-filter: blur(30px) saturate(150%);
  position: sticky;
  top: 0;
  z-index: 101;
  box-shadow: 0 2px 20px rgba(0,0,0,0.2);
}
.header-inner {
  display: flex;
  align-items: center;
  justify-content: space-between;
  width: 100%;
  max-width: 1440px;
  flex-wrap: nowrap;
  gap: 16px;
}
.logo {
  font-family: 'Orbitron', sans-serif;
  font-size: 1.9rem;
  font-weight: 900;
  color: var(--primary);
  letter-spacing: 2px;
  text-shadow: 0 0 20px var(--primary-dim);
  transition: text-shadow 0.3s, transform 0.3s;
  flex-shrink: 0;
}
.logo:hover {
  text-shadow: 0 0 38px var(--primary-dim);
  transform: scale(1.04);
}
.version-tag {
  font-size: 0.7rem;
  color: var(--primary);
  margin-left: 10px;
  font-weight: 500;
  opacity: 0.95;
  background: var(--primary-glass);
  padding: 3px 12px;
  border-radius: 20px;
  flex-shrink: 0;
}
.header-nav { display: flex; align-items: center; gap: 8px; }
.nav-link {
  padding: 10px 20px;
  border-radius: var(--radius-sm);
  color: var(--text3);
  font-size: 0.88rem;
  font-weight: 600;
  transition: all var(--transition);
  border: 1px solid transparent;
  background: none;
  cursor: pointer;
  font-family: inherit;
  position: relative;
  overflow: hidden;
}
.nav-link::after {
  content: '';
  position: absolute;
  bottom: 0;
  left: 50%;
  width: 0;
  height: 2px;
  background: var(--primary);
  transition: all var(--transition);
  transform: translateX(-50%);
}
.nav-link:hover {
  color: var(--primary);
  background: var(--primary-glass);
  border-color: transparent;
}
.nav-link:hover::after { width: 75%; }
.nav-link.active {
  color: var(--primary);
  background: var(--primary-glass);
  border-color: var(--primary-dim);
  backdrop-filter: blur(10px);
  box-shadow: 0 0 20px var(--primary-dim);
}
.nav-link.active::after { width: 95%; }
.header-right { display: flex; align-items: center; gap: 10px; flex-wrap: nowrap; }
.btn-icon {
  background: var(--surface3);
  border: 1px solid var(--border);
  color: var(--text3);
  border-radius: var(--radius-sm);
  padding: 10px;
  cursor: pointer;
  transition: all var(--transition);
  font-size: 1.1rem;
  backdrop-filter: blur(8px);
  display: inline-flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
}
.btn-icon:hover {
  color: var(--primary);
  border-color: var(--primary);
  background: var(--primary-glass);
  box-shadow: 0 0 18px var(--primary-dim);
  transform: translateY(-2px);
}
.lang-switch {
  display: flex;
  gap: 2px;
  background: var(--surface3);
  border-radius: var(--radius-sm);
  padding: 3px;
  backdrop-filter: blur(8px);
}
.lang-btn {
  padding: 6px 14px;
  border: none;
  background: transparent;
  color: var(--text3);
  font-size: 0.8rem;
  font-weight: 700;
  border-radius: 8px;
  cursor: pointer;
  font-family: inherit;
  transition: all var(--transition);
}
.lang-btn.active {
  background: var(--primary);
  color: #000;
  box-shadow: 0 0 16px var(--primary-dim);
}
.hamburger {
  display: none;
  background: transparent;
  border: 1px solid var(--border);
  color: var(--text3);
  font-size: 1.9rem;
  cursor: pointer;
  padding: 4px 12px;
  border-radius: var(--radius-sm);
}

.main {
  flex: 1;
  min-height: calc(100vh - var(--header-h) - var(--footer-h));
  padding: 36px 48px;
  overflow-y: auto;
  overflow-x: hidden;
}
.page { display: none; animation: pgIn 0.45s ease; }
.page.active { display: block; }
@keyframes pgIn {
  from { opacity: 0; transform: translateY(18px); }
  to { opacity: 1; transform: none; }
}
.page-header {
  margin-bottom: 32px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 16px;
}
.page-title {
  font-size: 2rem;
  font-weight: 800;
  color: var(--primary);
  letter-spacing: -0.03em;
  text-shadow: 0 0 18px var(--primary-dim);
}
.page-title[data-fa] { font-family: 'Vazirmatn'; }
.page-sub { font-size: 1rem; color: var(--text3); margin-top: 6px; }

.stats-row {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 24px;
  margin-bottom: 34px;
}
.stat-card {
  background: var(--surface2);
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  padding: 28px;
  position: relative;
  overflow: hidden;
  transition: all var(--transition);
  backdrop-filter: blur(18px);
  cursor: default;
  container-type: inline-size;
}
.stat-card::before {
  content: '';
  position: absolute;
  top: 0;
  left: 0;
  width: 5px;
  height: 100%;
  background: linear-gradient(180deg, var(--primary), transparent);
  opacity: 0;
  transition: opacity var(--transition);
}
.stat-card:hover {
  border-color: var(--border2);
  transform: translateY(-4px);
  box-shadow: var(--shadow-soft), 0 0 50px var(--primary-dim);
}
.stat-card:hover::before { opacity: 1; }
.stat-label {
  font-size: 0.75rem;
  color: var(--text3);
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.14em;
  margin-bottom: 14px;
}
.stat-val {
  font-size: 2.2rem;
  font-weight: 800;
  color: var(--text);
  transition: color 0.3s;
}
.stat-card:hover .stat-val { color: var(--primary); }
.stat-unit { font-size: 1rem; font-weight: 400; color: var(--text3); }

@container (max-width: 200px) {
  .stat-val { font-size: 1.4rem; }
}

.speed-card {
  background: var(--surface2);
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  padding: 24px;
  display: flex;
  flex-direction: column;
  gap: 16px;
  transition: all var(--transition);
  backdrop-filter: blur(18px);
}
.speed-card:hover { border-color: var(--border2); box-shadow: var(--shadow-soft), var(--shadow-glow); }
.speed-row { display: flex; flex-direction: column; gap: 14px; }
.speed-item { display: flex; justify-content: space-between; align-items: center; }
.speed-item .stat-label { margin-bottom: 0; font-size: 0.8rem; }
.speed-item .stat-val { font-size: 1.4rem; }

.card {
  background: var(--surface2);
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  padding: 30px;
  margin-bottom: 22px;
  transition: all var(--transition);
  backdrop-filter: blur(20px) saturate(110%);
}
.card:hover {
  border-color: var(--border2);
  box-shadow: var(--shadow-soft), 0 0 45px var(--primary-dim);
}
.card-hd { display: flex; align-items: center; justify-content: space-between; margin-bottom: 22px; }
.card-title { font-size: 1.15rem; font-weight: 600; color: var(--text); }
.chart-container { height: 280px; width: 100%; }

.btn {
  font-family: inherit;
  font-size: 0.88rem;
  font-weight: 700;
  border-radius: var(--radius-sm);
  padding: 12px 26px;
  cursor: pointer;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 10px;
  border: none;
  transition: all var(--transition);
  backdrop-filter: blur(10px);
  position: relative;
  overflow: hidden;
  letter-spacing: 0.3px;
}
.btn::after {
  content: '';
  position: absolute;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  background: linear-gradient(45deg, transparent, rgba(255,255,255,0.2), transparent);
  transform: translateX(-100%);
  transition: transform 0.8s;
}
.btn:hover::after { transform: translateX(100%); }
.btn-primary {
  background: linear-gradient(135deg, var(--primary), color-mix(in srgb, var(--primary) 80%, black));
  color: #000;
  box-shadow: 0 6px 28px var(--primary-dim);
}
.btn-primary:hover {
  filter: brightness(1.2);
  box-shadow: 0 10px 40px var(--primary-dim);
  transform: translateY(-3px);
}
.btn-primary:active { transform: translateY(0); }
.btn-outline {
  background: var(--surface3);
  color: var(--text);
  border: 1px solid var(--border);
}
.btn-outline:hover {
  background: var(--primary-glass);
  border-color: var(--primary);
  color: var(--primary);
  box-shadow: 0 0 28px var(--primary-dim);
}
.btn-danger {
  background: rgba(248,113,113,0.12);
  color: var(--red);
  border: 1px solid rgba(248,113,113,0.3);
}
.btn-danger:hover {
  background: rgba(248,113,113,0.25);
  box-shadow: 0 0 28px rgba(248,113,113,0.35);
}
.btn-sm { padding: 8px 18px; font-size: 0.78rem; }

.tbl-wrap { overflow-x: auto; border-radius: var(--radius-sm); }
.tbl {
  width: 100%;
  border-collapse: collapse;
  table-layout: auto;
  background: transparent;
}
.tbl th {
  text-align: center;
  font-size: 0.78rem;
  font-weight: 700;
  color: var(--text3);
  padding: 18px 16px;
  text-transform: uppercase;
  border-bottom: 1px solid var(--border);
  background: var(--surface3);
  letter-spacing: 0.08em;
  backdrop-filter: blur(6px);
}
.tbl td {
  padding: 17px 16px;
  border-bottom: 1px solid var(--border);
  font-size: 0.9rem;
  word-break: break-word;
  font-weight: 400;
  background: none;
  color: var(--text);
  transition: background var(--transition), color var(--transition);
  vertical-align: middle;
  text-align: center;
}
.tbl tbody tr:hover td {
  background: var(--primary-glass);
}
.tbl tbody tr:nth-child(even) td {
  background: rgba(255,255,255,0.02);
}

#inbound-table th, #inbound-table td {
  text-align: center !important;
}
#inbound-table td:first-child, #inbound-table th:first-child { width: 50px; }
#inbound-table th:nth-child(8), #inbound-table td:nth-child(8) { min-width: 180px; }
.tbl input[type="checkbox"] { width: 20px; height: 20px; accent-color: var(--primary); }
.time-col { white-space: nowrap; min-width: 130px; text-align: center; }

#login-logs-table {
  table-layout: fixed;
  width: 100%;
  border-collapse: collapse;
}

#login-logs-table th,
#login-logs-table td {
  text-align: center;
  vertical-align: middle;
  word-break: break-word;
  overflow-wrap: break-word;
}

#login-logs-table th:first-child,
#login-logs-table td:first-child { width: 15%; }

#login-logs-table th:nth-child(2),
#login-logs-table td:nth-child(2) {
  width: 30%;
  text-align: left;
  padding-left: 12px;
  padding-right: 8px;
}

#login-logs-table th:nth-child(3),
#login-logs-table td:nth-child(3) { width: 15%; }

#login-logs-table th:nth-child(4),
#login-logs-table td:nth-child(4) { width: 20%; }

#login-logs-table th:nth-child(5),
#login-logs-table td:nth-child(5) { width: 20%; }

body[dir="rtl"] #login-logs-table th:nth-child(2),
body[dir="rtl"] #login-logs-table td:nth-child(2) {
  text-align: right;
  padding-left: 8px;
  padding-right: 12px;
}

#logs-table th, #logs-tbody td {
  text-align: center !important;
  vertical-align: middle !important;
}

.tbl.scanner-tbl th:first-child,
.tbl.scanner-tbl td:first-child {
  width: auto;
  text-align: left;
}

.tag {
  display: inline-flex;
  align-items: center;
  padding: 5px 14px;
  border-radius: 10px;
  font-size: 0.68rem;
  font-weight: 800;
  text-transform: uppercase;
  letter-spacing: 0.06em;
}
.tag-vless { background: var(--primary-dim); color: var(--primary); border: 1px solid var(--border); }
.tag-on { background: rgba(74,222,128,0.2); color: var(--green); border: 1px solid rgba(74,222,128,0.4); }
.tag-off { background: rgba(248,113,113,0.2); color: var(--red); border: 1px solid rgba(248,113,113,0.4); }
.pill { display: flex; align-items: center; gap: 12px; font-size: 0.9rem; }
.pill-used { color: var(--text); font-weight: 600; }
.pill-bar { flex: 1; height: 8px; background: var(--border); border-radius: 5px; min-width: 30px; overflow: hidden; }
.pill-fill { height: 100%; border-radius: 5px; transition: width 0.5s ease; }
.pill-lim { color: var(--text3); font-size: 0.78rem; }

.toggle {
  width: 52px;
  height: 30px;
  border-radius: 15px;
  background: var(--surface3);
  position: relative;
  cursor: pointer;
  transition: all var(--transition);
  border: 2px solid var(--border);
  flex-shrink: 0;
}
.toggle::after {
  content: '';
  position: absolute;
  width: 24px;
  height: 24px;
  border-radius: 50%;
  background: var(--text3);
  top: 1px;
  left: 2px;
  transition: all var(--transition);
}
.toggle.on {
  background: var(--green);
  border-color: var(--green);
  box-shadow: 0 0 24px rgba(74,222,128,0.6);
}
.toggle.on::after {
  left: 26px;
  background: #fff;
}

.sys-bar { height: 10px; background: var(--border); border-radius: 6px; overflow: hidden; }
.sys-fill { height: 100%; border-radius: 6px; transition: width 0.8s ease; }

.sl-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 16px 0;
  border-bottom: 1px solid var(--border);
}
.sl-k { color: var(--text3); font-size: 0.98rem; }
.sl-v { color: var(--text); font-weight: 600; font-size: 0.98rem; }

.fg { display: flex; flex-direction: column; gap: 10px; margin-bottom: 26px; }
.fl {
  font-size: 0.78rem;
  font-weight: 700;
  color: var(--text2);
  text-transform: uppercase;
  letter-spacing: 0.07em;
}
.fi, .fs {
  padding: 16px 22px;
  border-radius: var(--radius-sm);
  border: 1px solid var(--border);
  font-family: inherit;
  font-size: 0.92rem;
  outline: none;
  color: var(--text);
  background: var(--surface);
  transition: all var(--transition);
  backdrop-filter: blur(8px);
}
.fi:focus, .fs:focus {
  border-color: var(--primary);
  box-shadow: 0 0 0 5px var(--primary-dim);
}

.act-btn {
  font-family: inherit;
  font-size: 0.72rem;
  font-weight: 700;
  padding: 6px 12px;
  border-radius: 7px;
  cursor: pointer;
  border: 1px solid;
  transition: all 0.2s;
  display: inline-flex;
  align-items: center;
  gap: 6px;
  background: transparent;
}
.act-copy { color: var(--primary); border-color: var(--border); } .act-copy:hover { background: var(--primary-glass); }
.act-sub { color: var(--green); border-color: rgba(74,222,128,0.4); } .act-sub:hover { background: rgba(74,222,128,0.2); }
.act-clash { color: #c084fc; border-color: #c084fc40; } .act-clash:hover { background: #c084fc20; }
.act-qr { color: #a78bfa; border-color: #a78bfa40; } .act-qr:hover { background: #a78bfa20; }
.act-edit { color: var(--yellow); border-color: rgba(251,191,36,0.4); } .act-edit:hover { background: rgba(251,191,36,0.2); }
.act-del { color: var(--red); border-color: rgba(248,113,113,0.4); } .act-del:hover { background: rgba(248,113,113,0.25); }

.toast {
  position: fixed;
  bottom: 40px;
  left: 50%;
  transform: translateX(-50%) translateY(20px);
  background: var(--surface);
  color: var(--text);
  border: 1px solid var(--border2);
  border-radius: var(--radius-md);
  padding: 18px 40px;
  font-size: 1rem;
  font-weight: 600;
  opacity: 0;
  transition: all 0.45s ease;
  z-index: 999;
  backdrop-filter: blur(30px);
  box-shadow: var(--shadow-soft);
  pointer-events: none;
}
.toast.show { opacity: 1; transform: translateX(-50%) translateY(0); pointer-events: auto; }

.mo {
  position: fixed;
  inset: 0;
  background: rgba(0,0,0,0.8);
  z-index: 200;
  display: none;
  align-items: center;
  justify-content: center;
  backdrop-filter: blur(14px);
  animation: fadeIn 0.3s ease;
}
.mo.show { display: flex; }
@keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
.mo-box {
  background: var(--surface2);
  border: 1px solid var(--border2);
  border-radius: var(--radius-lg);
  padding: 42px;
  width: 100%;
  max-width: 640px;
  max-height: 90vh;
  overflow-y: auto;
  box-shadow: 0 32px 80px rgba(0,0,0,0.7);
  backdrop-filter: blur(36px);
  position: relative;
  animation: scaleIn 0.35s ease;
}
@keyframes scaleIn { from { transform: scale(0.95); opacity: 0; } to { transform: scale(1); opacity: 1; } }
.mo-title { font-size: 1.6rem; font-weight: 700; margin-bottom: 28px; color: var(--primary); }
.mo-close {
  position: absolute;
  top: 20px;
  right: 20px;
  background: var(--surface3);
  border: 1px solid var(--border);
  color: var(--text3);
  width: 40px;
  height: 40px;
  border-radius: var(--radius-sm);
  cursor: pointer;
  transition: all var(--transition);
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 1.4rem;
}
.mo-close:hover { color: var(--red); border-color: var(--red); }
.qr-box { text-align: center; padding: 30px; background: var(--surface3); border-radius: var(--radius-md); border: 1px solid var(--border); margin-top: 18px; }
.qr-box img { max-width: 230px; border-radius: 18px; border: 3px solid var(--border); box-shadow: var(--shadow); }

.footer {
  height: var(--footer-h);
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 0.85rem;
  color: var(--text3);
  border-top: 1px solid var(--border);
  background: var(--surface);
  backdrop-filter: blur(10px);
  margin-top: auto;
}
.footer-inner { display: flex; align-items: center; justify-content: center; gap: 36px; flex-wrap: wrap; }
.footer-inner a { color: var(--primary); text-decoration: none; font-weight: 600; transition: all var(--transition); }
.footer-inner a:hover { text-shadow: 0 0 18px var(--primary); }
textarea.fi { resize: vertical; min-height: 130px; }

.chip {
  padding: 9px 20px;
  border-radius: 14px;
  font-size: 0.82rem;
  font-weight: 700;
  color: var(--text3);
  cursor: pointer;
  border: none;
  background: none;
  font-family: inherit;
  transition: all var(--transition);
}
.chip:hover { color: var(--primary); background: var(--primary-glass); }
.chip.active { background: var(--primary); color: #000; }
.pill-group { display: flex; flex-wrap: wrap; gap: 14px; }
.pill-btn {
  padding: 12px 22px;
  border-radius: 28px;
  border: 1px solid var(--border);
  background: var(--surface3);
  color: var(--text3);
  cursor: pointer;
  font-size: 0.86rem;
  font-weight: 600;
  transition: all var(--transition);
  font-family: inherit;
  backdrop-filter: blur(8px);
}
.pill-btn:hover { border-color: var(--primary); color: var(--primary); box-shadow: 0 0 18px var(--primary-dim); }
.pill-btn.active { background: var(--primary-glass); color: var(--primary); border-color: var(--primary); box-shadow: 0 0 28px var(--primary-dim); }

.adv-toggle {
  cursor: pointer;
  color: var(--primary);
  font-weight: 600;
  margin-bottom: 20px;
  display: inline-flex;
  align-items: center;
  gap: 10px;
  border: none;
  background: none;
  font-size: 0.98rem;
  font-family: inherit;
  transition: all var(--transition);
}
.adv-toggle:hover { opacity: 0.85; }
.adv-section {
  display: none;
  padding: 20px;
  background: var(--surface);
  border-radius: var(--radius-sm);
  border: 1px solid var(--border);
  margin-top: 14px;
}

.addr-list-scroll {
  max-height: 420px;
  overflow-y: auto;
  -webkit-overflow-scrolling: touch;
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  padding: 14px;
  background: var(--surface);
}
.logs-table-container { max-height: 480px; overflow-y: auto; -webkit-overflow-scrolling: touch; }
.scan-results-container { max-height: 350px; overflow-y: auto; -webkit-overflow-scrolling: touch; }

.mobile-nav {
  display: none;
  position: fixed;
  bottom: 0;
  left: 0;
  right: 0;
  background: var(--surface);
  border-top: 1px solid var(--border);
  z-index: 9999;
  backdrop-filter: blur(30px);
  padding: 12px 0 env(safe-area-inset-bottom, 0);
}
.mobile-nav .nav-items { display: flex; justify-content: space-around; align-items: center; width: 100%; }
.mobile-nav .nav-item {
  flex: 1;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 6px;
  padding: 10px 4px;
  color: var(--text3);
  font-size: 0.72rem;
  cursor: pointer;
  transition: all var(--transition);
  border-radius: var(--radius-sm);
}
.mobile-nav .nav-item.active { color: var(--primary); background: var(--primary-glass); }

.glass-btn-group {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  background: var(--primary-glass);
  border: 1px solid var(--border);
  padding: 6px;
  border-radius: var(--radius-sm);
  backdrop-filter: blur(14px);
}
.glass-btn {
  flex: 1;
  min-width: 90px;
  background: transparent;
  border: none;
  color: var(--text3);
  padding: 14px 20px;
  border-radius: 14px;
  cursor: pointer;
  font-weight: 600;
  font-family: inherit;
  font-size: 0.86rem;
  transition: all var(--transition);
}
.glass-btn.active { background: var(--primary); color: #000 !important; box-shadow: 0 0 24px var(--primary-dim); }
.glass-btn:hover:not(.active) { background: rgba(255,255,255,0.06); color: var(--text); }

.status-cards-grid {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 20px;
  margin-top: 18px;
}
#page-settings .status-cards-grid { justify-items: center; }
.status-glass-card {
  padding: 26px 22px;
  border-radius: var(--radius-md);
  text-align: center;
  cursor: pointer;
  font-weight: 700;
  transition: all var(--transition);
  user-select: none;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 16px;
  font-size: 0.9rem;
  max-width: 100%;
  backdrop-filter: blur(14px);
  background: rgba(255,255,255,0.03);
  border: 1px solid var(--border);
  color: var(--text3);
}
.status-glass-card.active {
  background: var(--primary-glass);
  border: 1px solid rgba(57,255,20,0.45);
  color: var(--primary);
  box-shadow: 0 0 32px var(--primary-dim);
}
.status-glass-card.inactive {
  background: rgba(255,255,255,0.02);
  border: 1px solid var(--border);
  color: var(--text3);
}
.railway-hl {
  background: rgba(168,85,247,0.2) !important;
  color: #d8b4fe !important;
  border: 1px solid #a855f7 !important;
  font-weight: 800;
  box-shadow: 0 0 24px rgba(168,85,247,0.3);
}

.tooltip-container { position: relative; display: inline-flex; }
.tooltip-text {
  visibility: hidden;
  background: rgba(0,0,0,0.95);
  color: #fff;
  text-align: center;
  border-radius: 12px;
  padding: 10px 18px;
  position: absolute;
  z-index: 100;
  bottom: 140%;
  left: 50%;
  transform: translateX(-50%);
  white-space: nowrap;
  border: 1px solid rgba(255,255,255,0.2);
  box-shadow: 0 14px 40px rgba(0,0,0,0.6);
  backdrop-filter: blur(20px);
  opacity: 0;
  transition: opacity 0.25s ease, transform 0.25s ease;
  font-size: 0.75rem;
  pointer-events: none;
}
.tooltip-container:hover .tooltip-text { visibility: visible; opacity: 1; transform: translateX(-50%) translateY(-8px); }

.multi-panel-grid { display: flex; flex-wrap: wrap; gap: 20px; }
.multi-panel-grid .status-glass-card {
  max-width: 400px;
  flex: 1 1 340px;
  text-align: left;
  align-items: flex-start;
  gap: 16px;
  flex-direction: column;
}
.multi-panel-grid .status-glass-card > div:first-child { width: 100%; display: flex; flex-direction: column; gap: 16px; }

.scanner-location-filter { margin: 18px 0; display: flex; flex-wrap: wrap; gap: 16px; align-items: center; }
.scanner-location-filter input {
  flex: 1;
  padding: 14px 20px;
  border-radius: 12px;
  border: 1px solid var(--border);
  background: var(--surface);
  color: var(--text);
}
.location-checkbox { display: inline-flex; align-items: center; gap: 6px; font-size: 0.82rem; color: var(--text2); cursor: pointer; }
.location-checkbox input[type="checkbox"] { width: 19px; height: 19px; }

/* ── Responsive (large screens) ── */
@media (min-width: 1024px) {
  .header-inner { flex-wrap: nowrap; }
  .main { padding: 40px 56px; }
  .card { max-width: 100%; }
  .status-cards-grid { grid-template-columns: repeat(2, 1fr); }
  .status-glass-card { max-width: 100%; }
  .btn { width: auto; }
}

/* ── Responsive (tablets / small laptops) ── */
@media (max-width: 1023px) {
  .header {
    min-height: auto;
    padding: 10px 18px;
  }
  .header-inner {
    flex-wrap: wrap;
    gap: 10px;
  }
  .header .header-nav { display: none; }
  .mobile-nav { display: block; }
  .main { padding: 22px 16px 120px; }
  .footer { display: none; }
  .logo { font-size: 1.6rem; }
  .version-tag { font-size: 0.7rem; }
  .header-right { gap: 6px; flex-wrap: wrap; justify-content: flex-end; }
  .btn-icon { padding: 8px; font-size: 1.1rem; }
  .lang-switch { flex-direction: row; }
  .lang-btn { padding: 6px 12px; font-size: 0.72rem; }
  .glass-btn { min-width: 70px; padding: 10px; font-size: 0.78rem; }
  .btn { font-size: 0.82rem; padding: 8px 16px; }
  .btn-primary { padding: 12px 20px; }
  .stats-row { grid-template-columns: repeat(2, 1fr); gap: 14px; }
  .stat-card { padding: 20px; }
  .stat-label { font-size: 0.7rem; }
  .stat-val { font-size: 1.6rem; }
  .tbl th, .tbl td { padding: 14px 10px; font-size: 0.8rem; }
  .mo-box { padding: 28px; max-width: 95vw; }
  .mobile-nav .nav-item { font-size: 0.68rem; }
  .pill-btn { font-size: 0.78rem; padding: 10px 16px; }
  .fi, .fs { max-width: 100%; }

  #srch { max-width: 160px; }

  .multi-panel-grid .status-glass-card { max-width: 100% !important; flex: 1 1 100% !important; padding: 20px; }
  .multi-panel-grid .status-glass-card > div:first-child {
    display: flex;
    flex-direction: column;
    gap: 14px;
    width: 100%;
  }
  #new-panel-name, #new-panel-url {
    width: 100%;
    padding: 14px;
    font-size: 1rem;
    box-sizing: border-box;
  }
  #new-panel-url + .btn {
    width: 100%;
    margin-top: 6px;
  }

  .status-glass-card { max-width: 100%; padding: 18px; font-size: 0.82rem; }

  .status-cards-grid { grid-template-columns: repeat(2, 1fr) !important; }

  /* ── Mobile table cards ── */
  #inbound-table thead { display: none; }
  #inbound-table tr { display: block; margin-bottom: 20px; border: 1px solid var(--border2); border-radius: var(--radius-md); padding: 20px; background: var(--surface); box-shadow: var(--shadow); }
  #inbound-table td { display: flex; align-items: center; justify-content: space-between; padding: 14px 0; border-bottom: 1px solid var(--border); font-size: 0.85rem; }
  #inbound-table td:last-child { border-bottom: none; }
  #inbound-table td::before { content: attr(data-label); font-weight: 700; color: var(--text3); margin-right: 16px; white-space: nowrap; }
  #inbound-table td:first-child { display: flex !important; align-items: center; justify-content: flex-start; padding: 10px 0; border-bottom: none; }
  #inbound-table td:first-child::before { content: "Select"; font-weight: 700; color: var(--text3); margin-right: 16px; }
  #inbound-table td:first-child input[type="checkbox"] { width: 22px; height: 22px; margin-right: 14px; }

  .addr-list-scroll > div { flex-direction: column !important; align-items: flex-start !important; gap: 14px; }
  #addresses-card > div:nth-child(2) { flex-wrap: wrap; gap: 12px; }
  #addresses-card > div:nth-child(2) .btn { flex: 1 1 auto; margin-bottom: 4px; }

  /* ── Recent Activity horizontal scroll ── */
  #login-logs-table {
    display: block;
    overflow-x: auto;
    -webkit-overflow-scrolling: touch;
    white-space: nowrap;
    min-width: 650px;
  }
  #login-logs-table thead,
  #login-logs-table tbody,
  #login-logs-table tr,
  #login-logs-table th,
  #login-logs-table td {
    white-space: nowrap;
  }
  #login-logs-table td {
    word-break: normal;
    overflow-wrap: normal;
  }

  #doh-ping-table {
    display: block;
    overflow-x: auto;
    -webkit-overflow-scrolling: touch;
  }
  #doh-ping-table table { min-width: 650px; }
}

/* ── Responsive (small phones) ── */
@media (max-width: 500px) {
  .stats-row { grid-template-columns: repeat(2, 1fr); }
  .glass-btn-group { flex-direction: column; }
  .glass-btn { width: 100%; }
  .page-title { font-size: 1.5rem; }
  .header-right { gap: 4px; }
  .btn-icon { padding: 6px; font-size: 0.95rem; }
  .lang-btn { padding: 5px 8px; font-size: 0.68rem; }
  .btn { padding: 8px 14px; }
  .btn-primary { padding: 10px 16px; }
}
</style>
</head>
<body>
<div class="toast" id="toast"></div>
<div id="login-page" style="display:none;width:100%">
  <div style="display:flex;align-items:center;justify-content:center;min-height:100vh;">
    <div style="background:var(--surface2);border:1px solid var(--border2);border-radius:28px;padding:48px 40px;width:100%;max-width:400px;box-shadow:0 0 40px var(--primary-dim);backdrop-filter:blur(20px);">
      <div style="text-align:center;margin-bottom:32px;">
        <svg width="100%" viewBox="0 0 180 80" height="100%">
          <rect width="180" height="80" rx="12" fill="var(--primary)" fill-opacity="0.1"/>
          <text x="90" y="58" font-family="'Orbitron',sans-serif" font-size="40" font-weight="900" fill="var(--primary)" text-anchor="middle">SulgX</text>
        </svg>
        <div style="font-family:'Orbitron',sans-serif;font-size:1.5rem;font-weight:900;color:var(--primary);margin-top:12px;display:flex;align-items:center;justify-content:center;gap:8px;">
          SulgX Panel <span style="font-size:0.8rem; font-family:'Inter'; color:var(--bg); background:var(--primary); padding:2px 6px; border-radius:4px;">V 1.5.3</span>
        </div>
        <div style="font-size:1rem;color:var(--text3);margin-top:8px;" data-en="Enter your password" data-fa="رمز عبور را وارد کنید">Enter your password</div>
        <div id="login-custom-message" style="margin-top:20px; text-align:center; color:var(--text3); font-size:0.9rem;"></div>
      </div>
      <div class="fg"><label class="fl">PASSWORD</label><input class="fi" type="password" id="login-pw" placeholder="••••••••" onkeydown="if(event.key==='Enter')doLogin()"></div>
      <button class="btn btn-primary" onclick="doLogin()" style="width:100%;justify-content:center;padding:14px;margin-top:16px;">LOGIN</button>
      <div id="login-err" style="color:var(--red);font-size:0.9rem;margin-top:10px;text-align:center;display:none">Invalid password</div>
      <div style="margin-top:20px; text-align:center; display:flex; justify-content:center; gap:20px;">
        <a href="https://github.com/SulgX" target="_blank" style="color:var(--text3); text-decoration:none; font-size:0.9rem;">🐙 GitHub</a>
        <a href="https://t.me/SulgX" target="_blank" style="color:var(--text3); text-decoration:none; font-size:0.9rem;">📨 Telegram</a>
      </div>
    </div>
  </div>
</div>
<div id="dashboard-page" style="display:none;width:100%">
  <header class="header">
    <div class="header-inner">
      <div style="display:flex;align-items:center;gap:16px;">
        <span class="logo">SulgX</span><span class="version-tag">v1.5.3</span>
        <span id="panel-clock" style="font-weight:600;color:var(--primary);margin-left:8px;font-size:0.9rem;"></span>
        <nav class="header-nav" id="mainNav">
          <button class="nav-link active" data-page="dashboard">📊 <span data-en="Dashboard" data-fa="داشبورد">Dashboard</span></button>
          <button class="nav-link" data-page="inbounds">📡 <span data-en="Inbounds" data-fa="اینباندها">Inbounds</span></button>
          <button class="nav-link" data-page="addresses">🔗 <span data-en="Clean IP" data-fa="آی‌پی تمیز">Clean IP</span></button>
          <button class="nav-link" data-page="ipscanner">🔍 <span data-en="IP Scanner" data-fa="اسکنر آی‌پی">IP Scanner</span></button>
          <button class="nav-link" data-page="logs">📋 <span data-en="Logs" data-fa="لاگ‌ها">Logs</span></button>
          <button class="nav-link" data-page="telegram">🤖 <span data-en="Telegram" data-fa="تلگرام">Telegram</span></button>
          <button class="nav-link" data-page="settings">⚙️ <span data-en="Settings" data-fa="تنظیمات">Settings</span></button>
        </nav>
      </div>
      <div class="header-right">
  <button class="btn-icon" onclick="showQuickAdd()" title="Quick Add" data-en-title="Quick Add" data-fa-title="ساخت سریع">➕</button>
  <div class="lang-switch">
    <button class="lang-btn lang-en active" onclick="setLang('en')">EN</button>
    <button class="lang-btn lang-fa" onclick="setLang('fa')">FA</button>
  </div>
  <button class="btn-icon" id="theme-toggle-btn" onclick="toggleTheme()">🌙</button>
  <button class="btn-icon btn-danger-icon" onclick="doLogout()" title="Logout" data-en-title="Logout" data-fa-title="خروج">🚪</button>
</div>
  </header>
  <main class="main">
    <section class="page active" id="page-dashboard">
      <div class="page-header"><div><div class="page-title" data-en="Dashboard" data-fa="داشبورد">Dashboard</div><div class="page-sub" id="last-up">–</div></div></div>
      <div class="stats-row">
        <div class="stat-card"><div class="stat-label" data-en="Traffic" data-fa="ترافیک">Traffic</div><div class="stat-val" id="sv-traffic">–<span class="stat-unit"> MB</span></div></div>
        <div class="stat-card"><div class="stat-label" data-en="Requests" data-fa="درخواست‌ها">Requests</div><div class="stat-val" id="sv-requests">–</div></div>
        <div class="stat-card"><div class="stat-label" data-en="Uptime" data-fa="آپتایم">Uptime</div><div class="stat-val" id="sv-uptime" style="font-size:1.2rem;">–</div></div>
        <div class="stat-card"><div class="stat-label" data-en="Disk Free" data-fa="فضای دیسک">Disk Free</div><div class="stat-val" id="sv-disk">–<span class="stat-unit"> GB</span></div></div>
      </div>
      <div class="stats-row">
        <div class="stat-card"><div class="stat-label" data-en="Download Speed" data-fa="سرعت دانلود">Download Speed</div><div class="stat-val" id="sv-down-speed">–<span class="stat-unit"> KB/s</span></div></div>
        <div class="stat-card"><div class="stat-label" data-en="Upload Speed" data-fa="سرعت آپلود">Upload Speed</div><div class="stat-val" id="sv-up-speed">–<span class="stat-unit"> KB/s</span></div></div>
        <div class="stat-card"><div class="stat-label" data-en="Monthly Usage" data-fa="مصرف ماهانه">Monthly Usage</div><div class="stat-val" id="sv-monthly">–<span class="stat-unit"> GB</span></div></div>
        <div class="stat-card" style="font-size:0.8rem;">
          <div class="stat-label" data-en="Settings Status" data-fa="وضعیت تنظیمات">Settings Status</div>
          <div class="status-cards-grid" id="settings-status">
            <div class="status-glass-card inactive" id="st-log" data-en="Logging" data-fa="لاگ">📝 Logging</div>
            <div class="status-glass-card inactive" id="st-auto" data-en="Auto Disable" data-fa="غیرفعال‌سازی">🚫 Auto Disable</div>
            <div class="status-glass-card inactive" id="st-tgrep" data-en="TG Reports" data-fa="گزارش تلگرام">📊 TG Reports</div>
            <div class="status-glass-card inactive" id="st-tgnot" data-en="TG Notify" data-fa="اعلان تلگرام">🔔 TG Notify</div>
            <div class="status-glass-card inactive" id="st-bot" data-en="Bot" data-fa="ربات">🤖 Bot</div>
            <div class="status-glass-card inactive" id="st-stealth" data-en="Stealth" data-fa="استتار">🥷 Stealth</div>
          </div>
        </div>
      </div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
        <div class="card"><div class="card-hd"><span class="card-title" data-en="CPU" data-fa="پردازنده">CPU</span><span id="cpu-v" style="font-weight:700;color:var(--primary);">–%</span></div><div class="sys-bar"><div class="sys-fill" id="cpu-b" style="background:var(--primary);width:0%"></div></div></div>
        <div class="card"><div class="card-hd"><span class="card-title" data-en="Memory" data-fa="حافظه">Memory</span><span id="mem-v" style="font-weight:700;color:var(--green);">–%</span></div><div class="sys-bar"><div class="sys-fill" id="mem-b" style="background:var(--green);width:0%"></div></div></div>
      </div>
      <div class="card"><div class="card-hd"><span class="card-title" data-en="Hourly Traffic" data-fa="ترافیک ساعتی">Hourly Traffic</span></div><div class="chart-container"><canvas id="tc"></canvas></div></div>
      <div class="card"><div class="card-hd"><span class="card-title" data-en="Usage Distribution" data-fa="توزیع مصرف">Usage Distribution</span></div><div class="chart-container"><canvas id="doughnut-chart"></canvas></div></div>
      <div class="card"><div class="card-hd"><span class="card-title" data-en="Live Speed" data-fa="سرعت زنده">Live Speed</span></div><div class="chart-container"><canvas id="speed-chart"></canvas></div></div>
      <div class="card">
  <div class="card-hd">
    <span class="card-title" data-en="Recent Activity" data-fa="فعالیت‌های اخیر">Recent Activity</span>
    <button class="btn btn-danger btn-sm" onclick="clearRecentActivity()" data-en="Clear" data-fa="پاک‌سازی">Clear</button>
  </div>
  <div class="logs-table-container" style="overflow-x: auto; -webkit-overflow-scrolling: touch;">
    <table class="tbl" id="login-logs-table">
      <thead>
        <tr>
          <th class="time-col" data-en="Time" data-fa="زمان">Time</th>
          <th data-en="User" data-fa="کاربر">User</th>
          <th data-en="Country" data-fa="کشور">Country</th>
          <th data-en="ISP" data-fa="ارائه دهنده">ISP</th>
          <th data-en="Status" data-fa="وضعیت">Status</th>
        </tr>
      </thead>
      <tbody id="login-logs-tbody"></tbody>
    </table>
  </div>
</div>
    </section>
    <section class="page" id="page-inbounds">
      <div class="page-header">
        <div><div class="page-title" data-en="Inbounds" data-fa="اینباندها">Inbounds</div><div class="page-sub" data-en="Manage VLESS Configs" data-fa="مدیریت کانفیگ‌های VLESS">Manage VLESS Configs</div></div>
        <div style="display:flex;gap:6px;">
          <button class="btn btn-primary" onclick="showAddMo()" data-en="+ Create" data-fa="+ ایجاد">+ Create</button>
          <button class="btn btn-outline btn-sm" onclick="exportLinks()" data-en="Export" data-fa="خروجی">Export</button>
          <button class="btn btn-outline btn-sm" onclick="document.getElementById('import-file').click()" data-en="Import" data-fa="ورودی">Import</button>
          <input type="file" id="import-file" style="display:none" accept=".json" onchange="importLinks(this)">
        </div>
      </div>
      <div style="display:flex;gap:10px;margin-bottom:16px;">
        <input id="srch" placeholder="Search…" oninput="filterLinks()" class="fi" style="flex:1;">
        <button class="chip active" data-filter="all" data-en="All" data-fa="همه" onclick="setFilter('all',this)">All</button>
        <button class="chip" data-filter="active" data-en="Active" data-fa="فعال" onclick="setFilter('active',this)">Active</button>
        <button class="chip" data-filter="off" data-en="Off" data-fa="خاموش" onclick="setFilter('off',this)">Off</button>
      </div>
      <div style="display:flex;gap:6px;margin-bottom:10px;">
        <button class="btn btn-outline btn-sm" onclick="batchAction('activate')" data-en="Activate Selected" data-fa="فعال‌سازی انتخاب">Activate Selected</button>
        <button class="btn btn-outline btn-sm" onclick="batchAction('deactivate')" data-en="Deactivate Selected" data-fa="غیرفعال‌سازی انتخاب">Deactivate Selected</button>
        <button class="btn btn-outline btn-sm" onclick="batchAction('reset_usage')" data-en="Reset Usage Selected" data-fa="بازنشانی مصرف انتخاب">Reset Usage Selected</button>
        <button class="btn btn-danger btn-sm" onclick="batchAction('delete')" data-en="Delete Selected" data-fa="حذف انتخاب">Delete Selected</button>
      </div>
      <div class="card" style="padding:0;overflow:hidden;">
        <div class="tbl-wrap">
        <table class="tbl" id="inbound-table"><thead><tr><th><input type="checkbox" id="select-all" onchange="toggleSelectAll()"></th><th data-sort="label" onclick="sortLinks('label')"><span data-en="Name" data-fa="نام">Name</span> ↕</th><th data-en="Type" data-fa="نوع">Type</th><th data-sort="used_bytes" onclick="sortLinks('used_bytes')"><span data-en="Usage" data-fa="مصرف">Usage</span> ↕</th><th data-en="Conns" data-fa="اتصالات">Conns</th><th data-sort="expires_at" onclick="sortLinks('expires_at')"><span data-en="Expiry" data-fa="انقضا">Expiry</span> ↕</th><th data-en="Status" data-fa="وضعیت">Status</th><th data-en="Actions" data-fa="عملیات">Actions</th></tr></thead><tbody id="ltb"></tbody></table></div>
        <div class="empty" id="lempty" style="display:none;padding:30px;">No inbounds found</div>
      </div>
    </section>
    <section class="page" id="page-addresses">
      <div class="page-header"><div class="page-title" data-en="Clean IP" data-fa="آی‌پی تمیز">Clean IP</div></div>
      <div id="profile-tabs" class="pill-group" style="margin-bottom:12px; overflow-x:auto; white-space:nowrap;">
        <button class="pill-btn active" data-profile="all" onclick="switchProfileView('all')">All</button>
      </div>
      <div class="card" id="addresses-card">
        <div class="fg"><label class="fl" data-en="Add Addresses (one per line)" data-fa="افزودن آدرس (هر خط یک)">Add Addresses (one per line)</label><textarea class="fi" id="batch-addrs" rows="4" placeholder="8.8.8.8
example.com"></textarea></div>
        <div style="display:flex; gap:6px; margin-bottom:12px;">
          <button class="btn btn-primary" onclick="addBatchAddrs()" data-en="Add All" data-fa="افزودن همه">Add All</button>
          <button class="btn btn-danger btn-sm" onclick="deleteAllAddrs()" data-en="Delete All" data-fa="حذف همه">Delete All</button>
          <button class="btn btn-danger btn-sm" onclick="bulkDeleteAddrs()" data-en="Delete Selected" data-fa="حذف انتخاب‌شده">Delete Selected</button>
          <button class="btn btn-outline btn-sm" onclick="toggleAllAddresses()" data-en="Select All" data-fa="انتخاب همه">Select All</button>
          <button class="btn btn-outline btn-sm" onclick="copySelectedAddrs()" data-en="📋 Copy Selected" data-fa="📋 کپی انتخاب‌ها">📋 Copy Selected</button>
          <input type="file" id="import-ip-file" accept=".txt" style="display:none" onchange="importIpFile(this)">
          <button class="btn btn-outline btn-sm" onclick="document.getElementById('import-ip-file').click()" data-en="Import .txt" data-fa="ورودی فایل">Import .txt</button>
          <button class="btn btn-outline btn-sm" onclick="resolveAllFlags()" data-en="Resolve All Flags" data-fa="دریافت همه پرچم‌ها">Resolve All Flags</button>
        </div>
        <div class="addr-list-scroll" id="addr-list" style="margin-top:16px;"></div>
      </div>
      <div class="card" style="margin-top:16px;">
        <div class="card-hd"><span class="card-title" data-en="IP Profiles" data-fa="پروفایل‌های آی‌پی">IP Profiles</span></div>
        <div class="status-cards-grid" id="ip-profiles-list"></div>
        <div style="display:flex; gap:6px; margin-top:8px;">
          <input class="fi" id="new-profile-name" placeholder="Profile name" style="flex:1;">
          <button class="btn btn-primary btn-sm" onclick="createIpProfile()" data-en="Create" data-fa="ایجاد">Create</button>
        </div>
      </div>
    </section>
    <section class="page" id="page-ipscanner">
      <div class="page-header"><div class="page-title" data-en="IP Scanner" data-fa="اسکنر آی‌پی">IP Scanner</div></div>
      <div style="background: rgba(251,191,36,0.1); border: 1px solid rgba(251,191,36,0.3); color: var(--yellow); padding: 10px 14px; border-radius: 10px; margin-bottom: 14px; font-size: 0.8rem; line-height: 1.4;">
        <strong data-en="⚠️ Safe Scan Notice:" data-fa="⚠️ هشدار اسکن ایمن:">⚠️ Safe Scan Notice:</strong><br>
        <span data-en="To prevent your hosting provider (like Railway/Render) from banning your account due to abuse detection, scans are strictly limited to 256 IPs at a time. The scanning process is intentionally slowed down." data-fa="برای جلوگیری از مسدود شدن اکانت هاستینگ شما (مثل Railway/Render) به دلیل تشخیص اسپم، اسکن‌ها به‌طور سخت‌گیرانه‌ای به حداکثر ۲۵۶ آی‌پی در هر بار محدود شده‌اند. روند اسکن به‌طور عمدی کندتر شده تا امنیت سرور حفظ شود."></span>
        <div id="railway-note" style="display:none; margin-top:8px; color: #d8b4fe;"><span data-en="ℹ️ Note: For Railway provider, only Railway-related IPs will work." data-fa="نکته: در ارائه دهنده railway فقط آیپی های مربوط به آن کار خواهد کرد."></span></div>
      </div>
      <div class="card">
        <div class="fg"><label class="fl" data-en="Provider" data-fa="ارائه‌دهنده">Provider</label><div id="provider-btns" class="pill-group"></div></div>
        <div class="fg" id="range-section" style="display:none;"><label class="fl" data-en="Ranges" data-fa="رنج‌ها">Ranges</label><div id="range-btns" class="pill-group"></div></div>
        <div class="fg"><label class="fl" data-en="IPs / Domains / CIDR Ranges (one per line)" data-fa="آی‌پی‌ها / دامنه‌ها / رنج‌های CIDR (هر خط یک)">IPs / Domains / CIDR Ranges (one per line)</label><textarea class="fi" id="scan-ips" rows="5" placeholder="8.8.8.8
example.com
192.168.1.0/24"></textarea></div>
        <div style="display:flex;gap:6px;">
          <button class="btn btn-primary" id="scan-start-btn" onclick="startIPScan()" data-en="Scan (port 443)" data-fa="اسکن (پورت ۴۴۳)">Scan (port 443)</button>
          <button class="btn btn-danger btn-sm" id="scan-stop-btn" onclick="stopScan()" style="display:none;" data-en="Stop" data-fa="توقف">Stop</button>
        </div>
        <div class="fg" style="margin-bottom:10px;"><div style="display:flex;align-items:center;gap:8px;"><div class="sys-bar" style="flex:1; height:6px;"><div id="scan-progress" class="sys-fill" style="width:0%; background:var(--primary);"></div></div><span id="progress-text" style="font-size:0.8rem; color:var(--text3);">0%</span></div></div>
        <div class="scanner-location-filter" id="location-filter" style="display:none; flex-wrap:wrap; gap:6px; align-items:center;">
          <span style="color:var(--text3); font-size:0.8rem;">Location:</span>
          <div id="location-checkboxes" style="display:flex; flex-wrap:wrap; gap:4px;"></div>
          <button class="btn btn-outline btn-sm" onclick="resetLocationFilter()">Show All</button>
        </div>
        <div class="scan-results-container" style="margin-top:8px;">
          <table class="tbl scanner-tbl"><thead><tr><th data-en="Address" data-fa="آدرس">Address</th><th data-en="Status" data-fa="وضعیت">Status</th><th>TCP</th><th>HTTPS</th><th>Location</th></tr></thead><tbody id="scan-tbody"></tbody></table>
        </div>
        <div style="display:flex;gap:6px;margin-top:8px;">
          <button class="btn btn-outline btn-sm" onclick="sortBestIPs()" data-en="⭐ Sort Best IPs" data-fa="⭐ مرتب‌سازی بهترین‌ها">⭐ Sort Best IPs</button>
          <button class="btn btn-outline btn-sm" onclick="copyReachableSorted()" data-en="📋 Copy Reachable (sorted)" data-fa="📋 کپی قابل دسترس (مرتب)">📋 Copy Reachable (sorted)</button>
          <button class="btn btn-primary btn-sm" onclick="createProfileFromReachable()" data-en="💾 Save as Profile" data-fa="💾 ذخیره به‌عنوان پروفایل">💾 Save as Profile</button>
        </div>
      </div>
    </section>
    <section class="page" id="page-logs">
      <div class="page-header"><div class="page-title" data-en="Logs" data-fa="لاگ‌ها">Logs</div></div>
      <div style="display:flex;gap:10px;margin-bottom:16px;">
        <input id="log-search" placeholder="Search logs…" oninput="filterLogs()" class="fi" style="flex:1;">
        <button class="btn btn-outline btn-sm" onclick="clearLogSearch()">✕</button>
      </div>
      <div class="card" style="padding:0;overflow:hidden;">
        <div class="logs-table-container">
          <table class="tbl">
            <thead><tr><th>#</th><th data-en="Time (UTC)" data-fa="زمان (UTC)">Time (UTC)</th><th data-en="Type" data-fa="نوع">Type</th><th data-en="Event" data-fa="رویداد">Event</th></tr></thead>
            <tbody id="logs-tbody"></tbody>
          </table>
        </div>
        <div class="empty" id="logs-empty" style="display:none;padding:30px;">No events recorded</div>
      </div>
      <div style="display:flex;gap:6px;margin-top:8px;">
        <button class="btn btn-outline btn-sm" onclick="refreshLogs()" data-en="🔄 Refresh" data-fa="🔄 بروزرسانی">🔄 Refresh</button>
        <button class="btn btn-outline btn-sm" onclick="fetchLogSize()" data-en="📏 Log Size" data-fa="📏 حجم لاگ">📏 Log Size</button>
        <button class="btn btn-danger btn-sm" onclick="clearLogs()" data-en="🗑️ Clear Logs" data-fa="🗑️ پاک‌سازی لاگ‌ها">🗑️ Clear Logs</button>
      </div>
    </section>
    <section class="page" id="page-telegram">
      <div class="page-header"><div class="page-title" data-en="Telegram Bot" data-fa="ربات تلگرام">Telegram Bot</div></div>
      <div class="card">
        <div class="fg"><label class="fl" data-en="Bot Token" data-fa="توکن ربات">Bot Token</label><input class="fi" id="tg-token"></div>
        <div class="fg"><label class="fl" data-en="Chat ID" data-fa="شناسه چت">Chat ID</label><input class="fi" id="tg-chat-id"></div>
        <div class="fg"><label class="fl" data-en="Notify Events" data-fa="رویدادهای اطلاع‌رسانی">Notify Events</label>
          <div style="display:flex;flex-wrap:wrap;gap:6px;">
            <label><input type="checkbox" value="quota_90" class="tg-event"> <span data-en="Quota 90%" data-fa="کوتا ۹۰٪">Quota 90%</span></label>
            <label><input type="checkbox" value="login" class="tg-event"> <span data-en="Login" data-fa="ورود">Login</span></label>
            <label><input type="checkbox" value="expiry" class="tg-event"> <span data-en="Expiry" data-fa="انقضا">Expiry</span></label>
            <label><input type="checkbox" value="error" class="tg-event"> <span data-en="Error" data-fa="خطا">Error</span></label>
          </div>
          <small style="color:var(--text3); font-size:0.75rem; display:block; margin-top:4px;"
                 data-en="These events trigger instant alerts, not the periodic stats report."
                 data-fa="این رویدادها فقط برای هشدارهای لحظه‌ای هستند و روی گزارش دوره‌ای تأثیری ندارند.">
            These events trigger instant alerts, not the periodic stats report.
          </small>
        </div>
        <div class="fg"><label class="fl" data-en="Report Interval (hours)" data-fa="فاصله گزارش (ساعت)">Report Interval (hours)</label><input class="fi" type="number" id="tg-interval" value="1" min="0.5" step="0.5"></div>
        <div class="fg"><label class="fl">Telegram Language</label>
          <div class="toggle on" id="tg-lang-toggle" onpointerdown="toggleTgLang()"></div>
          <span id="tg-lang-label">English</span>
          <input type="hidden" id="tg-lang-hidden" value="en">
        </div>
        <div class="fg"><label class="fl">Custom Templates (EN)</label>
          <textarea class="fi" id="tg-templates-en" rows="4">{"quota_90":"⚠️ {label} ({uid}) used 90% of quota","login":"🔐 SulgX Panel login\n🌐 IP: {ip}\n🤖 UA: {ua}\n📅 {time}","expiry":"⏰ {label} expired","error":"❌ Error on {label}: check logs"}</textarea>
        </div>
        <div class="fg"><label class="fl">Custom Templates (FA)</label>
          <textarea class="fi" id="tg-templates-fa" rows="4">{"quota_90":"⚠️ {label} ({uid}) ۹۰٪ کوتا","login":"🔐 ورود SulgX\n🌐 IP: {ip}\n🤖 UA: {ua}\n📅 {time}","expiry":"⏰ {label} منقضی شد","error":"❌ خطا در {label}: بررسی شود"}</textarea>
        </div>
        <div style="margin:6px 0;">
          <button class="btn btn-outline btn-sm" onclick="previewTemplate()">Preview</button>
          <div id="tg-preview" style="margin-top:6px; padding:8px; background:var(--surface3); border-radius:8px; white-space:pre-wrap;"></div>
        </div>
        <div style="display:flex;gap:6px;"><button class="btn btn-primary" onclick="saveTelegramSettings()" data-en="Save" data-fa="ذخیره">Save</button><button class="btn btn-outline btn-sm" onclick="testTelegram()" data-en="Test" data-fa="تست">Test</button></div>
      </div>
    </section>
    <section class="page" id="page-settings">
      <div class="page-header"><div class="page-title" data-en="Settings" data-fa="تنظیمات">Settings</div></div>
      <div class="card">
        <div class="fg"><label class="fl" data-en="Login Text" data-fa="متن ورود">Login Text</label><input class="fi" id="set-footer"></div>
        <div class="fg"><label class="fl" data-en="Default Path" data-fa="مسیر پیش‌فرض">Default Path</label><input class="fi" id="set-default-path" placeholder="/ws/{uid}"></div>
        <div class="fg">
          <label class="fl" data-en="Timezone / Region" data-fa="منطقه زمانی / ساعت">Timezone / Region</label>
          <div class="glass-btn-group" id="tz-glass-group">
            <button type="button" class="glass-btn active" id="btn-tz-utc" onclick="setPanelTZ(0, 'UTC')">UTC (00:00)</button>
            <button type="button" class="glass-btn" id="btn-tz-tehran" onclick="setPanelTZ(3.5, 'Tehran')">Tehran (+3:30)</button>
            <button type="button" class="glass-btn" id="btn-tz-custom" onclick="toggleCustomTZInput(true)">Custom</button>
          </div>
          <div id="custom-tz-container" style="display:none; margin-top:10px;">
            <input type="text" class="fi" id="custom-tz-value" placeholder="e.g. Asia/Tehran or +3.5" oninput="applyCustomTZ(this.value)">
          </div>
        </div>
        <div class="fg">
          <label class="fl" data-en="Interface Theme" data-fa="تم محیط کاربری">Interface Theme</label>
          <div class="glass-btn-group" id="theme-glass-group">
            <button type="button" class="glass-btn active" id="btn-theme-dark" onclick="setPanelTheme('dark')">Dark</button>
            <button type="button" class="glass-btn" id="btn-theme-light" onclick="setPanelTheme('light')">Light</button>
            <button type="button" class="glass-btn" id="btn-theme-blue-dark" onclick="setPanelTheme('blue-dark')">Blue</button>
          </div>
          <input type="hidden" id="set-theme-color" value="dark">
        </div>
        <div class="fg">
          <label class="fl" data-en="Panel Language" data-fa="زبان پنل">Panel Language</label>
          <div class="glass-btn-group" id="lang-glass-group">
            <button type="button" class="glass-btn active" id="btn-lang-en" onclick="setPanelLanguage('en')">English</button>
            <button type="button" class="glass-btn" id="btn-lang-fa" onclick="setPanelLanguage('fa')">فارسی</button>
          </div>
        </div>
        <div class="fg"><label class="fl" data-en="Keep Alive" data-fa="ضدخواب">Keep Alive</label>
          <div class="glass-btn-group" id="keepalive-mode-group">
            <button type="button" class="glass-btn active" id="btn-keepalive-simple" onclick="setKeepAliveMode('simple')">Simple</button>
            <button type="button" class="glass-btn" id="btn-keepalive-advanced" onclick="setKeepAliveMode('advanced')">Advanced</button>
          </div>
          <input type="hidden" id="set-keepalive-mode" value="simple">
          <div class="status-cards-grid" style="margin-top:8px;">
            <div class="status-glass-card active" id="card-keepalive" onclick="toggleSettingCard('card-keepalive', 'set-keepalive-enabled')">
              <span style="font-size:1.5rem;">⚡</span><span data-en="Keep-Alive Enabled" data-fa="ضدخواب فعال">Keep-Alive</span>
              <input type="hidden" id="set-keepalive-enabled" value="1">
            </div>
          </div>
        </div>
        <div class="fg"><label class="fl" data-en="Keep Alive Interval (seconds)" data-fa="فاصله ضدخواب (ثانیه)">Interval</label>
          <input class="fi" type="number" id="set-keep-alive-interval" placeholder="300" min="60">
        </div>
        <div class="fg"><label class="fl" data-en="Default Traffic Limit (GB)" data-fa="محدودیت ترافیک پیش‌فرض (گیگابایت)">Default Traffic Limit (GB)</label><input class="fi" type="number" id="set-default-limit" placeholder="0 = Unlimited"></div>
        <div class="fg"><label class="fl" data-en="Default Expiry (Days)" data-fa="انقضای پیش‌فرض (روز)">Default Expiry (Days)</label><input class="fi" type="number" id="set-default-expiry" placeholder="0 = Unlimited"></div>
        <div class="fg"><label class="fl" data-en="Default Max Connections" data-fa="حداکثر اتصالات پیش‌فرض">Default Max Connections</label><input class="fi" type="number" id="set-default-maxconn" placeholder="0 = Unlimited"></div>
        <div class="fg"><label class="fl" data-en="Scanner Timeout (seconds)" data-fa="تایم‌اوت اسکنر (ثانیه)">Scanner Timeout (seconds)</label><input class="fi" type="number" id="set-scanner-timeout" placeholder="4"></div>
        <div class="fg"><label class="fl" data-en="Max Scan IPs" data-fa="حداکثر آی‌پی اسکن">Max Scan IPs</label><input class="fi" type="number" id="set-max-scan-ips" placeholder="256"></div>
        <div class="fg"><label class="fl" data-en="Monthly Limit (GB)" data-fa="محدودیت ماهانه (گیگابایت)">Monthly Limit (GB)</label><input class="fi" type="number" id="set-monthly-limit" placeholder="0 = Unlimited"></div>
        <div class="fg">
          <label class="fl" data-en="DoH Upstreams" data-fa="Upstreamهای DoH">DoH Upstreams</label>
          <div class="pill-group" id="doh-presets"></div>
          <div style="margin-top: 8px;">
            <button class="btn btn-outline btn-sm" onclick="testDohPing()">Test Ping</button>
            <table class="tbl" id="doh-ping-table" style="display:none; margin-top:8px;">
                <thead><tr><th>Upstream</th><th>Latency</th><th>Status</th></tr></thead>
                <tbody></tbody>
            </table>
          </div>
          <input class="fi" id="custom-doh-input" placeholder="Custom upstream URL" style="margin-top:6px;">
          <button class="btn btn-outline btn-sm" onclick="addCustomDoh()">Add</button>
          <div class="status-cards-grid" style="margin-top:8px;">
            <div class="status-glass-card active" id="card-doh" onclick="toggleSettingCard('card-doh', 'set-doh-enabled')">
              <span style="font-size:1.5rem;">🌐</span><span data-en="DoH Enabled" data-fa="DoH فعال">DoH</span>
              <input type="hidden" id="set-doh-enabled" value="1">
            </div>
          </div>
          <div style="margin-top:12px;">
            <label class="fl" style="font-size:0.7rem;" data-en="Server DoH Endpoint" data-fa="خروجی DoH سرور">Server DoH Endpoint</label>
            <div style="display:flex; gap:6px; align-items:center;">
              <input class="fi" id="doh-endpoint-url" readonly style="flex:1; cursor:pointer;" onclick="this.select()" value="">
              <button class="btn btn-outline btn-sm" onclick="copyDohEndpoint()" style="white-space:nowrap;" data-en="Copy" data-fa="کپی">Copy</button>
            </div>
          </div>
        </div>
        <div class="fg" style="margin-top:10px; padding:15px; background:rgba(251,191,36,0.05); border:1px solid rgba(251,191,36,0.3); border-radius:16px;">
          <label class="fl" style="color:var(--yellow);" data-en="Anti-Abuse & Stealth" data-fa="ضد ابیوز و استتار">Anti-Abuse & Stealth</label>
          <div class="status-cards-grid" style="margin-bottom:10px;">
            <div class="status-glass-card inactive" id="card-stealth" onclick="toggleSettingCard('card-stealth', 'set-stealth-mode')">
              <span style="font-size:1.5rem;">🥷</span><span data-en="Stealth Mode" data-fa="حالت استتار (مخفی‌سازی اسکنر)">Stealth Mode</span>
              <input type="hidden" id="set-stealth-mode" value="0">
            </div>
          </div>
          <label class="fl" style="font-size:0.7rem; margin-top:8px;" data-en="Landing Redirect (e.g. https://google.com)" data-fa="تغییر مسیر فرود (مثلاً https://google.com)">Landing Redirect (e.g. https://google.com)</label>
          <input class="fi" id="set-landing-redirect" placeholder="Redirect unauthorized users">
          <label class="fl" style="font-size:0.7rem; margin-top:8px;" data-en="Camouflage URL (Reverse Proxy)" data-fa="آدرس استتار (پروکسی معکوس)">Camouflage URL (Reverse Proxy)</label>
          <input class="fi" id="set-camouflage-url" placeholder="e.g. https://news.ycombinator.com">
          <label class="fl" style="font-size:0.7rem; margin-top:8px;" data-en="Subscription Filename" data-fa="نام فایل اشتراک">Subscription Filename</label>
          <input class="fi" id="set-sub-filename" placeholder="e.g. update.txt">
          <label class="fl" style="font-size:0.7rem; margin-top:8px;" data-en="Panel Prefix (Hidden Admin Path)" data-fa="پیشوند پنل (مسیر مخفی ادمین)">Panel Prefix (Hidden Admin Path)</label>
          <input class="fi" id="set-panel-prefix" placeholder="e.g. mypanel (leave empty for root)">
          <div class="fg" style="margin-top:12px;">
            <label class="fl" data-en="Blocked Domains (one per line)" data-fa="دامنه‌های مسدود (هر خط یک)">Blocked Domains (one per line)</label>
            <textarea class="fi" id="set-blocked-domains" rows="4" placeholder="example.com
*.ads.com"></textarea>
            <button class="btn btn-outline btn-sm" onclick="saveBlockedDomains()" data-en="Save" data-fa="ذخیره">Save</button>
          </div>
        </div>
        <div class="fg" style="margin-top:20px;">
          <label class="fl" data-en="System Toggles" data-fa="وضعیت تنظیمات">System Toggles</label>
          <div class="status-cards-grid">
            <div class="status-glass-card active" id="card-log" onclick="toggleSettingCard('card-log', 'set-log-toggle')">
              <span style="font-size:1.5rem;">📝</span><span data-en="Logs" data-fa="لاگ سیستم">Logs</span>
              <input type="hidden" id="set-log-toggle" value="1">
            </div>
            <div class="status-glass-card active" id="card-auto" onclick="toggleSettingCard('card-auto', 'set-auto-disable')">
              <span style="font-size:1.5rem;">🚫</span><span data-en="Auto Disable" data-fa="غیرفعال‌سازی">Auto Disable</span>
              <input type="hidden" id="set-auto-disable" value="1">
            </div>
            <div class="status-glass-card active" id="card-tgrep" onclick="toggleSettingCard('card-tgrep', 'set-tg-report')">
              <span style="font-size:1.5rem;">📊</span><span data-en="TG Reports" data-fa="گزارش تلگرام">TG Reports</span>
              <input type="hidden" id="set-tg-report" value="1">
            </div>
            <div class="status-glass-card active" id="card-tgnot" onclick="toggleSettingCard('card-tgnot', 'set-tg-notify')">
              <span style="font-size:1.5rem;">🔔</span><span data-en="TG Alerts" data-fa="اعلان تلگرام">TG Alerts</span>
              <input type="hidden" id="set-tg-notify" value="1">
            </div>
          </div>
        </div>
        <hr style="border-color:var(--border);margin:14px 0;">
        <div class="mo-title" data-en="Change Password" data-fa="تغییر رمز عبور" style="margin-bottom:14px;">Change Password</div>
        <div class="fg"><label class="fl" data-en="Current Password" data-fa="رمز فعلی">Current Password</label><input class="fi" type="password" id="cpw"></div>
        <div class="fg"><label class="fl" data-en="New Password" data-fa="رمز جدید">New Password</label><input class="fi" type="password" id="npw"></div>
        <button class="btn btn-primary btn-sm" onclick="chgPw()" data-en="Update Password" data-fa="بروزرسانی رمز">Update Password</button>
        <div style="margin-top:16px;">
          <button class="btn btn-primary" onclick="saveGeneralSettings()" data-en="Save All Settings" data-fa="ذخیره همه تنظیمات" style="width:100%; justify-content:center; padding:12px;">Save All Settings</button>
        </div>
        <hr style="border-color:var(--border);margin:14px 0;">
        <div style="display:flex;align-items:center;gap:10px;">
          <button class="btn btn-danger" onclick="resetAllSettings()" data-en="Reset to Defaults" data-fa="بازنشانی به پیش‌فرض">Reset to Defaults</button>
          <span style="font-size:0.8rem;color:var(--text3);" data-en="Resets all settings except password." data-fa="همه تنظیمات به جز رمز عبور بازنشانی می‌شود."></span>
        </div>
      </div>
    </section>
  </main>
  <nav class="mobile-nav">
    <div class="nav-items">
      <div class="nav-item active" data-page="dashboard" onclick="switchPage('dashboard')"><span class="nav-icon">📊</span><span data-en="Home" data-fa="خانه">Home</span></div>
      <div class="nav-item" data-page="inbounds" onclick="switchPage('inbounds')"><span class="nav-icon">📡</span><span data-en="Inbound" data-fa="اینباند">Inbound</span></div>
      <div class="nav-item" data-page="addresses" onclick="switchPage('addresses')"><span class="nav-icon">🔗</span><span data-en="Clean IP" data-fa="آی‌پی تمیز">Clean IP</span></div>
      <div class="nav-item" data-page="ipscanner" onclick="switchPage('ipscanner')"><span class="nav-icon">🔍</span><span data-en="Scan" data-fa="اسکن">Scan</span></div>
      <div class="nav-item" data-page="logs" onclick="switchPage('logs')"><span class="nav-icon">📋</span><span data-en="Logs" data-fa="لاگ">Logs</span></div>
      <div class="nav-item" data-page="telegram" onclick="switchPage('telegram')"><span class="nav-icon">🤖</span><span data-en="Bot" data-fa="ربات">Bot</span></div>
      <div class="nav-item" data-page="settings" onclick="switchPage('settings')"><span class="nav-icon">⚙️</span><span data-en="Settings" data-fa="تنظیمات">Settings</span></div>
    </div>
  </nav>
  <footer class="footer">
    <div class="footer-inner">
      <span id="footer-dedication"></span>
      <a href="https://t.me/SulgX" target="_blank">Telegram</a>
      <a href="https://github.com/SulgX" target="_blank">GitHub</a>
      <a href="https://github.com/SulgX/SulgX-Panel" target="_blank">Project Repo</a>
    </div>
  </footer>
</div>
<!-- modals -->
<div class="mo" id="mo-add">
  <div class="mo-box">
    <button class="mo-close" onclick="document.getElementById('mo-add').classList.remove('show')">✕</button>
    <div class="mo-title" data-en="Create Inbound" data-fa="ایجاد اینباند">Create Inbound</div>
    <div class="fg"><label class="fl" data-en="Name" data-fa="نام">Name</label><input class="fi" id="nl" placeholder="Leave empty for random name" maxlength="60"></div>
    <div class="fg"><label class="fl" data-en="Flag / Country" data-fa="پرچم / کشور">Flag / Country</label>
      <select class="fs" id="flag-select-create" onchange="applyFlagCreate()">
        <option value="">None</option>
        <option value="cn">🇨🇳 China</option>
        <option value="nl">🇳🇱 Netherlands</option>
        <option value="ru">🇷🇺 Russia</option>
        <option value="us">🇺🇸 United States</option>
        <option value="ca">🇨🇦 Canada</option>
        <option value="ir">🇮🇷 Iran</option>
        <option value="de">🇩🇪 Germany</option>
        <option value="gb">🇬🇧 United Kingdom</option>
        <option value="it">🇮🇹 Italy</option>
        <option value="fr">🇫🇷 France</option>
        <option value="tr">🇹🇷 Turkey</option>
        <option value="ae">🇦🇪 UAE</option>
        <option value="custom">Custom (2-letter)</option>
      </select>
      <input class="fi" id="flag-custom-create" placeholder="e.g. jp" style="display:none; margin-top:5px;" maxlength="2">
      <input type="hidden" id="flag-code-create" value="">
      <button class="btn btn-outline btn-sm" onclick="autoDetectFlagCreate()" style="margin-top:4px;">🔍 Auto Detect</button>
    </div>
    <div class="fg"><label class="fl">UUID</label><div style="display:flex;gap:6px;"><input class="fi" id="auuid" placeholder="Leave empty for auto-generate" style="flex:1;"><button class="btn btn-outline btn-sm" onclick="generateUUID('auuid')">🎲 Generate</button></div></div>
    <div class="fg"><button class="adv-toggle" onclick="toggleAdv('adv-create')">▼ <span data-en="Advanced Options" data-fa="گزینه‌های پیشرفته">Advanced Options</span></button>
      <div id="adv-create" class="adv-section">
        <div class="fg"><label class="fl" data-en="Profile" data-fa="پروفایل">Profile</label>
          <select class="fs" id="ares-profile" onchange="applyProfileCreate()"><option value="">Custom</option><option value="default">Default</option><option value="youtube">YouTube</option><option value="instagram">Instagram</option><option value="twitter">Twitter</option><option value="tiktok">TikTok</option><option value="whatsapp">WhatsApp</option><option value="telegram">Telegram</option><option value="netflix">Netflix</option><option value="spotify">Spotify</option><option value="google">Google</option></select>
          <small style="color:var(--text3);font-size:0.75rem;">App profiles only change SNI/Host for DPI bypass and do not affect server connection.</small>
        </div>
        <div class="fg"><label class="fl">Path</label><input class="fi" id="ap" placeholder="/ws/{uid}"></div>
        <div class="fg"><label class="fl">SNI</label><input class="fi" id="asni" placeholder="example.com"></div>
        <div class="fg"><label class="fl">Host</label><input class="fi" id="ahost" placeholder="example.com"></div>
        <div class="fg"><label class="fl">Fingerprint</label>
          <select class="fs" id="afingerprint-sel" onchange="toggleFingerprintCustom('create')">
    <option value="none" selected>None / Disable</option>
    <option value="chrome">Chrome</option>
    <option value="firefox">Firefox</option>
    <option value="safari">Safari</option>
    <option value="ios">iOS</option>
    <option value="android">Android</option>
    <option value="edge">Edge</option>
    <option value="360">360</option>
    <option value="qq">QQ</option>
    <option value="random">Random</option>
    <option value="randomized">Randomized</option>
    <option value="custom">Custom</option>
</select>
          <input class="fi" id="afingerprint-custom" placeholder="Enter custom fingerprint" style="display:none; margin-top:5px;">
          <input type="hidden" id="afingerprint" value="chrome">
        </div>
        <div class="fg"><label class="fl">Fragment</label>
          <select class="fs" id="afrag-mode" onchange="toggleFragmentFields('create')">
            <option value="off">Off</option>
            <option value="tlshello">TLS Hello</option>
            <option value="range">Range</option>
          </select>
          <div id="frag-create-range" style="display:none;">
            <input class="fi" id="afrag-length" placeholder="Length (e.g. 100-200)" style="margin-top:5px;">
            <input class="fi" id="afrag-interval" placeholder="Interval (e.g. 10-20)" style="margin-top:5px;">
          </div>
          <input type="hidden" id="afrag" value="">
        </div>
        <div class="fg"><label class="fl">IP Profile</label><select class="fs" id="aip-profile"></select></div>
        <div class="fg"><label class="fl" data-en="Naming Mode" data-fa="شیوه نام‌گذاری">Naming Mode</label>
          <select class="fs" id="anaming-mode">
            <option value="default">Default (SulgX-Name-Server1)</option>
            <option value="short">Short (SXP 1, SXP 2, ...)</option>
          </select>
        </div>
        <div class="fg"><label class="fl">TCP Fast Open</label><div class="toggle" id="tfo-create" onclick="this.classList.toggle('on')"></div></div>
        <div class="fg"><label class="fl">ECH (Secure Hello)</label><div class="toggle" id="ech-create" onclick="this.classList.toggle('on'); toggleEchFields('create')"></div></div>
        <div id="ech-create-fields" style="display:none;">
          <input class="fi" id="ech-sni-create" placeholder="ECH SNI (e.g. cloudflare.com)" style="margin-top:5px;">
          <input class="fi" id="ech-doh-create" placeholder="ECH DoH URL (optional)" style="margin-top:5px;">
        </div>
        <div class="fg"><label class="fl">Allow Insecure</label><div class="toggle" id="insecure-create" onclick="this.classList.toggle('on')"></div></div>
        <div class="fg"><label class="fl">Random Path</label><div class="toggle" id="random-create" onclick="this.classList.toggle('on')"></div></div>
        <div class="fg"><label class="fl">SMUX</label><div class="toggle" id="smux-create" onclick="this.classList.toggle('on')"></div></div>
        <div class="fg"><label class="fl">IP Limit</label><input class="fi" type="number" id="aip-limit" min="0" value="0" placeholder="0 = Unlimited"></div>
                <div class="fg"><label class="fl">Protocol</label>
          <select class="fs" id="aprotocol">
            <option value="vless-ws">VLESS + WS</option>
            <option value="xhttp-packet-up">XHTTP Packet-Up</option>
            <option value="xhttp-stream-up">XHTTP Stream-Up</option>
            <option value="xhttp-stream-one">XHTTP Stream-One</option>
            <option value="xhttp-auto">XHTTP Auto</option>
          </select>
        </div>
        <div class="fg"><label class="fl">ALPN</label>
          <select class="fs" id="aalpn-sel" onchange="toggleAlpnCustom('create')">
    <option value="" selected>None (default)</option>
    <option value="http/1.1">http/1.1</option>
    <option value="h2,http/1.1">h2,http/1.1</option>
    <option value="h2">h2</option>
    <option value="h3">h3</option>
    <option value="custom">Custom</option>
</select>
          <input class="fi" id="aalpn-custom" placeholder="e.g. h2,http/1.1" style="display:none; margin-top:5px;">
          <input type="hidden" id="aalpn" value="http/1.1">
        </div>
        <div class="fg"><label class="fl">Port</label><input class="fi" type="number" id="aport" min="1" max="65535" value="443"></div>
      </div>
    </div>
    <div class="fg"><label class="fl" data-en="Traffic Limit (GB)" data-fa="محدودیت ترافیک (گیگابایت)">Traffic Limit (GB)</label><input class="fi" type="number" id="nv" min="0" step="0.1" value="0" placeholder="0 = Unlimited"></div>
    <div class="fg"><label class="fl" data-en="Max Connections" data-fa="حداکثر اتصالات">Max Connections</label><input class="fi" type="number" id="nc" min="0" value="0" placeholder="0 = Unlimited"></div>
    <div class="fg"><label class="fl" data-en="Validity (Days)" data-fa="اعتبار (روز)">Validity (Days)</label><input class="fi" type="number" id="nd" min="0" value="0" placeholder="0 = Unlimited"></div>
    <div class="fg"><label class="fl" data-en="Color" data-fa="رنگ">Color</label><input type="color" id="alink-color" value="#39ff14"></div>
    <div style="display:flex;gap:6px;margin-top:10px;"><button class="btn btn-primary" onclick="createLink()" style="flex:1;" data-en="Create" data-fa="ایجاد">Create</button><button class="btn btn-outline" onclick="document.getElementById('mo-add').classList.remove('show')" data-en="Cancel" data-fa="انصراف">Cancel</button></div>
  </div>
</div>

<div class="mo" id="mo-edit">
  <div class="mo-box">
    <button class="mo-close" onclick="document.getElementById('mo-edit').classList.remove('show')">✕</button>
    <div class="mo-title" id="et" data-en="Edit Inbound" data-fa="ویرایش اینباند">Edit Inbound</div>
    <input type="hidden" id="eu">
    <div class="fg"><label class="fl">UUID</label><input class="fi" id="euuid" readonly></div>
    <div class="fg"><label class="fl" data-en="Name" data-fa="نام">Name</label><input class="fi" id="en2" maxlength="60"></div>
    <div class="fg"><label class="fl" data-en="Flag / Country" data-fa="پرچم / کشور">Flag / Country</label>
      <select class="fs" id="flag-select-edit" onchange="applyFlagEdit()">
        <option value="">None</option>
        <option value="cn">🇨🇳 China</option>
        <option value="nl">🇳🇱 Netherlands</option>
        <option value="ru">🇷🇺 Russia</option>
        <option value="us">🇺🇸 United States</option>
        <option value="ca">🇨🇦 Canada</option>
        <option value="ir">🇮🇷 Iran</option>
        <option value="de">🇩🇪 Germany</option>
        <option value="gb">🇬🇧 United Kingdom</option>
        <option value="it">🇮🇹 Italy</option>
        <option value="fr">🇫🇷 France</option>
        <option value="tr">🇹🇷 Turkey</option>
        <option value="ae">🇦🇪 UAE</option>
        <option value="custom">Custom (2-letter)</option>
      </select>
      <input class="fi" id="flag-custom-edit" placeholder="e.g. jp" style="display:none; margin-top:5px;" maxlength="2">
      <input type="hidden" id="flag-code-edit" value="">
      <button class="btn btn-outline btn-sm" onclick="autoDetectFlagEdit()" style="margin-top:4px;">🔍 Auto Detect</button>
    </div>
    <div class="fg"><button class="adv-toggle" onclick="toggleAdv('adv-edit')">▼ <span data-en="Advanced Options" data-fa="گزینه‌های پیشرفته">Advanced Options</span></button>
      <div id="adv-edit" class="adv-section">
        <div class="fg"><label class="fl" data-en="Profile" data-fa="پروفایل">Profile</label>
          <select class="fs" id="eres-profile" onchange="applyProfile()"><option value="">Custom</option><option value="default">Default</option><option value="youtube">YouTube</option><option value="instagram">Instagram</option><option value="twitter">Twitter</option><option value="tiktok">TikTok</option><option value="whatsapp">WhatsApp</option><option value="telegram">Telegram</option><option value="netflix">Netflix</option><option value="spotify">Spotify</option><option value="google">Google</option></select>
          <small style="color:var(--text3);font-size:0.75rem;">App profiles only change SNI/Host for DPI bypass and do not affect server connection.</small>
        </div>
        <div class="fg"><label class="fl">Path</label><input class="fi" id="ep"></div>
        <div class="fg"><label class="fl">SNI</label><input class="fi" id="esni"></div>
        <div class="fg"><label class="fl">Host</label><input class="fi" id="ehost"></div>
        <div class="fg"><label class="fl">Fingerprint</label>
          <select class="fs" id="efingerprint-sel" onchange="toggleFingerprintCustom('edit')">
    <option value="none">None / Disable</option>
    <option value="chrome">Chrome</option>
    <option value="firefox">Firefox</option>
    <option value="safari">Safari</option>
    <option value="ios">iOS</option>
    <option value="android">Android</option>
    <option value="edge">Edge</option>
    <option value="360">360</option>
    <option value="qq">QQ</option>
    <option value="random">Random</option>
    <option value="randomized">Randomized</option>
    <option value="custom">Custom</option>
</select>
          <input class="fi" id="efingerprint-custom" placeholder="Enter custom fingerprint" style="display:none; margin-top:5px;">
          <input type="hidden" id="efingerprint" value="chrome">
        </div>
        <div class="fg"><label class="fl">Fragment</label>
          <select class="fs" id="efrag-mode" onchange="toggleFragmentFields('edit')">
            <option value="off">Off</option>
            <option value="tlshello">TLS Hello</option>
            <option value="range">Range</option>
          </select>
          <div id="frag-edit-range" style="display:none;">
            <input class="fi" id="efrag-length" placeholder="Length (e.g. 100-200)" style="margin-top:5px;">
            <input class="fi" id="efrag-interval" placeholder="Interval (e.g. 10-20)" style="margin-top:5px;">
          </div>
          <input type="hidden" id="efrag" value="">
        </div>
        <div class="fg"><label class="fl">IP Profile</label><select class="fs" id="eip-profile"></select></div>
        <div class="fg"><label class="fl" data-en="Naming Mode" data-fa="شیوه نام‌گذاری">Naming Mode</label>
          <select class="fs" id="enaming-mode">
            <option value="default">Default (SulgX-Name-Server1)</option>
            <option value="short">Short (SXP 1, SXP 2, ...)</option>
          </select>
        </div>
        <div class="fg"><label class="fl">TCP Fast Open</label><div class="toggle" id="tfo-edit" onclick="this.classList.toggle('on')"></div></div>
        <div class="fg"><label class="fl">ECH (Secure Hello)</label><div class="toggle" id="ech-edit" onclick="this.classList.toggle('on'); toggleEchFields('edit')"></div></div>
        <div id="ech-edit-fields" style="display:none;">
          <input class="fi" id="ech-sni-edit" placeholder="ECH SNI (e.g. cloudflare.com)" style="margin-top:5px;">
          <input class="fi" id="ech-doh-edit" placeholder="ECH DoH URL (optional)" style="margin-top:5px;">
        </div>
        <div class="fg"><label class="fl">Allow Insecure</label><div class="toggle" id="insecure-edit" onclick="this.classList.toggle('on')"></div></div>
        <div class="fg"><label class="fl">Random Path</label><div class="toggle" id="random-edit" onclick="this.classList.toggle('on')"></div></div>
        <div class="fg"><label class="fl">SMUX</label><div class="toggle" id="smux-edit" onclick="this.classList.toggle('on')"></div></div>
        <div class="fg"><label class="fl">IP Limit</label><input class="fi" type="number" id="eip-limit" min="0" value="0" placeholder="0 = Unlimited"></div>
        <div class="fg"><label class="fl">Protocol</label>
          <select class="fs" id="eprotocol">
            <option value="vless-ws">VLESS + WS</option>
            <option value="xhttp-packet-up">XHTTP Packet-Up</option>
            <option value="xhttp-stream-up">XHTTP Stream-Up</option>
            <option value="xhttp-stream-one">XHTTP Stream-One</option>
            <option value="xhttp-auto">XHTTP Auto</option>
          </select>
        </div>
        <div class="fg"><label class="fl">ALPN</label>
          <select class="fs" id="ealpn-sel" onchange="toggleAlpnCustom('edit')">
    <option value="">None (default)</option>
    <option value="http/1.1">http/1.1</option>
    <option value="h2,http/1.1">h2,http/1.1</option>
    <option value="h2">h2</option>
    <option value="h3">h3</option>
    <option value="custom">Custom</option>
</select>
          <input class="fi" id="ealpn-custom" placeholder="e.g. h2,http/1.1" style="display:none; margin-top:5px;">
          <input type="hidden" id="ealpn" value="http/1.1">
        </div>
        <div class="fg"><label class="fl">Port</label><input class="fi" type="number" id="eport" min="1" max="65535" value="443"></div>
      </div>
    </div>
    <div class="fg"><label class="fl" data-en="Traffic Limit (GB)" data-fa="محدودیت ترافیک (گیگابایت)">Traffic Limit (GB)</label><input class="fi" type="number" id="el" min="0" step="0.1" placeholder="0 = Unlimited"></div>
    <div class="fg"><label class="fl" data-en="Max Connections" data-fa="حداکثر اتصالات">Max Connections</label><input class="fi" type="number" id="ec" min="0" placeholder="0 = Unlimited"></div>
    <div class="fg"><label class="fl" data-en="Validity (Days)" data-fa="اعتبار (روز)">Validity (Days)</label><input class="fi" type="number" id="ed" min="0" placeholder="0 = Unlimited"></div>
    <div class="fg"><label class="fl" data-en="Color" data-fa="رنگ">Color</label><input type="color" id="e-color" value="#39ff14"></div>
    <div style="display:flex;gap:6px;margin-top:10px;"><button class="btn btn-primary" onclick="saveEdit()" style="flex:1;" data-en="Save" data-fa="ذخیره">Save</button><button class="btn btn-danger btn-sm" onclick="resetTraf()" data-en="Reset Traffic" data-fa="بازنشانی ترافیک">Reset Traffic</button><button class="btn btn-outline" onclick="document.getElementById('mo-edit').classList.remove('show')" data-en="Cancel" data-fa="انصراف">Cancel</button></div>
  </div>
</div>

<div class="mo" id="mo-qr">
  <div class="mo-box" style="max-width:360px;">
    <button class="mo-close" onclick="document.getElementById('mo-qr').classList.remove('show')">✕</button>
    <div class="mo-title">QR Code</div>
    <div class="qr-box"><img id="qr-img" src="" alt="QR Code"></div>
    <button class="btn btn-primary" onclick="dlQR()" style="width:100%;margin-top:10px;justify-content:center;" data-en="Download" data-fa="دانلود">Download</button>
  </div>
</div>

<div class="mo" id="mo-addr-edit">
  <div class="mo-box">
    <button class="mo-close" onclick="document.getElementById('mo-addr-edit').classList.remove('show')">✕</button>
    <div class="mo-title" data-en="Edit Address" data-fa="ویرایش آدرس">Edit Address</div>
    <div class="fg"><label class="fl" data-en="New Address" data-fa="آدرس جدید">New Address</label><input class="fi" id="edit-addr-input"></div>
    <button class="btn btn-primary" onclick="saveAddrEdit()" style="width:100%;justify-content:center;margin-top:10px;" data-en="Save" data-fa="ذخیره">Save</button>
  </div>
</div>

<div class="mo" id="mo-quick-add">
  <div class="mo-box">
    <button class="mo-close" onclick="document.getElementById('mo-quick-add').classList.remove('show')">✕</button>
    <div class="mo-title" data-en="Quick Add Inbound" data-fa="ساخت سریع اینباند">Quick Add Inbound</div>
    <div class="fg"><label class="fl" data-en="Name" data-fa="نام">Name</label><input class="fi" id="quick-label"></div>
    <div class="fg"><label class="fl" data-en="Traffic (GB)" data-fa="حجم (گیگ)">Traffic (GB)</label><input class="fi" type="number" id="quick-limit" value="0"></div>
    <div class="fg"><label class="fl" data-en="Days" data-fa="روز">Days</label><input class="fi" type="number" id="quick-days" value="0"></div>
    <button class="btn btn-primary" onclick="quickCreate()" style="width:100%;justify-content:center;">Create & Get Link</button>
  </div>
</div>

<div class="mo" id="mo-ip-profile">
  <div class="mo-box">
    <button class="mo-close" onclick="document.getElementById('mo-ip-profile').classList.remove('show')">✕</button>
    <div class="mo-title" data-en="Manage IP Profile" data-fa="مدیریت پروفایل آی‌پی">Manage IP Profile</div>
    <div class="fg"><label class="fl" data-en="Profile Name" data-fa="نام پروفایل">Profile Name</label><input class="fi" id="ip-profile-name"></div>
    <div class="fg">
      <label class="fl" data-en="Addresses (one per line)" data-fa="آدرس‌ها (هر خط یک)">Addresses (one per line)</label>
      <textarea class="fi" id="ip-profile-addrs" rows="6" placeholder="1.1.1.1#MyServer+us+1
8.8.8.8#Google+us
example.com"></textarea>
      <small style="color:var(--text3); font-size:0.75rem;">Format: IP#Name+Flag+SortNumber (Name, Flag, SortNumber optional)</small>
    </div>
    <button class="btn btn-outline btn-sm" onclick="detectFlagsForProfile()" style="margin-top:6px;">🔍 Auto-Detect Flags</button>
    <input type="hidden" id="ip-profile-id">
    <button class="btn btn-primary" onclick="saveIpProfile()" style="width:100%;justify-content:center;margin-top:10px;">Save</button>
  </div>
</div>

<div class="mo" id="mo-scanner-profile">
  <div class="mo-box">
    <button class="mo-close" onclick="document.getElementById('mo-scanner-profile').classList.remove('show')">✕</button>
    <div class="mo-title" data-en="Save as Profile" data-fa="ذخیره به‌عنوان پروفایل">Save as Profile</div>
    <div class="fg"><label class="fl" data-en="Profile Name" data-fa="نام پروفایل">Profile Name</label><input class="fi" id="scanner-profile-name"></div>
    <button class="btn btn-primary" onclick="saveScannerProfile()" style="width:100%;justify-content:center;margin-top:10px;">Save</button>
  </div>
</div>
<script>
let panelPrefix = '';
async function loadPanelInfo() {
    try {
        const r = await fetch('/api/panel-info');
        if (!r.ok) return;
        const info = await r.json();
        panelPrefix = info.prefix || '';
        window.panelPrefix = panelPrefix;
        localStorage.setItem('panelPrefix', panelPrefix);
    } catch(e) { console.warn('Panel info fetch failed'); }
}

function goToPanel() {
    const prefix = window.panelPrefix ? '/' + window.panelPrefix : '';
    window.location.href = prefix + '/panel';
}

function copyToClipboard(text) {
    if (!text) { toast('Nothing to copy', true); return; }
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(function() {
            toast('Copied!');
        }, function() {
            fallbackCopy(text);
        });
    } else {
        fallbackCopy(text);
    }
}

function fallbackCopy(text) {
    var textArea = document.createElement("textarea");
    textArea.value = text;
    textArea.style.top = "0"; textArea.style.left = "0"; textArea.style.position = "fixed"; textArea.style.opacity = "0";
    document.body.appendChild(textArea);
    textArea.focus(); textArea.select();
    try {
        var successful = document.execCommand('copy');
        toast(successful ? 'Copied!' : 'Failed to copy');
    } catch (err) {
        toast('Failed to copy', true);
    }
    document.body.removeChild(textArea);
}

function esc(s) {
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,"\\'");
}

const $=s=>document.querySelector(s),$m=id=>document.getElementById(id);
const i18n = {
  en:{
    hoursAgo:'{n} h ago', minsAgo:'{n} min ago', justNow:'Just now', updatedAt:'Updated {time}',
    success:'Success', failed:'Failed',
    mb:'MB', gb:'GB', kb:'KB', b:'B',
    active:'Active', inactive:'Inactive', expired:'Expired', unlimited:'∞',
    create:'Create', save:'Save', cancel:'Cancel', edit:'Edit', copy:'Copy', sub:'Sub', qr:'QR', del:'Del',
    on:'On', off:'Off',
    logout: '🚪 Logout',
    reachable:'✅ Reachable', failed:'❌ Failed'
  },
  fa:{
    hoursAgo:'{n} ساعت پیش', minsAgo:'{n} دقیقه پیش', justNow:'لحظاتی پیش', updatedAt:'بروزرسانی {time}',
    success:'موفق', failed:'ناموفق',
    mb:'مگابایت', gb:'گیگابایت', kb:'کیلوبایت', b:'بایت',
    active:'فعال', inactive:'غیرفعال', expired:'منقضی', unlimited:'∞',
    create:'ایجاد', save:'ذخیره', cancel:'انصراف', edit:'ویرایش', copy:'کپی', sub:'اشتراک', qr:'QR', del:'حذف',
    on:'روشن', off:'خاموش',
    logout: '🚪 خروج',
    reachable:'✅ در دسترس', failed:'❌ خطا'
  }
};
const stealth_i18n = {
  en: {
    hoursAgo: '{n} h ago', minsAgo: '{n} min ago', justNow: 'Just now',
    updatedAt: 'Updated {time}', success: 'Success', failed: 'Failed',
    mb: 'MB', gb: 'GB', kb: 'KB', b: 'B',
    active: 'Active', inactive: 'Inactive', expired: 'Expired', unlimited: '∞',
    create: 'New Service', save: 'Save', cancel: 'Cancel', edit: 'Modify',
    copy: 'Copy', sub: 'Link', qr: 'QR', del: 'Remove',
    on: 'On', off: 'Off',
    logout: '🚪 Logout',
    reachable: '✅ Reachable', failed: '❌ Failed',
    Inbound: 'Service', Inbounds: 'Services', Subscription: 'Sync',
    VLESS: 'Channel', Clash: 'Meta Config', SingBox: 'Sing Config',
    'Quick Add': 'Quick Service', 'Manage VLESS Configs': 'Manage Channels',
    'This Server is Free': 'Free Service', 'Regenerate UUID': 'Refresh ID',
    'Disconnect All': 'Terminate Links',
  },
  fa: {
    hoursAgo: '{n} ساعت پیش', minsAgo: '{n} دقیقه پیش', justNow: 'لحظاتی پیش',
    updatedAt: 'بروزرسانی {time}', success: 'موفق', failed: 'ناموفق',
    mb: 'مگابایت', gb: 'گیگابایت', kb: 'کیلوبایت', b: 'بایت',
    active: 'فعال', inactive: 'غیرفعال', expired: 'منقضی', unlimited: '∞',
    create: 'سرویس جدید', save: 'ذخیره', cancel: 'انصراف', edit: 'ویرایش',
    copy: 'کپی', sub: 'لینک', qr: 'QR', del: 'حذف',
    on: 'روشن', off: 'خاموش',
    logout: '🚪 خروج',
    reachable: '✅ در دسترس', failed: '❌ خطا',
    Inbound: 'سرویس', Inbounds: 'سرویس‌ها', Subscription: 'همگام‌سازی',
    VLESS: 'کانال', Clash: 'تنظیمات متا', SingBox: 'پیکربندی سینگ',
    'Quick Add': 'سرویس سریع', 'Manage VLESS Configs': 'مدیریت کانال‌ها',
    'This Server is Free': 'سرویس رایگان', 'Regenerate UUID': 'تازه‌سازی شناسه',
    'Disconnect All': 'قطع تمام اتصالات',
  }
};
let stealthMode = false;
function t(key, params = {}) {
  let str = '';
  if (stealthMode && stealth_i18n[lang] && stealth_i18n[lang][key]) {
    str = stealth_i18n[lang][key];
  } else if (i18n[lang] && i18n[lang][key]) {
    str = i18n[lang][key];
  } else {
    str = i18n['en'][key] || key;
  }
  for (let p in params) {
    str = str.replace(`{${p}}`, params[p]);
  }
  return str;
}
function codeToFlag(code) {
    if (!code || code.length !== 2) return '';
    code = code.toUpperCase();
    return String.fromCodePoint(0x1F1E6 + code.charCodeAt(0) - 65) + String.fromCodePoint(0x1F1E6 + code.charCodeAt(1) - 65);
}
let lang=localStorage.getItem('ll')||'en',theme=localStorage.getItem('theme')||'dark';
let allLinks=[],cf='all',sData={},tChart=null,allAddrs=[],isAuthenticated=false,isInitialChecking=false;
let prevUploadBytes = null, prevDownloadBytes = null, prevStatsTime = null;
let timezoneOffset = 0;
let editingAddrIndex = -1;
let selectedUids = new Set();
let selectedAddrIndices = new Set();
let uploadSpeedAvg = 0, downloadSpeedAvg = 0;
const footerTexts = {
  en: 'Dedicated to the people of my homeland Iran from <a href="https://github.com/SulgX" target="_blank">SulgX</a>',
  fa: 'تقدیم به مردم سرزمینم ایران از طرف <a href="https://github.com/SulgX" target="_blank">SulgX</a>'
};

const dnsRanges = new Set();
['1.1.1.1','1.0.0.1','9.9.9.9','149.112.112.112','208.67.222.222','208.67.220.220'].forEach(ip=>dnsRanges.add(ip));

const providerIPs = {"arvancloud":{"ipv4":["185.143.232.0/22","188.229.116.16/30","94.101.182.0/27","2.144.3.128/28","37.32.16.0/27","37.32.17.0/27","37.32.18.0/27","37.32.19.0/27","185.215.232.0/22","178.131.120.48/28","185.143.235.0/24"]},"cloudflare":{"ipv4":["173.245.48.0/20","103.21.244.0/22","103.22.200.0/22","103.31.4.0/22","141.101.64.0/18","108.162.192.0/18","190.93.240.0/20","188.114.96.0/20","197.234.240.0/22","198.41.128.0/17","162.158.0.0/15","104.16.0.0/13","104.24.0.0/14","172.64.0.0/13","131.0.72.0/22"]},"fastly":{"ipv4":["23.235.32.0/20","43.249.72.0/22","103.244.50.0/24","103.245.222.0/23","103.245.224.0/24","104.156.80.0/20","140.248.64.0/18","140.248.128.0/17","146.75.0.0/17","151.101.0.0/16","157.52.64.0/18","167.82.0.0/17","167.82.128.0/20","167.82.160.0/20","167.82.224.0/20","172.111.64.0/18","185.31.16.0/22","199.27.72.0/21","199.232.0.0/16"]},"Google":{"ipv4":["34.0.0.0/15","34.2.0.0/16","34.64.0.0/10","34.128.0.0/10","35.216.0.0/14","104.132.0.0/14"]},"Google_Cloud":{"ipv4":["34.0.228.0/22","34.0.232.0/23","34.0.235.0/24"]},"Microsoft":{"ipv4":["20.192.0.0/10","40.80.0.0/14","40.92.0.0/14","52.100.0.0/14","172.128.0.0/10","172.160.0.0/11"]},"Microsoft_Azure":{"ipv4":["4.152.0.0/15","4.154.0.0/15","4.156.0.0/15","4.158.0.0/15","13.68.0.0/14","13.80.0.0/15","13.82.0.0/15","13.84.0.0/15","51.140.0.0/14","108.142.0.0/15","172.166.0.0/15","172.168.0.0/15","172.176.0.0/15","172.180.0.0/15","172.184.0.0/15","172.190.0.0/15"]},"Amazon_AWS":{"ipv4":["18.128.0.0/9","3.5.180.0/22"]},"Oracle_Cloud":{"ipv4":["92.0.0.0/13","129.144.0.0/12"]},"IBM_Cloud":{"ipv4":["50.22.0.0/21","119.81.0.0/16","144.69.0.0/16","150.240.0.0/16","174.133.0.0/16"]},"Alibaba_Cloud":{"ipv4":["8.25.82.0/24","8.38.121.0/24","42.120.70.0/23","42.120.133.0/20","42.156.128.0/21","47.90.198.0/24","59.82.0.0/24","59.82.1.0/24"]},"Tencent_Cloud":{"ipv4":["1.12.0.0/14","49.232.0.0/14","111.229.0.0/18","124.220.0.0/14","162.14.0.0/16"]},"Akamai":{"ipv4":["2.16.30.0/23","2.16.32.0/23","2.16.38.0/23","23.4.92.0/24","23.52.140.0/24","23.56.32.0/19","23.192.0.0/11","96.7.130.0/23","184.24.0.0/13","184.28.102.0/23","184.28.236.0/23","209.200.128.0/17"]},"DigitalOcean":{"ipv4":["45.55.128.0/18","45.55.192.0/18","46.101.0.0/18","46.101.128.0/17","95.85.0.0/18","104.131.0.0/18","104.131.64.0/18","104.236.0.0/18","104.236.64.0/18","104.236.128.0/18","104.236.192.0/18","107.170.0.0/17","107.170.192.0/18","128.199.64.0/18","128.199.128.0/18","162.243.0.0/17","188.226.128.0/17"]},"Hetzner":{"ipv4":["5.9.0.0/16","5.75.128.0/17","5.78.0.0/21","5.161.8.0/21","136.243.0.0/16","213.239.224.0/24"]},"Linode":{"ipv4":["23.92.16.0/20","172.232.0.0/14","176.58.120.0/21","192.46.208.0/20","192.155.82.117/32"]},"Vultr":{"ipv4":["65.20.64.0/19","108.61.170.0/23","149.28.132.0/23","149.28.192.189/32"]},"OVHcloud":{"ipv4":["5.39.0.0/17","5.135.0.0/16","54.36.0.0/14","91.121.0.0/19","178.33.128.128/25","198.49.103.0/24"]},"Railway":{"ipv4":["69.46.46.0/24","208.77.244.0/24","208.77.245.0/24","208.77.246.0/24","208.77.247.0/24","208.77.248.0/24"]},"GitHub":{"ipv4":["140.82.112.0/20","143.55.64.0/20","192.30.252.0/22"]},"Facebook_Meta":{"ipv4":["31.13.24.0/21","57.141.0.0/14","66.220.144.0/20","69.63.184.0/21","157.240.0.0/16","163.70.128.0/17"]},"Twitter_X":{"ipv4":["8.25.194.0/23","8.25.196.0/23","64.63.0.0/18","69.12.56.0/21","69.195.160.0/19","104.244.40.0/21","192.48.236.0/23","192.133.78.0/23","199.16.156.0/23","202.160.131.0/24","209.237.192.0/19"]},"LinkedIn":{"ipv4":["45.42.64.0/22","103.20.92.0/22","108.174.0.0/20","128.241.35.0/24","128.242.95.0/24","199.101.160.0/22"]},"Dropbox":{"ipv4":["45.58.64.0/23","45.58.66.0/23","64.112.13.0/24","108.160.160.0/20","162.125.0.0/16","192.189.200.0/23","199.47.216.0/22"]},"Salesforce":{"ipv4":["13.108.0.0/14","13.111.0.0/16","66.231.80.0/20","85.222.128.0/19","101.53.160.0/19","136.147.208.0/20","140.190.64.0/16","145.224.128.0/17"]},"SAP":{"ipv4":["45.86.152.0/24","103.109.18.0/24","103.109.19.0/24","130.214.0.0/23","130.214.2.0/23","130.214.20.0/23","130.214.32.0/23","204.79.147.0/24"]},"Adobe":{"ipv4":["2.26.170.0/24","66.235.128.0/17","82.47.145.0/24","92.113.252.0/24"]},"Apple":{"ipv4":["17.0.0.0/8"]},"Spotify":{"ipv4":["23.92.96.0/20","78.31.8.0/22","193.182.8.0/21","193.235.232.0/24"]},"Netflix":{"ipv4":["23.246.0.0/18","37.77.184.0/21","45.57.0.0/17","64.120.128.0/17","66.197.128.0/17","69.53.224.0/19","198.45.48.0/20"]},"Stripe":{"ipv4":["8.14.0.0/24","8.21.168.0/24","8.39.50.0/24","8.39.157.0/24","139.45.128.0/18","139.45.168.0/24","139.45.170.0/24","139.45.180.0/24","194.34.152.0/22"]},"Twilio":{"ipv4":["3.25.42.128/25","3.26.81.96/27","3.80.20.0/25","3.251.214.32/27","34.203.250.0/23","54.172.60.0/23","67.213.136.0/23","185.187.132.0/23","208.78.112.0/22"]},"SendGrid":{"ipv4":["50.31.32.0/19","134.128.64.0/18","149.72.1.0/24","149.72.2.0/23","149.72.4.0/22","149.72.8.0/22","167.89.0.0/17","168.245.0.0/17","208.117.48.0/20"]}};

const OPERATIONAL_PROFILES = {
    "instagram": { sni: "www.instagram.com", host: "www.instagram.com", path: "/graphql", fp: "chrome" },
    "youtube": { sni: "www.youtube.com", host: "www.youtube.com", path: "/youtubei/v1/image", fp: "chrome" },
    "twitter": { sni: "twitter.com", host: "twitter.com", path: "/ws", fp: "chrome" },
    "tiktok": { sni: "www.tiktok.com", host: "www.tiktok.com", path: "/ws", fp: "chrome" },
    "whatsapp": { sni: "web.whatsapp.com", host: "web.whatsapp.com", path: "/ws/chat/v4", fp: "safari" },
    "telegram": { sni: "telegram.org", host: "telegram.org", path: "/ws", fp: "chrome" },
    "netflix": { sni: "www.netflix.com", host: "www.netflix.com", path: "/ws", fp: "chrome" },
    "spotify": { sni: "www.spotify.com", host: "www.spotify.com", path: "/ws", fp: "chrome" },
    "google": { sni: "www.google.com", host: "www.google.com", path: "/ws", fp: "chrome" },
    "default": { sni: "", host: "", path: "", fp: "chrome" }
};

const profiles = {
  default: {
      path: '/ws/{uid}',
      sni: location.hostname,
      host: location.hostname,
      fp: 'chrome'
  },
  youtube: {path:'/youtubei/v1/image',sni:'www.youtube.com',host:'www.youtube.com',fp:'chrome'},
  instagram: {path:'/graphql',sni:'www.instagram.com',host:'www.instagram.com',fp:'chrome'},
  twitter: {path:'/ws',sni:'twitter.com',host:'twitter.com',fp:'chrome'},
  tiktok: {path:'/ws',sni:'www.tiktok.com',host:'www.tiktok.com',fp:'chrome'},
  whatsapp: {path:'/ws/chat/v4',sni:'web.whatsapp.com',host:'web.whatsapp.com',fp:'safari'},
  telegram: {path:'/ws',sni:'telegram.org',host:'telegram.org',fp:'chrome'},
  netflix: {path:'/ws',sni:'www.netflix.com',host:'www.netflix.com',fp:'chrome'},
  spotify: {path:'/ws',sni:'www.spotify.com',host:'www.spotify.com',fp:'chrome'},
  google: {path:'/ws',sni:'www.google.com',host:'www.google.com',fp:'chrome'}
};

function applyProfile() {
  const p = $m('eres-profile').value;
  if (!p) return;
  const pr = OPERATIONAL_PROFILES[p] || profiles[p];
  if (pr) {
    $m('ep').value = pr.path || '';
    $m('esni').value = pr.sni || '';
    $m('ehost').value = pr.host || '';
    const fpVal = pr.fp || 'chrome';
    $m('efingerprint').value = fpVal;
    const sel = $m('efingerprint-sel');
    const customInput = $m('efingerprint-custom');
    if (['chrome','firefox','safari','ios','android','edge','360','qq','random','randomized'].includes(fpVal)) {
      sel.value = fpVal;
      customInput.style.display = 'none';
    } else {
      sel.value = 'custom';
      customInput.style.display = 'block';
      customInput.value = fpVal;
    }
  }
}

function applyProfileCreate() {
  const p = $m('ares-profile').value;
  if (!p) return;
  const pr = OPERATIONAL_PROFILES[p] || profiles[p];
  if (pr) {
    $m('ap').value = pr.path || '';
    $m('asni').value = pr.sni || '';
    $m('ahost').value = pr.host || '';
    const fpVal = pr.fp || 'chrome';
    $m('afingerprint').value = fpVal;
    const sel = $m('afingerprint-sel');
    const customInput = $m('afingerprint-custom');
    if (['chrome','firefox','safari','ios','android','edge','360','qq','random','randomized'].includes(fpVal)) {
      sel.value = fpVal;
      customInput.style.display = 'none';
    } else {
      sel.value = 'custom';
      customInput.style.display = 'block';
      customInput.value = fpVal;
    }
  }
}

function applyFlagCreate() {
    const sel = $m('flag-select-create').value;
    const customInput = $m('flag-custom-create');
    const hidden = $m('flag-code-create');
    if (sel === 'custom') {
        customInput.style.display = 'block';
        hidden.value = customInput.value.trim().toLowerCase();
    } else {
        customInput.style.display = 'none';
        hidden.value = sel;
    }
}

function applyFlagEdit() {
    const sel = $m('flag-select-edit').value;
    const customInput = $m('flag-custom-edit');
    const hidden = $m('flag-code-edit');
    if (sel === 'custom') {
        customInput.style.display = 'block';
        hidden.value = customInput.value.trim().toLowerCase();
    } else {
        customInput.style.display = 'none';
        hidden.value = sel;
    }
}

function toggleFragmentFields(context) {
    const modeEl = context === 'edit' ? $m('efrag-mode') : $m('afrag-mode');
    if (!modeEl) return;
    const mode = modeEl.value;
    const rangeDiv = context === 'edit' ? $m('frag-edit-range') : $m('frag-create-range');
    if (rangeDiv) {
        rangeDiv.style.display = (mode === 'range') ? 'block' : 'none';
    }
}

function toggleEchFields(context) {
    const toggle = $m(`ech-${context}`);
    const fields = $m(`ech-${context}-fields`);
    if (toggle.classList.contains('on')) {
        fields.style.display = 'block';
    } else {
        fields.style.display = 'none';
    }
}

function toggleFingerprintCustom(context) {
    const sel = context === 'edit' ? $m('efingerprint-sel') : $m('afingerprint-sel');
    const customInput = context === 'edit' ? $m('efingerprint-custom') : $m('afingerprint-custom');
    const hidden = context === 'edit' ? $m('efingerprint') : $m('afingerprint');
    
    if (sel.value === 'custom') {
        customInput.style.display = 'block';
        hidden.value = customInput.value.trim().toLowerCase();
    } else {
        customInput.style.display = 'none';
        hidden.value = sel.value;
    }
}

function toggleAlpnCustom(context) {
    const sel = context === 'edit' ? $m('ealpn-sel') : $m('aalpn-sel');
    const customInput = context === 'edit' ? $m('ealpn-custom') : $m('aalpn-custom');
    const hidden = context === 'edit' ? $m('ealpn') : $m('aalpn');
    
    if (sel.value === 'custom') {
        customInput.style.display = 'block';
        hidden.value = customInput.value.trim();
    } else {
        customInput.style.display = 'none';
        hidden.value = sel.value;
    }
}

async function autoDetectFlagCreate() {
  let ipField = null;
  if (allAddrs && allAddrs.length > 0) {
    for (let addr of allAddrs) {
      if (/^\d+\.\d+\.\d+\.\d+$/.test(addr) || addr.includes(':')) {
        ipField = addr;
        break;
      }
    }
  }
  if (!ipField) ipField = location.hostname;
  if (!ipField) return toast('No IP available', true);
  try {
    const r = await fetch('/api/auto-flag/' + encodeURIComponent(ipField));
    const data = await r.json();
    if (data.flag) {
      $m('flag-code-create').value = data.flag;
      const sel = $m('flag-select-create');
      if (['cn','nl','ru','us','ca','ir','de','gb','it','fr','tr','ae'].includes(data.flag)) {
        sel.value = data.flag;
        $m('flag-custom-create').style.display = 'none';
      } else {
        sel.value = 'custom';
        $m('flag-custom-create').style.display = 'block';
        $m('flag-custom-create').value = data.flag;
      }
      toast('Flag detected: ' + data.flag.toUpperCase());
    } else {
      toast('No flag found');
    }
  } catch(e) { toast('Auto-detect failed', true); }
}

async function autoDetectFlagEdit() {
  let ipField = null;
  if (allAddrs && allAddrs.length > 0) {
    for (let addr of allAddrs) {
      if (/^\d+\.\d+\.\d+\.\d+$/.test(addr) || addr.includes(':')) {
        ipField = addr;
        break;
      }
    }
  }
  if (!ipField) ipField = location.hostname;
  if (!ipField) return toast('No IP available', true);
  try {
    const r = await fetch('/api/auto-flag/' + encodeURIComponent(ipField));
    const data = await r.json();
    if (data.flag) {
      $m('flag-code-edit').value = data.flag;
      const sel = $m('flag-select-edit');
      if (['cn','nl','ru','us','ca','ir','de','gb','it','fr','tr','ae'].includes(data.flag)) {
        sel.value = data.flag;
        $m('flag-custom-edit').style.display = 'none';
      } else {
        sel.value = 'custom';
        $m('flag-custom-edit').style.display = 'block';
        $m('flag-custom-edit').value = data.flag;
      }
      toast('Flag detected: ' + data.flag.toUpperCase());
    } else {
      toast('No flag found');
    }
  } catch(e) { toast('Auto-detect failed', true); }
}

function setPanelLanguage(l) {
    document.querySelectorAll('#lang-glass-group .glass-btn').forEach(b => b.classList.remove('active'));
    document.getElementById(`btn-lang-${l}`).classList.add('active');
    setLang(l);
}
function setPanelTheme(th) {
    document.querySelectorAll('#theme-glass-group .glass-btn').forEach(b => b.classList.remove('active'));
    const btn = document.getElementById(`btn-theme-${th}`);
    if (btn) btn.classList.add('active');
    const hiddenInput = $m('set-theme-color');
    if (hiddenInput) hiddenInput.value = th;
    setTheme(th);
    localStorage.setItem('theme', th);
}
function setPanelTZ(offset, name) {
    document.querySelectorAll('#tz-glass-group .glass-btn').forEach(b => b.classList.remove('active'));
    if (name === 'Tehran') document.getElementById('btn-tz-tehran').classList.add('active');
    else if (name === 'UTC') document.getElementById('btn-tz-utc').classList.add('active');
    else if (name === 'Custom') document.getElementById('btn-tz-custom').classList.add('active');
    toggleCustomTZInput(false);
    timezoneOffset = offset;
    localStorage.setItem('timezone_offset', offset);
    saveSingleSetting('timezone_offset', offset);
}
function toggleCustomTZInput(show) {
    const container = $m('custom-tz-container');
    const customBtn = document.getElementById('btn-tz-custom');
    if (show) {
        document.querySelectorAll('#tz-glass-group .glass-btn').forEach(b => b.classList.remove('active'));
        customBtn.classList.add('active');
        container.style.display = 'block';
    } else {
        container.style.display = 'none';
    }
}
function applyCustomTZ(val) {
    let parsedOffset = parseFloat(val);
    if (!isNaN(parsedOffset)) {
        timezoneOffset = parsedOffset;
        localStorage.setItem('timezone_offset', parsedOffset);
        saveSingleSetting('timezone_offset', parsedOffset);
    }
}
function saveSingleSetting(key, value) {
    fetch('/api/settings', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({[key]: value}) });
}
function setKeepAliveMode(mode) {
    document.querySelectorAll('#keepalive-mode-group .glass-btn').forEach(b => b.classList.remove('active'));
    document.getElementById(`btn-keepalive-${mode}`).classList.add('active');
    var el = $m('set-keepalive-mode');
    if (el) el.value = mode;
}

function setTheme(t){
  theme=t;
  document.body.classList.toggle('light-mode',t==='light');
  document.body.classList.toggle('blue-mode',t==='blue-dark');
  localStorage.setItem('theme',t);
  const themeBtn = document.getElementById('theme-toggle-btn');
  if (themeBtn) themeBtn.textContent = t==='light'?'☀️':(t==='blue-dark'?'🌌':'🌙');
  updChartColors();
  syncGlassThemeButtons();
}
function toggleTheme(){
  const themes=['dark','light','blue-dark'];
  const idx=themes.indexOf(theme);
  setTheme(themes[(idx+1)%themes.length]);
}
function syncGlassThemeButtons() {
    document.querySelectorAll('#theme-glass-group .glass-btn').forEach(b => b.classList.remove('active'));
    const btn = document.getElementById(`btn-theme-${theme}`);
    if (btn) btn.classList.add('active');
}

function toggleSettingCard(cardId, inputId) {
    const card = $m(cardId);
    const input = $m(inputId);
    if (card.classList.contains('active')) {
        card.classList.remove('active');
        card.classList.add('inactive');
        input.value = '0';
    } else {
        card.classList.remove('inactive');
        card.classList.add('active');
        input.value = '1';
    }
}

function updateDashboardStatusCards(settings) {
    if (!settings) return;
    const cards = {
        'st-log': settings.log_enabled === '1',
        'st-auto': settings.auto_disable_enabled === '1',
        'st-tgrep': settings.telegram_report_enabled === '1',
        'st-tgnot': settings.telegram_notify_enabled === '1',
        'st-bot': !!(settings.tg_bot_token && settings.tg_chat_id),
        'st-stealth': settings.stealth_mode === '1'
    };
    for (const [id, enabled] of Object.entries(cards)) {
        const card = document.getElementById(id);
        if (card) {
            card.classList.toggle('active', enabled);
            card.classList.toggle('inactive', !enabled);
        }
    }
    updateSettingsStatusLabels();
}

function updateSettingsStatus(settings){
    if(!settings)return;
    const setCard = (cardId, enabled) => {
        const card = $m(cardId);
        if(card){
            card.classList.toggle('active', enabled);
            card.classList.toggle('inactive', !enabled);
        }
    };
    setCard('card-log', String(settings.log_enabled)==='1');
    setCard('card-auto', String(settings.auto_disable_enabled)==='1');
    setCard('card-tgrep', String(settings.telegram_report_enabled)==='1');
    setCard('card-tgnot', String(settings.telegram_notify_enabled)==='1');
    $m('set-log-toggle').value = String(settings.log_enabled)==='1' ? '1' : '0';
    $m('set-auto-disable').value = String(settings.auto_disable_enabled)==='1' ? '1' : '0';
    $m('set-tg-report').value = String(settings.telegram_report_enabled)==='1' ? '1' : '0';
    $m('set-tg-notify').value = String(settings.telegram_notify_enabled)==='1' ? '1' : '0';
    setCard('card-keepalive', String(settings.keep_alive_enabled)==='1');
    $m('set-keepalive-enabled').value = String(settings.keep_alive_enabled)==='1' ? '1' : '0';
    setCard('card-doh', String(settings.doh_enabled)==='1');
    $m('set-doh-enabled').value = String(settings.doh_enabled)==='1' ? '1' : '0';
    const stealthCard = $m('card-stealth');
    if(stealthCard){
        if(String(settings.stealth_mode)==='1'){
            stealthCard.classList.add('active'); stealthCard.classList.remove('inactive');
            $m('set-stealth-mode').value = '1';
        } else {
            stealthCard.classList.add('inactive'); stealthCard.classList.remove('active');
            $m('set-stealth-mode').value = '0';
        }
    }
}

function updateSettingsStatusLabels(){
  document.querySelectorAll('#settings-status .status-glass-card').forEach(card => {
    const key = card.id.replace('st-','');
    let label = card.getAttribute('data-'+lang) || card.querySelector('span[data-'+lang+']')?.textContent || '';
    const icon = card.querySelector('span:first-child')?.textContent || '';
    card.innerHTML = (card.classList.contains('active') ? '✅ ' : '❌ ') + icon + ' ' + label;
  });
}
function setLang(l){
  lang=l; document.querySelectorAll('.lang-en,.lang-fa').forEach(e=>e.classList.remove('active'));
  document.querySelectorAll(`.lang-${l}`).forEach(e=>e.classList.add('active'));
  document.body.dir=l==='fa'?'rtl':'ltr';
  document.querySelectorAll('[data-en]').forEach(el=>{const v=el.getAttribute('data-'+l);if(v)el.textContent=v;});
  document.querySelectorAll('[data-ph-en]').forEach(el=>{const v=el.getAttribute('data-ph-'+l);if(v)el.placeholder=v;});
  localStorage.setItem('ll',l);
  document.querySelectorAll('.mo-title[data-en]').forEach(el=>{const v=el.getAttribute('data-'+l);if(v)el.textContent=v;});
  updateSettingsStatusLabels();
  if (isAuthenticated) {
    loadLoginLogs();
    loadLogs();
    renderAddrs();
    filterLinks();
  }
  const footer = $m('footer-dedication');
  if (footer) footer.innerHTML = footerTexts[l] || footerTexts['en'];
  document.querySelectorAll('#lang-glass-group .glass-btn').forEach(b => b.classList.remove('active'));
  const activeLangBtn = document.getElementById(`btn-lang-${l}`);
  if (activeLangBtn) activeLangBtn.classList.add('active');
}
async function checkAuth() {
    if (sessionStorage.getItem('justLoggedOut') === '1') {
        sessionStorage.removeItem('justLoggedOut');
        isInitialChecking = false;
        showLogin();
        return;
    }

    isInitialChecking = true;
    await loadPanelInfo();
    try {
        const r = await fetch('/api/me');
        if (r.status === 200 && (await r.json()).authenticated) {
            isAuthenticated = true;
            isInitialChecking = false;
            await showDashboard();
            return;
        }
        isInitialChecking = false;
        showLogin();
    } catch (e) {
        console.warn('Auth check network error', e);
        isInitialChecking = false;
        showLogin();
    }
}
async function authenticatedFetch(url, options = {}) {
    const token = localStorage.getItem('token');
    if (!options.headers) options.headers = {};
    if (token) options.headers['Authorization'] = `Bearer ${token}`;
    const response = await fetch(url, options);
    if (response.status === 401 && !isInitialChecking) {
        localStorage.removeItem('token');
        isAuthenticated = false;
        throw new Error("Unauthorized");
    }
    return response;
}
function showLogin(){isAuthenticated=false;$m('login-page').style.display='';$m('dashboard-page').style.display='none';fetch('/api/public-settings').then(r=>r.json()).then(d=>{if(d.footer_text)$m('login-custom-message').textContent=d.footer_text;}).catch(()=>{});}
async function showDashboard(){
  isAuthenticated=true;
  $m('login-page').style.display='none';
  $m('dashboard-page').style.display='';
  await loadGeneralSettings();
  if (!localStorage.getItem('ll')) {
    const defLang = $m('set-default-lang')?.value || 'en';
    if (defLang) setLang(defLang);
  }
  initChart();
  initDoughnutChart();
  initSpeedChart();
  await loadStats();
  loadLinks();
  loadAddrs();
  loadLogs();
  loadLoginLogs();
  buildProviderPills();
  loadTelegramSettings();
  loadIpProfiles();
  buildDohUI();
  loadMultiPanel();
  setLang(lang);
  startPanelClock();
  syncGlassThemeButtons();
  startSSE();
  if (stealthMode) {
    const scannerPage = $m('page-ipscanner');
    if (scannerPage) scannerPage.style.display = 'none';
    const navScanner = document.querySelector('.nav-link[data-page="ipscanner"]');
    if (navScanner) navScanner.style.display = 'none';
    const mobileNavScanner = document.querySelector('.mobile-nav .nav-item[data-page="ipscanner"]');
    if (mobileNavScanner) mobileNavScanner.style.display = 'none';
  }
  buildProfileTabs();

  const prefix = window.panelPrefix ? '/' + window.panelPrefix : '';
  const newPath = prefix + '/panel';
  if (window.location.pathname !== newPath) {
    window.history.replaceState({}, '', newPath);
  }
}

function startPanelClock() {
  setInterval(() => {
    const d = new Date();
    d.setMinutes(d.getMinutes() + d.getTimezoneOffset() + timezoneOffset * 60);
    $m('panel-clock').textContent = d.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit' });
  }, 1000);
}

async function doLogin(){
    const pw=$m('login-pw').value;
    $m('login-err').style.display='none';
    try{
        const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:pw})});
        if(r.ok){
            $m('login-pw').value='';
            showDashboard();
        } else {
            $m('login-err').style.display='block';
        }
    } catch {
        console.error('Login error');
        $m('login-err').style.display='block';
    }
}

async function doLogout(){
    stopSSE();
    await fetch('/api/logout',{method:'POST'});
    localStorage.removeItem('token');
    sessionStorage.setItem('justLoggedOut', '1');
    const prefix = window.panelPrefix ? '/' + window.panelPrefix : '';
    window.location.href = prefix + '/login';
}
document.querySelectorAll('.nav-link[data-page]').forEach(el=>el.addEventListener('click',()=>{switchPage(el.dataset.page);document.getElementById('mainNav').classList.remove('open');}));
function switchPage(id){document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));$m('page-'+id).classList.add('active');document.querySelectorAll('.nav-link').forEach(n=>n.classList.toggle('active',n.dataset.page===id));document.querySelectorAll('.mobile-nav .nav-item').forEach(n=>n.classList.toggle('active',n.dataset.page===id));}
function toast(msg,err=false){const t=$m('toast');t.textContent=msg;t.className='toast'+(err?' err':'')+' show';clearTimeout(t._hide);t._hide=setTimeout(()=>t.classList.remove('show'),3000);}
function fmtB(b){if(!b||b===0)return'0 B';return b>=1073741824?(b/1073741824).toFixed(2)+' GB':b>=1048576?(b/1048576).toFixed(2)+' MB':(b/1024).toFixed(1)+' KB';}
function fmtLim(b){if(!b||b===0)return'∞';const g=b/1073741824;return(g%1===0?g.toFixed(0):g.toFixed(1))+' GB';}
function fmtExp(ea){if(!ea||ea===0)return'∞';const d=new Date(ea)-new Date();if(d<=0)return'Expired';const days=Math.floor(d/86400000);if(days>0)return days+'d';const hours=Math.floor(d/3600000);if(hours>0)return hours+'h';return Math.floor(d/60000)+'m';}
function setFilter(f,el){cf=f;document.querySelectorAll('.chip').forEach(c=>c.classList.remove('active'));el.classList.add('active');filterLinks();}
function filterLinks(){const q=($m('srch')?.value||'').toLowerCase();let r=allLinks;if(cf==='active')r=r.filter(l=>l.active);else if(cf==='off')r=r.filter(l=>!l.active);if(q)r=r.filter(l=>l.label.toLowerCase().includes(q)||l.uuid.toLowerCase().includes(q));renderLinks(r);}
function renderLinks(links){
  const tb=$m('ltb'),em=$m('lempty');
  if(!links||!links.length){tb.innerHTML='';em.style.display='block';return;}
  em.style.display='none';
  let tableBuffer = '';
  links.forEach(l=>{
    const u=l.used_bytes||0,lim=l.limit_bytes||0,pct=lim>0?Math.min(100,(u/lim)*100):0,col=pct>90?'var(--red)':pct>70?'var(--yellow)':'var(--primary)',ex=fmtExp(l.expires_at),ec=ex==='Expired'?'var(--red)':ex==='∞'?'var(--text3)':'var(--text2)',cc=l.current_connections||0,mc2=l.max_connections||0,check=selectedUids.has(l.uuid)?'checked':'',flagEmoji=l.flag?codeToFlag(l.flag):'',labelDisplay=(flagEmoji?flagEmoji+' ':'')+esc(l.label);
    tableBuffer += `<tr>
      <td><input type="checkbox" value="${esc(l.uuid)}" ${check} onchange="toggleSelectUid('${esc(l.uuid)}')"></td>
      <td data-label="Name" style="font-weight:600">${labelDisplay}</td>
      <td data-label="Type"><span class="tag tag-vless">VLESS</span></td>
      <td data-label="Usage" style="white-space:nowrap"><div class="pill"><span class="pill-used">${fmtB(u)}</span><div class="pill-bar"><div class="pill-fill" style="width:${pct}%;background:${col}"></div></div><span>${fmtLim(lim)}</span></div></td>
      <td data-label="Conns">${cc}/${mc2||'∞'}</td>
      <td data-label="Expiry" style="color:${ec}">${ex}</td>
      <td data-label="Status"><span class="tag ${l.active?'tag-on':'tag-off'}">${l.active?t('on'):t('off')}</span></td>
      <td data-label="Actions" style="min-width:140px;">
        <div style="display:flex; flex-direction:column; gap:6px; align-items:center;">
          <button class="toggle ${l.active?'on':''}" data-uid="${esc(l.uuid)}" onclick="togLink(this)"></button>
          <div style="display:flex; flex-wrap:wrap; gap:4px; justify-content:center;">
            ${l.label === 'This Server is Free' ? `
              <span class="tooltip-container"><button class="act-btn act-copy" onclick="cpLink('${esc(l.vless_link)}')">📋</button><span class="tooltip-text">${t('copy')}</span></span>
              <span class="tooltip-container"><button class="act-btn act-sub" onclick="cpSub('${esc(l.uuid)}')">🔗</button><span class="tooltip-text">${t('sub')}</span></span>
              <span class="tooltip-container"><button class="act-btn act-clash" onclick="copyClashLink('${esc(l.uuid)}')">🐱</button><span class="tooltip-text">Copy Clash Link</span></span>
              <span class="tooltip-container"><button class="act-btn act-clash" onclick="copySingboxLink('${esc(l.uuid)}')">🧩</button><span class="tooltip-text">Copy Sing‑Box Link</span></span>
              <span class="tooltip-container"><button class="act-btn act-qr" onclick="showQR('${esc(l.vless_link)}')">📷</button><span class="tooltip-text">${t('qr')}</span></span>
            ` : `
              <span class="tooltip-container"><button class="act-btn act-edit" onclick="showEditMo('${esc(l.uuid)}')">✏️</button><span class="tooltip-text">${t('edit')}</span></span>
              <span class="tooltip-container"><button class="act-btn act-copy" onclick="cpLink('${esc(l.vless_link)}')">📋</button><span class="tooltip-text">${t('copy')}</span></span>
              <span class="tooltip-container"><button class="act-btn act-sub" onclick="cpSub('${esc(l.uuid)}')">🔗</button><span class="tooltip-text">${t('sub')}</span></span>
              <span class="tooltip-container"><button class="act-btn act-clash" onclick="copyClashLink('${esc(l.uuid)}')">🐱</button><span class="tooltip-text">Copy Clash Link</span></span>
              <span class="tooltip-container"><button class="act-btn act-clash" onclick="copySingboxLink('${esc(l.uuid)}')">🧩</button><span class="tooltip-text">Copy Sing‑Box Link</span></span>
              <span class="tooltip-container"><button class="act-btn act-qr" onclick="showQR('${esc(l.vless_link)}')">📷</button><span class="tooltip-text">${t('qr')}</span></span>
              <span class="tooltip-container"><button class="act-btn act-del" onclick="delLink('${esc(l.uuid)}')">🗑️</button><span class="tooltip-text">${t('del')}</span></span>
              <span class="tooltip-container"><button class="act-btn act-edit" onclick="regenerateUUID('${esc(l.uuid)}')">🔄</button><span class="tooltip-text">Regenerate UUID</span></span>
              <span class="tooltip-container"><button class="act-btn act-del" onclick="disconnectLink('${esc(l.uuid)}')">🔌</button><span class="tooltip-text">Disconnect All</span></span>
              <span class="tooltip-container"><button class="act-btn act-sub" onclick="copySubLink('${esc(l.uuid)}')">📎 Sub</button><span class="tooltip-text">Copy Subscription Link</span></span>
              <span class="tooltip-container"><button class="act-btn act-edit" onclick="cloneLink('${esc(l.uuid)}')">🐑</button><span class="tooltip-text">Clone</span></span>
            `}
          </div>
        </div>
      </td>
    </tr>`;
  });
  tb.innerHTML = tableBuffer;
}
function copySubLink(uid) { const prefix = window.panelPrefix ? '/' + window.panelPrefix : ''; copyToClipboard('https://' + location.host + prefix + '/sub/' + uid); }
function copyClashLink(uid) { const prefix = window.panelPrefix ? '/' + window.panelPrefix : ''; copyToClipboard('https://' + location.host + prefix + '/sub/' + uid + '/clash'); }
function copySingboxLink(uid) { const prefix = window.panelPrefix ? '/' + window.panelPrefix : ''; copyToClipboard('https://' + location.host + prefix + '/sub/' + uid + '/singbox'); }
function toggleSelectUid(uid){selectedUids.has(uid)?selectedUids.delete(uid):selectedUids.add(uid);}
function toggleSelectAll(){const all=$m('select-all');const boxes=document.querySelectorAll('#ltb input[type=checkbox]');if(all.checked){boxes.forEach(c=>{c.checked=true;selectedUids.add(c.value);});}else{boxes.forEach(c=>{c.checked=false;selectedUids.clear();});}}
function batchAction(action) {
    if (selectedUids.size === 0) return toast('No items selected', true);
    if (action === 'delete' && !confirm('Delete selected?')) return;
    authenticatedFetch('/api/links/batch',{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({uids:Array.from(selectedUids),action})})
    .then(async (r)=>{
      if(!r.ok){const d = await r.json();toast(d.detail || 'Error', true);}
      else {selectedUids.clear(); loadLinks(); loadStats();}
    });
}
async function regenerateUUID(uid){const r=await authenticatedFetch('/api/links/'+uid+'/new-uuid',{method:'POST'});if(r.ok){loadLinks();toast('UUID regenerated');}}
async function disconnectLink(uid){await authenticatedFetch('/api/links/'+uid+'/disconnect',{method:'POST'});toast('Disconnected');loadLinks();}
let sortCol='created_at',sortDir='desc';
function sortLinks(col){if(sortCol===col)sortDir=sortDir==='asc'?'desc':'asc';else{sortCol=col;sortDir='desc';}allLinks.sort((a,b)=>{let va=a[sortCol]??'',vb=b[sortCol]??'';if(sortCol==='used_bytes'){va=Number(va);vb=Number(vb);}else if(sortCol==='expires_at'){va=va||'';vb=vb||'';}if(va<vb)return sortDir==='asc'?-1:1;if(va>vb)return sortDir==='asc'?1:-1;return 0;});filterLinks();}
async function togLink(el){const uid=el.dataset.uid,l=allLinks.find(x=>x.uuid===uid);if(!l)return;const na=!l.active;try{await authenticatedFetch('/api/links/'+uid,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({active:na})});l.active=na;filterLinks();loadStats();}catch{toast('Failed',true);}}
function showQuickAdd(){$m('mo-quick-add').classList.add('show');}
async function quickCreate(){const label=$m('quick-label').value.trim()||'User-'+Math.random().toString(36).slice(2,8);const limit=parseFloat($m('quick-limit').value)||0;const days=parseInt($m('quick-days').value)||0;try{const r=await authenticatedFetch('/api/links',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({label,limit_value:limit,limit_unit:'GB',days_valid:days})});if(!r.ok)throw new Error((await r.json()).detail);const data=await r.json();$m('mo-quick-add').classList.remove('show');const userUrl='https://'+location.host+'/user/'+data.uuid;toast('Created! '+userUrl);loadLinks();loadStats();}catch(e){toast('Error: '+e.message,true);}}
async function cloneLink(uid){try{const r=await authenticatedFetch('/api/links/'+uid+'/clone',{method:'POST'});if(!r.ok)throw new Error((await r.json()).detail);toast('Cloned successfully');loadLinks();loadStats();}catch(e){toast('Error: '+e.message,true);}}
function showAddMo(){$m('mo-add').classList.add('show');loadIpProfilesForSelect();}
async function createLink(){
  const label=$m('nl').value.trim()||'User-'+Math.random().toString(36).slice(2,8);
  const uuid=$m('auuid').value.trim();
  const v=parseFloat($m('nv').value)||0,mc=parseInt($m('nc').value)||0,days=parseInt($m('nd').value)||0;
  const flagCode=$m('flag-code-create').value||'';
  const ipProfileId=$m('aip-profile')?.value||'';
  const namingMode=$m('anaming-mode')?.value||'default';
  const tfo=$m('tfo-create').classList.contains('on');
  const echEnabled=$m('ech-create').classList.contains('on');
  const echSni=echEnabled?($m('ech-sni-create').value.trim()||''):'';
  const echDoh=echEnabled?($m('ech-doh-create').value.trim()||''):'';
  const allowInsecure=$m('insecure-create').classList.contains('on');
  const randomPath=$m('random-create').classList.contains('on');
  const smuxEnabled=$m('smux-create').classList.contains('on');
  const ipLimit=parseInt($m('aip-limit').value)||0;
  const protocol=$m('aprotocol').value||'vless-ws';
  const fingerprint=$m('afingerprint').value||'chrome';
  const alpn=$m('aalpn').value.trim()||'';
  const port=parseInt($m('aport').value)||443;
  const fragMode=$m('afrag-mode').value;
  let fragment='';
  if(fragMode==='tlshello') fragment='tlshello';
  else if(fragMode==='range'){
    const length=$m('afrag-length').value.trim()||'100-200';
    fragment=length;
  }
  const body={
    label,uuid,limit_value:v,limit_unit:'GB',max_connections:mc,days_valid:days,
    custom_path:$m('ap').value.trim(),custom_sni:$m('asni').value.trim(),
    custom_host:$m('ahost').value.trim(),custom_fp:fingerprint,
    color:$m('alink-color')?.value||'#39ff14',flag:flagCode,
    fragment:fragment,ip_profile_id:ipProfileId,naming_mode:namingMode,
    tfo:tfo,ech_enabled:echEnabled,ech_sni:echSni,ech_doh:echDoh,
    fragment_mode:fragMode,fragment_length:$m('afrag-length').value.trim()||'100-200',
    fragment_interval:$m('afrag-interval').value.trim()||'10-20',
    allow_insecure:allowInsecure,random_path:randomPath,
    smux_enabled:smuxEnabled,ip_limit:ipLimit,
    protocol:protocol,fingerprint:fingerprint,alpn:alpn,port:port
  };
  try{await authenticatedFetch('/api/links',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});toast('Created');$m('mo-add').classList.remove('show');loadLinks();loadStats();}catch{toast('Error',true);}
}
function showEditMo(uid){
  const l=allLinks.find(x=>x.uuid===uid); if(!l)return;
  $m('eu').value=uid; $m('euuid').value=l.uuid; $m('en2').value=l.label;
  $m('el').value=l.limit_bytes>0?(l.limit_bytes/1073741824):''; $m('ec').value=l.max_connections||''; $m('ed').value='';
  $m('ep').value=l.custom_path||''; $m('esni').value=l.custom_sni||''; $m('ehost').value=l.custom_host||'';
  $m('e-color').value=l.color||'#39ff14';
  const flag = l.flag || '';
  $m('flag-code-edit').value = flag;
  const sel = $m('flag-select-edit');
  if (flag && ['cn','nl','ru','us','ca','ir','de','gb','it','fr','tr','ae'].includes(flag)) {
    sel.value = flag;
    $m('flag-custom-edit').style.display = 'none';
  } else if (flag) {
    sel.value = 'custom';
    $m('flag-custom-edit').style.display = 'block';
    $m('flag-custom-edit').value = flag;
  } else {
    sel.value = '';
    $m('flag-custom-edit').style.display = 'none';
  }
  if(l.tfo) $m('tfo-edit').classList.add('on'); else $m('tfo-edit').classList.remove('on');
  if(l.ech_enabled){
    $m('ech-edit').classList.add('on');
    $m('ech-edit-fields').style.display='block';
    $m('ech-sni-edit').value=l.ech_sni||'';
    $m('ech-doh-edit').value=l.ech_doh||'';
  } else {
    $m('ech-edit').classList.remove('on');
    $m('ech-edit-fields').style.display='none';
  }
  if(l.allow_insecure) $m('insecure-edit').classList.add('on'); else $m('insecure-edit').classList.remove('on');
  if(l.random_path) $m('random-edit').classList.add('on'); else $m('random-edit').classList.remove('on');
  if(l.smux_enabled) $m('smux-edit').classList.add('on'); else $m('smux-edit').classList.remove('on');
  $m('eip-limit').value = l.ip_limit || 0;
  $m('eprotocol').value = l.protocol || 'vless-ws';
  // fingerprint
  const currentFp = l.fingerprint || 'chrome';
  const fpSel = $m('efingerprint-sel');
  const fpCustom = $m('efingerprint-custom');
  const fpHidden = $m('efingerprint');
  if (!currentFp || currentFp.toLowerCase() === 'none') {
      fpSel.value = 'none';
      fpCustom.style.display = 'none';
      fpHidden.value = '';   // send empty to backend (will become None)
  } else if (['chrome','firefox','safari','ios','android','edge','360','qq','random','randomized'].includes(currentFp)) {
      fpSel.value = currentFp;
      fpCustom.style.display = 'none';
      fpHidden.value = currentFp;
  } else {
      fpSel.value = 'custom';
      fpCustom.style.display = 'block';
      fpCustom.value = currentFp;
      fpHidden.value = currentFp;
  }

  // ALPN
  const currentAlpn = l.alpn || '';   // empty string means none
  const alpnSel = $m('ealpn-sel');
  const alpnCustom = $m('ealpn-custom');
  const alpnHidden = $m('ealpn');
  if (!currentAlpn) {
      alpnSel.value = '';   // select "None (default)"
      alpnCustom.style.display = 'none';
      alpnHidden.value = '';
  } else if (['http/1.1','h2,http/1.1','h2'].includes(currentAlpn)) {
      alpnSel.value = currentAlpn;
      alpnCustom.style.display = 'none';
      alpnHidden.value = currentAlpn;
  } else {
      alpnSel.value = 'custom';
      alpnCustom.style.display = 'block';
      alpnCustom.value = currentAlpn;
      alpnHidden.value = currentAlpn;
  }

  $m('eport').value = l.port || 443;
  const fragMode = l.fragment_mode||'off';
  $m('efrag-mode').value = fragMode;
  if(fragMode==='range'){
    $m('frag-edit-range').style.display='block';
    $m('efrag-length').value = l.fragment_length||'100-200';
    $m('efrag-interval').value = l.fragment_interval||'10-20';
  } else {
    $m('frag-edit-range').style.display='none';
  }
  $m('efrag').value = l.fragment||'';
  loadIpProfilesForSelectEdit(l.ip_profile_id || '');
  $m('enaming-mode').value = l.naming_mode || 'default';
  $m('et').textContent=(lang==='fa'?'ویرایش: ':'EDIT: ')+l.label; $m('mo-edit').classList.add('show');
}
async function saveEdit(){
  const uid=$m('eu').value,v=parseFloat($m('el').value)||0,mc=parseInt($m('ec').value)||0,days=parseInt($m('ed').value)||0;
  const flagCode=$m('flag-code-edit').value||'';
  const ipProfileId=$m('eip-profile')?.value||'';
  const namingMode=$m('enaming-mode')?.value||'default';
  const tfo=$m('tfo-edit').classList.contains('on');
  const echEnabled=$m('ech-edit').classList.contains('on');
  const echSni=echEnabled?($m('ech-sni-edit').value.trim()||''):'';
  const echDoh=echEnabled?($m('ech-doh-edit').value.trim()||''):'';
  const allowInsecure=$m('insecure-edit').classList.contains('on');
  const randomPath=$m('random-edit').classList.contains('on');
  const smuxEnabled=$m('smux-edit').classList.contains('on');
  const ipLimit=parseInt($m('eip-limit').value)||0;
  const protocol=$m('eprotocol').value||'vless-ws';
  const fingerprint=$m('efingerprint').value||'chrome';
  const alpn=$m('ealpn').value.trim()||'';
  const port=parseInt($m('eport').value)||443;
  const fragMode=$m('efrag-mode').value;
  let fragment='';
  if(fragMode==='tlshello') fragment='tlshello';
  else if(fragMode==='range'){
    const length=$m('efrag-length').value.trim()||'100-200';
    fragment=length;
  }
  const body={
    limit_value:v,limit_unit:'GB',max_connections:mc,label:$m('en2').value.trim(),
    custom_path:$m('ep').value.trim(),custom_sni:$m('esni').value.trim(),
    custom_host:$m('ehost').value.trim(),custom_fp:fingerprint,
    color:$m('e-color').value,flag:flagCode,
    fragment:fragment,ip_profile_id:ipProfileId,naming_mode:namingMode,
    tfo:tfo,ech_enabled:echEnabled,ech_sni:echSni,ech_doh:echDoh,
    fragment_mode:fragMode,fragment_length:$m('efrag-length').value.trim()||'100-200',
    fragment_interval:$m('efrag-interval').value.trim()||'10-20',
    allow_insecure:allowInsecure,random_path:randomPath,
    smux_enabled:smuxEnabled,ip_limit:ipLimit,
    protocol:protocol,fingerprint:fingerprint,alpn:alpn,port:port
  };
  if(days)body.days_valid=days;

  try {
    const r = await authenticatedFetch('/api/links/'+uid, {
      method:'PATCH',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify(body)
    });
    const data = await r.json();
    if (!r.ok) {
      toast(data.detail || 'Error', true);
      return;
    }
    if (data.message === 'no changes') {
      toast('No changes detected', true);
      return;
    }
    toast('Updated');
    $m('mo-edit').classList.remove('show');
    loadLinks();
  } catch(e) {
    toast('Error: ' + (e.message || 'Network error'), true);
  }
}
async function resetTraf(){const uid=$m('eu').value;if(!confirm('Reset?'))return;try{await authenticatedFetch('/api/links/'+uid,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({reset_usage:true})});toast('Reset');loadLinks();}catch{toast('Error',true);}}
async function delLink(uid){if(!confirm('Delete?'))return;try{const r=await authenticatedFetch('/api/links/'+uid,{method:'DELETE'});if(!r.ok){const d=await r.json();toast(d.detail||'Error',true);}else{toast('Deleted');loadLinks();loadStats();}}catch{toast('Error',true);}}
function cpLink(txt){copyToClipboard(txt);}
async function cpSub(uid){
    const prefix = window.panelPrefix ? '/' + window.panelPrefix : '';
    copyToClipboard('https://' + location.host + prefix + '/user/' + uid);
}
function showQR(txt){if(txt.length>2000){toast('Link too long for QR',true);return;}const img=$m('qr-img');img.src='https://api.qrserver.com/v1/create-qr-code/?size=280x280&data='+encodeURIComponent(txt);$m('mo-qr').classList.add('show');}
function dlQR(){const a=document.createElement('a');a.href=$m('qr-img').src;a.download='sulgx-qr.png';a.click();}

function updateSpeedDisplaySafe(id, bps) {
  const el = $m(id);
  if (el) el.innerHTML = formatSpeed(bps);
}
async function loadStats(){
  if (!isAuthenticated) return; 
  try{
    const r = await authenticatedFetch('/stats');
    if(!r.ok) return;
    sData = await r.json();

    const now = Date.now();
    if (prevUploadBytes === null || prevDownloadBytes === null) {
      prevUploadBytes = sData.upload_bytes;
      prevDownloadBytes = sData.download_bytes;
      prevStatsTime = now;
      updateSpeedDisplaySafe('sv-down-speed', 0);
      updateSpeedDisplaySafe('sv-up-speed', 0);
    } else {
      const intervalSec = (now - prevStatsTime) / 1000;
      if (intervalSec > 0) {
        let rawUpload = (sData.upload_bytes - prevUploadBytes) / intervalSec;
        let rawDownload = (sData.download_bytes - prevDownloadBytes) / intervalSec;
        if (sData.active_connections === 0) {
          rawUpload = 0;
          rawDownload = 0;
          uploadSpeedAvg = 0;
          downloadSpeedAvg = 0;
        } else {
          uploadSpeedAvg = rawUpload * 0.3 + uploadSpeedAvg * 0.7;
          downloadSpeedAvg = rawDownload * 0.3 + downloadSpeedAvg * 0.7;
        }
        updateSpeedDisplaySafe('sv-down-speed', downloadSpeedAvg);
        updateSpeedDisplaySafe('sv-up-speed', uploadSpeedAvg);
        updSpeedChart(uploadSpeedAvg, downloadSpeedAvg);
      }
      prevUploadBytes = sData.upload_bytes;
      prevDownloadBytes = sData.download_bytes;
      prevStatsTime = now;
    }

    safeSetHTML('sv-traffic', (sData.total_traffic_mb || 0) + '<span class="stat-unit"> MB</span>');
    safeSetText('sv-requests', sData.total_requests);
    safeSetText('sv-uptime', sData.uptime);
    safeSetHTML('sv-disk', (sData.disk_free_gb || 0) + '<span class="stat-unit"> GB</span>');
    safeSetText('last-up', t('updatedAt', { time: getLocalTimeString() }));

    if (sData.cpu_percent !== undefined && sData.cpu_percent !== null) {
      const c = sData.cpu_percent;
      safeSetText('cpu-v', c.toFixed(1) + '%');
      const bar = $m('cpu-b');
      if (bar) bar.style.width = c + '%';
    } else {
      safeSetText('cpu-v', 'N/A');
      const bar = $m('cpu-b');
      if (bar) bar.style.width = '0%';
    }

    if (sData.memory_percent !== undefined) {
      const m = sData.memory_percent;
      safeSetText('mem-v', m.toFixed(1) + '%');
      const bar = $m('mem-b');
      if (bar) bar.style.width = m + '%';
    }

    const monthlyUsageGB = sData.monthly_usage_bytes ? sData.monthly_usage_bytes / 1e9 : 0;
    const monthlyLimitGB = sData.monthly_limit_bytes ? sData.monthly_limit_bytes / 1e9 : 0;
    safeSetHTML('sv-monthly', monthlyUsageGB.toFixed(1) + ' GB' + (monthlyLimitGB > 0 ? ' / ' + monthlyLimitGB.toFixed(1) + ' GB' : ''));

    updChart();
    updDoughnutChart();
  } catch(err) {
    console.error('loadStats error:', err);
  }
}
function formatSpeed(bps){if(bps<1024)return bps.toFixed(1)+' B/s';const kbps=bps/1024;if(kbps<1024)return kbps.toFixed(1)+' KB/s';const mbps=kbps/1024;return mbps.toFixed(2)+' MB/s';}
function updateSpeedDisplay(id,bps){const el=$m(id);if(el)el.innerHTML=formatSpeed(bps);}
function safeSetText(id,text){const el=$m(id);if(el)el.textContent=text;}
function safeSetHTML(id,html){const el=$m(id);if(el)el.innerHTML=html;}
async function loadLinks(){
  if (!isAuthenticated || isInitialChecking) return;
  try {
    const r = await authenticatedFetch('/api/links');
    if (!r.ok) return;
    const d = await r.json();
    allLinks = d.links || [];
    filterLinks();
  } catch(e) { console.error('loadLinks error:', e); }
}
async function chgPw(){const cur=$m('cpw').value,nw=$m('npw').value;if(!cur||!nw){toast('Fill fields',true);return;}if(nw.length<8){toast('Password must be at least 8 characters',true);return;}if(!/[A-Z]/.test(nw)||!/[a-z]/.test(nw)||!/[0-9]/.test(nw)){toast('Password must contain uppercase, lowercase, and digit',true);return;}try{const r=await authenticatedFetch('/api/change-password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({current_password:cur,new_password:nw})});if(!r.ok)throw new Error((await r.json()).detail||'Error');toast('Password updated');}catch(e){toast(e.message,true);}}
function initChart(){
  const ctx=$m('tc'); if(!ctx||tChart)return;
  tChart=new Chart(ctx,{
    type:'bar',
    data:{labels:[],datasets:[{label:'MB',data:[],backgroundColor:'rgba(57,255,20,0.6)',borderColor:'#39ff14',borderWidth:1,barPercentage:0.7,categoryPercentage:0.9}]},
    options:{
      responsive:true, maintainAspectRatio:false,
      plugins:{legend:{display:false}},
      scales:{x:{ticks:{color:'rgba(57,255,20,0.3)',maxRotation:45}},y:{ticks:{color:'rgba(57,255,20,0.3)',callback:v=>v+' MB'},beginAtZero:true}}
    }
  });
  updChartColors();
}
function updChartColors(){if(!tChart)return;const col=theme==='light'?'#000':'rgba(57,255,20,0.4)';tChart.options.scales.x.ticks.color=col;tChart.options.scales.y.ticks.color=col;tChart.update();}
function getPanelTime(isoString){const d=new Date(isoString);if(!isNaN(d)){d.setMinutes(d.getMinutes()+d.getTimezoneOffset()+timezoneOffset*60);}return d;}
function getLocalTimeString(){const d=new Date();d.setMinutes(d.getMinutes()+d.getTimezoneOffset()+timezoneOffset*60);return `${String(d.getHours()).padStart(2,'0')}:${String(d.getMinutes()).padStart(2,'0')}:${String(d.getSeconds()).padStart(2,'0')}`;}
function updChart(){
  if(!tChart||!sData.hourly_traffic)return;
  const labels = []; const data = [];
  for(let h=0;h<24;h++){
    const key = `${h.toString().padStart(2,'0')}:00`;
    labels.push(key);
    data.push(Math.round((sData.hourly_traffic[key]||0)/1048576));
  }
  tChart.data.labels = labels;
  tChart.data.datasets[0].data = data;
  tChart.update();
}
let doughnutChart=null;
function initDoughnutChart(){const ctx=$m('doughnut-chart');if(!ctx||doughnutChart)return;doughnutChart=new Chart(ctx,{type:'doughnut',data:{labels:[],datasets:[{data:[],backgroundColor:[]}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{position:'bottom'},tooltip:{callbacks:{label:ctx=>`${ctx.label}: ${ctx.raw>=1e9?(ctx.raw/1e9).toFixed(1)+' GB':(ctx.raw/1e6).toFixed(1)+' MB'}`}}}}});}
function updDoughnutChart(){if(!doughnutChart)return;const labels=[],data=[],colors=[];allLinks.filter(l=>l.used_bytes>0).forEach(l=>{labels.push(l.label);data.push(l.used_bytes);colors.push(l.color||'#39ff14');});doughnutChart.data.labels=labels;doughnutChart.data.datasets[0].data=data;doughnutChart.data.datasets[0].backgroundColor=colors;doughnutChart.update();}
let speedChart=null,speedHistory=[];
function initSpeedChart(){
  const ctx=$m('speed-chart');if(!ctx||speedChart)return;
  speedChart=new Chart(ctx,{type:'line',data:{labels:[],datasets:[{label:'DL',borderColor:'#4ade80',data:[],tension:0.2},{label:'UL',borderColor:'#f87171',data:[],tension:0.2}]},options:{responsive:true,maintainAspectRatio:false,plugins:{tooltip:{callbacks:{label:ctx=>ctx.dataset.label+': '+formatSpeed(ctx.raw)}}},scales:{y:{max:undefined,beginAtZero:true,ticks:{callback:v=>formatSpeed(v)}}}}});
}
function updSpeedChart(up,down){
  if(!speedChart)return;
  const t=getLocalTimeString();
  speedHistory.push({t,up,down});
  if(speedHistory.length>60)speedHistory.shift();
  const maxVal = Math.max(...speedHistory.map(s=>Math.max(s.up,s.down)), 1);
  speedChart.options.scales.y.max = maxVal * 1.2;
  speedChart.data.labels=speedHistory.map(s=>s.t);
  speedChart.data.datasets[0].data=speedHistory.map(s=>s.down);
  speedChart.data.datasets[1].data=speedHistory.map(s=>s.up);
  speedChart.update();
}
let currentProfileId = 'all';
let currentProfileAddresses = [];

async function buildProfileTabs() {
    const r = await authenticatedFetch('/api/ip-profiles');
    const profiles = await r.json();
    const tabsDiv = $m('profile-tabs');
    if (!tabsDiv) return;
    tabsDiv.innerHTML = '<button class="pill-btn active" data-profile="all" onclick="switchProfileView(\'all\')">All</button>';
    profiles.forEach(p => {
        const btn = document.createElement('button');
        btn.className = 'pill-btn';
        btn.textContent = p.name;
        btn.dataset.profile = p.id;
        btn.onclick = () => switchProfileView(p.id);
        tabsDiv.appendChild(btn);
    });
}

async function switchProfileView(pid) {
    currentProfileId = pid;
    document.querySelectorAll('#profile-tabs .pill-btn').forEach(b => b.classList.remove('active'));
    const activeBtn = document.querySelector(`#profile-tabs .pill-btn[data-profile="${pid}"]`);
    if (activeBtn) activeBtn.classList.add('active');
    await loadAddrs();
}

async function loadAddressesForProfile(pid) {
    try {
        const r = await authenticatedFetch(`/api/ip-profiles/${pid}/addresses`);
        if (!r.ok) return;
        const addresses = await r.json();
        currentProfileAddresses = addresses;
        allAddrs = addresses.map(a => a.address);
        renderAddrs();
    } catch(e) {
        console.error('loadAddressesForProfile error:', e);
    }
}

async function loadAddrs(){
  if (!isAuthenticated || isInitialChecking) return;
  if (currentProfileId !== 'all') {
      await loadAddressesForProfile(currentProfileId);
      return;
  }
  try {
      const r = await authenticatedFetch('/api/addresses');
      if(!r.ok) return;
      allAddrs = (await r.json()).addresses || [];
      currentProfileAddresses = [];
      renderAddrs();
  } catch(e) { console.error('loadAddrs error:', e); }
}

function renderAddrs() {
    const el = $m('addr-list');
    if (!el) return;
    if (currentProfileId !== 'all' && currentProfileAddresses.length > 0) {
        renderProfileAddresses(currentProfileAddresses);
        return;
    }
    if (!allAddrs.length) {
        el.innerHTML = '<div style="color:var(--text3);font-size:0.9rem">No addresses added</div>';
        return;
    }
    let buffer = '';
    allAddrs.forEach((a, i) => {
        buffer += `<div style="display:flex;align-items:center;justify-content:space-between;padding:8px 12px;background:var(--surface3);border:1px solid var(--border);border-radius:10px;margin-bottom:6px"><div style="display:flex;align-items:center;gap:8px"><input type="checkbox" class="addr-checkbox" data-index="${i}" ${selectedAddrIndices.has(i)?'checked':''} onchange="toggleSelectAddr(${i})"><span style="font-size:0.9rem;font-weight:600">${esc(a)}</span></div><div style="display:flex;gap:4px;"><button class="act-btn act-edit" onclick="showEditAddr(${i})">✏️</button><button class="act-btn act-del" onclick="delAddr(${i})">🗑️</button></div></div>`;
    });
    el.innerHTML = buffer;
}

function renderProfileAddresses(addresses) {
    const el = $m('addr-list');
    if (!el) return;
    if (!addresses.length) {
        el.innerHTML = '<div style="color:var(--text3);font-size:0.9rem">No addresses in this profile</div>';
        return;
    }
    let buffer = '';
    addresses.forEach((a, i) => {
        const flagEmoji = a.flag ? codeToFlag(a.flag) : '';
        const displayName = a.name ? esc(a.name) : '';
        const displayAddr = esc(a.address);
        const metaText = displayName ? `${displayName} (${displayAddr})` : displayAddr;
        buffer += `<div style="display:flex;align-items:center;justify-content:space-between;padding:8px 12px;background:var(--surface3);border:1px solid var(--border);border-radius:10px;margin-bottom:6px">
                  <div style="display:flex;align-items:center;gap:8px">
                    <input type="checkbox" class="addr-checkbox" data-index="${i}" onchange="toggleSelectAddr(${i})">
                    <span style="font-size:0.9rem;font-weight:600">${flagEmoji ? flagEmoji + ' ' : ''}${esc(metaText)}</span>
                  </div>
                  <div style="display:flex;gap:4px;">
                    <button class="act-btn act-edit" onclick="showEditAddr(${i})">✏️</button>
                    <button class="act-btn act-del" onclick="delAddr(${i})">🗑️</button>
                  </div>
                </div>`;
    });
    el.innerHTML = buffer;
}

function toggleSelectAddr(i){selectedAddrIndices.has(i)?selectedAddrIndices.delete(i):selectedAddrIndices.add(i);}
function toggleAllAddresses(){
  const boxes = document.querySelectorAll('.addr-checkbox');
  const allChecked = Array.from(boxes).every(b => b.checked);
  boxes.forEach(b => { b.checked = !allChecked; });
  selectedAddrIndices.clear();
  if (!allChecked) {
    boxes.forEach(b => { if (b.checked) selectedAddrIndices.add(parseInt(b.dataset.index)); });
  }
}
function copySelectedAddrs(){
  const selected = Array.from(selectedAddrIndices).map(i => allAddrs[i]);
  if (selected.length === 0) return toast('No addresses selected', true);
  copyToClipboard(selected.join('\n'));
}
async function bulkDeleteAddrs(){if(selectedAddrIndices.size===0)return toast('No addresses selected',true);if(!confirm('Delete selected addresses?'))return;const indices = Array.from(selectedAddrIndices);try{const r=await authenticatedFetch('/api/addresses/bulk-delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({indices})});if(r.ok){selectedAddrIndices.clear();await loadAddrs();toast('Deleted selected');}}catch(e){toast('Error',true);}}
function showEditAddr(i){editingAddrIndex=i;$m('edit-addr-input').value=allAddrs[i];$m('mo-addr-edit').classList.add('show');}
async function saveAddrEdit(){const newAddr=$m('edit-addr-input').value.trim();if(!newAddr)return toast('Invalid address',true);try{const r=await authenticatedFetch('/api/addresses/'+editingAddrIndex,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({address:newAddr})});if(r.ok){toast('Address updated');$m('mo-addr-edit').classList.remove('show');await loadAddrs();}else{const d=await r.json();toast(d.detail||'Error updating',true);}}catch(e){toast('Error',true);}}
async function addBatchAddrs(){const raw=$m('batch-addrs').value;const lines=raw.split('\n').map(l=>l.trim()).filter(l=>l);if(!lines.length)return;try{const r=await authenticatedFetch('/api/addresses/batch',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({addresses:lines})});const d=await r.json();toast(`Added ${d.added} addresses`+(d.errors?` (${d.errors} errors)`:''));$m('batch-addrs').value='';await loadAddrs();}catch(e){toast('Batch add failed',true);}}
async function deleteAllAddrs(){if(!confirm('Delete all addresses?'))return;try{await authenticatedFetch('/api/addresses',{method:'DELETE'});toast('All deleted');await loadAddrs();}catch{toast('Error',true);}}
async function delAddr(i){if(!confirm('Delete?'))return;try{await authenticatedFetch('/api/addresses/'+i,{method:'DELETE'});toast('Deleted');await loadAddrs();}catch{toast('Error',true);}}
async function exportLinks(){try{const r=await authenticatedFetch('/api/export-links');const data=await r.json();const blob=new Blob([JSON.stringify(data,null,2)],{type:'application/json'});const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='sulgx-links.json';a.click();}catch{toast('Export failed',true);}}
async function importLinks(input){const file=input.files[0];if(!file)return;try{const text=await file.text();const data=JSON.parse(text);const r=await authenticatedFetch('/api/import-links',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});const res=await r.json();toast(`Imported ${res.imported} links`);loadLinks();loadStats();}catch{toast('Import failed',true);}input.value='';}
async function importIpFile(input){
  const file = input.files[0];
  if(!file) return;
  try {
    const text = await file.text();
    const lines = text.split(/[\r\n]+/g).map(l => l.trim()).filter(l => l);
    
    if(lines.length === 0) return toast('No addresses found in file', true);
    
    const r = await authenticatedFetch('/api/addresses/batch',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({addresses:lines})
    });
    
    const d = await r.json();
    toast(`Imported ${d.added} addresses` + (d.errors ? ` (${d.errors} errors)` : ''));
    await loadAddrs();
  } catch(e) { 
    toast('Import .txt failed', true); 
    console.error(e);
  }
  input.value='';
}
async function resolveAllFlags() {
    if (!allAddrs || allAddrs.length === 0) return toast('No addresses', true);
    const btn = document.querySelector('[data-en="Resolve All Flags"]') || document.querySelector('[data-fa="دریافت همه پرچم‌ها"]');
    if (btn) { btn.disabled = true; btn.textContent = 'Resolving...'; }
    try {
        const r = await authenticatedFetch('/api/resolve-flags-and-update', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({}) });
        const data = await r.json();
        toast(`Resolved flags for ${data.resolved} addresses`);
        await loadAddrs();
    } catch (e) {
        toast('Resolve failed: ' + e.message, true);
    }
    if (btn) { btn.disabled = false; btn.textContent = 'Resolve All Flags'; }
}
async function loadIpProfiles(){
    const r = await authenticatedFetch('/api/ip-profiles');
    const profiles = await r.json();
    const list = $m('ip-profiles-list');
    if (!list) return;
    const scrollTop = list.scrollTop;
    renderIpProfiles(profiles);
    list.scrollTop = scrollTop;
}
async function loadIpProfilesForSelect(){const r=await authenticatedFetch('/api/ip-profiles');const profiles=await r.json();const sel=$m('aip-profile');if(!sel)return;sel.innerHTML='<option value="">None</option>';profiles.forEach(p=>{sel.innerHTML+=`<option value="${p.id}">${p.name} (${p.address_count})</option>`;});}
async function loadIpProfilesForSelectEdit(currentId){const r=await authenticatedFetch('/api/ip-profiles');const profiles=await r.json();const sel=$m('eip-profile');if(!sel)return;sel.innerHTML='<option value="">None</option>';profiles.forEach(p=>{sel.innerHTML+=`<option value="${p.id}" ${p.id===currentId?'selected':''}>${p.name} (${p.address_count})</option>`;});}
function renderIpProfiles(profiles){
  const list=$m('ip-profiles-list'); if(!list)return;
  list.innerHTML = profiles.map(p=>`
    <div class="status-glass-card active" style="cursor:default; text-align:left;">
      <div style="font-weight:700;">${esc(p.name)} <span style="font-size:0.7rem;">(${p.address_count} IPs)</span></div>
      <div style="display:flex; gap:4px; margin-top:6px;">
        <button class="act-btn act-edit" onclick="editIpProfile('${p.id}')">✏️</button>
        <button class="act-btn act-del" onclick="deleteIpProfile('${p.id}')">🗑️</button>
      </div>
    </div>
  `).join('');
}
async function createIpProfile(){
  const name = $m('new-profile-name').value.trim();
  if (!name) return toast('Enter a name', true);
  $m('ip-profile-id').value = '';
  $m('ip-profile-name').value = name;
  $m('ip-profile-addrs').value = '';
  $m('mo-ip-profile').classList.add('show');
  $m('new-profile-name').value = '';
}
async function deleteIpProfile(pid){
  if(!confirm('Delete this profile?'))return;
  await authenticatedFetch('/api/ip-profiles/'+pid,{method:'DELETE'});
  await loadIpProfiles();
  await buildProfileTabs();
  await loadIpProfilesForSelect();
  await loadIpProfilesForSelectEdit();
  if (currentProfileId === pid) {
      currentProfileId = 'all';
      document.querySelectorAll('#profile-tabs .pill-btn').forEach(b => b.classList.remove('active'));
      const allBtn = document.querySelector('#profile-tabs .pill-btn[data-profile="all"]');
      if (allBtn) allBtn.classList.add('active');
      await loadAddrs();
  }
}
async function editIpProfile(pid) {
    const r = await authenticatedFetch('/api/ip-profiles/' + pid + '/addresses');
    const addresses = await r.json();
    const profiles = await (await authenticatedFetch('/api/ip-profiles')).json();
    const profile = profiles.find(p => p.id === pid);
    $m('ip-profile-id').value = pid;
    $m('ip-profile-name').value = profile ? profile.name : '';
    const lines = addresses.map(a => {
        let line = a.address;
        if (a.name || a.flag || a.sort_number) {
            line += '#' + (a.name || '');
            if (a.flag || a.sort_number) line += '+' + (a.flag || '');
            if (a.sort_number) line += '+' + a.sort_number;
        }
        return line;
    });
    $m('ip-profile-addrs').value = lines.join('\n');
    $m('mo-ip-profile').classList.add('show');
}
async function saveIpProfile(){
  let pid = $m('ip-profile-id').value;
  const name = $m('ip-profile-name').value.trim();
  const raw = $m('ip-profile-addrs').value.trim();

  if (!name) return toast('Enter a name', true);

  if (!pid) {
    const r = await authenticatedFetch('/api/ip-profiles', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name })
    });
    const data = await r.json();
    pid = data.id;
  } else {
    await authenticatedFetch('/api/ip-profiles/' + pid, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name })
    });
  }

  const newAddrs = raw.split('\n').map(l => l.trim()).filter(l => l);
  if (pid) {
    await authenticatedFetch('/api/ip-profiles/' + pid + '/addresses', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ addresses: newAddrs })
    });
  }

  $m('mo-ip-profile').classList.remove('show');
  await loadIpProfiles();
  await buildProfileTabs();
  await loadIpProfilesForSelect();
  await loadIpProfilesForSelectEdit();
  if (currentProfileId !== 'all') {
      await loadAddressesForProfile(currentProfileId);
  }
}
async function detectFlagsForProfile() {
    const raw = $m('ip-profile-addrs').value.trim();
    if (!raw) return toast('No addresses to process', true);
    const lines = raw.split('\n').map(l => l.trim()).filter(l => l);
    const ips = lines.map(line => {
        const ip = line.split('#')[0].trim();
        return ip;
    });
    try {
        const r = await authenticatedFetch('/api/resolve-flags', { 
            method: 'POST', 
            headers: {'Content-Type': 'application/json'}, 
            body: JSON.stringify({ips}) 
        });
        const flags = await r.json();
        const updatedLines = lines.map(line => {
            let [ip, rest] = line.split('#', 2);
            ip = ip.trim();
            let name = '', flag = '', sortNum = '';
            if (rest) {
                const metaParts = rest.split('+');
                name = metaParts[0] || '';
                flag = metaParts[1] || '';
                sortNum = metaParts[2] || '';
            }
            const newFlag = flags[ip] || flag;
            let newLine = ip;
            if (name || newFlag || sortNum) {
                newLine += '#' + (name || '');
                if (newFlag || sortNum) newLine += '+' + (newFlag || '');
                if (sortNum) newLine += '+' + sortNum;
            }
            return newLine;
        });
        $m('ip-profile-addrs').value = updatedLines.join('\n');
        toast('Flags detected and updated');
    } catch(e) { toast('Detection failed: ' + e.message, true); }
}
const dohPresets = [
  "https://dns.cloudflare.com/dns-query",
  "https://dns.google/dns-query",
  "https://dns.quad9.net/dns-query",
  "https://doh.opendns.com/dns-query",
  "https://dns.adguard.com/dns-query",
  "https://doh.cleanbrowsing.org/doh/family-filter/"
];

function buildDohUI() {
  authenticatedFetch('/api/doh-upstreams').then(r => r.json()).then(d => {
    const current = d.upstreams || [];
    const presetsDiv = $m('doh-presets');
    if (!presetsDiv) return;
    presetsDiv.innerHTML = '';
    current.forEach(u => {
      const isPreset = dohPresets.includes(u);
      const wrapper = document.createElement('div');
      wrapper.style.display = 'inline-flex';
      wrapper.style.alignItems = 'center';
      wrapper.style.gap = '4px';
      const btn = document.createElement('button');
      btn.className = 'pill-btn active';
      btn.textContent = u;
      btn.onclick = () => { btn.classList.toggle('active'); };
      wrapper.appendChild(btn);
      if (!isPreset) {
        const delBtn = document.createElement('button');
        delBtn.className = 'pill-btn';
        delBtn.textContent = '✕';
        delBtn.style.padding = '4px 8px';
        delBtn.onclick = (e) => {
          e.stopPropagation();
          wrapper.remove();
        };
        wrapper.appendChild(delBtn);
      }
      presetsDiv.appendChild(wrapper);
    });
    const card = $m('card-doh');
    if (d.enabled) {
      card.classList.add('active'); card.classList.remove('inactive');
      $m('set-doh-enabled').value = '1';
    } else {
      card.classList.add('inactive'); card.classList.remove('active');
      $m('set-doh-enabled').value = '0';
    }
    updateDohEndpoint();
  });
}

function addCustomDoh() {
  const input = $m('custom-doh-input');
  const val = input.value.trim();
  if (val && val.startsWith('http')) {
    const presetsDiv = $m('doh-presets');
    const wrapper = document.createElement('div');
    wrapper.style.display = 'inline-flex';
    wrapper.style.alignItems = 'center';
    wrapper.style.gap = '4px';
    const btn = document.createElement('button');
    btn.className = 'pill-btn active';
    btn.textContent = val;
    btn.onclick = () => { btn.classList.toggle('active'); };
    const delBtn = document.createElement('button');
    delBtn.className = 'pill-btn';
    delBtn.textContent = '✕';
    delBtn.style.padding = '4px 8px';
    delBtn.onclick = (e) => {
      e.stopPropagation();
      wrapper.remove();
    };
    wrapper.appendChild(btn);
    wrapper.appendChild(delBtn);
    presetsDiv.appendChild(wrapper);
    input.value = '';
  }
}

async function saveDohUpstreams() {
  const active = Array.from(document.querySelectorAll('#doh-presets .pill-btn.active')).map(b => b.textContent.trim());
  const enabled = $m('card-doh').classList.contains('active');
  await authenticatedFetch('/api/doh-upstreams', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ upstreams: active, enabled: enabled })
  });
}

async function testDohPing() {
  const r = await authenticatedFetch('/api/doh-ping');
  const data = await r.json();
  const tbody = document.querySelector('#doh-ping-table tbody');
  tbody.innerHTML = '';
  for (const [url, res] of Object.entries(data)) {
    const row = `<tr>
        <td>${url}</td>
        <td>${res.latency_ms !== null ? res.latency_ms + ' ms' : '–'}</td>
        <td style="color:${res.status==='failed'?'var(--red)':'var(--green)'}">${res.status}</td>
    </tr>`;
    tbody.insertAdjacentHTML('beforeend', row);
  }
  document.getElementById('doh-ping-table').style.display = '';
}

function updateDohEndpoint() {
  const el = $m('doh-endpoint-url');
  if (!el) return;
  const domain = window.location.host;
  const prefix = window.panelPrefix ? '/' + window.panelPrefix : '';
  el.value = `https://${domain}${prefix}/dns-query`;
}

function copyDohEndpoint() {
  const el = $m('doh-endpoint-url');
  if (el && el.value) {
    copyToClipboard(el.value);
    toast('DOH URL copied');
  }
}

let editingPanelIndex = -1;
function renderMultiPanel(panels) {
  const list = $m('multipanel-list');
  list.innerHTML = panels.map((p,i)=>`
    <div class="status-glass-card active">
      <div style="display:flex; justify-content:space-between; align-items:center;">
        <span style="font-weight:700;" onclick="window.open('${esc(p.url)}', '_blank')">${esc(p.name)}</span>
        <div>
          <button class="act-btn act-edit" onclick="editMultiPanel(${i})">✏️</button>
          <button class="act-btn act-del" onclick="removeMultiPanel(${i})">🗑️</button>
        </div>
      </div>
      <div style="font-size:0.7rem; margin-top:4px;">${esc(p.url)}</div>
    </div>
  `).join('');
}
function loadMultiPanel(){
  const list=$m('multipanel-list');
  if(!list)return;
  const stored=localStorage.getItem('multipanel')||'[]';
  const panels=JSON.parse(stored);
  renderMultiPanel(panels);
}
function editMultiPanel(index) {
  const panels = JSON.parse(localStorage.getItem('multipanel')||'[]');
  $m('new-panel-name').value = panels[index].name;
  $m('new-panel-url').value = panels[index].url;
  editingPanelIndex = index;
}
function addMultiPanel(){
  const name=$m('new-panel-name').value.trim();
  const url=$m('new-panel-url').value.trim();
  if(!name||!url)return toast('Enter name and URL');
  const stored=localStorage.getItem('multipanel')||'[]';
  const panels=JSON.parse(stored);
  if (editingPanelIndex >= 0) {
    panels[editingPanelIndex] = {name, url};
    editingPanelIndex = -1;
  } else {
    panels.push({name,url});
  }
  localStorage.setItem('multipanel',JSON.stringify(panels));
  $m('new-panel-name').value=''; $m('new-panel-url').value='';
  renderMultiPanel(panels);
}
function removeMultiPanel(index){
  const stored=localStorage.getItem('multipanel')||'[]';
  const panels=JSON.parse(stored);
  panels.splice(index,1);
  localStorage.setItem('multipanel',JSON.stringify(panels));
  renderMultiPanel(panels);
  editingPanelIndex = -1;
}

let currentProvider=null;
function buildProviderPills(){const container=$m('provider-btns');if(!container)return;container.innerHTML='';Object.keys(providerIPs).forEach(prov=>{const btn=document.createElement('button');btn.className='pill-btn';btn.textContent=prov;btn.onclick=()=>selectProvider(prov,btn);if(prov==='Railway') btn.classList.add('railway-hl');container.appendChild(btn);});const customBtn=document.createElement('button');customBtn.className='pill-btn';customBtn.textContent='Custom';customBtn.onclick=()=>selectProvider('Custom',customBtn);container.appendChild(customBtn);}
function selectProvider(prov,btn){
    document.querySelectorAll('#provider-btns .pill-btn').forEach(b=>b.classList.remove('active'));
    btn.classList.add('active');
    currentProvider=prov;
    const rangeSection=$m('range-section'), railNote=$m('railway-note');
    if(prov==='Custom'){
        rangeSection.style.display='none'; railNote.style.display='none';
        $m('scan-ips').value=''; return;
    }
    rangeSection.style.display='flex';
    railNote.style.display = (prov==='Railway') ? 'block' : 'none';
    const rangeBtns=$m('range-btns'); rangeBtns.innerHTML='';
    const ranges=providerIPs[prov]?.ipv4||[];
    ranges.forEach(r=>{const b=document.createElement('button');b.className='pill-btn';b.textContent=r;b.onclick=()=>{loadRangeIPs(r,b);};rangeBtns.appendChild(b);});
    const allIPs=[]; ranges.forEach(r=>{allIPs.push(...expandCIDR(r));});
    $m('scan-ips').value=allIPs.join('\n');
}
function loadRangeIPs(range,btn){document.querySelectorAll('#range-btns .pill-btn').forEach(b=>b.classList.remove('active'));if(btn)btn.classList.add('active');$m('scan-ips').value=expandCIDR(range).join('\n');}
function expandCIDR(cidr){
    const parts = cidr.split('/');
    if(parts.length !== 2) return [cidr];
    const ip = parts[0].trim(), mask = parseInt(parts[1]);
    if(isNaN(mask) || mask < 16 || mask > 32) return [cidr];
    const ipParts = ip.split('.').map(Number);
    if(ipParts.length !== 4 || ipParts.some(p => isNaN(p) || p > 255)) return [cidr];
    const count = Math.pow(2, 32 - mask);
    const limit = Math.min(count, 256);
    if(count > limit) toast(lang === 'fa' ? `رنج بزرگ: فقط ${limit} آی‌پی اول استخراج شد.` : `Large range: only first ${limit} IPs extracted.`);
    const start = (ipParts[0] << 24) + (ipParts[1] << 16) + (ipParts[2] << 8) + ipParts[3];
    const base = start & (~((1 << (32 - mask)) - 1));
    const result = [];
    for(let i = 0; i < limit; i++){
        const addr = base + i;
        const ipStr = `${(addr >>> 24) & 255}.${(addr >>> 16) & 255}.${(addr >>> 8) & 255}.${addr & 255}`;
        if(dnsRanges.has(ipStr)) continue;
        result.push(ipStr);
    }
    return result;
}

let totalScanCount = 0, scannedCount = 0, wsScanner = null;

function stopScan(){
    if(wsScanner){ wsScanner.close(); wsScanner = null; }
    $m('scan-start-btn').style.display = 'inline-flex';
    $m('scan-stop-btn').style.display = 'none';
}

async function startIPScan(){
    const raw = $m('scan-ips').value;
    const lines = raw.split('\n').map(l => l.trim()).filter(l => l);
    if(!lines.length) return;
    const items = [];
    lines.forEach(l => {
        if(l.includes('/')) items.push(...expandCIDR(l));
        else if(!dnsRanges.has(l.trim())) items.push(l.trim());
    });
    const unique = [...new Set(items)];
    const MAX_IPS = 256;
    if (unique.length > MAX_IPS) {
        toast(lang === 'fa' ? `حداکثر ${MAX_IPS} آی‌پی مجاز است. شما ${unique.length} آی‌پی وارد کردید.` : `Max ${MAX_IPS} IPs allowed. You entered ${unique.length}.`, true);
        return;
    }
    totalScanCount = unique.length; scannedCount = 0;
    $m('scan-tbody').innerHTML = '';
    $m('scan-progress').style.width = '0%'; $m('progress-text').textContent = '0%';
    $m('scan-start-btn').style.display = 'none'; $m('scan-stop-btn').style.display = 'inline-flex';
    if(wsScanner) wsScanner.close();
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    wsScanner = new WebSocket(`${proto}//${location.host}/ws/scanner`);
    wsScanner.onopen = () => wsScanner.send(JSON.stringify({ips: unique}));
    wsScanner.onmessage = (e) => {
        const d = JSON.parse(e.data);
        if(d.done){
            wsScanner.close();
            $m('scan-start-btn').style.display = 'inline-flex';
            $m('scan-stop-btn').style.display = 'none';
            fetchLocationData();
            toast(lang === 'fa' ? 'اسکن با موفقیت تمام شد.' : 'Scan finished successfully.');
            return;
        }
        scannedCount++;
        const pct = Math.round((scannedCount / totalScanCount) * 100);
        $m('scan-progress').style.width = pct + '%'; $m('progress-text').textContent = pct + '%';
        const row = `<tr class="scan-row" data-ip="${esc(d.ip)}"><td>${esc(d.ip)}</td><td style="color:${d.ok ? 'var(--green)' : 'var(--red)'}">${d.ok ? t('reachable') : t('failed')}</td><td>${d.tcp_latency!=null ? d.tcp_latency+' ms' : '–'}</td><td>${d.https_latency!=null ? d.https_latency+' ms' : '–'}</td><td class="location-cell">–</td></tr>`;
        $m('scan-tbody').insertAdjacentHTML('beforeend', row);
    };
    wsScanner.onerror = () => {
        toast(lang === 'fa' ? 'خطای اسکنر (احتمالاً تایم‌اوت)' : 'Scanner error (Timeout likely)', true);
        $m('scan-start-btn').style.display = 'inline-flex';
        $m('scan-stop-btn').style.display = 'none';
    };
    wsScanner.onclose = () => {
        $m('scan-start-btn').style.display = 'inline-flex';
        $m('scan-stop-btn').style.display = 'none';
    };
}
async function fetchLocationData(){
    const rows = document.querySelectorAll('#scan-tbody tr.scan-row');
    const ips = [];
    rows.forEach(r => {
        if(r.querySelector('td:nth-child(2)')?.textContent.includes('✅')) {
            ips.push(r.dataset.ip);
        }
    });
    if(ips.length===0) return;
    try {
        const res = await fetch('/api/resolve-flags', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ips})});
        const data = await res.json();
        const locations = new Map();
        rows.forEach(r => {
            const ip = r.dataset.ip;
            const info = data[ip];
            const locCell = r.querySelector('.location-cell');
            if(info && locCell){
                let text = '';
                if(info.city) text += info.city;
                if(info.country) text += (text?', ':'') + info.country;
                if(!text) text = 'Unknown';
                locCell.textContent = text;
                if(info.countryCode){
                    const key = info.countryCode;
                    if(!locations.has(key)){
                        locations.set(key, { name: info.country || key, code: key, count: 0 });
                    }
                    locations.get(key).count++;
                } else {
                    const key = 'unknown';
                    if(!locations.has(key)){
                        locations.set(key, { name: 'Unknown', code: key, count: 0 });
                    }
                    locations.get(key).count++;
                }
            }
        });
        const container = document.getElementById('location-checkboxes');
        if(!container) return;
        container.innerHTML = '';
        const sortedLocations = Array.from(locations.values()).sort((a,b) => a.name.localeCompare(b.name));
        sortedLocations.forEach(loc => {
            const label = document.createElement('label');
            label.className = 'location-checkbox';
            const cb = document.createElement('input');
            cb.type = 'checkbox';
            cb.checked = true;
            cb.dataset.code = loc.code;
            cb.addEventListener('change', applyLocationFilter);
            label.appendChild(cb);
            label.appendChild(document.createTextNode(`${loc.name} (${loc.count})`));
            container.appendChild(label);
        });
        document.getElementById('location-filter').style.display = 'flex';
    } catch(e) {}
}
function applyLocationFilter(){
    const checkedCodes = new Set();
    document.querySelectorAll('#location-checkboxes input[type="checkbox"]:checked').forEach(cb => checkedCodes.add(cb.dataset.code));
    const rows = document.querySelectorAll('#scan-tbody tr.scan-row');
    rows.forEach(r => {
        const locText = r.querySelector('.location-cell')?.textContent || '';
        const visible = checkedCodes.size === 0 || Array.from(checkedCodes).some(c => locText.includes(c));
        r.style.display = visible ? '' : 'none';
    });
}
function resetLocationFilter(){
    document.querySelectorAll('#location-checkboxes input[type="checkbox"]').forEach(cb => cb.checked = true);
    applyLocationFilter();
}
function sortBestIPs(){
    const rows=Array.from($m('scan-tbody').querySelectorAll('tr.scan-row'));
    const items=[];
    rows.forEach(r=>{
        const cells=r.querySelectorAll('td');
        const ip=cells[0].textContent.trim();
        const ok=cells[1].textContent.includes('✅');
        const tcp=parseFloat(cells[2].textContent);
        if(ok&&!isNaN(tcp))items.push({ip,latency:tcp});
    });
    if(items.length===0){toast('No reachable IPs',true);return;}
    items.sort((a,b)=>a.latency-b.latency);
    const tbody=$m('scan-tbody');
    const newRows = items.map(i => {
        const oldRow = document.querySelector(`tr.scan-row[data-ip="${i.ip}"]`);
        return oldRow ? oldRow.cloneNode(true) : null;
    }).filter(Boolean);
    tbody.innerHTML = '';
    newRows.forEach(r => tbody.appendChild(r));
}
function copyReachableSorted(){
  const rows=Array.from($m('scan-tbody').querySelectorAll('tr.scan-row'));
  const reachable=[];
  rows.forEach(r=>{
    const cells=r.querySelectorAll('td');
    const ip=cells[0].textContent.trim();
    const ok=cells[1].textContent.includes('✅');
    const lat=parseFloat(cells[2].textContent);
    if(ok&&!isNaN(lat))reachable.push({ip,lat});
  });
  if(reachable.length===0){toast('No reachable IPs found',true);return;}
  reachable.sort((a,b)=>a.lat-b.lat);
  copyToClipboard(reachable.map(item=>item.ip).join('\n'));
}

async function createProfileFromReachable() {
  const rows = Array.from($m('scan-tbody').querySelectorAll('tr.scan-row'));
  const reachable = [];
  rows.forEach(r=>{
    const cells = r.querySelectorAll('td');
    const ip = cells[0].textContent.trim();
    const ok = cells[1].textContent.includes('✅');
    if(ok) reachable.push(ip);
  });
  if (reachable.length === 0) return toast('No reachable IPs', true);
  window._scannerIps = reachable;
  $m('mo-scanner-profile').classList.add('show');
}

async function saveScannerProfile() {
  const name = $m('scanner-profile-name').value.trim();
  const ips = window._scannerIps;
  if (!name || !ips) return;
  try {
    const r = await fetch('/api/ip-profiles/from-scanner', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({name, ips})
    });
    if (r.ok) {
      toast('Profile created');
      $m('mo-scanner-profile').classList.remove('show');
      loadIpProfiles();
    }
  } catch(e) { toast('Error', true); }
}

async function loadLogs(){
  if (!isAuthenticated || isInitialChecking) return;
  try{const r=await authenticatedFetch('/api/logs');const d=await r.json();const logs=d.logs||[];const tbody=$m('logs-tbody'),empty=$m('logs-empty');if(!tbody)return;if(!logs.length){tbody.innerHTML='';empty.style.display='block';return;}empty.style.display='none';tbody.innerHTML=logs.map((l,i)=>{const local=getPanelTime(l.time);return`<tr><td>${i+1}</td><td>${local.toISOString().replace('T',' ').split('.')[0]}</td><td>${esc(l.type||'Event')}</td><td>${esc(l.error||'')}</td></tr>`}).join('');}catch(err){console.error('loadLogs error:',err);}}
async function refreshLogs(){ loadLogs(); }
async function loadLoginLogs(){
  if (!isAuthenticated || isInitialChecking) return;
  try{
    const r = await authenticatedFetch('/api/login-logs');
    if(!r.ok) return;
    const d = await r.json();
    const tbody = $m('login-logs-tbody');
    if(!tbody) return;
    tbody.innerHTML = d.logs.map(l => {
      const country = l.country || '';
      const city = l.city || '';
      const locationDisplay = country ? `${city ? city + ', ' : ''}${country}` : '-';
      const isp = l.isp || '-';
      const isLogout = l.path && l.path.includes('logout');
      const statusStyle = isLogout ? 'color: var(--yellow);' : (l.success ? 'color: var(--green);' : 'color: var(--red);');
      const statusText = isLogout ? t('logout') : (l.success ? '✅ ' + t('success') : '❌ ' + t('failed'));
      return `<tr>
        <td>${timeAgo(l.timestamp)}</td>
        <td>
          <span style="white-space:nowrap">${esc(l.ip)}${l.browser ? ` · ${esc(l.browser)}/${esc(l.os||'')}` : ''}</span>
        </td>
        <td>${esc(locationDisplay)}</td>
        <td>${esc(isp)}</td>
        <td style="${statusStyle}">${statusText}</td>
      </tr>`;
    }).join('');
  } catch(e) {}
}
async function clearRecentActivity(){
  if(!confirm('Clear all recent activity?')) return;
  try { await authenticatedFetch('/api/logs/clear', {method:'DELETE'}); loadLoginLogs(); } catch(e) { toast('Error', true); }
}
function timeAgo(ts){const then=new Date(ts),now=new Date(),diff=Math.floor((now-then)/1000);if(lang==='fa'){if(diff<60)return t('justNow');if(diff<3600)return t('minsAgo',{n:Math.floor(diff/60)});if(diff<86400)return t('hoursAgo',{n:Math.floor(diff/3600)});return new Date(ts).toLocaleDateString('fa-IR');}else{if(diff<60)return t('justNow');if(diff<3600)return t('minsAgo',{n:Math.floor(diff/60)});if(diff<86400)return t('hoursAgo',{n:Math.floor(diff/3600)});return new Date(ts).toLocaleDateString();}}

async function loadTelegramSettings(){
  if (!isAuthenticated) return;
  try{
    const r = await authenticatedFetch('/api/settings');
    const d = await r.json();

    $m('tg-token').value = d.tg_bot_token || '';
    $m('tg-chat-id').value = d.tg_chat_id || '';
    $m('tg-interval').value = d.telegram_interval || '1';

    const events = (d.telegram_events || '').split(',');
    document.querySelectorAll('.tg-event').forEach(cb => {
      cb.checked = events.includes(cb.value);
    });

    $m('tg-templates-en').value = d.telegram_templates_en ||
      '{"quota_90":"⚠️ {label} ({uid}) used 90% of quota","login":"🔐 Panel login\\n🌐 IP: {ip}\\n📍 Location: {location}\\n🏢 ISP: {isp}\\n🏛️ Org: {org}\\n🖥️ Browser: {browser}\\n💻 OS: {os}\\n🤖 UA: {ua}\\n📅 {time}","expiry":"⏰ {label} expired","error":"❌ Error on {label}: check logs"}';
    $m('tg-templates-fa').value = d.telegram_templates_fa ||
      '{"quota_90":"⚠️ {label} ({uid}) ۹۰٪ کوتا","login":"🔐 ورود به پنل\\n🌐 IP: {ip}\\n📍 موقعیت: {location}\\n🏢 ISP: {isp}\\n🏛️ سازمان: {org}\\n🖥️ مرورگر: {browser}\\n💻 سیستم‌عامل: {os}\\n🤖 UA: {ua}\\n📅 {time}","expiry":"⏰ {label} منقضی شد","error":"❌ خطا در {label}: بررسی شود"}';

    const tgLang = d.telegram_lang || 'en';
    const toggle = $m('tg-lang-toggle');
    if (tgLang === 'fa') {
      toggle.classList.remove('on');
      $m('tg-lang-label').textContent = 'فارسی';
      $m('tg-lang-hidden').value = 'fa';
    } else {
      toggle.classList.add('on');
      $m('tg-lang-label').textContent = 'English';
      $m('tg-lang-hidden').value = 'en';
    }

    const tgReportCard = $m('card-tgrep');
    if (tgReportCard) {
      if (d.telegram_report_enabled === '1') {
        tgReportCard.classList.add('active'); tgReportCard.classList.remove('inactive');
      } else {
        tgReportCard.classList.remove('active'); tgReportCard.classList.add('inactive');
      }
      $m('set-tg-report').value = d.telegram_report_enabled === '1' ? '1' : '0';
    }

    const tgNotifyCard = $m('card-tgnot');
    if (tgNotifyCard) {
      if (d.telegram_notify_enabled === '1') {
        tgNotifyCard.classList.add('active'); tgNotifyCard.classList.remove('inactive');
      } else {
        tgNotifyCard.classList.remove('active'); tgNotifyCard.classList.add('inactive');
      }
      $m('set-tg-notify').value = d.telegram_notify_enabled === '1' ? '1' : '0';
    }

  } catch(err) {
    console.error('loadTelegram error:', err);
  }
}

async function saveTelegramSettings(){
  const token = $m('tg-token').value.trim();
  const chat = $m('tg-chat-id').value.trim();
  const interval = $m('tg-interval').value.trim();
  const events = Array.from(document.querySelectorAll('.tg-event:checked')).map(cb => cb.value).join(',');
  const templates_en = $m('tg-templates-en').value.trim();
  const templates_fa = $m('tg-templates-fa').value.trim();
  const tglang = $m('tg-lang-hidden').value;

  try {
    JSON.parse(templates_en);
    JSON.parse(templates_fa);
  } catch (e) {
    toast('Invalid JSON in templates', true);
    return;
  }

  const tgReport = $m('set-tg-report')?.value || '0';
  const tgNotify = $m('set-tg-notify')?.value || '0';

  try {
    await authenticatedFetch('/api/settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        tg_bot_token: token,
        tg_chat_id: chat,
        telegram_interval: interval,
        telegram_events: events,
        telegram_templates_en: templates_en,
        telegram_templates_fa: templates_fa,
        telegram_lang: tglang,
        telegram_report_enabled: tgReport,
        telegram_notify_enabled: tgNotify
      })
    });
    toast('Saved');
  } catch {
    toast('Error', true);
  }
}

async function testTelegram(){
  const token = $m('tg-token').value.trim();
  const chat = $m('tg-chat-id').value.trim();
  if (!token || !chat) {
    toast('Fill token and chat ID', true);
    return;
  }
  const tglang = $m('tg-lang-hidden').value;
  const msg = tglang === 'fa' ? '✅ SulgX متصل شد' : '✅ SulgX is connected';
  try {
    const res = await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: chat, text: msg })
    });
    if (res.ok) toast('Test message sent!');
    else toast('Failed to send', true);
  } catch {
    toast('Error', true);
  }
}

function toggleTgLang() {
    const toggle = $m('tg-lang-toggle');
    toggle.classList.toggle('on');
    const isEn = toggle.classList.contains('on');
    $m('tg-lang-label').textContent = isEn ? 'English' : 'فارسی';
    $m('tg-lang-hidden').value = isEn ? 'en' : 'fa';
}

function previewTemplate() {
    const isEn = $m('tg-lang-toggle').classList.contains('on');
    const targetId = isEn ? 'tg-templates-en' : 'tg-templates-fa';
    const textarea = $m(targetId);
    const previewDiv = $m('tg-preview');
    if (!textarea || !previewDiv) return;

    try {
        const sanitizedValue = textarea.value.replace(/[\u0000-\u001f]/g, function(ch) {
            if (ch === '\n') return '\\n';
            if (ch === '\r') return '\\r';
            if (ch === '\t') return '\\t';
            return '';
        });
        const templates = JSON.parse(sanitizedValue);
        const mockData = {
            label: "SulgX_User",
            uid: "sulgx-7b8c-49ed-b45a",
            ip: "85.201.32.44",
            ua: "Mozilla/5.0 (iPhone; iOS 18)",
            time: new Date().toISOString().replace('T', ' ').substring(0, 19),
            location: "Dreieich, Germany",
            isp: "Cloudflare, Inc.",
            org: "Cloudflare",
            browser: "Firefox",
            os: "Windows"
        };

        let previewHTML = "";
        for (const [key, templateText] of Object.entries(templates)) {
            let text = templateText;
            text = text.replace(/{label}/g, mockData.label)
                       .replace(/{uid}/g, mockData.uid)
                       .replace(/{ip}/g, mockData.ip)
                       .replace(/{ua}/g, mockData.ua)
                       .replace(/{time}/g, mockData.time)
                       .replace(/{location}/g, mockData.location)
                       .replace(/{isp}/g, mockData.isp)
                       .replace(/{org}/g, mockData.org)
                       .replace(/{browser}/g, mockData.browser)
                       .replace(/{os}/g, mockData.os);
            previewHTML += `<div style="margin-bottom:10px;border-bottom:1px solid var(--border);padding-bottom:6px;">`;
            previewHTML += `<span style="color:var(--primary);font-weight:bold;font-size:0.8rem;">[${key}]:</span><br>`;
            previewHTML += `<span>${text}</span></div>`;
        }

        const mockDomain = window.location.host || "your-domain.com";
        const prefix = window.panelPrefix ? '/' + window.panelPrefix : '';
        previewHTML += `<div style="margin-top:6px;padding-top:4px;color:#4caf50;">`;
        previewHTML += `⚠️ <i>Auto Appended:</i><br>Open SulgX Panel (Link: https://${mockDomain}${prefix}/panel)`;
        previewHTML += `</div>`;

        previewDiv.innerHTML = previewHTML;
        previewDiv.style.border = "1px solid var(--primary)";
    } catch (e) {
        previewDiv.innerHTML = `<span style="color:#ff4d4f;font-weight:600;">❌ Invalid JSON:</span><br><small style="color:#ff7875;">${e.message}</small>`;
        previewDiv.style.border = "1px solid #ff4d4f";
    }
}
async function loadGeneralSettings(){
  if (!isAuthenticated || isInitialChecking) return;
  try {
    const r = await authenticatedFetch('/api/settings');
    if(!r.ok) return;
    const d = await r.json();
    $m('set-footer').value = d.footer_text || '';
    $m('set-default-path').value = d.default_path || '';
    timezoneOffset = parseFloat(d.timezone_offset) || 0;
    $m('set-default-limit').value = d.default_limit_bytes ? (parseInt(d.default_limit_bytes)/1073741824).toFixed(1) : '';
    $m('set-default-expiry').value = d.default_expiry_days || '';
    $m('set-default-maxconn').value = d.default_max_connections || '';
    $m('set-scanner-timeout').value = d.scanner_timeout || '4';
    $m('set-monthly-limit').value = d.monthly_limit_gb || '';
    $m('set-max-scan-ips').value = d.max_scan_ips || '256';
    $m('set-keep-alive-interval').value = d.keep_alive_interval || '300';
    
    updateSettingsStatus(d);
    updateDashboardStatusCards(d);
    
    if (d.keep_alive_mode) {
        setKeepAliveMode(d.keep_alive_mode);
        $m('set-keepalive-enabled').value = d.keep_alive_enabled === '1' ? '1' : '0';
        const card = $m('card-keepalive');
        if (d.keep_alive_enabled === '1') { card.classList.add('active'); card.classList.remove('inactive'); }
        else { card.classList.add('inactive'); card.classList.remove('active'); }
    }
    
    $m('set-landing-redirect').value = d.landing_redirect || '';
    $m('set-camouflage-url').value = d.camouflage_url || '';
    $m('set-sub-filename').value = d.sub_filename || '';
    $m('set-panel-prefix').value = d.panel_prefix || '';
    const newPrefix = d.panel_prefix || '';
    if (window.panelPrefix !== newPrefix) {
        window.panelPrefix = newPrefix;
        const newPath = newPrefix ? '/' + newPrefix + '/panel' : '/panel';
        if (window.location.pathname !== newPath) {
            window.history.replaceState({}, '', newPath);
        }
    }
    updateDohEndpoint();
    loadBlockedDomains();
    if (d.stealth_mode === '1') {
        const stealthCard = $m('card-stealth');
        if(stealthCard) { stealthCard.classList.add('active'); stealthCard.classList.remove('inactive'); }
        $m('set-stealth-mode').value = '1';
        stealthMode = true;
        const scannerPage = $m('page-ipscanner'); if (scannerPage) scannerPage.style.display = 'none';
        const navScanner = document.querySelector('.nav-link[data-page="ipscanner"]'); if (navScanner) navScanner.style.display = 'none';
        const mobileNavScanner = document.querySelector('.mobile-nav .nav-item[data-page="ipscanner"]'); if (mobileNavScanner) mobileNavScanner.style.display = 'none';
    } else {
        stealthMode = false;
        const scannerPage = $m('page-ipscanner'); if (scannerPage) scannerPage.style.display = '';
        const navScanner = document.querySelector('.nav-link[data-page="ipscanner"]'); if (navScanner) navScanner.style.display = '';
        const mobileNavScanner = document.querySelector('.mobile-nav .nav-item[data-page="ipscanner"]'); if (mobileNavScanner) mobileNavScanner.style.display = '';
    }

    if(timezoneOffset===3.5) setPanelTZ(3.5,'Tehran');
    else if(timezoneOffset===0) setPanelTZ(0,'UTC');
    else { toggleCustomTZInput(true); $m('custom-tz-value').value=timezoneOffset; }
    
    const savedTheme = d.theme_color || 'dark'; setPanelTheme(savedTheme);
  } catch(e) { console.error('General Settings Load Error:', e); }
}

async function saveGeneralSettings(){
  const footer = $m('set-footer').value.trim();
  const defPath = $m('set-default-path').value.trim();
  let tz = timezoneOffset;
  const logEnabled = $m('set-log-toggle').value;
  const themeColor = $m('set-theme-color')?.value || theme;
  const defLang = $m('set-default-lang')?.value || lang;
  const defLimit = parseFloat($m('set-default-limit').value) * 1073741824;
  const defExpiry = $m('set-default-expiry').value.trim();
  const defMaxConn = $m('set-default-maxconn').value.trim();
  const scannerTimeout = $m('set-scanner-timeout').value.trim();
  const monthlyLimit = $m('set-monthly-limit').value.trim();
  const maxScanIps = $m('set-max-scan-ips').value.trim();
  const keepAliveInterval = $m('set-keep-alive-interval').value.trim();
  const keepAliveEnabled = $m('set-keepalive-enabled').value;
  let keepAliveModeEl = $m('set-keepalive-mode'); 
  let keepAliveMode = keepAliveModeEl ? keepAliveModeEl.value : 'simple';
  const autoDisable = $m('set-auto-disable').value;
  const tgReport = $m('set-tg-report').value;
  const tgNotify = $m('set-tg-notify').value;
  
  const stealthModeVal = $m('set-stealth-mode').value;
  const landingRedirect = $m('set-landing-redirect').value.trim();
  const camouflageUrl = $m('set-camouflage-url').value.trim();
  const subFilename = $m('set-sub-filename').value.trim();
  const panelPrefixVal = $m('set-panel-prefix').value.trim();

  await saveDohUpstreams();
  try {
    await authenticatedFetch('/api/settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        footer_text: footer, default_path: defPath, timezone_offset: tz, log_enabled: logEnabled,
        theme_color: themeColor, default_lang: defLang, default_limit_bytes: isNaN(defLimit) ? '' : String(Math.round(defLimit)),
        default_expiry_days: defExpiry, default_max_connections: defMaxConn, scanner_timeout: scannerTimeout,
        monthly_limit_gb: monthlyLimit, max_scan_ips: maxScanIps, keep_alive_interval: keepAliveInterval,
        keep_alive_enabled: keepAliveEnabled, keep_alive_mode: keepAliveMode, auto_disable_enabled: autoDisable,
        telegram_report_enabled: tgReport, telegram_notify_enabled: tgNotify,
        stealth_mode: stealthModeVal, landing_redirect: landingRedirect, camouflage_url: camouflageUrl, sub_filename: subFilename,
        panel_prefix: panelPrefixVal
      })
    });
    timezoneOffset = parseFloat(tz) || 0;
    toast('Saved & Applied');
    if (panelPrefixVal !== (window.panelPrefix || '')) {
        setTimeout(() => {
            const newPrefix = panelPrefixVal ? '/' + panelPrefixVal : '';
            window.location.href = newPrefix + '/login';
        }, 600);
    } else {
        loadGeneralSettings();
    }
  } catch { toast('Error saving settings', true); }
}
function generateUUID(id){const uuid=crypto.randomUUID?crypto.randomUUID():'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g,c=>{const r=Math.random()*16|0;return(c=='x'?r:(r&0x3|0x8)).toString(16);});$m(id).value=uuid;}
function toggleAdv(id){const el=$m(id);el.style.display=el.style.display==='none'?'block':'none';}
function filterLogs(){const q=($m('log-search').value||'').toLowerCase();document.querySelectorAll('#logs-tbody tr').forEach(row=>{if(!q){row.style.display='';return;}row.style.display=row.innerText.toLowerCase().includes(q)?'':'none';});}
function clearLogSearch(){$m('log-search').value='';filterLogs();}
async function clearLogs(){if(!confirm('Clear all logs?'))return;await authenticatedFetch('/api/logs/clear',{method:'DELETE'});loadLogs();}
async function fetchLogSize(){const r=await authenticatedFetch('/api/logs/size');const d=await r.json();toast(`Log entries: ${d.count}, Size: ${d.size_kb} KB`);}
async function resetAllSettings() {
    const msg = lang === 'fa' ? 'آیا مطمئن هستید؟ تمام تنظیمات (به جز رمز عبور) بازنشانی می‌شوند.' : 'Are you sure? All settings (except password) will return to defaults.';
    if (!confirm(msg)) return;
    try {
        const r = await authenticatedFetch('/api/settings/reset', { method: 'POST' });
        if (!r.ok) throw new Error((await r.json()).detail);
        toast(lang === 'fa' ? 'تنظیمات بازنشانی شد. در حال بارگذاری مجدد...' : 'Settings reset. Reloading...');
        setTimeout(() => location.reload(), 1500);
    } catch (e) {
        toast(e.message, true);
    }
}
let sseConnection = null;
function startSSE() {
    const token = localStorage.getItem('token');
    if (!token) return;
    if (sseConnection) { sseConnection.close(); }
    const url = `/api/sse/stats-live?token=${encodeURIComponent(token)}`;
    sseConnection = new EventSource(url);
    sseConnection.onmessage = function(event) {
        const data = JSON.parse(event.data);
        safeSetText('sv-requests', data.total_requests);
        safeSetHTML('sv-traffic', data.total_traffic_mb + '<span class="stat-unit"> MB</span>');
        safeSetText('sv-uptime', data.uptime);
    };
    sseConnection.onerror = function() {
        sseConnection.close();
        setTimeout(startSSE, 5000);
    };
}
function stopSSE() {
    if (sseConnection) { sseConnection.close(); sseConnection = null; }
}
document.addEventListener('keydown',e=>{if(e.ctrlKey||e.metaKey){const pages=['dashboard','inbounds','addresses','ipscanner','logs','telegram','settings'];const num=parseInt(e.key);if(num>=1&&num<=pages.length)switchPage(pages[num-1]);}});
if(window.matchMedia('(prefers-color-scheme: dark)').matches && !localStorage.getItem('theme'))setTheme('dark');
setTheme(theme);setLang(lang);checkAuth();
setInterval(()=>{if(isAuthenticated && !isInitialChecking){loadStats();}},15000);

async function loadBlockedDomains() {
    try {
        const r = await authenticatedFetch('/api/blocked-domains');
        if (!r.ok) return;
        const d = await r.json();
        $m('set-blocked-domains').value = (d.domains || []).join('\n');
    } catch(e) {}
}
async function saveBlockedDomains() {
    const lines = $m('set-blocked-domains').value.split('\n').map(l => l.trim()).filter(l => l);
    try {
        await authenticatedFetch('/api/blocked-domains', {
            method:'POST',
            headers:{'Content-Type':'application/json'},
            body: JSON.stringify({domains: lines})
        });
        toast('Saved');
    } catch { toast('Error', true); }
}
</script>
</body>
</html>"""

# ... (PANEL_HTML variable remains unchanged, containing all HTML/JS/CSS) ...

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    prefix_row = await db_fetchone("SELECT value FROM settings WHERE key='panel_prefix'",
                                   "SELECT value FROM settings WHERE key='panel_prefix'")
    current_prefix = prefix_row["value"].strip() if prefix_row and prefix_row["value"].strip() else ""
    if current_prefix and request.scope.get("root_path") != f"/{current_prefix}":
        raise HTTPException(status_code=404)
    return HTMLResponse(content=PANEL_HTML)

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    prefix_row = await db_fetchone("SELECT value FROM settings WHERE key='panel_prefix'",
                                   "SELECT value FROM settings WHERE key='panel_prefix'")
    current_prefix = prefix_row["value"].strip() if prefix_row and prefix_row["value"].strip() else ""
    if current_prefix and request.scope.get("root_path") != f"/{current_prefix}":
        raise HTTPException(status_code=404)
    return HTMLResponse(content=PANEL_HTML)

@app.get("/panel", response_class=HTMLResponse)
async def panel_page(request: Request):
    prefix_row = await db_fetchone("SELECT value FROM settings WHERE key='panel_prefix'",
                                   "SELECT value FROM settings WHERE key='panel_prefix'")
    current_prefix = prefix_row["value"].strip() if prefix_row and prefix_row["value"].strip() else ""
    if current_prefix and request.scope.get("root_path") != f"/{current_prefix}":
        raise HTTPException(status_code=404)
    return HTMLResponse(content=PANEL_HTML)

@app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
async def dynamic_xhttp_router(full_path: str, request: Request):
    """
    Catch‑all router for XHTTP traffic.
    Handles three path formats:
      - stream-one:        POST <base_path>                         (exact base path)
      - stream-up/packet-up:
           <base_path>/<mode>/<user_uuid>/<session_id>[/<seq>]
      - legacy (no mode):  <base_path>/<session_id>[/<seq>]         (kept for compatibility)
    """
    base_paths = set()
    async with LINKS_LOCK:
        for uid, link in LINKS.items():
            if not link.get("active"):
                continue
            proto = link.get("protocol", "vless-ws")
            if proto.startswith("xhttp-"):
                bp = link.get("custom_path") or DEFAULT_XHTTP_PATH
                bp = bp.strip("/")
                if bp:
                    base_paths.add(bp)

    default_bp = DEFAULT_XHTTP_PATH.strip("/")
    if default_bp:
        base_paths.add(default_bp)

    for bp in base_paths:
        if full_path.strip("/") == bp:
            if request.method == "POST":
                return await xhttp_stream_one(bp, request)
            raise HTTPException(status_code=405, detail="Method Not Allowed")

    matched_base = None
    for bp in sorted(base_paths, key=lambda x: -len(x)):
        if full_path.startswith(bp + "/"):
            matched_base = bp
            break

    if not matched_base:
        raise HTTPException(status_code=404)

    remaining = full_path[len(matched_base):].strip("/")
    parts = remaining.split("/")

    VALID_MODES = {"stream-up", "packet-up", "stream-down"}
    if parts and parts[0] in VALID_MODES:
        if len(parts) >= 3:
            parts = parts[2:]
        elif len(parts) == 2:
            parts = []
        else:
            parts = parts[1:] 

    if len(parts) == 1:
        session_id = parts[0]
        if request.method == "GET":
            return await xhttp_downlink(session_id, request)
        elif request.method == "POST":
            return await xhttp_stream_up(session_id, request)
        else:
            raise HTTPException(status_code=405, detail="Method Not Allowed")
    elif len(parts) == 2:
        session_id = parts[0]
        try:
            seq = int(parts[1])
        except ValueError:
            raise HTTPException(status_code=404)
        if request.method == "POST":
            return await xhttp_packet_up(session_id, seq, request)
        else:
            raise HTTPException(status_code=405, detail="Method Not Allowed")
    else:
        raise HTTPException(status_code=404)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", CONFIG.get("port", 8000)))
    logger.info(f"Starting SulgX Panel on port {port}")
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=port,
        proxy_headers=True,
        forwarded_allow_ips="*",
        log_level="info",
    )
