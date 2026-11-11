import hashlib
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

import psycopg
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

DATABASE_URL = os.environ.get("DATABASE_URL", "")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")
SESSION_DAYS = int(os.environ.get("SESSION_DAYS", "7"))

app = FastAPI(title="Spectrolite Auth API", version="1.0.0")


def db():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is not configured")
    return psycopg.connect(DATABASE_URL, sslmode="require")


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@app.on_event("startup")
def init_db():
    with db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS license_keys (
                id BIGSERIAL PRIMARY KEY,
                key_hash TEXT UNIQUE NOT NULL,
                label TEXT NOT NULL DEFAULT '',
                expires_at TIMESTAMPTZ,
                device_id TEXT,
                active BOOLEAN NOT NULL DEFAULT TRUE,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                key_id BIGINT NOT NULL REFERENCES license_keys(id) ON DELETE CASCADE,
                device_id TEXT NOT NULL,
                expires_at TIMESTAMPTZ NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        """)


class LoginRequest(BaseModel):
    key: str = Field(min_length=8, max_length=256)
    device_id: str = Field(min_length=1, max_length=256)


class CreateKeyRequest(BaseModel):
    label: str = Field(default="", max_length=120)
    expires_in_days: Optional[int] = Field(default=None, ge=1, le=3650)


class DisableKeyRequest(BaseModel):
    key: str = Field(min_length=8, max_length=256)


def require_admin(authorization: Optional[str]):
    if not ADMIN_TOKEN or authorization != f"Bearer {ADMIN_TOKEN}":
        raise HTTPException(status_code=401, detail="Admin authentication required")


@app.get("/health")
def health():
    with db() as conn:
        conn.execute("SELECT 1")
    return {"ok": True, "service": "spectrolite-auth"}


@app.post("/auth/login")
def login(body: LoginRequest):
    with db() as conn:
        row = conn.execute(
            "SELECT id, expires_at, device_id, active FROM license_keys WHERE key_hash = %s",
            (digest(body.key),),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=401, detail="Invalid key")
        key_id, expires_at, bound_device, active = row
        now = datetime.now(timezone.utc)
        if not active:
            raise HTTPException(status_code=403, detail="Key disabled")
        if expires_at and expires_at <= now:
            raise HTTPException(status_code=403, detail="Key expired")
        if bound_device and bound_device != body.device_id:
            raise HTTPException(status_code=403, detail="Key is bound to another device")
        if not bound_device:
            conn.execute("UPDATE license_keys SET device_id = %s WHERE id = %s", (body.device_id, key_id))
        token = secrets.token_urlsafe(36)
        token_expiry = now + timedelta(days=SESSION_DAYS)
        conn.execute(
            "INSERT INTO sessions(token_hash, key_id, device_id, expires_at) VALUES (%s, %s, %s, %s)",
            (digest(token), key_id, body.device_id, token_expiry),
        )
    return {"ok": True, "session_token": token, "expires_at": token_expiry.isoformat()}


@app.get("/auth/me")
def me(authorization: Optional[str] = Header(default=None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Session token required")
    token = authorization[7:]
    with db() as conn:
        row = conn.execute("""
            SELECT k.label, s.device_id, s.expires_at
            FROM sessions s JOIN license_keys k ON k.id = s.key_id
            WHERE s.token_hash = %s AND k.active = TRUE
        """, (digest(token),)).fetchone()
    if not row or row[2] <= datetime.now(timezone.utc):
        raise HTTPException(status_code=401, detail="Session expired or revoked")
    return {"ok": True, "label": row[0], "device_id": row[1], "expires_at": row[2].isoformat()}


@app.post("/admin/keys")
def create_key(body: CreateKeyRequest, authorization: Optional[str] = Header(default=None)):
    require_admin(authorization)
    key = "SPX-" + secrets.token_urlsafe(24)
    expiry = datetime.now(timezone.utc) + timedelta(days=body.expires_in_days) if body.expires_in_days else None
    with db() as conn:
        conn.execute(
            "INSERT INTO license_keys(key_hash, label, expires_at) VALUES (%s, %s, %s)",
            (digest(key), body.label, expiry),
        )
    return {"ok": True, "key": key, "label": body.label, "expires_at": expiry.isoformat() if expiry else None}


@app.post("/admin/keys/disable")
def disable_key(body: DisableKeyRequest, authorization: Optional[str] = Header(default=None)):
    require_admin(authorization)
    with db() as conn:
        cur = conn.execute("UPDATE license_keys SET active = FALSE WHERE key_hash = %s", (digest(body.key),))
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Key not found")
    return {"ok": True, "disabled": True}
