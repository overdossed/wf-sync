import sqlite3
import secrets
import hashlib
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel

DB = "wf_sync.db"


def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            email    TEXT UNIQUE NOT NULL,
            pw_hash  TEXT NOT NULL,
            api_key  TEXT UNIQUE NOT NULL
        );
        CREATE TABLE IF NOT EXISTS inventories (
            user_id   INTEGER PRIMARY KEY REFERENCES users(id),
            data      TEXT NOT NULL,
            updated   DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS platinum_history (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id   INTEGER REFERENCES users(id),
            platinum  INTEGER NOT NULL,
            recorded  DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    """)
    conn.commit()
    conn.close()


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(lifespan=lifespan)


class RegisterRequest(BaseModel):
    email: str
    password: str


class LoginRequest(BaseModel):
    email: str
    password: str


class SyncRequest(BaseModel):
    inventory: dict


@app.post("/api/register")
def register(req: RegisterRequest):
    conn = get_db()
    try:
        api_key = secrets.token_hex(32)
        conn.execute(
            "INSERT INTO users (email, pw_hash, api_key) VALUES (?, ?, ?)",
            (req.email, hash_password(req.password), api_key)
        )
        conn.commit()
        return {"api_key": api_key}
    except sqlite3.IntegrityError:
        raise HTTPException(400, "Email ya registrado")
    finally:
        conn.close()


@app.post("/api/login")
def login(req: LoginRequest):
    conn = get_db()
    row = conn.execute(
        "SELECT api_key FROM users WHERE email=? AND pw_hash=?",
        (req.email, hash_password(req.password))
    ).fetchone()
    conn.close()
    if not row:
        raise HTTPException(401, "Credenciales incorrectas")
    return {"api_key": row["api_key"]}


@app.post("/api/sync")
def sync(req: SyncRequest, x_api_key: str = Header(...)):
    conn = get_db()
    row = conn.execute("SELECT id FROM users WHERE api_key=?", (x_api_key,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(401, "API key invalida")
    import json
    user_id = row["id"]
    data_str = json.dumps(req.inventory)
    platinum = req.inventory.get("PremiumCredits", 0)

    conn.execute(
        """INSERT INTO inventories (user_id, data, updated)
           VALUES (?, ?, CURRENT_TIMESTAMP)
           ON CONFLICT(user_id) DO UPDATE SET data=excluded.data, updated=excluded.updated""",
        (user_id, data_str)
    )

    # Solo guarda en historial si el platino cambió desde la última entrada
    last = conn.execute(
        "SELECT platinum FROM platinum_history WHERE user_id=? ORDER BY recorded DESC LIMIT 1",
        (user_id,)
    ).fetchone()
    if last is None or last["platinum"] != platinum:
        conn.execute(
            "INSERT INTO platinum_history (user_id, platinum) VALUES (?, ?)",
            (user_id, platinum)
        )

    conn.commit()
    conn.close()
    return {"ok": True}


@app.get("/api/platinum_history")
def get_platinum_history(x_api_key: str = Header(...)):
    conn = get_db()
    row = conn.execute("SELECT id FROM users WHERE api_key=?", (x_api_key,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(401, "API key invalida")
    rows = conn.execute(
        "SELECT platinum, recorded FROM platinum_history WHERE user_id=? ORDER BY recorded ASC LIMIT 30",
        (row["id"],)
    ).fetchall()
    conn.close()
    return {"history": [{"pl": r["platinum"], "date": r["recorded"][:16].replace("T", " ")} for r in rows]}


@app.get("/api/inventory")
def get_inventory(x_api_key: str = Header(...)):
    conn = get_db()
    row = conn.execute(
        """SELECT i.data, i.updated FROM inventories i
           JOIN users u ON u.id = i.user_id
           WHERE u.api_key=?""",
        (x_api_key,)
    ).fetchone()
    conn.close()
    if not row:
        raise HTTPException(404, "Sin inventario todavia")
    import json
    return {"inventory": json.loads(row["data"]), "updated": row["updated"]}