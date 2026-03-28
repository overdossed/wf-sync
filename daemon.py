"""
Warframe Inventory Daemon
- Detecta cuando Warframe esta abierto
- Lee el inventario de memoria
- Lo sube al backend automaticamente
"""
import os
import sys
import time
import json
import ctypes
import struct
import requests

BACKEND_URL = "http://localhost:8000"  # cambiar por URL de produccion
API_KEY_FILE = os.path.expanduser("~/.wf_sync_key")
CHECK_INTERVAL = 30  # segundos entre chequeos

PROCESS_NAME = "Warframe.x64"
NEEDLE = b'"PrimeVaultTraders"'


# ── proceso de memoria ────────────────────────────────────────────────────────

def find_warframe_pid() -> int | None:
    import subprocess
    try:
        out = subprocess.check_output(["pgrep", "-x", PROCESS_NAME], text=True)
        return int(out.strip().split()[0])
    except Exception:
        return None


def read_inventory_from_pid(pid: int) -> dict | None:
    maps_file = f"/proc/{pid}/maps"
    mem_file  = f"/proc/{pid}/mem"
    try:
        with open(maps_file) as f:
            maps = f.read()
        with open(mem_file, "rb") as mem:
            for line in maps.splitlines():
                parts = line.split()
                if len(parts) < 2 or parts[1] not in ("rw-p", "r--p"):
                    continue
                start, end = (int(x, 16) for x in parts[0].split("-"))
                size = end - start
                if size > 200 * 1024 * 1024:
                    continue
                try:
                    mem.seek(start)
                    chunk = mem.read(size)
                except OSError:
                    continue
                pos = chunk.rfind(NEEDLE)
                if pos == -1:
                    continue
                # buscar inicio del objeto JSON
                bracket = chunk.rfind(b"{", 0, pos)
                if bracket == -1:
                    continue
                raw = chunk[bracket:]
                # buscar cierre del JSON
                depth = 0
                for i, b in enumerate(raw):
                    if b == ord("{"):
                        depth += 1
                    elif b == ord("}"):
                        depth -= 1
                        if depth == 0:
                            try:
                                return json.loads(raw[:i+1])
                            except json.JSONDecodeError:
                                break
    except PermissionError:
        print("ERROR: Necesitas permisos de root para leer la memoria del proceso.")
        print("Corre el daemon con: sudo python daemon.py")
        sys.exit(1)
    except FileNotFoundError:
        return None
    return None


# ── backend ───────────────────────────────────────────────────────────────────

def load_api_key() -> str | None:
    if os.path.exists(API_KEY_FILE):
        return open(API_KEY_FILE).read().strip()
    return None


def save_api_key(key: str):
    with open(API_KEY_FILE, "w") as f:
        f.write(key)
    os.chmod(API_KEY_FILE, 0o600)


def register(email: str, password: str) -> str:
    r = requests.post(f"{BACKEND_URL}/api/register", json={"email": email, "password": password})
    if r.status_code == 200:
        return r.json()["api_key"]
    raise Exception(r.json().get("detail", r.text))


def login_backend(email: str, password: str) -> str:
    r = requests.post(f"{BACKEND_URL}/api/login", json={"email": email, "password": password})
    if r.status_code == 200:
        return r.json()["api_key"]
    raise Exception(r.json().get("detail", r.text))


def sync_inventory(api_key: str, inventory: dict) -> bool:
    r = requests.post(
        f"{BACKEND_URL}/api/sync",
        json={"inventory": inventory},
        headers={"X-Api-Key": api_key},
        timeout=15,
    )
    return r.status_code == 200


# ── setup inicial ─────────────────────────────────────────────────────────────

def setup():
    print("=== Warframe Sync — Setup ===")
    api_key = load_api_key()
    if api_key:
        print(f"API key encontrada en {API_KEY_FILE}")
        return api_key

    email = input("Email: ").strip()
    password = input("Password: ").strip()
    choice = input("¿Registrarse (r) o iniciar sesion (l)? [r/l]: ").strip().lower()

    if choice == "r":
        api_key = register(email, password)
        print("Cuenta creada!")
    else:
        api_key = login_backend(email, password)
        print("Login exitoso!")

    save_api_key(api_key)
    print(f"API key guardada en {API_KEY_FILE}")
    return api_key


# ── loop principal ────────────────────────────────────────────────────────────

def main():
    api_key = setup()
    print(f"\nDaemon iniciado. Chequeando cada {CHECK_INTERVAL}s...\n")

    last_sync = 0

    while True:
        pid = find_warframe_pid()

        if pid is None:
            print(f"[{time.strftime('%H:%M:%S')}] Warframe no esta corriendo...")
        else:
            print(f"[{time.strftime('%H:%M:%S')}] Warframe detectado (PID {pid}), leyendo inventario...")
            inventory = read_inventory_from_pid(pid)
            if inventory:
                if sync_inventory(api_key, inventory):
                    print(f"[{time.strftime('%H:%M:%S')}] Inventario sincronizado!")
                    last_sync = time.time()
                else:
                    print(f"[{time.strftime('%H:%M:%S')}] Error al sincronizar")
            else:
                print(f"[{time.strftime('%H:%M:%S')}] No se encontro inventario en memoria")

        time.sleep(CHECK_INTERVAL)


if __name__ == "__main__":
    main()