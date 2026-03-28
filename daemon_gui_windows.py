"""
Warframe Inventory Sync - Daemon Windows
Doble click para abrir, se queda en el system tray.
Requiere permisos de administrador para leer la memoria de Warframe.
"""
import ctypes
import json
import os
import re
import sys
import threading
import time
import tkinter as tk
from tkinter import messagebox
import requests
import psutil
from PIL import Image, ImageDraw
import pystray

# ── Config ────────────────────────────────────────────────────────────────────
BACKEND_URL  = os.getenv("BACKEND_URL", "https://wf-backend-production.up.railway.app")
WEB_APP_URL  = os.getenv("WEB_APP_URL", "https://wf-frontend-production.up.railway.app")
API_KEY_FILE = os.path.join(os.path.expanduser("~"), ".wf_sync_key")
CHECK_EVERY  = 30  # segundos

PROCESS_NAMES = ["Warframe.x64.exe", "Warframe.x64.ex", "Warframe.exe"]
PATTERN = b'?accountId='


# ── Búsqueda de proceso ───────────────────────────────────────────────────────
def find_warframe():
    for proc in psutil.process_iter(['name']):
        try:
            if proc.info['name'] in PROCESS_NAMES:
                return proc
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return None


# ── Lectura de memoria (Windows) ──────────────────────────────────────────────
def scan_auth_windows(pid):
    kernel32 = ctypes.windll.kernel32
    PROCESS_VM_READ = 0x0010
    PROCESS_QUERY_INFORMATION = 0x0400

    handle = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    if not handle:
        return None

    class MBI(ctypes.Structure):
        _fields_ = [
            ("BaseAddress", ctypes.c_void_p),
            ("AllocationBase", ctypes.c_void_p),
            ("AllocationProtect", ctypes.c_ulong),
            ("RegionSize", ctypes.c_size_t),
            ("State", ctypes.c_ulong),
            ("Protect", ctypes.c_ulong),
            ("Type", ctypes.c_ulong),
        ]

    candidates = {}
    address = 0
    max_addr = 0x7FFFFFFF0000
    MEM_COMMIT = 0x1000
    PAGE_READABLE = 0x02 | 0x04 | 0x08 | 0x10 | 0x20 | 0x40

    try:
        while address < max_addr:
            mbi = MBI()
            if not kernel32.VirtualQueryEx(handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi)):
                break

            if mbi.State == MEM_COMMIT and (mbi.Protect & PAGE_READABLE) and mbi.RegionSize < 100 * 1024 * 1024:
                buf = ctypes.create_string_buffer(mbi.RegionSize)
                read = ctypes.c_size_t(0)

                if kernel32.ReadProcessMemory(handle, ctypes.c_void_p(mbi.BaseAddress), buf, mbi.RegionSize, ctypes.byref(read)):
                    chunk = buf.raw[:read.value]
                    offset = 0
                    while (idx := chunk.find(PATTERN, offset)) != -1:
                        offset = idx + 1
                        try:
                            acc_start = idx + len(PATTERN)
                            if acc_start + 31 > len(chunk):
                                continue
                            account_id = chunk[acc_start:acc_start + 24].decode('ascii', errors='ignore')
                            if not account_id.replace('-', '').replace('_', '').isalnum():
                                continue
                            if chunk[acc_start + 24:acc_start + 31] != b'&nonce=':
                                continue
                            nonce_match = re.match(rb'(\d+)', chunk[acc_start + 31:acc_start + 81])
                            if nonce_match:
                                authz = f"?accountId={account_id}&nonce={nonce_match.group(1).decode()}"
                                candidates[authz] = candidates.get(authz, 0) + 1
                                if candidates[authz] >= 3:
                                    return authz
                        except Exception:
                            continue

            address += mbi.RegionSize
    finally:
        kernel32.CloseHandle(handle)

    if candidates:
        return max(candidates, key=candidates.get)
    return None


def fetch_inventory_from_api(authz: str):
    try:
        r = requests.get(f"https://mobile.warframe.com/api/inventory.php{authz}", timeout=30)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return None


def read_inventory(pid):
    authz = scan_auth_windows(pid)
    if not authz:
        return None
    return fetch_inventory_from_api(authz)


# ── Backend ───────────────────────────────────────────────────────────────────
def load_api_key():
    if os.path.exists(API_KEY_FILE):
        return open(API_KEY_FILE).read().strip()
    return None


def save_api_key(key):
    with open(API_KEY_FILE, "w") as f:
        f.write(key)


def do_login(email, password):
    r = requests.post(f"{BACKEND_URL}/api/login",
                      json={"email": email, "password": password}, timeout=10)
    if r.status_code == 200:
        return r.json()["api_key"], None
    return None, r.json().get("detail", "Error")


def do_register(email, password):
    r = requests.post(f"{BACKEND_URL}/api/register",
                      json={"email": email, "password": password}, timeout=10)
    if r.status_code == 200:
        return r.json()["api_key"], None
    return None, r.json().get("detail", "Error")


def sync_inventory(api_key, inventory):
    r = requests.post(f"{BACKEND_URL}/api/sync",
                      json={"inventory": inventory},
                      headers={"X-Api-Key": api_key}, timeout=15)
    return r.status_code == 200


# ── Icono del tray ────────────────────────────────────────────────────────────
def make_icon(color="#b18ef0"):
    img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    d   = ImageDraw.Draw(img)
    d.ellipse([4, 4, 60, 60], fill=color)
    d.polygon([(32, 12), (52, 48), (12, 48)], fill="white")
    return img


# ── Ventana de login ──────────────────────────────────────────────────────────
class LoginWindow:
    def __init__(self, on_success):
        self.on_success = on_success
        self.root = tk.Tk()
        self.root.title("Warframe Sync — Iniciar sesión")
        self.root.resizable(False, False)
        self.root.configure(bg="#0b0614")
        self._build()
        self.root.eval("tk::PlaceWindow . center")

    def _build(self):
        tk.Label(self.root, text="Warframe Inventory Sync",
                 bg="#0b0614", fg="#b18ef0",
                 font=("Segoe UI", 14, "bold")).pack(padx=16, pady=(20, 4))
        tk.Label(self.root, text="Iniciá sesión para sincronizar tu inventario.",
                 bg="#0b0614", fg="#7b6fa0",
                 font=("Segoe UI", 9)).pack(padx=16, pady=4)

        tk.Label(self.root, text="Email", bg="#0b0614", fg="#ede9f8",
                 font=("Segoe UI", 9)).pack(anchor="w", padx=16)
        self.email_var = tk.StringVar()
        tk.Entry(self.root, textvariable=self.email_var, width=30,
                 bg="#1a1030", fg="#ede9f8", insertbackground="white",
                 relief="flat", font=("Segoe UI", 10)).pack(padx=16, pady=6)

        tk.Label(self.root, text="Contraseña", bg="#0b0614", fg="#ede9f8",
                 font=("Segoe UI", 9)).pack(anchor="w", padx=16)
        self.pw_var = tk.StringVar()
        tk.Entry(self.root, textvariable=self.pw_var, show="•", width=30,
                 bg="#1a1030", fg="#ede9f8", insertbackground="white",
                 relief="flat", font=("Segoe UI", 10)).pack(padx=16, pady=6)

        self.error_var = tk.StringVar()
        tk.Label(self.root, textvariable=self.error_var,
                 bg="#0b0614", fg="#b05555",
                 font=("Segoe UI", 9)).pack()

        btn_frame = tk.Frame(self.root, bg="#0b0614")
        btn_frame.pack(padx=16, pady=(4, 20))

        tk.Button(btn_frame, text="Iniciar sesión", command=self._login,
                  bg="#b18ef0", fg="white", relief="flat",
                  font=("Segoe UI", 10), padx=12, pady=6,
                  cursor="hand2").pack(side="left", padx=4)

        tk.Button(btn_frame, text="Registrarme", command=self._register,
                  bg="#1a1030", fg="#b18ef0", relief="flat",
                  font=("Segoe UI", 10), padx=12, pady=6,
                  cursor="hand2").pack(side="left", padx=4)

    def _login(self):
        api_key, err = do_login(self.email_var.get(), self.pw_var.get())
        if api_key:
            save_api_key(api_key)
            self.root.destroy()
            self.on_success(api_key)
        else:
            self.error_var.set(err or "Error al iniciar sesión")

    def _register(self):
        api_key, err = do_register(self.email_var.get(), self.pw_var.get())
        if api_key:
            save_api_key(api_key)
            self.root.destroy()
            self.on_success(api_key)
        else:
            self.error_var.set(err or "Error al registrarse")

    def run(self):
        self.root.mainloop()


# ── Loop de sincronización ────────────────────────────────────────────────────
status_text = "Esperando Warframe..."

def sync_loop(api_key, icon):
    global status_text
    while True:
        proc = find_warframe()
        if proc:
            status_text = "Warframe detectado, leyendo inventario..."
            icon.icon = make_icon("#4faa7e")
            inventory = read_inventory(proc.pid)
            if inventory and sync_inventory(api_key, inventory):
                status_text = f"Sincronizado — {time.strftime('%H:%M')}"
                icon.icon = make_icon("#4faa7e")
            else:
                status_text = "Warframe abierto, sin datos aún"
                icon.icon = make_icon("#c4a84f")
        else:
            status_text = "Esperando Warframe..."
            icon.icon = make_icon("#b18ef0")
        time.sleep(CHECK_EVERY)


# ── Tray ──────────────────────────────────────────────────────────────────────
def start_tray(api_key):
    def on_status(icon, item):
        pass

    def on_open(icon, item):
        import webbrowser
        webbrowser.open(WEB_APP_URL)

    def on_sync(icon, item):
        proc = find_warframe()
        if not proc:
            messagebox.showinfo("Warframe Sync", "Warframe no está corriendo.")
            return
        inv = read_inventory(proc.pid)
        if inv and sync_inventory(api_key, inv):
            messagebox.showinfo("Warframe Sync", "Inventario sincronizado!")
        else:
            messagebox.showwarning("Warframe Sync", "No se pudo sincronizar.")

    def on_quit(icon, item):
        icon.stop()

    icon = pystray.Icon(
        "wf_sync",
        make_icon(),
        "Warframe Sync",
        menu=pystray.Menu(
            pystray.MenuItem(lambda _: status_text, on_status, enabled=False),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Sincronizar ahora", on_sync),
            pystray.MenuItem("Abrir web app", on_open),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Cerrar", on_quit),
        ),
    )

    threading.Thread(target=sync_loop, args=(api_key, icon), daemon=True).start()
    icon.run()


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    # Pedir UAC si no somos admin
    if not ctypes.windll.shell32.IsUserAnAdmin():
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, " ".join(f'"{a}"' for a in sys.argv), None, 1
        )
        sys.exit()

    api_key = load_api_key()
    if api_key:
        start_tray(api_key)
    else:
        win = LoginWindow(on_success=start_tray)
        win.run()


if __name__ == "__main__":
    main()