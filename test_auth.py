import time
import math
import subprocess
from curl_cffi import requests
from binascii import unhexlify
from uuid import uuid4

EMAIL    = "joaquinhd0505@gmail.com"
PASSWORD = "Psquo_879hd"

BASE_URL      = "https://mobile.warframe.com/api"
LOGIN_URL     = BASE_URL + "/login.php"
CAPTCHA_URL   = BASE_URL + "/mobileCaptcha/mblCaptcha.php"
INVENTORY_URL = BASE_URL + "/inventory.php"

SALT_HEX = "7714ae5c45fd1c5991daada98fbbe4e41d907323d7375120cb111d2b3f4a3502"

HEADERS = {
    "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 14; Pixel 8 Build/AD1A.240905.004)",
    "X-Unity-Version": "2021.3.21f1",
}


def whirlpool(data: bytes) -> str:
    result = subprocess.run(
        ["rhash", "--whirlpool", "-"],
        input=data,
        capture_output=True,
    )
    return result.stdout.decode().split()[0]


def get_unique_id() -> int:
    uid = str(uuid4()).replace('-', '')
    date = int(uid, 16)
    shave = math.floor(math.log(date) / math.log(10)) - 15
    if shave > 0:
        date = math.floor(date / 10 ** shave)
    return date


def get_captcha_url(email: str, password: str) -> str:
    pw_hash = whirlpool(password.encode('utf-8'))
    buf = unhexlify(SALT_HEX)
    buf += f"{email}/{pw_hash}".encode('utf-8')
    h = whirlpool(buf)
    return f"{CAPTCHA_URL}?input={h}"


def login(email: str, password: str, captcha_cookie: str, device_id: int, kick: bool = False) -> dict:
    pw_hash = whirlpool(password.encode('utf-8'))
    payload = {
        "email":      email,
        "password":   pw_hash,
        "time":       int(time.time()),
        "date":       device_id,
        "appVersion": "24.04.47.09",
        "os":         "android",
        "c":          captcha_cookie,
    }
    if kick:
        payload["kick"] = 1
    print(f"Enviando: {payload}")
    r = requests.post(LOGIN_URL, json=payload, headers=HEADERS, timeout=15, impersonate="chrome131")
    print(f"Login status: {r.status_code}")
    print(f"Response: {r.text[:800]}")
    if r.status_code == 200:
        return r.json()
    return {"_error": r.text, "_status": r.status_code}


def get_inventory(account_id: str, nonce: str) -> dict:
    params = {"accountId": account_id, "nonce": nonce}
    r = requests.post(INVENTORY_URL, data=b"{}", headers=HEADERS, params=params, timeout=30, impersonate="chrome131")
    print(f"Inventory status: {r.status_code}")
    return r.json()


if __name__ == "__main__":
    if not EMAIL or not PASSWORD:
        print("Pon tu email y password en las variables EMAIL y PASSWORD")
        exit(1)

    device_id = get_unique_id()
    captcha_url = get_captcha_url(EMAIL, PASSWORD)

    print("Abre esta URL en tu navegador y resuelve el captcha:")
    print(captcha_url)
    captcha_cookie = input("\nPega el valor de la cookie 'wfarggdsh': ").strip()

    print("\nHaciendo login...")
    data = login(EMAIL, PASSWORD, captcha_cookie, device_id, kick=False)

    if data.get("_status") == 400 and "new hardware detected" in data.get("_error", ""):
        code = input("Ingresa el codigo 2FA que llego a tu email: ").strip()
        requests.post(f"{BASE_URL}/authorizeNewHwid.php?code={code}", data=b"{}", headers=HEADERS, impersonate="chrome131")
        data = login(EMAIL, PASSWORD, captcha_cookie, device_id, kick=True)

    if data.get("_status") == 409:
        print(f"409 — posiblemente la cookie expiro. Resuelve el captcha de nuevo:")
        print(captcha_url)
        captcha_cookie = input("\nNueva cookie 'wfarggdsh': ").strip()
        data = login(EMAIL, PASSWORD, captcha_cookie, device_id, kick=True)

    account_id = data.get("id")
    nonce      = data.get("Nonce")

    if not account_id or not nonce:
        print("Login fallido:", data)
        exit(1)

    print(f"\naccountId: {account_id}")
    print(f"Nonce:     {nonce}")

    print("\nObteniendo inventario...")
    inv = get_inventory(account_id, str(nonce))
    print(f"Keys del inventario: {list(inv.keys())[:10]}")