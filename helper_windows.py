#!/usr/bin/env python3

import sys
import json
import re
import ctypes
from pathlib import Path
from typing import Optional

try:
    import psutil
    import requests
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad
except ImportError as e:
    print(f"Missing library: {e}\nRun: pip install psutil requests pycryptodome pywin32")
    sys.exit(1)

AES_KEY = bytes([76, 69, 79, 45, 65, 76, 69, 67, 9, 69, 79, 45, 65, 76, 69, 67])
AES_IV = bytes([49, 50, 70, 71, 66, 51, 54, 45, 76, 69, 51, 45, 113, 61, 57, 0])
PROCESS_NAMES = ["Warframe.x64.exe", "Warframe.x64.ex", "Warframe.exe"]
PATTERN = b'?accountId='


def find_warframe() -> Optional[psutil.Process]:
    for proc in psutil.process_iter(['name']):
        try:
            if proc.info['name'] in PROCESS_NAMES:
                return proc
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return None


def scan_memory(process: psutil.Process) -> Optional[str]:
    print("Scanning memory", end='', flush=True)

    kernel32 = ctypes.windll.kernel32
    PROCESS_VM_READ = 0x0010
    PROCESS_QUERY_INFORMATION = 0x0400

    handle = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, process.pid)
    if not handle:
        print("\nFailed to open process. Run as Administrator!")
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

    mbi = MBI()
    candidates = {}
    address = 0
    max_addr = 0x7FFFFFFF0000
    MEM_COMMIT = 0x1000
    PAGE_READABLE = 0x02 | 0x04 | 0x08 | 0x10 | 0x20 | 0x40

    while address < max_addr:
        if not kernel32.VirtualQueryEx(handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            break

        if mbi.State == MEM_COMMIT and (mbi.Protect & PAGE_READABLE) and mbi.RegionSize < 100 * 1024 * 1024:
            buffer = ctypes.create_string_buffer(mbi.RegionSize)
            bytes_read = ctypes.c_size_t()

            if kernel32.ReadProcessMemory(handle, ctypes.c_void_p(mbi.BaseAddress), buffer, mbi.RegionSize, ctypes.byref(bytes_read)):
                data = buffer.raw[:bytes_read.value]

                offset = 0
                while (idx := data.find(PATTERN, offset)) != -1:
                    offset = idx + 1
                    try:
                        acc_start = idx + len(PATTERN)
                        if acc_start + 31 > len(data):
                            continue

                        account_id = data[acc_start:acc_start + 24].decode('ascii', errors='ignore')
                        if not account_id.replace('-', '').replace('_', '').isalnum():
                            continue

                        # Extract nonce
                        if data[acc_start + 24:acc_start + 31] != b'&nonce=':
                            continue

                        nonce_match = re.match(rb'(\d+)', data[acc_start + 31:acc_start + 81])
                        if nonce_match:
                            authz = f"?accountId={account_id}&nonce={nonce_match.group(1).decode()}"
                            candidates[authz] = candidates.get(authz, 0) + 1
                            print(".", end='', flush=True)

                            if candidates[authz] >= 3:
                                kernel32.CloseHandle(handle)
                                print(" ✓")
                                return authz
                    except:
                        continue

        address += mbi.RegionSize

    kernel32.CloseHandle(handle)

    if candidates:
        print(f"\n\nFound {len(candidates)} candidates but none appeared 3+ times:")
        for authz, count in sorted(candidates.items(), key=lambda x: x[1], reverse=True)[:3]:
            print(f"  {authz[:60]}... (x{count})")
        print("\nTip: Wait longer in-game, then try again.")
    else:
        print("\n\nNo credentials found. Make sure you're:")
        print("  1. Logged into Warframe (in Orbiter/Arsenal)")
        print("  2. Running as Administrator")
        print("  3. In-game for 30+ seconds")

    return None


def download_inventory(authz: str) -> Optional[str]:
    print("Downloading inventory...", end=' ', flush=True)
    try:
        response = requests.get(f"https://mobile.warframe.com/api/inventory.php{authz}", timeout=30)
        if response.status_code == 200:
            print("✓")
            return response.text
        print(f"✗ (HTTP {response.status_code})")
    except Exception as e:
        print(f"✗ ({e})")
    return None


def save_files(inventory_json: str):
    with open("inventory.json", 'w', encoding='utf-8') as f:
        json.dump(json.loads(inventory_json), f, indent=2, ensure_ascii=False)

    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    encrypted = cipher.encrypt(pad(inventory_json.encode('utf-8'), AES.block_size))
    with open("lastData.dat", 'wb') as f:
        f.write(encrypted)

    print("✓ Saved: inventory.json & lastData.dat")


def main():
    print("Warframe API Helper\n" + "=" * 40)
    if sys.platform == 'win32':
        try:
            if not ctypes.windll.shell32.IsUserAnAdmin():
                print("⚠️  Not running as Administrator (may fail)\n")
        except:
            pass

    print("Looking for Warframe...", end=' ')
    process = find_warframe()
    if not process:
        print("✗ Not found")
        input("\nPress Enter to exit...")
        return 1
    print(f"✓ (PID: {process.pid})")

    authz = scan_memory(process)
    if not authz:
        input("\nPress Enter to exit...")
        return 2

    inventory = download_inventory(authz)
    if not inventory:
        input("\nPress Enter to exit...")
        return 3

    save_files(inventory)

    print("\n" + "=" * 40)
    print("Success! ✓")
    input("\nPress Enter to exit...")
    return 0


if __name__ == "__main__":
    sys.exit(main())