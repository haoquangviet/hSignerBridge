#!/usr/bin/env python3
"""Inject hSignerBridge.exe base64 vào pdfsignclient.js.

Usage:
    python build.py                          # dùng hSignerBridge.exe cùng folder
    python build.py path/to/other_exe.exe    # dùng exe khác
"""
import base64
import re
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent
JS_PATH = SCRIPT_DIR / "pdfsignclient.js"
EXE_PATH = Path(sys.argv[1]) if len(sys.argv) > 1 else SCRIPT_DIR / "hSignerBridge.exe"

if not EXE_PATH.exists():
    sys.exit(f"Không thấy exe: {EXE_PATH}")
if not JS_PATH.exists():
    sys.exit(f"Không thấy pdfsignclient.js: {JS_PATH}")

exe_bytes = EXE_PATH.read_bytes()
exe_b64 = base64.b64encode(exe_bytes).decode("ascii")

js = JS_PATH.read_text(encoding="utf-8")
new_js, n = re.subn(
    r"const BRIDGE_EXE_B64 = '[^']*';",
    f"const BRIDGE_EXE_B64 = '{exe_b64}';",
    js,
    count=1,
)
if n != 1:
    sys.exit("Không tìm thấy placeholder 'const BRIDGE_EXE_B64' trong pdfsignclient.js")

JS_PATH.write_text(new_js, encoding="utf-8")
sys.stdout.reconfigure(encoding="utf-8")
print(f"Injected {EXE_PATH.name} ({len(exe_bytes):,} bytes -> {len(exe_b64):,} chars base64) into {JS_PATH.name}")
print(f"  New pdfsignclient.js size: {len(new_js):,} chars (~{len(new_js)//1024} KB)")
