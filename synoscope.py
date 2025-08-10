#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
===============================================================================
synoscope – Synology® troubleshooting & (read‑only) recovery helper
===============================================================================
Author  : Mischa (Anovum BV)
Version : 1.0.0
License : Provided "as is" without warranty of any kind.

DISCLAIMER
----------
This tool is written and provided in good faith for diagnostic and data
recovery assistance. Use it at your own risk. The authors and Anovum BV
accept no liability for any loss or damage arising from its use.

All product names, logos, and brands are property of their respective owners.
Synology® and DiskStation® are trademarks of Synology Inc. Other names may be
trademarks of their respective owners. This project is not affiliated with,
endorsed by, or sponsored by Synology Inc.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import socket
import sys
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime
from math import gcd
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlunparse

__author__ = "Mischa (Anovum BV)"
__version__ = "1.0.0"

TOOL_NAME = "synoscope"

# ---------- Target configuration (single prompt at start) ----------
@dataclass
class Target:
    host: str
    http_port: int = 5000
    telnet_port: int = 23
    timeout: int = 10

# ---------- Logging ----------
SESSION_LOG_PATH: Optional[str] = None
LOGGER = logging.getLogger(TOOL_NAME)
CONSOLE_HANDLER: Optional[logging.Handler] = None
DEBUG_MODE = False  # global debug switch

def _default_log_dir() -> str:
    env = os.getenv("SYNOSCOPE_LOG_DIR")
    if env:
        return env
    home = os.path.expanduser("~")
    return os.path.join(home, ".synoscope", "logs")

def setup_logging() -> str:
    global SESSION_LOG_PATH, CONSOLE_HANDLER
    log_dir = _default_log_dir()
    os.makedirs(log_dir, exist_ok=True)
    ts = time.strftime("%Y%m%d-%H%M%S")
    log_file = os.path.join(log_dir, f"{TOOL_NAME}-{ts}.log")
    SESSION_LOG_PATH = log_file

    LOGGER.setLevel(logging.DEBUG)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)
    LOGGER.addHandler(fh)

    CONSOLE_HANDLER = logging.StreamHandler(sys.stderr)
    CONSOLE_HANDLER.setLevel(logging.INFO)  # raised to DEBUG if --debug
    CONSOLE_HANDLER.setFormatter(fmt)
    LOGGER.addHandler(CONSOLE_HANDLER)

    LOGGER.info("%s v%s start", TOOL_NAME, __version__)
    LOGGER.info("Log file: %s", log_file)
    return log_file

def set_debug_mode(enabled: bool) -> None:
    global DEBUG_MODE, CONSOLE_HANDLER
    DEBUG_MODE = bool(enabled)
    if CONSOLE_HANDLER is not None:
        CONSOLE_HANDLER.setLevel(logging.DEBUG if DEBUG_MODE else logging.INFO)
    LOGGER.debug("Debug mode %s", "ENABLED" if DEBUG_MODE else "disabled")

# ---------- Color & ANSI helpers ----------
USE_COLOR = True
CSI = "\033["
RESET = CSI + "0m"
BOLD = CSI + "1m"
DIM = CSI + "2m"
RED = CSI + "31m"
GREEN = CSI + "32m"
YELLOW = CSI + "33m"
BLUE = CSI + "34m"
MAGENTA = CSI + "35m"
CYAN = CSI + "36m"
WHITE = CSI + "37m"
GREY = CSI + "90m"
BRIGHT_GREEN = CSI + "92m"
BRIGHT_MAGENTA = CSI + "95m"

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
def strip_ansi(s: str) -> str:
    return ANSI_RE.sub("", s)

try:
    import colorama  # optional
    colorama.just_fix_windows_console()  # type: ignore
except Exception:
    pass

def colorize(s: str, col: str) -> str:
    if not USE_COLOR:
        return s
    return f"{col}{s}{RESET}"

def highlight_raid_name(name: str, base_color: str) -> str:
    if not name or not USE_COLOR:
        return name
    return f"{BOLD}{BRIGHT_MAGENTA}{name}{RESET}{base_color}"

# ---------- HTTP (HTTP-only) ----------
_HAS_REQUESTS = False
try:
    import requests  # type: ignore
    _HAS_REQUESTS = True
except Exception:
    _HAS_REQUESTS = False
    from urllib.request import urlopen, Request  # type: ignore
    from urllib.error import URLError, HTTPError  # type: ignore

def _build_url(host: str, port: int, path: str) -> str:
    scheme = "http"  # forced HTTP (recovery mode is HTTP-only)
    netloc = f"{host}:{port}" if port else host
    if not path.startswith("/"):
        path = "/" + path
    return urlunparse((scheme, netloc, path, "", "", ""))

def http_get(host: str,
             port: int,
             path: str,
             timeout: int = 10) -> Tuple[int, Dict[str, str], str, Optional[dict]]:
    url = _build_url(host, port, path)
    ua = {"User-Agent": f"{TOOL_NAME}/{__version__}"}
    LOGGER.debug("HTTP GET %s", url)
    if _HAS_REQUESTS:
        try:
            r = requests.get(url, headers=ua, timeout=timeout, allow_redirects=True)
            text = r.text
            obj = None
            try:
                obj = r.json()
            except Exception:
                obj = None
            hdrs = dict(r.headers)
            if DEBUG_MODE:
                LOGGER.debug("HTTP %s -> %s", url, r.status_code)
                LOGGER.debug("Headers: %r", hdrs)
                LOGGER.debug("Body (%d bytes):\n%s", len(text or ""), text)
            return r.status_code, hdrs, text, obj
        except Exception as e:
            LOGGER.error("HTTP error for %s: %s", url, e)
            return 0, {}, f"HTTP error: {e}", None
    else:
        req = Request(url, headers=ua, method="GET")
        try:
            with urlopen(req, timeout=timeout) as resp:  # type: ignore
                data = resp.read()
                text = data.decode("utf-8", errors="replace")
                obj = None
                try:
                    obj = json.loads(text)
                except Exception:
                    obj = None
                hdrs = {}
                try:
                    for k in resp.headers:
                        hdrs[k] = resp.headers[k]
                except Exception:
                    pass
                code = getattr(resp, "status", None) or resp.getcode()
                if DEBUG_MODE:
                    LOGGER.debug("HTTP %s -> %s", url, code)
                    LOGGER.debug("Headers: %r", hdrs)
                    LOGGER.debug("Body (%d bytes):\n%s", len(text or ""), text)
                return code, hdrs, text, obj
        except (URLError, HTTPError) as e:  # type: ignore
            LOGGER.error("HTTP error for %s: %s", url, e)
            return 0, {}, f"HTTP error: {e}", None

# ---------- Telnet backend selection ----------
TELNET_BACKEND = "stdlib"
StdTelnet = None
try:
    from telnetlib import Telnet as StdTelnet  # removed in Python 3.13
    TELNET_BACKEND = "stdlib"
except Exception:
    TELNET_BACKEND = "mini"

# Minimal Telnet fallback (Python 3.13+)
IAC = 255
DONT = 254
DO = 253
WONT = 252
WILL = 251
SB = 250
SE = 240

class MiniTelnet:
    """A minimal Telnet client used on Python 3.13+ where telnetlib was removed."""

    def __init__(self, host: str, port: int = 23, timeout: int = 10):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._timeout = max(0.05, float(timeout))
        self._sock.settimeout(self._timeout)
        self._sock.connect((host, port))
        self._buf = bytearray()
        self._closed = False

    def _send_iac(self, cmd: int, opt: int) -> None:
        try:
            self._sock.sendall(bytes([IAC, cmd, opt]))
        except Exception:
            pass

    def _process_iac(self, data: bytes) -> bytes:
        out = bytearray()
        i = 0
        L = len(data)
        while i < L:
            b = data[i]
            if b != IAC:
                out.append(b); i += 1; continue
            i += 1
            if i >= L:
                break
            cmd = data[i]; i += 1
            if cmd in (DO, DONT, WILL, WONT):
                if i >= L:
                    break
                opt = data[i]; i += 1
                if cmd in (DO, DONT):
                    self._send_iac(WONT, opt)  # refuse all options
                else:
                    self._send_iac(DONT, opt)
            elif cmd == IAC:
                out.append(IAC)  # literal 0xFF
            elif cmd == SB:
                while i < L:
                    if data[i] == IAC and i + 1 < L and data[i+1] == SE:
                        i += 2
                        break
                    i += 1
            else:
                pass
        return bytes(out)

    def _recv_some(self, timeout: Optional[float] = None) -> bytes:
        if timeout is None:
            timeout = self._timeout
        if timeout <= 0:
            timeout = 0.05
        self._sock.settimeout(timeout)
        try:
            chunk = self._sock.recv(4096)
            if not chunk:
                return b""
            data = self._process_iac(chunk)
            if DEBUG_MODE and data:
                try:
                    LOGGER.debug("TELNET RECV chunk:\n%s", data.decode("utf-8", errors="replace"))
                except Exception:
                    LOGGER.debug("TELNET RECV bytes: %r", data)
            return data
        except socket.timeout:
            return b""
        except BlockingIOError:
            return b""

    def read_very_eager(self) -> bytes:
        polled = self._recv_some(timeout=0.05)
        if polled:
            self._buf.extend(polled)
        data = bytes(self._buf)
        self._buf.clear()
        return data

    def read_until(self, expected: bytes, timeout: int = 10) -> bytes:
        end = time.time() + timeout
        while True:
            idx = self._buf.find(expected)
            if idx != -1:
                idx_end = idx + len(expected)
                data = bytes(self._buf[:idx_end])
                del self._buf[:idx_end]
                return data
            remaining = end - time.time()
            if remaining <= 0:
                data = bytes(self._buf)
                self._buf.clear()
                return data
            chunk = self._recv_some(timeout=max(0.05, min(self._timeout, remaining)))
            if chunk:
                self._buf.extend(chunk)
            else:
                time.sleep(0.05)

    def expect(self, patterns: List[re.Pattern], timeout: int = 10):
        end = time.time() + timeout
        while True:
            buf_bytes = bytes(self._buf)
            for idx, pat in enumerate(patterns):
                m = pat.search(buf_bytes)
                if m:
                    data = bytes(self._buf)
                    self._buf.clear()
                    return idx, m, data
            remaining = end - time.time()
            if remaining <= 0:
                data = bytes(self._buf)
                self._buf.clear()
                return -1, None, data
            chunk = self._recv_some(timeout=max(0.05, min(self._timeout, remaining)))
            if chunk:
                self._buf.extend(chunk)
            else:
                time.sleep(0.05)

    def write(self, data: bytes) -> None:
        data = data.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
        self._sock.sendall(data)

    def close(self) -> None:
        if not self._closed:
            try:
                self._sock.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                self._sock.close()
            except Exception:
                pass
            self._closed = True

def create_telnet(host: str, port: int, timeout: int):
    if TELNET_BACKEND == "stdlib" and StdTelnet is not None:
        LOGGER.info("Telnet backend: stdlib telnetlib")
        return StdTelnet(host, port, timeout)
    LOGGER.info("Telnet backend: built-in MiniTelnet (Python >=3.13)")
    return MiniTelnet(host, port, timeout)

# ---------- Password generator ----------
def generate_synology_telnet_password(now: Optional[datetime] = None) -> str:
    if now is None:
        now = datetime.now()
    m, d = now.month, now.day
    return f"{m:x}{m:02d}-{d:02x}{gcd(m, d):02d}"

# ---------- Synology state checker ----------
def synology_state_checker(host: str,
                           port: int = 5000,
                           timeout: int = 10) -> Dict[str, object]:
    sc, hdrs, text, obj = http_get(host, port, "/webman/get_state.cgi", timeout=timeout)
    result = {
        "http_status": sc,
        "recovery_mode": obj is not None,
        "raw_text_sample": text[:400] if text else "",
        "json": obj,
    }
    LOGGER.info("State check: recovery_mode=%s, http_status=%s", result["recovery_mode"], sc)
    return result

# ---------- Start Telnet service; avoid repeating per run ----------
_TELNET_STARTED: Dict[Tuple[str,int], bool] = {}

def ensure_telnet_started(host: str, port: int = 5000, timeout: int = 10) -> Tuple[bool, str]:
    key = (host, port)
    if _TELNET_STARTED.get(key):
        LOGGER.info("Telnet already started for %s:%s (skipping).", host, port)
        return True, "already started"
    sc, hdrs, text, obj = http_get(host, port, "/webman/start_telnet.cgi", timeout=timeout)
    if sc == 0:
        return False, text or "No HTTP response"
    try:
        if obj is not None:
            succ = obj.get("success")
            ok = (succ is True) or (isinstance(succ, str) and str(succ).lower() == "true")
            if ok:
                _TELNET_STARTED[key] = True
                LOGGER.info("Telnet service started via web API.")
                return True, "Telnet service started successfully."
    except Exception:
        pass
    LOGGER.warning("Unexpected telnet start response: status=%s body=%s", sc, text[:200] if text else "<no body>")
    return False, f"Unexpected response (status={sc}): {text[:200] if text else '<no body>'}"

# ---------- Telnet helpers ----------
_LOGIN_PATTERNS = [
    re.compile(br"[Ll]ogin:\s*"),
    re.compile(br"[Uu]sername:\s*"),
    re.compile(br"DiskStation login:\s*"),
]
_PASSWORD_PATTERNS = [re.compile(br"[Pp]assword:\s*")]
_AUTH_FAIL_PATTERNS = [re.compile(br"Login incorrect"), re.compile(br"[Ff]ailed")]
_SHELL_PROMPTS = [
    re.compile(br"(?m)^[^\r\n]*[>#\$]\s*$"),
    re.compile(br"(?m)^\s*(?:DiskStation|SynologyNAS)[>#\$]\s*$"),
]

def _telnet_expect_any(tn, patterns: List[re.Pattern], timeout: int):
    idx, match, buf = tn.expect(patterns, timeout)
    if DEBUG_MODE:
        try:
            LOGGER.debug("TELNET expect matched idx=%s; buffer:\n%s", idx,
                         buf.decode("utf-8", errors="replace"))
        except Exception:
            LOGGER.debug("TELNET expect matched idx=%s; raw buffer bytes len=%d", idx, len(buf or b""))
    return idx, match, buf

def telnet_login_root(host: str,
                      port: int = 23,
                      timeout: int = 10,
                      passwords: Optional[List[str]] = None,
                      quiet: bool = False):
    if passwords is None:
        passwords = [generate_synology_telnet_password(), "101-0101"]

    LOGGER.info("Connecting Telnet %s:%s ...", host, port)
    tn = create_telnet(host, port, timeout)

    _telnet_expect_any(tn, _LOGIN_PATTERNS + _PASSWORD_PATTERNS + _SHELL_PROMPTS, timeout=timeout)
    if DEBUG_MODE:
        LOGGER.debug("Sending username 'root'")
    tn.write(b"root\n")
    _telnet_expect_any(tn, _PASSWORD_PATTERNS, timeout=timeout)

    patterns = _SHELL_PROMPTS + _AUTH_FAIL_PATTERNS + _LOGIN_PATTERNS + _PASSWORD_PATTERNS
    n_shell, n_fail, n_login = len(_SHELL_PROMPTS), len(_AUTH_FAIL_PATTERNS), len(_LOGIN_PATTERNS)

    for attempt, pw in enumerate(passwords, 1):
        if DEBUG_MODE:
            LOGGER.debug("Sending password attempt #%d (len=%d)", attempt, len(pw))
        tn.write(pw.encode("ascii", "ignore") + b"\n")

        idx, _, _ = tn.expect(patterns, timeout)
        if idx == -1:
            tn.write(b"\n")
            idx2, _, _ = tn.expect(_SHELL_PROMPTS, 2)
            if 0 <= idx2 < n_shell:
                try: tn.read_very_eager()
                except Exception: pass
                if not quiet: LOGGER.info("Telnet login as root successful.")
                return tn
            if not quiet: LOGGER.warning("No clear response; trying next password...")
            continue

        if 0 <= idx < n_shell:
            try: tn.read_very_eager()
            except Exception: pass
            if not quiet: LOGGER.info("Telnet login as root successful.")
            return tn

        elif idx < n_shell + n_fail:
            if not quiet: LOGGER.warning("Password failed, trying next...")
            _telnet_expect_any(tn, _LOGIN_PATTERNS, timeout=timeout)
            if DEBUG_MODE: LOGGER.debug("Resending username 'root'")
            tn.write(b"root\n")
            _telnet_expect_any(tn, _PASSWORD_PATTERNS, timeout=timeout)
            continue

        elif idx < n_shell + n_fail + n_login:
            if DEBUG_MODE: LOGGER.debug("Got login prompt; sending username 'root' again")
            tn.write(b"root\n")
            _telnet_expect_any(tn, _PASSWORD_PATTERNS, timeout=timeout)
            continue

        else:
            if not quiet: LOGGER.warning("Password prompt again; trying next password...")
            continue

    try:
        tn.close()
    except Exception:
        pass
    LOGGER.error("Telnet authentication failed with all passwords attempted.")
    raise RuntimeError("Telnet authentication failed with all passwords attempted.")

def interactive_session(tn) -> None:
    stop = threading.Event()
    try:
        if DEBUG_MODE: LOGGER.debug("Priming remote prompt with newline")
        tn.write(b"\n")
    except Exception:
        pass
    def reader():
        try:
            while not stop.is_set():
                chunk = b""
                try: chunk = tn.read_very_eager()
                except Exception: pass
                if chunk:
                    try:
                        sys.stdout.buffer.write(chunk); sys.stdout.flush()
                    except Exception: pass
                    if DEBUG_MODE:
                        try: LOGGER.debug("TELNET RECV:\n%s", chunk.decode("utf-8", errors="replace"))
                        except Exception: LOGGER.debug("TELNET RECV bytes: %r", chunk)
                time.sleep(0.05)
        except Exception as e:
            if DEBUG_MODE: LOGGER.debug("Reader thread exception: %r", e)
    t = threading.Thread(target=reader, daemon=True); t.start()
    try:
        for line in sys.stdin:
            if DEBUG_MODE: LOGGER.debug("TELNET SEND: %s", line.rstrip("\r\n"))
            try: tn.write(line.encode("utf-8", "ignore"))
            except Exception as e:
                LOGGER.error("Write failed: %s", e); break
    except (KeyboardInterrupt, EOFError):
        pass
    finally:
        stop.set(); t.join(timeout=1)

def telnet_interactive_shell(target: Target) -> int:
    ok, msg = ensure_telnet_started(target.host, target.http_port, timeout=target.timeout)
    if not ok:
        LOGGER.error("Could not start Telnet: %s", msg)
        print(colorize(f"Could not start Telnet via web-API: {msg}", RED))
        return 2
    pw_today = generate_synology_telnet_password()
    LOGGER.info("Trying password-of-the-day: %s (fallback: 101-0101)", pw_today)
    try:
        tn = telnet_login_root(target.host, port=target.telnet_port, timeout=target.timeout,
                               passwords=[pw_today, "101-0101"])
    except Exception as e:
        LOGGER.error("Telnet login failed: %s", e)
        print(colorize("Telnet login failed (all passwords tried).", RED))
        return 3
    print(colorize("[*] Interactive telnet (Ctrl-C or Ctrl-] + 'quit' to exit).", CYAN))
    try:
        interactive_session(tn)
    finally:
        try: tn.close()
        except Exception: pass
    return 0

# ---------- Remote command execution ----------
def tn_run_cmd(tn, cmd: str, timeout: int = 20) -> str:
    sentinel = f"__SYNOSCOPE_EOF_{uuid.uuid4().hex}__"
    line = f"{cmd}; echo {sentinel}\n"
    if DEBUG_MODE: LOGGER.debug("TN CMD: %s", cmd)
    tn.write(line.encode("utf-8", "ignore"))
    data = tn.read_until(sentinel.encode("utf-8"), timeout=timeout)
    text = data.decode("utf-8", errors="ignore")
    text = text.split(sentinel)[0]
    lines = text.splitlines()
    if lines and lines[0].strip().startswith(cmd.split()[0]):
        lines = lines[1:]
    out = "\n".join(lines).strip()
    if DEBUG_MODE: LOGGER.debug("TN OUT for [%s]:\n%s", cmd, out)
    return out

# ---------- Parsers: lsblk / fdisk / blkid ----------
def parse_lsblk_json(text: str) -> Optional[dict]:
    try:
        obj = json.loads(text)
        if isinstance(obj, dict) and "blockdevices" in obj:
            return obj
    except Exception:
        pass
    return None

def parse_lsblk_p(text: str) -> List[dict]:
    out = []
    for line in text.splitlines():
        if not line.strip():
            continue
        entry = {}
        for m in re.finditer(r'(\w+)="(.*?)"', line):
            entry[m.group(1)] = m.group(2)
        if entry:
            out.append(entry)
    return out

def parse_fdisk_summary(text: str) -> Dict[str, str]:
    devs: Dict[str, str] = {}
    rx = re.compile(r"^Disk\s+(/dev/[a-zA-Z0-9]+):\s+([^,]+)", re.MULTILINE)
    for m in rx.finditer(text):
        devs[m.group(1)] = m.group(2).strip()
    return devs

def parse_blkid_map(text: str) -> Dict[str, Dict[str, str]]:
    mapping: Dict[str, Dict[str, str]] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or not line.startswith("/dev/"):
            continue
        try:
            dev, rest = line.split(":", 1)
        except ValueError:
            continue
        kvs: Dict[str, str] = {}
        for m in re.finditer(r'(\w+)="([^"]*)"', rest):
            kvs[m.group(1).upper()] = m.group(2)
        mapping[dev] = kvs
    return mapping

# ---------- Parsers: mdadm / mdstat ----------
def parse_mdadm_scan(scan_text: str) -> Dict[str, dict]:
    arrays: Dict[str, dict] = {}
    for line in scan_text.splitlines():
        line = line.strip()
        if not line or not line.startswith("ARRAY "):
            continue
        try:
            parts = line.split()
            dev = parts[1]
            attrs = {}
            for kv in parts[2:]:
                if "=" in kv:
                    k, v = kv.split("=", 1)
                    attrs[k] = v
            arrays[dev] = {
                "device": dev,
                "name": attrs.get("name", ""),
                "uuid": attrs.get("UUID", attrs.get("uuid", "")),
                "metadata": attrs.get("metadata", ""),
                "container": attrs.get("container", ""),
                "raw": line,
            }
        except Exception:
            continue
    return arrays

def parse_mdstat(mdstat_text: str) -> Dict[str, dict]:
    arrays: Dict[str, dict] = {}
    lines = mdstat_text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        m = re.match(r"^(md\d+)\s*:\s*(\w+)\s+(raid\d+)\s+(.*)$", line)
        if m:
            name, state_word, level, rest = m.groups()
            members = []
            for tok in rest.split():
                m2 = re.match(r"([a-zA-Z0-9/_-]+)\[\d+\](?:\(\w+\))?", tok)
                if m2:
                    dev = m2.group(1)
                    if not dev.startswith("/dev/"):
                        dev = "/dev/" + dev
                    members.append(dev)
            blocks = None
            bracket = ""
            conf = up = None
            progress = None
            j = i + 1
            if j < len(lines):
                l2 = lines[j].strip()
                m2 = re.search(r"(\d+)\s+blocks", l2)
                if m2: blocks = int(m2.group(1))
                m3 = re.search(r"\[(\d+)/(\d+)\]\s*\[([U_]+)\]", l2)
                if m3:
                    conf, up, bracket = int(m3.group(1)), int(m3.group(2)), m3.group(3)
                if j + 1 < len(lines):
                    l3 = lines[j + 1]
                    if any(x in l3 for x in ("recovery", "resync", "reshape", "check")):
                        m4 = re.search(r"=\s*([\d\.]+)%", l3)
                        prog = m4.group(1) if m4 else None
                        progress = f"{prog}%" if prog else l3.strip()
            arrays[name] = {
                "name": name,
                "level": level,
                "state_word": state_word,
                "members": members,
                "blocks": blocks,
                "status_bracket": bracket,
                "configured": conf,
                "up": up,
                "progress": progress,
                "raw": "\n".join(lines[i:i+3]),
            }
        i += 1
    return arrays

def parse_mdadm_detail_text(detail_text: str) -> Dict[str, object]:
    info: Dict[str, object] = {}
    def grab(rx: str, key: str, cast=None):
        m = re.search(rx, detail_text, re.MULTILINE)
        if m:
            val = m.group(1).strip()
            info[key] = cast(val) if cast else val
    grab(r"Raid Level\s*:\s*(.+)", "raid_level")
    grab(r"Array Size\s*:\s*([^\n]+)", "array_size")
    grab(r"State\s*:\s*([^\n]+)", "state")
    grab(r"Active Devices\s*:\s*(\d+)", "active_devices", int)
    grab(r"Working Devices\s*:\s*(\d+)", "working_devices", int)
    grab(r"Failed Devices\s*:\s*(\d+)", "failed_devices", int)
    grab(r"Spare Devices\s*:\s*(\d+)", "spare_devices", int)
    grab(r"Raid Devices\s*:\s*(\d+)", "raid_devices", int)
    grab(r"Name\s*:\s*([^\n]+)", "name")
    grab(r"UUID\s*:\s*([^\n]+)", "uuid")
    members: List[dict] = []
    for line in detail_text.splitlines():
        m = re.match(r"^\s*\d+\s+\d+\s+\d+\s+\d+\s+(.+?)\s+(/dev/\S+)\s*$", line)
        if m:
            state, dev = m.group(1).strip(), m.group(2).strip()
            members.append({"device": dev, "state": state})
        else:
            m2 = re.match(r"^\s*\d+\s+(.+?)\s+(/dev/\S+)\s*$", line)
            if m2:
                state, dev = m2.group(1).strip(), m2.group(2).strip()
                members.append({"device": dev, "state": state})
    if members:
        info["members"] = members
    info["raw"] = detail_text.strip()
    return info

# ---------- Build unified view ----------
def build_unified_view(lsblk_json: Optional[dict],
                       lsblk_p: Optional[List[dict]],
                       blkid_text: str,
                       fdisk_text: str,
                       mdadm_scan_text: str,
                       mdstat_text: str,
                       mdadm_details: Dict[str, dict]) -> dict:
    view: dict = {
        "devices": [],
        "arrays_scan": parse_mdadm_scan(mdadm_scan_text),
        "mdstat": parse_mdstat(mdstat_text),
        "mdadm_detail": mdadm_details,
        "blkid_map": parse_blkid_map(blkid_text),
        "mdstat_raw": mdstat_text.strip(),
        "mdadm_scan_raw": mdadm_scan_text.strip(),
        "fdisk_raw": fdisk_text.strip()[:8000],
        "blkid_raw": blkid_text.strip(),
    }
    if lsblk_json and isinstance(lsblk_json.get("blockdevices"), list):
        view["devices"] = lsblk_json["blockdevices"]
    elif lsblk_p:
        view["devices"] = lsblk_p

    sizes = parse_fdisk_summary(fdisk_text)
    def _attach_sizes(node):
        name = node.get("name") or node.get("KNAME") or ""
        kname = name if name.startswith("/dev/") else (f"/dev/{name}" if name else "")
        if not node.get("size") and kname and kname in sizes:
            node["size"] = sizes[kname]
        if "children" in node and isinstance(node["children"], list):
            for ch in node["children"]:
                if isinstance(ch, dict):
                    _attach_sizes(ch)
    if isinstance(view["devices"], list):
        for dev in view["devices"]:
            if isinstance(dev, dict):
                _attach_sizes(dev)
    return view

# ---------- Pretty printing helpers ----------
def _legend() -> None:
    print(colorize("Legend:", BOLD))
    print(f"  {colorize('DISK', GREEN)} physical disk   "
          f"{colorize('PART', CYAN)} partition   "
          f"{colorize('/dev/mdX', MAGENTA)} md-RAID device")
    print("  [UU_] status: U = ok, _ = missing/faulty")
    print("  State: clean/active = OK, degraded/recover/resync = attention, inactive/failed = error")
    print("")

def _color_for_state(state: str, bracket: str) -> str:
    s = (state or "").lower()
    if "inactive" in s or "failed" in s:
        return RED
    if "degraded" in s or (bracket and "_" in bracket):
        return YELLOW
    if any(x in s for x in ("recover", "resync", "reshape", "check")):
        return YELLOW
    return GREEN if any(x in s for x in ("clean", "active")) else WHITE

def _short_size(array_size_line: Optional[str]) -> str:
    if not array_size_line:
        return ""
    m = re.search(r"\(([^)]+)\)", array_size_line)
    return m.group(1) if m else array_size_line.strip()

def _progress_bar(percent_str: Optional[str], width: int = 28) -> str:
    if not percent_str or not percent_str.endswith("%"):
        return ""
    try:
        pct = float(percent_str.strip("%"))
    except Exception:
        return percent_str
    filled = int(round((pct / 100.0) * width))
    bar = "█" * filled + "░" * (width - filled)
    return f"{bar} ({pct:.1f}%)"

def _tolerance_for_level(level: str) -> Tuple[int, str]:
    lvl = (level or "").lower()
    if lvl == "raid0": return 0, "0 disks (striping only)"
    if lvl == "raid1": return 1_000_000, "n-1 disks (mirroring)"
    if lvl == "raid4": return 1, "1 disk (dedicated parity)"
    if lvl == "raid5": return 1, "1 disk (single parity)"
    if lvl == "raid6": return 2, "2 disks (dual parity)"
    if lvl == "raid10": return 1, "≥1 (layout dependent; 1 per mirror pair)"
    return 0, "unknown"

def _box(lines: List[str]) -> List[str]:
    width = max(len(strip_ansi(l)) for l in lines) if lines else 0
    top = "┌" + "─" * (width + 2) + "┐"
    bot = "└" + "─" * (width + 2) + "┘"
    body = [f"│ {l}{' ' * (width - len(strip_ansi(l)))} │" for l in lines]
    return [top, *body, bot]

def print_colored_disk_overview(view: dict) -> None:
    _legend()

    print(colorize("=== Physical Disks & Partitions ===", BOLD))
    devices = view.get("devices") or []
    blkid_map: Dict[str, Dict[str, str]] = view.get("blkid_map", {}) or {}

    def is_raid_member(dev_path: str, node: dict) -> bool:
        fstype = (node.get("fstype") or node.get("FSTYPE") or "").lower()
        if fstype == "linux_raid_member":
            return True
        bd = blkid_map.get(dev_path, {})
        return (bd.get("TYPE", "").lower() == "linux_raid_member")

    if not devices:
        print("(No lsblk data available; see mdadm/fdisk raw sections below.)")
    else:
        def _print_dev(dev: dict, indent: int = 0):
            ind = "  " * indent
            name = dev.get("name") or dev.get("KNAME") or ""
            dev_path = name if name.startswith("/dev/") else (f"/dev/{name}" if name else "")
            size = dev.get("size", "")
            dtype = (dev.get("type") or dev.get("TYPE") or "").lower()
            fstype = dev.get("fstype", dev.get("FSTYPE", ""))
            mp = dev.get("mountpoint", dev.get("MOUNTPOINT", "")) or ""
            model = dev.get("model", dev.get("MODEL", "")) or ""
            serial = dev.get("serial", dev.get("SERIAL", "")) or ""
            col = WHITE
            label = ""
            if dtype == "disk":
                col = GREEN; label = "DISK"
            elif dtype == "part":
                col = CYAN; label = "PART"
            elif name.startswith("md") or dev_path.startswith("/dev/md"):
                col = MAGENTA; label = "MD"
            extra = []
            if model: extra.append(model)
            if serial: extra.append(f"sn:{serial}")
            if mp: extra.append(f"mnt:{mp}")
            if fstype: extra.append(f"fs:{fstype}")
            if dev_path and is_raid_member(dev_path, dev):
                extra.append("member: mdraid")
            extra_s = f" [{' | '.join(extra)}]" if extra else ""
            name_disp = dev_path or name or "<unknown>"
            line = f"{ind}{name_disp:17} {label:4} {size:>10}{extra_s}"
            print(colorize(line, col))
            for ch in dev.get("children", []) or []:
                if isinstance(ch, dict):
                    cname = ch.get("name") or ch.get("KNAME") or ""
                    ch_path = cname if cname.startswith("/dev/") else f"/dev/{cname}"
                    tag = colorize(" [linux_raid_member]", MAGENTA) if is_raid_member(ch_path, ch) else ""
                    ch_fstype = ch.get("fstype", ch.get("FSTYPE", "")) or ""
                    ch_mp = ch.get("mountpoint", ch.get("MOUNTPOINT", "")) or ""
                    line_ch = f"{ind}  {ch_path:17} PART {ch.get('size',''):>10} fs:{ch_fstype or '-'}"
                    if ch_mp:
                        line_ch += f" mnt:{ch_mp}"
                    print(colorize(line_ch, CYAN) + tag)
                    for gg in ch.get("children", []) or []:
                        if isinstance(gg, dict):
                            _print_dev(gg, indent + 2)
        for dev in devices:
            if isinstance(dev, dict):
                _print_dev(dev)

    arrays_scan: Dict[str, dict] = view.get("arrays_scan", {}) or {}
    mdstat: Dict[str, dict] = view.get("mdstat", {}) or {}
    mdadm_detail: Dict[str, dict] = view.get("mdadm_detail", {}) or {}

    print()
    print(colorize("=== RAID Arrays (detailed summary) ===", BOLD))

    devnames: List[str] = []
    for name in mdstat.keys():
        devnames.append(f"/dev/{name}")
    for dev in arrays_scan.keys():
        if dev not in devnames:
            devnames.append(dev)

    if not devnames:
        print("(No RAID arrays detected.)")
    else:
        print(colorize(f"*** EXISTING RAID ARRAY(S) DETECTED: {len(devnames)} ***", BOLD + BRIGHT_GREEN))
        for dev in sorted(devnames):
            name = dev.split("/")[-1]
            st = mdstat.get(name, {})
            sc = arrays_scan.get(dev, {})
            dt = mdadm_detail.get(dev, {})

            level = (st.get("level") or dt.get("raid_level") or "").lower()
            bracket = st.get("status_bracket") or ""
            state = dt.get("state") or st.get("state_word") or "unknown"
            size_short = _short_size(dt.get("array_size"))
            mdname = sc.get("name") or dt.get("name") or ""
            uuid = sc.get("uuid") or dt.get("uuid") or ""
            progress = st.get("progress") or ""
            conf = st.get("configured")
            up = st.get("up")

            det_line = f"[DETECTED] Array {dev} ({level or '?'})"
            if mdname:
                det_line += f" name='{mdname}'"
            if uuid:
                det_line += f" uuid={uuid}"
            print(colorize(det_line, BRIGHT_GREEN))

            col = _color_for_state(str(state), str(bracket))
            base_col = col

            tol, tol_txt = _tolerance_for_level(level)
            missing = bracket.count("_") if isinstance(bracket, str) else None
            risk = "LOW"
            if "inactive" in state.lower() or "failed" in state.lower():
                risk = "HIGH"
            elif "degraded" in state.lower() or (missing and missing > 0):
                risk = "MEDIUM"
            if isinstance(tol, int) and missing is not None and tol != 1_000_000 and missing > tol:
                risk = "HIGH"
            if level == "raid1" and conf and up is not None:
                missing_ri = (conf - up) if (conf is not None and up is not None) else missing or 0
                if missing_ri >= conf:
                    risk = "HIGH"
                elif missing_ri == 0:
                    risk = "LOW"
                else:
                    risk = "MEDIUM"

            name_part = ""
            if mdname:
                name_part = f"name:{highlight_raid_name(mdname, base_col)}"
            header = f"{dev}  {level or '?'}  state:{state}  [{bracket or '??'}]"
            sub1 = []
            if name_part: sub1.append(name_part)
            if size_short: sub1.append(f"size:{size_short}")
            if uuid: sub1.append(f"uuid:{uuid}")
            if conf is not None and up is not None: sub1.append(f"devices:{up}/{conf}")
            sub1.append(f"tolerance:{tol_txt}")
            sub1.append(f"risk:{risk}")
            lines = [header, " ".join(sub1)]

            members_det = {m.get("device"): (m.get("state") or "") for m in (dt.get("members") or [])}
            ordered_members = (st.get("members") or list(members_det.keys()) or [])
            if ordered_members:
                lines.append("members:")
                for idx, mdev in enumerate(ordered_members):
                    letter = ""
                    if isinstance(bracket, str) and idx < len(bracket):
                        letter = bracket[idx]
                    letter_disp = f"[{letter or '?'}]"
                    mstate = (members_det.get(mdev, "") or "").lower()
                    if letter == "U" or "active" in mstate:
                        mcol = GREEN
                    elif letter == "_":
                        mcol = RED
                    else:
                        mcol = WHITE
                    lines.append(colorize(f"  {mdev:16} {letter_disp} {members_det.get(mdev,'-')}", mcol))

            if progress:
                pbar = _progress_bar(progress)
                lines.append(f"rebuild/progress: {pbar or progress}")

            hints = []
            stl = state.lower()
            if "inactive" in stl:
                hints.append("Array is INACTIVE → detecting/assembling members with mdadm may be needed (read‑only).")
            if "degraded" in stl:
                hints.append("DEGRADED → back up immediately; identify failed disk; rebuild only after copying data.")
            if "recover" in stl or "resync" in stl:
                hints.append("Recovery/resync in progress → minimize I/O; monitor mdstat.")
            if not hints:
                hints.append("Status appears healthy. Always maintain current backups.")
            lines.append(colorize("hint: " + " ".join(hints), GREY))

            for ln in _box([l if isinstance(l, str) else l for l in lines]):
                print(colorize(ln, col))

    print()
    print(colorize("=== mdadm --examine --scan (raw) ===", BOLD))
    scan_raw = view.get("mdadm_scan_raw", "")
    print(scan_raw if scan_raw else "(empty)")

    print()
    print(colorize("=== /proc/mdstat (raw) ===", BOLD))
    mdstat_raw = view.get("mdstat_raw", "")
    if mdstat_raw:
        for line in mdstat_raw.splitlines():
            if re.search(r"\bactive\b", line):
                print(colorize(line, GREEN))
            elif re.match(r"^md\d+\s*:", line):
                print(colorize(line, CYAN))
            else:
                print(line)
    else:
        print("(empty)")

    print()
    print(colorize("=== fdisk -l (summary/raw) ===", BOLD))
    print(view.get("fdisk_raw") or "(empty)")
    print()
    print(colorize("=== blkid (raw) ===", BOLD))
    print(view.get("blkid_raw") or "(empty)")

# ---------- Disk state collection over Telnet ----------
def disk_state_over_telnet(target: Target, as_json: bool = False) -> int:
    ok, msg = ensure_telnet_started(target.host, target.http_port, timeout=target.timeout)
    if not ok:
        LOGGER.error("Could not start Telnet: %s", msg)
        return 2
    pw_today = generate_synology_telnet_password()
    LOGGER.info("Trying password-of-the-day: %s (fallback: 101-0101)", pw_today)
    tn = telnet_login_root(target.host, port=target.telnet_port, timeout=target.timeout,
                           passwords=[pw_today, "101-0101"], quiet=True)
    try:
        lsblk_json_txt = tn_run_cmd(tn, 'lsblk -J -o NAME,KNAME,TYPE,SIZE,FSTYPE,MOUNTPOINT,MODEL,SERIAL,UUID 2>/dev/null', timeout=target.timeout)
        lsblk_json_obj = parse_lsblk_json(lsblk_json_txt)
        lsblk_p_txt = ""
        lsblk_p_list = None
        if not lsblk_json_obj:
            lsblk_p_txt = tn_run_cmd(tn, 'lsblk -P -o NAME,KNAME,TYPE,SIZE,FSTYPE,MOUNTPOINT,MODEL,SERIAL,UUID 2>/dev/null', timeout=target.timeout)
            lsblk_p_list = parse_lsblk_p(lsblk_p_txt) if lsblk_p_txt else None

        blkid_txt = tn_run_cmd(tn, 'blkid 2>/dev/null', timeout=target.timeout)
        fdisk_txt = tn_run_cmd(tn, 'fdisk -l 2>/dev/null', timeout=max(target.timeout, 25))
        mdadm_scan_txt = tn_run_cmd(tn, 'mdadm --examine --scan 2>/dev/null', timeout=target.timeout)
        mdstat_txt = tn_run_cmd(tn, 'cat /proc/mdstat 2>/dev/null || cat /prod/mdstat 2>/dev/null', timeout=target.timeout)

        arrays_from_scan = parse_mdadm_scan(mdadm_scan_txt)
        arrays_from_mdstat = parse_mdstat(mdstat_txt)
        md_devs = set(arrays_from_scan.keys()) | {f"/dev/{k}" for k in arrays_from_mdstat.keys()}
        mdadm_details: Dict[str, dict] = {}
        for dev in sorted(md_devs):
            detail_txt = tn_run_cmd(tn, f'mdadm --detail {dev} 2>/dev/null', timeout=target.timeout)
            if detail_txt.strip():
                mdadm_details[dev] = parse_mdadm_detail_text(detail_txt)

        view = build_unified_view(lsblk_json_obj, lsblk_p_list,
                                  blkid_txt, fdisk_txt,
                                  mdadm_scan_txt, mdstat_txt,
                                  mdadm_details)
        if as_json:
            print(json.dumps(view, indent=2, ensure_ascii=False))
        else:
            print_colored_disk_overview(view)

        LOGGER.info("Disk survey complete: %d devices, %d arrays",
                    len(view.get("devices") or []), len(view.get("mdadm_detail") or []))
        return 0
    finally:
        try: tn.close()
        except Exception: pass

# ---------- Mount & check restore flag ----------
def detect_md_arrays_from_mdstat(mdstat: str) -> List[str]:
    arrays = []
    for line in mdstat.splitlines():
        if re.match(r"^md\d+\s*:", line):
            name = line.split(":")[0].strip()
            arrays.append(name)
    return arrays

def mount_md0_and_check_flag(target: Target) -> int:
    ok, msg = ensure_telnet_started(target.host, target.http_port, timeout=target.timeout)
    if not ok:
        LOGGER.error("Could not start Telnet: %s", msg)
        return 2
    pw_today = generate_synology_telnet_password()
    LOGGER.info("Trying password-of-the-day: %s (fallback: 101-0101)", pw_today)
    tn = telnet_login_root(target.host, port=target.telnet_port, timeout=target.timeout,
                           passwords=[pw_today, "101-0101"], quiet=True)
    try:
        mdstat = tn_run_cmd(tn, 'cat /proc/mdstat 2>/dev/null || cat /prod/mdstat 2>/dev/null', timeout=target.timeout)
        arrays = detect_md_arrays_from_mdstat(mdstat)
        LOGGER.info("mdstat arrays detected: %s", ", ".join(arrays) if arrays else "<none>")

        target_md = "md0" if "md0" in arrays else (arrays[0] if arrays else None)
        if not target_md:
            print(colorize("No md array found in /proc/mdstat; cannot mount.", RED))
            LOGGER.warning("No arrays found; aborting mount.")
            return 3

        dev = f"/dev/{target_md}"
        mnt = "/mnt/md0"
        tn_run_cmd(tn, f'mkdir -p {mnt} 2>/dev/null || true', timeout=target.timeout)
        already = tn_run_cmd(tn, f'grep -q " {mnt} " /proc/mounts && echo MOUNTED || echo NOT', timeout=target.timeout)
        if already.strip() != "MOUNTED":
            mount_out = tn_run_cmd(tn, f'mount -o ro {dev} {mnt} 2>&1 || echo __MOUNT_ERR__', timeout=max(target.timeout, 20))
            if "__MOUNT_ERR__" in mount_out:
                print(colorize(f"Mount failed: {dev} -> {mnt}", RED))
                LOGGER.error("Mount failed for %s -> %s: %s", dev, mnt, mount_out)
                return 4
            LOGGER.info("Mounted %s at %s (ro).", dev, mnt)
        else:
            LOGGER.info("%s is already mounted.", mnt)

        flag_exists = tn_run_cmd(tn, f'[ -f {mnt}/.restore_to_default ] && echo YES || echo NO', timeout=target.timeout)
        if flag_exists.strip() == "YES":
            print(colorize(f"[!] Found: {mnt}/.restore_to_default", YELLOW))
            print(colorize("    Device is flagged for factory reset, but reset likely not executed yet.", YELLOW))
            print(colorize("    RAID restore/recovery may still be possible.", YELLOW))
            LOGGER.warning(".restore_to_default present at %s", mnt)
        else:
            print(colorize("[+] No .restore_to_default found at the array root.", GREEN))
            LOGGER.info("No restore flag present on array root.")

        return 0
    finally:
        try: tn.close()
        except Exception: pass

# ---------- Clear restore flag via HTTP ----------
def clear_restore_flag(target: Target) -> int:
    sc, hdrs, text, obj = http_get(target.host, target.http_port, "/webman/clean_restore_to_default_flags.cgi", timeout=target.timeout)
    if sc == 0:
        LOGGER.error("HTTP failure calling clean_restore_to_default_flags.cgi: %s", text)
        print(colorize("HTTP error calling clean_restore_to_default_flags.cgi", RED))
        return 2
    ok = False
    try:
        if obj is not None:
            succ = obj.get("success")
            ok = (succ is True) or (isinstance(succ, str) and str(succ).lower() == "true")
    except Exception:
        ok = False
    if ok:
        print(colorize("[+] 'restore to default' flag(s) cleared via web-API.", GREEN))
        print(colorize("    Reboot the device. Then manually verify the flag is absent on the disks.", CYAN))
        LOGGER.info("clean_restore_to_default_flags.cgi reported success.")
        return 0
    else:
        print(colorize("[-] clean_restore_to_default_flags.cgi did not return success.", YELLOW))
        print(colorize("    Try again and manually verify the disks.", YELLOW))
        LOGGER.warning("clean_restore_to_default_flags.cgi did not return success. Status=%s Body=%s", sc, text[:200] if text else "<no body>")
        return 1

# ---------- CLI / Menu ----------
def pause() -> None:
    try:
        input(colorize("\nPress Enter to return to the menu...", DIM))
    except EOFError:
        pass

def ask_target_once(default_http: int = 5000, default_telnet: int = 23, default_timeout: int = 10, pre_host: Optional[str] = None) -> Target:
    if pre_host:
        host = pre_host.strip()
    else:
        while True:
            host = input("IP/hostname: ").strip()
            if host:
                break
            print("Host is required.")
    t = Target(host=host, http_port=default_http, telnet_port=default_telnet, timeout=default_timeout)
    print(colorize(f"\nTarget set: host={t.host}  HTTP={t.http_port}  Telnet={t.telnet_port}  timeout={t.timeout}s", BOLD))
    return t

def menu(target: Target) -> None:
    while True:
        print(colorize("\n=== synoscope menu ===", BOLD))
        print(colorize(f"Target: {target.host} (HTTP {target.http_port}, Telnet {target.telnet_port}, timeout {target.timeout}s)", GREY))
        print("1) Check Synology state (recovery mode)")
        print("2) Telnet shell (enable via web API, auto-login root)")
        print("3) Disk state (read-only over Telnet)")
        print("4) Mount md0 and check .restore_to_default")
        print("5) Clear restore flag via web-API (clean_restore_to_default_flags.cgi)")
        print("0) Change target/IP")
        print("6) Exit")
        choice = input("Choose option [0-6]: ").strip()

        if choice not in {"0", "1", "2", "3", "4", "5", "6"}:
            continue
        if choice == "6":
            break

        if choice == "0":
            # Change target once; still won't prompt every time afterwards
            new_host = input("New IP/hostname: ").strip()
            if new_host:
                target.host = new_host
                print(colorize(f"Target updated → {target.host}", CYAN))
            continue

        if choice == "1":
            res = synology_state_checker(target.host, port=target.http_port, timeout=target.timeout)
            if res.get("recovery_mode"):
                print(colorize("[+] Recovery mode detected (get_state.cgi returned JSON).", GREEN))
                if res.get("json") is not None:
                    print(json.dumps(res.get("json"), indent=2, ensure_ascii=False))
            else:
                print(colorize("[-] Not in recovery mode (response was not JSON).", YELLOW))
                print(f"(HTTP {res['http_status']}) Body sample:\n{res['raw_text_sample']}")
            pause()

        elif choice == "2":
            rc = telnet_interactive_shell(target)
            if rc != 0:
                print(colorize("Could not start Telnet session.", RED))
            pause()

        elif choice == "3":
            as_json = (input("JSON output? [y/N]: ").strip().lower() == "y")
            rc = disk_state_over_telnet(target, as_json=as_json)
            if rc != 0:
                print(colorize("Could not retrieve disk state.", RED))
            pause()

        elif choice == "4":
            rc = mount_md0_and_check_flag(target)
            if rc != 0:
                print(colorize("Mount/check could not be completed.", RED))
            pause()

        elif choice == "5":
            _ = clear_restore_flag(target)
            pause()

def make_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="synoscope", description="Synology troubleshoot & (read-only) recovery helper.")
    sub = p.add_subparsers(dest="cmd")

    # Global flags
    p.add_argument("--menu", action="store_true", help="Start interactive menu (single IP prompt)")
    p.add_argument("--host", help="IP or hostname to prefill target (skips prompt)")
    p.add_argument("--no-color", action="store_true", help="Disable color in output (global)")
    p.add_argument("--debug", action="store_true", help="Debug mode: verbose console logging and Telnet I/O tracing")
    p.add_argument("--http-port", type=int, default=5000, help="HTTP port for webman (default 5000)")
    p.add_argument("--telnet-port", type=int, default=23, help="Telnet port (default 23)")
    p.add_argument("--timeout", type=int, default=10, help="Timeout in seconds (default 10)")

    # Subcommands still available for non-interactive use:
    def add_http_args(sp):
        sp.add_argument("--host", required=True, help="IP or hostname of the Synology")
        sp.add_argument("--http-port", type=int, default=5000, help="HTTP port for webman (default 5000)")
        sp.add_argument("--timeout", type=int, default=10, help="Timeout in seconds (default 10)")
        sp.add_argument("--no-color", action="store_true", help="Disable color in output")
        sp.add_argument("--debug", action="store_true", help="Debug mode (also allowed here)")

    sp_state = sub.add_parser("state", help="Check if the Synology is in recovery mode")
    add_http_args(sp_state)

    sp_shell = sub.add_parser("shell", help="Start Telnet service and open interactive root shell")
    add_http_args(sp_shell)
    sp_shell.add_argument("--telnet-port", type=int, default=23, help="Telnet port (default 23)")

    sp_disks = sub.add_parser("disks", help="Read-only disk state over Telnet (colored + detailed RAID summary)")
    add_http_args(sp_disks)
    sp_disks.add_argument("--telnet-port", type=int, default=23, help="Telnet port (default 23)")
    sp_disks.add_argument("--json", action="store_true", help="Emit JSON instead of text")

    sp_mount = sub.add_parser("mount-check", help="Mount /dev/md0 on /mnt/md0 (ro) and check .restore_to_default")
    add_http_args(sp_mount)
    sp_mount.add_argument("--telnet-port", type=int, default=23, help="Telnet port (default 23)")

    sp_clear = sub.add_parser("clear-flag", help="Clear restore flag via HTTP: /webman/clean_restore_to_default_flags.cgi")
    add_http_args(sp_clear)

    return p

def main() -> None:
    global USE_COLOR
    log_file = setup_logging()
    parser = make_parser()
    args = parser.parse_args()

    if getattr(args, "no_color", False):
        USE_COLOR = False

    set_debug_mode(bool(getattr(args, "debug", False)))

    # Interactive mode with single IP prompt at the beginning
    if args.cmd is None and (args.menu or True):
        # If a subcommand wasn't provided, run the menu.
        pre_host = args.host if hasattr(args, "host") else None
        target = ask_target_once(
            default_http=args.http_port,
            default_telnet=args.telnet_port,
            default_timeout=args.timeout,
            pre_host=pre_host
        )
        if DEBUG_MODE:
            LOGGER.debug("Entering menu with target: %s", target)
        menu(target)
        LOGGER.info("Exiting. Log: %s", log_file)
        return

    # Non-interactive subcommands (still supported)
    if args.cmd == "state":
        res = synology_state_checker(args.host, port=args.http_port, timeout=args.timeout)
        if res.get("recovery_mode"):
            print(colorize("[+] Recovery mode detected (JSON from get_state.cgi):", GREEN))
            print(json.dumps(res.get("json"), indent=2, ensure_ascii=False))
            sys.exit(0)
        else:
            print(colorize("[-] Not in recovery mode (response was not JSON).", YELLOW))
            print(f"(HTTP {res['http_status']}) Body sample:\n{res['raw_text_sample']}")
            sys.exit(1)

    elif args.cmd == "shell":
        t = Target(args.host, http_port=args.http_port, telnet_port=args.telnet_port, timeout=args.timeout)
        rc = telnet_interactive_shell(t)
        LOGGER.info("Exiting. Log: %s", log_file)
        sys.exit(rc)

    elif args.cmd == "disks":
        t = Target(args.host, http_port=args.http_port, telnet_port=args.telnet_port, timeout=args.timeout)
        rc = disk_state_over_telnet(t, as_json=bool(getattr(args, "json", False)))
        LOGGER.info("Exiting. Log: %s", log_file)
        sys.exit(rc)

    elif args.cmd == "mount-check":
        t = Target(args.host, http_port=args.http_port, telnet_port=args.telnet_port, timeout=args.timeout)
        rc = mount_md0_and_check_flag(t)
        LOGGER.info("Exiting. Log: %s", log_file)
        sys.exit(rc)

    elif args.cmd == "clear-flag":
        t = Target(args.host, http_port=args.http_port, telnet_port=args.telnet_port, timeout=args.timeout)
        rc = clear_restore_flag(t)
        LOGGER.info("Exiting. Log: %s", log_file)
        sys.exit(rc)

if __name__ == "__main__":
    main()
