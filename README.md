# synoscope

<img src="https://raw.githubusercontent.com/AnovumBV/synoscope/refs/heads/main/img/synoscope.png" width="20%" />

---

**Read‑only first‑aid for NAS recovery scenarios.**  

Quickly check recovery state over HTTP, optionally start Telnet, and generate a **RAID/disk overview** that helps you understand what’s safe to recover — before making any changes.

> **Author:** Mischa Rick van Geelen <m.vangeelen@anovum.nl> (Anovum BV) · **Version:** 1.0.0

---

## Features

- **HTTP checks** for recovery state.
- **Start Telnet** via device API (where available) and **auto‑login** as `root` using a date‑based password, with a sensible fallback.
- **Read‑only disk/RAID survey** from `lsblk`, `fdisk -l`, `blkid`, `mdadm --examine --scan`, `/proc/mdstat` (or `/prod/mdstat`), and `mdadm --detail`.
  - Clear level/state, member map **[UU_]**, tolerance, risk, progress; **bright RAID name highlight**.
  - Big **EXISTING RAID ARRAY(S) DETECTED** banner when arrays are found.
- **Mount check (ro)**: try `/dev/md0` → `/mnt/md0` and look for `.restore_to_default`.
- **Clear restore flag** via device API (where available).
- **Single IP prompt** at startup; actions reuse the same target.
- **Per‑run logs** in `~/.synoscope/logs/...`; `--debug` gives full I/O tracing.

> **Compatibility note:** Built around appliances that expose DSM‑style recovery endpoints (HTTP port 5000)

---

## Install

- **Python 3.8+** (works on 3.13+; contains a tiny Telnet fallback if `telnetlib` is missing)
- Optional (recommended):

```bash
pip install requests colorama
