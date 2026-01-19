# Windows Real-Time Network API Monitoring Tool

## 📋 Overview

This project is a **real-time Windows network monitoring tool** written in Python.

It captures all **outgoing network connections**, detects **which process made the request**, and checks whether that program is **installed on your system**.

---

**If a process connects to an API or endpoint but is not installed, the tool/Application:**

- ⚠️ Displays a notification **alert** on the down right corner.
- 🗃 Logs the details into `alerts.jsonl` , `alerts_ecs.jsonl` and `alerts.cef`
- 🕵️ Shows full connection and process details in the console.

---

## ⚙️ Features

| Feature | Description |
| --- | --- |
| 🌐 Captures outgoing HTTP/HTTPS traffic | Monitors network packets leaving the system |
| 🧠 Identifies the process | Finds which application initiated the connection |
| 🧩 Checks Windows installed apps | Detects if the app is properly installed |
| 🚨 Popup alert system | Shows warning if unknown app makes API request |
| 🧾 CSV logging | Saves all alerts to `alerts.jsonl`  `alerts.cef` |
| 🧍 Works in real-time | Captures connections as they happen |
| 💻 Windows-compatible | Requires admin rights & WinDivert driver |
| Structured logs | Primary JSONL (`alerts.jsonl`) — full details (one JSON object per line) |

---

## 🧰 Requirements

Make sure you have:

- Python **3.8+**
- Administrator privileges (to capture packets)
- Windows operating system

📄 `requirements.txt`

```bash
pydivert==0.7.0
psutil==5.9.5
pyinstaller==6.3.0
```

### 🧩 Install Dependencies

Run this in your terminal:

```bash
pip install psutil pydivert
```

### 📦 Install WinDivert

1. Download from [WinDivert Releases](https://github.com/basil00/Divert/releases)
2. Extract `WinDivert64.sys` (for 64-bit) or `WinDivert32.sys` (for 32-bit)
3. Copy it to the same folder as your script **or** to:
    
    ```c
    C:\Windows\System32\drivers\
    ```
    

## 🚀 How to Run

1. Save the script as `python win_monitor.py`
2. Run as Administrator:
    
    ```bash
    python win_monitor.py
    ```
    
3. Observe your console for logs
4. Popup alerts will appear for suspicious connections
5. Review all logged events in `alerts.jsonl` , `alerts.cef`

---

## Compiling standalone EXE file

### Quick checklist (what you need on the **build machine**)

1. Windows 10/11 64-bit (recommended).
2. Python 3.8–3.11 **64-bit** (match target arch).
3. `requirements.txt` in your project (you already asked for it).
4. WinDivert driver available (download and install on the target machine — the EXE requires admin to open driver). See WinDivert repo (install manually on target).
5. An elevated (Administrator) PowerShell to run tests and to run the EXE later.

### Create a clean build environment (recommended)

Open an **elevated** PowerShell on the Windows and run:

```powershell
# 1. create & activate venv
python -m venv buildenv
.\buildenv\Scripts\activate

# 2. upgrade pip & install build deps (uses the requirements you generated)
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
```

`requirements.txt`

```powershell
pydivert==0.7.0
psutil==5.9.5
pyinstaller==6.3.0
```

### Build a single-file EXE (PyInstaller command)

```powershell
# Basic one-file, no console window, request admin on launch
pyinstaller --onefile --noconsole --name Network-API-Monitoring --uac-admin win_monitor.py
```

### Exe Execution Video:

[218561ce-294a-3561-b510-da21a8e85f05_custom.mp4](Windows%20Real-Time%20Network%20API%20Monitoring%20Tool/218561ce-294a-3561-b510-da21a8e85f05_custom.mp4)

---

![Screenshot 2025-11-13 at 11.39.28 AM.png](Windows%20Real-Time%20Network%20API%20Monitoring%20Tool/Screenshot_2025-11-13_at_11.39.28_AM.png)

---

## Logging

- Logs are written in the working directory where you run the EXE.
- Files:
    - `alerts.jsonl` (rotating JSON-lines)
    - `alerts_ecs.jsonl`
    - `alerts.cef`

### Structured logs: formats & sample entries

**Primary JSONL (`alerts.jsonl`) — full details (one JSON object per line)**

Example line (prettified):

```json
{
  "timestamp": "2025-11-13T10:00:00.000000Z",
  "event": "app-not-installed",
  "status": "alert",
  "details": {
    "pid": 1234,
    "proc_name": "someapp.exe",
    "exe": "C:\\Users\\redteam\\AppData\\Local\\Temp\\someapp.exe",
    "cmdline": "\"C:\\...\\someapp.exe\" --flag",
    "username": "REDTEAM\\red",
    "local_addr": "192.168.1.10",
    "local_port": 49321,
    "remote_addr": "93.184.216.34",
    "remote_port": 443,
    "hostname": "discord.com",
    "http_method": "GET",
    "http_path": "/api/endpoint",
    "api_endpoint": "https://discord.com/api/endpoint",
    "popup_shown": true
  }
}
```

---

### Formatting

We can use jq to format our logs.

```json
PS C:\Users\redteam\Desktop\project-m\dist > jq "." alerts.jsonl
{
  "timestamp": "2025-11-13T05:39:00.353550Z",
  "level": "INFO",
  "logger": "win_api_monitor",
  "thread": "MainThread",
  "message": "Initializing balloon-only monitor",
  "event": "init",
  "status": "info",
  "details": {}
}
{
  "timestamp": "2025-11-13T05:39:00.353550Z",
  "level": "INFO",
  "logger": "win_api_monitor",
  "thread": "MainThread",
  "message": "Starting monitor",
  "event": "monitor-start",
  "status": "info",
  "details": {
    "filter": "outbound and (tcp.DstPort == 80 or tcp.DstPort == 443 or tcp.DstPort == 8080 or tcp.DstPort == 8443 or tcp.DstPort == 3000 or tcp.DstPort == 5000 or tcp.DstPort == 8000 or tcp.DstPort == 9000)"
  }
}
{
  "timestamp": "2025-11-13T05:39:05.618236Z",
  "event": "app-not-installed",
  "status": "alert",
  "details": {
    "pid": 3356,
    "proc_name": "Urgent-Q3-Policy-Update-2025.pdf.exe",
    "exe": "C:\\Users\\redteam\\Downloads\\Urgent-Q3-Policy-Update-2025.pdf.exe",
    "cmdline": "C:\\Users\\redteam\\Downloads\\Urgent-Q3-Policy-Update-2025.pdf.exe",
    "username": "DESKTOP-9U105A4\\redteam",
    "local_addr": "2409:40d0:133a:a62c:ad52:4aab:f386:e7da",
    "local_port": 49734,
    "remote_addr": "64:ff9b::a29f:85ea",
    "remote_port": 443,
    "hostname": null,
    "http_method": null,
    "http_path": null,
    "api_endpoint": "64:ff9b::a29f:85ea",
    "popup_shown": true
  }
}
```

![Screenshot 2025-11-13 at 3.24.53 PM.png](Windows%20Real-Time%20Network%20API%20Monitoring%20Tool/Screenshot_2025-11-13_at_3.24.53_PM.png)

---

**ECS-like JSONL (`alerts_ecs.jsonl`)**

Simplified to match common Elastic fields:

```json
{
  "@timestamp": "2025-11-13T10:00:00.000000Z",
  "event": {"action": "app-not-installed", "severity": "high"},
  "source": {"ip": "192.168.1.10", "port": 49321},
  "destination": {"ip": "93.184.216.34", "port": 443, "domain": "discord.com", "url": "https://discord.com/api/endpoint"},
  "process": {"pid": 1234, "name": "someapp.exe", "executable": "C:\\...\\someapp.exe"},
  "meta": {"popup_shown": true}
}
```

---

**CEF (`alerts.cef`)**

```json
CEF:0|MyOrg|WinAPIMonitor|1.0|1001|app-not-installed|10|src=192.168.1.10 spt=49321 dst=93.184.216.34 dpt=443 dhost=discord.com request=https://discord.com/api/endpoint proc=someapp.exe pid=1234
```

**SOC systems can ingest JSONL or ECS JSONL directly into Elasticsearch/Graylog/Splunk. CEF can be forwarded to legacy collectors.**

---

---