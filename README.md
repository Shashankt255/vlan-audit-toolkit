# VLAN Segmentation Audit Toolkit

**Automated VLAN segmentation testing for penetration testers and network auditors.**

![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-linux%20%7C%20windows%20%7C%20macos-lightgrey)

---

## Overview

VLAN segmentation is a foundational network security control that isolates traffic between zones — servers, users, management, DMZ, PCI, and IoT/OT networks. Misconfigured segmentation is one of the most common findings in network penetration tests and is a direct compliance requirement under **PCI-DSS** (Requirement 1), **HIPAA** (Technical Safeguards), **NIST 800-53** (SC-7), and **Zero Trust** architectures.

This toolkit automates the verification of VLAN segmentation from a tester's workstation. Given a set of target IP ranges representing different VLANs, it tests reachability via ICMP, TCP, and UDP; enumerates services; traces routes; passively sniffs for Layer 2 protocol leakage (CDP/LLDP/DTP); checks for management plane exposure; and compares results against a segmentation policy to highlight violations.

All scanning is **rate-limited** and **non-destructive** — no flooding, no CAM table overflow, no DTP spoofing, no DoS.

---

## Features

| Category | Capabilities |
|---|---|
| **Discovery** | ICMP sweep, ARP discovery (local subnet), DNS resolution |
| **Port Scanning** | TCP SYN/connect scan (top 100, top 1000, custom list, or all 65,535 ports), UDP scan |
| **Service Enumeration** | Banner grabbing, service identification, version detection on open ports |
| **Route Analysis** | Traceroute with TTL-based hop analysis, OS fingerprinting via TTL |
| **Layer 2 Checks** | CDP/LLDP/DTP passive sniffing, DHCP server discovery, broadcast leak detection |
| **Management Plane** | SSH, Telnet, HTTP/HTTPS, SNMP reachability to network infrastructure |
| **Policy Compliance** | Compare scan results against expected allow/deny policy (YAML) |
| **Reporting** | HTML (dark theme with reachability matrix), JSON, CSV export |
| **Risk Scoring** | Aggregate risk score (A–F) based on finding severity |
| **Scan Profiles** | Five speed presets: stealth, slow, medium, fast, insane |
| **Configuration** | YAML config files for complex multi-VLAN environments |

### Test Modules

| # | Module | Tests | Description |
|---|---|---|---|
| 1 | **Discovery** | ICMP sweep, ARP scan, DNS lookup | Host alive detection and initial reachability |
| 2 | **TCP Scan** | SYN/connect port scan | Full or selective TCP port enumeration |
| 3 | **UDP Scan** | UDP port scan | Top UDP ports with service detection |
| 4 | **Banner Grab** | Service ID, version detection | Banner collection on all open ports |
| 5 | **Traceroute** | Route tracing, hop analysis | Path analysis between VLANs |
| 6 | **VLAN Checks** | CDP/LLDP/DTP sniff, DHCP, broadcast | Layer 2 protocol leakage and misconfig |
| 7 | **Management** | SSH/Telnet/HTTP/SNMP sweep | Management plane exposure from test VLAN |
| 8 | **DNS Check** | Cross-VLAN DNS resolution | DNS reachability and zone transfer test |

---

## Quick Start

### Basic scan — single target range

```bash
sudo python3 vlan_audit.py -t 10.20.20.0/24
```

### Multiple target VLANs

```bash
sudo python3 vlan_audit.py -t 10.20.20.0/24 10.99.99.0/24 172.16.50.0/24
```

### Full 65,535 TCP port scan

```bash
sudo python3 vlan_audit.py -t 10.20.20.0/24 --full-ports
```

### Custom port list

```bash
sudo python3 vlan_audit.py -t 10.20.20.0/24 --ports 22,80,443,3389,445
```

### YAML config for complex environments

```bash
sudo python3 vlan_audit.py --config sample_config.yaml
```

### With segmentation policy check

```bash
sudo python3 vlan_audit.py --config sample_config.yaml --policy sample_policy.yaml
```

### Stealth mode (low rate, high delay)

```bash
sudo python3 vlan_audit.py -t 10.20.20.0/24 --speed stealth
```

### JSON + CSV export

```bash
sudo python3 vlan_audit.py -t 10.20.20.0/24 --json-output --csv-output
```

---

## Usage

```
usage: vlan_audit.py [-h] [-t TARGETS [TARGETS ...]] [--config CONFIG]
                     [--policy POLICY] [--source-vlan SOURCE_VLAN]
                     [--ports PORTS] [--full-ports] [--top-1000]
                     [--speed {stealth,slow,medium,fast,insane}]
                     [-m MODULES [MODULES ...]] [--skip-l2] [--skip-udp]
                     [--interface INTERFACE] [--timeout TIMEOUT]
                     [--json-output] [--csv-output] [-o OUTPUT_DIR] [-v]

VLAN Segmentation Audit Toolkit v1.0.0

options:
  -h, --help            show this help message and exit

Target:
  -t, --targets         Target IP ranges (CIDR notation)
  --config              YAML configuration file
  --policy              Segmentation policy YAML for compliance check
  --source-vlan         Source VLAN name (default: auto-detect)

Scan:
  --ports               Custom TCP port list (comma-separated)
  --full-ports          Scan all 65,535 TCP ports
  --top-1000            Scan top 1,000 TCP ports (default: top 100)
  --speed               Scan speed profile (default: medium)
  -m, --modules         Run specific modules only
  --skip-l2             Skip Layer 2 checks (CDP/LLDP/DTP/DHCP)
  --skip-udp            Skip UDP scanning
  --interface            Network interface for Layer 2 sniffing
  --timeout             Per-probe timeout in seconds

Output:
  --json-output         Also generate JSON report
  --csv-output          Also generate CSV report
  -o, --output-dir      Output directory (default: ./reports)
  -v, --verbose         Verbose output
```

---

## Configuration

### YAML Config File

For environments with multiple VLANs, use a YAML config file instead of CLI arguments. See `sample_config.yaml` for a full example.

```yaml
source_vlan:
  name: "User VLAN"
  vlan_id: 10
  subnet: "10.10.10.0/24"
  gateway: "10.10.10.1"

targets:
  - name: "Server VLAN"
    vlan_id: 20
    ranges:
      - "10.20.20.0/24"
    critical_hosts:
      - ip: "10.20.20.10"
        role: "Database Server"

scan_speed: "medium"
```

The config file lets you:
- Name each VLAN for readable reports
- Tag VLAN IDs for correlation
- Specify critical hosts that get highlighted in findings
- Define custom port lists per environment
- Set scan speed globally

---

## Segmentation Policy

Define your expected segmentation policy in YAML and the tool will compare actual scan results against it. See `sample_policy.yaml`.

```yaml
rules:
  - src_vlan: "User VLAN"
    dst_vlan: "Server VLAN"
    action: "deny"
    ports: [22, 3389, 445, 1433, 3306]
    description: "Users must not reach management/DB ports"
```

**Policy violations** are flagged as HIGH/CRITICAL findings:
- **deny + port open** = CRITICAL violation — traffic flows where it should not
- **allow + port closed** = INFO — expected service unavailable (may be operational)
- **no rule defined** = WARN — unaudited path, needs policy review

---

## Reports

### HTML Report

The HTML report includes:
- **Executive Summary** — total hosts, open ports, risk score (A–F)
- **Reachability Matrix** — grid showing which VLANs can reach which, with port counts
- **Per-Host Details** — open ports, services, banners, OS guess, traceroute hops
- **Findings Table** — all segmentation issues with severity, observation, remediation
- **Policy Violations** — expected vs. actual comparison (when policy YAML is provided)
- **Traceroute Map** — hop-by-hop path visualization between VLANs
- **Module Timing** — execution time per module

### JSON Report

Machine-readable output with full scan data, findings, host results, and metadata. Suitable for integration with SIEM, ticketing, or custom dashboards.

### CSV Report

Flat finding export for spreadsheet analysis or bulk import into GRC platforms.

---

## Architecture

```
vlan-audit-toolkit/
├── vlan_audit.py              # Main CLI orchestrator
├── config.py                  # Constants, port databases, speed profiles
├── modules/
│   ├── __init__.py
│   ├── base.py                # BaseModule, HostResult, PortResult, Finding
│   ├── discovery.py           # ICMP sweep, ARP scan, DNS resolution
│   ├── tcp_scan.py            # TCP SYN/connect port scanner
│   ├── udp_scan.py            # UDP port scanner
│   ├── banner_grab.py         # Banner grabbing, service identification
│   ├── traceroute.py          # Traceroute with hop analysis
│   ├── vlan_checks.py         # CDP/LLDP/DTP sniff, DHCP, broadcast
│   ├── management_check.py    # Management plane exposure testing
│   └── dns_check.py           # Cross-VLAN DNS resolution testing
├── reporting/
│   ├── __init__.py
│   └── html_report.py         # HTML, JSON, CSV report generators
├── sample_config.yaml         # Example YAML configuration
├── sample_policy.yaml         # Example segmentation policy
├── requirements.txt           # Python dependencies
├── run.sh                     # Linux/macOS launcher
├── run.bat                    # Windows launcher
├── LICENSE                    # MIT License
└── README.md
```

---

## Requirements

- **Python 3.8+**
- **Root/Administrator privileges** recommended for:
  - ICMP echo (raw sockets)
  - ARP discovery (raw sockets)
  - SYN scanning (raw sockets)
  - CDP/LLDP/DTP passive sniffing (promiscuous mode)
  - DHCP discovery (raw sockets)
- Works without root using TCP connect scan and limited features

### Dependencies

```
scapy>=2.5.0      # Packet crafting, L2/L3 scanning
rich>=13.7.0       # Terminal UI, progress bars, tables
jinja2>=3.1.3      # HTML report templating
pyyaml>=6.0.1      # YAML configuration parsing
```

---

## Installation

```bash
git clone https://github.com/Shashankt255/vlan-audit-toolkit.git
cd vlan-audit-toolkit
pip install -r requirements.txt
```

### Linux/macOS

```bash
chmod +x run.sh
sudo ./run.sh -t 10.20.20.0/24
```

### Windows (Administrator)

```cmd
run.bat -t 10.20.20.0/24
```

---

## Safety

This tool is designed for **authorized penetration testing** and network audits. It includes the following safety controls:

| Control | Description |
|---|---|
| **Rate limiting** | All probes are rate-limited per scan speed profile |
| **No flooding** | No SYN flood, no UDP flood, no ICMP flood |
| **No CAM overflow** | No MAC flooding or CAM table attacks |
| **No DTP spoofing** | CDP/LLDP/DTP are passively sniffed, never injected |
| **No VLAN hopping** | No double-tagging or trunk negotiation attacks |
| **No exploitation** | Discovery and enumeration only — no exploit payloads |
| **No DoS** | Configurable speed prevents bandwidth saturation |
| **Read-only** | No modifications to network device configurations |

---

## Disclaimer

**This tool is intended for authorized security testing only.** Unauthorized scanning of networks you do not own or have explicit written permission to test is illegal in most jurisdictions. The authors assume no liability for misuse.

Always obtain proper written authorization before running this tool. Coordinate with network operations teams to avoid disruption.

---

## Related Tools

| Tool | What it does |
|---|---|
| [**GLASSCAGE**](https://github.com/Shashankt255/glasscage) | LLM & agentic AI security assessment — OWASP LLM Top 10 probes, AI Attack Knowledge Graph, evidence-backed reports |
| [**AD Audit Toolkit**](https://github.com/Shashankt255/ad-audit-toolkit) | Active Directory security assessment — 93 test cases, 15 modules, MITRE ATT&CK mapping, attack path analysis |

## Author

**Shashankt255** — [GitHub](https://github.com/Shashankt255)

## License

MIT License — see [LICENSE](LICENSE) for details.
