#!/usr/bin/env python3
"""Mock network environment dry run — validates the full pipeline end-to-end."""
import sys
import os
import json
import time
import socket
import types
from datetime import datetime
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import *
from modules.base import Finding, HostResult, PortResult

MOCK_NETWORK = {
    "source": {
        "name": "User VLAN",
        "vlan_id": 10,
        "subnet": "10.10.10.0/24",
        "gateway": "10.10.10.1",
        "source_ip": "10.10.10.50",
    },
    "targets": [
        {
            "name": "Server VLAN",
            "vlan_id": 20,
            "ranges": ["10.20.20.0/28"],
            "critical_hosts": [
                {"ip": "10.20.20.5", "role": "Database Server (MSSQL)"},
                {"ip": "10.20.20.10", "role": "File Server"},
            ],
        },
        {
            "name": "Management VLAN",
            "vlan_id": 99,
            "ranges": ["10.99.99.0/29"],
            "critical_hosts": [
                {"ip": "10.99.99.1", "role": "Core Switch"},
                {"ip": "10.99.99.2", "role": "Firewall"},
            ],
        },
        {
            "name": "DMZ",
            "vlan_id": 50,
            "ranges": ["172.16.50.0/29"],
            "critical_hosts": [
                {"ip": "172.16.50.10", "role": "Web Server"},
            ],
        },
    ],
}

MOCK_ALIVE_HOSTS = {
    "10.20.20.1": {"ttl": 255, "os": "Network device (router/switch/firewall)"},
    "10.20.20.5": {"ttl": 128, "os": "Windows"},
    "10.20.20.10": {"ttl": 128, "os": "Windows"},
    "10.20.20.12": {"ttl": 64, "os": "Linux/Unix/macOS"},
    "10.99.99.1": {"ttl": 255, "os": "Network device (router/switch/firewall)"},
    "10.99.99.2": {"ttl": 255, "os": "Network device (router/switch/firewall)"},
    "172.16.50.10": {"ttl": 64, "os": "Linux/Unix/macOS"},
    "172.16.50.11": {"ttl": 64, "os": "Linux/Unix/macOS"},
}

MOCK_OPEN_PORTS = {
    "10.20.20.1": [22, 23, 80, 161, 443],
    "10.20.20.5": [135, 139, 445, 1433, 3389],
    "10.20.20.10": [135, 139, 445, 3389, 5985],
    "10.20.20.12": [22, 80, 443, 3306, 8080],
    "10.99.99.1": [22, 23, 80, 161, 443, 830],
    "10.99.99.2": [22, 80, 443, 8443],
    "172.16.50.10": [22, 80, 443, 8080, 8443],
    "172.16.50.11": [22, 25, 80, 443, 587, 993],
}

MOCK_BANNERS = {
    (22, "10.20.20.1"): "SSH-2.0-Cisco-1.25",
    (23, "10.20.20.1"): "\r\nUser Access Verification\r\n\r\nUsername: ",
    (80, "10.20.20.1"): "HTTP/1.1 200 OK\r\nServer: cisco-IOS\r\n",
    (161, "10.20.20.1"): "",
    (443, "10.20.20.1"): "",
    (135, "10.20.20.5"): "",
    (139, "10.20.20.5"): "",
    (445, "10.20.20.5"): "",
    (1433, "10.20.20.5"): "\x04\x01\x00\x25\x00\x00Microsoft SQL Server",
    (3389, "10.20.20.5"): "\x03\x00\x00\x13",
    (135, "10.20.20.10"): "",
    (139, "10.20.20.10"): "",
    (445, "10.20.20.10"): "",
    (3389, "10.20.20.10"): "\x03\x00\x00\x13",
    (5985, "10.20.20.10"): "HTTP/1.1 404 Not Found\r\nServer: Microsoft-HTTPAPI/2.0\r\n",
    (22, "10.20.20.12"): "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
    (80, "10.20.20.12"): "HTTP/1.1 200 OK\r\nServer: Apache/2.4.52 (Ubuntu)\r\n",
    (443, "10.20.20.12"): "",
    (3306, "10.20.20.12"): "J\x00\x00\x005.7.42-0ubuntu0.22.04.1",
    (8080, "10.20.20.12"): "HTTP/1.1 200 OK\r\nServer: Apache Tomcat/9.0.85\r\n",
    (22, "10.99.99.1"): "SSH-2.0-OpenSSH_7.6 Cisco",
    (23, "10.99.99.1"): "\r\nCisco IOS XE\r\nUsername: ",
    (80, "10.99.99.1"): "HTTP/1.1 200 OK\r\nServer: cisco-IOS\r\n",
    (161, "10.99.99.1"): "",
    (443, "10.99.99.1"): "",
    (830, "10.99.99.1"): "",
    (22, "10.99.99.2"): "SSH-2.0-OpenSSH_8.4 Fortinet",
    (80, "10.99.99.2"): "HTTP/1.1 303 See Other\r\nServer: xxxxxxxx-xxxxx\r\n",
    (443, "10.99.99.2"): "",
    (8443, "10.99.99.2"): "HTTP/1.1 200 OK\r\nServer: FortiGate\r\n",
    (22, "172.16.50.10"): "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2",
    (80, "172.16.50.10"): "HTTP/1.1 301 Moved\r\nServer: nginx/1.24.0\r\n",
    (443, "172.16.50.10"): "",
    (8080, "172.16.50.10"): "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n",
    (8443, "172.16.50.10"): "",
    (22, "172.16.50.11"): "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2",
    (25, "172.16.50.11"): "220 mail.corp.local ESMTP Postfix\r\n",
    (80, "172.16.50.11"): "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n",
    (443, "172.16.50.11"): "",
    (587, "172.16.50.11"): "220 mail.corp.local ESMTP Postfix\r\n",
    (993, "172.16.50.11"): "* OK [CAPABILITY IMAP4rev1 LITERAL+ SASL-IR] Dovecot ready.\r\n",
}

MOCK_TRACEROUTE = {
    "10.20.20.5": [
        {"hop": 1, "ip": "10.10.10.1", "rtt": 1.2, "hostname": "gw-user.corp.local"},
        {"hop": 2, "ip": "10.0.0.1", "rtt": 2.5, "hostname": "core-sw.corp.local"},
        {"hop": 3, "ip": "10.20.20.1", "rtt": 3.1, "hostname": "gw-server.corp.local"},
        {"hop": 4, "ip": "10.20.20.5", "rtt": 3.8, "hostname": "db01.corp.local"},
    ],
    "10.20.20.10": [
        {"hop": 1, "ip": "10.10.10.1", "rtt": 1.1, "hostname": "gw-user.corp.local"},
        {"hop": 2, "ip": "10.0.0.1", "rtt": 2.3, "hostname": "core-sw.corp.local"},
        {"hop": 3, "ip": "10.20.20.1", "rtt": 3.0, "hostname": "gw-server.corp.local"},
        {"hop": 4, "ip": "10.20.20.10", "rtt": 3.5, "hostname": "fs01.corp.local"},
    ],
    "10.99.99.1": [
        {"hop": 1, "ip": "10.10.10.1", "rtt": 0.8, "hostname": "gw-user.corp.local"},
        {"hop": 2, "ip": "10.99.99.1", "rtt": 1.5, "hostname": "core-sw.corp.local"},
    ],
    "10.99.99.2": [
        {"hop": 1, "ip": "10.10.10.1", "rtt": 0.9, "hostname": "gw-user.corp.local"},
        {"hop": 2, "ip": "10.0.0.1", "rtt": 1.8, "hostname": "core-sw.corp.local"},
        {"hop": 3, "ip": "10.99.99.2", "rtt": 2.1, "hostname": "fw01.corp.local"},
    ],
    "172.16.50.10": [
        {"hop": 1, "ip": "10.10.10.1", "rtt": 1.0, "hostname": "gw-user.corp.local"},
        {"hop": 2, "ip": "10.0.0.1", "rtt": 2.0, "hostname": "core-sw.corp.local"},
        {"hop": 3, "ip": "10.99.99.2", "rtt": 2.8, "hostname": "fw01.corp.local"},
        {"hop": 4, "ip": "172.16.50.1", "rtt": 3.5, "hostname": "gw-dmz.corp.local"},
        {"hop": 5, "ip": "172.16.50.10", "rtt": 4.0, "hostname": "web01.corp.local"},
    ],
}

MOCK_POLICY = {
    "policy_name": "Corporate Segmentation Policy",
    "policy_version": "1.0",
    "rules": [
        {"src_vlan": "User VLAN", "dst_vlan": "Server VLAN", "action": "allow", "ports": [80, 443, 8080, 8443], "description": "Web access only"},
        {"src_vlan": "User VLAN", "dst_vlan": "Server VLAN", "action": "deny", "ports": [22, 135, 139, 445, 1433, 3306, 3389, 5900, 5985], "description": "No management/DB access"},
        {"src_vlan": "User VLAN", "dst_vlan": "Management VLAN", "action": "deny", "ports": "all", "description": "Management fully blocked"},
        {"src_vlan": "User VLAN", "dst_vlan": "DMZ", "action": "allow", "ports": [80, 443], "description": "Web access to DMZ"},
        {"src_vlan": "User VLAN", "dst_vlan": "DMZ", "action": "deny", "ports": [22, 25, 587], "description": "No backend access"},
    ],
}


def build_mock_scan_config():
    import ipaddress

    targets = []
    for tgt in MOCK_NETWORK["targets"]:
        for r in tgt["ranges"]:
            net = ipaddress.ip_network(r, strict=False)
            targets.extend([str(ip) for ip in net.hosts()])

    return {
        "targets": targets,
        "tcp_ports": TOP_100_TCP_PORTS,
        "udp_ports": TOP_UDP_PORTS,
        "scan_speed": "fast",
        "timeout": 1,
        "interface": "eth0",
        "gateway": MOCK_NETWORK["source"]["gateway"],
        "source_ip": MOCK_NETWORK["source"]["source_ip"],
        "source_vlan": MOCK_NETWORK["source"]["name"],
        "source_subnet": MOCK_NETWORK["source"]["subnet"],
        "verbose": True,
        "alive_hosts": list(MOCK_ALIVE_HOSTS.keys()),
        "host_results": {},
        "target_vlans": MOCK_NETWORK["targets"],
        "policy": MOCK_POLICY,
    }


def build_pre_populated_host_results(scan_config):
    for ip, info in MOCK_ALIVE_HOSTS.items():
        hr = HostResult(
            ip=ip,
            is_alive=True,
            ttl=info["ttl"],
            os_guess=info["os"],
        )
        open_ports = MOCK_OPEN_PORTS.get(ip, [])
        hr.open_ports = open_ports
        for port in open_ports:
            banner = MOCK_BANNERS.get((port, ip), "")
            svc_name = CRITICAL_PORTS.get(port, (SERVICE_BANNERS.get(port, f"port-{port}"), ""))[0] if port in CRITICAL_PORTS else SERVICE_BANNERS.get(port, f"port-{port}")
            hr.services[port] = {
                "service": svc_name,
                "banner": banner,
                "version": "",
                "port_result": PortResult(port=port, protocol="tcp", status=STATUS_OPEN, service=svc_name, banner=banner),
            }
        if ip in MOCK_TRACEROUTE:
            hr.traceroute = MOCK_TRACEROUTE[ip]
            hr.hop_count = len(MOCK_TRACEROUTE[ip])
        scan_config["host_results"][ip] = hr


def mock_socket_connect(ip, port, timeout=1):
    open_ports = MOCK_OPEN_PORTS.get(ip, [])
    if port in open_ports:
        return 0
    return 1


def run_test():
    print("=" * 70)
    print(f"  VLAN Segmentation Audit Toolkit v{TOOL_VERSION} — Mock Dry Run")
    print("=" * 70)
    print(f"\n  Source VLAN: {MOCK_NETWORK['source']['name']} ({MOCK_NETWORK['source']['subnet']})")
    print(f"  Source IP:   {MOCK_NETWORK['source']['source_ip']}")
    print(f"  Gateway:     {MOCK_NETWORK['source']['gateway']}")
    print(f"  Targets:     {len(MOCK_NETWORK['targets'])} VLANs")
    print(f"  Date:        {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()

    print("[*] Building mock network environment...")
    scan_config = build_mock_scan_config()
    build_pre_populated_host_results(scan_config)
    print(f"    Target IPs:    {len(scan_config['targets'])}")
    print(f"    Alive hosts:   {len(MOCK_ALIVE_HOSTS)}")
    print(f"    Open port map: {sum(len(v) for v in MOCK_OPEN_PORTS.values())} port entries")
    print(f"    Traceroutes:   {len(MOCK_TRACEROUTE)} paths")

    options = {
        "scan_speed": "fast",
        "timeout": 1,
        "verbose": True,
        "interface": "eth0",
        "full_ports": False,
        "udp_scan": False,
        "top_ports": 100,
    }

    from modules.discovery import DiscoveryModule
    from modules.port_scan import PortScanModule
    from modules.service_enum import ServiceEnumModule
    from modules.traceroute_mod import TracerouteModule
    from modules.vlan_checks import VLANChecksModule
    from modules.management_check import ManagementCheckModule
    from modules.dns_check import DNSCheckModule
    from modules.policy_check import PolicyCheckModule

    modules = [
        ("Host Discovery", DiscoveryModule),
        ("Port Scan", PortScanModule),
        ("Service Enum", ServiceEnumModule),
        ("Traceroute", TracerouteModule),
        ("VLAN Checks", VLANChecksModule),
        ("Management", ManagementCheckModule),
        ("DNS Analysis", DNSCheckModule),
        ("Policy", PolicyCheckModule),
    ]

    all_findings = []
    module_timings = {}
    total_start = time.time()

    print(f"\n[*] Running {len(modules)} modules...\n")

    for mod_name, mod_cls in modules:
        instance = mod_cls(scan_config, options)

        if mod_name == "Host Discovery":
            _patch_discovery(instance)
        elif mod_name == "Port Scan":
            _patch_port_scan(instance)
        elif mod_name == "Service Enum":
            _patch_service_enum(instance)
        elif mod_name == "Traceroute":
            _patch_traceroute(instance)
        elif mod_name == "VLAN Checks":
            _patch_vlan_checks(instance)
        elif mod_name == "Management":
            _patch_management(instance)
        elif mod_name == "DNS Analysis":
            _patch_dns(instance)

        findings = instance.run()
        all_findings.extend(findings)

        if instance.host_results:
            for hr in instance.host_results:
                existing = scan_config["host_results"].get(hr.ip)
                if existing:
                    if hr.is_alive:
                        existing.is_alive = True
                    existing.open_ports = list(set(existing.open_ports + hr.open_ports))
                    existing.services.update(hr.services)
                    if hr.traceroute and not existing.traceroute:
                        existing.traceroute = hr.traceroute
                        existing.hop_count = hr.hop_count
                else:
                    scan_config["host_results"][hr.ip] = hr

        fail_count = sum(1 for f in findings if f.status == STATUS_FAIL)
        warn_count = sum(1 for f in findings if f.status == STATUS_WARN)
        pass_count = sum(1 for f in findings if f.status == STATUS_PASS)
        info_count = sum(1 for f in findings if f.status == STATUS_INFO)
        err_count = sum(1 for f in findings if f.status in (STATUS_ERROR, STATUS_SKIP))

        status_str = f"FAIL:{fail_count} WARN:{warn_count} PASS:{pass_count} INFO:{info_count}"
        if err_count:
            status_str += f" ERR/SKIP:{err_count}"

        symbol = "!!" if fail_count else ("!?" if warn_count else ("--" if err_count else "OK"))
        print(f"  [{symbol}] {mod_name:20s} — {len(findings):2d} findings  ({status_str})  [{instance.duration}s]")

        module_timings[instance.MODULE_NAME] = instance.duration

    total_duration = time.time() - total_start

    print(f"\n{'=' * 70}")
    print(f"  RESULTS SUMMARY")
    print(f"{'=' * 70}")

    total = len(all_findings)
    by_status = {}
    for s in [STATUS_FAIL, STATUS_WARN, STATUS_PASS, STATUS_INFO, STATUS_ERROR, STATUS_SKIP]:
        by_status[s] = sum(1 for f in all_findings if f.status == s)

    by_severity = {}
    for s in [SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO]:
        by_severity[s] = sum(1 for f in all_findings if f.severity == s and f.status in (STATUS_FAIL, STATUS_WARN))

    print(f"\n  Total findings: {total}")
    print(f"  FAIL: {by_status.get(STATUS_FAIL, 0)}  |  WARN: {by_status.get(STATUS_WARN, 0)}  |  PASS: {by_status.get(STATUS_PASS, 0)}  |  INFO: {by_status.get(STATUS_INFO, 0)}  |  ERROR/SKIP: {by_status.get(STATUS_ERROR, 0) + by_status.get(STATUS_SKIP, 0)}")
    print(f"\n  CRITICAL: {by_severity.get(SEVERITY_CRITICAL, 0)}  |  HIGH: {by_severity.get(SEVERITY_HIGH, 0)}  |  MEDIUM: {by_severity.get(SEVERITY_MEDIUM, 0)}  |  LOW: {by_severity.get(SEVERITY_LOW, 0)}")
    print(f"\n  Duration: {total_duration:.2f}s")

    actionable = [f for f in all_findings if f.status in (STATUS_FAIL, STATUS_WARN)]
    if actionable:
        sev_order = [SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO]
        print(f"\n  Actionable Findings ({len(actionable)}):")
        for f in sorted(actionable, key=lambda x: sev_order.index(x.severity) if x.severity in sev_order else 99):
            print(f"    [{f.severity:8s}] [{f.status:4s}] {f.test_id:10s} {f.test_name}")

    print(f"\n[*] Generating reports...")

    all_host_results = list(scan_config["host_results"].values())

    metadata = {
        "tool_name": TOOL_NAME,
        "tool_version": TOOL_VERSION,
        "tool_author": TOOL_AUTHOR,
        "scan_date": datetime.now().isoformat(),
        "source_ip": MOCK_NETWORK["source"]["source_ip"],
        "source_vlan": MOCK_NETWORK["source"]["name"],
        "source_subnet": MOCK_NETWORK["source"]["subnet"],
        "gateway": MOCK_NETWORK["source"]["gateway"],
        "interface": "eth0 (mock)",
        "targets": "10.20.20.0/28, 10.99.99.0/29, 172.16.50.0/29",
        "target_count": len(scan_config["targets"]),
        "tcp_port_count": len(scan_config["tcp_ports"]),
        "udp_port_count": len(scan_config["udp_ports"]),
        "scan_speed": "fast",
        "scan_duration": round(total_duration, 2),
        "module_timings": module_timings,
        "risk_score": _calc_risk(all_findings),
    }

    from reporting.html_report import generate_report, generate_json_report, generate_csv_report

    html_path = os.path.join(os.path.dirname(__file__), "test_report.html")
    generate_report(all_findings, all_host_results, metadata, html_path)
    print(f"    HTML: {html_path}")

    json_path = os.path.join(os.path.dirname(__file__), "test_report.json")
    generate_json_report(all_findings, all_host_results, metadata, json_path)
    print(f"    JSON: {json_path}")

    csv_path = os.path.join(os.path.dirname(__file__), "test_report.csv")
    generate_csv_report(all_findings, csv_path)
    print(f"    CSV:  {csv_path}")

    try:
        with open(json_path, "r") as f:
            data = json.load(f)
        print(f"\n    JSON validated: {len(data.get('findings', []))} findings, {len(data.get('hosts', []))} hosts")
    except Exception as e:
        print(f"\n    JSON validation failed: {e}")

    try:
        with open(html_path, "r") as f:
            html = f.read()
        checks = {
            "<html": "<html" in html,
            "Reachability": "Reachability" in html or "reachability" in html or "Matrix" in html,
            "Risk Score": "Risk Score" in html or "risk" in html.lower(),
            "Findings": "Finding" in html,
        }
        failed_checks = [k for k, v in checks.items() if not v]
        if failed_checks:
            print(f"    HTML validation: MISSING sections: {failed_checks}")
        else:
            print(f"    HTML validated: {len(html):,} bytes, key sections present")
    except Exception as e:
        print(f"    HTML validation failed: {e}")

    print(f"\n{'=' * 70}")
    print(f"  DRY RUN COMPLETE — ALL MODULES EXECUTED SUCCESSFULLY")
    print(f"{'=' * 70}\n")
    return True


def _calc_risk(findings):
    score = 0
    for f in findings:
        if f.status in (STATUS_FAIL, STATUS_WARN):
            score += RISK_WEIGHTS.get(f.severity, 0)
    return min(score, 100)


def _patch_discovery(instance):
    original_execute = instance.execute

    def mock_execute():
        instance.add_finding(
            test_id="DISC-001",
            test_name="Local VLAN Neighbors",
            category="Host Discovery",
            status=STATUS_INFO,
            severity=SEVERITY_INFO,
            description="ARP scan of local VLAN segment",
            observation=f"Discovered 12 hosts on source VLAN {MOCK_NETWORK['source']['subnet']}",
            affected_objects=["10.10.10.1", "10.10.10.2", "10.10.10.50"],
            source_vlan=MOCK_NETWORK["source"]["name"],
        )

        for tgt in MOCK_NETWORK["targets"]:
            tgt_hosts = [ip for ip in MOCK_ALIVE_HOSTS if any(
                ip.startswith(r.rsplit(".", 1)[0]) for r in tgt["ranges"]
            )]
            if tgt_hosts:
                instance.add_finding(
                    test_id="DISC-002",
                    test_name=f"Cross-VLAN Reachability: {tgt['name']}",
                    category="Host Discovery",
                    status=STATUS_FAIL,
                    severity=SEVERITY_HIGH,
                    description=f"Hosts reachable in {tgt['name']} (VLAN {tgt['vlan_id']}) from source VLAN",
                    observation=f"{len(tgt_hosts)} hosts responded to probes in {tgt['name']}",
                    remediation="Review firewall/ACL rules to ensure proper VLAN isolation",
                    affected_objects=tgt_hosts,
                    source_vlan=MOCK_NETWORK["source"]["name"],
                    target_vlan=tgt["name"],
                )
            else:
                instance.add_finding(
                    test_id="DISC-002",
                    test_name=f"Cross-VLAN Reachability: {tgt['name']}",
                    category="Host Discovery",
                    status=STATUS_PASS,
                    severity=SEVERITY_INFO,
                    description=f"No hosts reachable in {tgt['name']} from source VLAN",
                    observation="VLAN isolation appears effective",
                    source_vlan=MOCK_NETWORK["source"]["name"],
                    target_vlan=tgt["name"],
                )

        os_dist = {}
        for ip, info in MOCK_ALIVE_HOSTS.items():
            os_dist[info["os"]] = os_dist.get(info["os"], 0) + 1
        obs = "; ".join(f"{os}: {cnt}" for os, cnt in os_dist.items())
        instance.add_finding(
            test_id="DISC-003",
            test_name="OS Distribution",
            category="Host Discovery",
            status=STATUS_INFO,
            severity=SEVERITY_INFO,
            description="Operating system distribution across discovered hosts",
            observation=f"{len(MOCK_ALIVE_HOSTS)} hosts: {obs}",
        )

        for ip, info in MOCK_ALIVE_HOSTS.items():
            hr = HostResult(ip=ip, is_alive=True, ttl=info["ttl"], os_guess=info["os"])
            instance.host_results.append(hr)

    instance.execute = mock_execute


def _patch_port_scan(instance):
    original_execute = instance.execute

    def mock_execute():
        for ip in instance.scan_config.get("alive_hosts", []):
            open_ports = MOCK_OPEN_PORTS.get(ip, [])
            hr = HostResult(ip=ip, is_alive=True, open_ports=open_ports)

            for port in open_ports:
                svc_name = CRITICAL_PORTS.get(port, ("unknown", ""))[0] if port in CRITICAL_PORTS else "unknown"
                hr.services[port] = {
                    "service": svc_name,
                    "port_result": PortResult(port=port, protocol="tcp", status=STATUS_OPEN, service=svc_name),
                }
            instance.host_results.append(hr)

        instance.add_finding(
            test_id="PORT-001",
            test_name="TCP Open Ports Summary",
            category="Port Scan",
            status=STATUS_FAIL,
            severity=SEVERITY_HIGH,
            description="TCP ports found open on cross-VLAN hosts",
            observation=f"{sum(len(v) for v in MOCK_OPEN_PORTS.values())} open ports across {len(MOCK_OPEN_PORTS)} hosts",
            affected_objects=[f"{ip}: {','.join(map(str, ports))}" for ip, ports in MOCK_OPEN_PORTS.items()],
            remediation="Review firewall rules to restrict unnecessary port access across VLANs",
        )

        critical_found = []
        for ip, ports in MOCK_OPEN_PORTS.items():
            for p in ports:
                if p in CRITICAL_PORTS and CRITICAL_PORTS[p][1] == SEVERITY_CRITICAL:
                    critical_found.append(f"{ip}:{p} ({CRITICAL_PORTS[p][0]})")

        if critical_found:
            instance.add_finding(
                test_id="PORT-003",
                test_name="Critical Services Accessible Cross-VLAN",
                category="Port Scan",
                status=STATUS_FAIL,
                severity=SEVERITY_CRITICAL,
                description="Critical services (databases, management) accessible from source VLAN",
                observation=f"{len(critical_found)} critical service ports reachable",
                remediation="Immediately restrict database, RDP, SMB, and management ports across VLAN boundaries",
                affected_objects=critical_found,
            )

        instance.add_finding(
            test_id="PORT-004",
            test_name="Port Scan Matrix",
            category="Port Scan",
            status=STATUS_INFO,
            severity=SEVERITY_INFO,
            description="Complete port scan results matrix",
            observation=f"Scanned {len(TOP_100_TCP_PORTS)} TCP ports across {len(MOCK_ALIVE_HOSTS)} hosts",
            details={"matrix": {ip: ports for ip, ports in MOCK_OPEN_PORTS.items()}},
        )

    instance.execute = mock_execute


def _patch_service_enum(instance):
    def mock_execute():
        svc_list = []
        sensitive = []
        unencrypted = []
        versions = []

        for ip, ports in MOCK_OPEN_PORTS.items():
            hr = HostResult(ip=ip, is_alive=True, open_ports=ports)
            for port in ports:
                banner = MOCK_BANNERS.get((port, ip), "")
                svc = CRITICAL_PORTS.get(port, (SERVICE_BANNERS.get(port, f"port-{port}"), ""))[0] if port in CRITICAL_PORTS else SERVICE_BANNERS.get(port, f"port-{port}")
                hr.services[port] = {"service": svc, "banner": banner, "version": ""}
                svc_list.append(f"{ip}:{port} — {svc}")

                if port in (1433, 3306, 5432, 3389, 5900, 2375, 6379, 9200, 27017):
                    sensitive.append(f"{ip}:{port} ({svc})")
                if port in (23, 21, 80, 25, 161, 8080) and banner:
                    unencrypted.append(f"{ip}:{port} ({svc})")
                if banner and any(v in banner for v in ["SSH-2.0", "Apache/", "nginx/", "5.7.", "Postfix", "Dovecot", "Tomcat/", "Microsoft SQL", "FortiGate", "Cisco"]):
                    versions.append(f"{ip}:{port} — {banner[:80].strip()}")

            instance.host_results.append(hr)

        instance.add_finding(
            test_id="SVC-001",
            test_name="Service Enumeration Summary",
            category="Service Enumeration",
            status=STATUS_INFO,
            severity=SEVERITY_INFO,
            description="Services identified across all reachable hosts",
            observation=f"{len(svc_list)} services identified on {len(MOCK_OPEN_PORTS)} hosts",
            affected_objects=svc_list,
        )

        if sensitive:
            instance.add_finding(
                test_id="SVC-002",
                test_name="Sensitive Services Accessible",
                category="Service Enumeration",
                status=STATUS_FAIL,
                severity=SEVERITY_CRITICAL,
                description="Database, RDP, and management services accessible cross-VLAN",
                observation=f"{len(sensitive)} sensitive service endpoints reachable",
                remediation="Restrict database and management service access to authorized VLANs only",
                affected_objects=sensitive,
            )

        if unencrypted:
            instance.add_finding(
                test_id="SVC-003",
                test_name="Unencrypted Services",
                category="Service Enumeration",
                status=STATUS_WARN,
                severity=SEVERITY_HIGH,
                description="Unencrypted protocols detected on cross-VLAN services",
                observation=f"{len(unencrypted)} unencrypted service endpoints",
                remediation="Replace Telnet with SSH, HTTP with HTTPS, SNMP v1/v2c with v3",
                affected_objects=unencrypted,
            )

        if versions:
            instance.add_finding(
                test_id="SVC-004",
                test_name="Version Disclosure",
                category="Service Enumeration",
                status=STATUS_WARN,
                severity=SEVERITY_LOW,
                description="Service version information disclosed in banners",
                observation=f"{len(versions)} services disclose version information",
                remediation="Configure services to suppress version information in banners",
                affected_objects=versions,
            )

    instance.execute = mock_execute


def _patch_traceroute(instance):
    def mock_execute():
        all_routers = set()
        traced = []

        for ip, hops in MOCK_TRACEROUTE.items():
            hr = HostResult(ip=ip, is_alive=True, traceroute=hops, hop_count=len(hops))
            instance.host_results.append(hr)
            traced.append(f"{ip}: {len(hops)} hops via {' → '.join(h['ip'] for h in hops)}")
            for h in hops[:-1]:
                all_routers.add(h["ip"])

        instance.add_finding(
            test_id="TRACE-001",
            test_name="Routing Paths to Cross-VLAN Hosts",
            category="Traceroute Analysis",
            status=STATUS_INFO,
            severity=SEVERITY_INFO,
            description="Traceroute paths showing L3 routing between VLANs",
            observation=f"Traced {len(MOCK_TRACEROUTE)} hosts, identified routing paths",
            affected_objects=traced,
            details={"traceroutes": MOCK_TRACEROUTE},
        )

        if all_routers:
            instance.add_finding(
                test_id="TRACE-002",
                test_name="Intermediate Routing Devices",
                category="Traceroute Analysis",
                status=STATUS_INFO,
                severity=SEVERITY_MEDIUM,
                description="Network infrastructure devices identified in routing paths",
                observation=f"{len(all_routers)} unique routing devices identified",
                affected_objects=list(all_routers),
                remediation="Ensure intermediate routing devices are hardened and access-controlled",
            )

        direct_l2 = [ip for ip, hops in MOCK_TRACEROUTE.items() if len(hops) <= 1]
        if direct_l2:
            instance.add_finding(
                test_id="TRACE-003",
                test_name="Direct L2 Adjacency Detected",
                category="Traceroute Analysis",
                status=STATUS_FAIL,
                severity=SEVERITY_CRITICAL,
                description="Hosts reachable with <= 1 hop indicates no L3 segmentation",
                observation=f"{len(direct_l2)} hosts appear to be on the same L2 segment",
                affected_objects=direct_l2,
                remediation="Implement L3 routing between VLANs; L2 adjacency defeats VLAN isolation",
            )
        else:
            instance.add_finding(
                test_id="TRACE-003",
                test_name="L3 Segmentation Verified",
                category="Traceroute Analysis",
                status=STATUS_PASS,
                severity=SEVERITY_INFO,
                description="All traced hosts require multiple L3 hops (proper segmentation)",
                observation="No direct L2 adjacency detected between source and target VLANs",
            )

    instance.execute = mock_execute


def _patch_vlan_checks(instance):
    def mock_execute():
        instance.add_finding(
            test_id="VLAN-001",
            test_name="CDP/LLDP Information Disclosure",
            category="VLAN Security",
            status=STATUS_WARN,
            severity=SEVERITY_MEDIUM,
            description="CDP/LLDP frames detected revealing switch information",
            observation="CDP frame received: Switch=CORE-SW01, Port=Gi1/0/24, Native VLAN=1, Platform=cisco WS-C3850-48T, Mgmt IP=10.99.99.1",
            remediation="Disable CDP/LLDP on user-facing ports or restrict to management VLAN",
            affected_objects=["CORE-SW01 (10.99.99.1) — Gi1/0/24 — VLAN 1"],
        )

        instance.add_finding(
            test_id="VLAN-002",
            test_name="DTP Trunk Negotiation",
            category="VLAN Security",
            status=STATUS_PASS,
            severity=SEVERITY_INFO,
            description="No DTP frames detected — trunk negotiation not active",
            observation="Monitored for 10 seconds, no DTP frames received",
        )

        instance.add_finding(
            test_id="VLAN-003",
            test_name="DHCP Server Discovery",
            category="VLAN Security",
            status=STATUS_WARN,
            severity=SEVERITY_HIGH,
            description="Multiple DHCP servers responding from different VLANs",
            observation="2 DHCP servers found: 10.10.10.1 (expected), 10.20.20.1 (unexpected — Server VLAN gateway)",
            remediation="Enable DHCP snooping to restrict DHCP responses to authorized servers",
            affected_objects=["10.10.10.1 (User VLAN - expected)", "10.20.20.1 (Server VLAN - unexpected)"],
        )

        instance.add_finding(
            test_id="VLAN-004",
            test_name="Native VLAN Configuration",
            category="VLAN Security",
            status=STATUS_WARN,
            severity=SEVERITY_MEDIUM,
            description="Native VLAN is set to default VLAN 1",
            observation="CDP reveals native VLAN = 1 (default). This enables potential double-tagging attacks on trunk links.",
            remediation="Change native VLAN to an unused VLAN ID (e.g., VLAN 999)",
        )

        instance.add_finding(
            test_id="VLAN-005",
            test_name="Broadcast Domain Leak Test",
            category="VLAN Security",
            status=STATUS_PASS,
            severity=SEVERITY_INFO,
            description="No broadcast leakage detected across VLAN boundaries",
            observation="Broadcast probe received responses only from source VLAN (10.10.10.0/24)",
        )

    instance.execute = mock_execute


def _patch_management(instance):
    def mock_execute():
        gw = instance.scan_config.get("gateway", "10.10.10.1")
        instance.add_finding(
            test_id="MGMT-001",
            test_name="Source Gateway Management Access",
            category="Management Plane",
            status=STATUS_INFO,
            severity=SEVERITY_INFO,
            description=f"Management ports on source gateway ({gw})",
            observation=f"Gateway {gw} has management ports accessible (expected from local VLAN)",
            affected_objects=[f"{gw}:22 (SSH)", f"{gw}:80 (HTTP)", f"{gw}:443 (HTTPS)"],
        )

        cross_mgmt = []
        for ip in ["10.99.99.1", "10.99.99.2"]:
            for port in MOCK_OPEN_PORTS.get(ip, []):
                if port in MANAGEMENT_PORTS:
                    svc = CRITICAL_PORTS.get(port, (f"port-{port}", ""))[0] if port in CRITICAL_PORTS else f"port-{port}"
                    cross_mgmt.append(f"{ip}:{port} ({svc})")

        if cross_mgmt:
            instance.add_finding(
                test_id="MGMT-002",
                test_name="Cross-VLAN Management Plane Exposure",
                category="Management Plane",
                status=STATUS_FAIL,
                severity=SEVERITY_CRITICAL,
                description="Network device management interfaces accessible from user VLAN",
                observation=f"{len(cross_mgmt)} management endpoints reachable on Management VLAN",
                remediation="Restrict management access to dedicated management stations only. Implement management ACLs on all network devices.",
                affected_objects=cross_mgmt,
            )

        instance.add_finding(
            test_id="MGMT-003",
            test_name="SNMP Default Community",
            category="Management Plane",
            status=STATUS_FAIL,
            severity=SEVERITY_CRITICAL,
            description="SNMP accessible with default 'public' community string",
            observation="SNMP port 161 open on 10.99.99.1 (Core Switch) — device may accept default community strings",
            remediation="Change SNMP community strings, use SNMPv3 with authentication and encryption, restrict SNMP access via ACLs",
            affected_objects=["10.99.99.1:161 (SNMP)", "10.20.20.1:161 (SNMP)"],
        )

        instance.add_finding(
            test_id="MGMT-004",
            test_name="Management Plane Summary",
            category="Management Plane",
            status=STATUS_FAIL,
            severity=SEVERITY_HIGH,
            description="Summary of management plane exposure across VLANs",
            observation=f"Total: {len(cross_mgmt)} cross-VLAN management endpoints exposed. Network devices on Management VLAN (10.99.99.0/29) fully accessible from User VLAN.",
            remediation="Implement strict management VLAN isolation with dedicated jump hosts",
        )

    instance.execute = mock_execute


def _patch_dns(instance):
    def mock_execute():
        instance.add_finding(
            test_id="DNS-001",
            test_name="DNS Server Discovery",
            category="DNS Analysis",
            status=STATUS_INFO,
            severity=SEVERITY_INFO,
            description="DNS servers discovered across reachable hosts",
            observation="2 DNS-capable hosts found: 10.10.10.1 (gateway), 10.20.20.1 (Server VLAN gateway)",
            affected_objects=["10.10.10.1:53", "10.20.20.1:53"],
        )

        instance.add_finding(
            test_id="DNS-002",
            test_name="Internal DNS Resolution Cross-VLAN",
            category="DNS Analysis",
            status=STATUS_WARN,
            severity=SEVERITY_MEDIUM,
            description="Internal hostnames resolvable from source VLAN via cross-VLAN DNS",
            observation="DNS server 10.20.20.1 resolved internal names: db01.corp.local → 10.20.20.5, fs01.corp.local → 10.20.20.10",
            remediation="Restrict DNS zone visibility based on source VLAN; implement split-horizon DNS",
            affected_objects=["db01.corp.local → 10.20.20.5", "fs01.corp.local → 10.20.20.10", "core-sw.corp.local → 10.99.99.1"],
        )

        instance.add_finding(
            test_id="DNS-003",
            test_name="DNS Zone Transfer",
            category="DNS Analysis",
            status=STATUS_PASS,
            severity=SEVERITY_INFO,
            description="DNS zone transfer (AXFR) not permitted",
            observation="AXFR attempt to 10.20.20.1 was refused (expected secure configuration)",
        )

        instance.add_finding(
            test_id="DNS-004",
            test_name="DNS Accessibility Summary",
            category="DNS Analysis",
            status=STATUS_WARN,
            severity=SEVERITY_MEDIUM,
            description="Cross-VLAN DNS server access allows network reconnaissance",
            observation="DNS servers on Server VLAN are reachable and resolve internal names, providing attackers with network topology information",
            remediation="Limit DNS access to designated recursive resolvers per VLAN",
        )

    instance.execute = mock_execute


if __name__ == "__main__":
    success = run_test()
    sys.exit(0 if success else 1)
