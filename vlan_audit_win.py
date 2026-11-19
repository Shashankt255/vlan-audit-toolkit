"""
VLAN Segmentation Audit - Windows Compatible
No Scapy required. Uses ping, socket, and subprocess.
Run as Administrator: python vlan_audit_win.py -t 172.17.5.0/24 -g 172.17.5.254
"""

import argparse
import socket
import subprocess
import ipaddress
import json
import time
import sys
import os
import concurrent.futures
from datetime import datetime

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCbind", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    636: "LDAPS", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "HTTP-Alt2",
    9090: "WebConsole", 27017: "MongoDB"
}

HIGH_RISK_PORTS = {21, 23, 135, 139, 161, 445, 1433, 3306, 3389, 5432, 5900, 6379, 27017}
CRITICAL_SERVICES = {23: "Telnet (cleartext)", 21: "FTP (cleartext)", 161: "SNMP (community strings)"}


def ping_host(ip, timeout=1):
    try:
        result = subprocess.run(
            ["ping", "-n", "1", "-w", str(timeout * 1000), str(ip)],
            capture_output=True, text=True, timeout=timeout + 2
        )
        return result.returncode == 0 and "TTL=" in result.stdout
    except:
        return False


def get_ttl(ip):
    try:
        result = subprocess.run(
            ["ping", "-n", "1", "-w", "1000", str(ip)],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.split("\n"):
            if "TTL=" in line.upper():
                ttl_part = line.upper().split("TTL=")[1].split()[0].strip()
                ttl = int(ttl_part)
                if ttl <= 64:
                    return ttl, "Linux/Unix"
                elif ttl <= 128:
                    return ttl, "Windows"
                else:
                    return ttl, "Network Device"
        return None, "Unknown"
    except Exception:
        return None, "Unknown"


def scan_port(ip, port, timeout=1):
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((str(ip), port))
        return result == 0
    except Exception:
        return False
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def grab_banner(ip, port, timeout=2):
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((str(ip), port))
        if port in (80, 8080, 8443, 443):
            sock.send(b"HEAD / HTTP/1.0\r\nHost: " + str(ip).encode() + b"\r\n\r\n")
        else:
            sock.send(b"\r\n")
        banner = sock.recv(256).decode("utf-8", errors="replace").strip()
        return banner[:200] if banner else None
    except Exception:
        return None
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def traceroute(ip, max_hops=15):
    try:
        result = subprocess.run(
            ["tracert", "-d", "-w", "1000", "-h", str(max_hops), str(ip)],
            capture_output=True, text=True, timeout=max_hops * 3
        )
        hops = []
        for line in result.stdout.split("\n"):
            line = line.strip()
            if not line or line.startswith("Tracing") or line.startswith("Trace") or line.startswith("over"):
                continue
            parts = line.split()
            if parts and parts[0].isdigit():
                hop_ip = None
                for p in parts:
                    try:
                        ipaddress.ip_address(p)
                        hop_ip = p
                    except:
                        continue
                if hop_ip:
                    hops.append(hop_ip)
        return hops
    except:
        return []


def resolve_hostname(ip):
    try:
        return socket.getfqdn(str(ip))
    except:
        return None


def get_local_info():
    info = {"ip": None, "gateway": None, "hostname": socket.gethostname()}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        info["ip"] = s.getsockname()[0]
        s.close()
    except:
        pass
    try:
        result = subprocess.run(["ipconfig"], capture_output=True, text=True, timeout=5)
        for line in result.stdout.split("\n"):
            if "Default Gateway" in line and ":" in line:
                gw = line.split(":")[-1].strip()
                if gw:
                    info["gateway"] = gw
                    break
    except:
        pass
    return info


class VLANAuditWin:
    def __init__(self, targets, gateway, ports=None, speed="medium", verbose=False):
        self.targets = targets
        self.gateway = gateway
        self.ports = ports or list(COMMON_PORTS.keys())
        self.verbose = verbose
        self.findings = []
        self.hosts = []
        self.speed = speed
        self.workers = {"fast": 50, "medium": 30, "slow": 10}.get(speed, 30)
        self.port_timeout = {"fast": 0.5, "medium": 1, "slow": 2}.get(speed, 1)

    def log(self, msg):
        print(f"  [*] {msg}")

    def warn(self, msg):
        print(f"  [!] {msg}")

    def add_finding(self, test_id, title, severity, observation, recommendation=""):
        f = {
            "test_id": test_id,
            "title": title,
            "severity": severity,
            "observation": observation,
            "recommendation": recommendation,
            "timestamp": datetime.now().isoformat()
        }
        self.findings.append(f)
        marker = {"CRITICAL": "!!!", "HIGH": "!!", "MEDIUM": "!", "LOW": "~", "INFO": "-"}.get(severity, "-")
        print(f"  [{marker}] [{severity}] {title}")
        if self.verbose:
            print(f"      {observation[:120]}")

    def phase_discovery(self):
        print("\n[Phase 1] Host Discovery")
        all_ips = []
        for target in self.targets:
            try:
                network = ipaddress.ip_network(target, strict=False)
                all_ips.extend([str(ip) for ip in network.hosts()])
            except:
                all_ips.append(target)

        self.log(f"Scanning {len(all_ips)} addresses...")
        alive = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.workers) as executor:
            future_map = {executor.submit(ping_host, ip): ip for ip in all_ips}
            for future in concurrent.futures.as_completed(future_map):
                ip = future_map[future]
                try:
                    if future.result():
                        alive.append(ip)
                        if self.verbose:
                            self.log(f"  ALIVE: {ip}")
                except:
                    pass

        self.log(f"Found {len(alive)} live hosts out of {len(all_ips)}")

        for ip in alive:
            ttl, os_guess = get_ttl(ip)
            hostname = resolve_hostname(ip)
            self.hosts.append({
                "ip": ip, "ttl": ttl, "os_guess": os_guess,
                "hostname": hostname if hostname != ip else None,
                "open_ports": [], "banners": {}
            })

        self.add_finding("DISC-01", f"Host Discovery: {len(alive)}/{len(all_ips)} hosts alive",
                         "INFO",
                         f"Discovered {len(alive)} live hosts in target range(s): {', '.join(self.targets)}",
                         "Review if all discovered hosts are expected on this VLAN segment.")
        return alive

    def phase_port_scan(self):
        print(f"\n[Phase 2] Port Scan ({len(self.ports)} ports x {len(self.hosts)} hosts)")
        total_open = 0
        high_risk_found = []
        critical_found = []

        for host in self.hosts:
            ip = host["ip"]
            if self.verbose:
                self.log(f"Scanning {ip}...")

            with concurrent.futures.ThreadPoolExecutor(max_workers=self.workers) as executor:
                future_map = {executor.submit(scan_port, ip, p, self.port_timeout): p for p in self.ports}
                for future in concurrent.futures.as_completed(future_map):
                    port = future_map[future]
                    try:
                        if future.result():
                            svc = COMMON_PORTS.get(port, "unknown")
                            host["open_ports"].append({"port": port, "service": svc})
                            total_open += 1

                            banner = grab_banner(ip, port)
                            if banner:
                                host["banners"][port] = banner

                            if port in CRITICAL_SERVICES:
                                critical_found.append(f"{ip}:{port} ({CRITICAL_SERVICES[port]})")
                            elif port in HIGH_RISK_PORTS:
                                high_risk_found.append(f"{ip}:{port} ({svc})")

                            if self.verbose:
                                b = f" [{banner[:60]}]" if banner else ""
                                self.log(f"  OPEN: {ip}:{port} ({svc}){b}")
                    except:
                        pass

        self.add_finding("PORT-01", f"Port Scan Summary: {total_open} open ports across {len(self.hosts)} hosts",
                         "INFO",
                         f"Total open ports: {total_open}. Hosts scanned: {len(self.hosts)}. Ports checked: {len(self.ports)}.",
                         "Review all open ports for necessity on this VLAN segment.")

        if critical_found:
            self.add_finding("PORT-02", f"Critical Services Exposed: {len(critical_found)} instances",
                             "CRITICAL",
                             f"Cleartext/dangerous services found: {'; '.join(critical_found[:10])}",
                             "Disable cleartext protocols. Replace Telnet with SSH, FTP with SFTP.")

        if high_risk_found:
            self.add_finding("PORT-03", f"High-Risk Ports Open: {len(high_risk_found)} instances",
                             "HIGH",
                             f"High-risk services: {'; '.join(high_risk_found[:10])}",
                             "Restrict access to management and database ports via ACLs.")

    def phase_segmentation(self):
        print("\n[Phase 3] Segmentation Check")
        local_info = get_local_info()
        source_net = None
        if local_info["ip"]:
            try:
                source_net = str(ipaddress.ip_network(f"{local_info['ip']}/24", strict=False))
            except:
                pass

        cross_vlan = []
        same_vlan = []
        for host in self.hosts:
            ip = host["ip"]
            try:
                host_net = str(ipaddress.ip_network(f"{ip}/24", strict=False))
            except:
                continue
            if source_net and host_net != source_net:
                cross_vlan.append(ip)
            else:
                same_vlan.append(ip)

        if cross_vlan:
            self.add_finding("SEG-01", f"Cross-VLAN Reachability: {len(cross_vlan)} hosts on other subnets reachable",
                             "HIGH",
                             f"Hosts reachable from {source_net}: {', '.join(cross_vlan[:15])}",
                             "Review inter-VLAN ACLs. Restrict cross-segment access to required services only.")
        else:
            self.add_finding("SEG-01", "VLAN Segmentation: No cross-subnet hosts reachable",
                             "INFO",
                             f"All {len(same_vlan)} discovered hosts are within the source subnet {source_net}.",
                             "Consider testing additional target subnets to verify segmentation.")

        if self.gateway:
            self.log(f"Traceroute to gateway {self.gateway}...")
            hops = traceroute(self.gateway)
            if hops:
                self.add_finding("SEG-02", f"Gateway Path: {len(hops)} hops to {self.gateway}",
                                 "INFO",
                                 f"Route: {' -> '.join(hops)}",
                                 "Verify routing path is as expected.")

        self.phase_traceroute(source_net)

    def phase_traceroute(self, source_net=None):
        print(f"\n[Phase 3b] Traceroute Analysis")
        self.traceroute_results = []

        targets = []
        if self.gateway:
            targets.append(self.gateway)
        for host in self.hosts:
            if host["ip"] not in targets:
                targets.append(host["ip"])

        if len(targets) > 20:
            self.log(f"Limiting traceroute to first 20 of {len(targets)} targets")
            targets = targets[:20]

        self.log(f"Running traceroute to {len(targets)} targets...")

        for ip in targets:
            if self.verbose:
                self.log(f"Traceroute to {ip}...")
            hops = traceroute(ip, max_hops=15)
            hop_count = len(hops)
            l3_devices = []
            subnets_crossed = set()
            for h in hops:
                try:
                    hop_net = str(ipaddress.ip_network(f"{h}/24", strict=False))
                except Exception:
                    hop_net = "unknown"
                subnets_crossed.add(hop_net)
                if h != ip:
                    hostname = resolve_hostname(h)
                    l3_devices.append({
                        "ip": h,
                        "subnet": hop_net,
                        "hostname": hostname if hostname != h else None
                    })

            if source_net:
                subnets_crossed.add(source_net)
            subnets_crossed.discard("unknown")

            result = {
                "target": ip,
                "hops": hops,
                "hop_count": hop_count,
                "l3_devices": l3_devices,
                "subnets_crossed": sorted(subnets_crossed),
                "direct": hop_count <= 1
            }
            self.traceroute_results.append(result)

            if self.verbose:
                path = " -> ".join(hops) if hops else "no response"
                self.log(f"  {ip}: {hop_count} hops [{path}]")

        multi_hop = [r for r in self.traceroute_results if not r["direct"] and r["hop_count"] > 0]
        direct = [r for r in self.traceroute_results if r["direct"]]
        no_response = [r for r in self.traceroute_results if r["hop_count"] == 0]

        if multi_hop:
            for r in multi_hop:
                routers = [f"{d['ip']} ({d['subnet']})" for d in r["l3_devices"]]
                subnets = r.get("subnets_crossed", [])
                self.add_finding(
                    "TR-01",
                    f"Cross-VLAN Route to {r['target']}: {r['hop_count']} hops, {len(subnets)} subnets",
                    "HIGH" if len(subnets) > 2 else "MEDIUM",
                    f"Target {r['target']} is {r['hop_count']} hops away. "
                    f"Route: {' -> '.join(r['hops'])}. "
                    f"Subnets traversed: {', '.join(subnets)}. "
                    f"L3 devices in path: {'; '.join(routers) if routers else 'none identified'}.",
                    f"ACTION REQUIRED: Review ACLs on the routing devices ({', '.join([d['ip'] for d in r['l3_devices']]) or 'gateway'}). "
                    f"If {r['target']} should not be reachable from {source_net or 'this VLAN'}, "
                    f"add a deny rule on the inter-VLAN firewall/router for traffic between "
                    f"{source_net or 'source subnet'} and {r['subnets_crossed'][-1] if r['subnets_crossed'] else 'target subnet'}. "
                    f"If access is intentional, restrict to only required ports/protocols via ACL."
                )

        unique_l3 = {}
        for r in self.traceroute_results:
            for dev in r["l3_devices"]:
                if dev["ip"] not in unique_l3:
                    unique_l3[dev["ip"]] = {
                        "subnet": dev["subnet"],
                        "hostname": dev.get("hostname"),
                        "routes_through": []
                    }
                unique_l3[dev["ip"]]["routes_through"].append(r["target"])

        if unique_l3:
            device_details = []
            for ip, info in sorted(unique_l3.items()):
                name = f"{ip} ({info['hostname']})" if info.get("hostname") else ip
                device_details.append(
                    f"{name} on {info['subnet']} — routes to: {', '.join(info['routes_through'][:5])}"
                )
            self.add_finding(
                "TR-02",
                f"L3 Routing Devices: {len(unique_l3)} routers/firewalls identified",
                "INFO",
                f"The following L3 devices were identified in network paths:\n" +
                "\n".join(f"  - {d}" for d in device_details[:15]),
                f"ACTION REQUIRED: For each device listed, verify: "
                f"(1) ACLs restrict inter-VLAN traffic to only necessary services, "
                f"(2) management interfaces (SSH/HTTPS) are not exposed to user VLANs, "
                f"(3) routing between sensitive segments (server/DB VLANs) and user VLANs is filtered. "
                f"Devices to audit: {', '.join(sorted(unique_l3.keys()))}."
            )

        if no_response:
            blocked = [r["target"] for r in no_response]
            self.add_finding(
                "TR-03",
                f"Traceroute Blocked: {len(no_response)} targets did not respond",
                "INFO",
                f"No traceroute response from: {', '.join(blocked[:15])}. "
                f"These hosts may have ICMP/TTL-exceeded responses disabled or a firewall is dropping trace packets.",
                f"Note: Blocked traceroute may indicate a firewall is filtering ICMP. "
                f"This is generally positive from a security standpoint but verify these hosts "
                f"are still reachable on required service ports."
            )

        self.log(f"Traceroute complete: {len(direct)} direct, {len(multi_hop)} routed, {len(no_response)} no response")

    def phase_service_analysis(self):
        print("\n[Phase 4] Service Analysis")
        mgmt_services = []
        db_services = []
        web_services = []

        for host in self.hosts:
            ip = host["ip"]
            for p in host["open_ports"]:
                port = p["port"]
                if port in (22, 23, 3389, 5900):
                    mgmt_services.append(f"{ip}:{port} ({p['service']})")
                elif port in (1433, 1521, 3306, 5432, 6379, 27017):
                    db_services.append(f"{ip}:{port} ({p['service']})")
                elif port in (80, 443, 8080, 8443, 8888, 9090):
                    web_services.append(f"{ip}:{port} ({p['service']})")

        if mgmt_services:
            self.add_finding("SVC-01", f"Management Interfaces: {len(mgmt_services)} exposed",
                             "MEDIUM",
                             f"Remote management: {'; '.join(mgmt_services[:10])}",
                             "Restrict management access to dedicated management VLAN.")

        if db_services:
            self.add_finding("SVC-02", f"Database Services: {len(db_services)} exposed",
                             "HIGH",
                             f"Databases reachable: {'; '.join(db_services[:10])}",
                             "Database ports should not be reachable from non-application VLANs.")

        if web_services:
            self.add_finding("SVC-03", f"Web Services: {len(web_services)} found",
                             "INFO",
                             f"Web interfaces: {'; '.join(web_services[:10])}",
                             "Review web services for authentication and authorization controls.")

        hosts_with_many = [h for h in self.hosts if len(h["open_ports"]) > 10]
        if hosts_with_many:
            details = [f"{h['ip']} ({len(h['open_ports'])} ports)" for h in hosts_with_many]
            self.add_finding("SVC-04", f"Excessive Open Ports: {len(hosts_with_many)} hosts with 10+ ports",
                             "MEDIUM",
                             f"Hosts with excessive services: {'; '.join(details[:10])}",
                             "Harden hosts by disabling unnecessary services.")

    def run(self):
        start = time.time()
        print("=" * 60)
        print("  VLAN Segmentation Audit (Windows)")
        print(f"  Targets: {', '.join(self.targets)}")
        print(f"  Gateway: {self.gateway}")
        print(f"  Ports:   {len(self.ports)} | Speed: {self.speed}")
        print(f"  Time:    {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)

        local = get_local_info()
        print(f"\n  Source IP: {local['ip']}  |  Hostname: {local['hostname']}")

        self.phase_discovery()
        if self.hosts:
            self.phase_port_scan()
            self.phase_segmentation()
            self.phase_service_analysis()
        else:
            self.warn("No live hosts found. Check target range and connectivity.")
            self.add_finding("DISC-ERR", "No Live Hosts Found", "HIGH",
                             f"No hosts responded to ping in: {', '.join(self.targets)}",
                             "Verify network connectivity. Host firewalls may block ICMP.")

        elapsed = time.time() - start
        return self.generate_report(elapsed, local)

    def generate_report(self, elapsed, local):
        print(f"\n{'=' * 60}")
        print(f"  SCAN COMPLETE — {len(self.findings)} findings in {elapsed:.1f}s")
        print(f"{'=' * 60}")

        sev_count = {}
        for f in self.findings:
            sev_count[f["severity"]] = sev_count.get(f["severity"], 0) + 1

        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if sev in sev_count:
                print(f"  {sev}: {sev_count[sev]}")

        report = {
            "scan_info": {
                "targets": self.targets,
                "gateway": self.gateway,
                "source_ip": local["ip"],
                "hostname": local["hostname"],
                "timestamp": datetime.now().isoformat(),
                "duration_seconds": round(elapsed, 1),
                "ports_scanned": len(self.ports),
                "speed": self.speed
            },
            "summary": {
                "total_findings": len(self.findings),
                "severity_counts": sev_count,
                "hosts_discovered": len(self.hosts),
                "total_open_ports": sum(len(h["open_ports"]) for h in self.hosts)
            },
            "findings": self.findings,
            "hosts": self.hosts,
            "traceroute": getattr(self, "traceroute_results", [])
        }
        return report


def generate_html(report, output_path):
    sev_colors = {
        "CRITICAL": "#dc2626", "HIGH": "#ea580c",
        "MEDIUM": "#ca8a04", "LOW": "#2563eb", "INFO": "#6b7280"
    }
    findings_html = ""
    for f in report["findings"]:
        color = sev_colors.get(f["severity"], "#6b7280")
        findings_html += f"""
        <div style="border-left:4px solid {color};padding:12px 16px;margin:10px 0;background:#f9fafb;border-radius:0 6px 6px 0;">
            <span style="background:{color};color:#fff;padding:2px 8px;border-radius:3px;font-size:12px;font-weight:bold;">{f['severity']}</span>
            <strong style="margin-left:8px;">{f['test_id']}: {f['title']}</strong>
            <p style="margin:8px 0 4px;color:#374151;">{f['observation']}</p>
            <p style="margin:4px 0;color:#059669;font-style:italic;">Recommendation: {f['recommendation']}</p>
        </div>"""

    hosts_html = ""
    for h in report["hosts"]:
        ports_str = ", ".join([f"{p['port']}/{p['service']}" for p in h["open_ports"]]) or "None"
        banner_str = "<br>".join([f"Port {k}: {v[:80]}" for k, v in h.get("banners", {}).items()]) or "—"
        hosts_html += f"""
        <tr>
            <td>{h['ip']}</td>
            <td>{h.get('hostname') or '—'}</td>
            <td>{h.get('os_guess', '—')}</td>
            <td>{len(h['open_ports'])}</td>
            <td style="font-size:12px;">{ports_str}</td>
        </tr>"""

    traceroute_html = ""
    tr_data = report.get("traceroute", [])
    if tr_data:
        traceroute_html += """<table>
        <tr><th>Target</th><th>Hops</th><th>Route Path</th><th>Subnets Crossed</th><th>L3 Devices</th><th>Type</th></tr>"""
        for tr in tr_data:
            path = " &rarr; ".join(tr["hops"]) if tr["hops"] else "<em>No response</em>"
            l3_parts = []
            for d in tr.get("l3_devices", []):
                name = f"{d['ip']}"
                if d.get("hostname"):
                    name += f" ({d['hostname']})"
                name += f" [{d['subnet']}]"
                l3_parts.append(name)
            l3 = "<br>".join(l3_parts) or "—"
            subnets = ", ".join(tr.get("subnets_crossed", [])) or "—"
            rtype = "Direct (same VLAN)" if tr.get("direct") else f"Routed ({tr['hop_count']} hops)"
            rcolor = "#059669" if tr.get("direct") else "#dc2626"
            hop_count = tr["hop_count"]
            if hop_count == 0:
                rtype = "No response"
                rcolor = "#9ca3af"
            traceroute_html += f"""
            <tr>
                <td><strong>{tr['target']}</strong></td>
                <td style="text-align:center;">{hop_count}</td>
                <td style="font-size:12px;font-family:monospace;">{path}</td>
                <td style="font-size:12px;">{subnets}</td>
                <td style="font-size:12px;">{l3}</td>
                <td><span style="color:{rcolor};font-weight:bold;">{rtype}</span></td>
            </tr>"""
        traceroute_html += "</table>"

        direct_count = sum(1 for t in tr_data if t.get("direct"))
        routed_count = sum(1 for t in tr_data if not t.get("direct") and t["hop_count"] > 0)
        no_resp = sum(1 for t in tr_data if t["hop_count"] == 0)
        all_subnets = set()
        all_l3 = set()
        for t in tr_data:
            all_subnets.update(t.get("subnets_crossed", []))
            for d in t.get("l3_devices", []):
                all_l3.add(d["ip"])
        traceroute_html += f"""
        <div style="background:#fffbeb;border:1px solid #fbbf24;border-radius:8px;padding:16px;margin:16px 0;">
            <h3 style="margin:0 0 8px;color:#92400e;">Traceroute Summary</h3>
            <p><strong>Targets traced:</strong> {len(tr_data)} | <strong>Direct (same VLAN):</strong> {direct_count} |
            <strong>Routed (cross-VLAN):</strong> <span style="color:#dc2626;font-weight:bold;">{routed_count}</span> |
            <strong>No response:</strong> {no_resp}</p>
            <p><strong>Unique subnets observed:</strong> {', '.join(sorted(all_subnets)) or 'None'}</p>
            <p><strong>L3 devices (routers/firewalls) in paths:</strong> {', '.join(sorted(all_l3)) or 'None identified'}</p>
            {"<p style='color:#dc2626;font-weight:bold;'>⚠ Cross-VLAN routes detected — review ACLs on listed L3 devices to ensure inter-VLAN traffic is restricted to required services only.</p>" if routed_count > 0 else "<p style='color:#059669;'>✓ All targets are on the same VLAN segment — no unexpected cross-VLAN routing detected.</p>"}
        </div>"""
    else:
        traceroute_html = "<p><em>No traceroute data collected.</em></p>"

    info = report["scan_info"]
    summary = report["summary"]

    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>VLAN Segmentation Audit Report</title>
<style>
body{{font-family:Segoe UI,Arial,sans-serif;margin:40px;color:#1f2937;line-height:1.6;}}
h1{{color:#111827;border-bottom:3px solid #2563eb;padding-bottom:10px;}}
h2{{color:#1e40af;margin-top:30px;}}
table{{border-collapse:collapse;width:100%;margin:10px 0;}}
th,td{{border:1px solid #d1d5db;padding:8px 12px;text-align:left;font-size:13px;}}
th{{background:#1e40af;color:#fff;}}
tr:nth-child(even){{background:#f3f4f6;}}
.summary-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin:16px 0;}}
.summary-card{{background:#f0f9ff;border:1px solid #bfdbfe;border-radius:8px;padding:16px;text-align:center;}}
.summary-card .num{{font-size:28px;font-weight:bold;color:#1e40af;}}
.summary-card .label{{font-size:12px;color:#6b7280;text-transform:uppercase;}}
</style></head><body>
<h1>VLAN Segmentation Audit Report</h1>
<p><strong>Date:</strong> {info['timestamp'][:19]} | <strong>Source:</strong> {info['source_ip']} ({info['hostname']})
| <strong>Duration:</strong> {info['duration_seconds']}s</p>
<p><strong>Targets:</strong> {', '.join(info['targets'])} | <strong>Gateway:</strong> {info['gateway']}</p>

<div class="summary-grid">
    <div class="summary-card"><div class="num">{summary['hosts_discovered']}</div><div class="label">Hosts Found</div></div>
    <div class="summary-card"><div class="num">{summary['total_open_ports']}</div><div class="label">Open Ports</div></div>
    <div class="summary-card"><div class="num">{summary['severity_counts'].get('CRITICAL',0)}</div><div class="label">Critical</div></div>
    <div class="summary-card"><div class="num">{summary['severity_counts'].get('HIGH',0)}</div><div class="label">High</div></div>
    <div class="summary-card"><div class="num">{summary['severity_counts'].get('MEDIUM',0)}</div><div class="label">Medium</div></div>
    <div class="summary-card"><div class="num">{summary['total_findings']}</div><div class="label">Total Findings</div></div>
</div>

<h2>Findings</h2>
{findings_html}

<h2>Host Inventory</h2>
<table>
<tr><th>IP</th><th>Hostname</th><th>OS Guess</th><th>Open Ports</th><th>Services</th></tr>
{hosts_html}
</table>

<h2>Traceroute Analysis</h2>
{traceroute_html}

<h2>Scan Configuration</h2>
<p>Ports scanned: {info['ports_scanned']} | Speed: {info['speed']}</p>
<p style="color:#9ca3af;font-size:12px;margin-top:40px;">Generated by VLAN Segmentation Audit Toolkit (Windows) — Authorized testing only</p>
</body></html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"\n  HTML report: {os.path.abspath(output_path)}")


def main():
    parser = argparse.ArgumentParser(description="VLAN Segmentation Audit - Windows Compatible")
    parser.add_argument("-t", "--targets", required=True, help="Target subnets (comma-separated, e.g. 172.17.5.0/24,10.0.1.0/24)")
    parser.add_argument("-g", "--gateway", required=True, help="Gateway IP")
    parser.add_argument("-p", "--ports", default="common", help="Ports: common (default), top10, all, or comma-separated list")
    parser.add_argument("-s", "--speed", default="medium", choices=["fast", "medium", "slow"])
    parser.add_argument("-o", "--output", default="vlan_audit_report.html", help="HTML report path")
    parser.add_argument("--json-output", help="JSON report path")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    targets = [t.strip() for t in args.targets.split(",")]

    if args.ports == "common":
        ports = list(COMMON_PORTS.keys())
    elif args.ports == "top10":
        ports = [22, 23, 80, 135, 139, 443, 445, 3389, 8080, 3306]
    elif args.ports == "all":
        ports = list(range(1, 1025))
    else:
        ports = [int(p.strip()) for p in args.ports.split(",")]

    audit = VLANAuditWin(targets, args.gateway, ports, args.speed, args.verbose)
    report = audit.run()

    generate_html(report, args.output)

    if args.json_output:
        with open(args.json_output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"  JSON report: {os.path.abspath(args.json_output)}")


if __name__ == "__main__":
    main()
