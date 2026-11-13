import os
import socket
import subprocess
import platform
import time
import re
import ipaddress

from modules.base import BaseModule, Finding, HostResult
from config import *

HAS_SCAPY = False
try:
    from scapy.all import IP, TCP, ICMP, sr1, traceroute as scapy_traceroute, conf
    conf.verb = 0
    HAS_SCAPY = True
except ImportError:
    pass


class TracerouteModule(BaseModule):
    MODULE_NAME = "Traceroute Analysis"
    MODULE_DESCRIPTION = "Hop-by-hop path analysis to prove cross-VLAN routing"

    def _is_root(self):
        return os.geteuid() == 0

    def _reverse_dns(self, ip):
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except Exception:
            return None

    def _traceroute_scapy(self, ip, max_hops=30):
        hops = []
        try:
            for ttl in range(1, max_hops + 1):
                pkt = IP(dst=ip, ttl=ttl) / ICMP()
                start = time.time()
                reply = sr1(pkt, timeout=self.get_speed_config()["timeout"], verbose=0)
                rtt = round((time.time() - start) * 1000, 2)

                if reply is None:
                    hops.append({
                        "hop": ttl, "ip": "*", "rtt_ms": None,
                        "hostname": None,
                    })
                else:
                    hop_ip = reply[IP].src
                    hostname = self._reverse_dns(hop_ip)
                    hops.append({
                        "hop": ttl, "ip": hop_ip, "rtt_ms": rtt,
                        "hostname": hostname,
                    })
                    if hop_ip == ip:
                        break
                    if reply.haslayer(ICMP):
                        icmp_type = reply[ICMP].type
                        if icmp_type == 0:  # Echo reply = destination reached
                            break

                speed = self.get_speed_config()
                if speed["delay"] > 0:
                    time.sleep(speed["delay"])

        except Exception:
            pass

        return hops

    def _traceroute_subprocess(self, ip, max_hops=30):
        hops = []
        try:
            cmd = ["traceroute", "-n", "-m", str(max_hops), "-w", "2", ip]
            if platform.system() == "Windows":
                cmd = ["tracert", "-d", "-h", str(max_hops), "-w", "2000", ip]

            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=60
            )
            output = result.stdout

            for line in output.splitlines():
                line = line.strip()
                match = re.match(
                    r"^\s*(\d+)\s+"
                    r"(?:(\d+\.?\d*)\s*ms\s+)?(?:(\d+\.?\d*)\s*ms\s+)?(?:(\d+\.?\d*)\s*ms\s+)?"
                    r"(\d+\.\d+\.\d+\.\d+|\*)",
                    line
                )
                if not match:
                    match = re.match(
                        r"^\s*(\d+)\s+(\d+\.\d+\.\d+\.\d+|\*)\s+"
                        r"(?:(\d+\.?\d*)\s*ms)?",
                        line
                    )

                if match:
                    groups = match.groups()
                    hop_num = int(groups[0])
                    hop_ip = None
                    rtt = None

                    for g in groups[1:]:
                        if g and re.match(r"\d+\.\d+\.\d+\.\d+", g):
                            hop_ip = g
                        elif g and g != "*":
                            try:
                                rtt = float(g)
                            except ValueError:
                                pass

                    if hop_ip and hop_ip != "*":
                        hostname = self._reverse_dns(hop_ip)
                        hops.append({
                            "hop": hop_num, "ip": hop_ip,
                            "rtt_ms": rtt, "hostname": hostname,
                        })
                    else:
                        hops.append({
                            "hop": hop_num, "ip": "*",
                            "rtt_ms": None, "hostname": None,
                        })

        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            pass

        return hops

    def _traceroute(self, ip, max_hops=30):
        if HAS_SCAPY and self._is_root():
            hops = self._traceroute_scapy(ip, max_hops)
            if hops:
                return hops
        return self._traceroute_subprocess(ip, max_hops)

    def _analyze_path(self, hops):
        real_hops = [h for h in hops if h["ip"] != "*"]
        l3_hops = len(real_hops)

        routers = []
        for h in real_hops[:-1]:  # Exclude destination
            routers.append({
                "ip": h["ip"],
                "hostname": h.get("hostname"),
                "hop": h["hop"],
            })

        return {
            "total_hops": len(hops),
            "l3_hops": l3_hops,
            "routers": routers,
            "is_direct": l3_hops <= 1,
        }

    def execute(self):
        source = self.scan_config.get("source_vlan", {})
        targets = self.scan_config.get("targets", [])
        alive_hosts = self.scan_config.get("alive_hosts", [])
        host_results_map = self.scan_config.get("host_results", {})

        if not alive_hosts:
            self.add_finding(
                test_id="TRACE-001",
                test_name="Cross-VLAN Routing Paths",
                category="Traceroute Analysis",
                status=STATUS_INFO,
                severity=SEVERITY_INFO,
                description="Traceroute analysis to prove cross-VLAN routing paths",
                observation="No alive hosts — traceroute skipped",
                source_vlan=source.get("name", ""),
            )
            return

        # Select hosts to trace: up to 5 per target VLAN, prioritizing critical hosts
        hosts_to_trace = []
        for target in targets:
            target_name = target.get("name", "Unknown")
            critical = target.get("critical_hosts", [])
            target_ranges = target.get("ranges", [])

            target_alive = []
            for ip in alive_hosts:
                for r in target_ranges:
                    try:
                        net = ipaddress.ip_network(r, strict=False)
                        if ipaddress.ip_address(ip) in net:
                            target_alive.append(ip)
                            break
                    except ValueError:
                        if ip == r or ip in r:
                            target_alive.append(ip)

            # Prioritize critical hosts
            ordered = []
            for ip in critical:
                if ip in target_alive:
                    ordered.append(ip)
            for ip in target_alive:
                if ip not in ordered:
                    ordered.append(ip)

            for ip in ordered[:5]:
                hosts_to_trace.append({"ip": ip, "vlan": target_name})

        # If no target matching, just trace all alive (max 10)
        if not hosts_to_trace:
            for ip in alive_hosts[:10]:
                hosts_to_trace.append({"ip": ip, "vlan": "Unknown"})

        all_traces = []
        routers_seen = {}
        direct_adjacency = []

        for entry in hosts_to_trace:
            ip = entry["ip"]
            vlan_name = entry["vlan"]

            hops = self._traceroute(ip)
            analysis = self._analyze_path(hops)

            # Store in host result
            hr = host_results_map.get(ip)
            if hr:
                hr.traceroute = hops
                hr.hop_count = analysis["l3_hops"]

            all_traces.append({
                "ip": ip, "vlan": vlan_name,
                "hops": hops, "analysis": analysis,
            })

            for router in analysis["routers"]:
                r_ip = router["ip"]
                if r_ip not in routers_seen:
                    routers_seen[r_ip] = {
                        "ip": r_ip,
                        "hostname": router.get("hostname"),
                        "seen_in_paths": [],
                    }
                routers_seen[r_ip]["seen_in_paths"].append(ip)

            if analysis["is_direct"]:
                direct_adjacency.append(ip)

        # TRACE-001: Routing paths
        path_details = []
        for t in all_traces:
            hop_str = " → ".join(
                h["ip"] if h["ip"] != "*" else "* * *"
                for h in t["hops"]
            )
            path_details.append(f"{t['ip']} ({t['vlan']}): {hop_str}")

        self.add_finding(
            test_id="TRACE-001",
            test_name="Cross-VLAN Routing Paths",
            category="Traceroute Analysis",
            status=STATUS_INFO,
            severity=SEVERITY_INFO,
            description="Hop-by-hop routing paths to reachable cross-VLAN hosts (PoC evidence)",
            observation=f"Traced routes to {len(all_traces)} hosts across target VLANs",
            affected_objects=path_details,
            details={"traces": [
                {
                    "destination": t["ip"],
                    "target_vlan": t["vlan"],
                    "hops": t["hops"],
                    "l3_hops": t["analysis"]["l3_hops"],
                }
                for t in all_traces
            ]},
            source_vlan=source.get("name", ""),
        )

        # TRACE-002: Intermediate routing devices
        if routers_seen:
            self.add_finding(
                test_id="TRACE-002",
                test_name="Intermediate Routing Devices",
                category="Traceroute Analysis",
                status=STATUS_INFO,
                severity=SEVERITY_INFO,
                description="Routers and gateways identified in cross-VLAN paths (infrastructure disclosure)",
                observation=f"{len(routers_seen)} unique routing devices identified in traced paths",
                affected_objects=[
                    f"{r['ip']} ({r['hostname'] or 'no PTR'}) — seen in {len(r['seen_in_paths'])} paths"
                    for r in routers_seen.values()
                ],
                details={"routers": list(routers_seen.values())},
                source_vlan=source.get("name", ""),
            )
        else:
            self.add_finding(
                test_id="TRACE-002",
                test_name="Intermediate Routing Devices",
                category="Traceroute Analysis",
                status=STATUS_INFO,
                severity=SEVERITY_INFO,
                description="Routers and gateways identified in cross-VLAN paths",
                observation="No intermediate routing devices identified (all hops timed out or direct paths)",
                source_vlan=source.get("name", ""),
            )

        # TRACE-003: Direct L2 adjacency
        if direct_adjacency:
            self.add_finding(
                test_id="TRACE-003",
                test_name="Direct L2 Adjacency Detected",
                category="Traceroute Analysis",
                status=STATUS_WARN,
                severity=SEVERITY_HIGH,
                description="Hosts in target VLANs reachable with 0-1 L3 hops, indicating missing L3 segmentation",
                observation=f"{len(direct_adjacency)} hosts appear to be on the same L2 segment or directly adjacent "
                            f"(no L3 routing between source and destination)",
                remediation="Verify VLAN segmentation is enforced at L3 — direct adjacency may indicate "
                            "trunk misconfiguration, VLAN leaking, or flat network segments",
                affected_objects=direct_adjacency,
                details={"direct_hosts": direct_adjacency},
                source_vlan=source.get("name", ""),
            )
        else:
            self.add_finding(
                test_id="TRACE-003",
                test_name="Direct L2 Adjacency Detected",
                category="Traceroute Analysis",
                status=STATUS_PASS,
                severity=SEVERITY_INFO,
                description="Check for missing L3 segmentation between VLANs",
                observation="All traced hosts show proper L3 routing (multiple hops), indicating segmentation is in place",
                source_vlan=source.get("name", ""),
            )

        self.scan_config["host_results"] = host_results_map
