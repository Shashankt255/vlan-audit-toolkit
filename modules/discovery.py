import os
import time
import socket
import struct
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

from modules.base import BaseModule, Finding, HostResult
from config import *

HAS_SCAPY = False
try:
    from scapy.all import (
        IP, ICMP, TCP, Ether, ARP, sr, sr1, srp, conf
    )
    conf.verb = 0
    HAS_SCAPY = True
except ImportError:
    pass


class DiscoveryModule(BaseModule):
    MODULE_NAME = "Host Discovery"
    MODULE_DESCRIPTION = "Discover alive hosts via ICMP sweep, ARP scan, and TCP fallback"

    def _is_root(self):
        return os.geteuid() == 0

    def _os_fingerprint(self, ttl):
        if ttl is None:
            return "Unknown"
        for (low, high), os_name in TTL_OS_MAP.items():
            if low <= ttl <= high:
                return os_name
        return "Unknown"

    def _expand_ranges(self, ranges):
        hosts = []
        for r in ranges:
            try:
                net = ipaddress.ip_network(r, strict=False)
                for ip in net.hosts():
                    hosts.append(str(ip))
            except ValueError:
                if "-" in r:
                    parts = r.split("-")
                    if len(parts) == 2:
                        try:
                            base = parts[0].strip()
                            end_octet = int(parts[1].strip())
                            base_parts = base.split(".")
                            start_octet = int(base_parts[3])
                            for i in range(start_octet, end_octet + 1):
                                hosts.append(f"{base_parts[0]}.{base_parts[1]}.{base_parts[2]}.{i}")
                        except (IndexError, ValueError):
                            pass
                else:
                    hosts.append(r)
        return hosts

    def _arp_local(self):
        source = self.scan_config.get("source_vlan", {})
        subnet = source.get("subnet")
        if not subnet or not HAS_SCAPY or not self._is_root():
            return []

        iface = self.options.get("interface")
        try:
            ans, _ = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet),
                timeout=self.get_speed_config()["timeout"],
                iface=iface,
                verbose=0,
            )
            neighbors = []
            for snd, rcv in ans:
                neighbors.append({
                    "ip": rcv.psrc,
                    "mac": rcv.hwsrc,
                })
            return neighbors
        except Exception:
            return []

    def _icmp_sweep(self, target_ips):
        speed = self.get_speed_config()
        alive = []

        if HAS_SCAPY and self._is_root():
            alive = self._icmp_sweep_scapy(target_ips, speed)
        else:
            alive = self._icmp_sweep_socket(target_ips, speed)

        if not alive:
            alive = self._tcp_fallback_sweep(target_ips, speed)

        return alive

    def _icmp_sweep_scapy(self, target_ips, speed):
        alive = []
        batch_size = max(1, speed["pps"])
        timeout = speed["timeout"]

        for i in range(0, len(target_ips), batch_size):
            batch = target_ips[i:i + batch_size]
            try:
                pkts = [IP(dst=ip) / ICMP() for ip in batch]
                ans, _ = sr(pkts, timeout=timeout, verbose=0)
                for snd, rcv in ans:
                    if rcv.haslayer(ICMP):
                        icmp_type = rcv[ICMP].type
                        if icmp_type == 0:
                            ttl = rcv[IP].ttl
                            alive.append({"ip": rcv[IP].src, "ttl": ttl})
            except Exception:
                pass
            if speed["delay"] > 0:
                time.sleep(speed["delay"] * len(batch))

        return alive

    def _icmp_sweep_socket(self, target_ips, speed):
        alive = []

        def ping_one(ip):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(speed["timeout"])
                result = sock.connect_ex((ip, 80))
                sock.close()
                if result == 0:
                    return {"ip": ip, "ttl": None}
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(speed["timeout"])
                result = sock.connect_ex((ip, 443))
                sock.close()
                if result == 0:
                    return {"ip": ip, "ttl": None}
            except Exception:
                pass
            return None

        workers = min(50, speed["pps"])
        with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
            futures = {pool.submit(ping_one, ip): ip for ip in target_ips}
            for f in as_completed(futures):
                r = f.result()
                if r:
                    alive.append(r)

        return alive

    def _tcp_fallback_sweep(self, target_ips, speed):
        alive = []
        ports_to_try = [80, 443, 22, 445, 3389]

        def probe(ip):
            for port in ports_to_try:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(speed["timeout"])
                    if sock.connect_ex((ip, port)) == 0:
                        sock.close()
                        return {"ip": ip, "ttl": None}
                    sock.close()
                except Exception:
                    pass
            return None

        workers = min(50, speed["pps"])
        with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
            futures = {pool.submit(probe, ip): ip for ip in target_ips}
            for f in as_completed(futures):
                r = f.result()
                if r:
                    alive.append(r)

        return alive

    def execute(self):
        source = self.scan_config.get("source_vlan", {})
        targets = self.scan_config.get("targets", [])

        # DISC-001: ARP scan local VLAN
        neighbors = self._arp_local()
        if neighbors:
            self.add_finding(
                test_id="DISC-001",
                test_name="Local VLAN Neighbors",
                category="Host Discovery",
                status=STATUS_INFO,
                severity=SEVERITY_INFO,
                description="ARP scan of the local VLAN subnet to discover neighbors",
                observation=f"Found {len(neighbors)} hosts on source VLAN {source.get('name', 'N/A')} ({source.get('subnet', 'N/A')})",
                affected_objects=[n["ip"] for n in neighbors],
                details={"neighbors": neighbors},
                source_vlan=source.get("name", ""),
            )
        else:
            method = "No root/scapy" if (not HAS_SCAPY or not self._is_root()) else "No results"
            self.add_finding(
                test_id="DISC-001",
                test_name="Local VLAN Neighbors",
                category="Host Discovery",
                status=STATUS_INFO,
                severity=SEVERITY_INFO,
                description="ARP scan of the local VLAN subnet to discover neighbors",
                observation=f"ARP scan skipped or returned no results ({method})",
                source_vlan=source.get("name", ""),
            )

        # DISC-002: ICMP sweep each target VLAN
        all_alive = []
        for target in targets:
            target_name = target.get("name", "Unknown")
            target_vlan = target.get("vlan_id", "N/A")
            ranges = target.get("ranges", [])

            ips = self._expand_ranges(ranges)
            if not ips:
                continue

            alive = self._icmp_sweep(ips)

            for host_info in alive:
                hr = HostResult(
                    ip=host_info["ip"],
                    is_alive=True,
                    ttl=host_info.get("ttl"),
                    os_guess=self._os_fingerprint(host_info.get("ttl")),
                )
                try:
                    hostname = socket.gethostbyaddr(host_info["ip"])[0]
                    hr.hostname = hostname
                except Exception:
                    pass
                self.host_results.append(hr)
                all_alive.append(host_info["ip"])

            status = STATUS_FAIL if alive else STATUS_PASS
            severity = SEVERITY_HIGH if alive else SEVERITY_INFO

            self.add_finding(
                test_id="DISC-002",
                test_name="Cross-VLAN Host Reachability",
                category="Host Discovery",
                status=status,
                severity=severity,
                description=f"ICMP/TCP sweep to detect reachable hosts in target VLAN {target_name} (VLAN {target_vlan})",
                observation=f"{len(alive)} of {len(ips)} hosts reachable in {target_name} (VLAN {target_vlan})",
                remediation="Review ACLs and firewall rules to restrict unnecessary cross-VLAN traffic" if alive else "",
                affected_objects=[h["ip"] for h in alive],
                details={
                    "target_vlan": target_name,
                    "vlan_id": target_vlan,
                    "total_scanned": len(ips),
                    "alive_count": len(alive),
                    "alive_hosts": [h["ip"] for h in alive],
                },
                source_vlan=source.get("name", ""),
                target_vlan=target_name,
            )

        # DISC-003: OS distribution summary
        os_dist = {}
        for hr in self.host_results:
            os_name = hr.os_guess or "Unknown"
            os_dist.setdefault(os_name, []).append(hr.ip)

        self.add_finding(
            test_id="DISC-003",
            test_name="OS Distribution",
            category="Host Discovery",
            status=STATUS_INFO,
            severity=SEVERITY_INFO,
            description="Operating system fingerprinting based on TTL analysis",
            observation=f"Detected {len(self.host_results)} alive hosts across target VLANs: " +
                        ", ".join(f"{k}: {len(v)}" for k, v in os_dist.items()) if os_dist else "No hosts detected",
            details={"os_distribution": {k: v for k, v in os_dist.items()}},
            source_vlan=source.get("name", ""),
        )

        # Store alive hosts for downstream modules
        self.scan_config["alive_hosts"] = all_alive
        self.scan_config["host_results"] = {hr.ip: hr for hr in self.host_results}
