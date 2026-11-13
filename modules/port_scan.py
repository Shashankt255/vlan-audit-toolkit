import os
import time
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from modules.base import BaseModule, Finding, HostResult, PortResult
from config import *

HAS_SCAPY = False
try:
    from scapy.all import IP, TCP, UDP, ICMP, sr, sr1, conf
    conf.verb = 0
    HAS_SCAPY = True
except ImportError:
    pass


class PortScanModule(BaseModule):
    MODULE_NAME = "Port Scan"
    MODULE_DESCRIPTION = "TCP SYN and UDP port scanning on alive hosts"

    def _is_root(self):
        return os.geteuid() == 0

    def _determine_ports(self, protocol="tcp"):
        if protocol == "tcp":
            if self.options.get("full_ports"):
                return list(range(1, 65536))
            top_n = self.options.get("top_ports")
            if top_n:
                return TOP_100_TCP_PORTS[:int(top_n)]
            custom = self.scan_config.get("tcp_ports")
            if custom:
                return custom
            return TOP_100_TCP_PORTS
        else:
            custom = self.scan_config.get("udp_ports")
            if custom:
                return custom
            return TOP_UDP_PORTS

    def _tcp_syn_scan(self, ip, ports):
        speed = self.get_speed_config()
        results = []

        if HAS_SCAPY and self._is_root():
            results = self._tcp_syn_scapy(ip, ports, speed)
        else:
            results = self._tcp_connect_scan(ip, ports, speed)

        return results

    def _tcp_syn_scapy(self, ip, ports, speed):
        results = []
        batch_size = max(1, speed["pps"])
        timeout = speed["timeout"]

        for i in range(0, len(ports), batch_size):
            batch = ports[i:i + batch_size]
            try:
                pkts = [IP(dst=ip) / TCP(dport=p, flags="S") for p in batch]
                ans, unans = sr(pkts, timeout=timeout, verbose=0)

                answered_ports = set()
                for snd, rcv in ans:
                    port = snd[TCP].dport
                    answered_ports.add(port)
                    if rcv.haslayer(TCP):
                        flags = rcv[TCP].flags
                        if flags == 0x12:  # SYN-ACK
                            results.append(PortResult(
                                port=port, protocol="tcp", status="OPEN",
                                service=SERVICE_BANNERS.get(port, ""),
                            ))
                            # RST to close
                            try:
                                sr1(IP(dst=ip) / TCP(dport=port, flags="R"),
                                    timeout=0.5, verbose=0)
                            except Exception:
                                pass
                        elif flags & 0x04:  # RST
                            results.append(PortResult(
                                port=port, protocol="tcp", status="CLOSED",
                            ))
                    elif rcv.haslayer(ICMP):
                        results.append(PortResult(
                            port=port, protocol="tcp", status="FILTERED",
                        ))

                for unanswered in unans:
                    port = unanswered[TCP].dport
                    results.append(PortResult(
                        port=port, protocol="tcp", status="FILTERED",
                    ))

            except Exception:
                pass

            if speed["delay"] > 0 and i + batch_size < len(ports):
                time.sleep(speed["delay"] * len(batch))

        return results

    def _tcp_connect_scan(self, ip, ports, speed):
        results = []

        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(speed["timeout"])
                result = sock.connect_ex((ip, port))
                sock.close()
                if result == 0:
                    return PortResult(
                        port=port, protocol="tcp", status="OPEN",
                        service=SERVICE_BANNERS.get(port, ""),
                    )
                elif result == 111:  # Connection refused
                    return PortResult(port=port, protocol="tcp", status="CLOSED")
                else:
                    return PortResult(port=port, protocol="tcp", status="FILTERED")
            except socket.timeout:
                return PortResult(port=port, protocol="tcp", status="FILTERED")
            except Exception:
                return PortResult(port=port, protocol="tcp", status="FILTERED")

        workers = min(100, speed["pps"])
        with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
            futures = {pool.submit(scan_port, p): p for p in ports}
            for f in as_completed(futures):
                r = f.result()
                if r:
                    results.append(r)

        return results

    def _udp_scan(self, ip, ports):
        if not HAS_SCAPY or not self._is_root():
            return []

        speed = self.get_speed_config()
        results = []
        timeout = speed["timeout"]

        for port in ports:
            try:
                pkt = IP(dst=ip) / UDP(dport=port)
                resp = sr1(pkt, timeout=timeout, verbose=0)

                if resp is None:
                    results.append(PortResult(
                        port=port, protocol="udp", status="OPEN|FILTERED",
                        service=SERVICE_BANNERS.get(port, ""),
                    ))
                elif resp.haslayer(UDP):
                    results.append(PortResult(
                        port=port, protocol="udp", status="OPEN",
                        service=SERVICE_BANNERS.get(port, ""),
                    ))
                elif resp.haslayer(ICMP):
                    icmp_type = resp[ICMP].type
                    icmp_code = resp[ICMP].code
                    if icmp_type == 3 and icmp_code == 3:
                        results.append(PortResult(
                            port=port, protocol="udp", status="CLOSED",
                        ))
                    elif icmp_type == 3:
                        results.append(PortResult(
                            port=port, protocol="udp", status="FILTERED",
                        ))
            except Exception:
                pass

            if speed["delay"] > 0:
                time.sleep(speed["delay"])

        return results

    def execute(self):
        source = self.scan_config.get("source_vlan", {})
        alive_hosts = self.scan_config.get("alive_hosts", [])
        host_results_map = self.scan_config.get("host_results", {})

        if not alive_hosts:
            self.add_finding(
                test_id="PORT-001",
                test_name="TCP Port Scan",
                category="Port Scan",
                status=STATUS_PASS,
                severity=SEVERITY_INFO,
                description="TCP port scan of reachable cross-VLAN hosts",
                observation="No alive hosts to scan",
                source_vlan=source.get("name", ""),
            )
            return

        tcp_ports = self._determine_ports("tcp")
        do_udp = self.options.get("udp", False)
        udp_ports = self._determine_ports("udp") if do_udp else []

        all_open_tcp = {}
        all_open_udp = {}
        critical_services = []

        for ip in alive_hosts:
            hr = host_results_map.get(ip, HostResult(ip=ip, is_alive=True))

            # TCP scan
            tcp_results = self._tcp_syn_scan(ip, tcp_ports)
            open_tcp = [r for r in tcp_results if r.status == "OPEN"]
            filtered_tcp = [r for r in tcp_results if r.status == "FILTERED"]

            hr.open_ports = [r.port for r in open_tcp]
            hr.filtered_ports = [r.port for r in filtered_tcp]

            if open_tcp:
                all_open_tcp[ip] = open_tcp

            for pr in open_tcp:
                if pr.port in CRITICAL_PORTS:
                    svc_name, sev = CRITICAL_PORTS[pr.port]
                    critical_services.append({
                        "ip": ip, "port": pr.port,
                        "service": svc_name, "severity": sev,
                    })

            # UDP scan
            if do_udp:
                udp_results = self._udp_scan(ip, udp_ports)
                open_udp = [r for r in udp_results if r.status in ("OPEN", "OPEN|FILTERED")]
                if open_udp:
                    all_open_udp[ip] = open_udp
                    hr.open_ports.extend([r.port for r in open_udp])

            # Update host_results_map
            host_results_map[ip] = hr
            if hr not in self.host_results:
                self.host_results.append(hr)

        # PORT-001: TCP open ports summary
        total_open = sum(len(v) for v in all_open_tcp.values())
        status = STATUS_FAIL if total_open > 0 else STATUS_PASS
        severity = SEVERITY_HIGH if total_open > 0 else SEVERITY_INFO

        port_details = {}
        for ip, ports_list in all_open_tcp.items():
            port_details[ip] = [
                {"port": p.port, "service": p.service or SERVICE_BANNERS.get(p.port, "unknown")}
                for p in ports_list
            ]

        self.add_finding(
            test_id="PORT-001",
            test_name="TCP Open Ports",
            category="Port Scan",
            status=status,
            severity=severity,
            description=f"TCP port scan across {len(alive_hosts)} alive hosts ({len(tcp_ports)} ports per host)",
            observation=f"{total_open} open TCP ports found across {len(all_open_tcp)} hosts",
            remediation="Review firewall rules to restrict unnecessary cross-VLAN TCP access" if total_open > 0 else "",
            affected_objects=list(all_open_tcp.keys()),
            details={"open_ports_by_host": port_details, "ports_scanned": len(tcp_ports)},
            source_vlan=source.get("name", ""),
        )

        # PORT-002: UDP open ports summary
        if do_udp:
            total_udp = sum(len(v) for v in all_open_udp.values())
            udp_details = {}
            for ip, ports_list in all_open_udp.items():
                udp_details[ip] = [
                    {"port": p.port, "status": p.status, "service": p.service or SERVICE_BANNERS.get(p.port, "unknown")}
                    for p in ports_list
                ]

            self.add_finding(
                test_id="PORT-002",
                test_name="UDP Open Ports",
                category="Port Scan",
                status=STATUS_FAIL if total_udp > 0 else STATUS_PASS,
                severity=SEVERITY_MEDIUM if total_udp > 0 else SEVERITY_INFO,
                description=f"UDP port scan across {len(alive_hosts)} alive hosts ({len(udp_ports)} ports per host)",
                observation=f"{total_udp} open/filtered UDP ports found across {len(all_open_udp)} hosts",
                remediation="Review UDP firewall rules — SNMP, DNS, and NTP are common cross-VLAN leak vectors" if total_udp > 0 else "",
                affected_objects=list(all_open_udp.keys()),
                details={"open_ports_by_host": udp_details},
                source_vlan=source.get("name", ""),
            )

        # PORT-003: Critical services accessible cross-VLAN
        if critical_services:
            crit_only = [c for c in critical_services if c["severity"] == SEVERITY_CRITICAL]
            high_only = [c for c in critical_services if c["severity"] == SEVERITY_HIGH]

            sev = SEVERITY_CRITICAL if crit_only else SEVERITY_HIGH
            self.add_finding(
                test_id="PORT-003",
                test_name="Critical Services Accessible Cross-VLAN",
                category="Port Scan",
                status=STATUS_FAIL,
                severity=sev,
                description="Critical/high-risk services accessible from source VLAN",
                observation=f"{len(critical_services)} critical/high-risk services reachable cross-VLAN "
                            f"({len(crit_only)} critical, {len(high_only)} high)",
                remediation="Immediately restrict access to database, remote desktop, and management services across VLAN boundaries",
                affected_objects=[f"{c['ip']}:{c['port']} ({c['service']})" for c in critical_services],
                details={"critical_services": critical_services},
                source_vlan=source.get("name", ""),
            )
        else:
            self.add_finding(
                test_id="PORT-003",
                test_name="Critical Services Accessible Cross-VLAN",
                category="Port Scan",
                status=STATUS_PASS,
                severity=SEVERITY_INFO,
                description="Check for critical/high-risk services accessible from source VLAN",
                observation="No critical services found accessible cross-VLAN",
                source_vlan=source.get("name", ""),
            )

        # PORT-004: Full port matrix
        matrix = {}
        for ip in alive_hosts:
            hr = host_results_map.get(ip)
            if hr:
                matrix[ip] = {
                    "open": hr.open_ports,
                    "filtered": len(hr.filtered_ports),
                    "os_guess": hr.os_guess,
                }

        self.add_finding(
            test_id="PORT-004",
            test_name="Port Scan Matrix",
            category="Port Scan",
            status=STATUS_INFO,
            severity=SEVERITY_INFO,
            description="Complete port scan results matrix for all alive hosts",
            observation=f"Scan complete: {len(alive_hosts)} hosts, {len(tcp_ports)} TCP ports"
                        + (f", {len(udp_ports)} UDP ports" if do_udp else ""),
            details={"matrix": matrix},
            source_vlan=source.get("name", ""),
        )

        # Propagate updated host results
        self.scan_config["host_results"] = host_results_map
