import socket
import struct
import random
import time
from modules.base import BaseModule, Finding, HostResult, PortResult
from config import *


class DNSCheckModule(BaseModule):
    MODULE_NAME = "DNS Analysis"
    MODULE_DESCRIPTION = "Tests DNS server accessibility, resolution, and zone transfer across VLANs"

    def _build_dns_query(self, domain, qtype=1, rd=1):
        txn_id = random.randint(0, 0xFFFF)
        flags = (rd << 8)
        header = struct.pack("!HHHHHH", txn_id, flags, 1, 0, 0, 0)

        qname = b""
        for label in domain.split("."):
            qname += struct.pack("B", len(label)) + label.encode("ascii")
        qname += b"\x00"

        question = qname + struct.pack("!HH", qtype, 1)
        return txn_id, header + question

    def _parse_dns_response(self, data, txn_id):
        if len(data) < 12:
            return None
        resp_id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", data[:12])
        if resp_id != txn_id:
            return None

        rcode = flags & 0x0F
        return {
            "rcode": rcode,
            "answer_count": ancount,
            "authority_count": nscount,
            "additional_count": arcount,
            "raw_length": len(data),
            "data": data,
        }

    def _send_dns_query(self, dns_ip, domain, qtype=1, timeout=3):
        txn_id, query = self._build_dns_query(domain, qtype)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(query, (dns_ip, 53))
            data, _ = sock.recvfrom(4096)
            sock.close()
            return self._parse_dns_response(data, txn_id)
        except (socket.timeout, OSError):
            return None

    def _find_dns_servers(self):
        dns_servers = []
        speed = self.get_speed_config()
        timeout = speed.get("timeout", 1.5)

        src_gw = self.scan_config.get("source_vlan", {}).get("gateway", "")
        if src_gw:
            if self._test_dns_port(src_gw, timeout):
                dns_servers.append({"ip": src_gw, "source": "source_gateway"})

        for target in self.scan_config.get("targets", []):
            tgt_gw = target.get("gateway", "")
            if tgt_gw and tgt_gw not in [d["ip"] for d in dns_servers]:
                if self._test_dns_port(tgt_gw, timeout):
                    dns_servers.append({"ip": tgt_gw, "source": f"gateway_{target.get('name', 'unknown')}"})

        alive_hosts = self.scan_config.get("alive_hosts", {})
        for ip, host in alive_hosts.items():
            if ip in [d["ip"] for d in dns_servers]:
                continue
            if hasattr(host, "open_ports"):
                for pr in host.open_ports:
                    if hasattr(pr, "port") and pr.port == 53:
                        dns_servers.append({"ip": ip, "source": "discovered_host"})
                        break
            elif isinstance(host, dict):
                ports = host.get("open_ports", [])
                if 53 in ports or any(getattr(p, "port", p) == 53 for p in ports if hasattr(p, "port")):
                    dns_servers.append({"ip": ip, "source": "discovered_host"})

        system_dns = self._get_system_dns()
        for dns_ip in system_dns:
            if dns_ip not in [d["ip"] for d in dns_servers]:
                if self._test_dns_port(dns_ip, timeout):
                    dns_servers.append({"ip": dns_ip, "source": "system_resolv_conf"})

        return dns_servers

    def _get_system_dns(self):
        servers = []
        try:
            with open("/etc/resolv.conf", "r") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("nameserver"):
                        parts = line.split()
                        if len(parts) >= 2:
                            servers.append(parts[1])
        except (IOError, OSError):
            pass
        return servers

    def _test_dns_port(self, ip, timeout=2):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, 53))
            sock.close()
            if result == 0:
                return True
        except (socket.timeout, OSError):
            pass

        resp = self._send_dns_query(ip, "localhost", qtype=1, timeout=timeout)
        return resp is not None

    def _test_resolution(self, dns_ip):
        results = {"internal": [], "external": []}
        timeout = self.get_speed_config().get("timeout", 2)

        external_domains = ["google.com", "cloudflare.com"]
        for domain in external_domains:
            resp = self._send_dns_query(dns_ip, domain, qtype=1, timeout=timeout)
            if resp and resp["rcode"] == 0 and resp["answer_count"] > 0:
                results["external"].append({"domain": domain, "resolved": True, "answers": resp["answer_count"]})
            elif resp:
                results["external"].append({"domain": domain, "resolved": False, "rcode": resp["rcode"]})
            else:
                results["external"].append({"domain": domain, "resolved": False, "rcode": "timeout"})

        internal_domains = []
        src = self.scan_config.get("source_vlan", {})
        domain = src.get("domain", "")
        if domain:
            internal_domains.append(f"dc01.{domain}")
            internal_domains.append(domain)

        for target in self.scan_config.get("targets", []):
            td = target.get("domain", "")
            if td and td not in internal_domains:
                internal_domains.append(td)

        if not internal_domains:
            internal_domains = ["corp.local", "internal.local"]

        for domain in internal_domains[:4]:
            resp = self._send_dns_query(dns_ip, domain, qtype=1, timeout=timeout)
            if resp and resp["rcode"] == 0 and resp["answer_count"] > 0:
                results["internal"].append({"domain": domain, "resolved": True, "answers": resp["answer_count"]})
            elif resp:
                results["internal"].append({"domain": domain, "resolved": False, "rcode": resp["rcode"]})
            else:
                results["internal"].append({"domain": domain, "resolved": False, "rcode": "timeout"})

        return results

    def _test_zone_transfer(self, dns_ip, domain, timeout=5):
        txn_id = random.randint(0, 0xFFFF)
        flags = 0
        header = struct.pack("!HHHHHH", txn_id, flags, 1, 0, 0, 0)

        qname = b""
        for label in domain.split("."):
            qname += struct.pack("B", len(label)) + label.encode("ascii")
        qname += b"\x00"

        # AXFR = qtype 252
        question = qname + struct.pack("!HH", 252, 1)
        dns_msg = header + question

        tcp_msg = struct.pack("!H", len(dns_msg)) + dns_msg

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((dns_ip, 53))
            sock.sendall(tcp_msg)

            resp_len_bytes = sock.recv(2)
            if len(resp_len_bytes) < 2:
                sock.close()
                return {"success": False, "reason": "no_response"}

            resp_len = struct.unpack("!H", resp_len_bytes)[0]
            data = b""
            while len(data) < resp_len:
                chunk = sock.recv(resp_len - len(data))
                if not chunk:
                    break
                data += chunk
            sock.close()

            if len(data) < 12:
                return {"success": False, "reason": "short_response"}

            resp_flags = struct.unpack("!H", data[2:4])[0]
            rcode = resp_flags & 0x0F
            ancount = struct.unpack("!H", data[6:8])[0]

            if rcode == 0 and ancount > 0:
                return {"success": True, "record_count": ancount, "response_size": len(data)}
            elif rcode == 5:
                return {"success": False, "reason": "refused"}
            elif rcode == 9:
                return {"success": False, "reason": "not_authorized"}
            else:
                return {"success": False, "reason": f"rcode_{rcode}"}
        except socket.timeout:
            return {"success": False, "reason": "timeout"}
        except (ConnectionRefusedError, ConnectionResetError):
            return {"success": False, "reason": "connection_refused"}
        except OSError as e:
            return {"success": False, "reason": str(e)}

    def execute(self):
        src_vlan = self.scan_config.get("source_vlan", {})
        src_name = src_vlan.get("name", "Source VLAN")

        # DNS-001: Find Reachable DNS Servers
        dns_servers = self._find_dns_servers()

        if dns_servers:
            self.add_finding(
                test_id="DNS-001",
                test_name="DNS Server Discovery",
                category=self.MODULE_NAME,
                status=STATUS_INFO,
                severity=SEVERITY_INFO,
                description="Identified DNS servers reachable from the source VLAN.",
                observation=f"Found {len(dns_servers)} reachable DNS server(s): "
                            f"{', '.join(d['ip'] + ' (' + d['source'] + ')' for d in dns_servers)}.",
                details={"dns_servers": dns_servers},
                source_vlan=src_name,
            )
        else:
            self.add_finding(
                test_id="DNS-001",
                test_name="DNS Server Discovery",
                category=self.MODULE_NAME,
                status=STATUS_INFO,
                severity=SEVERITY_INFO,
                description="No DNS servers found reachable from the source VLAN.",
                observation="Port 53 is not open on any tested host, gateway, or system resolver.",
                source_vlan=src_name,
            )
            return

        # DNS-002: Internal Name Resolution Cross-VLAN
        for dns in dns_servers:
            dns_ip = dns["ip"]
            resolution = self._test_resolution(dns_ip)

            internal_resolved = [r for r in resolution.get("internal", []) if r.get("resolved")]
            external_resolved = [r for r in resolution.get("external", []) if r.get("resolved")]

            if internal_resolved:
                domains_str = ", ".join(r["domain"] for r in internal_resolved)
                severity = SEVERITY_MEDIUM
                if dns["source"] != "source_gateway":
                    severity = SEVERITY_HIGH

                self.add_finding(
                    test_id="DNS-002",
                    test_name=f"Internal DNS Resolution via {dns_ip}",
                    category=self.MODULE_NAME,
                    status=STATUS_WARN,
                    severity=severity,
                    description=f"Internal hostnames are resolvable via DNS server {dns_ip}.",
                    observation=f"DNS server {dns_ip} ({dns['source']}) resolves internal names: {domains_str}. "
                                f"External resolution: {'yes' if external_resolved else 'no'}. "
                                "Internal name resolution across VLANs can aid lateral movement.",
                    remediation="Implement split DNS. Restrict internal DNS to authorized VLANs only. "
                                "Use DNS views/policies to limit internal zone access.",
                    affected_objects=[dns_ip],
                    details={"dns_server": dns_ip, "resolution": resolution},
                    source_vlan=src_name,
                    target_vlan=dns.get("source", ""),
                )
            elif external_resolved:
                self.add_finding(
                    test_id="DNS-002",
                    test_name=f"DNS Resolution via {dns_ip}",
                    category=self.MODULE_NAME,
                    status=STATUS_PASS,
                    severity=SEVERITY_INFO,
                    description=f"DNS server {dns_ip} resolves external names only (no internal leakage).",
                    observation=f"External domains resolved: {', '.join(r['domain'] for r in external_resolved)}. "
                                "No internal names were resolvable.",
                    details={"dns_server": dns_ip, "resolution": resolution},
                    source_vlan=src_name,
                )
            else:
                self.add_finding(
                    test_id="DNS-002",
                    test_name=f"DNS Resolution via {dns_ip}",
                    category=self.MODULE_NAME,
                    status=STATUS_INFO,
                    severity=SEVERITY_INFO,
                    description=f"DNS server {dns_ip} did not resolve any test queries.",
                    observation="Server is reachable on port 53 but did not return answers. "
                                "May require specific query format or authentication.",
                    details={"dns_server": dns_ip, "resolution": resolution},
                    source_vlan=src_name,
                )

        # DNS-003: Zone Transfer Test
        domains_to_test = set()
        domain = src_vlan.get("domain", "")
        if domain:
            domains_to_test.add(domain)
        for target in self.scan_config.get("targets", []):
            td = target.get("domain", "")
            if td:
                domains_to_test.add(td)

        if not domains_to_test:
            domains_to_test = {"corp.local"}

        zone_transfer_found = False
        for dns in dns_servers:
            dns_ip = dns["ip"]
            for domain in domains_to_test:
                zt_result = self._test_zone_transfer(dns_ip, domain)
                if zt_result.get("success"):
                    zone_transfer_found = True
                    self.add_finding(
                        test_id="DNS-003",
                        test_name=f"DNS Zone Transfer ({domain} via {dns_ip})",
                        category=self.MODULE_NAME,
                        status=STATUS_FAIL,
                        severity=SEVERITY_CRITICAL,
                        description=f"DNS zone transfer (AXFR) successful for '{domain}' from {dns_ip}.",
                        observation=f"Zone transfer returned {zt_result.get('record_count', '?')} records "
                                    f"({zt_result.get('response_size', '?')} bytes). "
                                    "Full zone data including all hostnames, IPs, and service records is exposed. "
                                    "This provides a complete network map to an attacker.",
                        remediation="Restrict zone transfers to authorized secondary DNS servers only. "
                                    "Configure 'allow-transfer' in BIND or equivalent in your DNS software. "
                                    "Use TSIG keys for zone transfer authentication.",
                        affected_objects=[dns_ip],
                        details={"dns_server": dns_ip, "domain": domain, "result": zt_result},
                        source_vlan=src_name,
                        references=["CWE-200 - Information Exposure", "NIST SP 800-81 - DNS Security"],
                    )

        if not zone_transfer_found:
            self.add_finding(
                test_id="DNS-003",
                test_name="DNS Zone Transfer Test",
                category=self.MODULE_NAME,
                status=STATUS_PASS,
                severity=SEVERITY_INFO,
                description="DNS zone transfers (AXFR) are properly restricted.",
                observation=f"Tested {len(dns_servers)} server(s) across {len(domains_to_test)} domain(s). "
                            "All AXFR requests were refused or timed out.",
                source_vlan=src_name,
            )

        # DNS-004: DNS Accessibility Summary
        cross_vlan_dns = [d for d in dns_servers if d["source"] not in ("source_gateway", "system_resolv_conf")]
        self.add_finding(
            test_id="DNS-004",
            test_name="DNS Server Accessibility Summary",
            category=self.MODULE_NAME,
            status=STATUS_WARN if cross_vlan_dns else STATUS_PASS,
            severity=SEVERITY_MEDIUM if cross_vlan_dns else SEVERITY_INFO,
            description="Summary of DNS server accessibility from the source VLAN.",
            observation=f"Total DNS servers reachable: {len(dns_servers)}. "
                        f"Cross-VLAN DNS servers: {len(cross_vlan_dns)}. "
                        f"Zone transfer vulnerable: {'yes' if zone_transfer_found else 'no'}. "
                        + (f"Cross-VLAN DNS access to: {', '.join(d['ip'] for d in cross_vlan_dns)}." if cross_vlan_dns else
                           "DNS access is limited to expected servers."),
            remediation="Ensure DNS access is restricted to authorized DNS servers per VLAN. "
                        "Use firewall rules to prevent cross-VLAN DNS queries to unauthorized servers."
                        if cross_vlan_dns else "",
            details={
                "total_servers": len(dns_servers),
                "cross_vlan_servers": cross_vlan_dns,
                "zone_transfer_vulnerable": zone_transfer_found,
            },
            source_vlan=src_name,
        )
