import os
import socket
import struct
import time
from modules.base import BaseModule, Finding, HostResult, PortResult
from config import *

try:
    from scapy.all import IP, UDP, Raw, sr1, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class ManagementCheckModule(BaseModule):
    MODULE_NAME = "Management Plane Check"
    MODULE_DESCRIPTION = "Tests reachability of network device management interfaces across VLANs"

    def _check_management_ports(self, ip):
        open_ports = []
        speed = self.get_speed_config()
        timeout = speed.get("timeout", 1.5)
        delay = speed.get("delay", 0.005)

        for port in MANAGEMENT_PORTS:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    banner = self._grab_banner(sock, port)
                    open_ports.append({
                        "port": port,
                        "service": CRITICAL_PORTS.get(port, (SERVICE_BANNERS.get(port, "unknown"), SEVERITY_INFO))[0],
                        "banner": banner,
                    })
                sock.close()
            except (socket.timeout, OSError):
                pass
            time.sleep(delay)
        return open_ports

    def _grab_banner(self, sock, port):
        try:
            if port in (80, 443, 8080, 8443, 9090, 10000):
                sock.sendall(b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n")
            elif port == 22:
                pass
            sock.settimeout(2)
            banner = sock.recv(1024)
            return banner.decode("ascii", errors="replace").strip()[:200]
        except Exception:
            return ""

    def _check_snmp(self, ip):
        timeout = self.get_speed_config().get("timeout", 1.5)

        if SCAPY_AVAILABLE and os.geteuid() == 0:
            return self._check_snmp_scapy(ip, timeout)
        return self._check_snmp_socket(ip, timeout)

    def _check_snmp_scapy(self, ip, timeout):
        community = b"public"
        # SNMPv2c GET sysDescr.0 (1.3.6.1.2.1.1.1.0)
        snmp_get = (
            b'\x30'  # SEQUENCE
            b'\x29'
            b'\x02\x01\x01'  # version: v2c
            b'\x04\x06' + community +  # community
            b'\xa0\x1c'  # GetRequest
            b'\x02\x04\x00\x00\x00\x01'  # request-id
            b'\x02\x01\x00'  # error-status
            b'\x02\x01\x00'  # error-index
            b'\x30\x0e'  # varbind list
            b'\x30\x0c'
            b'\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00'  # sysDescr.0
            b'\x05\x00'  # NULL value
        )
        conf.verb = 0
        try:
            resp = sr1(IP(dst=ip) / UDP(sport=16161, dport=161) / Raw(load=snmp_get),
                        timeout=timeout, verbose=0)
            if resp and resp.haslayer(Raw):
                payload = bytes(resp[Raw].load)
                return {"accessible": True, "community": "public", "response": payload.decode("ascii", errors="replace")[:200]}
        except Exception:
            pass
        return {"accessible": False}

    def _check_snmp_socket(self, ip, timeout):
        community = b"public"
        snmp_get = (
            b'\x30\x29'
            b'\x02\x01\x01'
            b'\x04\x06' + community +
            b'\xa0\x1c'
            b'\x02\x04\x00\x00\x00\x01'
            b'\x02\x01\x00'
            b'\x02\x01\x00'
            b'\x30\x0e'
            b'\x30\x0c'
            b'\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00'
            b'\x05\x00'
        )
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(snmp_get, (ip, 161))
            data, _ = sock.recvfrom(4096)
            sock.close()
            if data and len(data) > 10:
                return {"accessible": True, "community": "public", "response": data.decode("ascii", errors="replace")[:200]}
        except (socket.timeout, OSError):
            pass
        return {"accessible": False}

    def _identify_device(self, ip, open_ports, banners):
        port_nums = [p["port"] for p in open_ports]
        all_banners = " ".join(p.get("banner", "") for p in open_ports).lower()

        if 830 in port_nums:
            return "Network Device (NETCONF)"
        if 161 in port_nums and 22 in port_nums and 80 not in port_nums:
            return "Network Switch/Router"
        if any(kw in all_banners for kw in ["cisco", "ios", "juniper", "junos", "arista", "eos"]):
            return "Network Device"
        if any(kw in all_banners for kw in ["fortigate", "paloalto", "pan-os", "checkpoint", "asa"]):
            return "Firewall"
        if 23 in port_nums and 161 in port_nums:
            return "Legacy Network Device"
        if set(port_nums) & {80, 443, 8080, 8443, 9090}:
            if set(port_nums) & {22, 161}:
                return "Network Appliance"
            return "Server/Appliance"
        if 22 in port_nums or 23 in port_nums:
            return "Managed Device"
        return "Unknown"

    def _collect_gateway_ips(self):
        gateways = []
        src = self.scan_config.get("source_vlan", {})
        src_gw = src.get("gateway", "")
        if src_gw:
            gateways.append({"ip": src_gw, "vlan": src.get("name", "Source VLAN"), "role": "source_gateway"})

        for target in self.scan_config.get("targets", []):
            tgt_gw = target.get("gateway", "")
            if tgt_gw and tgt_gw not in [g["ip"] for g in gateways]:
                gateways.append({"ip": tgt_gw, "vlan": target.get("name", "Target VLAN"), "role": "target_gateway"})
        return gateways

    def execute(self):
        src_vlan = self.scan_config.get("source_vlan", {})
        src_name = src_vlan.get("name", "Source VLAN")
        gateways = self._collect_gateway_ips()

        # MGMT-001: Source VLAN Gateway Management Access
        src_gw = src_vlan.get("gateway", "")
        if src_gw:
            src_gw_ports = self._check_management_ports(src_gw)
            device_type = self._identify_device(src_gw, src_gw_ports, "")

            if src_gw_ports:
                port_list = ", ".join(f"{p['port']}/{p['service']}" for p in src_gw_ports)
                self.add_finding(
                    test_id="MGMT-001",
                    test_name="Source Gateway Management Access",
                    category=self.MODULE_NAME,
                    status=STATUS_WARN,
                    severity=SEVERITY_MEDIUM,
                    description=f"Management ports open on source VLAN gateway ({src_gw}).",
                    observation=f"Gateway {src_gw} ({device_type}) has {len(src_gw_ports)} management port(s) open: "
                                f"{port_list}. Access from source VLAN is expected but should be restricted by ACL.",
                    remediation="Apply ACL to restrict management access to authorized admin IPs/VLANs only. "
                                "Disable Telnet (use SSH only). Use HTTPS instead of HTTP for web management.",
                    affected_objects=[src_gw],
                    details={"gateway_ip": src_gw, "open_ports": src_gw_ports, "device_type": device_type},
                    source_vlan=src_name,
                )
            else:
                self.add_finding(
                    test_id="MGMT-001",
                    test_name="Source Gateway Management Access",
                    category=self.MODULE_NAME,
                    status=STATUS_PASS,
                    severity=SEVERITY_INFO,
                    description=f"No management ports detected on source VLAN gateway ({src_gw}).",
                    observation="Management interfaces are not accessible from the source VLAN, "
                                "or are filtered by ACLs.",
                    source_vlan=src_name,
                )
        else:
            self.add_finding(
                test_id="MGMT-001",
                test_name="Source Gateway Management Access",
                category=self.MODULE_NAME,
                status=STATUS_SKIP,
                severity=SEVERITY_INFO,
                description="No source VLAN gateway IP configured. Skipping gateway management check.",
                source_vlan=src_name,
            )

        # MGMT-002: Cross-VLAN Management Access to Target Gateways
        target_gateways = [g for g in gateways if g.get("role") == "target_gateway"]
        cross_vlan_exposed = []

        for gw in target_gateways:
            gw_ip = gw["ip"]
            gw_vlan = gw["vlan"]
            open_ports = self._check_management_ports(gw_ip)

            if open_ports:
                device_type = self._identify_device(gw_ip, open_ports, "")
                cross_vlan_exposed.append({
                    "ip": gw_ip,
                    "vlan": gw_vlan,
                    "open_ports": open_ports,
                    "device_type": device_type,
                })

        if cross_vlan_exposed:
            all_exposed = []
            for dev in cross_vlan_exposed:
                ports_str = ", ".join(f"{p['port']}/{p['service']}" for p in dev["open_ports"])
                all_exposed.append(f"{dev['ip']} ({dev['vlan']}, {dev['device_type']}): {ports_str}")

            self.add_finding(
                test_id="MGMT-002",
                test_name="Cross-VLAN Management Plane Exposure",
                category=self.MODULE_NAME,
                status=STATUS_FAIL,
                severity=SEVERITY_CRITICAL,
                description="Network device management interfaces are accessible from the source VLAN across VLAN boundaries.",
                observation=f"{len(cross_vlan_exposed)} gateway(s) with management ports accessible cross-VLAN: "
                            f"{'; '.join(all_exposed)}. "
                            "An attacker in the source VLAN could attempt to manage these devices.",
                remediation="Restrict management plane access with ACLs. Use a dedicated management VLAN. "
                            "Configure 'ip access-class' on VTY lines. Implement 802.1X or NAC.",
                affected_objects=[d["ip"] for d in cross_vlan_exposed],
                details={"exposed_devices": cross_vlan_exposed},
                source_vlan=src_name,
                references=["CIS Network Device Benchmark - Management Plane Hardening"],
            )
        elif target_gateways:
            self.add_finding(
                test_id="MGMT-002",
                test_name="Cross-VLAN Management Plane Exposure",
                category=self.MODULE_NAME,
                status=STATUS_PASS,
                severity=SEVERITY_INFO,
                description="No management ports accessible on target VLAN gateways from the source VLAN.",
                observation=f"Tested {len(target_gateways)} target gateway(s). "
                            "Management plane is properly isolated.",
                source_vlan=src_name,
            )
        else:
            self.add_finding(
                test_id="MGMT-002",
                test_name="Cross-VLAN Management Plane Exposure",
                category=self.MODULE_NAME,
                status=STATUS_SKIP,
                severity=SEVERITY_INFO,
                description="No target VLAN gateway IPs configured. Skipping cross-VLAN management check.",
                source_vlan=src_name,
            )

        # MGMT-003: SNMP Default Community String
        snmp_vulnerable = []
        for gw in gateways:
            gw_ip = gw["ip"]
            snmp_result = self._check_snmp(gw_ip)
            if snmp_result.get("accessible"):
                snmp_vulnerable.append({
                    "ip": gw_ip,
                    "vlan": gw["vlan"],
                    "community": snmp_result.get("community", "public"),
                    "response_preview": snmp_result.get("response", "")[:100],
                })

        if snmp_vulnerable:
            self.add_finding(
                test_id="MGMT-003",
                test_name="SNMP Default Community String",
                category=self.MODULE_NAME,
                status=STATUS_FAIL,
                severity=SEVERITY_CRITICAL,
                description="Network devices respond to SNMP queries with default community string 'public'.",
                observation=f"{len(snmp_vulnerable)} device(s) accept SNMP 'public' community: "
                            f"{', '.join(d['ip'] + ' (' + d['vlan'] + ')' for d in snmp_vulnerable)}. "
                            "Full device configuration and network topology may be readable.",
                remediation="Change default SNMP community strings. Use SNMPv3 with authentication and encryption. "
                            "Restrict SNMP access with ACLs to management VLAN only.",
                affected_objects=[d["ip"] for d in snmp_vulnerable],
                details={"snmp_devices": snmp_vulnerable},
                source_vlan=src_name,
                references=["CVE-1999-0517 - SNMP default community string"],
            )
        else:
            self.add_finding(
                test_id="MGMT-003",
                test_name="SNMP Default Community String",
                category=self.MODULE_NAME,
                status=STATUS_PASS,
                severity=SEVERITY_INFO,
                description="No devices responded to SNMP with default 'public' community string.",
                observation=f"Tested {len(gateways)} gateway(s). "
                            "SNMP is either disabled, using non-default communities, or ACL-restricted.",
                source_vlan=src_name,
            )

        # MGMT-004: Management Plane Summary
        alive_hosts = self.scan_config.get("alive_hosts", {})
        mgmt_hosts = []
        sample_ips = list(alive_hosts.keys())[:20]
        for ip in sample_ips:
            open_ports = self._check_management_ports(ip)
            if open_ports:
                device_type = self._identify_device(ip, open_ports, "")
                mgmt_hosts.append({
                    "ip": ip,
                    "open_ports": [p["port"] for p in open_ports],
                    "device_type": device_type,
                })

        total_mgmt = len(cross_vlan_exposed) + len(mgmt_hosts)
        if total_mgmt > 0:
            self.add_finding(
                test_id="MGMT-004",
                test_name="Management Plane Exposure Summary",
                category=self.MODULE_NAME,
                status=STATUS_WARN,
                severity=SEVERITY_HIGH if cross_vlan_exposed else SEVERITY_MEDIUM,
                description="Summary of all management interfaces accessible from the source VLAN.",
                observation=f"Total devices with management ports accessible: {total_mgmt}. "
                            f"Cross-VLAN gateways exposed: {len(cross_vlan_exposed)}. "
                            f"Other hosts with management ports: {len(mgmt_hosts)}.",
                remediation="Implement a dedicated management VLAN (out-of-band management). "
                            "Use jump boxes / bastion hosts for management access. "
                            "Apply principle of least privilege to management plane.",
                details={
                    "cross_vlan_gateways": cross_vlan_exposed,
                    "other_mgmt_hosts": mgmt_hosts,
                    "total_exposed": total_mgmt,
                },
                source_vlan=src_name,
            )
        else:
            self.add_finding(
                test_id="MGMT-004",
                test_name="Management Plane Exposure Summary",
                category=self.MODULE_NAME,
                status=STATUS_PASS,
                severity=SEVERITY_INFO,
                description="No management interfaces found accessible from the source VLAN.",
                observation="Management plane appears well-isolated. No management ports detected on gateways "
                            "or sampled hosts.",
                source_vlan=src_name,
            )
