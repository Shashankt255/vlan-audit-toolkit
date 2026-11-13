import os
import socket
import struct
import ipaddress
from modules.base import BaseModule, Finding, HostResult, PortResult
from config import *

try:
    from scapy.all import (
        sniff, conf, Ether, IP, UDP, BOOTP, DHCP, ICMP,
        sendp, sr1, send,
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class VLANChecksModule(BaseModule):
    MODULE_NAME = "VLAN Security Checks"
    MODULE_DESCRIPTION = "Passive and safe active VLAN security tests: CDP/LLDP, DTP, DHCP, native VLAN, broadcast leak"

    def _is_root(self):
        return os.geteuid() == 0

    def _get_interface(self):
        return self.options.get("interface", conf.iface if SCAPY_AVAILABLE else "eth0")

    def _get_source_subnet(self):
        src = self.scan_config.get("source_vlan", {})
        subnet_str = src.get("subnet", "")
        if subnet_str:
            try:
                return ipaddress.ip_network(subnet_str, strict=False)
            except ValueError:
                pass
        return None

    def _check_cdp_lldp(self, timeout=10):
        iface = self._get_interface()
        cdp_filter = "ether dst 01:00:0c:cc:cc:cc"
        lldp_filter = "ether dst 01:80:c2:00:00:0e"
        combined_filter = f"({cdp_filter}) or ({lldp_filter})"

        conf.verb = 0
        captured = sniff(filter=combined_filter, timeout=timeout, iface=iface)

        cdp_frames = []
        lldp_frames = []

        for pkt in captured:
            raw = bytes(pkt)
            dst_mac = pkt[Ether].dst.lower() if pkt.haslayer(Ether) else ""

            if dst_mac == "01:00:0c:cc:cc:cc":
                info = self._parse_cdp(raw)
                if info:
                    cdp_frames.append(info)
            elif dst_mac == "01:80:c2:00:00:0e":
                info = self._parse_lldp(raw)
                if info:
                    lldp_frames.append(info)

        return cdp_frames, lldp_frames

    def _parse_cdp(self, raw_bytes):
        info = {"protocol": "CDP", "device_name": "", "port": "",
                "native_vlan": "", "management_ip": "", "platform": ""}
        try:
            snap_offset = raw_bytes.find(b'\xaa\xaa\x03\x00\x00\x0c\x20\x00')
            if snap_offset < 0:
                return info
            cdp_start = snap_offset + 8
            cdp_data = raw_bytes[cdp_start:]
            if len(cdp_data) < 4:
                return info
            pos = 4
            while pos + 4 <= len(cdp_data):
                tlv_type = struct.unpack("!H", cdp_data[pos:pos+2])[0]
                tlv_len = struct.unpack("!H", cdp_data[pos+2:pos+4])[0]
                if tlv_len < 4:
                    break
                tlv_val = cdp_data[pos+4:pos+tlv_len]
                if tlv_type == 0x0001:
                    info["device_name"] = tlv_val.decode("ascii", errors="replace").strip('\x00')
                elif tlv_type == 0x0003:
                    info["port"] = tlv_val.decode("ascii", errors="replace").strip('\x00')
                elif tlv_type == 0x0006:
                    info["platform"] = tlv_val.decode("ascii", errors="replace").strip('\x00')
                elif tlv_type == 0x000a:
                    if len(tlv_val) >= 2:
                        info["native_vlan"] = str(struct.unpack("!H", tlv_val[:2])[0])
                elif tlv_type == 0x0002:
                    if len(tlv_val) >= 4:
                        info["management_ip"] = socket.inet_ntoa(tlv_val[-4:])
                pos += tlv_len
        except Exception:
            pass
        return info

    def _parse_lldp(self, raw_bytes):
        info = {"protocol": "LLDP", "device_name": "", "port": "",
                "native_vlan": "", "management_ip": "", "platform": ""}
        try:
            lldp_start = 14
            data = raw_bytes[lldp_start:]
            pos = 0
            while pos + 2 <= len(data):
                header = struct.unpack("!H", data[pos:pos+2])[0]
                tlv_type = (header >> 9) & 0x7F
                tlv_len = header & 0x01FF
                tlv_val = data[pos+2:pos+2+tlv_len]
                if tlv_type == 0:
                    break
                if tlv_type == 5:
                    info["device_name"] = tlv_val.decode("ascii", errors="replace")
                elif tlv_type == 7:
                    info["platform"] = tlv_val.decode("ascii", errors="replace")
                elif tlv_type == 2:
                    if len(tlv_val) > 1:
                        info["port"] = tlv_val[1:].decode("ascii", errors="replace")
                elif tlv_type == 8:
                    if len(tlv_val) >= 7 and tlv_val[1] == 1:
                        info["management_ip"] = socket.inet_ntoa(tlv_val[3:7])
                elif tlv_type == 127:
                    if len(tlv_val) >= 7 and tlv_val[:3] == b'\x00\x80\xc2':
                        sub = tlv_val[3]
                        if sub == 1 and len(tlv_val) >= 6:
                            info["native_vlan"] = str(struct.unpack("!H", tlv_val[4:6])[0])
                pos += 2 + tlv_len
        except Exception:
            pass
        return info

    def _check_dtp(self, timeout=10):
        iface = self._get_interface()
        conf.verb = 0
        dtp_filter = "ether dst 01:00:0c:cc:cc:cc"
        captured = sniff(filter=dtp_filter, timeout=timeout, iface=iface)

        dtp_frames = []
        for pkt in captured:
            raw = bytes(pkt)
            if b'\xaa\xaa\x03\x00\x00\x0c\x20\x04' in raw:
                dtp_frames.append({
                    "src_mac": pkt[Ether].src if pkt.haslayer(Ether) else "unknown",
                    "raw_length": len(raw),
                })
        return dtp_frames

    def _check_dhcp_servers(self):
        iface = self._get_interface()
        conf.verb = 0

        dhcp_discover = (
            Ether(dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=b'\x00\x11\x22\x33\x44\x55', xid=0x12345678) /
            DHCP(options=[("message-type", "discover"), "end"])
        )

        sendp(dhcp_discover, iface=iface, verbose=0)

        dhcp_filter = "udp and src port 67 and dst port 68"
        responses = sniff(filter=dhcp_filter, timeout=5, iface=iface)

        servers = []
        for pkt in responses:
            if pkt.haslayer(BOOTP):
                server_ip = pkt[IP].src if pkt.haslayer(IP) else "unknown"
                offered_ip = pkt[BOOTP].yiaddr
                server_id = ""
                if pkt.haslayer(DHCP):
                    for opt in pkt[DHCP].options:
                        if isinstance(opt, tuple) and opt[0] == "server_id":
                            server_id = opt[1]
                            break
                servers.append({
                    "server_ip": server_ip,
                    "server_id": str(server_id) if server_id else server_ip,
                    "offered_ip": offered_ip,
                })
        return servers

    def _check_native_vlan(self, cdp_frames, lldp_frames):
        native_vlans = []
        for frame in cdp_frames + lldp_frames:
            nv = frame.get("native_vlan", "")
            if nv:
                native_vlans.append({
                    "protocol": frame.get("protocol", "unknown"),
                    "device": frame.get("device_name", "unknown"),
                    "native_vlan": nv,
                })
        return native_vlans

    def _check_broadcast_leak(self):
        iface = self._get_interface()
        source_subnet = self._get_source_subnet()
        conf.verb = 0

        pkt = IP(dst="255.255.255.255") / ICMP()
        responses = sniff(
            filter="icmp",
            timeout=3,
            started_callback=lambda: send(pkt, iface=iface, verbose=0),
            iface=iface,
        )

        leak_ips = []
        for r in responses:
            if r.haslayer(IP):
                src_ip = r[IP].src
                if source_subnet:
                    try:
                        if ipaddress.ip_address(src_ip) not in source_subnet:
                            leak_ips.append(src_ip)
                    except ValueError:
                        pass
        return leak_ips

    def execute(self):
        src_vlan = self.scan_config.get("source_vlan", {})
        src_name = src_vlan.get("name", "Source VLAN")

        if not SCAPY_AVAILABLE:
            self.add_finding(
                test_id="VLAN-000",
                test_name="Scapy Dependency",
                category=self.MODULE_NAME,
                status=STATUS_SKIP,
                severity=SEVERITY_INFO,
                description="Scapy is not installed. VLAN security checks require scapy.",
                observation="Install scapy: pip install scapy>=2.5.0",
                remediation="pip install scapy",
                source_vlan=src_name,
            )
            return

        if not self._is_root():
            self.add_finding(
                test_id="VLAN-000",
                test_name="Root Privileges Required",
                category=self.MODULE_NAME,
                status=STATUS_SKIP,
                severity=SEVERITY_INFO,
                description="VLAN security checks require root privileges for raw packet capture.",
                observation="Re-run with sudo or as root.",
                remediation="sudo python3 vlan_audit.py ...",
                source_vlan=src_name,
            )
            return

        verbose = self.options.get("verbose", False)
        sniff_timeout = self.options.get("sniff_timeout", 10)

        # VLAN-001: CDP/LLDP Discovery
        cdp_frames, lldp_frames = self._check_cdp_lldp(timeout=sniff_timeout)
        all_disc = cdp_frames + lldp_frames
        if all_disc:
            devices_info = []
            for f in all_disc:
                dev = f.get("device_name", "unknown")
                port = f.get("port", "")
                mgmt = f.get("management_ip", "")
                plat = f.get("platform", "")
                devices_info.append(f"{dev} (port: {port}, mgmt: {mgmt}, platform: {plat})")
            self.add_finding(
                test_id="VLAN-001",
                test_name="CDP/LLDP Discovery Protocol Detection",
                category=self.MODULE_NAME,
                status=STATUS_WARN,
                severity=SEVERITY_MEDIUM,
                description="Network discovery protocols (CDP/LLDP) are broadcasting switch information.",
                observation=f"Captured {len(all_disc)} discovery frame(s) in {sniff_timeout}s. "
                            f"Devices: {'; '.join(devices_info)}",
                remediation="Disable CDP/LLDP on access ports. On Cisco: 'no cdp enable' per interface. "
                            "LLDP: 'no lldp transmit' / 'no lldp receive'.",
                affected_objects=[f.get("device_name", "unknown") for f in all_disc],
                details={"cdp_count": len(cdp_frames), "lldp_count": len(lldp_frames), "frames": all_disc},
                source_vlan=src_name,
                references=["CIS Cisco IOS Benchmark - CDP/LLDP controls"],
            )
        else:
            self.add_finding(
                test_id="VLAN-001",
                test_name="CDP/LLDP Discovery Protocol Detection",
                category=self.MODULE_NAME,
                status=STATUS_PASS,
                severity=SEVERITY_INFO,
                description="No CDP/LLDP frames detected during sniff window.",
                observation=f"No discovery protocol frames captured in {sniff_timeout}s. "
                            "Protocols may be disabled or not in use on connected switch port.",
                source_vlan=src_name,
            )

        # VLAN-002: DTP Detection
        dtp_frames = self._check_dtp(timeout=sniff_timeout)
        if dtp_frames:
            self.add_finding(
                test_id="VLAN-002",
                test_name="DTP Trunk Negotiation Detection",
                category=self.MODULE_NAME,
                status=STATUS_FAIL,
                severity=SEVERITY_CRITICAL,
                description="DTP (Dynamic Trunking Protocol) frames detected. Port may allow trunk negotiation, "
                            "enabling VLAN hopping attacks.",
                observation=f"Captured {len(dtp_frames)} DTP frame(s). Source MACs: "
                            f"{', '.join(f.get('src_mac', '?') for f in dtp_frames)}. "
                            "An attacker could negotiate a trunk and access all VLANs.",
                remediation="Set all access ports to 'switchport mode access' and 'switchport nonegotiate'. "
                            "Never leave ports in 'dynamic auto' or 'dynamic desirable' mode.",
                affected_objects=[f.get("src_mac", "unknown") for f in dtp_frames],
                details={"dtp_frames": dtp_frames},
                source_vlan=src_name,
                references=["VLAN Hopping via DTP - MITRE ATT&CK T1599"],
            )
        else:
            self.add_finding(
                test_id="VLAN-002",
                test_name="DTP Trunk Negotiation Detection",
                category=self.MODULE_NAME,
                status=STATUS_PASS,
                severity=SEVERITY_INFO,
                description="No DTP frames detected. Port appears configured as static access.",
                observation=f"No DTP frames captured in {sniff_timeout}s. "
                            "Switch port is likely in 'switchport mode access' with nonegotiate.",
                source_vlan=src_name,
            )

        # VLAN-003: DHCP Server Discovery
        try:
            servers = self._check_dhcp_servers()
            source_subnet = self._get_source_subnet()
            unexpected = []
            expected = []
            for s in servers:
                sip = s.get("server_ip", "")
                if source_subnet:
                    try:
                        if ipaddress.ip_address(sip) not in source_subnet:
                            unexpected.append(s)
                        else:
                            expected.append(s)
                    except ValueError:
                        unexpected.append(s)
                else:
                    expected.append(s)

            if unexpected:
                self.add_finding(
                    test_id="VLAN-003",
                    test_name="DHCP Server Discovery",
                    category=self.MODULE_NAME,
                    status=STATUS_FAIL,
                    severity=SEVERITY_HIGH,
                    description="DHCP servers responding from outside the source VLAN subnet detected.",
                    observation=f"Found {len(servers)} DHCP server(s). {len(unexpected)} outside source subnet: "
                                f"{', '.join(s['server_ip'] for s in unexpected)}. "
                                "This indicates DHCP traffic is crossing VLAN boundaries (rogue DHCP or misconfigured relay).",
                    remediation="Enable DHCP snooping on switches. Configure 'ip dhcp snooping' and mark "
                                "only legitimate DHCP server ports as trusted.",
                    affected_objects=[s["server_ip"] for s in unexpected],
                    details={"expected_servers": expected, "unexpected_servers": unexpected},
                    source_vlan=src_name,
                )
            elif servers:
                self.add_finding(
                    test_id="VLAN-003",
                    test_name="DHCP Server Discovery",
                    category=self.MODULE_NAME,
                    status=STATUS_PASS,
                    severity=SEVERITY_INFO,
                    description="All detected DHCP servers are within the source VLAN subnet.",
                    observation=f"Found {len(servers)} DHCP server(s) within expected subnet: "
                                f"{', '.join(s['server_ip'] for s in servers)}.",
                    source_vlan=src_name,
                )
            else:
                self.add_finding(
                    test_id="VLAN-003",
                    test_name="DHCP Server Discovery",
                    category=self.MODULE_NAME,
                    status=STATUS_INFO,
                    severity=SEVERITY_INFO,
                    description="No DHCP servers responded to discovery broadcast.",
                    observation="No DHCP Offer received. DHCP may use relay or static addressing.",
                    source_vlan=src_name,
                )
        except Exception as e:
            self.add_finding(
                test_id="VLAN-003",
                test_name="DHCP Server Discovery",
                category=self.MODULE_NAME,
                status=STATUS_ERROR,
                severity=SEVERITY_INFO,
                description=f"DHCP discovery failed: {e}",
                source_vlan=src_name,
            )

        # VLAN-004: Native VLAN Check
        native_vlans = self._check_native_vlan(cdp_frames, lldp_frames)
        if native_vlans:
            vlan1_devices = [nv for nv in native_vlans if nv.get("native_vlan") == "1"]
            if vlan1_devices:
                self.add_finding(
                    test_id="VLAN-004",
                    test_name="Native VLAN Configuration",
                    category=self.MODULE_NAME,
                    status=STATUS_WARN,
                    severity=SEVERITY_MEDIUM,
                    description="Default native VLAN (VLAN 1) detected on trunk ports. "
                                "This can facilitate double-tagging VLAN hopping attacks.",
                    observation=f"{len(vlan1_devices)} device(s) using VLAN 1 as native: "
                                f"{', '.join(d['device'] for d in vlan1_devices)}.",
                    remediation="Change native VLAN to an unused VLAN ID on all trunk ports: "
                                "'switchport trunk native vlan <unused_id>'. Tag native VLAN traffic: "
                                "'vlan dot1q tag native'.",
                    affected_objects=[d["device"] for d in vlan1_devices],
                    details={"native_vlan_info": native_vlans},
                    source_vlan=src_name,
                    references=["IEEE 802.1Q double-tagging attack"],
                )
            else:
                self.add_finding(
                    test_id="VLAN-004",
                    test_name="Native VLAN Configuration",
                    category=self.MODULE_NAME,
                    status=STATUS_PASS,
                    severity=SEVERITY_INFO,
                    description="Native VLAN is not set to default VLAN 1.",
                    observation=f"Native VLAN(s) detected: "
                                f"{', '.join(nv['native_vlan'] for nv in native_vlans)}. "
                                "Not using the default VLAN 1.",
                    details={"native_vlan_info": native_vlans},
                    source_vlan=src_name,
                )
        else:
            self.add_finding(
                test_id="VLAN-004",
                test_name="Native VLAN Configuration",
                category=self.MODULE_NAME,
                status=STATUS_INFO,
                severity=SEVERITY_INFO,
                description="Could not determine native VLAN (no CDP/LLDP data available).",
                observation="No discovery protocol frames were captured to extract native VLAN information. "
                            "Manual verification recommended.",
                source_vlan=src_name,
            )

        # VLAN-005: Broadcast Leak Check
        try:
            leak_ips = self._check_broadcast_leak()
            if leak_ips:
                self.add_finding(
                    test_id="VLAN-005",
                    test_name="Broadcast Domain Leak Detection",
                    category=self.MODULE_NAME,
                    status=STATUS_FAIL,
                    severity=SEVERITY_HIGH,
                    description="ICMP responses received from IPs outside the source subnet, "
                                "indicating broadcast traffic is leaking across VLAN boundaries.",
                    observation=f"{len(leak_ips)} response(s) from outside source subnet: "
                                f"{', '.join(leak_ips)}. Broadcast domain extends beyond expected VLAN.",
                    remediation="Verify VLAN configuration on switches. Ensure no VLAN bridging or "
                                "misconfigured trunk ports allow broadcast propagation across VLANs.",
                    affected_objects=leak_ips,
                    details={"leak_ips": leak_ips},
                    source_vlan=src_name,
                )
            else:
                self.add_finding(
                    test_id="VLAN-005",
                    test_name="Broadcast Domain Leak Detection",
                    category=self.MODULE_NAME,
                    status=STATUS_PASS,
                    severity=SEVERITY_INFO,
                    description="No broadcast domain leakage detected.",
                    observation="All ICMP responses to broadcast came from within the source subnet. "
                                "Broadcast domain appears properly isolated.",
                    source_vlan=src_name,
                )
        except Exception as e:
            self.add_finding(
                test_id="VLAN-005",
                test_name="Broadcast Domain Leak Detection",
                category=self.MODULE_NAME,
                status=STATUS_ERROR,
                severity=SEVERITY_INFO,
                description=f"Broadcast leak check failed: {e}",
                source_vlan=src_name,
            )
