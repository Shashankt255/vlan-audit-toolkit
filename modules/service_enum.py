import socket
import ssl
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from modules.base import BaseModule, Finding, HostResult, PortResult
from config import *


HTTP_PORTS = {80, 443, 8080, 8443, 8000, 8008, 8081, 8082, 8088, 8888, 3000, 9090, 4443, 4848, 7001, 9000, 9001, 10000}

UNENCRYPTED_SERVICES = {
    21: "FTP", 23: "Telnet", 25: "SMTP", 80: "HTTP",
    110: "POP3", 143: "IMAP", 161: "SNMP", 389: "LDAP",
    513: "rlogin", 514: "rsh", 5900: "VNC",
}

SENSITIVE_SERVICES = {
    1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 5432: "PostgreSQL",
    6379: "Redis", 9200: "Elasticsearch", 11211: "Memcached",
    27017: "MongoDB", 2375: "Docker-API", 5555: "ADB",
    6443: "Kubernetes-API", 50000: "SAP",
}

SERVICE_PATTERNS = [
    (re.compile(rb"SSH-[\d.]+-(OpenSSH[^\r\n]*)", re.I), "SSH"),
    (re.compile(rb"SSH-[\d.]+-(dropbear[^\r\n]*)", re.I), "SSH"),
    (re.compile(rb"SSH-[\d.]+-([^\r\n]+)"), "SSH"),
    (re.compile(rb"220[- ].*FTP", re.I), "FTP"),
    (re.compile(rb"220[- ].*FileZilla", re.I), "FTP"),
    (re.compile(rb"220[- ].*vsFTPd", re.I), "FTP"),
    (re.compile(rb"220[- ].*ProFTPD", re.I), "FTP"),
    (re.compile(rb"HTTP/[\d.]+\s+\d+"), "HTTP"),
    (re.compile(rb"Server:\s*([^\r\n]+)", re.I), "HTTP"),
    (re.compile(rb"220[- ].*SMTP", re.I), "SMTP"),
    (re.compile(rb"220[- ].*Postfix", re.I), "SMTP"),
    (re.compile(rb"220[- ].*Exim", re.I), "SMTP"),
    (re.compile(rb"220[- ].*Microsoft ESMTP", re.I), "SMTP"),
    (re.compile(rb"\+OK.*POP3", re.I), "POP3"),
    (re.compile(rb"\* OK.*IMAP", re.I), "IMAP"),
    (re.compile(rb"mysql_native_password|MariaDB|mysql", re.I), "MySQL"),
    (re.compile(rb"PostgreSQL", re.I), "PostgreSQL"),
    (re.compile(rb"Microsoft SQL Server", re.I), "MSSQL"),
    (re.compile(rb"-ERR.*redis|REDIS|\$\d+\r\nredis", re.I), "Redis"),
    (re.compile(rb"MongoDB|mongod|ismaster", re.I), "MongoDB"),
    (re.compile(rb"RFB \d+\.\d+"), "VNC"),
    (re.compile(rb"Memcached", re.I), "Memcached"),
    (re.compile(rb"elasticsearch|\"cluster_name\"", re.I), "Elasticsearch"),
    (re.compile(rb"Apache[/ ](\d+[\d.]+)", re.I), "Apache"),
    (re.compile(rb"nginx[/ ](\d+[\d.]+)", re.I), "nginx"),
    (re.compile(rb"Microsoft-IIS[/ ](\d+[\d.]+)", re.I), "IIS"),
    (re.compile(rb"Apache Tomcat[/ ](\d+[\d.]+)", re.I), "Tomcat"),
    (re.compile(rb"lighttpd[/ ](\d+[\d.]+)", re.I), "lighttpd"),
]


class ServiceEnumModule(BaseModule):
    MODULE_NAME = "Service Enumeration"
    MODULE_DESCRIPTION = "Banner grabbing and service identification on open ports"

    def _grab_banner(self, ip, port, timeout=3):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))

            if port in HTTP_PORTS:
                probe = f"HEAD / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n".encode()
            elif port == 25 or port == 587:
                probe = b""  # SMTP sends banner on connect
            else:
                probe = b""

            if probe:
                sock.sendall(probe)
            else:
                time.sleep(0.3)

            banner = b""
            try:
                banner = sock.recv(1024)
            except socket.timeout:
                pass

            if not banner and not probe:
                try:
                    sock.sendall(b"\r\n")
                    banner = sock.recv(1024)
                except Exception:
                    pass

            sock.close()
            return banner
        except (socket.timeout, ConnectionRefusedError, OSError):
            return b""
        except Exception:
            return b""

    def _grab_banner_ssl(self, ip, port, timeout=3):
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            ssock = ctx.wrap_socket(sock, server_hostname=ip)
            ssock.connect((ip, port))
            probe = f"HEAD / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n".encode()
            ssock.sendall(probe)
            banner = ssock.recv(1024)
            ssock.close()
            return banner
        except Exception:
            return b""

    def _identify_service(self, port, banner):
        if not banner:
            return SERVICE_BANNERS.get(port, ""), ""

        service = ""
        version = ""

        for pattern, svc_name in SERVICE_PATTERNS:
            match = pattern.search(banner)
            if match:
                service = svc_name
                if match.lastindex and match.lastindex >= 1:
                    version = match.group(1).decode("utf-8", errors="replace").strip()
                break

        if not service:
            service = SERVICE_BANNERS.get(port, "unknown")

        return service, version

    def _check_http(self, ip, port, timeout=3):
        use_ssl = port in (443, 8443, 4443, 9443)
        try:
            if use_ssl:
                banner = self._grab_banner_ssl(ip, port, timeout)
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                sock.connect((ip, port))
                req = f"HEAD / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n".encode()
                sock.sendall(req)
                banner = sock.recv(2048)
                sock.close()

            if not banner:
                return {}

            decoded = banner.decode("utf-8", errors="replace")
            info = {}

            status_match = re.search(r"HTTP/[\d.]+ (\d+)", decoded)
            if status_match:
                info["status_code"] = int(status_match.group(1))

            server_match = re.search(r"Server:\s*([^\r\n]+)", decoded, re.I)
            if server_match:
                info["server"] = server_match.group(1).strip()

            title_match = re.search(r"<title>([^<]+)</title>", decoded, re.I)
            if title_match:
                info["title"] = title_match.group(1).strip()

            return info
        except Exception:
            return {}

    def execute(self):
        source = self.scan_config.get("source_vlan", {})
        host_results_map = self.scan_config.get("host_results", {})
        speed = self.get_speed_config()
        timeout = min(speed["timeout"] + 1, 5)

        all_services = {}
        sensitive_found = []
        unencrypted_found = []
        versions_found = []

        for ip, hr in host_results_map.items():
            if not hr.open_ports:
                continue

            host_services = {}

            def enum_port(port):
                banner = self._grab_banner(ip, port, timeout)
                if not banner and port in (443, 8443, 4443, 9443):
                    banner = self._grab_banner_ssl(ip, port, timeout)

                service, version = self._identify_service(port, banner)
                http_info = {}
                if port in HTTP_PORTS:
                    http_info = self._check_http(ip, port, timeout)

                return port, {
                    "service": service,
                    "banner": banner.decode("utf-8", errors="replace")[:200] if banner else "",
                    "version": version,
                    "http_info": http_info,
                }

            workers = min(20, len(hr.open_ports))
            with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
                futures = [pool.submit(enum_port, p) for p in hr.open_ports]
                for f in as_completed(futures):
                    try:
                        port, svc_info = f.result()
                        host_services[port] = svc_info

                        hr.services[port] = svc_info

                        if port in SENSITIVE_SERVICES:
                            sensitive_found.append({
                                "ip": ip, "port": port,
                                "service": svc_info["service"] or SENSITIVE_SERVICES[port],
                            })
                        if port in UNENCRYPTED_SERVICES:
                            unencrypted_found.append({
                                "ip": ip, "port": port,
                                "service": svc_info["service"] or UNENCRYPTED_SERVICES[port],
                            })
                        if svc_info["version"]:
                            versions_found.append({
                                "ip": ip, "port": port,
                                "service": svc_info["service"],
                                "version": svc_info["version"],
                            })
                    except Exception:
                        pass

            if host_services:
                all_services[ip] = host_services

        # SVC-001: Service enumeration summary
        total_services = sum(len(v) for v in all_services.values())
        self.add_finding(
            test_id="SVC-001",
            test_name="Service Enumeration Summary",
            category="Service Enumeration",
            status=STATUS_INFO,
            severity=SEVERITY_INFO,
            description="Banner grabbing and service identification on all open ports",
            observation=f"Enumerated {total_services} services across {len(all_services)} hosts",
            details={"services_by_host": {
                ip: {str(p): {"service": s["service"], "version": s["version"]}
                     for p, s in svcs.items()}
                for ip, svcs in all_services.items()
            }},
            source_vlan=source.get("name", ""),
        )

        # SVC-002: Sensitive services accessible
        if sensitive_found:
            self.add_finding(
                test_id="SVC-002",
                test_name="Sensitive Services Accessible Cross-VLAN",
                category="Service Enumeration",
                status=STATUS_FAIL,
                severity=SEVERITY_CRITICAL,
                description="Database, container, and management services accessible from source VLAN",
                observation=f"{len(sensitive_found)} sensitive services confirmed accessible with banner response",
                remediation="Restrict database, Docker, Kubernetes, and other sensitive services to their designated VLAN only",
                affected_objects=[f"{s['ip']}:{s['port']} ({s['service']})" for s in sensitive_found],
                details={"sensitive_services": sensitive_found},
                source_vlan=source.get("name", ""),
            )
        else:
            self.add_finding(
                test_id="SVC-002",
                test_name="Sensitive Services Accessible Cross-VLAN",
                category="Service Enumeration",
                status=STATUS_PASS,
                severity=SEVERITY_INFO,
                description="Check for database, container, and management services accessible from source VLAN",
                observation="No sensitive services found accessible cross-VLAN",
                source_vlan=source.get("name", ""),
            )

        # SVC-003: Unencrypted services
        if unencrypted_found:
            self.add_finding(
                test_id="SVC-003",
                test_name="Unencrypted Services Detected",
                category="Service Enumeration",
                status=STATUS_WARN,
                severity=SEVERITY_HIGH,
                description="Services transmitting data in cleartext detected cross-VLAN",
                observation=f"{len(unencrypted_found)} unencrypted services found (Telnet, FTP, HTTP, SNMP v1/v2, etc.)",
                remediation="Replace unencrypted protocols with their secure equivalents (SSH, SFTP, HTTPS, SNMPv3)",
                affected_objects=[f"{s['ip']}:{s['port']} ({s['service']})" for s in unencrypted_found],
                details={"unencrypted_services": unencrypted_found},
                source_vlan=source.get("name", ""),
            )
        else:
            self.add_finding(
                test_id="SVC-003",
                test_name="Unencrypted Services Detected",
                category="Service Enumeration",
                status=STATUS_PASS,
                severity=SEVERITY_INFO,
                description="Check for unencrypted services accessible cross-VLAN",
                observation="No unencrypted services detected",
                source_vlan=source.get("name", ""),
            )

        # SVC-004: Version disclosure
        if versions_found:
            self.add_finding(
                test_id="SVC-004",
                test_name="Service Version Disclosure",
                category="Service Enumeration",
                status=STATUS_WARN,
                severity=SEVERITY_LOW,
                description="Exact version strings disclosed by services, useful for vulnerability mapping",
                observation=f"{len(versions_found)} services disclosed version information",
                remediation="Configure services to suppress version banners where possible",
                affected_objects=[f"{v['ip']}:{v['port']} {v['service']} {v['version']}" for v in versions_found],
                details={"versions": versions_found},
                source_vlan=source.get("name", ""),
            )
        else:
            self.add_finding(
                test_id="SVC-004",
                test_name="Service Version Disclosure",
                category="Service Enumeration",
                status=STATUS_PASS,
                severity=SEVERITY_INFO,
                description="Check for service version disclosure in banners",
                observation="No version strings captured from service banners",
                source_vlan=source.get("name", ""),
            )

        self.scan_config["host_results"] = host_results_map
