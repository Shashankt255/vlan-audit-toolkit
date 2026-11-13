#!/usr/bin/env python3
"""VLAN Segmentation Audit Toolkit — Main Orchestrator"""

import argparse
import ipaddress
import importlib
import json
import os
import re
import socket
import subprocess
import sys
import time
from datetime import datetime

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
    from rich import box
except ImportError:
    print("[!] 'rich' not installed. Run: pip3 install rich")
    sys.exit(1)

try:
    import yaml
except ImportError:
    yaml = None

from config import (
    TOOL_NAME, TOOL_VERSION, TOOL_AUTHOR,
    SCAN_SPEED, TOP_100_TCP_PORTS, TOP_UDP_PORTS,
    STATUS_PASS, STATUS_FAIL, STATUS_WARN, STATUS_INFO, STATUS_ERROR, STATUS_SKIP,
    SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO,
    RISK_WEIGHTS,
)

console = Console()

AVAILABLE_MODULES = {
    "discovery": ("modules.discovery", "DiscoveryModule"),
    "port_scan": ("modules.port_scan", "PortScanModule"),
    "service_enum": ("modules.service_enum", "ServiceEnumModule"),
    "traceroute": ("modules.traceroute_mod", "TracerouteModule"),
    "vlan_checks": ("modules.vlan_checks", "VLANChecksModule"),
    "management_check": ("modules.management_check", "ManagementCheckModule"),
    "dns_check": ("modules.dns_check", "DNSCheckModule"),
    "policy_check": ("modules.policy_check", "PolicyCheckModule"),
}


def detect_source_info():
    """Auto-detect source IP, gateway, and interface."""
    info = {"source_ip": None, "gateway": None, "interface": None, "subnet": None}
    try:
        result = subprocess.run(
            ["ip", "route", "get", "8.8.8.8"],
            capture_output=True, text=True, timeout=5,
        )
        output = result.stdout.strip()
        src_match = re.search(r"src\s+(\S+)", output)
        via_match = re.search(r"via\s+(\S+)", output)
        dev_match = re.search(r"dev\s+(\S+)", output)
        if src_match:
            info["source_ip"] = src_match.group(1)
        if via_match:
            info["gateway"] = via_match.group(1)
        if dev_match:
            info["interface"] = dev_match.group(1)
    except Exception:
        pass

    if not info["source_ip"]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            info["source_ip"] = s.getsockname()[0]
            s.close()
        except Exception:
            info["source_ip"] = "127.0.0.1"

    if info["source_ip"] and info["source_ip"] != "127.0.0.1":
        try:
            result = subprocess.run(
                ["ip", "-o", "-f", "inet", "addr", "show"],
                capture_output=True, text=True, timeout=5,
            )
            for line in result.stdout.strip().split("\n"):
                if info["source_ip"] in line:
                    cidr_match = re.search(r"inet\s+(\S+)", line)
                    if cidr_match:
                        info["subnet"] = cidr_match.group(1)
                    break
        except Exception:
            pass

    return info


def parse_targets(target_str, max_hosts=256):
    """Parse target specification into list of IP addresses."""
    hosts = []
    for part in target_str.split(","):
        part = part.strip()
        if not part:
            continue
        range_match = re.match(r"^(\d+\.\d+\.\d+\.)(\d+)-(\d+)$", part)
        if range_match:
            prefix = range_match.group(1)
            start = int(range_match.group(2))
            end = int(range_match.group(3))
            for i in range(start, min(end + 1, start + max_hosts)):
                hosts.append(f"{prefix}{i}")
            continue
        try:
            net = ipaddress.ip_network(part, strict=False)
            if net.prefixlen == 32:
                hosts.append(str(net.network_address))
            else:
                count = 0
                for ip in net.hosts():
                    hosts.append(str(ip))
                    count += 1
                    if count >= max_hosts:
                        break
        except ValueError:
            try:
                ipaddress.ip_address(part)
                hosts.append(part)
            except ValueError:
                console.print(f"[yellow][!] Skipping invalid target: {part}[/yellow]")
    return hosts


def parse_ports(port_spec, port_type="tcp"):
    """Parse port specification string into a list of port numbers."""
    if not port_spec:
        if port_type == "tcp":
            return list(TOP_100_TCP_PORTS)
        return list(TOP_UDP_PORTS)

    spec = port_spec.strip().lower()

    if spec == "top100":
        return list(TOP_100_TCP_PORTS) if port_type == "tcp" else list(TOP_UDP_PORTS)
    if spec == "top1000":
        return list(range(1, 1001))
    if spec in ("all", "1-65535", "full"):
        return list(range(1, 65536))
    if spec == "common":
        return list(TOP_UDP_PORTS) if port_type == "udp" else list(TOP_100_TCP_PORTS)

    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            try:
                start, end = part.split("-", 1)
                for p in range(int(start), int(end) + 1):
                    if 1 <= p <= 65535:
                        ports.add(p)
            except ValueError:
                console.print(f"[yellow][!] Invalid port range: {part}[/yellow]")
        else:
            try:
                p = int(part)
                if 1 <= p <= 65535:
                    ports.add(p)
            except ValueError:
                console.print(f"[yellow][!] Invalid port: {part}[/yellow]")
    return sorted(ports)


def load_yaml_config(config_path):
    """Load scan configuration from YAML file."""
    if yaml is None:
        console.print("[red][!] PyYAML not installed. Run: pip3 install pyyaml[/red]")
        sys.exit(1)
    try:
        with open(config_path, "r") as f:
            return yaml.safe_load(f) or {}
    except Exception as e:
        console.print(f"[red][!] Failed to load config: {e}[/red]")
        sys.exit(1)


def load_module(module_name):
    """Dynamically load a scan module."""
    if module_name not in AVAILABLE_MODULES:
        console.print(f"[red][!] Unknown module: {module_name}[/red]")
        return None
    module_path, class_name = AVAILABLE_MODULES[module_name]
    try:
        mod = importlib.import_module(module_path)
        return getattr(mod, class_name)
    except (ImportError, AttributeError) as e:
        console.print(f"[yellow][!] Could not load module {module_name}: {e}[/yellow]")
        return None


def print_banner():
    banner_text = (
        f"[bold cyan]{TOOL_NAME}[/bold cyan] v{TOOL_VERSION}\n"
        f"[dim]Author: {TOOL_AUTHOR}[/dim]\n\n"
        "[dim]VLAN segmentation testing with reachability analysis,[/dim]\n"
        "[dim]port scanning, service enumeration, and risk scoring.[/dim]\n\n"
        "[bold yellow]SAFETY:[/bold yellow] [dim]Rate-limited probing only. No flooding, no CAM overflow,[/dim]\n"
        "[dim]no VLAN hopping exploitation. Passive protocol sniffing only.[/dim]"
    )
    console.print(Panel(banner_text, border_style="cyan", expand=False))
    console.print()


def print_summary(all_findings, host_results, elapsed):
    """Print end-of-scan summary."""
    severity_counts = {}
    status_counts = {}
    for f in all_findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
        status_counts[f.status] = status_counts.get(f.status, 0) + 1

    alive_hosts = [h for h in host_results if h.is_alive]
    total_open = sum(len(h.open_ports) for h in host_results)

    table = Table(title="Scan Summary", box=box.ROUNDED, border_style="cyan")
    table.add_column("Metric", style="bold")
    table.add_column("Value", justify="right")

    table.add_row("Total Targets", str(len(host_results)))
    table.add_row("Alive Hosts", str(len(alive_hosts)))
    table.add_row("Open Ports Found", str(total_open))
    table.add_row("Total Findings", str(len(all_findings)))
    table.add_row("", "")

    sev_order = [SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO]
    sev_colors = {
        SEVERITY_CRITICAL: "red", SEVERITY_HIGH: "bright_red",
        SEVERITY_MEDIUM: "yellow", SEVERITY_LOW: "blue", SEVERITY_INFO: "dim",
    }
    for sev in sev_order:
        count = severity_counts.get(sev, 0)
        if count > 0:
            table.add_row(f"  {sev}", f"[{sev_colors.get(sev, 'white')}]{count}[/]")

    table.add_row("", "")
    table.add_row("Scan Duration", f"{elapsed:.1f}s")

    console.print()
    console.print(table)


def calculate_risk_score(findings):
    """Calculate overall risk score 0-100."""
    if not findings:
        return 0
    total = 0
    for f in findings:
        if f.status in (STATUS_FAIL, STATUS_WARN):
            total += RISK_WEIGHTS.get(f.severity, 0)
    return min(100, total)


def main():
    parser = argparse.ArgumentParser(
        description=f"{TOOL_NAME} v{TOOL_VERSION} — VLAN segmentation testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s -t 10.20.0.0/24 -g 10.20.0.1\n"
            "  %(prog)s -t 10.20.0.0/24,10.30.0.0/24 --full-ports -s slow\n"
            "  %(prog)s -c vlan_config.yaml\n"
            "  %(prog)s -t 10.20.0.0/24 -p 22,80,443,3389 --udp --udp-ports common\n"
        ),
    )

    parser.add_argument("-c", "--config", help="Path to YAML config file")
    parser.add_argument("-t", "--targets", help="Comma-separated target IP ranges")
    parser.add_argument("--source-vlan", default="auto", help="Source VLAN name (default: auto-detect)")
    parser.add_argument("-g", "--gateway", help="Gateway IP of source VLAN")
    parser.add_argument("-p", "--tcp-ports", default="top100", help="TCP ports: top100, top1000, 1-65535, or list (default: top100)")
    parser.add_argument("--udp-ports", help="UDP ports: common, or comma-separated list")
    parser.add_argument("--udp", action="store_true", help="Enable UDP scanning")
    parser.add_argument("--full-ports", action="store_true", help="Scan all 65535 TCP ports")
    parser.add_argument("-s", "--speed", default="medium", choices=list(SCAN_SPEED.keys()), help="Scan speed (default: medium)")
    parser.add_argument("-o", "--output", default="vlan_audit_report.html", help="HTML report output path")
    parser.add_argument("--json-output", help="JSON report output path")
    parser.add_argument("--csv-output", help="CSV report output path")
    parser.add_argument("-i", "--interface", help="Network interface to use")
    parser.add_argument("--timeout", type=float, help="Per-probe timeout in seconds")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--policy", help="Path to policy YAML for compliance checking")
    parser.add_argument("--skip-traceroute", action="store_true", help="Skip traceroute phase")
    parser.add_argument("--skip-vlan-checks", action="store_true", help="Skip VLAN-specific checks (CDP/LLDP/DTP)")
    parser.add_argument("--max-hosts", type=int, default=256, help="Max hosts per target range (default: 256)")
    parser.add_argument("--list-modules", action="store_true", help="List available modules and exit")

    args = parser.parse_args()

    if args.list_modules:
        console.print(f"\n[bold cyan]{TOOL_NAME}[/bold cyan] — Available Modules:\n")
        for name, (mod_path, cls_name) in AVAILABLE_MODULES.items():
            console.print(f"  [bold]{name:20s}[/bold] {mod_path}.{cls_name}")
        console.print()
        return

    config = {}
    if args.config:
        config = load_yaml_config(args.config)

    targets_str = args.targets or config.get("targets", "")
    if not targets_str:
        console.print("[red][!] No targets specified. Use -t or --config.[/red]")
        parser.print_help()
        sys.exit(1)

    print_banner()

    source_info = detect_source_info()
    source_vlan = args.source_vlan or config.get("source_vlan", "auto")
    gateway = args.gateway or config.get("gateway") or source_info.get("gateway")
    interface = args.interface or config.get("interface") or source_info.get("interface")
    scan_speed = args.speed or config.get("speed", "medium")
    timeout = args.timeout or config.get("timeout") or SCAN_SPEED[scan_speed]["timeout"]

    if args.full_ports:
        tcp_ports = list(range(1, 65536))
    else:
        tcp_ports = parse_ports(args.tcp_ports or config.get("tcp_ports", "top100"), "tcp")

    udp_ports = []
    if args.udp or config.get("udp", False):
        udp_ports = parse_ports(args.udp_ports or config.get("udp_ports", "common"), "udp")

    targets = parse_targets(targets_str, args.max_hosts)
    if not targets:
        console.print("[red][!] No valid targets after parsing.[/red]")
        sys.exit(1)

    console.print(f"[bold]Source IP:[/bold]    {source_info.get('source_ip', 'unknown')}")
    console.print(f"[bold]Source VLAN:[/bold]  {source_vlan}")
    console.print(f"[bold]Gateway:[/bold]      {gateway or 'not specified'}")
    console.print(f"[bold]Interface:[/bold]    {interface or 'auto'}")
    console.print(f"[bold]Targets:[/bold]      {len(targets)} hosts across {targets_str}")
    console.print(f"[bold]TCP Ports:[/bold]    {len(tcp_ports)} ports")
    if udp_ports:
        console.print(f"[bold]UDP Ports:[/bold]    {len(udp_ports)} ports")
    console.print(f"[bold]Scan Speed:[/bold]   {scan_speed} ({SCAN_SPEED[scan_speed]['pps']} pps)")
    console.print()

    scan_config = {
        "targets": targets,
        "tcp_ports": tcp_ports,
        "udp_ports": udp_ports,
        "scan_speed": scan_speed,
        "timeout": timeout,
        "interface": interface,
        "gateway": gateway,
        "source_ip": source_info.get("source_ip"),
        "source_vlan": source_vlan,
        "source_subnet": source_info.get("subnet"),
        "verbose": args.verbose,
        "alive_hosts": [],
        "host_results": {},
    }

    policy_config = None
    if args.policy or config.get("policy"):
        policy_path = args.policy or config.get("policy")
        if os.path.exists(policy_path):
            policy_config = load_yaml_config(policy_path)
        else:
            console.print(f"[yellow][!] Policy file not found: {policy_path}[/yellow]")

    all_findings = []
    all_host_results = []
    module_timings = {}
    scan_start = time.time()

    phases = [
        ("Phase 1: Host Discovery", "discovery", {}),
        ("Phase 2: Port Scanning", "port_scan", {}),
        ("Phase 3: Service Enumeration", "service_enum", {}),
    ]
    if not args.skip_traceroute:
        phases.append(("Phase 4: Traceroute Analysis", "traceroute", {}))
    if not args.skip_vlan_checks:
        phases.append(("Phase 5: VLAN Security Checks", "vlan_checks", {}))
    phases.append(("Phase 6: Management Plane Check", "management_check", {}))
    phases.append(("Phase 7: DNS Analysis", "dns_check", {}))
    if policy_config:
        phases.append(("Phase 8: Policy Compliance", "policy_check", {"policy": policy_config}))

    for phase_name, module_name, extra_opts in phases:
        console.print(f"\n[bold cyan]{'='*60}[/bold cyan]")
        console.print(f"[bold cyan]{phase_name}[/bold cyan]")
        console.print(f"[bold cyan]{'='*60}[/bold cyan]")

        module_cls = load_module(module_name)
        if module_cls is None:
            console.print(f"[yellow]  [SKIP] Module not available[/yellow]")
            continue

        opts = {"scan_speed": scan_speed, **extra_opts}
        module_inst = module_cls(scan_config, opts)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task(f"  Running {module_name}...", total=None)
            findings = module_inst.run()
            progress.update(task, completed=True)

        module_timings[module_name] = module_inst.duration

        if module_inst.host_results:
            for hr in module_inst.host_results:
                existing = scan_config["host_results"].get(hr.ip)
                if existing:
                    if hr.is_alive:
                        existing.is_alive = True
                    if hr.ttl and not existing.ttl:
                        existing.ttl = hr.ttl
                    if hr.os_guess and not existing.os_guess:
                        existing.os_guess = hr.os_guess
                    existing.open_ports = list(set(existing.open_ports + hr.open_ports))
                    existing.filtered_ports = list(set(existing.filtered_ports + hr.filtered_ports))
                    existing.services.update(hr.services)
                    if hr.traceroute and not existing.traceroute:
                        existing.traceroute = hr.traceroute
                        existing.hop_count = hr.hop_count
                else:
                    scan_config["host_results"][hr.ip] = hr

            if module_name == "discovery":
                scan_config["alive_hosts"] = [
                    hr.ip for hr in module_inst.host_results if hr.is_alive
                ]
                console.print(f"  [green]Discovered {len(scan_config['alive_hosts'])} alive hosts[/green]")

        all_findings.extend(findings)

        status_counts = {}
        for f in findings:
            status_counts[f.status] = status_counts.get(f.status, 0) + 1
        status_parts = []
        for s in [STATUS_FAIL, STATUS_WARN, STATUS_PASS, STATUS_INFO, STATUS_SKIP]:
            c = status_counts.get(s, 0)
            if c > 0:
                color = {"FAIL": "red", "WARN": "yellow", "PASS": "green", "INFO": "blue", "SKIP": "dim"}.get(s, "white")
                status_parts.append(f"[{color}]{s}:{c}[/]")
        console.print(f"  Results: {' | '.join(status_parts)} ({module_inst.duration:.1f}s)")

    scan_elapsed = time.time() - scan_start

    all_host_results = list(scan_config["host_results"].values())

    metadata = {
        "tool_name": TOOL_NAME,
        "tool_version": TOOL_VERSION,
        "tool_author": TOOL_AUTHOR,
        "scan_date": datetime.now().isoformat(),
        "source_ip": source_info.get("source_ip", "unknown"),
        "source_vlan": source_vlan,
        "source_subnet": source_info.get("subnet", "unknown"),
        "gateway": gateway or "not specified",
        "interface": interface or "auto",
        "targets": targets_str,
        "target_count": len(targets),
        "tcp_port_count": len(tcp_ports),
        "udp_port_count": len(udp_ports),
        "scan_speed": scan_speed,
        "scan_duration": round(scan_elapsed, 2),
        "module_timings": module_timings,
        "risk_score": calculate_risk_score(all_findings),
    }

    console.print(f"\n[bold cyan]{'='*60}[/bold cyan]")
    console.print("[bold cyan]Generating Reports[/bold cyan]")
    console.print(f"[bold cyan]{'='*60}[/bold cyan]")

    try:
        from reporting.html_report import generate_report, generate_json_report, generate_csv_report

        generate_report(all_findings, all_host_results, metadata, args.output)
        console.print(f"  [green]HTML report: {args.output}[/green]")

        json_path = args.json_output or args.output.replace(".html", ".json")
        generate_json_report(all_findings, all_host_results, metadata, json_path)
        console.print(f"  [green]JSON report: {json_path}[/green]")

        if args.csv_output:
            generate_csv_report(all_findings, args.csv_output)
            console.print(f"  [green]CSV report:  {args.csv_output}[/green]")
    except Exception as e:
        console.print(f"[red][!] Report generation failed: {e}[/red]")
        if args.verbose:
            import traceback
            traceback.print_exc()

    print_summary(all_findings, all_host_results, scan_elapsed)

    risk = metadata["risk_score"]
    if risk >= 80:
        grade, color = "F", "red"
    elif risk >= 60:
        grade, color = "D", "bright_red"
    elif risk >= 40:
        grade, color = "C", "yellow"
    elif risk >= 20:
        grade, color = "B", "green"
    else:
        grade, color = "A", "bold green"

    console.print(f"\n[{color}]Risk Score: {risk}/100 (Grade: {grade})[/{color}]")
    console.print(f"\n[dim]Reports saved. Open {args.output} in a browser to view.[/dim]\n")


if __name__ == "__main__":
    main()
