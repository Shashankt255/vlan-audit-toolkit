import time
import traceback
from dataclasses import dataclass, field
from typing import Optional
from config import *


@dataclass
class HostResult:
    ip: str
    hostname: Optional[str] = None
    is_alive: bool = False
    ttl: Optional[int] = None
    os_guess: str = ""
    open_ports: list = field(default_factory=list)
    filtered_ports: list = field(default_factory=list)
    closed_ports: list = field(default_factory=list)
    services: dict = field(default_factory=dict)
    traceroute: list = field(default_factory=list)
    hop_count: int = 0


@dataclass
class PortResult:
    port: int
    protocol: str  # tcp / udp
    status: str  # OPEN, CLOSED, FILTERED
    service: str = ""
    banner: str = ""
    version: str = ""


@dataclass
class Finding:
    test_id: str
    test_name: str
    category: str
    status: str
    severity: str
    description: str
    observation: str = ""
    remediation: str = ""
    affected_objects: list = field(default_factory=list)
    details: dict = field(default_factory=dict)
    source_vlan: str = ""
    target_vlan: str = ""
    references: list = field(default_factory=list)


class BaseModule:
    MODULE_NAME = "Base"
    MODULE_DESCRIPTION = ""

    def __init__(self, scan_config, options=None):
        self.scan_config = scan_config
        self.options = options or {}
        self.findings: list[Finding] = []
        self.host_results: list[HostResult] = []
        self.start_time = None
        self.end_time = None

    def add_finding(self, **kwargs):
        finding = Finding(**kwargs)
        self.findings.append(finding)
        return finding

    def get_speed_config(self):
        speed = self.options.get("scan_speed", "medium")
        return SCAN_SPEED.get(speed, SCAN_SPEED["medium"])

    def run(self):
        self.start_time = time.time()
        try:
            self.execute()
        except Exception as e:
            self.add_finding(
                test_id=f"{self.MODULE_NAME}-ERR",
                test_name=f"{self.MODULE_NAME} Module Error",
                category=self.MODULE_NAME,
                status=STATUS_ERROR,
                severity=SEVERITY_INFO,
                description=f"Module encountered an error: {e}",
                observation=traceback.format_exc(),
            )
        self.end_time = time.time()
        return self.findings

    def execute(self):
        raise NotImplementedError

    @property
    def duration(self):
        if self.start_time and self.end_time:
            return round(self.end_time - self.start_time, 2)
        return 0
