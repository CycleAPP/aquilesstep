"""Nmap XML output parser."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any


@dataclass
class NmapPort:
    port: int
    protocol: str
    state: str
    service: str = ""
    product: str = ""
    version: str = ""
    extra_info: str = ""
    scripts: dict[str, str] = field(default_factory=dict)

    @property
    def display(self) -> str:
        s = f"{self.port}/{self.protocol} {self.state} {self.service}"
        if self.product:
            s += f" ({self.product}"
            if self.version:
                s += f" {self.version}"
            s += ")"
        return s


@dataclass
class NmapHost:
    address: str
    hostname: str = ""
    state: str = "unknown"
    ports: list[NmapPort] = field(default_factory=list)
    os_matches: list[str] = field(default_factory=list)

    @property
    def open_ports(self) -> list[NmapPort]:
        return [p for p in self.ports if p.state == "open"]


def parse_nmap_xml(xml_content: str) -> list[NmapHost]:
    """Parse nmap XML output into structured data."""
    hosts: list[NmapHost] = []

    try:
        root = ET.fromstring(xml_content)
    except ET.ParseError:
        return hosts

    for host_elem in root.findall(".//host"):
        # Address
        addr_elem = host_elem.find("address")
        if addr_elem is None:
            continue
        addr = addr_elem.get("addr", "")

        # Hostname
        hostname = ""
        hostname_elem = host_elem.find(".//hostname")
        if hostname_elem is not None:
            hostname = hostname_elem.get("name", "")

        # Host state
        status_elem = host_elem.find("status")
        state = status_elem.get("state", "unknown") if status_elem is not None else "unknown"

        host = NmapHost(address=addr, hostname=hostname, state=state)

        # Ports
        for port_elem in host_elem.findall(".//port"):
            port_id = int(port_elem.get("portid", 0))
            protocol = port_elem.get("protocol", "tcp")

            state_elem = port_elem.find("state")
            port_state = state_elem.get("state", "unknown") if state_elem is not None else "unknown"

            service_elem = port_elem.find("service")
            service = ""
            product = ""
            version = ""
            extra_info = ""
            if service_elem is not None:
                service = service_elem.get("name", "")
                product = service_elem.get("product", "")
                version = service_elem.get("version", "")
                extra_info = service_elem.get("extrainfo", "")

            # Script outputs
            scripts: dict[str, str] = {}
            for script_elem in port_elem.findall("script"):
                script_id = script_elem.get("id", "")
                script_output = script_elem.get("output", "")
                if script_id:
                    scripts[script_id] = script_output

            port = NmapPort(
                port=port_id,
                protocol=protocol,
                state=port_state,
                service=service,
                product=product,
                version=version,
                extra_info=extra_info,
                scripts=scripts,
            )
            host.ports.append(port)

        # OS detection
        for os_match in host_elem.findall(".//osmatch"):
            os_name = os_match.get("name", "")
            if os_name:
                host.os_matches.append(os_name)

        hosts.append(host)

    return hosts


def nmap_to_summary(hosts: list[NmapHost]) -> str:
    """Convert parsed nmap data to a readable summary."""
    lines = []
    for host in hosts:
        header = f"Host: {host.address}"
        if host.hostname:
            header += f" ({host.hostname})"
        header += f" — {host.state}"
        lines.append(header)

        for port in host.open_ports:
            lines.append(f"  {port.display}")
            for script_id, output in port.scripts.items():
                lines.append(f"    [{script_id}] {output[:200]}")

        if host.os_matches:
            lines.append(f"  OS: {host.os_matches[0]}")
        lines.append("")

    return "\n".join(lines)
