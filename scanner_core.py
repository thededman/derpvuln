"""Core scanning logic for the network scanner application."""

from __future__ import annotations

import datetime as dt
import os
import subprocess
import sys
import threading
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, List

Logger = Callable[[str], None]


@dataclass
class ScanConfig:
    target: str
    output_dir: Path
    use_wsl: bool = False
    run_vuln_scan: bool = True
    nmap_args: List[str] | None = None


@dataclass
class ScanResult:
    discovery_xml: Path
    discovery_html: Path
    ports_xml: Path
    ports_html: Path
    vuln_xml: Path | None = None
    vuln_html: Path | None = None


class ScanError(RuntimeError):
    pass


def ensure_output_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def _log(logger: Logger | None, message: str) -> None:
    if logger:
        logger(message)


def _run_command(command: List[str], use_wsl: bool, logger: Logger | None = None) -> None:
    if use_wsl:
        command = ["wsl", "--"] + command
    _log(logger, f"Running: {' '.join(command)}")
    try:
        subprocess.run(command, check=True)
    except subprocess.CalledProcessError as exc:
        raise ScanError(f"Command failed: {' '.join(command)}") from exc


def _load_xml(path: Path) -> ET.Element:
    try:
        tree = ET.parse(path)
    except ET.ParseError as exc:
        raise ScanError(f"Unable to parse XML at {path}") from exc
    return tree.getroot()


def _write_html(path: Path, title: str, body: str) -> None:
    html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>{title}</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 2rem; }}
    table {{ border-collapse: collapse; width: 100%; margin-bottom: 2rem; }}
    th, td {{ border: 1px solid #ccc; padding: 0.5rem; text-align: left; }}
    th {{ background: #f2f2f2; }}
    code {{ background: #f7f7f7; padding: 0.2rem 0.4rem; }}
  </style>
</head>
<body>
<h1>{title}</h1>
{body}
</body>
</html>
"""
    path.write_text(html, encoding="utf-8")


def _host_table(hosts: Iterable[ET.Element]) -> str:
    rows = []
    for host in hosts:
        addr = host.find("address")
        addr_val = addr.attrib.get("addr") if addr is not None else "Unknown"
        hostname_el = host.find("hostnames/hostname")
        hostname_val = hostname_el.attrib.get("name") if hostname_el is not None else ""
        status_el = host.find("status")
        status_val = status_el.attrib.get("state") if status_el is not None else "unknown"
        rows.append(
            f"<tr><td>{addr_val}</td><td>{hostname_val}</td><td>{status_val}</td></tr>"
        )
    if not rows:
        rows.append("<tr><td colspan=\"3\">No hosts found.</td></tr>")
    return """
<table>
  <thead>
    <tr><th>Address</th><th>Hostname</th><th>Status</th></tr>
  </thead>
  <tbody>
    {rows}
  </tbody>
</table>
""".format(rows="\n".join(rows))


def _ports_table(hosts: Iterable[ET.Element]) -> str:
    rows = []
    for host in hosts:
        addr = host.find("address")
        addr_val = addr.attrib.get("addr") if addr is not None else "Unknown"
        for port in host.findall("ports/port"):
            port_id = port.attrib.get("portid", "")
            proto = port.attrib.get("protocol", "")
            state = port.find("state")
            state_val = state.attrib.get("state") if state is not None else ""
            service = port.find("service")
            service_val = service.attrib.get("name") if service is not None else ""
            rows.append(
                f"<tr><td>{addr_val}</td><td>{port_id}/{proto}</td><td>{state_val}</td><td>{service_val}</td></tr>"
            )
    if not rows:
        rows.append("<tr><td colspan=\"4\">No ports found.</td></tr>")
    return """
<table>
  <thead>
    <tr><th>Address</th><th>Port</th><th>State</th><th>Service</th></tr>
  </thead>
  <tbody>
    {rows}
  </tbody>
</table>
""".format(rows="\n".join(rows))


def _vuln_table(hosts: Iterable[ET.Element]) -> str:
    rows = []
    for host in hosts:
        addr = host.find("address")
        addr_val = addr.attrib.get("addr") if addr is not None else "Unknown"
        for port in host.findall("ports/port"):
            port_id = port.attrib.get("portid", "")
            proto = port.attrib.get("protocol", "")
            for script in port.findall("script"):
                script_id = script.attrib.get("id", "")
                output = script.attrib.get("output", "")
                rows.append(
                    "<tr>"
                    f"<td>{addr_val}</td>"
                    f"<td>{port_id}/{proto}</td>"
                    f"<td>{script_id}</td>"
                    f"<td><code>{output}</code></td>"
                    "</tr>"
                )
    if not rows:
        rows.append("<tr><td colspan=\"4\">No vulnerability findings.</td></tr>")
    return """
<table>
  <thead>
    <tr><th>Address</th><th>Port</th><th>Script</th><th>Output</th></tr>
  </thead>
  <tbody>
    {rows}
  </tbody>
</table>
""".format(rows="\n".join(rows))


def _timestamp() -> str:
    return dt.datetime.now().strftime("%Y%m%d-%H%M%S")


def _collect_open_ports(hosts: Iterable[ET.Element]) -> List[str]:
    ports: set[str] = set()
    for host in hosts:
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.attrib.get("state") != "open":
                continue
            port_id = port.attrib.get("portid")
            if port_id:
                ports.add(port_id)
    return sorted(ports, key=lambda value: int(value))


def _to_wsl_path(path: Path) -> str:
    try:
        result = subprocess.run(
            ["wsl", "--", "wslpath", "-a", str(path)],
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as exc:
        raise ScanError("Failed to convert path for WSL usage.") from exc
    return result.stdout.strip()


def _command_path(path: Path, use_wsl: bool) -> str:
    if use_wsl:
        return _to_wsl_path(path)
    return str(path)


def run_scan(config: ScanConfig, logger: Logger | None = None) -> ScanResult:
    ensure_output_dir(config.output_dir)

    discovery_xml = config.output_dir / f"discovery-{_timestamp()}.xml"
    ports_xml = config.output_dir / f"ports-{_timestamp()}.xml"
    vuln_xml = config.output_dir / f"vuln-{_timestamp()}.xml"

    nmap_base = ["nmap"]
    if config.nmap_args:
        nmap_base.extend(config.nmap_args)

    _log(logger, "Starting host discovery scan...")
    _run_command(
        nmap_base + ["-sn", config.target, "-oX", _command_path(discovery_xml, config.use_wsl)],
        config.use_wsl,
        logger,
    )

    _log(logger, "Starting port scan...")
    _run_command(
        nmap_base + ["-sV", "-p-", config.target, "-oX", _command_path(ports_xml, config.use_wsl)],
        config.use_wsl,
        logger,
    )

    ports_root = _load_xml(ports_xml)

    vuln_enabled = config.run_vuln_scan
    if vuln_enabled:
        open_ports = _collect_open_ports(ports_root.findall("host"))
        if open_ports:
            _log(
                logger,
                f"Starting vulnerability scan (nmap scripts) on ports: {', '.join(open_ports)}",
            )
            _run_command(
                nmap_base
                + [
                    "-sV",
                    "--script",
                    "vuln",
                    "-p",
                    ",".join(open_ports),
                    config.target,
                    "-oX",
                    _command_path(vuln_xml, config.use_wsl),
                ],
                config.use_wsl,
                logger,
            )
        else:
            _log(logger, "No open ports found. Skipping vulnerability scan.")
            vuln_xml = None
    else:
        vuln_xml = None

    discovery_html = config.output_dir / "discovery.html"
    ports_html = config.output_dir / "ports.html"
    vuln_html = config.output_dir / "vuln.html" if vuln_enabled else None

    discovery_root = _load_xml(discovery_xml)
    _write_html(
        discovery_html,
        "Discovery Report",
        _host_table(discovery_root.findall("host")),
    )

    _write_html(
        ports_html,
        "Port Scan Report",
        _ports_table(ports_root.findall("host")),
    )

    if vuln_enabled and vuln_xml:
        vuln_root = _load_xml(vuln_xml)
        _write_html(
            vuln_html,
            "Vulnerability Report",
            _vuln_table(vuln_root.findall("host")),
        )

    _log(logger, "Scan complete.")

    return ScanResult(
        discovery_xml=discovery_xml,
        discovery_html=discovery_html,
        ports_xml=ports_xml,
        ports_html=ports_html,
        vuln_xml=vuln_xml,
        vuln_html=vuln_html,
    )


def run_scan_in_thread(config: ScanConfig, logger: Logger | None, on_finish: Callable[[ScanResult | None, Exception | None], None]) -> None:
    def worker() -> None:
        try:
            result = run_scan(config, logger)
        except Exception as exc:  # noqa: BLE001 - surfaces scan errors to UI
            on_finish(None, exc)
        else:
            on_finish(result, None)

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()


def resolve_default_output() -> Path:
    base = Path.cwd() / "reports"
    ensure_output_dir(base)
    return base


def ensure_nmap_available(use_wsl: bool) -> None:
    command = ["nmap", "--version"]
    if use_wsl:
        command = ["wsl", "--"] + command
    try:
        subprocess.run(command, check=True, capture_output=True)
    except subprocess.CalledProcessError as exc:
        raise ScanError("Nmap is required but was not found.") from exc
    except FileNotFoundError as exc:
        raise ScanError("Nmap is required but was not found.") from exc


def validate_target(target: str) -> None:
    if not target.strip():
        raise ScanError("Target cannot be empty.")

    if target.strip().lower() == "localhost":
        raise ScanError("Use 127.0.0.1 or a subnet instead of localhost.")

    if " " in target.strip():
        raise ScanError("Target must not contain spaces.")


def example_targets() -> str:
    return "Examples: 192.168.1.0/24, 10.0.0.5"


def check_platform() -> str:
    return sys.platform