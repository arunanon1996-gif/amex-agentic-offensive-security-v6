import json
import os
import shutil
import subprocess
from dataclasses import dataclass, asdict
import socket


@dataclass
class PortResult:

    port: int
    protocol: str
    state: str
    service: str
    version: str | None = None


@dataclass
class NmapResult:

    target: str
    command: list[str]
    return_code: int
    ports: list[PortResult]
    raw_output: str
    engine: str = "nmap"
    warning: str | None = None


class NmapAdapter:

    def __init__(
        self,
        nmap_path: str = "nmap",
    ):
        self.nmap_path = nmap_path

    @staticmethod
    def resolve_path() -> str | None:
        candidates = [
            shutil.which("nmap"),
            os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "Nmap", "nmap.exe"),
            os.path.join(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"), "Nmap", "nmap.exe"),
        ]
        for candidate in candidates:
            if candidate and os.path.isfile(candidate):
                return candidate
        return None

    @classmethod
    def check_available(cls) -> tuple[bool, str]:
        path = cls.resolve_path()
        if path:
            return True, path
        return False, "Nmap was not found on PATH or in the standard Windows Nmap installation locations."

    def scan(
        self,
        target: str,
        ports: list[int],
    ) -> NmapResult:

        resolved = self.resolve_path() if self.nmap_path == "nmap" else self.nmap_path
        if not resolved:
            # The POC must remain runnable on a clean Windows workstation.
            # Use a localhost-safe TCP fallback when Nmap is not installed;
            # real Nmap is always preferred when available.
            return self._fallback_scan(target, ports)

        port_spec = ",".join(str(port) for port in ports)
        command = [resolved, "-Pn", "-sV", "--version-light", "-p", port_spec, target]
        completed = subprocess.run(command, capture_output=True, text=True, timeout=45, check=False)
        ports_found = self._parse_ports(completed.stdout)
        return NmapResult(target=target, command=command, return_code=completed.returncode, ports=ports_found, raw_output=completed.stdout, engine="nmap")

    def _fallback_scan(self, target: str, ports: list[int]) -> NmapResult:
        found = []
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.25)
            try:
                rc = sock.connect_ex((target, int(port)))
                if rc == 0:
                    service = {80: "http", 443: "https", 3000: "http", 5000: "http", 8000: "http", 8080: "http"}.get(int(port), "unknown")
                    found.append(PortResult(port=int(port), protocol="tcp", state="open", service=service, version="Built-in TCP fallback"))
            finally:
                sock.close()
        return NmapResult(target=target, command=["builtin-tcp-recon", target], return_code=0, ports=found, raw_output="Nmap not installed; built-in TCP reconnaissance was used. Install Nmap to enable Nmap service/version enumeration.", engine="builtin_tcp", warning="Nmap executable not found. Built-in TCP reconnaissance was used so the agentic assessment can continue.")

    def _parse_ports(
        self,
        output: str,
    ) -> list[PortResult]:

        results = []

        for line in output.splitlines():

            line = line.strip()

            if not line:
                continue

            if (
                "/tcp" not in line
                and "/udp" not in line
            ):
                continue

            parts = line.split()

            if len(parts) < 3:
                continue

            port_protocol = parts[0]
            state = parts[1]
            service = parts[2]

            try:

                port_string, protocol = (
                    port_protocol.split(
                        "/",
                        maxsplit=1,
                    )
                )

                port = int(port_string)

            except ValueError:
                continue

            version = None

            if len(parts) > 3:

                version = " ".join(
                    parts[3:]
                )

            results.append(
                PortResult(
                    port=port,
                    protocol=protocol,
                    state=state,
                    service=service,
                    version=version,
                )
            )

        return results

    def to_dict(
        self,
        result: NmapResult,
    ) -> dict:

        return asdict(result)

    def to_json(
        self,
        result: NmapResult,
    ) -> str:

        return json.dumps(
            self.to_dict(result),
            indent=2,
        )