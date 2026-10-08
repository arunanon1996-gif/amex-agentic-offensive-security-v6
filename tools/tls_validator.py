from dataclasses import dataclass, asdict
import socket
import ssl
from validation.validator import ValidatorMetadata

@dataclass
class TLSValidationResult:
    target: str
    port: int
    reachable: bool
    tls_enabled: bool
    protocol: str | None
    cipher: str | None
    certificate_subject: str | None
    certificate_issuer: str | None
    certificate_expired: bool | None
    conclusion: str
    error: str | None = None

class TLSValidator:
    metadata = ValidatorMetadata(name="tls_validate", description="Inspect TLS availability and certificate/protocol posture on an approved local target.", category="TLS")

    def validate(self, target: str, port: int = 443) -> TLSValidationResult:
        host = target
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, int(port)), timeout=4) as raw:
                with ctx.wrap_socket(raw, server_hostname=host) as sock:
                    cert = sock.getpeercert() or {}
                    subject = self._name(cert.get("subject"))
                    issuer = self._name(cert.get("issuer"))
                    not_after = cert.get("notAfter")
                    expired = None
                    if not_after:
                        import datetime
                        expired = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z") < datetime.datetime.utcnow()
                    return TLSValidationResult(host, int(port), True, True, sock.version(), (sock.cipher() or (None,))[0], subject, issuer, expired, "TLS is enabled and the endpoint negotiated a TLS session.")
        except ssl.SSLError as exc:
            return TLSValidationResult(host, int(port), True, False, None, None, None, None, None, "The port is reachable but did not negotiate TLS.", str(exc))
        except OSError as exc:
            return TLSValidationResult(host, int(port), False, False, None, None, None, None, None, "TLS is not reachable on this port; no TLS finding is asserted.", str(exc))
        except Exception as exc:
            return TLSValidationResult(host, int(port), False, False, None, None, None, None, None, "TLS validation could not be completed safely.", str(exc))

    @staticmethod
    def _name(value):
        if not value:
            return None
        return ", ".join("=".join(str(x) for x in item) for part in value for item in part)

    @staticmethod
    def to_dict(result):
        return asdict(result)
