import re
from urllib.parse import urlparse

from evidence.security_models import SecurityAnalysis, SecuritySignal


OBJECT_ID_PATTERNS = (
    re.compile(r"/(?P<name>[A-Za-z][A-Za-z0-9_-]*)/(?P<id>\d+)(?:/|$)"),
    re.compile(
        r"/(?P<name>[A-Za-z][A-Za-z0-9_-]*)/"
        r"(?P<id>[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,})"
        r"(?:/|$)"
    ),
)


class IdorAnalyzer:
    """
    Converts authenticated resource URL evidence into an IDOR/BOLA hypothesis.

    The analyzer does not decide that IDOR exists. It only identifies the
    authorization boundary candidate that should be validated next.
    """

    def analyze(self, target, resource):
        signals = []

        if not isinstance(resource, dict):
            resource = getattr(resource, "__dict__", {})

        authenticated = bool(resource.get("authenticated"))
        url = str(
            resource.get("resource_url")
            or resource.get("url")
            or ""
        )
        object_identifier = resource.get("object_identifier")

        if not authenticated or not url:
            return SecurityAnalysis(
                analyzer="idor_analyzer",
                target=target,
                signals=[],
            )

        parsed = urlparse(url)
        match = self._find_object_identifier(
            parsed.path,
            object_identifier,
        )

        if not match:
            return SecurityAnalysis(
                analyzer="idor_analyzer",
                target=target,
                signals=[],
            )

        object_name, object_id = match

        signals.append(
            SecuritySignal(
                category="IDOR",
                name="authenticated_object_identifier",
                value=f"{object_name}/{object_id}",
                severity_hint="high",
                confidence=0.92,
                source="authenticated_resource_probe",
                rationale=(
                    "An authenticated request contains a direct object "
                    "identifier in the URL. This creates an explicit "
                    "object-level authorization boundary that can be "
                    "validated by comparing access to another object ID."
                ),
            )
        )

        return SecurityAnalysis(
            analyzer="idor_analyzer",
            target=target,
            signals=signals,
        )

    @staticmethod
    def _find_object_identifier(path, explicit_id=None):
        for pattern in OBJECT_ID_PATTERNS:
            match = pattern.search(path)
            if match:
                return match.group("name"), match.group("id")

        if explicit_id is not None:
            explicit_id = str(explicit_id)
            segments = path.strip("/").split("/")
            if explicit_id in segments:
                index = segments.index(explicit_id)
                if index > 0:
                    return segments[index - 1], explicit_id

        return None
