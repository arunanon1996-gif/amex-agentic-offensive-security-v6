from evidence.security_models import (
    SecurityAnalysis,
    SecuritySignal,
)


class SecurityHeaderAnalyzer:

    EXPECTED_HEADERS = {
        "content-security-policy": {
            "name": "CSP",
            "severity": "medium",
            "rationale": (
                "CSP provides browser-side controls "
                "against several classes of injection."
            ),
        },
        "strict-transport-security": {
            "name": "HSTS",
            "severity": "medium",
            "rationale": (
                "HSTS helps enforce HTTPS for "
                "supported clients."
            ),
        },
        "x-frame-options": {
            "name": "X-Frame-Options",
            "severity": "medium",
            "rationale": (
                "Frame restrictions can reduce "
                "clickjacking exposure."
            ),
        },
        "x-content-type-options": {
            "name": "X-Content-Type-Options",
            "severity": "low",
            "rationale": (
                "nosniff reduces MIME-sniffing behavior."
            ),
        },
        "referrer-policy": {
            "name": "Referrer-Policy",
            "severity": "low",
            "rationale": (
                "Controls how referrer information "
                "is disclosed."
            ),
        },
        "permissions-policy": {
            "name": "Permissions-Policy",
            "severity": "low",
            "rationale": (
                "Controls access to selected browser "
                "features."
            ),
        },
    }

    def analyze(
        self,
        target: str,
        headers: dict,
    ) -> SecurityAnalysis:

        normalized = {
            key.lower(): value
            for key, value in headers.items()
        }

        signals = []

        for header, metadata in (
            self.EXPECTED_HEADERS.items()
        ):

            if header not in normalized:

                signals.append(
                    SecuritySignal(
                        category="security_header",
                        name=metadata["name"],
                        value="missing",
                        severity_hint=
                            metadata["severity"],
                        confidence=0.95,
                        source="http_probe",
                        rationale=(
                            metadata["rationale"]
                            + " Header was not observed "
                            "in the HTTP response."
                        ),
                    )
                )

            else:

                signals.append(
                    SecuritySignal(
                        category="security_header",
                        name=metadata["name"],
                        value=str(
                            normalized[header]
                        ),
                        severity_hint="info",
                        confidence=0.99,
                        source="http_probe",
                        rationale=(
                            metadata["name"]
                            + " was observed in "
                            "the HTTP response."
                        ),
                    )
                )

        return SecurityAnalysis(
            analyzer="security_header_analyzer",
            target=target,
            signals=signals,
        )