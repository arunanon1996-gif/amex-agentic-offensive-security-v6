from evidence.security_models import SecurityAnalysis, SecuritySignal


class CorsAnalyzer:
    def analyze(self, target, headers):
        signals = []

        normalized = {
            key.lower(): str(value)
            for key, value in headers.items()
        }

        allow_origin = normalized.get("access-control-allow-origin")
        allow_credentials = normalized.get(
            "access-control-allow-credentials"
        )

        if allow_origin:
            if allow_origin == "*":
                signals.append(
                    SecuritySignal(
                        category="cors",
                        name="Access-Control-Allow-Origin",
                        value="*",
                        severity_hint="medium",
                        confidence=0.99,
                        source="http_probe",
                        rationale=(
                            "The application permits wildcard cross-origin "
                            "access. This is a security-relevant signal "
                            "that requires contextual validation."
                        ),
                    )
                )
            else:
                signals.append(
                    SecuritySignal(
                        category="cors",
                        name="Access-Control-Allow-Origin",
                        value=allow_origin,
                        severity_hint="info",
                        confidence=0.99,
                        source="http_probe",
                        rationale=(
                            "The application explicitly advertises an "
                            "allowed cross-origin origin."
                        ),
                    )
                )

        if allow_credentials:
            signals.append(
                SecuritySignal(
                    category="cors",
                    name="Access-Control-Allow-Credentials",
                    value=allow_credentials,
                    severity_hint="medium",
                    confidence=0.99,
                    source="http_probe",
                    rationale=(
                        "The response indicates whether browser credentials "
                        "may be included in cross-origin requests."
                    ),
                )
            )

        return SecurityAnalysis(
            analyzer="cors_analyzer",
            target=target,
            signals=signals,
        )