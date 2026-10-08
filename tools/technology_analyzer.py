from evidence.security_models import (
    SecurityAnalysis,
    SecuritySignal,
)


class TechnologyAnalyzer:

    def analyze(
        self,
        target: str,
        headers: dict,
        body: str,
    ) -> SecurityAnalysis:

        signals = []

        normalized_headers = {
            key.lower(): str(value)
            for key, value in headers.items()
        }

        body_lower = body.lower()

        # ==============================================
        # Server header
        # ==============================================

        server = normalized_headers.get("server")

        if server:

            signals.append(
                SecuritySignal(
                    category="technology",
                    name="server",
                    value=server,
                    severity_hint="info",
                    confidence=0.95,
                    source="http_probe",
                    rationale=(
                        "The HTTP Server header provides "
                        "technology identification."
                    ),
                )
            )

        # ==============================================
        # X-Powered-By
        # ==============================================

        powered_by = normalized_headers.get(
            "x-powered-by"
        )

        if powered_by:

            signals.append(
                SecuritySignal(
                    category="technology",
                    name="x-powered-by",
                    value=powered_by,
                    severity_hint="info",
                    confidence=0.95,
                    source="http_probe",
                    rationale=(
                        "X-Powered-By may reveal "
                        "application framework information."
                    ),
                )
            )

        # ==============================================
        # JavaScript
        # ==============================================

        if (
            "<script" in body_lower
            or ".js" in body_lower
        ):

            signals.append(
                SecuritySignal(
                    category="technology",
                    name="JavaScript",
                    value="detected",
                    severity_hint="info",
                    confidence=0.99,
                    source="html",
                    rationale=(
                        "JavaScript resources or script "
                        "elements were identified."
                    ),
                )
            )

        # ==============================================
        # Angular
        # ==============================================

        if (
            "ng-version" in body_lower
            or "ng-app" in body_lower
            or "angular" in body_lower
        ):

            signals.append(
                SecuritySignal(
                    category="technology",
                    name="Angular",
                    value="detected",
                    severity_hint="info",
                    confidence=0.70,
                    source="html",
                    rationale=(
                        "Angular-related markers were "
                        "identified in the page."
                    ),
                )
            )

        # ==============================================
        # React
        # ==============================================

        if (
            "react" in body_lower
            or "__react" in body_lower
        ):

            signals.append(
                SecuritySignal(
                    category="technology",
                    name="React",
                    value="detected",
                    severity_hint="info",
                    confidence=0.65,
                    source="html",
                    rationale=(
                        "React-related markers were "
                        "identified in the page."
                    ),
                )
            )

        # ==============================================
        # Next.js
        # ==============================================

        if (
            "__next_data__" in body_lower
            or "/_next/" in body_lower
        ):

            signals.append(
                SecuritySignal(
                    category="technology",
                    name="Next.js",
                    value="detected",
                    severity_hint="info",
                    confidence=0.85,
                    source="html",
                    rationale=(
                        "Next.js runtime or resource "
                        "markers were identified."
                    ),
                )
            )

        # ==============================================
        # Express
        # ==============================================

        if (
            powered_by
            and "express" in powered_by.lower()
        ):

            signals.append(
                SecuritySignal(
                    category="technology",
                    name="Express",
                    value="detected",
                    severity_hint="info",
                    confidence=0.90,
                    source="http_probe",
                    rationale=(
                        "Express was explicitly identified "
                        "through the X-Powered-By header."
                    ),
                )
            )

        # ==============================================
        # HTML application
        # ==============================================

        if "<html" in body_lower:

            signals.append(
                SecuritySignal(
                    category="technology",
                    name="HTML",
                    value="web_application",
                    severity_hint="info",
                    confidence=0.99,
                    source="html",
                    rationale=(
                        "The response contains a standard "
                        "HTML document."
                    ),
                )
            )

        return SecurityAnalysis(
            analyzer="technology_analyzer",
            target=target,
            signals=signals,
        )