from tools.security_header_analyzer import SecurityHeaderAnalyzer
from tools.technology_analyzer import TechnologyAnalyzer
from tools.cors_analyzer import CorsAnalyzer
from tools.idor_analyzer import IdorAnalyzer


class AnalysisEngine:
    def __init__(self):
        self.security_headers = SecurityHeaderAnalyzer()
        self.technology = TechnologyAnalyzer()
        self.cors = CorsAnalyzer()
        self.idor = IdorAnalyzer()

    def analyze_http(self, target, http_result):
        headers = self._get_field(http_result, "headers", {})
        body_preview = self._get_field(
            http_result,
            "body_preview",
            "",
        )

        analyses = [
            self.security_headers.analyze(target, headers),
            self.technology.analyze(
                target,
                headers,
                body_preview,
            ),
            self.cors.analyze(target, headers),
        ]

        return [
            signal
            for analysis in analyses
            for signal in analysis.signals
        ]

    def analyze_authenticated_resource(self, target, resource_result):
        return self.idor.analyze(
            target,
            resource_result,
        ).signals

    @staticmethod
    def _get_field(source, field_name, default=None):
        if isinstance(source, dict):
            return source.get(field_name, default)
        return getattr(source, field_name, default)
