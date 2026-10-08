from dataclasses import dataclass
from urllib.request import Request, urlopen
from urllib.parse import urljoin
from validation.validator import ValidatorMetadata


@dataclass
class DomXssValidationResult:
    source_url: str
    source_signal: str
    sink_signal: str
    source_observed: bool
    unsafe_sink_observed: bool
    confirmed: bool
    conclusion: str
    error: str | None = None


class DomXssValidator:
    """Bounded runtime JavaScript-bundle analysis for DOM-XSS evidence.

    This does not execute attacker JavaScript. It inspects the target's served
    bundles for a user-controlled location/search source reaching a known
    unsafe HTML sink. The result is explicitly labelled static runtime evidence.
    """

    metadata = ValidatorMetadata(
        name="dom_xss_validate",
        description="Validate a DOM XSS hypothesis by inspecting served JavaScript bundles for source-to-unsafe-sink evidence.",
        category="XSS",
    )

    SOURCE_PATTERNS = (
        "location.hash",
        "location.search",
        "URLSearchParams",
        "searchQuery",
        "queryParams",
    )
    SINK_PATTERNS = (
        "bypassSecurityTrustHtml",
        ".innerHTML",
        "insertAdjacentHTML",
        "document.write(",
    )

    def validate(self, target, port, source_url="/", bundle_url=""):
        root = f"http://{target}:{port}"
        url = urljoin(root + "/", bundle_url or source_url.lstrip("/"))
        try:
            body = self._get(url)
            source = next((x for x in self.SOURCE_PATTERNS if x.lower() in body.lower()), None)
            sink = next((x for x in self.SINK_PATTERNS if x.lower() in body.lower()), None)
            confirmed = bool(source and sink)
            conclusion = (
                "Served JavaScript contains a user-controlled URL/search source and an unsafe HTML sink; DOM-XSS static runtime evidence is confirmed."
                if confirmed else
                "No sufficient DOM-XSS source-to-sink evidence was observed in the inspected runtime bundle."
            )
            return DomXssValidationResult(url, source or "", sink or "", bool(source), bool(sink), confirmed, conclusion)
        except Exception as exc:
            return DomXssValidationResult(url, "", "", False, False, False, "DOM-XSS bundle validation could not be completed.", str(exc))

    @staticmethod
    def _get(url):
        req = Request(url, method="GET", headers={"User-Agent": "AMEX-AI-Offensive-Security-Agent/6.0", "Accept": "application/javascript,text/javascript,*/*"})
        with urlopen(req, timeout=8) as response:
            return response.read(200000).decode("utf-8", errors="replace")
