from dataclasses import dataclass, asdict
import json
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from validation.validator import ValidatorMetadata
from tools.session_store import SESSION_STORE


@dataclass
class IdorValidationResult:
    status: str
    url: str
    baseline_url: str
    alternate_url: str
    method: str
    baseline_status_code: int
    alternate_status_code: int
    object_identifier: str
    alternate_object_identifier: str
    alternate_object_accessible: bool
    response_different: bool
    evidence_summary: str
    error: str | None = None


class IdorValidator:
    """
    Controlled BOLA/IDOR validation.

    The baseline object is requested first using the authenticated session.
    A second object identifier is then requested with the same session.
    HTTP 2xx access to a distinct alternate object is treated as CONFIRMED;
    explicit authorization denial is REJECTED; ambiguous outcomes are
    INCONCLUSIVE.
    """

    metadata = ValidatorMetadata(
        name="idor_validate",
        description=(
            "Compare authenticated access to the owned object and a "
            "controlled alternate object identifier."
        ),
        category="IDOR/BOLA",
    )

    def validate(
        self,
        target: str,
        port: int,
        session_id: str,
        path_template: str,
        object_identifier: str,
        alternate_object_identifier: str,
    ) -> IdorValidationResult:
        session = SESSION_STORE.get(session_id)

        if session is None:
            return IdorValidationResult(
                status="INCONCLUSIVE",
                url="",
                baseline_url="",
                alternate_url="",
                method="GET",
                baseline_status_code=0,
                alternate_status_code=0,
                object_identifier=str(object_identifier),
                alternate_object_identifier=str(
                    alternate_object_identifier
                ),
                alternate_object_accessible=False,
                response_different=False,
                evidence_summary=(
                    "The authenticated session is unavailable in the "
                    "process-local session store."
                ),
                error="Unknown session_id",
            )

        base = path_template.format(
            object_id=object_identifier
        )
        alternate = path_template.format(
            object_id=alternate_object_identifier
        )

        baseline_url = f"http://{target}:{port}{base}"
        alternate_url = f"http://{target}:{port}{alternate}"

        baseline_status, baseline_body, baseline_error = self._get(
            baseline_url,
            session.token,
        )

        if baseline_status < 200 or baseline_status >= 300:
            return IdorValidationResult(
                status="INCONCLUSIVE",
                url=alternate_url,
                baseline_url=baseline_url,
                alternate_url=alternate_url,
                method="GET",
                baseline_status_code=baseline_status,
                alternate_status_code=0,
                object_identifier=str(object_identifier),
                alternate_object_identifier=str(
                    alternate_object_identifier
                ),
                alternate_object_accessible=False,
                response_different=False,
                evidence_summary=(
                    "The authenticated baseline object could not be "
                    "retrieved, so the authorization comparison is invalid."
                ),
                error=baseline_error,
            )

        alternate_status, alternate_body, alternate_error = self._get(
            alternate_url,
            session.token,
        )

        accessible = (
            200 <= alternate_status < 300
        )

        different = (
            accessible
            and bool(alternate_body)
            and alternate_body != baseline_body
        )

        if accessible and different:
            status = "CONFIRMED"
            summary = (
                "The same authenticated session retrieved a distinct "
                "alternate object identifier successfully. This is "
                "strong evidence of broken object-level authorization."
            )
        elif alternate_status in {401, 403, 404}:
            status = "REJECTED"
            summary = (
                "The alternate object was denied or not exposed to the "
                "authenticated session."
            )
        elif accessible:
            status = "INCONCLUSIVE"
            summary = (
                "The alternate object request succeeded, but the response "
                "could not be established as a distinct protected object."
            )
        else:
            status = "INCONCLUSIVE"
            summary = (
                "The alternate object request produced an ambiguous "
                "authorization result."
            )

        return IdorValidationResult(
            status=status,
            url=alternate_url,
            baseline_url=baseline_url,
            alternate_url=alternate_url,
            method="GET",
            baseline_status_code=baseline_status,
            alternate_status_code=alternate_status,
            object_identifier=str(object_identifier),
            alternate_object_identifier=str(
                alternate_object_identifier
            ),
            alternate_object_accessible=accessible,
            response_different=different,
            evidence_summary=summary,
            error=alternate_error,
        )

    @staticmethod
    def _get(url, token):
        request = Request(
            url,
            method="GET",
            headers={
                "User-Agent": "AMEX-AI-Offensive-Security-Agent/1.0",
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
            },
        )
        try:
            with urlopen(request, timeout=10) as response:
                body = response.read(5000).decode(
                    "utf-8",
                    errors="replace",
                )
                return response.status, body, None
        except HTTPError as exc:
            body = exc.read(5000).decode(
                "utf-8",
                errors="replace",
            )
            return exc.code, body, f"HTTP {exc.code}"
        except Exception as exc:
            return 0, "", str(exc)

    @staticmethod
    def to_dict(result):
        return asdict(result)

    @staticmethod
    def to_json(result):
        return json.dumps(asdict(result), indent=2)
