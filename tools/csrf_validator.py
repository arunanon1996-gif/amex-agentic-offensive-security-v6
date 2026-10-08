from dataclasses import dataclass, asdict
import json
from urllib.request import Request, urlopen

from validation.validator import ValidatorMetadata
from tools.session_store import SESSION_STORE


@dataclass
class CsrfValidationResult:
    url: str
    method: str
    status_code: int
    request_content_type: str
    csrf_token_present: bool
    same_site_cookie_present: bool
    access_control_allow_origin: str | None
    access_control_allow_credentials: str | None
    cross_origin_request_accepted: bool
    state_change_confirmed: bool
    confirmed: bool
    conclusion: str
    error: str | None = None
    not_applicable: bool = False


class CsrfValidator:

    metadata = ValidatorMetadata(
        name="csrf_validate",
        description=(
            "Perform a controlled CSRF validation against an "
            "approved state-changing endpoint."
        ),
        category="CSRF",
    )

    def validate(
        self,
        target: str,
        port: int,
        path: str = "/",
        method: str = "POST",
        body: str = "",
        content_type: str = "application/x-www-form-urlencoded",
        origin: str = "https://attacker.example",
        csrf_token: str | None = None,
        session_id: str | None = None,
    ) -> CsrfValidationResult:

        url = f"http://{target}:{port}{path}"

        headers = {
            "User-Agent": "AMEX-AI-Offensive-Security-Agent/1.0",
            "Origin": origin,
            "Content-Type": content_type,
        }

        session = SESSION_STORE.get(session_id) if session_id else None
        if session:
            # A bearer Authorization header is not ambient browser credential
            # state and therefore is not a classic CSRF primitive. Do not send
            # it as though an attacker-controlled page could add it.
            return CsrfValidationResult(
                url=url,
                method=method.upper(),
                status_code=0,
                request_content_type=content_type,
                csrf_token_present=bool(csrf_token),
                same_site_cookie_present=False,
                access_control_allow_origin=None,
                access_control_allow_credentials=None,
                cross_origin_request_accepted=False,
                state_change_confirmed=False,
                confirmed=False,
                conclusion="Classic CSRF is not applicable to this authenticated flow because authentication uses a bearer token rather than ambient browser credentials.",
                error=None,
                not_applicable=True,
            )
        if csrf_token:
            headers["X-CSRF-Token"] = csrf_token

        request = Request(
            url,
            data=body.encode("utf-8"),
            method=method.upper(),
            headers=headers,
        )

        try:
            with urlopen(request, timeout=10) as response:

                response_body = response.read(2000)

                allow_origin = response.headers.get(
                    "Access-Control-Allow-Origin"
                )

                allow_credentials = response.headers.get(
                    "Access-Control-Allow-Credentials"
                )

                set_cookie = response.headers.get(
                    "Set-Cookie",
                    "",
                )

                same_site_cookie_present = (
                    "samesite=" in set_cookie.lower()
                )

                cross_origin_request_accepted = (
                    response.status < 400
                )

                csrf_token_present = bool(csrf_token)
                state_change_confirmed = response.status < 400 and response.status not in {401,403}

                confirmed = (
                    state_change_confirmed
                    and cross_origin_request_accepted
                    and not csrf_token_present
                    and (
                        allow_origin == origin
                        or allow_origin == "*"
                    )
                )

                if confirmed:
                    conclusion = (
                        "The controlled cross-origin request was accepted "
                        "without a CSRF token. This is security-relevant "
                        "evidence, but exploitability depends on whether "
                        "the endpoint performs an authenticated state change."
                    )
                elif cross_origin_request_accepted:
                    conclusion = (
                        "The controlled request was accepted, but the "
                        "available evidence is insufficient to confirm CSRF."
                    )
                else:
                    conclusion = (
                        "The controlled cross-origin request was rejected "
                        "or otherwise failed."
                    )

                return CsrfValidationResult(
                    url=url,
                    method=method.upper(),
                    status_code=response.status,
                    request_content_type=content_type,
                    csrf_token_present=csrf_token_present,
                    same_site_cookie_present=same_site_cookie_present,
                    access_control_allow_origin=allow_origin,
                    access_control_allow_credentials=allow_credentials,
                    cross_origin_request_accepted=cross_origin_request_accepted,
                    state_change_confirmed=state_change_confirmed,
                    confirmed=confirmed,
                    conclusion=conclusion,
                    not_applicable=False,
                    error=None,
                )

        except Exception as exc:

            return CsrfValidationResult(
                url=url,
                method=method.upper(),
                status_code=0,
                request_content_type=content_type,
                csrf_token_present=bool(csrf_token),
                same_site_cookie_present=False,
                access_control_allow_origin=None,
                access_control_allow_credentials=None,
                cross_origin_request_accepted=False,
                state_change_confirmed=False,
                confirmed=False,
                not_applicable=False,
                conclusion=(
                    "The controlled CSRF validation could not be completed."
                ),
                error=str(exc),
            )

    @staticmethod
    def to_dict(
        result: CsrfValidationResult,
    ) -> dict:
        return asdict(result)

    @staticmethod
    def to_json(
        result: CsrfValidationResult,
    ) -> str:
        return json.dumps(
            CsrfValidator.to_dict(result),
            indent=2,
        )