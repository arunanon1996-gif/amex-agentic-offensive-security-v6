from dataclasses import dataclass, asdict
import json
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from validation.validator import ValidatorMetadata
from tools.session_store import SESSION_STORE


@dataclass
class AuthenticatedResourceProbeResult:
    authenticated: bool
    username: str
    user_id: str | None
    session_id: str | None
    login_url: str
    resource_url: str | None
    method: str
    status_code: int
    object_identifier: str | None
    object_identifier_name: str | None
    resource_type: str | None
    response_preview: str
    error: str | None = None


class AuthenticatedResourceProbe:
    """
    Controlled authenticated resource discovery.

    The probe logs in, obtains an application-owned object identifier,
    and requests that user's own resource. The bearer token is kept only
    in the process-local SessionStore and is never returned in the result.
    """

    metadata = ValidatorMetadata(
        name="authenticated_resource_probe",
        description=(
            "Establish an approved authenticated session and probe the "
            "user-owned resource identified in the configured URL template."
        ),
        category="Authorization",
    )

    def probe(
        self,
        target: str,
        port: int,
        username: str,
        password: str,
        login_path: str = "/rest/user/login",
        resource_template: str = "/rest/basket/{object_id}",
        object_id_field: str = "bid",
        resource_type: str = "basket",
    ) -> AuthenticatedResourceProbeResult:
        login_url = f"http://{target}:{port}{login_path}"
        login_payload = json.dumps(
            {"email": username, "password": password}
        ).encode("utf-8")

        login_request = Request(
            login_url,
            data=login_payload,
            method="POST",
            headers={
                "User-Agent": "AMEX-AI-Offensive-Security-Agent/1.0",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )

        try:
            with urlopen(login_request, timeout=10) as response:
                raw = response.read(10000)
                login_data = json.loads(
                    raw.decode("utf-8", errors="replace")
                )

            token = self._read_path(
                login_data,
                "authentication.token",
            )

            user_id = self._read_path(
                login_data,
                "authentication.umail",
            ) or self._read_path(
                login_data,
                "authentication.id",
            )

            object_id = self._read_path(
                login_data,
                object_id_field,
            )

            if object_id is None:
                object_id = self._read_path(
                    login_data,
                    f"authentication.{object_id_field}",
                )

            if not token:
                return self._failure(
                    username=username,
                    login_url=login_url,
                    reason="Login succeeded but no bearer token was returned.",
                )

            if object_id is None:
                return self._failure(
                    username=username,
                    login_url=login_url,
                    reason=(
                        f"Login succeeded but object field "
                        f"'{object_id_field}' was not returned."
                    ),
                    authenticated=True,
                    user_id=user_id,
                )

            session = SESSION_STORE.create(
                token=str(token),
                username=username,
                user_id=str(user_id) if user_id is not None else None,
            )

            object_id = str(object_id)
            resource_path = resource_template.format(
                object_id=object_id
            )
            resource_url = (
                f"http://{target}:{port}{resource_path}"
            )

            resource_request = Request(
                resource_url,
                method="GET",
                headers={
                    "User-Agent": "AMEX-AI-Offensive-Security-Agent/1.0",
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/json",
                },
            )

            try:
                with urlopen(resource_request, timeout=10) as response:
                    body = response.read(3000)
                    return AuthenticatedResourceProbeResult(
                        authenticated=True,
                        username=username,
                        user_id=session.user_id,
                        session_id=session.session_id,
                        login_url=login_url,
                        resource_url=resource_url,
                        method="GET",
                        status_code=response.status,
                        object_identifier=object_id,
                        object_identifier_name=self._identifier_name(
                            resource_path,
                            object_id,
                        ),
                        resource_type=resource_type,
                        response_preview=body.decode(
                            "utf-8",
                            errors="replace",
                        ),
                    )
            except HTTPError as exc:
                body = exc.read(3000).decode(
                    "utf-8",
                    errors="replace",
                )
                return AuthenticatedResourceProbeResult(
                    authenticated=True,
                    username=username,
                    user_id=session.user_id,
                    session_id=session.session_id,
                    login_url=login_url,
                    resource_url=resource_url,
                    method="GET",
                    status_code=exc.code,
                    object_identifier=object_id,
                    object_identifier_name=self._identifier_name(
                        resource_path,
                        object_id,
                    ),
                    resource_type=resource_type,
                    response_preview=body,
                    error=f"HTTP {exc.code}",
                )

        except Exception as exc:
            return self._failure(
                username=username,
                login_url=login_url,
                reason=str(exc),
            )

    @staticmethod
    def _read_path(data, path):
        if path in data:
            return data.get(path)

        current = data
        for part in path.split("."):
            if not isinstance(current, dict) or part not in current:
                return None
            current = current[part]
        return current

    @staticmethod
    def _identifier_name(resource_path, object_id):
        parts = resource_path.strip("/").split("/")
        for index, part in enumerate(parts):
            if part == object_id and index > 0:
                return parts[index - 1]
        return "object_id"

    @staticmethod
    def _failure(
        username,
        login_url,
        reason,
        authenticated=False,
        user_id=None,
    ):
        return AuthenticatedResourceProbeResult(
            authenticated=authenticated,
            username=username,
            user_id=user_id,
            session_id=None,
            login_url=login_url,
            resource_url=None,
            method="GET",
            status_code=0,
            object_identifier=None,
            object_identifier_name=None,
            resource_type=None,
            response_preview="",
            error=reason,
        )

    @staticmethod
    def to_dict(result):
        return asdict(result)

    @staticmethod
    def to_json(result):
        return json.dumps(asdict(result), indent=2)
