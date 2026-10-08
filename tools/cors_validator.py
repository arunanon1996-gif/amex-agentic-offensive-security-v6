from dataclasses import dataclass, asdict
import json
from urllib.request import Request, urlopen
from validation.validator import ValidatorMetadata

@dataclass
class CorsValidationResult:
    url: str
    test_origin: str
    status_code: int
    access_control_allow_origin: str | None
    access_control_allow_credentials: str | None
    origin_reflected: bool
    wildcard_detected: bool
    confirmed: bool
    error: str | None = None


class CorsValidator:
    metadata = ValidatorMetadata(
    name="cors_validate",
    description=(
    "Validate CORS behavior using a controlled external Origin."
        ),
        category="CORS",
    )

    def validate(
        self,
        target: str,
        port: int,
        origin: str = "https://attacker.example",
    ) -> CorsValidationResult:

        url = f"http://{target}:{port}/"

        request = Request(
            url,
            method="GET",
            headers={
                "User-Agent": "AMEX-AI-Offensive-Security-Agent/1.0",
                "Origin": origin,
            },
        )

        try:
            with urlopen(request, timeout=10) as response:

                allow_origin = response.headers.get(
                    "Access-Control-Allow-Origin"
                )

                allow_credentials = response.headers.get(
                    "Access-Control-Allow-Credentials"
                )

                origin_reflected = allow_origin == origin
                wildcard_detected = allow_origin == "*"

                return CorsValidationResult(
                    url=url,
                    test_origin=origin,
                    status_code=response.status,
                    access_control_allow_origin=allow_origin,
                    access_control_allow_credentials=allow_credentials,
                    origin_reflected=origin_reflected,
                    wildcard_detected=wildcard_detected,
                    confirmed=(
                        origin_reflected
                        or wildcard_detected
                    ),
                )

        except Exception as exc:

            return CorsValidationResult(
                url=url,
                test_origin=origin,
                status_code=0,
                access_control_allow_origin=None,
                access_control_allow_credentials=None,
                origin_reflected=False,
                wildcard_detected=False,
                confirmed=False,
                error=str(exc),
            )

    @staticmethod
    def to_dict(result: CorsValidationResult) -> dict:
        return asdict(result)

    @staticmethod
    def to_json(result: CorsValidationResult) -> str:
        return json.dumps(
            CorsValidator.to_dict(result),
            indent=2,
        )