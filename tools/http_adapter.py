import json
from dataclasses import dataclass, asdict
from urllib.request import Request, urlopen


@dataclass
class HttpResult:
    url: str
    status_code: int
    headers: dict
    body_preview: str
    error: str | None = None


class HttpAdapter:

    def probe(self, target: str, port: int) -> HttpResult:

        url = f"http://{target}:{port}/"

        request = Request(
            url,
            method="GET",
            headers={
                "User-Agent": "AMEX-AI-Offensive-Security-Agent/1.0"
            },
        )

        try:
            with urlopen(request, timeout=10) as response:

                body = response.read(2000)

                return HttpResult(
                    url=url,
                    status_code=response.status,
                    headers=dict(response.headers),
                    body_preview=body.decode(
                        "utf-8",
                        errors="replace",
                    ),
                )

        except Exception as exc:

            return HttpResult(
                url=url,
                status_code=0,
                headers={},
                body_preview="",
                error=str(exc),
            )

    def to_dict(self, result: HttpResult) -> dict:
        return asdict(result)

    def to_json(self, result: HttpResult) -> str:
        return json.dumps(
            self.to_dict(result),
            indent=2,
        )