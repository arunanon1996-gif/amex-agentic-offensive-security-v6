import secrets
from dataclasses import dataclass
from threading import Lock


@dataclass
class AuthSession:
    session_id: str
    token: str
    username: str
    user_id: str | None = None


class SessionStore:
    """In-memory secret store. Tokens never enter the evidence database."""

    def __init__(self):
        self._sessions: dict[str, AuthSession] = {}
        self._lock = Lock()

    def create(
        self,
        token: str,
        username: str,
        user_id: str | None = None,
    ) -> AuthSession:
        session = AuthSession(
            session_id=secrets.token_urlsafe(18),
            token=token,
            username=username,
            user_id=user_id,
        )
        with self._lock:
            self._sessions[session.session_id] = session
        return session

    def get(self, session_id: str) -> AuthSession | None:
        with self._lock:
            return self._sessions.get(session_id)

    def clear(self):
        with self._lock:
            self._sessions.clear()


SESSION_STORE = SessionStore()
