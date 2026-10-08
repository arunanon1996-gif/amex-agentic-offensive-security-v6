import base64
import json

from tools.auth_bruteforce_validator import AuthBruteForceValidator
from tools.jwt_validator import JwtValidator
from tools.session_store import SESSION_STORE


def test_bruteforce_is_bounded_without_network(monkeypatch):
    calls=[]
    class Resp:
        status=401
        def read(self, n): return b'Unauthorized'
        def __enter__(self): return self
        def __exit__(self,*a): pass
    def fake_urlopen(req, timeout=5):
        calls.append(req)
        return Resp()
    monkeypatch.setattr('tools.auth_bruteforce_validator.urlopen', fake_urlopen)
    result=AuthBruteForceValidator().validate('localhost',3000,'/rest/user/login','test@example.local',attempts=99,interval_seconds=0.01)
    assert result.attempts == 5
    assert len(calls) == 5
    assert result.confirmed is True


def test_jwt_validator_inspects_runtime_session():
    def enc(obj):
        raw=json.dumps(obj,separators=(',',':')).encode()
        return base64.urlsafe_b64encode(raw).decode().rstrip('=')
    token='.'.join([enc({'alg':'HS256','typ':'JWT'}),enc({'sub':'1'}),enc({'sig':'x'})])
    session=SESSION_STORE.create(token,'test@example.local','1')
    result=JwtValidator().validate('localhost',session_id=session.session_id)
    assert result.token_present is True
    assert result.algorithm == 'HS256'
    assert result.has_exp is False
    assert result.confirmed is True
    SESSION_STORE.clear()
