from tools.tls_validator import TLSValidator

def test_tls_validator_returns_structured_result_for_closed_port():
    result = TLSValidator().validate("127.0.0.1", 1)
    assert result.tls_enabled is False
    assert result.reachable is False
    assert result.conclusion
