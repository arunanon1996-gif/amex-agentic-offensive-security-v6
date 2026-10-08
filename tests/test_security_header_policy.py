from policy.policy_engine import PolicyEngine


def test_security_header_validator_is_policy_allowed():
    decision = PolicyEngine().check_tool("security_header_validate")
    assert decision.allowed is True
