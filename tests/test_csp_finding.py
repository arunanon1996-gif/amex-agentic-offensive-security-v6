from agent.finding_engine import FindingEngine


def test_missing_csp_becomes_confirmed_header_finding():
    findings = FindingEngine().from_observation('security_header_validate', {
        'url': 'http://localhost:3000/',
        'missing_headers': ['Content-Security-Policy', 'Referrer-Policy'],
        'present_headers': [],
    })
    assert findings
    assert findings[0]['finding_id'] == 'F-CSP-001'
    assert findings[0]['status'] == 'CONFIRMED'
    assert findings[0]['severity'] == 'MEDIUM'
