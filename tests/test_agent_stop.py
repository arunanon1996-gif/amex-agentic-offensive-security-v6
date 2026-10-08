from agent.orchestrator import AgentOrchestrator


def test_explicit_stop_is_persisted_and_does_not_execute():
    orchestrator = AgentOrchestrator()
    state = orchestrator.start_assessment('localhost', 'STOP gate')
    orchestrator.decision_engine.decide_next_action = lambda state, context=None: None

    def must_not_execute(*args, **kwargs):
        raise AssertionError('STOP must never reach tool execution')

    orchestrator.assessment_service.execute = must_not_execute
    final = orchestrator.run_assessment(state, initial_parameters={'ports': [3000]})

    assert final.status == 'COMPLETED'
    assert final.actions_taken == []
    assert final.decisions[-1].action == 'STOP'
    assert final.decisions[-1].reason
    evidence = orchestrator.evidence.get_all(final.assessment_id)
    assert any(e['evidence_type'] == 'agent_stop' for e in evidence)
    assert any(e['evidence_type'] == 'assessment_completed' for e in evidence)

if __name__ == '__main__':
    test_explicit_stop_is_persisted_and_does_not_execute()
    print('Agent STOP / COMPLETION test PASSED.')
