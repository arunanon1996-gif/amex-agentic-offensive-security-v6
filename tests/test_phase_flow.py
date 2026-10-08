from agent.orchestrator import AgentOrchestrator


def test_unauthenticated_phase_waits_for_credentials_then_authenticated_phase(monkeypatch):
    orch=AgentOrchestrator()
    results={
      'nmap': {'ports':[{'port':3000,'state':'open','service':'http'}]},
      'http_probe': {'url':'http://localhost:3000/','status_code':200,'headers':{},'body_preview':'Juice Shop'},
      'initial_web_scan': {'endpoints':[],'technologies':['Juice Shop'],'security_signals':[],'xss_candidates':[],'sqli_candidates':[],'forms':[]},
      'security_header_validate': {'missing_headers': [], 'present_headers':['Content-Security-Policy'], 'confirmed':False, 'conclusion':'Headers present.'},
      'authenticated_resource_probe': {'authenticated':True,'username':'u','user_id':'1','session_id':'s1','resource_url':'http://localhost:3000/rest/basket/1','status_code':200,'object_identifier':'1','object_identifier_name':'basket','resource_type':'basket','response_preview':'{}'},
      'idor_validate': {'status':'NOT_CONFIRMED','baseline_status_code':200,'alternate_status_code':404,'alternate_object_accessible':False,'response_different':True,'evidence_summary':'Alternate object denied.'},
      'auth_bruteforce_validate': {'confirmed':False,'rate_limited':True,'account_lockout_observed':False,'status_codes':[401,429,429,429],'response_lengths':[1,1,1,1],'conclusion':'Rate limiting observed.'},
      'jwt_validate': {'confirmed':False,'token_present':True,'algorithm':'HS256','has_exp':True,'expired':False,'has_issuer':True,'has_audience':True,'sensitive_claims':[],'conclusion':'JWT controls appear reasonable.'},
    }
    def fake_execute(assessment_id,target,tool,action_count,_runtime_context=None,**kwargs):
        return {'status':'COMPLETED','result':results[tool]}
    orch.assessment_service.execute=fake_execute
    state=orch.start_assessment('localhost','phase test')
    orch.run_assessment(state, initial_parameters={'ports':[3000]}, phase='UNAUTHENTICATED')
    assert state.status == 'WAITING_FOR_AUTH'
    assert 'authenticated_resource_probe' not in state.actions_taken
    state.runtime_context.update({'username':'u','password':'p','resource_template':'/rest/basket/{object_id}','login_path':'/rest/user/login'})
    state.phase='AUTHENTICATED'; state.status='RUNNING'
    orch.run_assessment(state, phase='AUTHENTICATED')
    assert state.status == 'COMPLETED'
    assert 'authenticated_resource_probe' in state.actions_taken
    assert 'idor_validate' in state.actions_taken
    assert 'STOP' == state.decisions[-1].action
