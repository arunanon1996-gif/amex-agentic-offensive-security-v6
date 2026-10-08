from agent.orchestrator import AgentOrchestrator


def main():
    orch = AgentOrchestrator()
    samples = {
        'nmap': {'ports':[{'port':3000,'state':'open','service':'http'}]},
        'http_probe': {'url':'http://localhost:3000/','status_code':200,'headers':{'Access-Control-Allow-Origin':'*','Content-Type':'text/html'},'body_preview':'OWASP Juice Shop'},
        'initial_web_scan': {'base_url':'http://localhost:3000','status_code':200,'discovered_urls':['http://localhost:3000/rest/products/search?q=x'],'endpoints':[{'url':'http://localhost:3000/rest/products/search?q=x','method':'GET','status_code':200,'parameters':['q']}],'technologies':['OWASP Juice Shop'],'security_signals':[],'xss_candidates':[{'url':'http://localhost:3000/rest/products/search?q=x','parameter':'q','marker':'AMEX_XSS_7f31','evidence':'Input marker was reflected.'}],'sqli_candidates':[{'url':'http://localhost:3000/rest/products/search?q=x','parameter':'q','error_signature':'sequelize','evidence':'Database error signature observed.'}],'forms':[]},
        'sqli_validate': {'url':'http://localhost:3000/rest/products/search?q=%27','method':'GET','parameter':'q','baseline_status':200,'probe_status':500,'error_signature':'sequelize','confirmed':True,'conclusion':'SQL error observed.','error':None},
        'cors_validate': {'status_code':200,'access_control_allow_origin':'*','access_control_allow_credentials':None,'origin_reflected':False,'wildcard_detected':True,'confirmed':True,'error':None},
        'authenticated_resource_probe': {'authenticated':True,'username':'test@example.local','user_id':'1','session_id':'s1','login_url':'http://localhost:3000/rest/user/login','resource_url':'http://localhost:3000/rest/basket/8','method':'GET','status_code':200,'object_identifier':'8','object_identifier_name':'basket','resource_type':'basket','response_preview':'{}'},
        'idor_validate': {'status':'CONFIRMED','alternate_object_accessible':True,'alternate_status_code':200,'baseline_status_code':200,'baseline_url':'http://localhost:3000/rest/basket/8','alternate_url':'http://localhost:3000/rest/basket/9','response_different':True,'evidence_summary':'Alternate object accessible.'},
        'csrf_validate': {'not_applicable':True,'status_code':0,'cross_origin_request_accepted':False,'state_change_confirmed':False,'confirmed':False,'conclusion':'Bearer authentication is not a classic CSRF primitive.'},
        'xss_validate': {'url':'http://localhost:3000/rest/products/search?q=x','method':'GET','parameter':'q','payload':'<img src=x onerror=alert(\'AMEX_XSS\')>','status_code':200,'reflected':True,'executable_context':True,'confirmed':True,'conclusion':'Executable context observed.','error':None},
        'security_header_validate': {'url':'http://localhost:3000/','status_code':200,'confirmed':True,'csp_present':False,'missing_headers':['Content-Security-Policy'],'present_headers':['X-Content-Type-Options'],'conclusion':'Missing CSP','error':None},
    }
    def fake(**kw): return {'status':'COMPLETED','result':samples[kw['tool']]}
    orch.assessment_service.execute = fake
    st = orch.start_assessment('localhost','agentic pentest')
    st = orch.run_assessment(st, {'ports':[3000],'username':'test@example.local','password':'secret','resource_template':'/rest/basket/{object_id}','login_path':'/rest/user/login','csrf_path':'/rest/basket/1/checkout'})
    assert st.status == 'COMPLETED'
    assert st.actions_taken[0:3] == ['nmap','http_probe','initial_web_scan']
    assert 'sqli_validate' in st.actions_taken
    assert 'xss_validate' in st.actions_taken
    assert 'idor_validate' in st.actions_taken
    assert st.decisions[-1].action == 'STOP'
    categories = {f['category']:f['status'] for f in st.findings}
    assert categories['SQL Injection'] == 'CONFIRMED'
    assert categories['XSS'] == 'CONFIRMED'
    assert categories['IDOR/BOLA'] == 'CONFIRMED'
    assert categories['CSRF'] == 'NOT_APPLICABLE'
    assert any(l['relation']=='baseline_candidate' for l in st.evidence_links)
    assert any(l['relation']=='hypothesis_drives_action' for l in st.evidence_links)
    print('Agentic baseline-to-validation chain PASSED.')


if __name__ == '__main__':
    main()
