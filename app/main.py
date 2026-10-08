from flask import Flask, jsonify, render_template, request

import json
import secrets
import string
import threading
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from tools.nmap_adapter import NmapAdapter
from app.target_utils import normalize_target

from agent.orchestrator import AgentOrchestrator
from evaluation.harness import EvaluationHarness
from report.report_generator import ReportGenerator


app = Flask(__name__, template_folder="../templates", static_folder="../static")

ASSESSMENTS = {}
ASSESSMENT_LOCK = threading.RLock()
REPORTS = ReportGenerator()
EVALUATION = EvaluationHarness()



def _provision_local_test_account(target: str, port: int) -> dict:
    suffix = secrets.token_hex(5)
    email = f"amex-poc-{suffix}@example.local"
    alphabet = string.ascii_letters + string.digits
    password = "A!" + "".join(secrets.choice(alphabet) for _ in range(18))
    url = f"http://{target}:{port}/api/Users"
    payload = json.dumps({"email": email, "password": password, "passwordRepeat": password}).encode()
    req = Request(url, data=payload, method="POST", headers={"User-Agent":"AMEX-AI-Offensive-Security-Agent/3.0","Content-Type":"application/json","Accept":"application/json"})
    try:
        with urlopen(req, timeout=10) as response:
            response.read(5000)
            if response.status >= 400:
                raise RuntimeError(f"Account creation returned HTTP {response.status}")
    except HTTPError as exc:
        body = exc.read(5000).decode("utf-8", errors="replace")
        raise RuntimeError(f"Account creation returned HTTP {exc.code}: {body[:300]}") from exc
    return {"username": email, "password": password}


def _run_phase(state, orchestrator, phase):
    try:
        orchestrator.run_assessment(state, phase=phase)
    except Exception as exc:
        state.status = "FAILED"
        state.runtime_context["worker_error"] = str(exc)


def _start_worker(state, orchestrator, phase):
    thread = threading.Thread(target=_run_phase, args=(state, orchestrator, phase), daemon=True)
    thread.start()
    state.runtime_context["worker_started"] = True


@app.route("/")
def dashboard():
    return render_template("dashboard.html")


@app.route("/scoring")
def scoring():
    return render_template("scoring.html")

@app.route("/health")
def health():
    return {"status": "ok", "service": "AMEX AI Offensive Security Agent"}


@app.post("/api/test-account")
def create_test_account():
    payload = request.get_json(silent=True) or {}
    target = payload.get("target", "localhost")
    port = int(payload.get("port", 3000))
    if target not in {"localhost", "127.0.0.1"}:
        return jsonify({"status":"DENIED","reason":"Only localhost targets are permitted by the POC."}), 403
    try:
        account = _provision_local_test_account(target, port)
        return jsonify({"status":"CREATED", **account, "note":"Disposable localhost-only POC account."})
    except Exception as exc:
        return jsonify({"status":"FAILED","reason":str(exc)}), 502


@app.get("/api/preflight")
def preflight():
    raw_target = request.args.get("target", "")
    try:
        target, port, display = normalize_target(raw_target, request.args.get("port"))
    except (ValueError, TypeError) as exc:
        return jsonify({"ready": False, "target_ok": False, "nmap_ok": False, "target": raw_target, "reason": str(exc)}), 400
    nmap_ok, nmap_detail = NmapAdapter.check_available()
    reachable = False
    reachability_detail = "Not checked"
    try:
        with urlopen(f"http://{target}:{port}/", timeout=3) as response:
            reachable = 200 <= response.status < 500
            reachability_detail = f"HTTP {response.status}"
    except HTTPError as exc:
        reachable = True
        reachability_detail = f"HTTP {exc.code}"
    except Exception as exc:
        reachability_detail = str(exc)[:160]
    ready = reachable
    return jsonify({
        "ready": ready,
        "target_ok": True,
        "nmap_ok": nmap_ok,
        "nmap_detail": nmap_detail,
        "recon_fallback_available": True,
        "recon_mode": "nmap" if nmap_ok else "builtin_tcp_fallback",
        "target_reachable": reachable,
        "target_detail": reachability_detail,
        "target": target,
        "port": port,
        "display": display,
        "reason": None if ready else (nmap_detail if not nmap_ok else "Target is not reachable."),
    })


@app.post("/api/assessments")
def create_assessment():
    payload = request.get_json(silent=True) or {}
    try:
        target, port, display = normalize_target(payload.get("target_url") or payload.get("target"), payload.get("port"))
    except (ValueError, TypeError) as exc:
        return jsonify({"status":"DENIED","reason":str(exc)}), 400

    orchestrator = AgentOrchestrator()
    state = orchestrator.start_assessment(target=target, objective=payload.get("objective", "Identify and validate security-relevant web application hypotheses."))
    state.runtime_context.update({
        "ports": [port],
        "target_url": display,
        "login_path": payload.get("login_path", "/rest/user/login"),
        "resource_template": payload.get("resource_template", "/rest/basket/{object_id}"),
        "object_id_field": payload.get("object_id_field", "bid"),
        "resource_type": payload.get("resource_type", "basket"),
        "alternate_object_id": payload.get("alternate_object_id"),
        "csrf_path": payload.get("csrf_path", "/rest/basket/1/checkout"),
        "csrf_body": payload.get("csrf_body", "test=value"),
    })
    with ASSESSMENT_LOCK:
        ASSESSMENTS[state.assessment_id] = state
    _start_worker(state, orchestrator, "UNAUTHENTICATED")
    return jsonify({"assessment_id": state.assessment_id, "status": state.status, "phase": state.phase, "target": target, "port": port, "target_url": display, "message": "Unauthenticated recon/baseline started."}), 202


@app.post("/api/assessments/<assessment_id>/authenticate")
def authenticate_assessment(assessment_id):
    state = ASSESSMENTS.get(assessment_id)
    if state is None:
        return jsonify({"error":"Assessment not found."}), 404
    if state.status != "WAITING_FOR_AUTH":
        return jsonify({"status":"DENIED","reason":f"Authenticated phase requires WAITING_FOR_AUTH; current status is {state.status}."}), 409
    payload = request.get_json(silent=True) or {}
    username = payload.get("username")
    password = payload.get("password")
    if not username or not password:
        return jsonify({"status":"DENIED","reason":"Username and password are required to start the authenticated phase."}), 400
    state.runtime_context["username"] = username
    state.runtime_context["password"] = password
    state.phase = "AUTHENTICATED"
    state.status = "RUNNING"
    orchestrator = getattr(state, "_orchestrator", None)
    if orchestrator is None:
        return jsonify({"status":"FAILED","reason":"Assessment orchestrator is unavailable."}), 500
    _start_worker(state, orchestrator, "AUTHENTICATED")
    return jsonify({"assessment_id": assessment_id, "status": state.status, "phase": state.phase, "message":"Authenticated assessment started."}), 202


@app.get("/api/assessments/<assessment_id>")
def get_assessment(assessment_id):
    state = ASSESSMENTS.get(assessment_id)
    if state is None:
        return jsonify({"error":"Assessment not found."}), 404
    summary = state.summary()
    summary["worker_error"] = state.runtime_context.get("worker_error")
    return jsonify(summary)


@app.get("/api/assessments/<assessment_id>/evidence")
def get_evidence(assessment_id):
    state = ASSESSMENTS.get(assessment_id)
    if state is None:
        return jsonify({"error":"Assessment not found."}), 404
    orchestrator = getattr(state, "_orchestrator", None)
    return jsonify(orchestrator.evidence.get_all(assessment_id) if orchestrator else {"assessment": state.summary()})


@app.get("/api/assessments/<assessment_id>/report")
def get_report(assessment_id):
    state = ASSESSMENTS.get(assessment_id)
    if state is None:
        return jsonify({"error":"Assessment not found."}), 404
    if request.args.get("format", "json") == "markdown":
        return REPORTS.to_markdown(state), 200, {"Content-Type":"text/markdown; charset=utf-8"}
    return jsonify(REPORTS.generate(state))


@app.get("/api/evaluation")
def get_evaluation():
    return jsonify({"cases": EVALUATION.run_reference_cases()})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
