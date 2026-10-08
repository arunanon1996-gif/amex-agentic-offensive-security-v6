# AMEX Agentic Offensive Security POC — V6

A bounded, evidence-driven agentic penetration-testing workbench built for the AMEX offensive-security assignment.

## What this POC demonstrates

The system models an offensive-security workflow as an evidence loop:

```text
OBSERVE
  ↓
UNDERSTAND TARGET
  ↓
SECURITY SIGNALS
  ↓
HYPOTHESES
  ↓
CANDIDATE ACTIONS
  ↓
SCORE / PRIORITIZE
  ↓
NEXT BEST ACTION
  ↓
POLICY CHECK
  ↓
EXECUTE VALIDATOR
  ↓
OBSERVE NEW EVIDENCE
  ↓
CORRELATE / UPDATE HYPOTHESES
  ↓
FINDING / NEXT ACTION / STOP
```

The POC is deliberately bounded. The decision layer cannot bypass target scope, registered tools, action limits, or runtime controls.

## Safety boundary

The default policy permits only:

- `localhost`
- `127.0.0.1`

Testing is intended for an authorized local sandbox such as OWASP Juice Shop.

Do not use this POC against third-party systems.

## Prerequisites

- Windows
- PowerShell
- Python 3.13+
- Docker Desktop
- Nmap on PATH for full network/service reconnaissance

The application has a localhost-safe built-in TCP reconnaissance fallback when Nmap is unavailable.

## Run the POC

### 1. Start the authorized Juice Shop sandbox

```powershell
docker compose -f .\sandbox\docker-compose.yml up -d
```

Juice Shop will be available at:

```text
http://127.0.0.1:3000
```

### 2. Start the POC

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\run_poc.ps1
```

The script creates a local Python virtual environment, installs `requirements.txt`, and starts the application.

Open:

```text
http://127.0.0.1:5000
```

### 3. Use the dashboard

Enter the authorized target:

```text
http://127.0.0.1:3000
```

The dashboard performs localhost scope and reachability checks before starting an assessment.

The main workflow is:

```text
Target
→ Scope / Policy
→ Recon
→ HTTP Discovery
→ Unauthenticated Baseline
→ Attack Surface
→ Signals
→ Hypotheses
→ Next Best Action
→ Targeted Validation
→ Findings
→ Authentication Phase
→ Authorization / JWT / IDOR / CSRF / Login Resilience
→ Evidence Correlation
→ Attack Paths
→ STOP
→ Report
```

## Agentic capabilities

### Unauthenticated baseline

`initial_web_scan` performs bounded public web discovery and records:

- endpoints
- parameters
- forms
- technologies
- CORS/security-header signals
- controlled XSS candidates
- controlled SQLi candidates

Baseline results are candidates, not confirmed vulnerabilities.

### Evidence-driven validation

Registered validators include:

- `xss_validate`
- `sqli_validate`
- `cors_validate`
- `csrf_validate`
- `security_header_validate`
- `authenticated_resource_probe`
- `idor_validate`
- `jwt_validate`
- `auth_bruteforce_validate`
- `tls_validate`
- `dom_xss_validate`
- `sqli_login_validate`

The decision engine chooses actions from evidence-backed hypotheses rather than following a fixed vulnerability checklist.

### Authentication phase

The POC does not silently inject credentials into the initial scan.

An approved test account can be created from the local dashboard. The authenticated phase can then establish context for:

- JWT inspection
- authentication-resilience checks
- authenticated resource discovery
- BOLA/IDOR validation
- CSRF applicability and validation

Credentials remain in runtime memory and are redacted from persisted action evidence.

### Explainability

The dashboard exposes:

- reasoning timeline
- hypothesis relationships
- action scores
- expected evidence
- validation outcomes
- findings
- evidence graph
- attack paths
- report output

The POC uses a deterministic decision/scoring layer so that the demonstration is reproducible and auditable. A production version could introduce an LLM into hypothesis generation/planning while keeping policy and execution boundaries deterministic.

## Testing

The repository includes the deterministic Python test suite.

Run:

```powershell
.\run_tests.ps1
```

or directly:

```powershell
python -m pytest -q
```

The test suite covers policy enforcement, tool registration, decision scoring, hypothesis/action flow, validators, evidence handling, finding generation, secret redaction, and agent STOP behavior.

Some live-target/infrastructure tests require the authorized Juice Shop sandbox and/or Nmap.

## Repository structure

```text
agent/          Decision, state, scoring, correlation, findings, orchestration
app/            Flask application and assessment service
evidence/       Evidence persistence and security models
evaluation/     Offline decision-quality evaluation
policy/         Scope and execution policy
report/         Report generation
sandbox/        Authorized Juice Shop Docker setup
templates/      Interactive dashboard UI
tests/          Automated tests
tools/          Reconnaissance and security validators
validation/     Validator interfaces
```

## Scope of the submission

This repository contains the executable V6 POC and its supporting tests. Generated runtime state, local virtual environments, cached Python files, and unrelated assignment documents are intentionally excluded.
