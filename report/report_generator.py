from datetime import datetime, timezone

class ReportGenerator:
    def generate(self, state):
        return {
            'report_version': '2.0',
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'assessment': state.summary(),
            'executive_summary': self._summary(state),
            'finding_count': len(state.findings),
            'finding_counts': state.summary().get('finding_counts', {}),
            'phase': state.phase,
            'attack_paths': state.attack_paths,
            'scoring_trace': state.scoring_trace,
            'confirmed_findings': [f for f in state.findings if f.get('status') == 'CONFIRMED'],
            'decision_trace': [
                {
                    'step': index + 1,
                    'action': d.action,
                    'reason': d.reason,
                    'expected_evidence': d.expected_evidence,
                    'parameters': d.parameters,
                    'score': d.score,
                    'hypothesis_id': d.hypothesis_id,
                }
                for index, d in enumerate(state.decisions)
            ],
            'evidence_relationships': state.evidence_links,
            'attack_surface': state.attack_surface,
        }

    def to_markdown(self, state):
        r = self.generate(state)
        lines = [
            '# AMEX Agentic Offensive Security Assessment', '',
            f'**Assessment:** `{state.assessment_id}`  ',
            f'**Target:** `{state.target}`  ',
            f'**Status:** `{state.status}`  ',
            f'**Phase:** `{state.phase}`  ',
            f'**Actions:** `{state.action_count}`  ', '',
            '## Executive Summary', '', r['executive_summary'], '',
            '## Attack Surface', '',
            f"- Services: {len(state.attack_surface.get('services', []))}",
            f"- Endpoints: {len(state.attack_surface.get('endpoints', []))}",
            f"- Technologies: {', '.join(state.attack_surface.get('technologies', [])) or 'Not identified'}", '',
            '## Findings', ''
        ]
        if not state.findings:
            lines.append('No validated findings were produced.')
        else:
            for f in state.findings:
                lines += [f"### {f['finding_id']} — {f['title']}", '', f"- **Category:** {f['category']}", f"- **Severity:** {f['severity']}", f"- **Status:** {f['status']}", f"- **Confidence:** {f['confidence']:.2f}", f"- **Hypothesis:** {f['hypothesis']}", f"- **How found:** {f.get('discovery_method', f.get('validation', {}).get('validator', 'Security validation'))}", f"- **Impact:** {f['impact']}", f"- **Remediation:** {f['remediation']}", '']
        lines += ['## Agent Reasoning Timeline', '', '| Step | Action | Score | Why | Expected evidence |', '|---:|---|---:|---|---|']
        for i, d in enumerate(state.decisions, 1):
            lines.append(f"| {i} | `{d.action}` | {d.score if d.score is not None else ''} | {d.reason.replace('|','\\|')} | {d.expected_evidence.replace('|','\\|')} |")
        lines += ['', '## Attack Paths', '']
        for path in state.attack_paths:
            lines.append(f"- **{path['title']}**: {' → '.join(path['steps'])}")
        if not state.attack_paths:
            lines.append('No confirmed attack paths were correlated.')
        lines += ['', '## Evidence Relationships', '']
        for link in state.evidence_links:
            lines.append(f"- **{link['source']}** — {link['relation']} → **{link['target']}**: {link['reason']}")
        lines += ['', '## Actions Taken', '', '`' + ' → '.join(state.actions_taken) + '`', '']
        return '\n'.join(lines)

    @staticmethod
    def _summary(state):
        if not state.findings:
            return 'The agent completed the assessment without producing a validated finding.'
        confirmed = sum(1 for f in state.findings if f.get('status') == 'CONFIRMED')
        inconclusive = sum(1 for f in state.findings if f.get('status') == 'INCONCLUSIVE')
        return f'The agent produced {len(state.findings)} validation result(s): {confirmed} confirmed and {inconclusive} inconclusive.'
