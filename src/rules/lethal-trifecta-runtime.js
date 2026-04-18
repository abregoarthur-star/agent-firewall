// Runtime correlate of mcp-audit's static lethal-trifecta rule.
// If a session uses tools spanning a forbidden capability combo, warn.
// (Static analysis catches design-time risk; this catches runtime composition.)

const FORBIDDEN_COMBOS = [
  { caps: ['shell_exec', 'network_out'],  severity: 'critical', title: 'Runtime: shell exec + network egress in same session' },
  { caps: ['secret_read', 'network_out'], severity: 'critical', title: 'Runtime: secret read + network egress in same session' },
  { caps: ['file_read', 'network_out'],   severity: 'high',     title: 'Runtime: file read + network egress in same session' },
  { caps: ['file_write', 'shell_exec'],   severity: 'high',     title: 'Runtime: file write + shell exec in same session' },
];

export const lethalTrifectaRuntime = {
  id: 'lethal-trifecta-runtime',
  check(ctx, session) {
    if (!session) return null;
    const seen = new Set(session.capsSeen || []);
    for (const c of ctx.caps || []) seen.add(c);

    const findings = [];
    for (const combo of FORBIDDEN_COMBOS) {
      if (combo.caps.every(c => seen.has(c))) {
        // Only fire on the call that completes the combo
        const newOnes = (ctx.caps || []).filter(c => combo.caps.includes(c) && !(session.capsSeen || new Set()).has(c));
        if (newOnes.length === 0) continue;
        findings.push({
          severity: combo.severity,
          verdict: combo.severity === 'critical' ? 'block' : 'warn',
          title: combo.title,
          message: `Session has now exercised every capability in a forbidden combo. Blocking before the kill chain completes.`,
          evidence: { combo: combo.caps, allCapsSeen: [...seen], thisCallCaps: ctx.caps },
        });
      }
    }
    return findings.length ? findings : null;
  },
};
