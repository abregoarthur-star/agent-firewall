// Detect cross-tool exfiltration patterns within a single session:
// a sensitive read followed by an outbound send within N calls.
//
// Capability tags expected on ctx.caps (set by caller or inferred from tool name):
//   - secret_read, file_read, history_read  → "sensitive read"
//   - network_out, email_send, webhook      → "outbound"
//
// Window: last 10 calls in the session. If we see a sensitive read followed by
// an outbound call (in that order, in the same session), flag the second call.

const SENSITIVE_READ = new Set(['secret_read', 'file_read', 'history_read', 'memory_read']);
const OUTBOUND = new Set(['network_out', 'email_send', 'webhook', 'telegram_send', 'slack_send', 'sms_send']);

export const exfilTrail = {
  id: 'exfil-trail',
  check(ctx, session) {
    if (!session?.history?.length) return null;
    const isOutbound = (ctx.caps || []).some(c => OUTBOUND.has(c));
    if (!isOutbound) return null;

    const window = session.history.slice(-10);
    const sensitive = window.filter(h => (h.caps || []).some(c => SENSITIVE_READ.has(c)));
    if (sensitive.length === 0) return null;

    const last = sensitive[sensitive.length - 1];
    return {
      severity: 'high', verdict: 'block',
      title: 'Exfiltration trail detected',
      message: `Outbound tool "${ctx.toolName}" follows a sensitive-read tool "${last.toolName}" in the same session. Blocking to prevent data exfiltration.`,
      evidence: {
        sensitiveRead: { tool: last.toolName, ts: last.ts, caps: last.caps },
        outbound: { tool: ctx.toolName, caps: ctx.caps },
        windowSize: window.length,
      },
    };
  },
};
