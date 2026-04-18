// Block tool calls whose args contain string values matching well-known secret formats.
// Most useful on send_email/post_webhook/notify-style tools that move data outward.

const SECRET_PATTERNS = [
  { re: /\bsk-(?:ant|proj|live|test)-[A-Za-z0-9_-]{20,}/, label: 'Anthropic / OpenAI API key' },
  { re: /\bghp_[A-Za-z0-9]{30,}/, label: 'GitHub PAT (classic)' },
  { re: /\bghs_[A-Za-z0-9]{30,}/, label: 'GitHub server token' },
  { re: /\bgho_[A-Za-z0-9]{30,}/, label: 'GitHub OAuth token' },
  { re: /\bxox[baprs]-[A-Za-z0-9-]{10,}/, label: 'Slack token' },
  { re: /\bAKIA[A-Z0-9]{16}\b/, label: 'AWS access key' },
  { re: /-----BEGIN [A-Z]+ PRIVATE KEY-----/, label: 'PEM private key' },
  { re: /\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/, label: 'JWT' },
];

function scan(value, out = [], path = '$') {
  if (value == null) return out;
  if (typeof value === 'string') {
    for (const { re, label } of SECRET_PATTERNS) {
      const m = value.match(re);
      if (m) out.push({ path, label, match: m[0].slice(0, 12) + '…' });
    }
  } else if (Array.isArray(value)) {
    value.forEach((v, i) => scan(v, out, `${path}[${i}]`));
  } else if (typeof value === 'object') {
    for (const [k, v] of Object.entries(value)) scan(v, out, `${path}.${k}`);
  }
  return out;
}

export const secretEgress = {
  id: 'secret-egress',
  check(ctx) {
    const hits = scan(ctx.args);
    if (!hits.length) return null;
    return hits.map(h => ({
      severity: 'critical', verdict: 'block',
      title: `Secret pattern in tool args: ${h.label}`,
      message: `Tool "${ctx.toolName}" called with arg path ${h.path} that matches a secret format. Blocking to prevent egress.`,
      evidence: { path: h.path, label: h.label, prefix: h.match },
    }));
  },
};
