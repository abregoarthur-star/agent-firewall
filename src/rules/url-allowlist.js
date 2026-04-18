// Block tool calls whose args contain URLs going to non-allowlisted hosts.
// Policy: { url: { allowedHosts: ['github.com', 'api.openai.com'], allowedSchemes: ['https'] } }

const URL_RE = /\bhttps?:\/\/[^\s"'<>)]+/gi;

function findUrls(value, out = []) {
  if (!value) return out;
  if (typeof value === 'string') {
    const m = value.match(URL_RE);
    if (m) out.push(...m);
  } else if (Array.isArray(value)) {
    for (const v of value) findUrls(v, out);
  } else if (typeof value === 'object') {
    for (const v of Object.values(value)) findUrls(v, out);
  }
  return out;
}

export const urlAllowlist = {
  id: 'url-allowlist',
  check(ctx, session, policy) {
    const cfg = policy.url;
    if (!cfg || (!cfg.allowedHosts && !cfg.blockedHosts && !cfg.allowedSchemes)) return null;
    const urls = findUrls(ctx.args);
    if (urls.length === 0) return null;

    const findings = [];
    for (const raw of urls) {
      let u;
      try { u = new URL(raw); } catch { continue; }
      const host = u.hostname.toLowerCase();
      const scheme = u.protocol.replace(':', '');

      if (cfg.allowedSchemes && !cfg.allowedSchemes.includes(scheme)) {
        findings.push({
          severity: 'high', verdict: 'block',
          title: `Disallowed URL scheme: ${scheme}`,
          message: `Tool call passes ${scheme}:// — only ${cfg.allowedSchemes.join(',')} permitted by policy.`,
          evidence: { url: raw, scheme },
        });
        continue;
      }

      if (cfg.blockedHosts && hostMatches(host, cfg.blockedHosts)) {
        findings.push({
          severity: 'critical', verdict: 'block',
          title: `Blocked host: ${host}`,
          message: `Tool call targets explicitly blocked host.`,
          evidence: { url: raw, host },
        });
        continue;
      }

      if (cfg.allowedHosts && !hostMatches(host, cfg.allowedHosts)) {
        findings.push({
          severity: 'high', verdict: 'block',
          title: `Non-allowlisted host: ${host}`,
          message: `Tool call targets a host not in the URL allowlist.`,
          evidence: { url: raw, host, allowedHosts: cfg.allowedHosts },
        });
      }
    }
    return findings.length ? findings : null;
  },
};

function hostMatches(host, list) {
  for (const pattern of list) {
    if (pattern === host) return true;
    if (pattern.startsWith('*.') && host.endsWith(pattern.slice(1))) return true;
    if (host.endsWith('.' + pattern)) return true; // suffix match (api.github.com matches github.com)
  }
  return false;
}
