// Block file write/read tools whose path arg is outside allowed roots.
// Policy: { fs: { allowedRoots: ['/workspace', '/tmp'], blockedPaths: ['/etc', '/.ssh'] } }
//
// Heuristic: looks for any string arg shaped like a path (contains '/' or starts with letter:\).

const PATH_KEYS = /^(path|file|filename|filepath|src|dst|destination|to|target|output)$/i;

function looksLikePath(s) {
  return typeof s === 'string' && (s.startsWith('/') || /^[a-zA-Z]:\\/.test(s) || s.startsWith('~/') || s.startsWith('./') || s.startsWith('../'));
}

function collectPaths(args, out = []) {
  if (!args || typeof args !== 'object') return out;
  for (const [k, v] of Object.entries(args)) {
    if (typeof v === 'string') {
      if (PATH_KEYS.test(k) || looksLikePath(v)) out.push({ key: k, value: v });
    } else if (typeof v === 'object') {
      collectPaths(v, out);
    }
  }
  return out;
}

function expandHome(p) {
  return p.startsWith('~/') ? p.replace(/^~/, process.env.HOME || '') : p;
}

function isUnder(child, parent) {
  const c = expandHome(child);
  const p = expandHome(parent);
  return c === p || c.startsWith(p.endsWith('/') ? p : p + '/');
}

export const pathAllowlist = {
  id: 'path-allowlist',
  check(ctx, session, policy) {
    const cfg = policy.fs;
    if (!cfg || (!cfg.allowedRoots && !cfg.blockedPaths)) return null;
    const paths = collectPaths(ctx.args);
    if (paths.length === 0) return null;

    const findings = [];
    for (const { key, value } of paths) {
      if (cfg.blockedPaths) {
        for (const blocked of cfg.blockedPaths) {
          if (isUnder(value, blocked)) {
            findings.push({
              severity: 'critical', verdict: 'block',
              title: `Path under blocked root: ${blocked}`,
              message: `Tool arg "${key}" targets a sensitive path.`,
              evidence: { key, value, blocked },
            });
          }
        }
      }
      if (cfg.allowedRoots) {
        const ok = cfg.allowedRoots.some(root => isUnder(value, root));
        if (!ok) {
          findings.push({
            severity: 'high', verdict: 'block',
            title: `Path outside allowed roots`,
            message: `Tool arg "${key}" = "${value}" is outside ${cfg.allowedRoots.join(', ')}.`,
            evidence: { key, value, allowedRoots: cfg.allowedRoots },
          });
        }
      }
    }
    return findings.length ? findings : null;
  },
};
