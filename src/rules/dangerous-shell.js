// Detect dangerous shell command patterns in args of exec-style tools.
// Matches against well-known destructive or pipe-and-execute idioms.

const SHELL_ARG_KEYS = /^(cmd|command|exec|shell|script|run|args|argv)$/i;

const DANGEROUS_PATTERNS = [
  { re: /\brm\s+(-[rRf]+\s+)*\/(\s|$)/, severity: 'critical', label: 'rm root' },
  { re: /\brm\s+-rf?\b/, severity: 'high',     label: 'rm -rf' },
  { re: /(?:curl|wget)[^|]*\|\s*(?:sh|bash|zsh|sudo)/i, severity: 'critical', label: 'curl|sh remote exec' },
  { re: /\bdd\s+if=.*of=\/dev\/(sd|nvme|hd)/, severity: 'critical', label: 'dd to disk device' },
  { re: /:(){\s*:\|:&\s*};:/, severity: 'critical', label: 'fork bomb' },
  { re: /\bmkfs\./, severity: 'critical', label: 'filesystem format' },
  { re: /\bchmod\s+777\b/, severity: 'medium', label: 'chmod 777' },
  { re: /\bsudo\b/, severity: 'high', label: 'sudo escalation' },
  { re: /\beval\s*\(\s*\$/i, severity: 'high', label: 'shell eval' },
  { re: /\b(?:nc|ncat|netcat)\b.*-e/, severity: 'critical', label: 'netcat reverse shell' },
  { re: /\$\(\s*curl|`curl/, severity: 'high', label: 'command substitution + curl' },
  { re: />\s*\/dev\/(?:sda|sdb|sdc|nvme0)/, severity: 'critical', label: 'redirect to raw disk' },
  { re: /\bbase64\s+-d\s*\|\s*(?:sh|bash)/, severity: 'critical', label: 'base64 decode + exec' },
];

function collectShellStrings(args, out = []) {
  if (!args || typeof args !== 'object') return out;
  for (const [k, v] of Object.entries(args)) {
    if (typeof v === 'string') {
      if (SHELL_ARG_KEYS.test(k) || /\b(?:rm|curl|wget|sudo|chmod|dd|mkfs|nc|netcat)\b/.test(v)) {
        out.push({ key: k, value: v });
      }
    } else if (Array.isArray(v)) {
      const joined = v.join(' ');
      if (SHELL_ARG_KEYS.test(k)) out.push({ key: k, value: joined });
    } else if (typeof v === 'object') {
      collectShellStrings(v, out);
    }
  }
  return out;
}

export const dangerousShell = {
  id: 'dangerous-shell',
  check(ctx) {
    const strings = collectShellStrings(ctx.args);
    if (strings.length === 0) return null;
    const findings = [];
    for (const { key, value } of strings) {
      for (const { re, severity, label } of DANGEROUS_PATTERNS) {
        if (re.test(value)) {
          findings.push({
            severity, verdict: severity === 'critical' || severity === 'high' ? 'block' : 'warn',
            title: `Dangerous shell pattern: ${label}`,
            message: `Tool arg "${key}" contains pattern that matches "${label}".`,
            evidence: { key, snippet: value.slice(0, 200), pattern: label },
          });
        }
      }
    }
    return findings.length ? findings : null;
  },
};
