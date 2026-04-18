// Block destructive tools (delete_*, drop_*, kill_*) unless an explicit
// confirm flag is set in the args. Mirrors mcp-audit's static rule but
// enforced at call time.

const DESTRUCTIVE_VERBS = /^(delete|remove|drop|destroy|purge|wipe|kill|terminate|reset|truncate|uninstall|revoke)/i;
const CONFIRM_KEYS = /^(confirm|confirmed|i_understand|force|really|yes_im_sure|consent)$/i;

function hasConsent(args) {
  if (!args || typeof args !== 'object') return false;
  for (const [k, v] of Object.entries(args)) {
    if (CONFIRM_KEYS.test(k) && (v === true || v === 'true' || v === 1)) return true;
  }
  return false;
}

export const destructiveNoConsent = {
  id: 'destructive-no-consent',
  check(ctx) {
    if (!DESTRUCTIVE_VERBS.test(ctx.toolName || '')) return null;
    if (hasConsent(ctx.args)) return null;
    return {
      severity: 'high', verdict: 'block',
      title: `Destructive tool "${ctx.toolName}" called without consent flag`,
      message: `Tool name implies a destructive action. Reject unless an explicit confirm/consent flag is present.`,
      evidence: { toolName: ctx.toolName, argsKeys: Object.keys(ctx.args || {}) },
    };
  },
};
