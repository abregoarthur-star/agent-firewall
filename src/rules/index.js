import { urlAllowlist } from './url-allowlist.js';
import { pathAllowlist } from './path-allowlist.js';
import { dangerousShell } from './dangerous-shell.js';
import { secretEgress } from './secret-egress.js';
import { exfilTrail } from './exfil-trail.js';
import { lethalTrifectaRuntime } from './lethal-trifecta-runtime.js';
import { rateLimits } from './rate-limits.js';
import { destructiveNoConsent } from './destructive-no-consent.js';
import { recipientAllowlist } from './recipient-allowlist.js';

export const ALL_RULES = [
  urlAllowlist,
  pathAllowlist,
  dangerousShell,
  secretEgress,
  exfilTrail,
  lethalTrifectaRuntime,
  rateLimits,
  destructiveNoConsent,
  recipientAllowlist,
];

export const SEVERITY_RANK = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};
