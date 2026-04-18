/**
 * Adapter: wrap Anthropic Agent SDK tools (created via `tool()` from
 * @anthropic-ai/claude-agent-sdk) so every invocation passes through a
 * Firewall before reaching the original handler.
 *
 * Capabilities are inferred from the tool name using the same convention
 * mcp-audit uses (token-based verb_noun matching). Override per-tool by
 * passing `caps: ['shell_exec', ...]` in `wrapMcpTool(t, firewall, { caps })`.
 */

import { tool as createTool } from '@anthropic-ai/claude-agent-sdk';

const VERBS_EXEC = new Set(['exec','execute','run','shell','bash','sh','cmd','spawn','subprocess']);
const STRONG_EXEC = new Set(['shell','bash','cmd','exec','execute','spawn','subprocess']);
const VERBS_READ = new Set(['read','get','list','cat','tail','head','stat','open','load','fetch','show','find','search','tree','describe']);
const VERBS_WRITE = new Set(['write','create','save','put','append','edit','modify','update','move','copy','delete','remove','rm','unlink','mkdir','rmdir','chmod','chown']);
const VERBS_EGRESS = new Set(['send','post','publish','upload','notify','dispatch','push','call','invoke','trigger']);
const NOUNS_FILE = new Set(['file','files','dir','directory','directories','folder','folders','path','paths','disk']);
const NOUNS_SECRET = new Set(['env','envvar','secret','secrets','credential','credentials','token','tokens','key','keys','password','passwords','vault','apikey']);
const NOUNS_HISTORY = new Set(['memory','memories','history','log','logs','conversation','conversations','notes']);
const SERVICES_NETWORK = new Set(['telegram','slack','discord','email','mail','smtp','webhook','sms','twilio','http','https','api','pagerduty','teams','zoom']);

function tokens(name) {
  if (!name) return [];
  return name.replace(/([a-z0-9])([A-Z])/g, '$1 $2').toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
}
const has = (set, t) => t.some(x => set.has(x));

export function inferCaps(toolName) {
  const t = tokens(toolName);
  const caps = new Set();
  if (has(STRONG_EXEC, t) || (t.includes('command') && has(VERBS_EXEC, t))) caps.add('shell_exec');
  if (has(VERBS_READ, t) && has(NOUNS_FILE, t)) caps.add('file_read');
  if (has(VERBS_WRITE, t) && has(NOUNS_FILE, t)) caps.add('file_write');
  if (t.includes('mkdir') || t.includes('rmdir')) caps.add('file_write');
  if (has(VERBS_READ, t) && has(NOUNS_SECRET, t)) caps.add('secret_read');
  if (has(VERBS_READ, t) && has(NOUNS_HISTORY, t)) caps.add('history_read');
  if (has(VERBS_EGRESS, t) && has(SERVICES_NETWORK, t)) caps.add('network_out');
  if (t.includes('email') && (t.includes('send') || t.includes('reply') || t.includes('forward'))) caps.add('email_send');
  if (t.includes('telegram') && (t.includes('send') || t.includes('post') || t.includes('notify'))) caps.add('telegram_send');
  if (t.includes('webhook')) caps.add('webhook');
  return [...caps];
}

/**
 * Wrap an existing Agent SDK tool with a Firewall guard.
 *
 * @param {ReturnType<typeof createTool>} t       — the original tool
 * @param {Firewall} firewall                     — your firewall instance
 * @param {object} [opts]
 * @param {string[]} [opts.caps]                  — override inferred caps
 * @param {string} [opts.sessionId]               — static session id; or pass via call args._sessionId
 * @returns wrapped tool (drop-in replacement)
 */
export function wrapMcpTool(t, firewall, opts = {}) {
  const inner = t;
  const caps = opts.caps || inferCaps(inner.name);

  return createTool(
    inner.name,
    inner.description,
    inner.inputSchema,
    async (args, ...rest) => {
      const sessionId = opts.sessionId || args?._sessionId || 'default';
      const decision = await firewall.evaluate({
        toolName: inner.name,
        args,
        sessionId,
        caps,
      });

      if (decision.verdict === 'block') {
        const f = decision.findings.find(x => x.verdict === 'block') || decision.findings[0];
        return {
          content: [{
            type: 'text',
            text: `[firewall] blocked: ${f?.title || 'policy violation'}\n${f?.message || ''}`,
          }],
          isError: true,
        };
      }

      return inner.handler ? inner.handler(args, ...rest) : inner.callback(args, ...rest);
    }
  );
}

/**
 * Wrap an entire SDK MCP server's tools array.
 */
export function wrapMcpServer(server, firewall, opts = {}) {
  if (!server?.instance?._registeredTools) return server;
  // Replace each registered tool with a firewalled version
  for (const [name, t] of Object.entries(server.instance._registeredTools)) {
    const original = { name, description: t.description, inputSchema: t.inputSchema, handler: t.callback };
    const wrapped = wrapMcpTool(original, firewall, opts);
    server.instance._registeredTools[name] = { ...t, callback: wrapped.handler ?? wrapped.callback };
  }
  return server;
}
