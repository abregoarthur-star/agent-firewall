/**
 * Agent Firewall — runtime defensive middleware for AI agent tool calls.
 *
 * Modes:
 *   - 'observe' — never blocks; logs all decisions for visibility
 *   - 'enforce' — blocks on warn/block verdicts from rules
 *
 * Each rule is a pure function: (ctx, session) → Decision[] | Decision | null
 * The firewall aggregates rule decisions and emits the final verdict.
 *
 * Session state is in-memory and scoped by `sessionId` from the call context.
 * It tracks recent calls so cross-tool patterns (exfiltration trails, rate
 * spikes, capability combinations) can be detected.
 */

import { ALL_RULES, SEVERITY_RANK } from './rules/index.js';

export const VERDICTS = ['allow', 'warn', 'block'];

export class Firewall {
  constructor(opts = {}) {
    this.mode = opts.mode || 'observe';            // 'observe' | 'enforce'
    this.rules = opts.rules || ALL_RULES;
    this.policy = opts.policy || {};                // shared config rules read from
    this.onDecision = opts.onDecision || null;      // sink for every decision
    this.sessions = new Map();                       // sessionId → session state
    this.maxHistory = opts.maxHistory || 100;
  }

  getSession(id) {
    if (!id) id = 'default';
    let s = this.sessions.get(id);
    if (!s) {
      s = { id, history: [], capsSeen: new Set(), startedAt: Date.now() };
      this.sessions.set(id, s);
    }
    return s;
  }

  _recordCall(session, ctx, decision) {
    session.history.push({
      ts: Date.now(),
      toolName: ctx.toolName,
      caps: ctx.caps || [],
      verdict: decision.verdict,
      args: ctx.args,
    });
    if (session.history.length > this.maxHistory) {
      session.history.splice(0, session.history.length - this.maxHistory);
    }
    for (const c of ctx.caps || []) session.capsSeen.add(c);
  }

  /**
   * Evaluate a tool-call context. Returns the aggregated Decision.
   *
   * @param {object} ctx
   * @param {string} ctx.toolName
   * @param {*} ctx.args
   * @param {string} [ctx.sessionId]
   * @param {string} [ctx.callerId]
   * @param {string[]} [ctx.caps] — capability tags (shell_exec, network_out, secret_read, etc.)
   * @returns {{verdict: 'allow'|'warn'|'block', findings: object[], finalSeverity: string|null}}
   */
  async evaluate(ctx) {
    const session = this.getSession(ctx.sessionId);
    const findings = [];

    for (const rule of this.rules) {
      try {
        const out = await rule.check(ctx, session, this.policy);
        if (!out) continue;
        const list = Array.isArray(out) ? out : [out];
        for (const f of list) {
          findings.push({ ...f, ruleId: f.ruleId || rule.id });
        }
      } catch (e) {
        findings.push({
          ruleId: rule.id,
          severity: 'info',
          verdict: 'allow',
          title: `Rule errored: ${rule.id}`,
          message: e.message,
        });
      }
    }

    // Aggregate verdict: worst rule decision wins, clamped by mode
    let verdict = 'allow';
    let finalSeverity = null;
    let maxRank = -1;

    for (const f of findings) {
      if (f.verdict === 'block') verdict = 'block';
      else if (f.verdict === 'warn' && verdict !== 'block') verdict = 'warn';

      const rank = SEVERITY_RANK[f.severity] ?? -1;
      if (rank > maxRank) { maxRank = rank; finalSeverity = f.severity; }
    }

    // observe mode never blocks — downgrade
    if (this.mode === 'observe' && verdict === 'block') verdict = 'warn';

    const decision = { verdict, findings, finalSeverity, mode: this.mode };

    this._recordCall(session, ctx, decision);

    if (this.onDecision) {
      try { await this.onDecision({ ctx, decision, session }); }
      catch (e) { /* sink should not throw */ }
    }

    return decision;
  }
}

export function createFirewall(opts) {
  return new Firewall(opts);
}
