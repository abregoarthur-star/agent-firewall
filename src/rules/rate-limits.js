// Loop / spike detection: the same tool fired N times in M seconds is almost
// always a runaway agent loop or a brute-force pattern.
// Policy: { rateLimits: { perTool: { count: 8, windowMs: 60_000 } } }

const DEFAULT = { count: 12, windowMs: 60_000 };

export const rateLimits = {
  id: 'rate-limits',
  check(ctx, session, policy) {
    const cfg = policy.rateLimits?.perTool || DEFAULT;
    if (!session?.history) return null;
    const cutoff = Date.now() - cfg.windowMs;
    const recentSame = session.history.filter(h => h.toolName === ctx.toolName && h.ts >= cutoff);
    if (recentSame.length < cfg.count) return null;
    return {
      severity: 'high', verdict: 'block',
      title: `Tool rate spike: ${ctx.toolName} called ${recentSame.length} times in ${cfg.windowMs}ms`,
      message: `Likely runaway loop or repetitive abuse. Blocking until the rate window clears.`,
      evidence: { toolName: ctx.toolName, count: recentSame.length, windowMs: cfg.windowMs },
    };
  },
};
