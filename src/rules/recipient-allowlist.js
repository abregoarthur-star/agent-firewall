// For email/messaging tools, restrict the recipient field to an allowlist.
// Policy: { recipients: { allowedEmails: ['arthur@gmail.com'], allowedTelegramChats: ['1234'] } }

const EMAIL_KEYS = /^(to|recipient|recipients|email|emails|email_to)$/i;
const CHAT_KEYS = /^(chat_id|chatId|chat|telegram_chat|conversation_id)$/i;

function flatten(value, out = []) {
  if (value == null) return out;
  if (Array.isArray(value)) value.forEach(v => flatten(v, out));
  else if (typeof value === 'string') out.push(value);
  return out;
}

export const recipientAllowlist = {
  id: 'recipient-allowlist',
  check(ctx, session, policy) {
    const cfg = policy.recipients;
    if (!cfg) return null;
    if (!ctx.args || typeof ctx.args !== 'object') return null;

    const findings = [];
    for (const [k, v] of Object.entries(ctx.args)) {
      if (EMAIL_KEYS.test(k) && cfg.allowedEmails) {
        for (const addr of flatten(v)) {
          const norm = addr.match(/[^<\s,;]+@[^>\s,;]+/g) || [addr];
          for (const a of norm) {
            const lower = a.toLowerCase().trim();
            if (!cfg.allowedEmails.map(x => x.toLowerCase()).includes(lower)) {
              findings.push({
                severity: 'critical', verdict: 'block',
                title: `Email recipient not on allowlist: ${a}`,
                message: `Tool "${ctx.toolName}" tried to send to a non-allowlisted address.`,
                evidence: { key: k, recipient: a, allowedEmails: cfg.allowedEmails },
              });
            }
          }
        }
      }
      if (CHAT_KEYS.test(k) && cfg.allowedTelegramChats) {
        for (const chat of flatten(v)) {
          if (!cfg.allowedTelegramChats.includes(String(chat))) {
            findings.push({
              severity: 'critical', verdict: 'block',
              title: `Telegram chat not on allowlist: ${chat}`,
              message: `Tool "${ctx.toolName}" tried to send to a non-allowlisted Telegram chat.`,
              evidence: { key: k, chatId: chat, allowedTelegramChats: cfg.allowedTelegramChats },
            });
          }
        }
      }
    }
    return findings.length ? findings : null;
  },
};
