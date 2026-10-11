// PRT-SEC-01/02/03 — Security checks on the HR API.
// These call the server directly (no browser), the way someone probing the site would.
// Real people's data is NEVER printed — only counted.
const { test, expect } = require('@playwright/test');
const { adminApi, anonApi, employeeApi, testTag, postJson, findMessage } = require('../helpers/api');

const REFUSED = [401, 403];
const count = (data, key) => (Array.isArray(data?.[key]) ? data[key].length : Array.isArray(data) ? data.length : 0);

test('PRT-SEC-04 · Sender identity comes from sign-in; anonymous feedback stays anonymous', async ({}, testInfo) => {
  const emp = await employeeApi();
  const admin = await adminApi();
  const tag = testTag('SEC04');
  const lines = [], problems = [], ids = [];

  // 1. Normal message that CLAIMS to be someone else → server must use Test Tester's real identity
  const r1 = await emp.post('/hr-api/messages', {
    data: { subject: `${tag} identity check`, body: 'Automated test — safe to ignore.', sender_name: 'ZZTEST Someone Else', employee_id: 'EMP-ZZTEST' },
  });
  const id1 = (await r1.json().catch(() => ({}))).id;
  if (id1) ids.push(id1);
  const m1 = id1 ? ((await (await admin.get('/hr-api/messages')).json()).messages || []).find(m => m.id === id1) : null;
  if (m1 && m1.employee_id === emp.session.employee_id && m1.sender_name !== 'ZZTEST Someone Else') {
    lines.push(`✓ Message claiming another name was saved as ${m1.sender_name} (${m1.employee_id}) — identity taken from sign-in`);
  } else {
    lines.push(`✗ Message claiming another name was saved as "${m1?.sender_name}" (${m1?.employee_id}) — spoofing possible`);
    problems.push('sender name/ID taken from the request instead of the sign-in');
  }

  // 2. Anonymous feedback (Portal's "Submit anonymously" checkbox) → no identity stored
  const r2 = await emp.post('/hr-api/messages', {
    data: { subject: `${tag} anonymous feedback`, body: 'Automated test — safe to ignore.', sender_name: 'Anonymous Employee' },
  });
  const id2 = (await r2.json().catch(() => ({}))).id;
  if (id2) ids.push(id2);
  const m2 = id2 ? ((await (await admin.get('/hr-api/messages')).json()).messages || []).find(m => m.id === id2) : null;
  const leaks = m2 ? ['employee_id', 'sender_email'].filter(k => m2[k]) : ['(not saved)'];
  if (m2 && m2.sender_name === 'Anonymous Employee' && leaks.length === 0) {
    lines.push('✓ Anonymous feedback saved with no name, email, or employee ID');
  } else {
    lines.push(`✗ Anonymous feedback stored identifying info: ${leaks.join(', ')}`);
    problems.push('anonymous feedback is not anonymous');
  }

  // Cleanup + verify
  for (const id of ids) await postJson(admin, '/messages/delete', { id, box: 'inbox' });
  const left = ((await (await admin.get('/hr-api/messages')).json()).messages || []).filter(m => String(m.subject || '').startsWith(tag));
  lines.push(left.length ? `CLEANUP FAILED [SEC04]: ${left.map(m => m.id).join(', ')}` : `CLEANUP VERIFIED [SEC04]: ${ids.length} message(s) deleted, 0 left`);
  await emp.dispose(); await admin.dispose();

  const summary = lines.join('\n');
  await testInfo.attach('summary', { body: summary, contentType: 'text/plain' });
  console.log('\n' + summary + '\n');
  expect(left.length, 'Test messages were left in the HR inbox').toBe(0);
  expect(problems).toEqual([]);
});

test('TAPI-01/02/04 · Test cleanup command is admin-only and never touches real employees', async ({}, testInfo) => {
  const anon = await anonApi(), emp = await employeeApi(), admin = await adminApi();
  const lines = [], problems = [];
  for (const [who, ctx] of [['not signed in', anon], ['Test Tester (employee)', emp]]) {
    const r = await ctx.post('/hr-api/test/cleanup', { data: {} });
    if (REFUSED.includes(r.status())) lines.push(`✓ ${who}: /test/cleanup → ${r.status()} refused`);
    else { lines.push(`✗ ${who}: /test/cleanup → ${r.status()} ALLOWED`); problems.push(`${who} could run the test cleanup`); }
  }
  // Real employees' attendance must be identical before and after a cleanup run
  const realRecs = async () => {
    const d = await (await admin.get('/hr-api/attendance?period=all')).json();
    const lo = await (await admin.get('/hr-api/test/leftovers')).json();
    const tt = new Set(lo.test_employee_ids || []);
    return (d.records || d.attendance || []).filter(a => !tt.has(a.employee_id)).map(a => a.id).sort().join(',');
  };
  const before = await realRecs();
  const res = await admin.post('/hr-api/test/cleanup', { data: {} });
  const after = await realRecs();
  if (res.ok() && before === after) lines.push(`✓ Admin cleanup ran; every real employee's attendance record is untouched`);
  else { lines.push(`✗ Admin cleanup changed real employees' records (or failed: ${res.status()})`); problems.push('cleanup touched real data'); }
  await anon.dispose(); await emp.dispose(); await admin.dispose();
  const summary = lines.join('\n');
  await testInfo.attach('summary', { body: summary, contentType: 'text/plain' });
  console.log('\n' + summary + '\n');
  expect(problems).toEqual([]);
});

test('PRT-SEC-01 · Employee cannot read admin-only data', async ({}, testInfo) => {
  const emp = await employeeApi();
  const lines = [];
  const checks = [
    ['GET', '/employees',  'the full employee list'],
    ['GET', '/pto',        "everyone's time-off requests"],
    ['GET', '/messages',   'the HR inbox (everyone\'s messages)'],
    ['GET', '/incidents',  'all incident reports'],
  ];
  const problems = [];
  for (const [method, path, what] of checks) {
    const res = await emp.fetch('/hr-api' + path, { method });
    const ok = REFUSED.includes(res.status());
    lines.push(`${ok ? '✓' : '✗'} As Test Tester: ${method} ${path} (${what}) → ${res.status()}${ok ? ' refused' : ' ALLOWED'}`);
    if (!ok) problems.push(`${path} returned ${res.status()} to an employee — should be 401/403`);
  }
  await emp.dispose();
  const summary = lines.join('\n');
  await testInfo.attach('summary', { body: summary, contentType: 'text/plain' });
  console.log('\n' + summary + '\n');
  expect(problems, 'An employee could read admin-only data').toEqual([]);
});

test('PRT-SEC-02 · Incident reports cannot be read without signing in', async ({}, testInfo) => {
  const anon = await anonApi();
  const lines = [];
  const problems = [];

  // 1. Not signed in, one-letter name "a" — should be refused
  const r1 = await anon.post('/hr-api/messages/my-reports', { data: { sender_name: 'a' } });
  const d1 = await r1.json().catch(() => ({}));
  const n1 = count(d1, 'reports') || count(d1, 'messages');
  if (REFUSED.includes(r1.status())) {
    lines.push(`✓ Not signed in, name "a" → ${r1.status()} refused`);
  } else if (r1.status() >= 500) {
    lines.push(`⚠ Server unavailable (${r1.status()}) — could not check; this is NOT a security result`);
    problems.push(`server unavailable (${r1.status()}) — re-run when AI-Prowler is up`);
  } else {
    lines.push(`✗ Not signed in, name "a" → ${r1.status()} ALLOWED, returned ${n1} incident report(s) (contents not shown)`);
    problems.push(`/messages/my-reports answered without sign-in (${r1.status()}, ${n1} reports)`);
  }

  // 2. Signed in as Test Tester, asking for someone else's name — only Test Tester's own reports may come back
  const emp = await employeeApi();
  const r2 = await emp.post('/hr-api/messages/my-reports', { data: { sender_name: 'Vavro' } });
  const d2 = await r2.json().catch(() => ({}));
  const list = d2.reports || d2.messages || (Array.isArray(d2) ? d2 : []);
  const notMine = list.filter(m => m.employee_id !== emp.session.employee_id).length;
  if (REFUSED.includes(r2.status()) || notMine === 0) {
    lines.push(`✓ Signed in as Test Tester, asked for "Vavro" → ${r2.status()}, ${notMine} other people's report(s)`);
  } else {
    lines.push(`✗ Signed in as Test Tester, asked for "Vavro" → ${r2.status()}, got ${notMine} OTHER people's report(s) (contents not shown)`);
    problems.push(`an employee could read ${notMine} other people's incident reports by typing a name`);
  }
  await anon.dispose(); await emp.dispose();

  const summary = lines.join('\n');
  await testInfo.attach('summary', { body: summary, contentType: 'text/plain' });
  console.log('\n' + summary + '\n');
  expect(problems, 'Incident reports are exposed').toEqual([]);
});

test('PRT-SEC-03 · Messages cannot be sent or read without signing in', async ({}, testInfo) => {
  const anon = await anonApi();
  const admin = await adminApi();
  const tag = testTag('SEC03');
  const lines = [];
  const problems = [];
  const cleanupLines = [];

  // 1. Send a message to HR while NOT signed in, pretending to be someone else
  const r1 = await anon.post('/hr-api/messages', {
    data: { subject: `${tag} spoof probe`, body: 'Automated security probe — safe to ignore.', sender_name: 'ZZTEST Spoofed Name', employee_id: 'EMP-ZZTEST' },
  });
  const d1 = await r1.json().catch(() => ({}));
  const probeId = d1.id || d1.message?.id || null;
  if (REFUSED.includes(r1.status())) {
    lines.push(`✓ Send message without signing in → ${r1.status()} refused`);
  } else if (r1.status() >= 500) {
    lines.push(`⚠ Server unavailable (${r1.status()}) — could not check; this is NOT a security result`);
    problems.push(`server unavailable (${r1.status()}) — re-run when AI-Prowler is up`);
  } else {
    lines.push(`✗ Send message without signing in, as a made-up name → ${r1.status()} ACCEPTED${probeId ? ` (${probeId})` : ''}`);
    problems.push(`anyone can post messages to HR without signing in, under any name (${r1.status()})`);
  }

  // 2. Read the HR broadcast outbox while NOT signed in
  const r2 = await anon.get('/hr-api/messages/outbox');
  const d2 = await r2.json().catch(() => ({}));
  const n2 = count(d2, 'messages') || count(d2, 'outbox');
  if (REFUSED.includes(r2.status())) lines.push(`✓ Read HR broadcasts without signing in → ${r2.status()} refused`);
  else if (r2.status() >= 500) {
    lines.push(`⚠ Server unavailable (${r2.status()}) — could not check; this is NOT a security result`);
    problems.push(`server unavailable (${r2.status()}) — re-run when AI-Prowler is up`);
  }
  else {
    lines.push(`✗ Read HR broadcasts without signing in → ${r2.status()} ALLOWED (${n2} broadcast(s), contents not shown)`);
    problems.push(`HR broadcasts readable without sign-in (${r2.status()})`);
  }

  // Cleanup: remove the probe message if the server accepted it, then verify
  if (probeId) await postJson(admin, '/messages/delete', { id: probeId, box: 'inbox' });
  const inbox = ((await (await admin.get('/hr-api/messages')).json()).messages || []).filter(m => String(m.subject || '').startsWith(tag));
  cleanupLines.push(inbox.length ? `CLEANUP FAILED [SEC03]: probe still in HR inbox → ${inbox.map(m => m.id).join(', ')}`
                                 : `CLEANUP VERIFIED [SEC03]: ${probeId ? 1 : 0} probe deleted, 0 left`);
  await anon.dispose(); await admin.dispose();

  const summary = [...lines, ...cleanupLines].join('\n');
  await testInfo.attach('summary', { body: summary, contentType: 'text/plain' });
  console.log('\n' + summary + '\n');
  expect(inbox.length, 'Security probe was left in the HR inbox').toBe(0);
  expect(problems, 'Messaging is open without sign-in').toEqual([]);
});
