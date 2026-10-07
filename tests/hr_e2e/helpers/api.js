// HR API helper for tests: verify server state and clean up test data.
// Uses the admin token (never the UI) — tests only use this to CHECK results
// and to CLEAN UP, never to perform the action being tested.
const { request } = require('@playwright/test');
const { adminToken } = require('./admin');

// Same browser identity as the runner — the public address refuses "script" requests.
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36 AI-Prowler-HR-E2E';

async function adminApi() {
  return request.newContext({
    baseURL: process.env.HR_E2E_BASE_URL,
    extraHTTPHeaders: { Authorization: `Bearer ${adminToken()}`, 'User-Agent': UA, Accept: 'application/json' },
  });
}

// Not signed in at all — for security tests ("does this work WITHOUT signing in?")
async function anonApi() {
  return request.newContext({
    baseURL: process.env.HR_E2E_BASE_URL,
    extraHTTPHeaders: { 'User-Agent': UA, Accept: 'application/json' },
  });
}

// Signed in as Test Tester (real employee session from /auth/employee with this run's one-time PIN)
async function employeeApi() {
  const anon = await anonApi();
  const res = await anon.post('/hr-api/auth/employee', {
    data: { email: process.env.HR_E2E_TT_EMAIL, pin: process.env.HR_E2E_TT_PIN },
  });
  const data = await res.json().catch(() => ({}));
  await anon.dispose();
  if (!res.ok() || !data.session) throw new Error(`Test Tester API sign-in failed (${res.status()})`);
  const ctx = await request.newContext({
    baseURL: process.env.HR_E2E_BASE_URL,
    extraHTTPHeaders: { 'X-Employee-Session': JSON.stringify(data.session), 'User-Agent': UA, Accept: 'application/json' },
  });
  ctx.session = data.session;
  return ctx;
}

async function getJson(api, path) {
  const res = await api.get('/hr-api' + path);
  if (!res.ok()) throw new Error(`GET ${path} → ${res.status()}`);
  return res.json();
}
async function postJson(api, path, body) {
  const res = await api.post('/hr-api' + path, { data: body || {} });
  let data = {}; try { data = await res.json(); } catch {}
  return { status: res.status(), data };
}

// A unique tag for everything this test creates: ZZTEST-<run>-<test>
function testTag(testId) {
  const run = process.env.HR_E2E_RUN_ID || String(Date.now()).slice(-8);
  return `ZZTEST-${run}-${testId}`;
}

// ── Messages ────────────────────────────────────────────────────────────
async function allMessages(api) { return (await getJson(api, '/messages')).messages || []; }
async function findMessage(api, id) { return (await allMessages(api)).find(m => m.id === id) || null; }

// Test messages = subject starts with ZZTEST. Real messages are never touched.
function isTestMessage(m) { return /^ZZTEST/.test(String(m.subject || '')); }

// ── Cleanup tracker: record → delete → verify ───────────────────────────
class Cleanup {
  constructor(api, testId) { this.api = api; this.testId = testId; this.items = []; this.lines = []; }
  trackMessage(id) { if (id && !this.items.find(i => i.id === id)) this.items.push({ kind: 'message', id }); }

  // Delete leftover ZZTEST messages from earlier crashed runs, before this test starts.
  async sweepOldTestMessages() {
    const old = (await allMessages(this.api)).filter(isTestMessage);
    for (const m of old) await postJson(this.api, '/messages/delete', { id: m.id, box: 'inbox' });
    const still = (await allMessages(this.api)).filter(isTestMessage);
    this.lines.push(old.length
      ? `Pre-sweep: removed ${old.length} leftover ZZTEST message(s) from earlier runs${still.length ? ` — ${still.length} STILL THERE` : ''}`
      : 'Pre-sweep: no leftover test messages');
    return still.length === 0;
  }

  // Delete everything this test created, then ask the server again to prove it's gone.
  async run() {
    const leftovers = [];
    for (const it of this.items) {
      if (it.kind === 'message') {
        if (await findMessage(this.api, it.id)) await postJson(this.api, '/messages/delete', { id: it.id, box: 'inbox' });
        if (await findMessage(this.api, it.id)) leftovers.push(`message ${it.id}`);
      }
    }
    // Belt and braces: nothing tagged ZZTEST may remain in the inbox
    const stray = (await allMessages(this.api)).filter(isTestMessage).map(m => `message ${m.id} "${m.subject}"`);
    leftovers.push(...stray.filter(s => !leftovers.some(l => s.startsWith(l))));

    const created = this.items.map(i => `${i.kind} ${i.id}`).join(', ') || 'nothing';
    this.lines.push(`Created: ${created}`);
    this.lines.push(leftovers.length
      ? `CLEANUP FAILED [${this.testId}]: still on server → ${leftovers.join('; ')}`
      : `CLEANUP VERIFIED [${this.testId}]: ${this.items.length} item(s) deleted, 0 test records left on server`);
    return leftovers;
  }
}

// ── Employees (admin) ───────────────────────────────────────────────────
async function getEmployee(api, id) {
  const d = await getJson(api, '/employees');
  return (d.employees || d || []).find(e => e.id === id) || null;
}
async function patchEmployee(api, id, fields) {
  const res = await api.patch(`/hr-api/employees/${id}`, { data: fields });
  if (!res.ok()) throw new Error(`PATCH /employees/${id} → ${res.status()}`);
  return res.json().catch(() => ({}));
}

async function deleteEmployee(api, id) {
  const res = await api.delete(`/hr-api/employees/${id}`);
  return res.status();
}
async function allEmployees(api) { const d = await getJson(api, '/employees'); return d.employees || d || []; }

module.exports = { adminApi, anonApi, employeeApi, getJson, postJson, testTag, allMessages, findMessage, isTestMessage, Cleanup, getEmployee, patchEmployee, deleteEmployee, allEmployees };
