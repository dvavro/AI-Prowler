// Shared sweep used by CLN-01 (first test of every run) and CLN-02 (last test of every run).
// Searches EVERY data area for test data (ZZTEST names, or Test Tester activity), removes it,
// then checks again and returns what (if anything) is still there.
const { getJson, postJson, allMessages, allEmployees, deleteEmployee } = require('./api');

const ZZ = (v) => JSON.stringify(v || '').includes('ZZTEST');

async function scan(api) {
  const tt = process.env.HR_E2E_TT_ID;
  const found = {};
  found.employees = (await allEmployees(api)).filter(e => String(e.first_name || '').startsWith('ZZTEST'));
  found.messages  = (await allMessages(api)).filter(m => ZZ(m.subject) || ZZ(m.incident_data));
  const pto = (await getJson(api, '/pto')).requests || [];
  found.time_off  = pto.filter(r => r.employee_id === tt && ZZ(r.notes));
  found.directory = ((await getJson(api, '/directory')).contacts || []).filter(c => ZZ(c.name));
  const ev = await getJson(api, '/calendar/events').catch(() => ({ events: [] }));
  found.calendar_events = (ev.events || []).filter(e => ZZ(e.title));
  const rec = (await getJson(api, '/recruiting')).recruiting || {};
  found.recruiting = ['positions', 'candidates', 'interviews', 'offers'].flatMap(k => (rec[k] || []).filter(ZZ).map(x => ({ kind: k, id: x.id })));
  const lo = await getJson(api, '/test/leftovers').catch(() => ({ leftovers: {} }));
  found.test_tester_activity = Object.entries(lo.leftovers || {}).filter(([, n]) => n > 0).map(([area, n]) => ({ area, n }));
  const docs = await getJson(api, `/documents?employee_id=${encodeURIComponent(tt)}`).catch(() => ({ documents: [] }));
  found.documents = (docs.documents || docs || []).filter(d => String(d.name || d.filename || '').startsWith('ZZTEST'));
  return found;
}

async function sweep(api) {
  const f = await scan(api);
  for (const e of f.employees) await deleteEmployee(api, e.id);
  for (const m of f.messages) await postJson(api, '/messages/delete', { id: m.id, box: 'inbox' });
  for (const r of f.time_off) await postJson(api, `/pto/${r.id}/delete`, {});
  for (const c of f.directory) await api.delete(`/hr-api/directory/${c.id}`);
  for (const e of f.calendar_events) await postJson(api, `/calendar/events/${e.id}/delete`, {});
  if (f.recruiting.length) {
    const d = await getJson(api, '/recruiting');
    const b = d.recruiting || {};
    const clean = { version: d.version };
    for (const k of ['positions', 'candidates', 'interviews', 'offers']) clean[k] = (b[k] || []).filter(x => !ZZ(x));
    await postJson(api, '/recruiting', clean);
  }
  if (f.test_tester_activity.length) await postJson(api, '/test/cleanup', {});
  for (const d of f.documents) await api.delete(`/hr-api/documents/${d.id}`);
  const removed = Object.fromEntries(Object.entries(f).map(([k, v]) => [k, v.length]));
  const left = await scan(api);
  const leftCounts = Object.fromEntries(Object.entries(left).map(([k, v]) => [k, v.length]).filter(([, n]) => n > 0));
  return { removed, leftCounts };
}

module.exports = { scan, sweep };
