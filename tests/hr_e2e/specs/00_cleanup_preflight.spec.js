// CLN-01 — Pre-flight sweep: runs FIRST in every full run.
// If an earlier run was cut off (e.g. AI-Prowler restarted mid-test), its test data may still be
// sitting in the real HR data. Find it in EVERY area, remove it, and prove nothing is left —
// so this run starts clean and no leftovers can skew results.
const { test, expect } = require('@playwright/test');
const { adminApi } = require('../helpers/api');
const { sweep } = require('../helpers/sweep');

test('CLN-01 · Pre-flight: no leftover test data anywhere before the run starts', async ({}, testInfo) => {
  const api = await adminApi();
  const { removed, leftCounts } = await sweep(api);
  await api.dispose();
  const total = Object.values(removed).reduce((a, b) => a + b, 0);
  const lines = [
    total ? `• Removed ${total} leftover test item(s) from earlier runs: ${Object.entries(removed).filter(([, n]) => n).map(([k, n]) => `${k} ${n}`).join(', ')}`
          : '• No leftover test data found',
    `Areas checked: employees, messages + incident reports, time off, directory, calendar events, recruiting, clock-ins/attendance/shift swaps`,
    Object.keys(leftCounts).length ? `CLEANUP FAILED [CLN-01]: still left → ${JSON.stringify(leftCounts)}` : 'CLEANUP VERIFIED [CLN-01]: 0 test items in any area',
  ];
  await testInfo.attach('summary', { body: lines.join('\n'), contentType: 'text/plain' });
  console.log('\n' + lines.join('\n') + '\n');
  expect(leftCounts, 'test data still present after the pre-flight sweep').toEqual({});
});
