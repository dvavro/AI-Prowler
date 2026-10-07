// CLN-02 — Final sweep: runs LAST in every full run.
// Every test already cleans up after itself; this double-checks EVERY data area so nothing a
// test created is ever left in a business's real HR data. Anything found is reported (it means
// some test's own cleanup missed it) and then removed.
const { test, expect } = require('@playwright/test');
const { adminApi } = require('../helpers/api');
const { scan, sweep } = require('../helpers/sweep');

test('CLN-02 · Final: zero test data left anywhere after the run', async ({}, testInfo) => {
  const api = await adminApi();
  const before = await scan(api);
  const missed = Object.fromEntries(Object.entries(before).map(([k, v]) => [k, v.length]).filter(([, n]) => n > 0));
  const { leftCounts } = await sweep(api);
  await api.dispose();
  const lines = [
    Object.keys(missed).length
      ? `⚠ Some test's own cleanup missed: ${JSON.stringify(missed)} — removed now`
      : '✓ Every test cleaned up after itself — nothing to remove',
    'Areas checked: employees, messages + incident reports, time off, directory, calendar events, recruiting, clock-ins/attendance/shift swaps',
    Object.keys(leftCounts).length ? `CLEANUP FAILED [CLN-02]: still left → ${JSON.stringify(leftCounts)}` : 'CLEANUP VERIFIED [CLN-02]: 0 test items in any area',
  ];
  await testInfo.attach('summary', { body: lines.join('\n'), contentType: 'text/plain' });
  console.log('\n' + lines.join('\n') + '\n');
  expect(leftCounts, 'test data still present after the final sweep').toEqual({});
  expect.soft(missed, 'a test\'s own cleanup left data behind (see summary)').toEqual({});
});
