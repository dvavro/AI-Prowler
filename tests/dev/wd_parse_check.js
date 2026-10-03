// Dev check (2026-10-02): run the Jobs app's own _parseWorkingDays() from
// jobs/index.html under Node and print what it makes of a few inputs.
const fs = require('fs');
const path = require('path');
const html = fs.readFileSync(path.join(__dirname, '..', '..', 'jobs', 'index.html'), 'utf8');
const start = html.indexOf('const _WD_DEFAULT');
const end = html.indexOf('function _isWorkingDay(');
if (start < 0 || end < 0) { console.log('could not find the parser'); process.exit(1); }
const window = {};
eval(html.slice(start, end).replace('const _WD_DEFAULT', 'var _WD_DEFAULT') +
     '; globalThis._parseWorkingDays = _parseWorkingDays;');
for (const t of ['Mon,Tue,Wed,Thu,Fri', 'Mon,Tue,Wed,Thu,Fri,Sat,Sun', 'Mon-Sat', 'Weekdays',
                 'Fri-Mon', '', 'junk']) {
  console.log(JSON.stringify(t).padEnd(32), '->', JSON.stringify(Array.from(_parseWorkingDays(t)).sort()));
}
