const fs = require('fs');
const vm = require('vm');
const path = require('path');

const file = path.join(__dirname, '..', 'hr_admin', 'index.html');
const html = fs.readFileSync(file, 'utf8');

const scriptRe = /<script\b([^>]*)>([\s\S]*?)<\/script>/gi;
let match;
let blockNum = 0;
let hadError = false;

while ((match = scriptRe.exec(html)) !== null) {
  const attrs = match[1];
  const code = match[2];
  if (/\bsrc\s*=/.test(attrs)) continue;
  blockNum++;
  if (!code.trim()) continue;

  const startIndex = match.index;
  const lineNumber = html.slice(0, startIndex).split('\n').length;

  try {
    new vm.Script(code, { filename: `inline-script-block-${blockNum}` });
    console.log(`OK   block #${blockNum} (starts near line ${lineNumber})`);
  } catch (e) {
    hadError = true;
    console.log(`FAIL block #${blockNum} (starts near line ${lineNumber})`);
    console.log(`     ${e.name}: ${e.message}`);
  }
}

console.log('----------------------------------------');
console.log(hadError ? 'RESULT: FAILED' : `RESULT: All ${blockNum} blocks OK`);
process.exit(hadError ? 1 : 0);
