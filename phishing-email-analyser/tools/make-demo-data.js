/* =============================================================================
 * Developer helper (optional - you never need to run this to USE the tool).
 *
 * It rebuilds samples/demo-emails.js from the .txt sample files, so the
 * "Load example" buttons inside the page work even when the page is opened
 * directly from disk (browsers block a page from reading neighbouring files
 * for security reasons, so the samples have to be baked into a script file).
 *
 * Run it from this folder with:  node tools/make-demo-data.js
 * It needs nothing installed - it uses only Node's built-in modules.
 * ========================================================================== */
'use strict';

const fs = require('fs');
const path = require('path');

const samplesDir = path.join(__dirname, '..', 'samples');
const outFile = path.join(samplesDir, 'demo-emails.js');

/* Friendly names and teaching notes for each sample. */
const CATALOGUE = [
  { file: '01-obvious-phishing.txt', id: 'obvious', label: 'Obvious phishing', note: 'Crude mass campaign: threats, a password request, an MFA code request, an IP-address link and a disguised program file.' },
  { file: '02-sophisticated-phishing.txt', id: 'sophisticated', label: 'Sophisticated phishing', note: 'Well written, correct grammar, no threats, and authentication passes because the attacker really owns the domain. Only subtle clues remain.' },
  { file: '03-fake-microsoft-365.txt', id: 'm365', label: 'Fake Microsoft 365 warning', note: 'Brand impersonation with a lookalike domain, a shortened link whose visible text is a real Microsoft address, and a demand for a verification code.' },
  { file: '04-fake-parcel-delivery.txt', id: 'parcel', label: 'Fake parcel delivery', note: 'Delivery fee scam: lookalike courier domain, a small "handling fee", a 48 hour deadline and a request for a one-time banking code.' },
  { file: '05-fake-invoice-bec.txt', id: 'bec', label: 'Fake invoice / BEC', note: 'Business email compromise: no links at all, just polite urgency, secrecy, a change of bank details and a Reply-To that goes elsewhere.' },
  { file: '06-legitimate-email.txt', id: 'legit', label: 'Legitimate email', note: 'An ordinary internal message. Expect a score of zero - no warning signs should be found.' },
  { file: '07-legitimate-password-notice.txt', id: 'legit-password', label: 'Legitimate password notice', note: 'A genuine notification that mentions passwords. It contains the reassuring wording real services use, so it should still score zero - a useful false-positive lesson.' }
];

const emails = CATALOGUE.map(function (item) {
  const full = path.join(samplesDir, item.file);
  const text = fs.readFileSync(full, 'utf8');
  if (!fs.existsSync(full)) throw new Error('Missing sample file: ' + item.file);
  return {
    id: item.id,
    label: item.label,
    note: item.note,
    file: item.file,
    text: text
  };
});

/* JSON.stringify produces a safe JavaScript string literal. U+2028 and U+2029
 * are legal in JSON but were historically awkward in JavaScript, so they are
 * escaped explicitly. */
function safeJson(value) {
  return JSON.stringify(value, null, 2)
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029');
}

const banner = [
  '/* GENERATED FILE - do not edit by hand.',
  ' * Built from the .txt files in this folder by tools/make-demo-data.js.',
  ' * All content is fictional and uses reserved documentation domains',
  ' * (example.com, .example, .invalid) and RFC 5737 IP addresses only.',
  ' * Contains no working malicious links. */',
  ''
].join('\n');

const output = banner + 'window.DEMO_EMAILS = ' + safeJson(emails) + ';\n';
fs.writeFileSync(outFile, output, 'utf8');
console.log('Wrote ' + outFile + ' (' + emails.length + ' samples, ' + output.length + ' bytes)');