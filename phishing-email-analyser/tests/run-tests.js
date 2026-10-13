/* =============================================================================
 * Phishing Email Analyser - test suite
 * -----------------------------------------------------------------------------
 * Runs with plain Node (no packages, nothing to install):
 *     node tests/run-tests.js
 *
 * Two kinds of test live here:
 *   1. Engine tests  - the analysis logic, run against the sample emails.
 *   2. Page tests    - the real app.js is loaded into a tiny fake DOM built
 *                      below, to prove the page renders correctly and that it
 *                      never inserts untrusted text as HTML.
 * ========================================================================== */
'use strict';

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const SAMPLES = path.join(ROOT, 'samples');

let passed = 0;
let failed = 0;
const failures = [];

function ok(condition, label) {
  if (condition) { passed++; console.log('  PASS  ' + label); }
  else { failed++; failures.push(label); console.log('  FAIL  ' + label); }
}

function eq(actual, expected, label) {
  ok(actual === expected, label + ' (expected ' + JSON.stringify(expected) + ', got ' + JSON.stringify(actual) + ')');
}

function section(name) { console.log('\n' + name); }

/* =============================================================================
 * A deliberately tiny fake DOM. It only implements what app.js actually uses,
 * which is also useful in itself: if app.js ever needs something more, the
 * tests break rather than the page.
 * ========================================================================== */
function createDom() {
  function makeNode(tag) {
    const node = {
      tagName: String(tag).toUpperCase(),
      childNodes: [],
      attributes: {},
      style: {},
      className: '',
      textContent: '',
      hidden: false,
      value: '',
      listeners: {},
      usedInnerHtml: false
    };

    node.appendChild = function (child) {
      node.childNodes.push(child);
      if (child && child.__isFragment) {
        node.childNodes.pop();
        for (const c of child.childNodes) { node.childNodes.push(c); }
      }
      return child;
    };
    node.removeChild = function (child) {
      const i = node.childNodes.indexOf(child);
      if (i >= 0) { node.childNodes.splice(i, 1); }
      return child;
    };
    node.setAttribute = function (name, value) { node.attributes[name] = String(value); };
    node.getAttribute = function (name) { return Object.prototype.hasOwnProperty.call(node.attributes, name) ? node.attributes[name] : null; };
    node.addEventListener = function (type, fn) {
      if (!node.listeners[type]) { node.listeners[type] = []; }
      node.listeners[type].push(fn);
    };
    node.focus = function () { node.focused = true; };
    node.querySelector = function (selector) {
      if (String(selector).toLowerCase() === 'tbody') {
        if (!node._tbody) {
          node._tbody = makeNode('tbody');
          node.childNodes.push(node._tbody);
        }
        return node._tbody;
      }
      return null;
    };
    node.click = function () {
      const list = node.listeners.click || [];
      for (const fn of list) { fn({ preventDefault() {} }); }
    };

    Object.defineProperty(node, 'firstChild', {
      get() { return node.childNodes.length ? node.childNodes[0] : null; }
    });

    /* app.js must NEVER use innerHTML. Writing to it in these tests throws, so
     * an accidental HTML injection becomes a test failure rather than a real
     * cross-site-scripting hole. */
    Object.defineProperty(node, 'innerHTML', {
      get() { return ''; },
      set() {
        node.usedInnerHtml = true;
        throw new Error('innerHTML was used - untrusted email text must never be inserted as HTML');
      }
    });

    /* Collect all text inside the node, for assertions. */
    node.allText = function () {
      let out = node.textContent || '';
      for (const child of node.childNodes) {
        if (child && typeof child.allText === 'function') { out += ' ' + child.allText(); }
      }
      return out;
    };
    node.descendants = function (tag) {
      let out = [];
      for (const child of node.childNodes) {
        if (!child) { continue; }
        if (child.tagName === String(tag).toUpperCase()) { out.push(child); }
        if (typeof child.descendants === 'function') { out = out.concat(child.descendants(tag)); }
      }
      return out;
    };
    return node;
  }

  const ids = {};
  const idList = [
    'emailInput', 'charCount', 'inputError', 'analyseBtn', 'clearBtn', 'demoBadge',
    'demoButtons', 'demoNote', 'resultsStatus', 'results', 'resultsTitle',
    'scoreArc', 'scoreValue', 'bandLabel', 'bandMeaning', 'scoreNote',
    'checksSummary', 'overviewList', 'recommendationsList', 'findingsList',
    'checksTable', 'rulesTable'
  ];
  for (const id of idList) { ids[id] = makeNode(id === 'emailInput' ? 'textarea' : 'div'); }

  /* Mirror the "hidden" attributes that index.html sets on these two elements,
   * so the tests start from the same state a browser would. */
  ids.results.hidden = true;
  ids.demoBadge.hidden = true;

  const document = {
    getElementById(id) { return ids[id] || null; },
    createElement(tag) { return makeNode(tag); },
    createDocumentFragment() {
      const frag = makeNode('#fragment');
      frag.__isFragment = true;
      return frag;
    },
    querySelector() { return null; },
    addEventListener() {}
  };

  return {
    document,
    byId: ids,
    /* Simulate the user clicking "Analyse Email". */
    runAnalysis() { ids.analyseBtn.click(); }
  };
}

/* =============================================================================
 * Engine tests
 * ========================================================================== */

const Engine = require(path.join(ROOT, 'engine.js'));
const readSample = (file) => fs.readFileSync(path.join(SAMPLES, file), 'utf8');
const sampleFiles = fs.readdirSync(SAMPLES).filter((f) => f.endsWith('.txt')).sort();
const reportFor = (file) => Engine.analyse(readSample(file));

section('1. The engine loads and its rules are well formed');
eq(typeof Engine.analyse, 'function', 'analyse() is exported');
const catalogue = Engine.ruleCatalogue();
eq(catalogue.length, 44, 'the check catalogue contains 44 checks');
ok(Engine.maxScore > 0, 'the maximum possible score is greater than zero');
eq(new Set(catalogue.map((r) => r.id)).size, catalogue.length, 'every check id is unique');
const allowedSeverities = new Set(['High', 'Medium', 'Low', 'Informational']);
ok(catalogue.every((r) => allowedSeverities.has(r.severity)), 'every check uses one of the four allowed severity words');
ok(catalogue.every((r) => typeof r.weight === 'number' && r.weight >= 0), 'every check has a numeric, non-negative point value');
ok(catalogue.every((r) => r.why && r.benign && r.action), 'every check explains why it matters, an innocent explanation, and what to do');
ok(!catalogue.some((r) => /critical/i.test(r.severity)), 'no check uses the word "Critical"');

section('2. Link defanging');
eq(Engine.defang('https://evil.example/login'), 'hxxps://evil[.]example/login', 'https links are defanged for display');
eq(Engine.defang('http://192.0.2.15:8080/a'), 'hxxp://192[.]0[.]2[.]15:8080/a', 'http links with an IP address are defanged');
eq(Engine.refang('hxxp://evil[.]example/login'), 'http://evil.example/login', 'defanged links are re-armed for analysis');

section('3. The sample emails behave as documented');
const expectations = {
  '01-obvious-phishing.txt': { band: 'High Risk', min: 50, rules: ['password_request', 'mfa_code_request', 'payment_giftcard', 'executable_attachment', 'double_extension', 'url_raw_ip', 'spf_fail', 'dmarc_fail', 'reply_to_mismatch', 'macro_enable', 'threat_suspension'] },
  '02-sophisticated-phishing.txt': { band: 'Suspicious', min: 20, max: 49, rules: ['credential_harvest'] },
  '03-fake-microsoft-365.txt': { band: 'High Risk', min: 50, rules: ['brand_sender_mismatch', 'misleading_link_text', 'url_shortener', 'mfa_code_request', 'dmarc_fail'] },
  '04-fake-parcel-delivery.txt': { band: 'High Risk', min: 50, rules: ['url_brand_lookalike', 'payment_giftcard', 'urgency', 'return_path_mismatch'] },
  '05-fake-invoice-bec.txt': { band: 'High Risk', min: 50, rules: ['bank_change', 'reply_to_mismatch', 'secrecy_pressure', 'bec_tone', 'unexpected_invoice'] },
  '06-legitimate-email.txt': { band: 'No Warning Signs Detected', max: 0, rules: [] },
  '07-legitimate-password-notice.txt': { band: 'No Warning Signs Detected', max: 0, rules: [] }
};

for (const file of sampleFiles) {
  const expected = expectations[file];
  const report = reportFor(file);
  const found = new Set(report.findings.map((f) => f.id));
  if (!expected) { ok(false, 'sample ' + file + ' has no documented expectation'); continue; }
  eq(report.band.label, expected.band, file + ' - classification');
  if (expected.min !== undefined) { ok(report.score >= expected.min, file + ' - score is at least ' + expected.min + ' (got ' + report.score + ')'); }
  if (expected.max !== undefined) { ok(report.score <= expected.max, file + ' - score is at most ' + expected.max + ' (got ' + report.score + ')'); }
  ok(expected.rules.every((id) => found.has(id)), file + ' - the expected checks fired');
  ok(report.findings.every((f) => Array.isArray(f.evidence) && f.evidence.length > 0), file + ' - every finding carries evidence');
}

section('4. The scoring model is explainable and adds up');
for (const file of sampleFiles) {
  const report = reportFor(file);
  const sum = report.findings.reduce((total, f) => total + f.weight, 0);
  eq(report.rawScore, sum, file + ' - the reported total equals the sum of the finding weights');
  eq(report.score, Math.min(100, sum), file + ' - the score is the capped total');
  eq(report.checks.length, 44, file + ' - all 44 checks are reported as performed');
  eq(report.checksTriggered, report.findings.length, file + ' - the count of matched checks agrees with the findings');
  eq(new Set(report.checks.map((c) => c.id)).size, 44, file + ' - the performed-check list has no duplicates');
}
ok(reportFor('01-obvious-phishing.txt').capped === true, 'a very obvious phishing email reports that the scale was capped at 100');
eq(reportFor('01-obvious-phishing.txt').band.level, 'high', 'the band exposes a machine-readable level for styling');
eq(reportFor('06-legitimate-email.txt').findings.length, 0, 'the legitimate email produces no findings at all');
eq(reportFor('07-legitimate-password-notice.txt').score, 0, 'a genuine password notice with reassuring wording still scores zero');

section('5. Robustness, safety and determinism');
const nastyInputs = {
  'an empty string': '',
  'only whitespace': '   \n\n\t  ',
  'null': null,
  'undefined': undefined,
  'a number instead of text': 12345,
  'binary junk': '\u0000\u0001\u0002\ufffd\ufffd',
  'an ordinary sentence': 'Hello, this is just an ordinary sentence about nothing in particular.',
  'bare html': '<html><body><p>hi</p></body></html>',
  'a script tag': '<script>alert(1)</script>',
  'a very large paste': 'Please verify your account immediately '.repeat(20000)
};
for (const label of Object.keys(nastyInputs)) {
  let threw = false;
  try { Engine.analyse(nastyInputs[label]); } catch (err) { threw = true; console.log('        -> ' + err.message); }
  ok(!threw, 'analysing ' + label + ' does not crash');
}
const first = reportFor('01-obvious-phishing.txt');
const second = reportFor('01-obvious-phishing.txt');
eq(first.score, second.score, 'the same email always produces the same score');
eq(first.findings.map((f) => f.id).join(','), second.findings.map((f) => f.id).join(','), 'the same email always produces the same findings');
const tricks = Engine.analyse('Please use \u202e fancy input and hxxps://micros0ft[.]invalid/login now');
ok(tricks.findings.some((f) => f.id === 'url_brand_lookalike'), 'a leetspeak lookalike domain inside a defanged link is still detected');
const rtl = Engine.analyse('Content-Disposition: attachment; filename="invoice\u202egnp.exe"');
ok(rtl.findings.some((f) => f.id === 'rtl_override_filename'), 'a filename with a hidden text-direction character is flagged');
const bodyOnly = Engine.analyse('Dear Customer, your account will be suspended. Verify your account now.');
ok(bodyOnly.findings.some((f) => f.id === 'no_headers'), 'body-only text reports that the header checks were skipped');
ok(!bodyOnly.findings.some((f) => f.id === 'no_auth_results'), 'body-only text does not claim that headers were present but empty');

/* =============================================================================
 * Page tests: the real app.js running in the fake DOM
 * ========================================================================== */

section('6. The page logic renders correctly');
let dom;
let pageThrew = null;
try {
  dom = createDom();
  global.window = global;
  global.document = dom.document;
  require(path.join(SAMPLES, 'demo-emails.js'));
  require(path.join(ROOT, 'app.js'));
} catch (err) {
  pageThrew = err;
}
ok(!pageThrew, 'app.js loads without throwing' + (pageThrew ? ' -> ' + pageThrew.message : ''));
if (pageThrew) { throw pageThrew; }

eq((window.DEMO_EMAILS || []).length, 7, 'seven fictional examples are available');
eq(dom.byId.demoButtons.childNodes.length, 7, 'a button was created for every example');

/* The fake DOM returns a node for any id, so this check catches the mistake
 * that really happens: an id in app.js that does not exist in index.html. */
const htmlForIds = fs.readFileSync(path.join(ROOT, 'index.html'), 'utf8');
const htmlIds = new Set(Array.from(htmlForIds.matchAll(/\sid="([^"]+)"/g)).map((m) => m[1]));
for (const id of Object.keys(dom.byId)) {
  ok(htmlIds.has(id), 'index.html contains the element #' + id);
}
ok(htmlIds.size >= 22, 'the page defines the expected number of identifiable elements');
eq(dom.byId.rulesTable.querySelector('tbody').childNodes.length, 44, 'the published check table lists all 44 checks');
eq(dom.byId.results.hidden, true, 'results stay hidden until something is analysed');

dom.byId.emailInput.value = '';
dom.runAnalysis();
ok(/paste an email/i.test(dom.byId.inputError.textContent), 'analysing an empty box shows a friendly message');
eq(dom.byId.results.hidden, true, 'no result is shown for an empty box');

dom.byId.emailInput.value = readSample('01-obvious-phishing.txt');
dom.runAnalysis();
eq(dom.byId.results.hidden, false, 'results appear after a real analysis');
eq(dom.byId.scoreValue.textContent, '100', 'the dial shows the score');
eq(dom.byId.bandLabel.textContent, 'High Risk', 'the classification is shown');
ok(dom.byId.findingsList.descendants('article').length >= 10, 'a card is rendered for every finding');
eq(dom.byId.checksTable.querySelector('tbody').childNodes.length, 44, 'every check is listed as performed');
ok(dom.byId.recommendationsList.childNodes.length >= 5, 'practical recommendations are listed');
ok(dom.byId.overviewList.childNodes.length > 8, 'the summary panel is populated');
ok(/Analysis complete/.test(dom.byId.resultsStatus.textContent), 'the result is announced in the live region');
ok(!dom.byId.findingsList.usedInnerHtml && !dom.byId.overviewList.usedInnerHtml, 'no innerHTML was used while rendering');

dom.byId.emailInput.value = readSample('06-legitimate-email.txt');
dom.runAnalysis();
eq(dom.byId.bandLabel.textContent, 'No Warning Signs Detected', 'the legitimate email is shown as clean');
eq(dom.byId.scoreValue.textContent, '0', 'the legitimate email scores zero');

dom.byId.demoButtons.childNodes[4].click();
eq(dom.byId.demoBadge.hidden, false, 'loading an example shows the Demo Data label');
ok(/BEC/.test(dom.byId.demoNote.textContent), 'loading an example shows its teaching note');
ok(dom.byId.emailInput.value.indexOf('Return-Path') > -1, 'loading an example fills the input box');

dom.byId.clearBtn.click();
eq(dom.byId.emailInput.value, '', 'the Clear button empties the box');
eq(dom.byId.demoBadge.hidden, true, 'clearing hides the Demo Data label');
eq(dom.byId.results.hidden, true, 'clearing hides the results');

section('7. Untrusted email text cannot become markup or script');
const payload = [
  'From: "Test Sender <script>alert(1)</script>" <a@example.com>',
  'Subject: URGENT <img src=x onerror=alert(1)>',
  '',
  'Dear Customer, please verify your account <script>alert(2)</script> now.',
  'Or use <a href="javascript:alert(3)">this link</a>.'
].join('\n');
let injectionThrew = null;
try {
  dom.byId.emailInput.value = payload;
  dom.runAnalysis();
} catch (err) { injectionThrew = err; }
ok(!injectionThrew, 'rendering a message full of HTML and script payloads does not throw' + (injectionThrew ? ' -> ' + injectionThrew.message : ''));
const rendered = dom.byId.findingsList.allText() + ' ' + dom.byId.overviewList.allText() + ' ' + dom.byId.recommendationsList.allText();
ok(rendered.indexOf('onerror=alert(1)') > -1, 'the payload text is displayed as inert text');
ok(!dom.byId.findingsList.usedInnerHtml && !dom.byId.overviewList.usedInnerHtml && !dom.byId.checksSummary.usedInnerHtml, 'nothing was inserted as raw HTML');
const sourceOfApp = fs.readFileSync(path.join(ROOT, 'app.js'), 'utf8')
  .replace(/\/\*[\s\S]*?\*\//g, '')      // drop block comments - we test code, not prose
  .replace(/(^|[^:])\/\/[^\n]*/g, '$1'); // drop // line comments
ok(!/innerHTML|outerHTML|insertAdjacentHTML|document\.write|\beval\s*\(|new Function/.test(sourceOfApp), 'app.js contains no HTML-injection or code-evaluation functions');
ok(/textContent/.test(sourceOfApp), 'app.js writes content using textContent');

section('8. Privacy and static-hosting guarantees');
const watched = ['index.html', 'styles.css', 'engine.js', 'app.js', 'samples/demo-emails.js'];
const bannedPatterns = [
  [/\bfetch\s*\(/, 'fetch()'],
  [/XMLHttpRequest/, 'XMLHttpRequest'],
  [/new\s+WebSocket/, 'WebSocket'],
  [/sendBeacon/, 'sendBeacon'],
  [/new\s+EventSource/, 'EventSource'],
  [/importScripts/, 'importScripts'],
  [/localStorage/, 'localStorage'],
  [/sessionStorage/, 'sessionStorage'],
  [/document\.cookie/, 'cookies'],
  [/indexedDB/, 'IndexedDB'],
  [/googletagmanager|google-analytics|gtag\s*\(|matomo|plausible|sentry\.io|hotjar/, 'analytics or telemetry services'],
  [/<script[^>]+src\s*=\s*["']https?:/i, 'a script loaded from another website'],
  [/<link[^>]+href\s*=\s*["']https?:/i, 'a stylesheet loaded from another website'],
  [/<img[^>]+src\s*=\s*["']https?:/i, 'an image loaded from another website'],
  [/@import\s+url\(\s*["']?https?:/i, 'a webfont or stylesheet import']
];
for (const file of watched) {
  const text = fs.readFileSync(path.join(ROOT, file), 'utf8');
  for (const [pattern, label] of bannedPatterns) {
    ok(!pattern.test(text), file + ' contains no ' + label);
  }
}

const html = fs.readFileSync(path.join(ROOT, 'index.html'), 'utf8');
const htmlNoComments = html.replace(/<!--[\s\S]*?-->/g, '');
ok(/Content-Security-Policy/.test(html), 'index.html sets a Content Security Policy');
ok(/connect-src 'none'/.test(html), 'the policy blocks every outbound connection (connect-src none)');
ok(/name="referrer" content="no-referrer"/.test(html), 'the page sends no referrer information');
ok(/<meta charset="utf-8">/i.test(html), 'the page declares UTF-8 encoding');
ok(/<html lang="en">/.test(html), 'the page declares its language for screen readers');
ok(/class="skip-link"/.test(html), 'a skip link is provided for keyboard users');
ok(/aria-live="polite"/.test(html), 'results are announced in an accessible live region');
ok(/<label for="emailInput">/.test(html), 'the input box has a proper label');
ok(/https?:\/\//i.test(htmlNoComments) === false, 'the page source contains no external addresses at all');

for (const asset of ['engine.js', 'app.js', 'styles.css', 'samples/demo-emails.js']) {
  ok(html.indexOf(asset) > -1 && fs.existsSync(path.join(ROOT, asset)), asset + ' is referenced by the page and exists on disk');
}

/* =============================================================================
 * Summary
 * ========================================================================== */

console.log('\n' + '='.repeat(66));
console.log('  ' + passed + ' checks passed, ' + failed + ' failed');
if (failed) {
  console.log('\n  Failures:');
  for (const f of failures) { console.log('   - ' + f); }
}
console.log('='.repeat(66));
process.exit(failed ? 1 : 0);