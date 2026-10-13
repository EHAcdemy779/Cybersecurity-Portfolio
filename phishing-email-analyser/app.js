/* =============================================================================
 * Phishing Email Analyser - interface logic
 * -----------------------------------------------------------------------------
 * Rules followed throughout this file:
 *   1. All text that came from the pasted email is inserted with textContent,
 *      never with innerHTML, so nothing in an email can become markup or script.
 *   2. Nothing here performs a network request. The only files loaded are the
 *      ones sitting next to this page.
 * ========================================================================== */
(function () {
  'use strict';

  var Engine = window.PhishingEngine;
  if (!Engine) { return; }               // engine.js must load first

  var MIN_LENGTH = 20;                   // refuse to "analyse" an empty box
  var DIAL_CIRCUMFERENCE = 2 * Math.PI * 52;

  var el = {
    input: document.getElementById('emailInput'),
    charCount: document.getElementById('charCount'),
    inputError: document.getElementById('inputError'),
    analyseBtn: document.getElementById('analyseBtn'),
    clearBtn: document.getElementById('clearBtn'),
    demoBadge: document.getElementById('demoBadge'),
    demoButtons: document.getElementById('demoButtons'),
    demoNote: document.getElementById('demoNote'),
    status: document.getElementById('resultsStatus'),
    results: document.getElementById('results'),
    resultsTitle: document.getElementById('resultsTitle'),
    scoreArc: document.getElementById('scoreArc'),
    scoreValue: document.getElementById('scoreValue'),
    bandLabel: document.getElementById('bandLabel'),
    bandMeaning: document.getElementById('bandMeaning'),
    scoreNote: document.getElementById('scoreNote'),
    checksSummary: document.getElementById('checksSummary'),
    overviewList: document.getElementById('overviewList'),
    recommendationsList: document.getElementById('recommendationsList'),
    findingsList: document.getElementById('findingsList'),
    checksTable: document.getElementById('checksTable'),
    rulesTable: document.getElementById('rulesTable')
  };

  /* ------------------------------- helpers ------------------------------- */

  function clearNode(node) {
    while (node.firstChild) { node.removeChild(node.firstChild); }
  }

  function make(tag, className, text) {
    var node = document.createElement(tag);
    if (className) { node.className = className; }
    if (text !== undefined && text !== null) { node.textContent = String(text); }
    return node;
  }

  function append(parent, children) {
    for (var i = 0; i < children.length; i++) {
      if (children[i]) { parent.appendChild(children[i]); }
    }
    return parent;
  }

  function levelClass(severity) {
    var map = { High: 'sev-high', Medium: 'sev-medium', Low: 'sev-low', Informational: 'sev-info' };
    return map[severity] || 'sev-info';
  }

  /* ---------------------------- input handling ---------------------------- */

  function updateCharCount() {
    var n = el.input.value.length;
    el.charCount.textContent = n.toLocaleString() + (n === 1 ? ' character' : ' characters');
  }

  function setError(message) {
    el.inputError.textContent = message || '';
  }

  function loadDemo(id) {
    var list = window.DEMO_EMAILS || [];
    for (var i = 0; i < list.length; i++) {
      if (list[i].id === id) {
        el.input.value = list[i].text;
        el.demoNote.textContent = list[i].label + ': ' + list[i].note;
        el.demoBadge.hidden = false;
        setError('');
        updateCharCount();
        runAnalysis();
        return;
      }
    }
  }

  function buildDemoButtons() {
    var list = window.DEMO_EMAILS || [];
    clearNode(el.demoButtons);
    var fragment = document.createDocumentFragment();
    for (var i = 0; i < list.length; i++) {
      (function (item) {
        var btn = make('button', 'btn btn-small', item.label);
        btn.type = 'button';
        btn.setAttribute('aria-label', 'Load the fictional example: ' + item.label);
        btn.addEventListener('click', function () { loadDemo(item.id); });
        fragment.appendChild(btn);
      })(list[i]);
    }
    el.demoButtons.appendChild(fragment);
    if (!list.length) {
      el.demoNote.textContent = 'No example data file was found next to this page.';
    }
  }

  el.input.addEventListener('input', function () {
    el.demoBadge.hidden = true;
    updateCharCount();
    if (el.inputError.textContent) { setError(''); }
  });

  el.analyseBtn.addEventListener('click', runAnalysis);

  el.clearBtn.addEventListener('click', function () {
    el.input.value = '';
    el.demoBadge.hidden = true;
    el.demoNote.textContent = '';
    el.results.hidden = true;
    setError('');
    updateCharCount();
    el.input.focus();
  });

  /* Analyse, then draw. Any unexpected error is reported to the user in plain
   * language instead of leaving a broken page. */
  function runAnalysis() {
    var text = el.input.value;
    if (text.replace(/\s+/g, '').length < MIN_LENGTH) {
      setError('Please paste an email first - the box is empty or too short to analyse.');
      el.input.focus();
      return;
    }
    setError('');
    var report;
    try {
      report = Engine.analyse(text);
    } catch (err) {
      setError('Something went wrong while analysing this text. Nothing was sent anywhere - please check the text and try again.');
      return;
    }
    renderReport(report);
  }

  /* ------------------------------ reporting ------------------------------ */

  function renderReport(report) {
    renderScore(report);
    renderOverview(report);
    renderRecommendations(report.recommendations);
    renderFindings(report.findings);
    renderChecksTable(report.checks);

    el.results.hidden = false;
    el.status.textContent = 'Analysis complete. Score ' + report.score + ' out of 100. ' +
      report.band.label + '. ' + report.findings.length + ' warning sign(s) listed.';
    el.results.focus();
  }

  function renderScore(report) {
    var offset = DIAL_CIRCUMFERENCE * (1 - report.score / 100);
    el.scoreArc.style.strokeDasharray = DIAL_CIRCUMFERENCE.toFixed(2);
    el.scoreArc.style.strokeDashoffset = offset.toFixed(2);
    el.scoreArc.setAttribute('class', 'dial-arc level-' + report.band.level);

    el.scoreValue.textContent = String(report.score);
    el.bandLabel.textContent = report.band.label;
    el.bandLabel.className = 'band level-' + report.band.level;
    el.bandMeaning.textContent = report.bandMeaning;
    el.scoreNote.textContent = report.capped
      ? 'The matched checks added up to ' + report.rawScore + ' points, which is beyond the top of the scale, so the score is shown as 100.'
      : '';
    el.checksSummary.textContent = report.checksTotal + ' checks were run, ' + report.checksTriggered +
      ' matched, and their values added up to ' + report.rawScore + ' point' + (report.rawScore === 1 ? '' : 's') + '.';
  }

  function definitionRow(term, description) {
    var dt = make('dt', null, term);
    var dd = make('dd', null, description);
    return [dt, dd];
  }

  function renderOverview(report) {
    var s = report.summary;
    var fragment = document.createDocumentFragment();
    var rows = [];

    rows.push(definitionRow('Subject', s.subject || '(no subject line found)'));
    rows.push(definitionRow('Sender', (s.fromName ? '"' + s.fromName + '" ' : '') + (s.fromAddress ? '<' + s.fromAddress + '>' : 'no From header found')));
    if (s.replyToAddress) { rows.push(definitionRow('Replies go to', s.replyToAddress)); }
    if (s.returnPathAddress) { rows.push(definitionRow('Return-Path', s.returnPathAddress)); }
    rows.push(definitionRow('Raw headers', s.headerDetected ? 'found - identity and authentication checks ran' : 'not found - only the body was analysed'));
    rows.push(definitionRow('SPF / DKIM / DMARC', s.auth.spf + ' / ' + s.auth.dkim + ' / ' + s.auth.dmarc));
    rows.push(definitionRow('Links found', String(s.linkCount)));
    rows.push(definitionRow('Attachments found', s.attachmentCount ? String(s.attachmentCount) + ': ' + s.attachments.join(', ') : (s.hasAttachmentHeader ? 'the message says it has attachments but no file names could be read' : 'none')));

    for (var i = 0; i < rows.length; i++) {
      for (var j = 0; j < rows[i].length; j++) { fragment.appendChild(rows[i][j]); }
    }

    if (s.links.length) {
      var note = make('dt', null, 'Links (shown broken so they cannot be clicked)');
      var dd = make('dd');
      var ul = make('ul', 'link-list');
      for (var k = 0; k < s.links.length; k++) { ul.appendChild(make('li', null, s.links[k])); }
      if (s.linkCount > s.links.length) {
        ul.appendChild(make('li', 'muted', 'and ' + (s.linkCount - s.links.length) + ' more'));
      }
      dd.appendChild(ul);
      fragment.appendChild(note);
      fragment.appendChild(dd);
    }

    clearNode(el.overviewList);
    el.overviewList.appendChild(fragment);
  }

  function renderRecommendations(list) {
    clearNode(el.recommendationsList);
    var fragment = document.createDocumentFragment();
    for (var i = 0; i < list.length; i++) {
      fragment.appendChild(make('li', null, list[i]));
    }
    el.recommendationsList.appendChild(fragment);
  }

  function renderFindings(findings) {
    clearNode(el.findingsList);
    var fragment = document.createDocumentFragment();

    if (!findings.length) {
      var empty = make('div', 'empty-state');
      empty.appendChild(make('p', null, 'No warning signs matched any of the checks.'));
      empty.appendChild(make('p', 'small muted', 'That is a good sign, but it is not a guarantee. None of the checks in this tool found anything in the text you pasted - a short, polite phishing email, a link hidden behind an image, or a message written in another language could still be hostile. If the message asks for money, credentials, a code or a change of bank details, verify it independently before acting.'));
      fragment.appendChild(empty);
    }

    for (var i = 0; i < findings.length; i++) {
      var f = findings[i];
      var card = make('article', 'finding ' + levelClass(f.severity));

      var header = make('header', 'finding-head');
      header.appendChild(make('span', 'sev ' + levelClass(f.severity), f.severity));
      header.appendChild(make('h4', null, f.name));
      header.appendChild(make('span', 'pts', f.weight > 0 ? '+' + f.weight + ' pts' : '0 pts'));
      card.appendChild(header);

      card.appendChild(make('p', 'cat', f.category));

      var ul = make('ul', 'evidence');
      for (var j = 0; j < f.evidence.length; j++) {
        ul.appendChild(make('li', null, f.evidence[j]));
      }
      card.appendChild(ul);

      var dl = make('dl', 'finding-detail');
      dl.appendChild(make('dt', null, 'Why this matters'));
      dl.appendChild(make('dd', null, f.why));
      dl.appendChild(make('dt', null, 'Possible innocent explanation'));
      dl.appendChild(make('dd', null, f.benign));
      dl.appendChild(make('dt', null, 'What to do'));
      dl.appendChild(make('dd', null, f.action));
      card.appendChild(dl);

      fragment.appendChild(card);
    }
    el.findingsList.appendChild(fragment);
  }

  function renderChecksTable(checks) {
    var body = el.checksTable.querySelector('tbody');
    clearNode(body);
    var fragment = document.createDocumentFragment();
    for (var i = 0; i < checks.length; i++) {
      var c = checks[i];
      var tr = document.createElement('tr');
      tr.appendChild(make('th', null, c.name)).setAttribute('scope', 'row');
      tr.appendChild(make('td', null, c.category));
      tr.appendChild(make('td', null, c.weight > 0 ? '+' + c.weight : '0'));
      var result = make('td', c.triggered ? 'matched' : 'clear', c.triggered ? 'matched' : 'no match');
      tr.appendChild(result);
      fragment.appendChild(tr);
    }
    body.appendChild(fragment);
  }

  function renderRulesTable() {
    var body = el.rulesTable.querySelector('tbody');
    clearNode(body);
    var rules = Engine.ruleCatalogue();
    var fragment = document.createDocumentFragment();
    for (var i = 0; i < rules.length; i++) {
      var r = rules[i];
      var tr = document.createElement('tr');
      var th = make('th', null, r.name);
      th.setAttribute('scope', 'row');
      tr.appendChild(th);
      tr.appendChild(make('td', null, r.category));
      tr.appendChild(make('td', null, r.weight > 0 ? '+' + r.weight : '0'));
      tr.appendChild(make('td', null, r.severity));
      fragment.appendChild(tr);
    }
    body.appendChild(fragment);
  }

  /* -------------------------------- start -------------------------------- */

  updateCharCount();
  buildDemoButtons();
  renderRulesTable();
})();