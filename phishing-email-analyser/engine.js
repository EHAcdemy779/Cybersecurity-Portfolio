/* =============================================================================
 * Phishing Email Analyser — analysis engine
 * -----------------------------------------------------------------------------
 * This file contains ONLY analysis logic. It:
 *   - never touches the network (no fetch/XHR/WebSocket anywhere in this project)
 *   - never touches the screen (no DOM access), so it can be unit-tested
 *   - never executes anything found inside an email
 *
 * The browser loads it with a <script> tag and uses window.PhishingEngine.
 * The test runner loads it with require() and uses module.exports.
 * ========================================================================== */
(function (root) {
  'use strict';

  /* ------------------------------------------------------------------ *
   * 1. Reference data (all fictional / educational)
   * ------------------------------------------------------------------ */

  /* Brands frequently impersonated, with the domains they really use.
   * Used to answer: "does this email claim to be from X while coming from
   * somewhere else?" */
  var BRANDS = [
    { label: 'Microsoft 365 / Outlook', terms: ['microsoft', 'microsoft 365', 'office 365', 'office365', 'outlook', 'onedrive', 'sharepoint', 'azure'], domains: ['microsoft.com', 'office.com', 'outlook.com', 'microsoftonline.com', 'live.com', 'sharepoint.com'] },
    { label: 'PayPal', terms: ['paypal'], domains: ['paypal.com', 'paypal.co.uk', 'paypal.me'] },
    { label: 'Amazon', terms: ['amazon', 'amazon prime'], domains: ['amazon.com', 'amazon.co.uk', 'amazon.de'] },
    { label: 'Apple', terms: ['apple', 'icloud', 'itunes', 'apple id'], domains: ['apple.com', 'icloud.com'] },
    { label: 'Google', terms: ['google', 'gmail', 'google workspace'], domains: ['google.com', 'gmail.com', 'google.co.uk'] },
    { label: 'Netflix', terms: ['netflix'], domains: ['netflix.com'] },
    { label: 'Meta / Facebook', terms: ['facebook', 'instagram', 'meta'], domains: ['facebook.com', 'instagram.com', 'meta.com'] },
    { label: 'LinkedIn', terms: ['linkedin'], domains: ['linkedin.com'] },
    { label: 'Dropbox', terms: ['dropbox'], domains: ['dropbox.com'] },
    { label: 'DocuSign', terms: ['docusign'], domains: ['docusign.com', 'docusign.net'] },
    { label: 'Adobe', terms: ['adobe', 'acrobat'], domains: ['adobe.com'] },
    { label: 'DHL', terms: ['dhl'], domains: ['dhl.com', 'dhl.co.uk'] },
    { label: 'FedEx', terms: ['fedex'], domains: ['fedex.com'] },
    { label: 'UPS', terms: ['ups', 'united parcel service'], domains: ['ups.com'] },
    { label: 'Royal Mail', terms: ['royal mail'], domains: ['royalmail.com'] },
    { label: 'USPS', terms: ['usps', 'united states postal'], domains: ['usps.com'] },
    { label: 'Evri / Hermes', terms: ['evri', 'hermes parcel'], domains: ['evri.com', 'myhermes.co.uk'] },
    { label: 'HSBC', terms: ['hsbc'], domains: ['hsbc.com', 'hsbc.co.uk'] },
    { label: 'Barclays', terms: ['barclays'], domains: ['barclays.co.uk'] },
    { label: 'Lloyds Bank', terms: ['lloyds'], domains: ['lloydsbank.com'] },
    { label: 'NatWest', terms: ['natwest'], domains: ['natwest.com'] },
    { label: 'Santander', terms: ['santander'], domains: ['santander.com', 'santander.co.uk'] },
    { label: 'HMRC', terms: ['hmrc', 'hm revenue'], domains: ['gov.uk', 'tax.service.gov.uk'] },
    { label: 'IRS', terms: ['irs', 'internal revenue service'], domains: ['irs.gov'] },
    { label: 'GOV.UK', terms: ['dwp', 'gov.uk', 'government gateway'], domains: ['gov.uk'] },
    { label: 'Zoom', terms: ['zoom'], domains: ['zoom.us', 'zoom.com'] },
    { label: 'Microsoft Teams', terms: ['microsoft teams', 'ms teams'], domains: ['teams.microsoft.com', 'microsoft.com'] },
    { label: 'Xero', terms: ['xero'], domains: ['xero.com'] },
    { label: 'QuickBooks', terms: ['quickbooks', 'intuit'], domains: ['quickbooks.intuit.com', 'intuit.com'] },
    { label: 'Sage', terms: ['sage accounting'], domains: ['sage.com'] },
    { label: 'Steam', terms: ['steam', 'steam community'], domains: ['steampowered.com'] }
  ];

  /* Legitimate, but not corporate. Seeing one of these on an email that claims
   * to come from a company or an IT department is worth a comment. */
  var FREE_MAIL_DOMAINS = ['gmail.com', 'googlemail.com', 'yahoo.com', 'yahoo.co.uk', 'hotmail.com', 'hotmail.co.uk', 'outlook.com', 'live.com', 'msn.com', 'aol.com', 'proton.me', 'protonmail.com', 'gmx.com', 'mail.com', 'zoho.com', 'yandex.com', 'icloud.com'];

  /* Link-shortening services. You cannot see where a shortened link really
   * goes, which is exactly why they appear in phishing campaigns. */
  var SHORTENERS = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'buff.ly', 'ow.ly', 'rebrand.ly', 'cutt.ly', 'shorturl.at', 'tiny.cc', 'rb.gy', 'bit.do', 'soo.gd', 'clck.ru', 'short.gy', 'lnkd.in', 'trib.al', 'v.gd', 'qr.ae', 'zpr.io', 'shorte.st', 'adf.ly', 's.id', 'urlz.fr', 'u.to', 'mcaf.ee', 'x.co', 'smarturl.it'];

  /* Top-level domains with a very high abuse rate in public reporting. A .zip
   * domain is not automatically bad - it is just uncommon for a business
   * login page. */
  var RISKY_TLDS = ['zip', 'mov', 'top', 'xyz', 'club', 'icu', 'tk', 'gq', 'cf', 'ml', 'ga', 'work', 'click', 'link', 'rest', 'fit', 'cam', 'monster', 'live', 'buzz', 'cyou', 'sbs', 'quest', 'cfd', 'shop', 'bar', 'beauty', 'autos', 'lol', 'pw', 'ws', 'su', 'download', 'review', 'country', 'men', 'loan', 'date', 'racing', 'win', 'bid', 'stream', 'gdn', 'ooo', 'info', 'biz'];

  var DANGEROUS_FILES = {
    executable: ['exe', 'scr', 'com', 'pif', 'cpl', 'msi', 'msp', 'msc', 'jar', 'bat', 'cmd', 'ps1', 'psm1', 'vbs', 'vbe', 'js', 'jse', 'wsf', 'wsh', 'hta', 'lnk', 'reg', 'inf', 'gadget', 'apk', 'dll', 'sys', 'iso', 'img', 'vhd', 'vhdx', 'dmg', 'app', 'desktop', 'scf', 'url', 'sh', 'run'],
    macro: ['docm', 'xlsm', 'pptm', 'dotm', 'xltm', 'potm', 'ppam', 'xlam', 'doc', 'xls', 'ppt'],
    web: ['html', 'htm', 'xhtml', 'shtml', 'svg', 'mhtml', 'mht'],
    archive: ['zip', 'rar', '7z', 'gz', 'tgz', 'bz2', 'xz', 'cab', 'ace', 'arj', 'lzh']
  };

  /* Extensions that look harmless and are regularly used to hide code. */
  var LURE_EXTENSIONS = ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'jpg', 'jpeg', 'png', 'gif', 'txt', 'csv', 'mp3', 'mp4', 'wav', 'zip', 'html', 'htm'];

  /* Attachment names built to look like a business document. */
  var LURE_KEYWORDS = ['invoice', 'payment', 'receipt', 'statement', 'remittance', 'purchase order', 'shipping', 'delivery', 'parcel', 'resume', 'cv', 'scan', 'scanned', 'document', 'doc', 'photo', 'secure', 'update', 'urgent', 'swift', 'bank', 'verify', 'confirmation', 'order', 'payslip', 'report'];

  /* Private / documentation-only address ranges. Safer than real examples. */
  var PRIVATE_IP = /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|0\.)/;

  /* 192.0.2.0/24, 198.51.100.0/24 and 203.0.113.0/24 are reserved by RFC 5737
   * specifically for documentation, so they can never belong to a real host. */
  var DOCUMENTATION_IP = /^(192\.0\.2\.|198\.51\.100\.|203\.0\.113\.)/;

  /* ------------------------------------------------------------------ *
   * 2. Small helper functions
   * ------------------------------------------------------------------ */

  function lower(s) { return String(s == null ? '' : s).toLowerCase(); }

  function uniq(list) {
    var seen = Object.create(null), out = [];
    for (var i = 0; i < list.length; i++) {
      var k = list[i];
      if (k && !seen[k]) { seen[k] = 1; out.push(k); }
    }
    return out;
  }

  function escapeRegex(text) {
    return String(text).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }

  /* Find whole phrases as they appear in the text, e.g. "act now".
   * Spaces in a phrase will also match a hyphen or extra whitespace, because
   * attackers often write "act-now" or "act  now". */
  function findTerms(haystack, terms) {
    var text = haystack;
    var found = [], seen = Object.create(null);
    for (var i = 0; i < terms.length; i++) {
      var pattern = escapeRegex(terms[i]).replace(/\\? /g, '[\\s\\-_]*');
      var rx = new RegExp('(?:^|[^a-z0-9])(' + pattern + ')(?![a-z0-9])', 'i');
      var m = rx.exec(text);
      var key = lower(terms[i]);
      if (m && !seen[key]) { seen[key] = 1; found.push(m[0].replace(/^[^a-zA-Z0-9]+/, '').trim()); }
    }
    return found;
  }

  /* Show links in a harmless, un-clickable form (defanging).
   * "https://evil.example/login" -> "hxxps://evil[.]example/login" */
  function defang(url) {
    return String(url == null ? '' : url)
      .replace(/^https:\/\//i, 'hxxps://')
      .replace(/^http:\/\//i, 'hxxp://')
      .replace(/\./g, '[.]');
  }

  /* Undo defanging so that a "safe" pasted link is still analysed:
   * "hxxp://evil[.]example/login" -> "http://evil.example/login" */
  function refang(text) {
    return String(text == null ? '' : text)
      .replace(/\bhxxps:\/\//gi, 'https://')
      .replace(/\bhxxp:\/\//gi, 'http://')
      .replace(/\[\.\]|\(\.\)/g, '.')
      .replace(/\[:\]/g, ':');
  }

  function clip(text, max) {
    var t = String(text == null ? '' : text).replace(/\s+/g, ' ').trim();
    if (t.length <= max) return t;
    return t.slice(0, max - 1) + '…';
  }

  /* Convert HTML to readable text WITHOUT a browser. Tags are removed and
   * common entities decoded. Nothing here renders HTML - it only converts
   * it to plain text for analysis. */
  function htmlToText(html) {
    var s = String(html == null ? '' : html);
    s = s.replace(/<\s*(script|style)[^>]*>[\s\S]*?<\s*\/\s*\1\s*>/gi, ' ');
    s = s.replace(/<br\s*\/?>/gi, '\n');
    s = s.replace(/<\s*\/\s*(p|div|tr|li|h[1-6]|table|a)\s*>/gi, '\n');
    s = s.replace(/<[^>]*>/g, ' ');
    s = s.replace(/&nbsp;/gi, ' ')
      .replace(/&amp;/gi, '&')
      .replace(/&lt;/gi, '<')
      .replace(/&gt;/gi, '>')
      .replace(/&quot;/gi, '"')
      .replace(/&#0?39;|&apos;/gi, "'")
      .replace(/&#x([0-9a-f]+);/gi, function (m, h) { var n = parseInt(h, 16); return isNaN(n) ? m : String.fromCharCode(n); })
      .replace(/&#(\d+);/g, function (m, d) { var n = parseInt(d, 10); return isNaN(n) ? m : String.fromCharCode(n); });
return s.replace(/[ \t]+/g, ' ');
  }
    /* ------------------------------------------------------------------ *
   * 3. Parsing the pasted email (headers + body + HTML)
   * ------------------------------------------------------------------ */

  var HEADER_LINE = /^([A-Za-z][A-Za-z0-9-]{0,40}):[ \t]?([\s\S]*)$/;

  function isHeaderLine(line) {
    return /^[A-Za-z][A-Za-z0-9-]{0,40}:[ \t]?.*$/.test(line);
  }

  /* A pasted email may be:
   *   - body only
   *   - body + raw headers (the technical block at the top)
   * We only treat the top of the paste as headers if at least two
   * header-looking lines appear before the first blank line. */
  function splitHeadersAndBody(raw) {
    var text = String(raw == null ? '' : raw)
      .replace(/\r\n/g, '\n').replace(/\r/g, '\n')
      .replace(/^\uFEFF/, '');

    var lines = text.split('\n');
    var headerLines = [], started = false, idx = 0;

    for (; idx < lines.length; idx++) {
      var line = lines[idx];
      if (line === '') { if (started) { idx++; } break; }
      if (isHeaderLine(line)) { headerLines.push(line); started = true; continue; }
      if (started && /^[ \t]/.test(line)) { headerLines.push(line); continue; } // folded line
      break;
    }

    if (headerLines.length < 2) {
      return { headerLines: [], detected: false, body: text };
    }
    return { headerLines: headerLines, detected: true, body: lines.slice(idx).join('\n') };
  }

  function unfold(values) {
    var out = [];
    for (var i = 0; i < values.length; i++) {
      if (/^[ \t]+$|^[ \t]\S/.test(values[i]) && out.length) out[out.length - 1] += ' ' + values[i].trim();
      else out.push(values[i]);
    }
    return out;
  }

  function parseHeaderBlock(headerLines) {
    var unfolded = unfold(headerLines);
    var map = Object.create(null), order = [], list = Object.create(null);
    var current = null;

    for (var i = 0; i < unfolded.length; i++) {
      var m = HEADER_LINE.exec(unfolded[i]);
      if (!m) continue;
      var name = lower(m[1]);
      var value = m[2].trim();
      if (current === name && map[name]) { map[name] = map[name] + ' ' + value; continue; }
      if (map[name]) map[name] = map[name] + '\n' + value;
      else { map[name] = value; order.push(name); }
      if (!list[name]) list[name] = [];
      list[name].push(value);
      current = name;
    }
    return { map: map, order: order, list: list };
  }

  function extractAddress(value) {
    if (!value) return null;
    var vm = /<([^<>]+)>/.exec(value);
    var addr = (vm ? vm[1] : value).trim();
    addr = addr.replace(/^["']|["']$/g, '').trim();
    addr = addr.replace(/^mailto:/i, '');
    var at = addr.lastIndexOf('@');
    if (at < 1) return null;
    var local = addr.slice(0, at).trim();
    var domain = lower(addr.slice(at + 1).replace(/[>,;)\s].*$/, '').replace(/\.+$/, ''));
    if (!domain || domain.indexOf(' ') >= 0) return null;
    return { address: local + '@' + domain, local: lower(local), domain: domain };
  }

  function displayName(value) {
    if (!value) return '';
    var m = /^[ \t]*"?([^"<>]*?)"?[ \t]*</.exec(value);
    if (m && m[1].trim()) return m[1].trim();
    if (value.indexOf('@') < 0) return value.trim();
return '';
  }
    /* ------------------------------------------------------------------ *
   * 4. Links and attachments
   * ------------------------------------------------------------------ */

  var TWO_PART_SUFFIXES = ['co.uk', 'org.uk', 'me.uk', 'ltd.uk', 'plc.uk', 'net.uk', 'sch.uk', 'ac.uk', 'gov.uk', 'nhs.uk', 'police.uk', 'mod.uk', 'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au', 'asn.au', 'co.nz', 'net.nz', 'org.nz', 'govt.nz', 'ac.nz', 'co.jp', 'ne.jp', 'or.jp', 'go.jp', 'ac.jp', 'co.kr', 'com.br', 'com.cn', 'com.hk', 'com.sg', 'com.my', 'com.tw', 'com.ph', 'com.vn', 'co.id', 'co.th', 'co.in', 'net.in', 'org.in', 'co.za', 'com.mx', 'com.ar', 'com.co', 'com.pe', 'com.tr', 'com.ua', 'co.il', 'co.ke', 'com.ng', 'com.pk', 'com.bd', 'com.sa', 'com.eg', 'gov.ie'];

  var URL_RX = /\b((?:hxxps?|https?|ftp):\/\/[^\s<>"'`]+)/gi;

  function isIpHost(host) {
    var h = String(host || '').replace(/^\[|\]$/g, '');
    if (!h) return false;
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h)) return true;
    if (/^0x[0-9a-f]{6,}$/i.test(h)) return true;   // hex-encoded address
    if (/^\d{8,10}$/.test(h)) return true;          // decimal-encoded address
    return h.indexOf(':') >= 0;                     // IPv6
  }

  function registeredDomain(host) {
    if (!host || isIpHost(host)) return host || '';
    var parts = String(host).split('.').filter(Boolean);
    if (parts.length <= 2) return parts.join('.');
    var lastTwo = parts.slice(-2).join('.');
    if (TWO_PART_SUFFIXES.indexOf(lastTwo) >= 0 && parts.length >= 3) return parts.slice(-3).join('.');
    return lastTwo;
  }

  function parseUrl(candidate) {
    var m = /^([a-z][a-z0-9+.-]*):\/\/([^\/?#]*)([^?#]*)(\?[^#]*)?(#.*)?$/i.exec(candidate);
    if (!m) return null;
    var scheme = lower(m[1]);
    var authority = m[2];
    var userinfo = '';
    var at = authority.lastIndexOf('@');
    if (at >= 0) { userinfo = authority.slice(0, at); authority = authority.slice(at + 1); }
    var host = authority, port = '';
    var pm = /^(\[[^\]]+\]|[^:]+)(?::(\d+))?$/.exec(authority);
    if (pm) { host = pm[1] || ''; port = pm[2] || ''; }
    host = lower(host).replace(/\.$/, '');
    if (!host) return null;
    return {
      url: candidate,
      scheme: scheme,
      userinfo: userinfo,
      host: host,
      port: port,
      path: m[3] || '',
      query: m[4] || '',
      registered: registeredDomain(host),
      isIp: isIpHost(host),
      isDocumentationIp: DOCUMENTATION_IP.test(host.replace(/^\[|\]$/g, '')),
      labels: host.split('.').length
    };
  }

  /* Pull every link out of the text. Defanged links (hxxp://evil[.]example)
   * are re-armed internally so they can still be analysed, and everything is
   * re-defanged before display. */
  function extractUrls(text) {
    var armed = refang(text);
    var out = [], seen = Object.create(null), m;
    URL_RX.lastIndex = 0;
    while ((m = URL_RX.exec(armed)) !== null) {
      var candidate = m[1].replace(/[.,;:!?]+$/, '').replace(/[)\]}>'"]+$/, '');
      var parsed = parseUrl(candidate);
      if (!parsed || !parsed.host || seen[parsed.url]) continue;
      seen[parsed.url] = 1;
      out.push(parsed);
    }
    return out;
  }

  function extensionList(name) {
    var matches = lower(name).match(/\.[a-z0-9]{1,8}/g) || [];
    return matches.map(function (x) { return x.slice(1); });
  }

  function inList(list, value) { return list.indexOf(lower(value)) >= 0; }

  /* Find attachment filenames in two places:
   *   1. the MIME headers (filename="..." / Content-Disposition: attachment)
   *   2. filenames typed into the message body
   * The body scan only accepts extensions we care about, so ordinary
   * sentences containing a dot are not mistaken for attachments. */
  function extractAttachments(rawText, bodyText) {
    var raw = String(rawText == null ? '' : rawText);
    var body = String(bodyText == null ? '' : bodyText);
    var found = [], seen = Object.create(null);

    function add(name, source) {
      var clean = String(name || '').replace(/[\u0000-\u001f\u007f]/g, '').replace(/^["'\s]+|["'\s]+$/g, '').trim();
      if (!clean || clean.length > 200) return;
      var key = lower(clean);
      if (seen[key]) return;
      seen[key] = 1;
      found.push({ name: clean, source: source, extensions: extensionList(clean) });
    }

    var rx1 = /(?:file)?name\s*=\s*(?:"([^"\r\n]{1,180})"|([^\s;\r\n"]{1,180}))/gi, m;
    while ((m = rx1.exec(raw)) !== null) add(m[1] || m[2], 'mime');

    var rx2 = /content-disposition:\s*attachment[^\r\n]*(?:filename\*?=(?:utf-8''|["']?)([^"'\r\n;]+))/gi;
    while ((m = rx2.exec(raw)) !== null) add(m[1], 'mime');

    var interesting = uniq(DANGEROUS_FILES.executable.concat(DANGEROUS_FILES.macro, DANGEROUS_FILES.web, DANGEROUS_FILES.archive, LURE_EXTENSIONS));
    var bodyRx = new RegExp('(?:^|[\\s(\\[<>\'",;:])([A-Za-z0-9][A-Za-z0-9 _()\\-]{0,60}?\\.(?:' + interesting.join('|') + ')(?:\\.[A-Za-z0-9]{1,5})?)(?=[\\s)\\]<>,.!?"\';:]|$)', 'gi');
    var n;
    bodyRx.lastIndex = 0;
    while ((n = bodyRx.exec(body)) !== null) {
      var start = n.index + n[0].indexOf(n[1]);
      var before = body.charAt(start - 1);
      if (before === '/' || before === '@' || before === '.') continue;  // part of a link, not a file
      add(n[1], 'text');
    }

    var hasAttachmentHeader = /content-disposition:\s*attach/i.test(raw);
    return {
      names: found,
      hasAttachmentHeader: hasAttachmentHeader,
      hasAttachments: found.length > 0 || hasAttachmentHeader
    };
  }

  /* Find "click here" anchors so the VISIBLE text can be compared with the
   * ACTUAL destination - the oldest trick in phishing. */
  function extractAnchors(html) {
    var source = String(html == null ? '' : html);
    var out = [], m;
    var rx = /<a\b[^>]*href\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))[^>]*>([\s\S]*?)<\/a\s*>/gi;
    while ((m = rx.exec(source)) !== null) {
      var href = refang(m[1] || m[2] || m[3] || '').trim();
      var text = htmlToText(m[4] || '').trim();
      var hrefUrl = /^[a-z][a-z0-9+.-]*:\/\//i.test(href) ? parseUrl(href) : null;
      var textUrls = extractUrls(text);
      out.push({
        href: href,
        hrefHost: hrefUrl ? hrefUrl.host : '',
        hrefRegistered: hrefUrl ? hrefUrl.registered : '',
        text: text,
        textHost: textUrls.length ? textUrls[0].host : '',
        textRegistered: textUrls.length ? textUrls[0].registered : ''
      });
    }
    return out;
  }

  /* ------------------------------------------------------------------ *
   * 5. Build the analysis context from the pasted text
   * ------------------------------------------------------------------ */

  /* "Leetspeak" normalisation: m1crosoft, paypa1 and rnicrosoft become
   * readable again so lookalike names can be spotted. */
  var LEET_MAP = { '0': 'o', '1': 'i', '3': 'e', '5': 's', '4': 'a', '7': 't', '8': 'b', '9': 'g', '@': 'a', '$': 's', '!': 'i', '|': 'l' };

  function skeleton(text) {
    var chars = lower(text).replace(/vv/g, 'w').replace(/rn/g, 'm').split('');
    var out = '';
    for (var i = 0; i < chars.length; i++) out += (LEET_MAP[chars[i]] || chars[i]);
    return out.replace(/[^a-z]/g, '');
  }

  function isOfficialHost(host, brand) {
    if (!host) return false;
    for (var i = 0; i < brand.domains.length; i++) {
      var d = brand.domains[i];
      if (host === d || host.slice(-(d.length + 1)) === '.' + d) return true;
    }
    return false;
  }

  /* Does a hostname look like a brand name it is not? */
  function findBrandInHost(host) {
    var hostSkel = skeleton(host);
    var labels = String(host || '').split('.').map(skeleton);
    var hits = [];
    for (var b = 0; b < BRANDS.length; b++) {
      var brand = BRANDS[b];
      for (var t = 0; t < brand.terms.length; t++) {
        var sk = skeleton(brand.terms[t]);
        if (sk.length < 3) continue;
        var hit = false;
        if (sk.length >= 5) hit = hostSkel.indexOf(sk) >= 0;
        else {
          for (var l = 0; l < labels.length; l++) {
            if (labels[l].length >= sk.length && (labels[l].indexOf(sk) === 0 || labels[l].slice(-sk.length) === sk)) hit = true;
          }
        }
        if (hit) { hits.push(brand); break; }
      }
    }
    return hits;
  }

  function findBrandInText(text, minTermLength) {
    var hits = [];
    var min = minTermLength || 4;
    for (var b = 0; b < BRANDS.length; b++) {
      var brand = BRANDS[b];
      for (var t = 0; t < brand.terms.length; t++) {
        if (brand.terms[t].length < min) continue;
        if (findTerms(text, [brand.terms[t]]).length) { hits.push(brand); break; }
      }
    }
    return hits;
  }

  function parseEmail(rawInput) {
    var raw = String(rawInput == null ? '' : rawInput);
    var split = splitHeadersAndBody(raw);
    var headers = split.detected
      ? parseHeaderBlock(split.headerLines)
      : { map: Object.create(null), order: [], list: Object.create(null) };
    var body = split.body || '';
    var hasHtml = /<\s*(html|body|div|p|br|span|table|font|img|a)\b/i.test(body);
    var bodyText = hasHtml ? htmlToText(body) : body;

    var fromValue = headers.map['from'] || '';
    var authText = [headers.map['authentication-results'] || '', headers.map['arc-authentication-results'] || '']
      .concat(headers.list['received-spf'] || []).join('\n');

    var urls = extractUrls(body).concat(extractUrls(bodyText));
    var seenUrls = Object.create(null);
    var uniqueUrls = [];
    for (var i = 0; i < urls.length; i++) {
      if (!seenUrls[urls[i].url]) { seenUrls[urls[i].url] = 1; uniqueUrls.push(urls[i]); }
    }

    return {
      raw: raw,
      body: body,
      bodyText: bodyText,
      hasHtml: hasHtml,
      headerDetected: split.detected,
      headers: headers,
      subject: headers.map['subject'] || '',
      fromValue: fromValue,
      fromName: displayName(fromValue),
      from: extractAddress(fromValue),
      replyTo: extractAddress(headers.map['reply-to'] || ''),
      returnPath: extractAddress(headers.map['return-path'] || ''),
      sender: extractAddress(headers.map['sender'] || ''),
      authText: authText,
      /* True when the sender's authentication verdict was actually present in
       * the headers (the values look like "spf=pass; dkim=fail; dmarc=fail"). */
      hasAuthResults: !!(
        headers.map['authentication-results'] ||
        headers.map['arc-authentication-results'] ||
        headers.map['received-spf'] ||
        (headers.list['received-spf'] && headers.list['received-spf'].length) ||
        /spf\s*=|dkim\s*=|dmarc\s*=/i.test(authText)
      ),
      received: headers.list['received'] || [],
      urls: uniqueUrls,
      attachments: extractAttachments(raw, bodyText),
      anchors: hasHtml ? extractAnchors(body) : [],
      searchText: (headers.map['subject'] || '') + '\n' + bodyText
    };
  }

  /* ------------------------------------------------------------------ *
   * 6. Detection rules
   *    Every rule has a fixed point value and a written explanation, so the
   *    final score can always be traced back to specific evidence.
   * ------------------------------------------------------------------ */

  function keywordRule(spec) {
    return {
      id: spec.id,
      name: spec.name,
      category: spec.category || 'Language and pressure',
      weight: spec.weight,
      severity: spec.severity,
      why: spec.why,
      benign: spec.benign,
      action: spec.action,
      test: function (c) {
        var found = findTerms(c.searchText, spec.terms);
        if (!found.length) return null;
        return { evidence: found.map(function (f) { return 'Contains the wording "' + f + '"'; }) };
      }
    };
  }

  var SAFE_MARKERS = ['no action is required', 'no action required', 'you do not need to take any action', 'do not need to take any action', 'this is a confirmation', 'if you did not request', 'if you did not make this change', 'if you did not authorise', 'never ask you for your password', 'never ask for your password', 'do not share your password', 'we will not ask you', 'no further action'];

  /* An email that tells the reader not to share credentials, and that no
   * action is needed, is showing good practice. Recognising that stops the
   * tool from punishing a genuine notification. */
  function safeWording(ctx) {
    return findTerms(ctx.searchText, SAFE_MARKERS);
  }

  var RULES = [
    keywordRule({
      id: 'urgency',
      name: 'Urgency and pressure language',
      weight: 10,
      severity: 'Medium',
      terms: ['urgent', 'immediately', 'act now', 'immediate action', 'within 24 hours', 'within 48 hours', 'expires', 'expiring', 'final notice', 'final reminder', 'last warning', 'last chance', 'time sensitive', 'as soon as possible', 'right away', 'without delay', 'do not delay', 'before it is too late', 'deadline', 'today only', 'limited time', 'overdue', 'immediate attention', 'act immediately'],
      why: 'Pressure to act fast is the most common social-engineering technique. It is designed to stop you checking the message properly.',
      benign: 'Genuine services do send deadline reminders - a real renewal date or payment due date is not automatically suspicious.',
      action: 'Slow down. Verify the request through a channel you chose yourself, such as typing the organisation\'s address into your browser.'
    }),
    keywordRule({
      id: 'threat_suspension',
      name: 'Threat of account closure or suspension',
      weight: 20,
      severity: 'High',
      terms: ['will be suspended', 'account suspended', 'will be closed', 'account closure', 'will be deactivated', 'deactivated', 'permanently deleted', 'will be deleted', 'permanently disabled', 'access will be revoked', 'access will be restricted', 'account locked', 'locked out', 'legal action', 'law enforcement', 'police report', 'terminate your account', 'disable your account', 'failure to comply', 'failure to verify', 'for legal reasons', 'account will be terminated'],
      why: 'Threatening loss of access or legal consequences creates fear. Real organisations rarely use threats to force a quick click.',
      benign: 'Some regulated industries do send formal warnings about overdue accounts or policy changes.',
      action: 'Do not act from the email itself. Log in to the service the way you normally would and look for a real notification there.'
    }),
    keywordRule({
      id: 'mfa_code_request',
      name: 'Request for a verification or MFA code',
      weight: 25,
      severity: 'High',
      terms: ['verification code', 'one-time code', 'one time code', 'otp', 'one-time password', 'authenticator code', '6-digit code', 'six digit code', 'security code', 'two-factor code', 'mfa code', 'share the code', 'provide the code', 'read out the code', 'code sent to your phone', 'approve the sign-in request', 'approve the login request', 'send us the code', 'reply with the code'],
      why: 'A one-time code is the last line of defence on your account. Anyone who asks you to reveal it is trying to finish a login or payment that you did not start.',
      benign: 'Legitimate services deliver codes to you; they do not ask you to send a code back to them.',
      action: 'Never send, read out or type a one-time code into an email, chat or website. Report the message.'
    }),
    keywordRule({
      id: 'payment_giftcard',
      name: 'Payment, gift card or fee request',
      weight: 25,
      severity: 'High',
      terms: ['gift card', 'gift cards', 'itunes card', 'google play card', 'amazon card', 'steam card', 'voucher code', 'voucher codes', 'wire transfer', 'wire the funds', 'bank transfer', 'money order', 'western union', 'moneygram', 'cryptocurrency', 'bitcoin', 'usdt', 'processing fee', 'handling fee', 'redelivery fee', 'service fee', 'small fee', 'payment required', 'pay the fee', 'clearing fee', 'release fee', 'customs fee', 'payment page'],
      why: 'Gift cards, vouchers and crypto are almost untraceable, which is why fraudsters ask for them. Unexpected "fees" are the standard parcel and invoice scam.',
      benign: 'Genuine companies do request payment for real services - but through their own billing portal, with an invoice history you can check.',
      action: 'Never pay with gift cards or vouchers in response to an email. Verify the debt on the organisation\'s official website using a phone number you look up yourself.'
    }),
    keywordRule({
      id: 'bank_change',
      name: 'Request to change bank or payment details',
      weight: 25,
      severity: 'High',
      terms: ['change of bank details', 'updated banking details', 'revised banking details', 'new bank details', 'new account number', 'new bank account', 'our bank account has changed', 'update our bank details', 'update your bank account', 'update payment details', 'update your payment details', 'update your direct deposit', 'new remittance details', 'revised remittance', 'update your billing', 'bank details have changed', 'account details have changed'],
      why: 'Changing payment details is the normal route for invoice fraud - the money goes to the fraudster instead of the real supplier.',
      benign: 'Suppliers genuinely do change banks occasionally, and payroll details do change for real reasons.',
      action: 'Confirm any change of bank details by phoning the supplier or colleague on a number you already have - never a number supplied in the email.'
    }),
    keywordRule({
      id: 'credential_harvest',
      name: 'Credential-harvesting language',
      weight: 20,
      severity: 'High',
      terms: ['verify your account', 'verify your identity', 'confirm your identity', 'confirm your account', 'confirm your details', 'sign in to continue', 'click here to login', 'click here to sign in', 're-validate', 'restore access', 'reactivate your account', 'unlock your account', 'validate your account', 'update your information', 'unusual activity', 'unusual sign-in', 'unusual login', 'suspicious activity on your account', 'secure your account', 'account verification', 'security check', 'confirm your information'],
      why: 'These phrases exist to move you onto a fake login page. The pattern is usually more reliable to spot than the design of the page.',
      benign: 'Real security notifications may mention unusual activity, but they direct you to log in normally rather than through a link in the message.',
      action: 'Do not follow the link. Open the service by typing its address yourself and review your account security settings there.'
    }),
    {
      id: 'password_request',
      name: 'Password request or password discussion',
      category: 'Language and pressure',
      weight: 25,
      severity: 'High',
      why: 'No legitimate organisation asks you to send or type your password into an email. A direct request for one is an attempt to steal access.',
      benign: 'A genuine notification may mention passwords - for example "your password was changed". What matters is whether the email is asking you to supply one.',
      action: 'Never reply with a password. If you are concerned, change the password from the service\'s own website and turn on multi-factor authentication.',
      test: function (c) {
        var strong = findTerms(c.searchText, ['enter your password', 'type your password', 'provide your password', 'confirm your password', 'send your password', 'username and password', 'login credentials', 'provide your credentials', 'your login details', 'your credentials']);
        var soft = findTerms(c.searchText, ['your password']);
        var chosen = [];
        if (strong.length) chosen = strong;
        else if (soft.length && !safeWording(c).length) chosen = soft;
        if (!chosen.length) return null;
        return { evidence: chosen.map(function (f) { return 'Contains the wording "' + f + '"'; }) };
      }
    },
    {
      id: 'safe_wording',
      name: 'Recognised good-practice wording',
      category: 'Reassurance',
      weight: 0,
      severity: 'Informational',
      why: 'The message explicitly says that no action is needed and never to share credentials. This is the wording genuine services use.',
      benign: 'Fraudsters sometimes copy this wording to look trustworthy, so it lowers concern but proves nothing.',
      action: 'If you are still unsure, verify through the official app or website.',
      test: function (c) {
        var s = safeWording(c);
        if (!s.length) return null;
        return { evidence: s.map(function (f) { return 'Contains the reassuring wording "' + f + '"'; }) };
      }
    },
    keywordRule({
      id: 'role_impersonation',
      name: 'Impersonation of a team or support role',
      weight: 12,
      severity: 'Medium',
      terms: ['it helpdesk', 'help desk', 'helpdesk', 'it support', 'it department', 'technical support', 'system administrator', 'network administrator', 'security team', 'security department', 'account protection team', 'microsoft account team', 'fraud department', 'billing department', 'people operations', 'human resources', 'payroll department', 'accounts department', 'delivery support', 'support team'],
      why: 'Claiming to be an IT, security, payroll or support team works well because people are used to following internal instructions.',
      benign: 'Real internal teams do send genuine notifications under these names.',
      action: 'Check the actual sending address rather than the display name, and confirm internal requests in person or on a number you already have.'
    }),
    keywordRule({
      id: 'generic_greeting',
      name: 'Impersonal or generic greeting',
      weight: 5,
      severity: 'Low',
      terms: ['dear customer', 'dear user', 'dear valued customer', 'dear sir/madam', 'dear account holder', 'dear client', 'dear member', 'dear email user'],
      why: 'A service you actually use usually knows your name. Generic greetings are typical of mass campaigns.',
      benign: 'Newsletters and some legitimate senders do use "Dear customer" when they do not personalise messages.',
      action: 'Treat it as one small clue among many, not as proof on its own.'
    }),
    keywordRule({
      id: 'secrecy_pressure',
      name: 'Pressure to keep the request secret',
      weight: 15,
      severity: 'Medium',
      terms: ['do not tell anyone', 'do not tell', 'keep this confidential', 'keep it confidential', 'do not discuss', 'do not mention', 'keep this between us', 'reply from your personal email', 'from your personal email', 'do not contact anyone', 'confidential until'],
      why: 'Asking you not to discuss a request is a way of stopping a colleague from spotting the fraud. Genuine payment processes do not need secrecy.',
      benign: 'Some HR or legal matters really are confidential, but they normally follow a formal process rather than an informal email.',
      action: 'Discuss it with a colleague or your manager anyway. Secrecy requests around money are a serious warning sign.'
    }),
    keywordRule({
      id: 'unexpected_invoice',
      name: 'Unexpected invoice or payment demand',
      weight: 12,
      severity: 'Medium',
      terms: ['invoice', 'payment overdue', 'outstanding balance', 'outstanding invoice', 'remittance advice', 'remittance details', 'purchase order', 'statement of account', 'payment reference', 'awaiting payment', 'amount due', 'attached invoice', 'please settle'],
      why: 'An invoice you were not expecting is the standard opening for invoice fraud and business email compromise.',
      benign: 'Real suppliers do send real invoices, and busy finance teams receive many every day.',
      action: 'Match the invoice against your own records - purchase orders, contracts, delivery notes - before any payment is authorised.'
    }),
    keywordRule({
      id: 'bec_tone',
      name: 'Executive or assistant impersonation tone',
      weight: 12,
      severity: 'Medium',
      terms: ['are you at your desk', 'are you available', 'quick favour', 'quick favor', 'need your help urgently', 'i need a favour', 'urgent request', 'have you got a minute', 'are you free', 'handle this today', 'are you in the office', 'can you do something for me'],
      why: 'Short, friendly requests that sound like a senior colleague or their assistant are the trademark of business email compromise.',
      benign: 'Colleagues really do send short informal messages - which is exactly why this technique works.',
      action: 'Confirm the request using a contact method you already have for that person, never the reply address in the message.'
    }),
    keywordRule({
      id: 'macro_enable',
      name: 'Instructions to enable macros or active content',
      weight: 20,
      severity: 'High',
      terms: ['enable macros', 'enable content', 'enable editing', 'enable editing and enable macros', 'click enable content', 'turn on macros', 'macro must be enabled', 'trust the document', 'enable active content', 'click enable editing'],
      why: 'Macros run code. A document that has to have macros "enabled" before it shows anything is a well-known malware delivery method.',
      benign: 'Some genuine business spreadsheets use macros, but the request usually comes from a known colleague with context, not from an unexpected attachment.',
      action: 'Do not enable macros. Ask the sender, through an address you verify separately, whether they really sent the file.'
    }),
    {
      id: 'brand_sender_mismatch',
      name: 'Sender does not match the claimed organisation',
      category: 'Sender identity',
      weight: 20,
      severity: 'High',
      why: 'The display name claims to be a well-known organisation, but the actual address belongs to a different domain. Display names are free to type; the address is much harder to fake.',
      benign: 'Real companies sometimes send through a genuine mailing partner, but that partner is normally a recognised domain, not a lookalike.',
      action: 'Compare the address with the domain you normally receive mail from, and contact the organisation using details you look up yourself.',
      test: function (c) {
        if (!c.from || !c.fromName) return null;
        var claimed = findBrandInText(c.fromName, 3);
        var mismatched = [];
        for (var i = 0; i < claimed.length; i++) {
          if (!isOfficialHost(c.from.domain, claimed[i])) mismatched.push(claimed[i]);
        }
        if (!mismatched.length) return null;
        return {
          evidence: mismatched.map(function (b) {
            return 'Claims to be ' + b.label + ' but was sent from "' + c.from.domain + '" (real ' + b.label + ' mail comes from ' + b.domains.join(' or ') + ')';
          })
        };
      }
    },
    {
      id: 'free_mail_sender',
      name: 'Business or official message sent from a free mailbox',
      category: 'Sender identity',
      weight: 10,
      severity: 'Low',
      why: 'A message that presents itself as a company, IT team or official service but comes from a public mailbox is unusual, because organisations normally send from their own domain.',
      benign: 'Small businesses, contractors and genuine individuals do use free mailboxes for real work.',
      action: 'Verify the person or organisation independently before acting on the request.',
      test: function (c) {
        if (!c.from || FREE_MAIL_DOMAINS.indexOf(c.from.domain) < 0) return null;
        var claims = findBrandInText(c.fromName + ' ' + c.subject, 3);
        var roleLike = findTerms(c.fromName + ' ' + c.subject, ['helpdesk', 'help desk', 'support', 'security', 'billing', 'accounts', 'invoice', 'payroll', 'official', 'team', 'department']);
        if (!claims.length && !roleLike.length) return null;
        return { evidence: ['Sends from the public mailbox "' + c.from.domain + '" while presenting itself as an official or business sender'] };
      }
    },
    {
      id: 'reply_to_mismatch',
      name: 'Reply-To address differs from the sender',
      category: 'Sender identity',
      weight: 20,
      severity: 'High',
      why: 'If replies go to a different address than the one shown in the From line, someone is trying to redirect your conversation. This is a hallmark of business email compromise.',
      benign: 'Call centres and ticketing systems sometimes use a different reply address on purpose, and mailing lists do this by design.',
      action: 'Do not reply to the message. Contact the person or organisation using an address you already have.',
      test: function (c) {
        if (!c.from || !c.replyTo) return null;
        if (c.from.domain === c.replyTo.domain) return null;
        if (registeredDomain(c.from.domain) === registeredDomain(c.replyTo.domain)) {
          return { evidence: ['Replies go to "' + c.replyTo.address + '" instead of the displayed sender "' + c.from.address + '" (same organisation, different sub-domain)'] };
        }
        return { evidence: ['Displayed sender is "' + c.from.address + '" but replies are redirected to "' + c.replyTo.address + '"'] };
      }
    },
    {
      id: 'return_path_mismatch',
      name: 'Return-Path does not match the sender',
      category: 'Sender identity',
      weight: 8,
      severity: 'Low',
      why: 'The Return-Path is where bounce messages go. Using an unrelated domain there is typical of bulk sending tools, including phishing kits.',
      benign: 'Mailing platforms and marketing tools routinely use their own bounce domain, so this alone is weak evidence.',
      action: 'Combine it with the other findings rather than treating it as proof.',
      test: function (c) {
        if (!c.from || !c.returnPath) return null;
        if (registeredDomain(c.from.domain) === registeredDomain(c.returnPath.domain)) return null;
        return { evidence: ['Return-Path is "' + c.returnPath.address + '" while the visible sender is "' + c.from.address + '"'] };
      }
    },
    {
      id: 'crude_mailer',
      name: 'Sent by a simple web script mailer',
      category: 'Sender identity',
      weight: 8,
      severity: 'Low',
      why: 'Headers showing a PHP mail library or an empty Return-Path suggest the message was sent by a quick script rather than a professional mail platform - common in low-effort campaigns.',
      benign: 'Plenty of legitimate websites, contact forms and small businesses also send mail this way.',
      action: 'Treat it as supporting context only, not as proof of anything.',
      test: function (c) {
        var hits = [];
        var mailer = /x-mailer:\s*([^\r\n]+)/i.exec(c.raw) || /x-php-originating-script:\s*([^\r\n]+)/i.exec(c.raw);
        if (/x-mailer:\s*(phpmailer|swift ?mailer|sendmail|mail\()/i.test(c.raw)) hits.push('X-Mailer header identifies "' + clip(mailer && mailer[1], 60) + '"');
        if (/x-php-originating-script/i.test(c.raw)) hits.push('X-PHP-Originating-Script header is present');
        if (/^\s*return-path:\s*<>\s*$/mi.test(c.raw)) hits.push('Return-Path is empty (<>)');
        if (!hits.length) return null;
        return { evidence: hits };
      }
    },
    {
      id: 'spf_fail',
      name: 'SPF check failed',
      category: 'Email authentication',
      weight: 20,
      severity: 'High',
      why: 'SPF records say which servers may send mail for a domain. A failing result means the message came from a server the claimed domain does not authorise.',
      benign: 'Forwarded mail often fails SPF, and genuinely misconfigured senders exist. This is strong evidence of a problem, not proof of intent.',
      action: 'Treat the sender as unverified and contact the organisation through details you look up yourself.',
      test: function (c) {
        var m = /spf\s*=\s*(fail|softfail|permerror|temperror)/i.exec(c.authText) || /received-spf:\s*(fail|softfail|permerror|temperror)/i.exec(c.authText);
        if (!m) return null;
        var verdict = lower(m[1]);
        var note = verdict === 'softfail' ? 'softfail, which means "probably not allowed to send"' : verdict;
        return { evidence: ['Authentication-Results / Received-SPF reports SPF ' + note + ' (' + clip(m[0], 80) + ')'] };
      }
    },
    {
      id: 'dkim_fail',
      name: 'DKIM signature check failed',
      category: 'Email authentication',
      weight: 15,
      severity: 'Medium',
      why: 'DKIM is a cryptographic signature that shows a message was not altered in transit and really came from the signing domain. A failure means the signature could not be verified.',
      benign: 'Legitimate mail sometimes fails DKIM because of mailing-list rewriting or a broken key. Bulk mail also fairly often has no signature at all.',
      action: 'Combine it with the other findings, and prefer to verify through the official website or app.',
      test: function (c) {
        var m = /dkim\s*=\s*(fail|permerror|temperror)/i.exec(c.authText);
        if (!m) return null;
        return { evidence: ['Authentication-Results reports DKIM ' + lower(m[1]) + ' (' + clip(m[0], 80) + ')'] };
      }
    },
    {
      id: 'dmarc_fail',
      name: 'DMARC check failed',
      category: 'Email authentication',
      weight: 25,
      severity: 'High',
      why: 'DMARC is the policy that ties SPF and DKIM to the visible From address. A failure means the mail failed the domain owner\'s own authentication policy.',
      benign: 'Strong mailing lists and some forwarders break DMARC legitimately. Otherwise, failures on brand mail usually mean the sender is not the brand.',
      action: 'Do not trust the display name. Verify the request using the organisation\'s official app or website.',
      test: function (c) {
        var m = /dmarc\s*=\s*(fail|quarantine|reject)/i.exec(c.authText);
        if (!m) return null;
        return { evidence: ['Authentication-Results reports DMARC ' + lower(m[1]) + ' (' + clip(m[0], 80) + ')'] };
      }
    },
    {
      id: 'no_auth_results',
      name: 'No SPF, DKIM or DMARC results available',
      category: 'Email authentication',
      weight: 0,
      severity: 'Informational',
      why: 'Authentication results are only present when the raw headers are included. Without them this tool cannot comment on sender authentication at all.',
      benign: 'Most email clients hide these headers by default, so their absence says nothing about the message.',
      action: 'For a full check, paste the raw headers as well as the message body.',
      test: function (c) {
        if (!c.headerDetected || c.hasAuthResults) return null;
        return { evidence: ['Headers were provided but contain no Authentication-Results or Received-SPF line, so those checks were skipped'] };
      }
    },
    {
      id: 'no_headers',
      name: 'Message body only - no headers supplied',
      category: 'Email authentication',
      weight: 0,
      severity: 'Informational',
      why: 'Without the raw headers, sender-address, Reply-To and authentication checks cannot run. The body text was still fully analysed.',
      benign: 'Pasting only the visible message is a perfectly normal thing to do.',
      action: 'If you can, paste the full headers as well - in Outlook choose File, Properties, Internet headers; in Gmail choose the three dots and "Show original".',
      test: function (c) {
        if (c.headerDetected) return null;
        return { evidence: ['No header block was detected, so identity and authentication checks were skipped'] };
      }
    },
    urlRule({
      id: 'url_raw_ip',
      name: 'Link points at a raw IP address',
      category: 'Suspicious links',
      weight: 20,
      severity: 'High',
      why: 'Legitimate services publish normal domain names. A login page reached by a bare numeric address is a strong sign it does not belong to the organisation it pretends to be.',
      benign: 'Internal test systems, home routers, printers and lab equipment are genuinely reached by IP address.',
      action: 'Do not open it. Open the real service from your own bookmark or by typing its address.',
      match: function (u) {
        if (!u.isIp) return null;
        var label = u.isDocumentationIp ? 'a documentation-range address (never a real host)' : 'a raw IP address';
        return 'The host is ' + label + (u.port ? ' on port ' + u.port : '');
      }
    }),
    urlRule({
      id: 'url_shortener',
      name: 'Shortened link hides the destination',
      category: 'Suspicious links',
      weight: 15,
      severity: 'Medium',
      why: 'A shortened link shows none of the real destination, so you cannot tell who will receive anything you type. This is why they are popular in mass phishing.',
      benign: 'Businesses, charities and social media teams use short links legitimately for campaigns and tracking.',
      action: 'Expand or preview the link without visiting it, or find the page through the organisation\'s official site instead.',
      match: function (u) {
        if (SHORTENERS.indexOf(u.registered) < 0) return null;
        return 'It uses the shortening service "' + u.registered + '", so the true destination is hidden';
      }
    }),
    urlRule({
      id: 'url_punycode',
      name: 'Link uses lookalike (punycode) characters',
      category: 'Suspicious links',
      weight: 20,
      severity: 'High',
      why: 'Punycode lets a domain display characters that look like Latin letters but are not. It is a common way to make a fake domain look like a real brand.',
      benign: 'Internationalised domain names are a normal, legitimate technology for non-Latin languages.',
      action: 'Do not trust the visible spelling of the address. Reach the service from your own bookmark instead.',
      match: function (u) {
        if (!/(^|\.)xn--/.test(u.host)) return null;
        return 'The host "' + u.host + '" uses an encoded (punycode) form that can imitate another brand';
      }
    }),
    urlRule({
      id: 'url_userinfo_trick',
      name: 'Link hides its real destination with an @ symbol',
      category: 'Suspicious links',
      weight: 20,
      severity: 'High',
      why: 'In "https://real-looking-name@actual-host/", everything before the @ is ignored by the browser. It is used to make a link look like one site while going to another.',
      benign: 'Some legitimate systems embed a username in a URL, but it is rare in email links to customers.',
      action: 'Read only the part AFTER the @ sign. That is where the link really goes.',
      match: function (u) {
        if (!u.userinfo) return null;
        return 'The address contains "' + u.userinfo + '@" before the real host "' + u.host + '"';
      }
    }),
    urlRule({
      id: 'url_brand_lookalike',
      name: 'Domain imitates a well-known brand',
      category: 'Suspicious links',
      weight: 20,
      severity: 'High',
      why: 'The link address contains a well-known name but is not that organisation\'s actual domain. Attackers build domains like this so the address looks convincing at a glance.',
      benign: 'Review sites, resellers and news articles contain brand names in their addresses without any bad intent.',
      action: 'Check the exact spelling of the domain - especially the part immediately before the first single slash.',
      match: function (u) {
        var brands = findBrandInHost(u.host);
        var bad = [];
        for (var i = 0; i < brands.length; i++) {
          if (!isOfficialHost(u.host, brands[i])) bad.push(brands[i]);
        }
        if (!bad.length) return null;
        return 'The host "' + u.host + '" mentions ' + bad[0].label + ' but is not an official domain (' + bad[0].domains.join(' or ') + ')';
      }
    }),
    urlRule({
      id: 'url_risky_tld',
      name: 'Domain uses a high-abuse extension',
      category: 'Suspicious links',
      weight: 12,
      severity: 'Medium',
      why: 'Some domain extensions are heavily used for short-lived scam sites because they are cheap and easy to register in bulk. This is a weak signal on its own.',
      benign: 'Real businesses do use these extensions. Many are perfectly ordinary domains.',
      action: 'Treat it as one piece of evidence, not a verdict. Check the full address carefully.',
      match: function (u) {
        var parts = u.host.split('.');
        var tld = parts[parts.length - 1];
        if (RISKY_TLDS.indexOf(tld) < 0) return null;
        return 'The address ends in ".' + tld + '", an extension with a high reported abuse rate';
      }
    }),
    urlRule({
      id: 'url_long_or_deep',
      name: 'Unusually long or deeply nested address',
      category: 'Suspicious links',
      weight: 8,
      severity: 'Low',
      why: 'Long addresses with many sub-domains, folders and parameters are used to push the real domain out of view or to hide tracking and tokens.',
      benign: 'Newsletters, e-commerce and analytics platforms create long tracked links all the time.',
      action: 'Look only at the domain between "https://" and the first single "/" - that is the part that matters.',
      match: function (u) {
        var segments = u.path.split('/').filter(function (s) { return s.length > 0; }).length;
        if (u.url.length > 110 || u.labels >= 6 || segments >= 5) {
          return 'The address is ' + u.url.length + ' characters long with ' + u.labels + ' domain labels and ' + segments + ' path section(s)';
        }
        return null;
      }
    }),
    urlRule({
      id: 'url_insecure_http',
      name: 'Login-style link uses unencrypted http',
      category: 'Suspicious links',
      weight: 10,
      severity: 'Medium',
      why: 'Anything you type into an http:// page travels unencrypted, so it can be read or changed in transit. No serious service asks for credentials over plain http.',
      benign: 'Some old internal systems and intranet pages still run on plain http. A bare http link to a blog is harmless.',
      action: 'Never type a password into a page that is not https:// with a valid certificate for the expected domain.',
      match: function (u) {
        if (u.scheme !== 'http') return null;
        if (!/login|log-in|signin|sign-in|verify|password|account|secure|auth|portal|billing|payment|update/i.test(u.url)) return null;
        return 'It uses unencrypted http:// for what looks like an account page';
      }
    }),
    urlRule({
      id: 'url_unusual_port',
      name: 'Link specifies an unusual port number',
      category: 'Suspicious links',
      weight: 8,
      severity: 'Low',
      why: 'Public websites serve https on port 443. Seeing an explicit port such as :8080 or :8443 in a customer-facing link suggests a temporary or self-hosted server.',
      benign: 'Test environments, home labs and internal services genuinely run on non-standard ports.',
      action: 'Be cautious - a real customer portal almost never needs a port number in the address.',
      match: function (u) {
        if (!u.port || u.port === '80' || u.port === '443') return null;
        return 'The address uses port ' + u.port;
      }
    }),
    {
      id: 'misleading_link_text',
      name: 'Link text does not match the real destination',
      category: 'Suspicious links',
      weight: 25,
      severity: 'High',
      why: 'When the words you see are a web address but the link really points somewhere else, the message is deliberately deceiving you. This cannot be seen without inspecting the link.',
      benign: 'Perfectly honest marketing emails sometimes display a friendly name while linking through a tracking domain.',
      action: 'Hover the link (without clicking) and read the real address shown in the status bar.',
      test: function (c) {
        var hits = [];
        for (var i = 0; i < c.anchors.length && hits.length < 6; i++) {
          var a = c.anchors[i];
          if (!a.hrefHost || !a.textHost) continue;
          if (a.textRegistered === a.hrefRegistered) continue;
          hits.push('Link shows "' + clip(a.text, 60) + '" but actually goes to ' + defang(a.href));
        }
        if (!hits.length) return null;
        return { evidence: hits };
      }
    },
    {
      id: 'executable_attachment',
      name: 'Executable or program attachment',
      category: 'Attachments',
      weight: 25,
      severity: 'High',
      why: 'Attachments ending in .exe, .scr, .js, .lnk and similar are programs. Email is one of the main ways malware is delivered.',
      benign: 'IT teams do occasionally send installers by email, but they usually use a managed software portal or a file-sharing link instead.',
      action: 'Do not open it. Redeploy from a trusted source or ask your IT team through a channel you trust.',
      test: function (c) {
        var hits = [];
        for (var i = 0; i < c.attachments.names.length; i++) {
          var a = c.attachments.names[i];
          var last = a.extensions.length ? a.extensions[a.extensions.length - 1] : '';
          if (last && inList(DANGEROUS_FILES.executable, last)) hits.push('"' + a.name + '" is a program file (.' + last + ')');
        }
        if (!hits.length) return null;
        return { evidence: hits };
      }
    },
    {
      id: 'double_extension',
      name: 'Double file extension hides a program',
      category: 'Attachments',
      weight: 25,
      severity: 'High',
      why: 'A name such as "invoice.pdf.exe" looks like a document in a list of files, but the part that decides what runs is the last extension. This is a deliberate deception.',
      benign: 'Very occasionally a genuine archive or export tool produces a name like this by accident.',
      action: 'Do not open it, and tell your IT or security team about the message.',
      test: function (c) {
        var hits = [];
        for (var i = 0; i < c.attachments.names.length; i++) {
          var a = c.attachments.names[i];
          var exts = a.extensions;
          if (exts.length < 2) continue;
          var last = exts[exts.length - 1];
          var previous = exts[exts.length - 2];
          if (inList(DANGEROUS_FILES.executable, last) && inList(LURE_EXTENSIONS, previous)) {
            hits.push('"' + a.name + '" pretends to be a .' + previous + ' file but is actually a .' + last + ' program');
          }
        }
        if (!hits.length) return null;
        return { evidence: hits };
      }
    },
    {
      id: 'macro_attachment',
      name: 'Macro-enabled or legacy Office attachment',
      category: 'Attachments',
      weight: 20,
      severity: 'High',
      why: 'Files such as .docm and .xlsm can carry macros, which are small programs. Malware is often delivered this way because the document looks harmless.',
      benign: 'Many organisations do use macro-enabled spreadsheets for real work, and old .doc or .xls files are still common.',
      action: 'Do not enable macros. Open the file in a protected view or ask the sender to confirm through a verified channel.',
      test: function (c) {
        var hits = [];
        for (var i = 0; i < c.attachments.names.length; i++) {
          var a = c.attachments.names[i];
          var last = a.extensions.length ? a.extensions[a.extensions.length - 1] : '';
          if (last === 'docm' || last === 'xlsm' || last === 'pptm' || last === 'dotm' || last === 'xltm' || last === 'xlam') {
            hits.push('"' + a.name + '" is a macro-enabled Office file (.' + last + ')');
          } else if (last === 'doc' || last === 'xls' || last === 'ppt') {
            hits.push('"' + a.name + '" uses the legacy .' + last + ' format, which can carry macros');
          }
        }
        if (!hits.length) return null;
        return { evidence: hits };
      }
    },
    {
      id: 'web_attachment',
      name: 'Web page attached instead of linked',
      category: 'Attachments',
      weight: 15,
      severity: 'Medium',
      why: 'An attached .html or .svg file opens in your browser and can look like a real sign-in page while it is really a saved copy controlled by the sender. It also works with no internet access.',
      benign: 'People do send saved web pages, reports and single-page snapshots as attachments.',
      action: 'Do not open it. Reach the service through the official website or app instead.',
      test: function (c) {
        var hits = [];
        for (var i = 0; i < c.attachments.names.length; i++) {
          var a = c.attachments.names[i];
          var last = a.extensions.length ? a.extensions[a.extensions.length - 1] : '';
          if (inList(DANGEROUS_FILES.web, last)) hits.push('"' + a.name + '" is a web page file (.' + last + ') that could imitate a login form');
        }
        if (!hits.length) return null;
        return { evidence: hits };
      }
    },
    {
      id: 'archive_attachment',
      name: 'Archive attachment',
      category: 'Attachments',
      weight: 10,
      severity: 'Low',
      why: 'Compressed archives are used to get past mail filters and to protect a program with a password, so the contents cannot be scanned.',
      benign: 'Archives are used constantly in ordinary business for documents, logs and photos.',
      action: 'Check what is inside before opening, and treat any password-protected archive in an unexpected email as suspicious.',
      test: function (c) {
        var hits = [];
        for (var i = 0; i < c.attachments.names.length; i++) {
          var a = c.attachments.names[i];
          var last = a.extensions.length ? a.extensions[a.extensions.length - 1] : '';
          if (inList(DANGEROUS_FILES.archive, last)) hits.push('"' + a.name + '" is a compressed archive (.' + last + ')');
        }
        if (!hits.length) return null;
        return { evidence: hits };
      }
    },
    {
      id: 'rtl_override_filename',
      name: 'Attachment name uses a text-direction trick',
      category: 'Attachments',
      weight: 20,
      severity: 'High',
      why: 'A hidden "right-to-left override" character reverses how the rest of the file name is displayed, so "invoice" followed by a hidden character and "gnp.exe" can appear on screen as "invoiceexe.png".',
      benign: 'Some languages legitimately need right-to-left characters, though not normally inside an English file name.',
      action: 'Do not open the file. Ask the sender to confirm what it contains through a verified channel.',
      test: function (c) {
        var hits = [];
        for (var i = 0; i < c.attachments.names.length; i++) {
          var a = c.attachments.names[i];
          if (/[\u202a-\u202e\u2066-\u2069]/.test(a.name)) {
            hits.push('"' + a.name.replace(/[\u202a-\u202e\u2066-\u2069]/g, '[hidden direction character]') + '" contains a hidden direction character');
          }
        }
        if (!hits.length) return null;
        return { evidence: hits };
      }
    },
    {
      id: 'unusual_attachment_name',
      name: 'Unusual attachment file name',
      category: 'Attachments',
      weight: 5,
      severity: 'Low',
      why: 'Very long names, or names mixing alphabets, are used to push the real extension off the screen so you only see the harmless-looking part.',
      benign: 'Long file names are common in business, and non-English alphabets are completely normal in many countries.',
      action: 'Check the very end of the file name, not the beginning, before opening anything.',
      test: function (c) {
        var hits = [];
        for (var i = 0; i < c.attachments.names.length; i++) {
          var a = c.attachments.names[i];
          if (a.name.length > 80) hits.push('The name is unusually long (' + a.name.length + ' characters): "' + clip(a.name, 50) + '"');
          else if (/[^\u0000-\u007f]/.test(a.name)) hits.push('The name contains non-English characters: "' + clip(a.name, 50) + '"');
        }
        if (!hits.length) return null;
        return { evidence: hits };
      }
    },
    {
      id: 'hidden_html_text',
      name: 'Text hidden inside the message',
      category: 'Tricks and obfuscation',
      weight: 12,
      severity: 'Medium',
      why: 'Text can be hidden using white-on-white colour, zero font size or display:none. In phishing this hides content from spam filters or from the reader\'s eye while still being present in the message.',
      benign: 'Real marketing emails use hidden preview text legitimately to control what is shown in the inbox list.',
      action: 'Read the message as plain text if you can - many mail clients offer a "show original" or plain-text view.',
      test: function (c) {
        if (!c.hasHtml) return null;
        var hits = [];
        if (/color\s*:\s*(#fff(fff)?|white|rgba\(\s*255\s*,\s*255\s*,\s*255)/i.test(c.body)) hits.push('Some text is coloured white, which makes it invisible on the usual white background');
        if (/font-size\s*:\s*(0|0px|1px)/i.test(c.body)) hits.push('Some text has a zero or near-zero font size');
        if (/display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0(\.0*)?[;\s"]/i.test(c.body)) hits.push('Some text is set to display:none, visibility:hidden or opacity:0');
        if (!hits.length) return null;
        return { evidence: hits };
      }
    },
    {
      id: 'homoglyph_script',
      name: 'Mixed alphabets inside the message',
      category: 'Tricks and obfuscation',
      weight: 12,
      severity: 'Medium',
      why: 'Letters copied from another alphabet can look identical to English ones. A few foreign letters among English text can be an attempt to make a fake domain or address look right.',
      benign: 'Emails written in Russian, Ukrainian, Bulgarian and other languages use these characters normally, and a signature may mix alphabets.',
      action: 'Do not copy a domain or address out of the message. Type it yourself or use a bookmark.',
      test: function (c) {
        var text = c.searchText;
        var cyrillic = (text.match(/[\u0400-\u04ff]/g) || []).length;
        var latin = (text.match(/[A-Za-z]/g) || []).length;
        if (cyrillic === 0) return null;
        if (cyrillic < 4) return { evidence: ['Only a few Cyrillic characters (' + cyrillic + ') appear in an otherwise English message'] };
        if (latin > 0 && cyrillic / (cyrillic + latin) < 0.15) {
          return { evidence: ['The message mixes ' + cyrillic + ' Cyrillic characters with ' + latin + ' Latin letters, which can be used to imitate a name'] };
        }
        return null;
      }
    },
    {
      id: 'zero_width_chars',
      name: 'Invisible characters in the text',
      category: 'Tricks and obfuscation',
      weight: 8,
      severity: 'Low',
      why: 'Zero-width characters are invisible but they break up words, so "microsoft" written with an invisible separator no longer matches a simple filter or keyword search.',
      benign: 'Copying text from web pages and PDFs sometimes carries these characters along with no bad intent.',
      action: 'Treat any hidden character tricks as a deliberate attempt to avoid detection.',
      test: function (c) {
        var count = (c.searchText.match(/[\u200b\u200c\u200d\u2060\ufeff]/g) || []).length;
        if (!count) return null;
        return { evidence: ['The message contains ' + count + ' invisible zero-width character(s)'] };
      }
    }
  ];

  /* Helper for the link-based rules above. It is declared after the array,
   * but JavaScript function declarations are hoisted - they exist before any
   * code in this scope runs - so calling it above is safe. */
  function urlRule(spec) {
    return {
      id: spec.id,
      name: spec.name,
      category: spec.category,
      weight: spec.weight,
      severity: spec.severity,
      why: spec.why,
      benign: spec.benign,
      action: spec.action,
      test: function (c) {
        if (!c.urls.length) return null;
        var hits = [];
        for (var i = 0; i < c.urls.length && hits.length < 40; i++) {
          var detail = spec.match(c.urls[i], c);
          if (detail) hits.push({ url: c.urls[i], detail: detail });
        }
        if (!hits.length) return null;
        var shown = hits.slice(0, 4);
        var evidence = shown.map(function (h) { return defang(h.url.url) + ' - ' + h.detail; });
        if (hits.length > shown.length) evidence.push((hits.length - shown.length) + ' more link(s) matched the same pattern');
        return { evidence: evidence };
      }
    };
  }

  /* ------------------------------------------------------------------ *
   * 7. Score, classification and advice
   *    The score is a plain sum of fixed rule weights, capped at 100. It is
   *    a triage aid, not a probability that the email is malicious.
   * ------------------------------------------------------------------ */

  var BANDS = [
    { min: 0, max: 0, label: 'No Warning Signs Detected', level: 'none' },
    { min: 1, max: 19, label: 'Low Risk', level: 'low' },
    { min: 20, max: 49, label: 'Suspicious', level: 'medium' },
    { min: 50, max: 100, label: 'High Risk', level: 'high' }
  ];

  var BAND_MEANING = {
    none: 'None of the checks in this tool matched. That does not prove the message is safe - it only means no known warning sign was present.',
    low: 'A small number of minor warning signs matched. Most such messages are genuine, but it is still worth confirming the sender before you act on it.',
    medium: 'Several warning signs matched. Treat the message with caution and verify it through a channel you trust before you do anything.',
    high: 'Multiple strong warning signs matched. Treat this message as hostile: do not click, do not open attachments, and report it.'
  };

  function classify(score) {
    for (var i = 0; i < BANDS.length; i++) {
      if (score >= BANDS[i].min && score <= BANDS[i].max) return BANDS[i];
    }
    return BANDS[BANDS.length - 1];
  }

  var BASE_RECOMMENDATIONS = [
    'Do not click links or open attachments in this message - not even to "test" whether they are real.',
    'Verify the request through something you already trust: the organisation\'s official website or app, or a phone number you look up yourself. Never use the contact details inside the message.',
    'If you have already entered a password or a code, change that password now on the official website and turn on multi-factor authentication.',
    'Report the message (most mail providers and clients have a "report phishing" option) and then delete it.'
  ];

  function buildRecommendations(findings) {
    var out = [], seen = Object.create(null);
    function push(text) {
      var key = lower(text);
      if (!text || seen[key]) return;
      seen[key] = 1;
      out.push(text);
    }
    for (var i = 0; i < BASE_RECOMMENDATIONS.length; i++) push(BASE_RECOMMENDATIONS[i]);
    for (var j = 0; j < findings.length; j++) {
      if (findings[j].weight > 0) push(findings[j].action);
    }
    return out.slice(0, 9);
  }

  function authOutcome(ctx) {
    function pick(re) {
      var m = re.exec(ctx.authText);
      return m ? lower(m[1]) : 'not available';
    }
    return {
      spf: pick(/spf\s*=\s*(pass|fail|softfail|neutral|none|permerror|temperror)/i),
      dkim: pick(/dkim\s*=\s*(pass|fail|none|neutral|permerror|temperror|policy)/i),
      dmarc: pick(/dmarc\s*=\s*(pass|fail|none|quarantine|reject)/i)
    };
  }

  function summaryOf(ctx) {
    var links = [];
    for (var i = 0; i < ctx.urls.length && i < 25; i++) links.push(defang(ctx.urls[i].url));
    var attachments = [];
    for (var j = 0; j < ctx.attachments.names.length; j++) attachments.push(ctx.attachments.names[j].name);
    return {
      headerDetected: ctx.headerDetected,
      hasHtml: ctx.hasHtml,
      subject: clip(ctx.subject, 200),
      fromName: clip(ctx.fromName, 120),
      fromAddress: ctx.from ? ctx.from.address : '',
      replyToAddress: ctx.replyTo ? ctx.replyTo.address : '',
      returnPathAddress: ctx.returnPath ? ctx.returnPath.address : '',
      linkCount: ctx.urls.length,
      links: links,
      attachmentCount: ctx.attachments.names.length,
      attachments: attachments,
      hasAttachmentHeader: ctx.attachments.hasAttachmentHeader,
      auth: authOutcome(ctx)
    };
  }

  /* Main entry point: give it text, get back a fully explained report. */
  function analyse(rawInput) {
    var ctx = parseEmail(rawInput);
    var findings = [], checks = [];
    var order = { High: 0, Medium: 1, Low: 2, Informational: 3 };

    for (var i = 0; i < RULES.length; i++) {
      var rule = RULES[i];
      var result = null;
      try {
        result = rule.test(ctx);
      } catch (e) {
        /* A single broken rule must never break the page. */
        result = null;
      }
      checks.push({
        id: rule.id,
        name: rule.name,
        category: rule.category,
        weight: rule.weight,
        severity: rule.severity,
        triggered: !!result
      });
      if (result) {
        findings.push({
          id: rule.id,
          name: rule.name,
          category: rule.category,
          weight: rule.weight,
          severity: rule.severity,
          evidence: result.evidence || [],
          why: rule.why,
          benign: rule.benign,
          action: rule.action
        });
      }
    }

    var sum = 0;
    for (var k = 0; k < findings.length; k++) sum += findings[k].weight;
    var score = Math.min(100, sum);
    var band = classify(score);

    findings.sort(function (a, b) {
      if (order[a.severity] !== order[b.severity]) return order[a.severity] - order[b.severity];
      return b.weight - a.weight;
    });

    var triggered = 0;
    for (var c = 0; c < checks.length; c++) if (checks[c].triggered) triggered++;

    return {
      version: '1.0',
      score: score,
      rawScore: sum,
      capped: sum > 100,
      band: band,
      bandMeaning: BAND_MEANING[band.level],
      findings: findings,
      checks: checks,
      checksTriggered: triggered,
      checksTotal: checks.length,
      recommendations: buildRecommendations(findings),
      summary: summaryOf(ctx)
    };
  }

  /* ------------------------------------------------------------------ *
   * 8. Public interface
   * ------------------------------------------------------------------ */

  var api = {
    analyse: analyse,
    parseEmail: parseEmail,
    defang: defang,
    refang: refang,
    htmlToText: htmlToText,
    bands: BANDS,
    ruleCatalogue: function () {
      return RULES.map(function (r) {
        return { id: r.id, name: r.name, category: r.category, weight: r.weight, severity: r.severity, why: r.why, benign: r.benign, action: r.action };
      });
    },
    maxScore: RULES.reduce(function (t, r) { return t + r.weight; }, 0)
  };

  if (typeof module === 'object' && module.exports) module.exports = api;
  if (root && typeof root === 'object') root.PhishingEngine = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);