# Phishing Email Analyser

An educational, **browser-only** tool that looks at a suspicious email and explains the warning signs it can find: pressure language, credential and payment requests, lookalike links, dangerous attachments, and email authentication failures.

- **Nothing is uploaded.** The analysis runs inside the visitor's browser. There is no server, no database, no AI service, no API key and no analytics.
- **Nothing is installed.** It is a static website made of plain HTML, CSS and JavaScript. No frameworks, no build step, no dependencies.
- **The score is explainable.** Every check has a published point value, and the interface shows exactly which checks matched, why each one matters, an innocent explanation to consider, and what to do next.

This tool is a **triage aid**. It never claims that an email is malicious, and it never proves that an email is safe.

---

## 1. What it does

Paste an email (the message body, or the body **plus the raw headers**) and click **Analyse Email**. You get back:

| Output | What it means |
|---|---|
| **Risk score, 0-100** | The points of every matched check added together, capped at 100 |
| **Classification** | No Warning Signs Detected, Low Risk, Suspicious or High Risk |
| **Warning signs found** | One card per matched check: the evidence, why it matters, a possible innocent explanation, and what to do |
| **What to do next** | Practical steps tailored to the findings that matched |
| **Every check performed** | The complete list of all 44 checks, including the ones that found nothing |

## 2. Quick start (Windows)

1. Download or copy the `phishing-email-analyser` folder.
2. Double-click **`index.html`**.

That is the whole installation. The page opens in your default browser and works offline. There is no installer, no command-line step, and no internet connection needed after the first load.

To try it immediately, click any button under **"Try a fictional example"** - those examples are built into the page, so nothing needs uploading.

### Publishing it for free (optional)

Because it is a static site, GitHub Pages (or Netlify, Cloudflare Pages, or any web host) will serve it as-is:

1. Put the folder in a GitHub repository.
2. Go to **Settings → Pages**, choose **Deploy from a branch**, pick your branch and the folder containing `index.html`.
3. Share the URL it gives you.

## 3. How to give it the best input

The body text alone is enough for most checks. To also get the **sender identity** and **SPF / DKIM / DMARC** checks, include the raw headers - the technical block at the top of the message.

- **Outlook (desktop):** open the message → **File** → **Properties** → copy **Internet headers**.
- **Outlook on the web:** open the message → **More actions** → **View** → **View message source**.
- **Gmail:** open the message → the three dots next to Reply → **Show original** → copy the text.

Paste the headers first, then the body underneath. If you paste the body only, the tool says clearly that the identity checks were skipped rather than pretending they ran.

## 4. How the score works

The score is **simple addition of fixed weights**, capped at 100. There is no machine learning, no hidden arithmetic and no randomness, so the same email always produces the same result.

| Score | Classification | Meaning |
|---|---|---|
| 0 | No Warning Signs Detected | No check matched. This does **not** prove the email is safe. |
| 1-19 | Low Risk | A few minor signs. Confirm the sender before acting. |
| 20-49 | Suspicious | Several signs. Verify through a channel you trust. |
| 50-100 | High Risk | Multiple strong signs. Do not click, do not open attachments, report it. |

Because an obvious phishing email can match many checks at once, the raw total is shown in the results ("the matched checks added up to 210 points"), so you can see when the scale has been reached.

## 5. The checks and their point values

44 checks in five categories. The same table with live point values is inside the page (**The checks** section).

### Language and pressure

| Check | Points |
|---|---|
| Request for a verification or MFA code | +25 |
| Password request or password discussion | +25 |
| Payment, gift card or fee request | +25 |
| Request to change bank or payment details | +25 |
| Credential-harvesting language | +20 |
| Instructions to enable macros or active content | +20 |
| Threat of account closure or suspension | +20 |
| Pressure to keep the request secret | +15 |
| Impersonation of a team or support role | +12 |
| Unexpected invoice or payment demand | +12 |
| Executive or assistant impersonation tone | +12 |
| Urgency and pressure language | +10 |
| Impersonal or generic greeting | +5 |
| Recognised good-practice wording | 0 (reassurance only) |

### Sender identity

| Check | Points |
|---|---|
| Sender does not match the claimed organisation | +20 |
| Reply-To address differs from the sender | +20 |
| Business or official message sent from a free mailbox | +10 |
| Return-Path does not match the sender | +8 |
| Sent by a simple web script mailer | +8 |

### Email authentication (needs the raw headers)

| Check | Points |
|---|---|
| DMARC check failed | +25 |
| SPF check failed | +20 |
| DKIM signature check failed | +15 |
| No SPF, DKIM or DMARC results available | 0 (explains the gap) |
| Message body only - no headers supplied | 0 (explains the gap) |

### Suspicious links

| Check | Points |
|---|---|
| Link text does not match the real destination | +25 |
| Link points at a raw IP address | +20 |
| Link uses lookalike (punycode) characters | +20 |
| Link hides its real destination with an @ symbol | +20 |
| Domain imitates a well-known brand | +20 |
| Shortened link hides the destination | +15 |
| Domain uses a high-abuse extension | +12 |
| Login-style link uses unencrypted http | +10 |
| Unusually long or deeply nested address | +8 |
| Link specifies an unusual port number | +8 |

### Attachments and obfuscation

| Check | Points |
|---|---|
| Executable or program attachment | +25 |
| Double file extension hides a program | +25 |
| Macro-enabled or legacy Office attachment | +20 |
| Attachment name uses a text-direction trick | +20 |
| Web page attached instead of linked | +15 |
| Text hidden inside the message | +12 |
| Mixed alphabets inside the message | +12 |
| Archive attachment | +10 |
| Invisible characters in the text | +8 |
| Unusual attachment file name | +5 |

### Good practice the tool actively recognises

Some checks carry **0 points on purpose**. "Recognised good-practice wording" fires when a message explicitly says that no action is required and that the sender will never ask for a password. Real password-change confirmations use that wording, so they should not be pushed up the scale just for mentioning a password.

## 6. The built-in example emails

All seven examples are fictional. They use only reserved documentation domains (`example.com`, `example.org`, `.example`, `.invalid`) and documentation IP ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, defined in RFC 5737 for exactly this purpose). **No example contains a working link or a real malicious domain**, and links are written in a broken "defanged" form so they cannot be clicked in a browser.

| File | What it teaches | Expected result |
|---|---|---|
| `samples/01-obvious-phishing.txt` | Crude mass campaign: threats, password and MFA requests, an IP-address link, a disguised `.pdf.exe` program and a macro document | High Risk (100) |
| `samples/02-sophisticated-phishing.txt` | The hard case: correct grammar, no threats, no attachments, and authentication passes because the attacker owns a domain. Only the request itself and the off-domain link give it away | Suspicious (~42) |
| `samples/03-fake-microsoft-365.txt` | Brand impersonation, a shortened link whose visible text is a genuine Microsoft address, and a demand for a verification code | High Risk |
| `samples/04-fake-parcel-delivery.txt` | Courier-style fee fraud: lookalike courier domain, a small "handling fee", a 48-hour deadline and a request for a banking one-time code | High Risk |
| `samples/05-fake-invoice-bec.txt` | Business email compromise: no links at all, just polite urgency, secrecy, a change of bank details and a redirected Reply-To | High Risk |
| `samples/06-legitimate-email.txt` | An ordinary internal message | 0 - No Warning Signs Detected |
| `samples/07-legitimate-password-notice.txt` | A genuine password confirmation that mentions passwords. It contains reassuring wording, so it stays at 0 - the false-positive lesson | 0 - No Warning Signs Detected |

### How the example buttons work

Browsers block a page opened from disk from reading neighbouring files, so the examples are also baked into `samples/demo-emails.js` by a small script. That file is generated - do not edit it by hand. The real `.txt` files are the source of truth and are also meant to be uploaded or pasted.

## 7. Project files

```
phishing-email-analyser/
├── index.html                  the page (semantic HTML, CSP, ARIA live region)
├── styles.css                  the dark theme, responsive layout, print styles
├── engine.js                   all analysis logic - no DOM, no network, testable
├── app.js                      page behaviour and rendering - textContent only
├── README.md                   this file
├── samples/
│   ├── 01-obvious-phishing.txt ... 07-legitimate-password-notice.txt
│   └── demo-emails.js          GENERATED copy of the samples for the demo buttons
├── tools/
│   └── make-demo-data.js       regenerates demo-emails.js (optional, developer only)
└── tests/
    └── run-tests.js            212 automated checks (optional, developer only)
```

`engine.js` (the "brain") is deliberately separated from `app.js` (the "face") so the analysis can be tested automatically. Both are plain JavaScript - there is no build step.

## 8. Running the tests (optional)

The tests need Node.js, and only if you want to verify the logic yourself. They are **not** needed to use the tool.

```bash
cd phishing-email-analyser
node tests/run-tests.js
```

The suite covers:

- every sample email reaching its documented classification
- the score being exactly the sum of the finding weights, and capped at 100
- every check having a point value, a severity, an explanation, an innocent explanation and an action
- no check ever using the word "Critical"
- malformed input (empty, whitespace, null, binary, 400 KB of text) never crashing the analysis
- the same email always producing the same result
- rendering the real `app.js` in a fake DOM, including XSS payloads
- the source containing no `fetch`, `XMLHttpRequest`, `WebSocket`, storage, cookies or analytics
- the page carrying a Content Security Policy that blocks all outbound connections

## 9. Privacy architecture

The privacy claim is enforced by design, not by promise:

1. **No networking code exists.** There is no `fetch`, no `XMLHttpRequest`, no `WebSocket`, no `sendBeacon` and no third-party script, stylesheet, font or image. The tests fail if any of those are ever added.
2. **A Content Security Policy** in `index.html` tells the browser to refuse every outbound connection (`connect-src 'none'`), to load scripts only from the same folder, and to allow no forms.
3. **Nothing is stored.** No cookies, no `localStorage`, no `sessionStorage`, no IndexedDB. Close the tab and the pasted text is gone.
4. **Links are never fetched or opened.** They are displayed defanged (`hxxp://example[.]com`) so a click cannot work by accident.
5. **Verify it yourself:** open your browser's developer tools, go to the **Network** tab, analyse an email, and watch that no requests appear. Analysing a real email lists only the four local files that make up the page.

## 10. Security notes

- Pasted email text is treated as **untrusted input**. It is inserted into the page only with `textContent`, never with `innerHTML`, so HTML, scripts or event handlers inside an email are displayed as literal text.
- The test suite makes `innerHTML` a **throwing** property in its fake DOM, so any future accident becomes a failing test rather than a real vulnerability.
- Nothing from an email is evaluated, executed or interpreted as code.
- Each check has an error guard: if one check ever throws, it is skipped and the rest of the report still renders.

## 11. Limitations

Documented honestly, because knowing where a tool stops is part of using it well.

- It **cannot prove** an email is malicious, and it cannot detect every attack.
- It only sees text. Content hidden in an image, a QR code, a PDF or a web page is invisible to it.
- The SPF, DKIM, DMARC, Reply-To and Return-Path checks need the raw headers. Forwarded messages often carry misleading headers.
- Copying text out of a mail client can change formatting, break links, or drop header lines.
- Brand and lookalike detection covers the well-known organisations listed in `engine.js`, not every company in the world.
- Wording varies enormously between languages and cultures, so non-English messages match far fewer checks.
- Legitimate emails can score highly (invoices, delivery notices, genuine password confirmations) and well-crafted phishing can score low. Both are expected outcomes of a warning-sign tool.
- The wording lists are tuned to common business email patterns and are English-language.
- It is an educational aid. It is not an email security gateway and does not replace one.

## 12. Accessibility

- Semantic HTML with real headings, lists, tables and `scope` attributes.
- Every control is keyboard reachable, with a visible focus outline and a skip link.
- The result is announced through an `aria-live` region and focus moves to the results heading.
- Severity is never communicated by colour alone: each card carries the word High, Medium, Low or Informational.
- Contrast targets WCAG AA, `prefers-reduced-motion` is respected, and a print stylesheet is included.

## 13. Educational use and disclaimer

This project exists to teach how phishing emails are constructed and how a defender reasons about them. It is intended for study, classroom use, lab exercises and portfolio demonstrations.

- Use it on your own messages, or on synthetic examples such as the ones included here.
- **Never** click a suspicious link or open a suspicious attachment to test it - not on your own device and not on a work device.
- **Never** rely on this tool alone for a decision about a real message. Verify important messages independently, using an organisation's official website, application, or a contact detail you already have.
- Results identify warning signs. They do not prove malicious behaviour, and a low score does not prove an email is safe.

## 14. Possible future improvements

Not implemented, listed for direction only: highlighting the matched text inside the pasted message; a side-by-side view of two emails; an exportable report (print or text); QR-code extraction from images (needs OCR, which would break the "no dependencies" rule); language detection with localised wording packs; and a `.eml` file drop zone. Any addition must keep the "no server, no tracking" rule intact.