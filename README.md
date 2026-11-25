# 🎣 Phishing Email Analyzer

A Python tool that reads a saved email (`.eml` file) and flags the warning signs of **phishing**, the same first-pass triage a SOC analyst does when a user reports a suspicious email.

It uses only the Python standard library, so there's nothing to install.

## What it checks

| Check | What it catches | Why it matters |
|---|---|---|
| **Sender mismatch** | `From`, `Reply-To` and `Return-Path` use different domains | Attackers fake the From address but want your replies to reach **them** |
| **Display-name spoofing** | `"security@bank.example" <x@evil.top>` | Most email apps show only the name, so the fake address is all you see |
| **SPF / DKIM / DMARC** | Failed email authentication checks | A failure means the sender may be forged |
| **Mismatched links** | Link text says `bank.example` but goes somewhere else | The #1 phishing trick |
| **Raw IP links** | `http://203.0.113.50/login.php` | Real companies use domain names, not IP addresses |
| **Shortened links** | `bit.ly/...` | Hides where the link really goes |
| **Look-alike domains** | Punycode (`xn--`) domains such as `pаypal` with a Cyrillic "а" | They look identical to the real name |
| **Risky attachments** | `.exe`, `.js`, `.iso`, macro documents, double extensions like `invoice.pdf.exe` | Common ways malware is delivered |
| **Pressure language** | "urgent", "suspended", "within 24 hours" | Urgency makes people click without thinking |

Every finding adds to a **risk score** (HIGH = 3, MEDIUM = 2, LOW = 1):

| Score | Verdict |
|---|---|
| 8+ | 🔴 **LIKELY PHISHING:** don't click anything, report it |
| 4–7 | 🟠 **SUSPICIOUS:** verify with the sender another way |
| 0–3 | 🟢 **LOW RISK:** no major warning signs |

Links in the report are **defanged** (`hxxp://203[.]0[.]113[.]50`) so they can't be clicked by accident. This is standard practice in SOC reports.

## Example output

```
===== Phishing Email Analyzer =====
From        : "security@mapletrust.example" <alerts@mapletrust-secure.top>
Reply-To    : verify-team@account-help.example
Subject     : URGENT: Your Maple Trust account has been suspended
Auth checks : SPF=fail, DKIM=none, DMARC=fail
Links       : 2    Attachments: 1

[HIGH  ] Replies go to a different domain: From is 'mapletrust-secure.top' but Reply-To is 'account-help.example'
[HIGH  ] Display name shows 'security@mapletrust.example' but the real sender is 'mapletrust-secure.top'
[HIGH  ] SPF check: fail (sender may be forged)
[HIGH  ] DMARC check: fail (sender may be forged)
[HIGH  ] Link text shows 'www.mapletrust.example' but really goes to hxxp://203[.]0[.]113[.]50/mapletrust/login[.]php
[HIGH  ] Link uses a raw IP address instead of a name: hxxp://203[.]0[.]113[.]50/mapletrust/login[.]php
[HIGH  ] Double extension hides the file type: 'Account_Statement.pdf.exe'
[MEDIUM] Return-Path domain 'bulk-mailer.example' does not match From 'mapletrust-secure.top'
[MEDIUM] Shortened link hides the real destination: hxxps://bit[.]ly/3xMpl3
[MEDIUM] Pressure language: urgent, suspended, verify your, within 24 hours, unusual activity
[LOW   ] DKIM check: none
[LOW   ] Link is not encrypted (http, not https): hxxp://203[.]0[.]113[.]50/mapletrust/login[.]php

Risk score: 29  ->  LIKELY PHISHING - do not click anything, report it
```

The included legitimate email (`samples/safe_sample.eml`) scores **0: LOW RISK**.

## How to run

Requires Python 3.8 or newer.

```bash
python analyzer.py samples/phishing_sample.eml
python analyzer.py samples/safe_sample.eml
```

### Analyzing a real email

Save the email as a `.eml` file:
- **Gmail:** open the email, click **⋮**, then **Download message**
- **Outlook:** drag the email to your desktop, or use **File → Save As**

Then run `python analyzer.py your_email.eml`.

> ⚠️ The tool only **reads** the file. It never opens links or runs attachments, so it's safe to use on real phishing emails.

## How it works

1. **Parse.** Python's built-in `email` module splits the file into headers, text, HTML and attachments.
2. **Extract links.** An `HTMLParser` collects every `<a href="...">text</a>` pair, so the tool can compare what the link **shows** with where it **goes**.
3. **Run the checks.** Each check adds findings with a severity level.
4. **Score.** The points are added up into a final verdict.

## About the samples

The sample emails are **fake** and made for testing. They use a made-up company and domains under `.example`, which is reserved for documentation ([RFC 2606](https://datatracker.ietf.org/doc/html/rfc2606)), plus documentation IP addresses ([RFC 5737](https://datatracker.ietf.org/doc/html/rfc5737)). The "attachment" is a harmless line of text, not malware.

## Known limitations

- **Domain comparison is simplified.** It compares the last two parts of a domain, so `mail.example.co.uk` and `other.co.uk` would wrongly match. Real tools use the Public Suffix List.
- **It trusts the Authentication-Results header,** which is added by the receiving mail server. It doesn't re-check SPF/DKIM itself.
- **It's rule-based.** A well-crafted phishing email that avoids every rule can score low. Always use judgment.

## Ideas for future versions

- [ ] Check links and attachment hashes against VirusTotal
- [ ] Detect look-alike domains by character similarity (`rnicrosoft` vs `microsoft`)
- [ ] Trace the `Received` headers to show the email's real path
- [ ] Export the report as JSON for a SIEM

---
*Part of my cybersecurity learning portfolio. See also: [Brute-Force Login Detector](https://github.com/Preksha-Paul/brute-force-detector) · [File Integrity Monitor](https://github.com/Preksha-Paul/file-integrity-monitor)*
