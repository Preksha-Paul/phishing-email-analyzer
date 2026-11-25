"""
Phishing Email Analyzer
-----------------------
Reads a saved email file (.eml) and looks for the warning signs of phishing:
  1. Sender tricks      - From / Reply-To / Return-Path don't match
  2. Failed checks      - SPF, DKIM or DMARC did not pass
  3. Dangerous links    - link text says one site but goes to another,
                          raw IP addresses, URL shorteners, look-alike domains
  4. Risky attachments  - .exe, .js, macro documents, double extensions
  5. Pressure language  - "urgent", "suspended", "verify now"...

Usage:
    py analyzer.py samples/phishing_sample.eml

How to save an email as .eml:
    Gmail:   open the email -> three dots -> "Download message"
    Outlook: drag the email to your desktop (or File -> Save As)
"""

import argparse
import ipaddress
import os
import re
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser
from urllib.parse import urlparse

# ---------- Colors for the terminal ----------
os.system("")  # turns on color support in older Windows terminals
RED, YELLOW, GREEN, CYAN, BOLD, RESET = (
    "\033[91m", "\033[93m", "\033[92m", "\033[96m", "\033[1m", "\033[0m")

# ---------- Things that look suspicious ----------
URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly",
                  "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc"}
RISKY_TLDS = {"zip", "mov", "top", "xyz", "click", "country", "gq", "tk", "ml", "work"}
RISKY_EXTENSIONS = {".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".ps1", ".jar",
                    ".hta", ".iso", ".img", ".lnk", ".docm", ".xlsm", ".pptm",
                    ".html", ".htm"}
URGENT_WORDS = ["urgent", "immediately", "suspended", "locked", "verify your",
                "confirm your", "within 24 hours", "unusual activity", "final notice",
                "action required", "password expires", "click below", "unauthorized"]

# How many points each severity adds to the risk score
POINTS = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}


# ---------- Helpers ----------
def domain_of(address):
    """'Bob <bob@mail.example.com>' -> 'mail.example.com'"""
    addr = parseaddr(address or "")[1]
    return addr.rsplit("@", 1)[-1].lower() if "@" in addr else ""


def base_domain(domain):
    """'mail.example.com' -> 'example.com' (simple version: last two parts)."""
    parts = domain.lower().strip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


def defang(url):
    """Make a link un-clickable so it is safe to paste into a report.
    This is standard practice for SOC analysts."""
    return url.replace("http", "hxxp").replace(".", "[.]")


def is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


class LinkFinder(HTMLParser):
    """Collects every <a href="...">text</a> in an HTML email."""
    def __init__(self):
        super().__init__()
        self.links = []      # list of (href, visible text)
        self._href = None
        self._text = ""

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href")
            self._text = ""

    def handle_data(self, data):
        if self._href is not None:
            self._text += data

    def handle_endtag(self, tag):
        if tag == "a" and self._href:
            self.links.append((self._href.strip(), self._text.strip()))
            self._href = None


# ---------- Step 1: read the email ----------
def read_email(path):
    with open(path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    text, html, attachments = "", "", []
    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        if filename or part.get_content_disposition() == "attachment":
            attachments.append(filename or "(unnamed)")
            continue
        try:
            content = part.get_content()
        except (LookupError, KeyError):
            continue
        if part.get_content_type() == "text/plain":
            text += content
        elif part.get_content_type() == "text/html":
            html += content
    return msg, text, html, attachments


# ---------- Step 2: run the checks ----------
def check_sender(msg, add):
    from_dom = domain_of(msg.get("From"))
    reply_dom = domain_of(msg.get("Reply-To"))
    return_dom = domain_of(msg.get("Return-Path"))
    display = parseaddr(msg.get("From", ""))[0]

    if reply_dom and base_domain(reply_dom) != base_domain(from_dom):
        add("HIGH", f"Replies go to a different domain: From is '{from_dom}' "
                    f"but Reply-To is '{reply_dom}'")
    if return_dom and base_domain(return_dom) != base_domain(from_dom):
        add("MEDIUM", f"Return-Path domain '{return_dom}' does not match From '{from_dom}'")

    # Display name pretending to be an email address: "support@bank.com" <x@evil.com>
    shown = re.search(r"[\w.+-]+@([\w-]+\.[\w.-]+)", display)
    if shown and base_domain(shown.group(1)) != base_domain(from_dom):
        add("HIGH", f"Display name shows '{shown.group(0)}' but the real sender is '{from_dom}'")
    return from_dom


def check_authentication(msg, add):
    results = " ".join(msg.get_all("Authentication-Results", [])).lower()
    if not results:
        add("LOW", "No Authentication-Results header (SPF/DKIM/DMARC could not be checked)")
        return {}
    found = dict(re.findall(r"\b(spf|dkim|dmarc)=(\w+)", results))
    for check in ("spf", "dkim", "dmarc"):
        status = found.get(check)
        if status is None:
            continue
        if status in ("fail", "softfail", "permerror"):
            level = "HIGH" if check == "dmarc" or status == "fail" else "MEDIUM"
            add(level, f"{check.upper()} check: {status} (sender may be forged)")
        elif status in ("none", "neutral", "temperror"):
            add("LOW", f"{check.upper()} check: {status}")
    return found


def collect_links(text, html):
    finder = LinkFinder()
    finder.feed(html)
    links = finder.links
    seen = {href for href, _ in links}
    # Plain-text part: any URL written out is a link
    for url in re.findall(r"https?://[^\s<>\"')]+", text):
        if url not in seen:
            links.append((url, ""))
            seen.add(url)
    return links


def check_links(links, add):
    for href, shown in links:
        parsed = urlparse(href)
        if parsed.scheme not in ("http", "https"):
            continue
        host = (parsed.hostname or "").lower()
        safe = defang(href)

        # The text says one website, but the link goes somewhere else
        shown_host = ""
        m = re.search(r"(?:https?://)?([\w-]+(?:\.[\w-]+)+)", shown)
        if m:
            shown_host = m.group(1).lower()
        if shown_host and base_domain(shown_host) != base_domain(host):
            add("HIGH", f"Link text shows '{shown_host}' but really goes to {safe}")
        if is_ip(host):
            add("HIGH", f"Link uses a raw IP address instead of a name: {safe}")
        if "@" in parsed.netloc:
            add("HIGH", f"Link hides its real destination with '@': {safe}")
        if host in URL_SHORTENERS:
            add("MEDIUM", f"Shortened link hides the real destination: {safe}")
        if "xn--" in host:
            add("HIGH", f"Look-alike (punycode) domain: {safe}")
        if host.rsplit(".", 1)[-1] in RISKY_TLDS:
            add("MEDIUM", f"Link uses a domain ending often used for abuse: {safe}")
        if parsed.scheme == "http":
            add("LOW", f"Link is not encrypted (http, not https): {safe}")


def check_attachments(attachments, add):
    for name in attachments:
        lower = name.lower()
        ext = os.path.splitext(lower)[1]
        parts = lower.split(".")
        if len(parts) >= 3 and "." + parts[-1] in RISKY_EXTENSIONS:
            add("HIGH", f"Double extension hides the file type: '{name}'")
        elif ext in RISKY_EXTENSIONS:
            add("HIGH", f"Dangerous attachment type: '{name}'")


def check_language(subject, text, html, add):
    content = (subject + " " + text + " " + re.sub(r"<[^>]+>", " ", html)).lower()
    hits = [w for w in URGENT_WORDS if w in content]
    if len(hits) >= 3:
        add("MEDIUM", f"Pressure language: {', '.join(hits)}")
    elif hits:
        add("LOW", f"Some urgent wording: {', '.join(hits)}")


# ---------- Step 3: report ----------
def verdict(score):
    if score >= 8:
        return RED, "LIKELY PHISHING - do not click anything, report it"
    if score >= 4:
        return YELLOW, "SUSPICIOUS - verify with the sender another way"
    return GREEN, "LOW RISK - no major warning signs found"


def analyze(path):
    msg, text, html, attachments = read_email(path)
    findings = []

    def add(level, message):
        findings.append((level, message))

    from_dom = check_sender(msg, add)
    auth = check_authentication(msg, add)
    links = collect_links(text, html)
    check_links(links, add)
    check_attachments(attachments, add)
    check_language(msg.get("Subject", ""), text, html, add)

    score = sum(POINTS[level] for level, _ in findings)

    # ----- print the report -----
    print(f"\n{BOLD}===== Phishing Email Analyzer ====={RESET}")
    print(f"From        : {msg.get('From', '(none)')}")
    print(f"Reply-To    : {msg.get('Reply-To', '(none)')}")
    print(f"Subject     : {msg.get('Subject', '(none)')}")
    auth_text = ", ".join(f"{k.upper()}={v}" for k, v in auth.items()) or "(not found)"
    print(f"Auth checks : {auth_text}")
    print(f"Links       : {len(links)}    Attachments: {len(attachments)}\n")

    colors = {"HIGH": RED, "MEDIUM": YELLOW, "LOW": CYAN}
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    for level, message in sorted(findings, key=lambda f: order[f[0]]):
        print(f"{colors[level]}{BOLD}[{level:<6}]{RESET} {message}")
    if not findings:
        print(f"{GREEN}No warning signs found.{RESET}")

    color, text_verdict = verdict(score)
    print(f"\n{BOLD}Risk score: {score}{RESET}  ->  {color}{BOLD}{text_verdict}{RESET}\n")


def main():
    parser = argparse.ArgumentParser(description="Check a saved email (.eml) for phishing signs.")
    parser.add_argument("email_file", help="path to a .eml file")
    args = parser.parse_args()
    if not os.path.isfile(args.email_file):
        print(f"{RED}Could not find '{args.email_file}'.{RESET}")
        return
    analyze(args.email_file)


if __name__ == "__main__":
    main()
