#!/usr/bin/env python3
"""
Email Risk Analyzer
===================
Scans raw email files (.eml) for phishing indicators and spoofing signs.

Pipeline (matches the task steps):
  1. Parse raw headers      -> Received, Return-Path, SPF, DKIM, DMARC, From/Reply-To
  2. Scan body text/links   -> suspicious links, domain spoofing, urgent-action language
  3. Assign a risk score    -> 0-100 with a Low / Medium / High / Critical verdict
  4. Generate audit report  -> console, JSON and PDF

Usage:
  python email_analyzer.py samples/                       # analyze a folder
  python email_analyzer.py samples/phish1.eml --json out.json --pdf report.pdf

This tool is for defensive analysis only. It never opens links or downloads
attachments; it only reads the text of the email file you give it.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlparse
from xml.sax.saxutils import escape

# --------------------------------------------------------------------------
# Detection data
# --------------------------------------------------------------------------
BRANDS = {
    "paypal": ["paypal.com"],
    "microsoft": ["microsoft.com", "office.com", "outlook.com", "live.com", "microsoftonline.com"],
    "amazon": ["amazon.com", "amazon.in", "amazonaws.com"],
    "google": ["google.com", "gmail.com", "googlemail.com"],
    "apple": ["apple.com", "icloud.com"],
    "netflix": ["netflix.com"],
    "dhl": ["dhl.com"],
    "facebook": ["facebook.com", "fb.com", "meta.com"],
    "linkedin": ["linkedin.com"],
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc",
}

SUSPICIOUS_TLDS = {
    "zip", "top", "xyz", "click", "country", "gq", "tk", "ml", "cf", "ga",
    "work", "support", "loan", "rest", "icu", "monster",
}

URGENCY_PHRASES = [
    "urgent", "immediately", "act now", "action required", "within 24 hours",
    "within 48 hours", "account suspended", "account will be closed",
    "account has been locked", "verify your account", "confirm your identity",
    "password expires", "final notice", "unusual activity", "suspicious activity",
    "security alert", "limited time", "failure to", "click here", "update your payment",
    "your account will be", "immediate action",
]

CREDENTIAL_PATTERNS = [
    r"\bpassword\b", r"\bpasscode\b", r"\bsocial security\b", r"\bssn\b",
    r"\bcredit card\b", r"\bcard number\b", r"\bcvv\b", r"\bpin\b",
    r"\blogin credentials\b", r"\bbank account\b", r"\bone[- ]time (code|password)\b",
]

RISKY_EXTENSIONS = {
    ".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".com", ".jar", ".msi",
    ".ps1", ".lnk", ".iso", ".hta", ".html", ".htm", ".docm", ".xlsm", ".pptm",
}
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".gz", ".tar"}
DOUBLE_EXT_RE = re.compile(r"\.\w{2,5}\.(exe|scr|js|vbs|bat|cmd|com|jar|lnk|hta|ps1)$", re.I)

SECOND_LEVEL = {"co", "com", "org", "net", "gov", "ac", "edu"}

URL_RE = re.compile(r"https?://[^\s<>\"'\)\]]+", re.I)
IP_RE = re.compile(r"\[?(\d{1,3}(?:\.\d{1,3}){3})\]?")


# --------------------------------------------------------------------------
# Data structures
# --------------------------------------------------------------------------
@dataclass
class Finding:
    category: str          # "Header", "Link", "Content", "Attachment"
    title: str
    points: int
    detail: str
    evidence: str = ""

    @property
    def severity(self) -> str:
        if self.points >= 15:
            return "High"
        if self.points >= 8:
            return "Medium"
        return "Low"


@dataclass
class Result:
    file: str
    subject: str
    from_header: str
    score: int = 0
    verdict: str = "Low"
    header_info: dict = field(default_factory=dict)
    links: list = field(default_factory=list)
    attachments: list = field(default_factory=list)
    findings: list = field(default_factory=list)


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------
def domain_of(addr: str) -> str:
    addr = addr.strip().strip("<>").lower()
    return addr.rsplit("@", 1)[1] if "@" in addr else ""


def registered_domain(host: str) -> str:
    """Naive registrable-domain guess (no external public-suffix list needed)."""
    host = host.lower().strip(".")
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    if len(parts[-1]) == 2 and parts[-2] in SECOND_LEVEL:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def normalize_leet(text: str) -> set[str]:
    """Return de-obfuscated variants so 'paypa1' / 'rnicrosoft' match the brand."""
    variants = {text}
    for a, b in (("1", "l"), ("1", "i"), ("0", "o"), ("3", "e"), ("5", "s"), ("rn", "m"), ("vv", "w")):
        variants |= {v.replace(a, b) for v in list(variants)}
    return variants


def brand_lookalike(host: str) -> str | None:
    """Return the impersonated brand if `host` mimics one without being official."""
    host = host.lower()
    reg = registered_domain(host)
    for brand, official in BRANDS.items():
        if reg in official:
            continue
        # brand-looking text anywhere in the hostname (subdomain or registered part)
        if any(brand in v for v in normalize_leet(host)):
            return brand
    return None


def severity_verdict(score: int) -> str:
    if score >= 75:
        return "Critical"
    if score >= 50:
        return "High"
    if score >= 25:
        return "Medium"
    return "Low"


# --------------------------------------------------------------------------
# Step 1: header analysis
# --------------------------------------------------------------------------
def analyze_headers(msg: EmailMessage) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []

    from_name, from_addr = parseaddr(str(msg.get("From", "")))
    reply_to = parseaddr(str(msg.get("Reply-To", "")))[1]
    return_path = parseaddr(str(msg.get("Return-Path", "")))[1]
    from_dom, rp_dom, reply_dom = domain_of(from_addr), domain_of(return_path), domain_of(reply_to)

    auth_text = " ".join(str(v) for v in msg.get_all("Authentication-Results", []))
    rspf = " ".join(str(v) for v in msg.get_all("Received-SPF", []))

    def grab(name: str) -> str:
        m = re.search(rf"\b{name}=(\w+)", auth_text, re.I)
        return m.group(1).lower() if m else ""

    spf, dkim, dmarc = grab("spf"), grab("dkim"), grab("dmarc")
    if not spf and rspf:
        m = re.match(r"\s*(\w+)", rspf)
        spf = m.group(1).lower() if m else ""

    dkim_domain = ""
    m = re.search(r"header\.d=([\w.-]+)", auth_text, re.I)
    if m:
        dkim_domain = m.group(1).lower()
    elif msg.get("DKIM-Signature"):
        m = re.search(r"\bd=([\w.-]+)", str(msg.get("DKIM-Signature")))
        dkim_domain = m.group(1).lower() if m else ""

    # Received chain (top = newest hop, bottom = origin)
    received = [" ".join(str(r).split()) for r in msg.get_all("Received", [])]
    origin_ip = ""
    if received:
        m = IP_RE.search(received[-1])
        origin_ip = m.group(1) if m else ""

    info = {
        "From": str(msg.get("From", "")),
        "Return-Path": str(msg.get("Return-Path", "")),
        "Reply-To": str(msg.get("Reply-To", "")),
        "Message-ID": str(msg.get("Message-ID", "")),
        "Date": str(msg.get("Date", "")),
        "SPF": spf or "not present",
        "DKIM": dkim or "not present",
        "DMARC": dmarc or "not present",
        "DKIM signing domain": dkim_domain or "n/a",
        "Received hops": len(received),
        "Origin IP (first hop)": origin_ip or "n/a",
    }

    # --- SPF ---
    if spf in ("fail", "hardfail"):
        findings.append(Finding("Header", "SPF check failed", 20,
                                "The sending server is not authorised by the domain's SPF policy.",
                                f"spf={spf}"))
    elif spf == "softfail":
        findings.append(Finding("Header", "SPF soft-fail", 12,
                                "The sending server is probably not authorised by the domain.", "spf=softfail"))
    elif spf in ("none", "neutral", "permerror", "temperror"):
        findings.append(Finding("Header", "SPF not verifiable", 8,
                                "SPF gave no usable pass result.", f"spf={spf}"))

    # --- DKIM ---
    if dkim in ("fail", "permerror"):
        findings.append(Finding("Header", "DKIM signature invalid", 20,
                                "The DKIM signature did not validate; the message may be forged or altered.",
                                f"dkim={dkim}"))
    elif dkim in ("none", "neutral", "temperror"):
        findings.append(Finding("Header", "No valid DKIM signature", 8,
                                "The message is not cryptographically signed.", f"dkim={dkim}"))

    # --- DMARC ---
    if dmarc in ("fail", "reject", "quarantine"):
        findings.append(Finding("Header", "DMARC alignment failed", 20,
                                "Neither SPF nor DKIM aligned with the visible From domain.",
                                f"dmarc={dmarc}"))

    if not (spf or dkim or dmarc):
        findings.append(Finding("Header", "No authentication results", 8,
                                "No SPF/DKIM/DMARC results found in the headers."))

    # --- Domain alignment ---
    if from_dom and rp_dom and registered_domain(from_dom) != registered_domain(rp_dom):
        findings.append(Finding("Header", "Return-Path domain differs from From domain", 12,
                                "The envelope sender does not match the visible sender.",
                                f"From: {from_dom} | Return-Path: {rp_dom}"))
    if from_dom and reply_dom and registered_domain(from_dom) != registered_domain(reply_dom):
        findings.append(Finding("Header", "Reply-To redirects replies to another domain", 15,
                                "Replies would go to a different domain than the visible sender.",
                                f"From: {from_dom} | Reply-To: {reply_dom}"))
    if dkim_domain and from_dom and dkim == "pass" and registered_domain(dkim_domain) != registered_domain(from_dom):
        findings.append(Finding("Header", "DKIM domain not aligned with From domain", 10,
                                "The signature is valid but for a different domain than the sender shown.",
                                f"d={dkim_domain} | From: {from_dom}"))

    # --- Display-name spoofing ---
    name_l = from_name.lower()
    if "@" in from_name:
        shown = domain_of(re.sub(r".*?([\w.+-]+@[\w.-]+).*", r"\1", from_name))
        if shown and registered_domain(shown) != registered_domain(from_dom):
            findings.append(Finding("Header", "Display name contains a different email address", 15,
                                    "The name shown to the reader pretends to be another address.",
                                    f"Display name: {from_name}"))
    for brand, official in BRANDS.items():
        if brand in name_l and registered_domain(from_dom) not in official:
            findings.append(Finding("Header", f"Display name impersonates '{brand}'", 15,
                                    "The display name uses a brand but the address is not from that brand.",
                                    f"Display name: {from_name} | Address: {from_addr}"))
            break

    # --- Lookalike sender domain ---
    brand = brand_lookalike(from_dom) if from_dom else None
    if brand:
        findings.append(Finding("Header", f"Sender domain imitates '{brand}'", 20,
                                "The sender domain resembles a well-known brand but is not the real domain.",
                                from_dom))
    if "xn--" in from_dom:
        findings.append(Finding("Header", "Sender domain uses punycode (possible homograph)", 15,
                                "Internationalised domains can visually imitate real ones.", from_dom))

    # --- Misc hygiene ---
    if not msg.get("Message-ID"):
        findings.append(Finding("Header", "Missing Message-ID", 5, "Legitimate mail servers always add one."))
    if not msg.get("Date"):
        findings.append(Finding("Header", "Missing Date header", 3, "Unusual for legitimate mail."))
    if len(received) > 8:
        findings.append(Finding("Header", "Unusually long Received chain", 4,
                                f"{len(received)} hops; may indicate relaying through unexpected servers."))

    return findings, info


# --------------------------------------------------------------------------
# Step 2: body / link / attachment analysis
# --------------------------------------------------------------------------
class _AnchorParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[tuple[str, str]] = []
        self.text_parts: list[str] = []
        self._href: str | None = None
        self._buf: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self._skip += 1
        if tag == "a":
            self._href = dict(attrs).get("href") or ""
            self._buf = []

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip:
            self._skip -= 1
        if tag == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._buf).strip()))
            self._href = None

    def handle_data(self, data):
        if self._skip:
            return
        self.text_parts.append(data)
        if self._href is not None:
            self._buf.append(data)


def extract_content(msg: EmailMessage) -> tuple[str, list[tuple[str, str]], list[str]]:
    """Return (plain_text, [(href, anchor_text)], [attachment_filenames])."""
    text_chunks: list[str] = []
    links: list[tuple[str, str]] = []
    attachments: list[str] = []

    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        if filename:
            attachments.append(filename)
            continue
        ctype = part.get_content_type()
        if ctype not in ("text/plain", "text/html"):
            continue
        try:
            content = part.get_content()
        except Exception:
            content = part.get_payload(decode=True).decode("utf-8", "replace") if part.get_payload() else ""
        if ctype == "text/html":
            parser = _AnchorParser()
            parser.feed(content)
            links.extend(parser.links)
            text_chunks.append(" ".join(parser.text_parts))
        else:
            text_chunks.append(content)
            links.extend((u, u) for u in URL_RE.findall(content))

    return "\n".join(text_chunks), links, attachments


def analyze_body(text: str) -> list[Finding]:
    findings: list[Finding] = []
    lowered = text.lower()

    hits = [p for p in URGENCY_PHRASES if p in lowered]
    if hits:
        pts = min(4 * len(hits), 16)
        findings.append(Finding("Content", "Urgent / pressure language", pts,
                                "Phishing emails often create time pressure to stop the reader thinking.",
                                ", ".join(hits[:8])))

    creds = sorted({m.group(0) for p in CREDENTIAL_PATTERNS for m in re.finditer(p, lowered)})
    if creds:
        findings.append(Finding("Content", "Requests sensitive information", 12,
                                "The text mentions credentials or financial data.", ", ".join(creds)))

    if re.search(r"\b(dear (customer|user|member|client)|valued customer)\b", lowered):
        findings.append(Finding("Content", "Generic greeting", 4,
                                "Real providers usually address you by name."))
    return findings


def analyze_links(links: list[tuple[str, str]]) -> tuple[list[Finding], list[dict]]:
    findings: list[Finding] = []
    table: list[dict] = []
    seen: set[str] = set()

    for href, anchor in links:
        href = href.strip()
        if not href or href in seen or not href.lower().startswith(("http://", "https://")):
            continue
        seen.add(href)
        p = urlparse(href)
        host = (p.hostname or "").lower()
        reg = registered_domain(host)
        flags: list[str] = []

        def add(title: str, pts: int, detail: str) -> None:
            flags.append(title)
            findings.append(Finding("Link", title, pts, detail, href))

        if is_ip(host):
            add("Link uses a raw IP address", 15, "Legitimate services use domain names, not bare IPs.")
        if p.username is not None:
            add("Link contains '@' credentials trick", 12, "Text before '@' is ignored by browsers; the real host is after it.")
        if host in URL_SHORTENERS:
            add("URL shortener hides destination", 8, "The real target cannot be seen without following the link.")
        if "xn--" in host:
            add("Link domain uses punycode", 12, "Possible look-alike (homograph) domain.")
        if host.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
            add("Link uses a high-abuse TLD", 6, f"TLD .{host.rsplit('.', 1)[-1]} is frequently abused.")
        if p.scheme == "http":
            add("Link is not HTTPS", 4, "Unencrypted link; legitimate login pages use HTTPS.")
        brand = brand_lookalike(host) if host and not is_ip(host) else None
        if brand:
            add(f"Link domain imitates '{brand}'", 15,
                "The brand name appears in the hostname but the registered domain is not the brand's.")

        # anchor text shows one domain, href goes to another
        if anchor and re.search(r"[\w-]+\.[a-z]{2,}", anchor.lower()) and " " not in anchor.strip():
            shown = urlparse(anchor if "://" in anchor else "http://" + anchor).hostname or ""
            if shown and registered_domain(shown) != reg:
                add("Link text does not match its destination", 20,
                    f"Displayed '{anchor}' but goes to '{host}'.")

        table.append({"url": href, "text": anchor, "host": host, "flags": flags})
    return findings, table


def analyze_attachments(names: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for name in names:
        ext = Path(name).suffix.lower()
        if DOUBLE_EXT_RE.search(name):
            findings.append(Finding("Attachment", "Double file extension", 25,
                                    "Disguises an executable as a document.", name))
        elif ext in RISKY_EXTENSIONS:
            findings.append(Finding("Attachment", "Risky attachment type", 20,
                                    f"{ext} files can run code or open phishing pages.", name))
        elif ext in ARCHIVE_EXTENSIONS:
            findings.append(Finding("Attachment", "Archive attachment", 6,
                                    "Archives are commonly used to bypass scanners.", name))
    return findings


# --------------------------------------------------------------------------
# Step 3: scoring / orchestration
# --------------------------------------------------------------------------
def analyze_file(path: Path) -> Result:
    with open(path, "rb") as fh:
        msg = BytesParser(policy=policy.default).parse(fh)

    header_findings, header_info = analyze_headers(msg)
    text, links, attachments = extract_content(msg)
    body_findings = analyze_body(text)
    link_findings, link_table = analyze_links(links)
    att_findings = analyze_attachments(attachments)

    findings = header_findings + link_findings + body_findings + att_findings
    score = min(100, sum(f.points for f in findings))

    return Result(
        file=path.name,
        subject=str(msg.get("Subject", "(no subject)")),
        from_header=str(msg.get("From", "")),
        score=score,
        verdict=severity_verdict(score),
        header_info=header_info,
        links=link_table,
        attachments=attachments,
        findings=[{**asdict(f), "severity": f.severity} for f in
                  sorted(findings, key=lambda x: -x.points)],
    )


# --------------------------------------------------------------------------
# Step 4: reporting
# --------------------------------------------------------------------------
RECOMMENDATIONS = {
    "Low": ["No strong phishing indicators found. Still verify unexpected requests through a trusted channel."],
    "Medium": [
        "Treat with caution; do not click links or open attachments until verified.",
        "Confirm the request with the sender using a known phone number or website.",
    ],
    "High": [
        "Do not click links, open attachments, or reply.",
        "Report the message to your security team / mail provider as phishing.",
        "If any link was clicked or data entered, change passwords and enable MFA immediately.",
    ],
    "Critical": [
        "Quarantine or delete the message; do not interact with it in any way.",
        "Report it to your security team and block the sender and linked domains.",
        "If any link was clicked or credentials entered, reset passwords, revoke sessions and enable MFA.",
        "Search mail logs for other recipients of the same campaign.",
    ],
}


def print_console(r: Result) -> None:
    bar = "=" * 70
    print(f"\n{bar}\nFile    : {r.file}\nSubject : {r.subject}\nFrom    : {r.from_header}")
    print(f"RISK    : {r.score}/100  ->  {r.verdict.upper()}\n{bar}")
    print("Authentication: SPF={SPF}  DKIM={DKIM}  DMARC={DMARC}".format(**r.header_info))
    if not r.findings:
        print("No indicators found.")
    for f in r.findings:
        print(f"  [{f['severity']:<6}] +{f['points']:<2} {f['category']}: {f['title']}")
        if f["evidence"]:
            print(f"             evidence: {f['evidence'][:110]}")


def build_pdf(results: list[Result], out_path: Path) -> None:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (KeepTogether, PageBreak, Paragraph, SimpleDocTemplate,
                                    Spacer, Table, TableStyle)

    styles = getSampleStyleSheet()
    small = ParagraphStyle("small", parent=styles["Normal"], fontSize=8, leading=10)
    body = ParagraphStyle("body", parent=styles["Normal"], fontSize=9.5, leading=13)
    colors_by_verdict = {
        "Low": colors.HexColor("#2e7d32"), "Medium": colors.HexColor("#f9a825"),
        "High": colors.HexColor("#ef6c00"), "Critical": colors.HexColor("#c62828"),
    }

    def P(text, style=small):
        return Paragraph(escape(str(text)), style)

    doc = SimpleDocTemplate(str(out_path), pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm,
                            topMargin=16 * mm, bottomMargin=16 * mm,
                            title="Phishing Analysis Report", author="Email Risk Analyzer")
    story = [
        Paragraph("Phishing Analysis Report", styles["Title"]),
        Paragraph(f"Generated {datetime.now():%Y-%m-%d %H:%M} by Email Risk Analyzer", body),
        Spacer(1, 8),
        Paragraph("Executive summary", styles["Heading2"]),
    ]

    hdr = ParagraphStyle("hdr", parent=small, textColor=colors.white)
    rows = [[Paragraph(h, hdr) for h in ("Email file", "Subject", "Score", "Verdict")]]
    style = [("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#263238")),
             ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
             ("VALIGN", (0, 0), (-1, -1), "TOP")]
    for i, r in enumerate(results, start=1):
        rows.append([P(r.file), P(r.subject), P(f"{r.score}/100"),
                     Paragraph(escape(r.verdict), ParagraphStyle(f"v{i}", parent=small, textColor=colors.white))])
        style.append(("BACKGROUND", (3, i), (3, i), colors_by_verdict[r.verdict]))
    t = Table(rows, colWidths=[42 * mm, 78 * mm, 20 * mm, 28 * mm], repeatRows=1)
    t.setStyle(TableStyle(style))
    story += [t, Spacer(1, 6),
              Paragraph("Scoring: 0-24 Low, 25-49 Medium, 50-74 High, 75-100 Critical. "
                        "Each indicator adds weighted points; the total is capped at 100.", body)]

    for r in results:
        story.append(PageBreak())
        story.append(Paragraph(f"Email: {escape(r.file)}", styles["Heading1"]))
        story.append(Paragraph(f"<b>Subject:</b> {escape(r.subject)}<br/>"
                               f"<b>From:</b> {escape(r.from_header)}<br/>"
                               f"<b>Risk score:</b> {r.score}/100 &nbsp; "
                               f"<b>Verdict:</b> <font color='{colors_by_verdict[r.verdict].hexval()}'>"
                               f"{r.verdict.upper()}</font>", body))
        story.append(Spacer(1, 6))

        story.append(Paragraph("Header analysis", styles["Heading3"]))
        hrows = [[P(k), P(v)] for k, v in r.header_info.items()]
        ht = Table(hrows, colWidths=[45 * mm, 125 * mm])
        ht.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.3, colors.lightgrey),
                                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eceff1")),
                                ("VALIGN", (0, 0), (-1, -1), "TOP")]))
        story.append(ht)

        story.append(Paragraph("Findings", styles["Heading3"]))
        if r.findings:
            frows = [[P("Severity"), P("Category"), P("Indicator / evidence"), P("Pts")]]
            for f in r.findings:
                cell = Paragraph(f"<b>{escape(f['title'])}</b><br/>{escape(f['detail'])}"
                                 + (f"<br/><i>{escape(f['evidence'][:160])}</i>" if f["evidence"] else ""), small)
                frows.append([P(f["severity"]), P(f["category"]), cell, P(f"+{f['points']}")])
            ft = Table(frows, colWidths=[20 * mm, 22 * mm, 118 * mm, 10 * mm], repeatRows=1)
            ft.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#cfd8dc")),
                                    ("GRID", (0, 0), (-1, -1), 0.3, colors.grey),
                                    ("VALIGN", (0, 0), (-1, -1), "TOP")]))
            story.append(ft)
        else:
            story.append(Paragraph("No phishing indicators were detected.", body))

        if r.links:
            story.append(Paragraph("Links extracted", styles["Heading3"]))
            lrows = [[P("URL"), P("Flags")]]
            for l in r.links:
                lrows.append([P(l["url"][:120]), P(", ".join(l["flags"]) or "none")])
            lt = Table(lrows, colWidths=[95 * mm, 75 * mm], repeatRows=1)
            lt.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.3, colors.lightgrey),
                                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eceff1")),
                                    ("VALIGN", (0, 0), (-1, -1), "TOP")]))
            story.append(lt)
        if r.attachments:
            story.append(Paragraph("Attachments: " + escape(", ".join(r.attachments)), body))

        recs = [Paragraph("Recommended actions", styles["Heading3"])]
        recs += [Paragraph("&bull; " + escape(x), body) for x in RECOMMENDATIONS[r.verdict]]
        story.append(KeepTogether(recs))

    doc.build(story)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def collect_files(inputs: list[str]) -> list[Path]:
    files: list[Path] = []
    for item in inputs:
        p = Path(item)
        if p.is_dir():
            files += sorted(p.glob("*.eml"))
        elif p.is_file():
            files.append(p)
        else:
            print(f"Warning: {item} not found", file=sys.stderr)
    return files


def main() -> int:
    ap = argparse.ArgumentParser(description="Scan emails (.eml) for phishing indicators.")
    ap.add_argument("inputs", nargs="+", help=".eml files or folders containing them")
    ap.add_argument("--json", metavar="FILE", help="write results as JSON")
    ap.add_argument("--pdf", metavar="FILE", help="write a PDF audit report")
    args = ap.parse_args()

    files = collect_files(args.inputs)
    if not files:
        print("No .eml files to analyze.", file=sys.stderr)
        return 1

    results = [analyze_file(f) for f in files]
    for r in results:
        print_console(r)

    if args.json:
        Path(args.json).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json).write_text(json.dumps([asdict(r) for r in results], indent=2), encoding="utf-8")
        print(f"\nJSON saved to {args.json}")
    if args.pdf:
        Path(args.pdf).parent.mkdir(parents=True, exist_ok=True)
        try:
            build_pdf(results, Path(args.pdf))
            print(f"PDF report saved to {args.pdf}")
        except ImportError:
            print("PDF needs reportlab: pip install -r requirements.txt", file=sys.stderr)
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
