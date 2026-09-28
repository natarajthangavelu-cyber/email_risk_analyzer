# Email Risk Analyzer

A Python tool that scans raw emails (`.eml`) for phishing indicators and spoofing signs, assigns a 0-100 risk score, and produces an email security audit report (console, JSON and PDF).

It is **defensive and read-only**: it never opens links or downloads attachments. All sample emails use reserved example domains (`example.com`, `example.net`, `example.org`) and documentation IP ranges, so no live links or real accounts are involved.

## What it checks

**1. Header analysis**
- SPF, DKIM and DMARC results (`Authentication-Results`, `Received-SPF`)
- `From` vs `Return-Path` vs `Reply-To` domain mismatch
- DKIM signing domain not aligned with the sender
- Display-name spoofing (brand names or a different address in the name)
- Look-alike sender domains (`paypa1`, `rnicrosoft`, punycode `xn--`)
- `Received` chain (hop count, originating IP), missing `Message-ID` / `Date`

**2. Body and link analysis**
- Urgent-action language ("act now", "within 24 hours", "verify your account")
- Requests for passwords, card numbers and other sensitive data
- Links with text that does not match the real destination
- Raw-IP links, `user@host` tricks, URL shorteners, punycode, high-abuse TLDs, non-HTTPS links
- Brand names hidden in subdomains (`paypal.com.evil-site.example.net`)
- Risky attachments and double extensions (`Invoice.pdf.exe`)

**3. Risk score**

Each indicator adds weighted points (total capped at 100):

| Score | Verdict |
|-------|---------|
| 0-24 | Low |
| 25-49 | Medium |
| 50-74 | High |
| 75-100 | Critical |

**4. Report**

A PDF audit report with an executive summary, header table, findings with evidence, extracted links and recommended actions.

## Setup

```bash
git clone <your-repo-url>
cd email-risk-analyzer
pip install -r requirements.txt
```

Requires Python 3.9+. Only the PDF report needs `reportlab`; the analysis itself uses the standard library.

## Usage

```bash
# Analyze every .eml in a folder and create the PDF + JSON
python email_analyzer.py samples/ --pdf reports/phishing_analysis_report.pdf --json reports/results.json

# Analyze a single file (console output only)
python email_analyzer.py samples/02_phishing_paypal_spoof.eml
```

To analyze a real email, save it as `.eml` (in Gmail: **Show original** -> **Download original**) and pass it to the script.

## Sample results

| File | Score | Verdict |
|------|-------|---------|
| `01_legit_newsletter.eml` | 0 | Low |
| `02_phishing_paypal_spoof.eml` | 100 | Critical |
| `03_ceo_invoice_attachment.eml` | 92 | Critical |

The generated report is in `reports/phishing_analysis_report.pdf`.

## Project structure

```
email-risk-analyzer/
├── email_analyzer.py    # the analyzer (parse -> scan -> score -> report)
├── requirements.txt
├── samples/             # synthetic safe test emails
├── reports/             # generated PDF and JSON
└── README.md
```

## Limitations

- Heuristic scoring: a high score means "very suspicious", not proof; a low score is not a guarantee of safety.
- SPF/DKIM/DMARC results are read from the headers added by the receiving server; the tool does not do live DNS lookups.
- The registered-domain check is a simple approximation (no public-suffix list).
