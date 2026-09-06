#!/usr/bin/env python3
"""
main.py
--------
Data Extraction & Secure Validation Assignment

Reads raw, messy, production-style text (e.g. a support-ticket export) and
extracts structured data using regular expressions:

    1. Email addresses (general)            -> plus ALU-specific sub-rules
    2. Credit card numbers                   -> validated with the Luhn algorithm
    3. URLs
    4. Phone numbers (local + international)
    5. Times (12-hour and 24-hour)
    6. Hashtags
    7. Currency amounts (multiple symbols)
    8. HTML tags                             -> extracted ONLY to flag/strip them,
                                                 never trusted or rendered

The program treats every line of input as untrusted. Before extraction, each
line is screened for injection-style payloads (script tags, SQL keywords,
null-byte sequences, javascript: pseudo-protocols, credential-stuffed URLs,
etc.). Flagged lines are quarantined into a separate security report and are
NOT used for data extraction, so a hostile payload can never masquerade as a
"valid" email/URL/card just because it happens to contain matching characters.

Sensitive fields (credit card numbers) are masked before they ever reach the
JSON output or the console log — we only ever display the last 4 digits.
"""

import json
import re
from pathlib import Path

# ---------------------------------------------------------------------------
# 1. SECURITY / THREAT SCREENING
# ---------------------------------------------------------------------------
# These patterns describe *shapes* of hostile input, not specific payloads.
# The goal isn't to build a full WAF — it's to demonstrate that raw text
# pulled from an external API is never blindly trusted before extraction.

THREAT_PATTERNS = [
    (re.compile(r"<\s*script\b", re.IGNORECASE), "embedded <script> tag (possible XSS)"),
    (re.compile(r"javascript\s*:", re.IGNORECASE), "javascript: pseudo-protocol"),
    (re.compile(r"on\w+\s*=\s*['\"]", re.IGNORECASE), "inline HTML event handler (onerror=, onclick=...)"),
    (re.compile(r"(?:--|;)\s*(DROP|DELETE|INSERT|UPDATE|SELECT)\s+", re.IGNORECASE), "SQL-injection-style keyword"),
    (re.compile(r"'\s*--"), "SQL comment injection pattern ('--)"),
    (re.compile(r"%00|\\x00|\x00"), "null-byte injection attempt"),
    (re.compile(r"http[s]?://[^\s/@]+@[^\s/]+"), "credential-stuffed / phishing-style URL (user@host trick)"),
    (re.compile(r"(.)\1{25,}"), "abnormally long repeated-character run (possible buffer overflow probe)"),
]


def scan_line_for_threats(line: str):
    """Return a list of human-readable reasons a line looks hostile, if any."""
    hits = []
    for pattern, description in THREAT_PATTERNS:
        if pattern.search(line):
            hits.append(description)
    return hits


def sanitize_and_partition(raw_text: str):
    """
    Split raw text into:
      - clean_lines: safe to run extraction regexes against
      - quarantined:  [{line_number, content_preview, reasons}] for reporting

    We partition per-line (rather than scrubbing individual matches) so that
    an entire hostile line is excluded from extraction, instead of trying to
    "clean" it and risk half-sanitized data leaking through.
    """
    clean_lines = []
    quarantined = []

    for i, line in enumerate(raw_text.splitlines(), start=1):
        # Strip stray control characters (defensive normalisation) before scanning.
        normalized = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", line)
        reasons = scan_line_for_threats(normalized)
        if reasons:
            quarantined.append({
                "line_number": i,
                "preview": normalized.strip()[:80] + ("..." if len(normalized.strip()) > 80 else ""),
                "reasons": reasons,
            })
        else:
            clean_lines.append(normalized)

    return "\n".join(clean_lines), quarantined


# ---------------------------------------------------------------------------
# 2. EXTRACTION PATTERNS
# ---------------------------------------------------------------------------

# General email: local-part @ domain.tld — deliberately does NOT allow
# consecutive dots or a doubled "@@", which is a common malformed/spoofed shape.
EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9](?:[A-Za-z0-9._%+-]*[A-Za-z0-9])?@"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,}\b"
)

# ALU-specific email families. Anchored on the domain suffix so a lookalike
# domain (e.g. "alueducation.com.evil.ru") cannot slip through: \b plus the
# requirement that the match ends the address (no trailing domain segments).
ALU_OFFICIAL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@alueducation\.com\b", re.IGNORECASE)
ALU_ALUMNI_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@alumni\.alueducation\.com\b", re.IGNORECASE)
ALU_SI_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@si\.alueducation\.com\b", re.IGNORECASE)

# URLs: http(s) or bare www., stopping before whitespace / trailing punctuation.
URL_RE = re.compile(
    r"\b(?:https?://[^\s<>\"']+|www\.[^\s<>\"']+)"
)

# Phone numbers: Rwandan (+250 / 0) and generic international/local formats,
# tolerant of spaces, dots or dashes as separators.
PHONE_RE = re.compile(
    r"(?:\+?\d{1,3}[\s.-]?)?"          # optional country code
    r"(?:\(\d{2,4}\)[\s.-]?)?"         # optional area code in parentheses
    r"\d{2,4}[\s.-]\d{2,4}[\s.-]\d{2,4}(?:[\s.-]\d{2,4})?"
)

# Credit card numbers: 13–16 digits, grouped with spaces or dashes or none.
CARD_RE = re.compile(r"\b(?:\d[ -]?){13,16}\b")

# Time: 12-hour (e.g. 9:30 AM, 2:00PM) and 24-hour (e.g. 14:00, 07:45).
TIME_12H_RE = re.compile(r"\b(0?[1-9]|1[0-2]):[0-5]\d\s?(?:[AaPp][Mm])\b")
TIME_24H_RE = re.compile(r"\b([01]?\d|2[0-3]):[0-5]\d\b")

HASHTAG_RE = re.compile(r"#[A-Za-z][A-Za-z0-9_]{1,49}\b")

# Currency: symbol-first ($, €, £, KES/RWF/USD style codes) with optional
# thousands separators and decimals.
CURRENCY_RE = re.compile(
    r"(?:[$€£¥]\s?\d{1,3}(?:,\d{3})*(?:\.\d{2})?)"
    r"|(?:\b(?:USD|KES|RWF|GBP|EUR)\s?\d{1,3}(?:,\d{3})*(?:\.\d{2})?)"
)

HTML_TAG_RE = re.compile(r"<\/?[a-zA-Z][a-zA-Z0-9]*(?:\s+[^<>]*)?>")


# ---------------------------------------------------------------------------
# 3. SEMANTIC VALIDATION (beyond "does it match the shape")
# ---------------------------------------------------------------------------

def is_obviously_fake_number(digits: str) -> bool:
    """Catch placeholder/test values that pass Luhn by construction
    (e.g. all zeros) but are not real card numbers — e.g. 0000000000000000."""
    if len(set(digits)) == 1:
        return True
    ascending = "".join(str(d % 10) for d in range(len(digits)))
    descending = ascending[::-1]
    return digits in (ascending[:len(digits)], descending[-len(digits):])


def luhn_is_valid(digits: str) -> bool:
    """Standard Luhn checksum used by all major card networks."""
    digits = re.sub(r"\D", "", digits)
    if not (13 <= len(digits) <= 16) or is_obviously_fake_number(digits):
        return False
    total = 0
    reverse = digits[::-1]
    for i, ch in enumerate(reverse):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def mask_card(digits: str) -> str:
    """Never expose a full PAN in output or logs — keep only the last 4."""
    digits = re.sub(r"\D", "", digits)
    return f"**** **** **** {digits[-4:]}" if len(digits) >= 4 else "****"


def time_is_plausible(raw: str) -> bool:
    """Reject shapes that pass the regex loosely but are nonsense (25:99, 99:99)."""
    match = re.match(r"(\d{1,2}):(\d{2})", raw)
    if not match:
        return False
    hour, minute = int(match.group(1)), int(match.group(2))
    return 0 <= hour <= 23 and 0 <= minute <= 59


def mask_email_for_log(email: str) -> str:
    """Partial mask for console/log display so full addresses aren't dumped
    into logs unnecessarily, even though the JSON report keeps the full,
    validated address for legitimate ticket-handling purposes."""
    local, _, domain = email.partition("@")
    if len(local) <= 2:
        masked_local = local[0] + "*"
    else:
        masked_local = local[0] + "*" * (len(local) - 2) + local[-1]
    return f"{masked_local}@{domain}"


# ---------------------------------------------------------------------------
# 4. EXTRACTION PIPELINE
# ---------------------------------------------------------------------------

def extract_all(clean_text: str) -> dict:
    results = {
        "emails": {"general": [], "alu_official": [], "alu_alumni": [], "alu_si": []},
        "credit_cards": [],
        "urls": [],
        "phone_numbers": [],
        "times": {"12_hour": [], "24_hour": []},
        "hashtags": [],
        "currency_amounts": [],
        "html_tags_found_and_ignored": [],
    }

    # --- Emails -------------------------------------------------------
    all_emails = sorted(set(EMAIL_RE.findall(clean_text)))
    for email in all_emails:
        if ALU_ALUMNI_RE.fullmatch(email):
            results["emails"]["alu_alumni"].append(email)
        elif ALU_SI_RE.fullmatch(email):
            results["emails"]["alu_si"].append(email)
        elif ALU_OFFICIAL_RE.fullmatch(email):
            results["emails"]["alu_official"].append(email)
        else:
            results["emails"]["general"].append(email)

    # --- Credit cards (regex match -> Luhn semantic validation) ------
    for candidate in CARD_RE.findall(clean_text):
        digits = re.sub(r"\D", "", candidate)
        if luhn_is_valid(digits):
            results["credit_cards"].append({
                "masked": mask_card(digits),
                "network_length": len(digits),
                "valid_luhn": True,
            })
        # Invalid-Luhn "card-like" strings (e.g. the fake verification number
        # in the phishing ticket) are deliberately dropped, not reported —
        # they are not real card numbers and repeating them back is pointless
        # exposure of attacker-supplied junk.

    # --- URLs -----------------------------------------------------------
    results["urls"] = sorted(set(URL_RE.findall(clean_text)))

    # --- Phone numbers ----------------------------------------------------
    for candidate in PHONE_RE.findall(clean_text):
        digit_count = len(re.sub(r"\D", "", candidate))
        if 9 <= digit_count <= 13:  # plausible phone-number length
            results["phone_numbers"].append(candidate.strip())
    results["phone_numbers"] = sorted(set(results["phone_numbers"]))

    # --- Times ------------------------------------------------------------
    for match in TIME_12H_RE.findall(clean_text):
        pass  # findall with no groups would be full match; handled below instead
    for match in TIME_12H_RE.finditer(clean_text):
        val = match.group(0)
        if time_is_plausible(val):
            results["times"]["12_hour"].append(val)
    for match in TIME_24H_RE.finditer(clean_text):
        val = match.group(0)
        # Avoid double-counting the 24h-shaped prefix of a 12h match (e.g. "9:30" inside "9:30 AM")
        if time_is_plausible(val) and not any(val in t for t in results["times"]["12_hour"]):
            results["times"]["24_hour"].append(val)
    results["times"]["12_hour"] = sorted(set(results["times"]["12_hour"]))
    results["times"]["24_hour"] = sorted(set(results["times"]["24_hour"]))

    # --- Hashtags -------------------------------------------------------
    # Strip URLs first so a "#fragment" inside a link (e.g. ...page?x=1#pin=22)
    # is never mistaken for a social hashtag.
    text_without_urls = URL_RE.sub(" ", clean_text)
    results["hashtags"] = sorted(set(HASHTAG_RE.findall(text_without_urls)))

    # --- Currency -----------------------------------------------------------
    results["currency_amounts"] = sorted(set(m.strip() for m in CURRENCY_RE.findall(clean_text)))

    # --- HTML tags: extracted ONLY to prove they were found & neutralised ---
    results["html_tags_found_and_ignored"] = sorted(set(HTML_TAG_RE.findall(clean_text)))

    return results


# ---------------------------------------------------------------------------
# 5. MAIN
# ---------------------------------------------------------------------------

def main():
    base_dir = Path(__file__).resolve().parent.parent
    input_path = base_dir / "input" / "raw-text.txt"
    output_path = base_dir / "output" / "sample-output.json"

    raw_text = input_path.read_text(encoding="utf-8", errors="replace")

    clean_text, quarantined = sanitize_and_partition(raw_text)
    extracted = extract_all(clean_text)

    report = {
        "security_summary": {
            "total_lines_scanned": len(raw_text.splitlines()),
            "lines_quarantined": len(quarantined),
            "quarantined_lines": quarantined,
        },
        "extracted_data": extracted,
    }

    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    # --- Console summary (with sensitive values masked) --------------------
    print("=" * 60)
    print("SECURITY SCAN")
    print("=" * 60)
    print(f"Lines scanned: {report['security_summary']['total_lines_scanned']}")
    print(f"Lines quarantined as unsafe: {report['security_summary']['lines_quarantined']}")
    for q in quarantined:
        print(f"  - line {q['line_number']}: {', '.join(q['reasons'])}")
        print(f"    preview: {q['preview']}")

    print("\n" + "=" * 60)
    print("EXTRACTED DATA (summary)")
    print("=" * 60)
    print(f"General emails found: {len(extracted['emails']['general'])}")
    for e in extracted['emails']['general']:
        print(f"  - {mask_email_for_log(e)}")
    print(f"ALU official emails: {[mask_email_for_log(e) for e in extracted['emails']['alu_official']]}")
    print(f"ALU alumni emails:   {[mask_email_for_log(e) for e in extracted['emails']['alu_alumni']]}")
    print(f"ALU SI emails:       {[mask_email_for_log(e) for e in extracted['emails']['alu_si']]}")
    print(f"Valid credit cards found (masked): {[c['masked'] for c in extracted['credit_cards']]}")
    print(f"URLs found: {len(extracted['urls'])}")
    print(f"Phone numbers found: {extracted['phone_numbers']}")
    print(f"12-hour times: {extracted['times']['12_hour']}")
    print(f"24-hour times: {extracted['times']['24_hour']}")
    print(f"Hashtags: {extracted['hashtags']}")
    print(f"Currency amounts: {extracted['currency_amounts']}")
    print(f"HTML tags found (neutralised, never rendered): {len(extracted['html_tags_found_and_ignored'])}")
    print(f"\nFull report written to: {output_path}")


if __name__ == "__main__":
    main()
