 ALU Regex Data Extraction & Secure Validation

A regex-based pipeline that extracts structured data from raw, messy,
production-style text (modeled on an exported batch of customer-support
tickets) and defends the extraction process against hostile or malformed
input before anything is parsed.

What it does

1. Reads `input/raw-text.txt` — a realistic support-ticket export with
   inconsistent formatting, typos, mixed date/time styles, and (deliberately)
   a few hostile/malformed entries.
2. **Screens every line for threats** before extraction ever touches it —
   see [Security approach](#security-approach) below.
3. **Extracts** eight data types from the surviving, clean lines:
   - Email addresses (general), **plus** three ALU-specific categories:
     `@alueducation.com`, `@alumni.alueducation.com`, `@si.alueducation.com`
   - Credit card numbers (validated with the Luhn checksum, not just shape)
   - URLs
   - Phone numbers (local Rwandan and generic international formats)
   - Times, both 12-hour (`9:30 AM`) and 24-hour (`14:00`)
   - Hashtags
   - Currency amounts (`$`, `€`, `£`, and 3-letter codes like `KES`/`USD`)
   - HTML tags (extracted only to prove they were detected and neutralised —
     never treated as trusted markup)
4. **Writes** a structured JSON report to `output/sample-output.json` and
   prints a masked summary to the console.

## How to run it

Requires Python 3.9+ (standard library only — no dependencies to install).

```bash
cd src
python3 main.py
```

The script reads `../input/raw-text.txt` and writes
`../output/sample-output.json` relative to its own location, so it can be run
from anywhere as long as the folder structure stays intact.

## Project structure

```
alu-regex-data-extraction_{GithubUsername}/
├── input/
│   └── raw-text.txt        
├── src/
│   └── main.py              
├── output/
│   └── sample-output.json   
└── README.md
```

## Security approach

The brief for this assignment is explicit that text pulled from an external
API should never be treated as automatically trustworthy. This project acts
on that in a few concrete ways:

- **Line-level quarantine before extraction.** Every line is scanned against
  a small set of threat signatures — `<script>` tags, `javascript:`
  pseudo-protocols, inline event handlers (`onerror=`, `onclick=`), SQL
  keywords following a comment/statement terminator (`DROP TABLE`, `'--`),
  null-byte sequences, "credential-stuffed" URLs (`http://user@host` used for
  phishing), and abnormally long repeated-character runs (a classic
  buffer-overflow probe shape). A line matching any of these is **removed
  from the pool used for extraction** and logged separately in
  `security_summary.quarantined_lines` — it can never "accidentally" produce
  a valid-looking email or URL just because it also contains matching
  characters.
- **Shape validation isn't enough — semantic validation is applied too.**
  - Credit card numbers are only accepted if they pass the **Luhn checksum**,
    and obvious placeholder values (all-zero, all-identical-digit, or
    perfectly sequential numbers) are rejected even if they happen to satisfy
    Luhn by construction.
  - Times are checked for a **plausible range** (`00–23` hours, `00–59`
    minutes), so junk like `25:99` or `99:99` is discarded even though it
    matches the basic `\d{1,2}:\d{2}` shape.
  - Email domains for the ALU-specific rules are anchored with `\b` and an
    exact suffix match, so a lookalike domain such as
    `secure-login-alueducation.com.verify-now.ru` cannot be mistaken for a
    real `@alueducation.com` address (this exact attempt is in the sample
    input, and it gets quarantined at the line-scan stage anyway).
- **Sensitive data is never fully exposed in output or logs.**
  - Credit card numbers are masked to `**** **** **** 1234` everywhere,
    including in the JSON report — the full PAN is never written to disk.
  - Email addresses are shown in full in the JSON report (support staff
    genuinely need the full address to resolve a ticket), but the **console
    log** only ever prints a partially masked version
    (`s********2@gmail.com`), since console output is far more likely to end
    up in a shared terminal, screen share, or log aggregator than the report
    file a specific agent opens deliberately.
  - Invalid-Luhn "card numbers" (e.g. the fake verification number planted in
    the phishing ticket) are dropped entirely rather than echoed back, since
    reprinting attacker-supplied junk serves no purpose.

## Known limitations

This is a learning exercise, not a production security scanner:

- The phone-number regex is intentionally permissive (9–13 digits) and will
  accept obviously fake numbers like `000-000-0000` if they're well-formed
  numerically. A production system would cross-check against a real
  numbering-plan library (e.g. `libphonenumber`).
- The threat-signature list is illustrative, not exhaustive. It demonstrates
  the *pattern* of not trusting external input by default, rather than
  claiming to catch every possible injection technique.
- Regex-based HTML tag detection is a blunt instrument; real HTML sanitisation
  should use a proper parser (e.g. `bleach`) rather than regex, which is why
  tags are only ever *reported*, never re-inserted into any output.
