# Email Health Check

A small Python command-line tool that checks whether a domain's email is set up securely, and explains the result in plain English.

It calls a public DNS-over-HTTPS REST API (Google or Cloudflare, no API key needed) and checks four things:

| Check | Question it answers |
|---|---|
| **MX** | Where is this domain's email delivered, and by which provider? |
| **SPF** | Which servers are allowed to send email as this domain? Is the record valid, and within the 10-lookup limit? |
| **DKIM** | Are email signing keys published (tries common selectors, including Microsoft 365 and Google Workspace)? |
| **DMARC** | What happens to fake email, and is anyone receiving reports? |

Every result has a one-sentence summary written for a non-technical reader, the technical detail for an engineer, and a suggested fix.

## Why I built it

When IT clients ask "are we protected from email spoofing?", the honest answer lives in a handful of DNS records that are hard to read. This turns those records into a report a business owner can follow, while keeping the raw detail available for whoever makes the change.

## Setup

```bash
pip install -r requirements.txt
```

Requires Python 3.9+ and the `requests` library.

## Usage

```bash
# Plain-text report
python email_health_check.py example.com

# Several domains, Markdown output (paste straight into a ticket or client email)
python email_health_check.py example.com other.com --markdown > report.md

# JSON, for scripts or other tools
python email_health_check.py example.com --json

# Use Cloudflare's API instead of Google's
python email_health_check.py example.com --resolver cloudflare
```

The exit code is `1` if any domain has a failing check and `0` otherwise, so it can run in a scheduled job or CI pipeline.

## Example output

```
Email health check: acme.example
==================================================
Overall: [WARN] Mostly set up, but there are improvements worth making.

[PASS] MX (where your email is delivered)
  Mail servers are published and look healthy. It looks like Microsoft 365.

[WARN] SPF (who may send email as you)
  SPF is set up, but unlisted senders are only flagged as suspicious, not rejected.
  Fix: Once you are sure every legitimate sender is listed, change ~all to -all.

[PASS] DKIM (is your email tamper-proof)
  Email signing (DKIM) keys are published, so receivers can confirm mail was not altered.

[WARN] DMARC (what to do with fake email)
  DMARC is in monitoring mode only. It reports on fake email but does not block it.
  Fix: Review the reports, then move to p=quarantine and then p=reject.
```

(Technical detail lines are omitted here for length. Example domain and records are made up.)

## Tests

```bash
python -m unittest -v
```

The tests use a fake DNS lookup, so they run offline and instantly. They cover missing, duplicate and over-complex SPF records, each DMARC policy, MX provider detection, DKIM found via TXT and CNAME, circular SPF includes, and API failures.

## Design notes

- **The lookup is a plain function.** `make_lookup()` returns the function that calls the REST API, and every check takes it as an argument. That is what makes the checks testable without a network, and it would make swapping in a different DNS API a few-line change.
- **API failures do not crash the report.** If the DNS API is unreachable, the affected check is reported as "could not be completed" with the reason, and the other checks still run.
- **DKIM cannot be fully verified.** DNS has no way to list all selectors, so a "not found" is a warning, not a failure. The tool says so in the report.
- **SPF lookups are counted recursively**, following `include:` and `redirect=` chains with loop protection, because exceeding 10 lookups silently breaks SPF.

## Possible next steps

- Check for MTA-STS and BIMI.
- Read DMARC `rua` reports (see my [dmarc-viewer](https://github.com/K4fledmanish/dmarc-viewer)).
- Add a `--selector` option for custom DKIM selectors.
- Export the report as a PDF for client handoff.
