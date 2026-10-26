#!/usr/bin/env python3
"""Email Health Check

Checks a domain's email authentication setup (SPF, DKIM, DMARC, MX) by calling
a public DNS-over-HTTPS REST API, then writes a plain-English report that can
be read out to a non-technical client.

Usage:
    python email_health_check.py example.com
    python email_health_check.py example.com other.com --markdown > report.md
    python email_health_check.py example.com --json
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass, field
from typing import Callable, Iterable

import warnings

# macOS's built-in Python uses LibreSSL, which makes urllib3 print a harmless
# warning on every run. Hide just that one message.
warnings.filterwarnings("ignore", message="urllib3 v2 only supports OpenSSL")

import requests  # noqa: E402  (must come after the warning filter)

# Two public DNS-over-HTTPS JSON APIs. Both are free and need no API key.
RESOLVERS = {
    "google": "https://dns.google/resolve",
    "cloudflare": "https://cloudflare-dns.com/dns-query",
}

# DNS record type numbers returned by the JSON APIs.
TYPE_TXT = 16
TYPE_MX = 15
TYPE_CNAME = 5

# Common DKIM selectors. DKIM has no "list all selectors" lookup, so we try the
# ones used by the big providers. A miss does not prove DKIM is absent.
DKIM_SELECTORS = [
    "selector1",  # Microsoft 365
    "selector2",  # Microsoft 365
    "google",  # Google Workspace
    "default",
    "k1",  # Mailchimp
    "s1",  # SendGrid
    "s2",  # SendGrid
    "mail",
    "dkim",
]

# SPF allows at most 10 DNS-querying terms (RFC 7208). Going over breaks SPF.
SPF_LOOKUP_LIMIT = 10

PASS, WARN, FAIL = "pass", "warn", "fail"
ICONS = {PASS: "[PASS]", WARN: "[WARN]", FAIL: "[FAIL]"}


# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------
@dataclass
class CheckResult:
    name: str
    status: str  # pass | warn | fail
    summary: str  # one plain-English sentence for the client
    detail: str = ""  # technical detail for the engineer
    fix: str = ""  # what to do about it


@dataclass
class DomainReport:
    domain: str
    results: list[CheckResult] = field(default_factory=list)
    exists: bool = True  # False when the domain is not in DNS at all

    @property
    def overall(self) -> str:
        statuses = {r.status for r in self.results}
        if FAIL in statuses:
            return FAIL
        if WARN in statuses:
            return WARN
        return PASS


class DNSError(Exception):
    """Raised when the DNS API cannot be reached or returns bad data."""


class NameNotFound(DNSError):
    """Raised when a DNS name does not exist at all (NXDOMAIN)."""


# --------------------------------------------------------------------------
# REST API call
# --------------------------------------------------------------------------
# A "lookup" is any function (name, record_type) -> list of answer strings.
# Keeping it a plain function lets the tests swap in a fake with no network.
Lookup = Callable[[str, str], "list[str]"]


def make_lookup(resolver: str = "google", timeout: float = 10.0) -> Lookup:
    """Return a lookup function that calls the chosen DNS-over-HTTPS API."""
    url = RESOLVERS[resolver]
    session = requests.Session()
    session.headers.update({"Accept": "application/dns-json"})

    def lookup(name: str, rtype: str) -> list[str]:
        try:
            resp = session.get(
                url, params={"name": name, "type": rtype}, timeout=timeout
            )
            resp.raise_for_status()
            payload = resp.json()
        except requests.RequestException as exc:
            raise DNSError(f"Could not reach {resolver} DNS API: {exc}") from exc
        except ValueError as exc:
            raise DNSError(f"{resolver} DNS API returned invalid JSON") from exc

        # Status 0 = NOERROR, 3 = NXDOMAIN (the name does not exist at all).
        # Anything else is a real problem with the lookup.
        status = payload.get("Status")
        if status == 3:
            raise NameNotFound(name)
        if status != 0:
            raise DNSError(f"{resolver} DNS API returned DNS status {status}")

        return [a["data"] for a in payload.get("Answer", []) if "data" in a]

    return lookup


def clean_txt(raw: str) -> str:
    """TXT answers arrive quoted and sometimes split: '"v=spf1 " "include:x"'.

    Join the pieces back into the single string the domain owner published.
    """
    parts = []
    in_quote = False
    buf = []
    for ch in raw:
        if ch == '"':
            if in_quote:
                parts.append("".join(buf))
                buf = []
            in_quote = not in_quote
        elif in_quote:
            buf.append(ch)
    return "".join(parts) if parts else raw.strip()


def records_for(lookup: Lookup, name: str, rtype: str) -> list[str]:
    """Like lookup(), but a name that does not exist just has no records.

    Names such as _dmarc.example.com or a DKIM selector are expected to be
    missing on many domains, so that is a normal "nothing here" answer.
    """
    try:
        return lookup(name, rtype)
    except NameNotFound:
        return []


def txt_records(lookup: Lookup, name: str) -> list[str]:
    return [clean_txt(r) for r in records_for(lookup, name, "TXT")]


# --------------------------------------------------------------------------
# SPF
# --------------------------------------------------------------------------
def count_spf_lookups(
    lookup: Lookup, record: str, seen: set[str] | None = None, depth: int = 0
) -> int:
    """Count DNS-querying terms in an SPF record, following includes."""
    seen = seen if seen is not None else set()
    if depth > 10:  # runaway include chain; stop
        return SPF_LOOKUP_LIMIT + 1

    total = 0
    for term in record.split()[1:]:
        t = term.lstrip("+-~?").lower()
        if t.startswith(("include:", "redirect=")):
            total += 1
            target = t.split(":", 1)[-1] if ":" in t else t.split("=", 1)[1]
            if target in seen:
                continue
            seen.add(target)
            for txt in txt_records(lookup, target):
                if txt.lower().startswith("v=spf1"):
                    total += count_spf_lookups(lookup, txt, seen, depth + 1)
                    break
        elif t.startswith(("a:", "a/", "mx:", "mx/", "exists:", "ptr")) or t in ("a", "mx"):
            total += 1
    return total


def check_spf(lookup: Lookup, domain: str) -> CheckResult:
    name = "SPF (who may send email as you)"
    records = [r for r in txt_records(lookup, domain) if r.lower().startswith("v=spf1")]

    if not records:
        return CheckResult(
            name,
            FAIL,
            "No SPF record found, so anyone can pretend to send email from this domain.",
            fix="Publish a TXT record listing the services that send your email, "
            "for example: v=spf1 include:spf.protection.outlook.com -all",
        )
    if len(records) > 1:
        return CheckResult(
            name,
            FAIL,
            "More than one SPF record is published, which makes SPF fail entirely.",
            detail=" | ".join(records),
            fix="Merge them into a single v=spf1 TXT record.",
        )

    record = records[0]
    lowered = record.lower().split()
    lookups = count_spf_lookups(lookup, record)

    if lookups > SPF_LOOKUP_LIMIT:
        return CheckResult(
            name,
            FAIL,
            "The SPF record is too complex, so receiving mail servers will ignore it.",
            detail=f"{record}\nDNS lookups: {lookups} (limit {SPF_LOOKUP_LIMIT})",
            fix="Remove unused include: entries or flatten the record.",
        )

    ending = next((t for t in lowered if t.endswith("all") and len(t) <= 4), None)
    detail = f"{record}\nDNS lookups: {lookups} of {SPF_LOOKUP_LIMIT}"

    if ending == "-all":
        return CheckResult(
            name,
            PASS,
            "SPF is set up and tells other servers to reject email from unlisted senders.",
            detail=detail,
        )
    if ending == "~all":
        return CheckResult(
            name,
            WARN,
            "SPF is set up, but unlisted senders are only flagged as suspicious, not rejected.",
            detail=detail,
            fix="Once you are sure every legitimate sender is listed, change ~all to -all.",
        )
    if ending in ("?all", "+all", "all"):
        return CheckResult(
            name,
            FAIL,
            "SPF is present but allows (or does not restrict) any sender, so it offers no protection.",
            detail=detail,
            fix="End the record with -all (or ~all while testing).",
        )
    return CheckResult(
        name,
        WARN,
        "SPF is present but has no final 'all' rule, so the policy is incomplete.",
        detail=detail,
        fix="Add -all to the end of the record.",
    )


# --------------------------------------------------------------------------
# DMARC
# --------------------------------------------------------------------------
def parse_tags(record: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    for part in record.split(";"):
        if "=" in part:
            key, _, value = part.partition("=")
            tags[key.strip().lower()] = value.strip()
    return tags


def check_dmarc(lookup: Lookup, domain: str) -> CheckResult:
    name = "DMARC (what to do with fake email)"
    records = [
        r
        for r in txt_records(lookup, f"_dmarc.{domain}")
        if r.lower().startswith("v=dmarc1")
    ]

    if not records:
        return CheckResult(
            name,
            FAIL,
            "No DMARC policy found, so spoofed email pretending to be you is not blocked "
            "and you get no reports about it.",
            fix="Start with: v=DMARC1; p=none; rua=mailto:dmarc@yourdomain.com "
            "then tighten to quarantine and reject once reports look clean.",
        )

    record = records[0]
    tags = parse_tags(record)
    policy = tags.get("p", "").lower()
    has_reports = "rua" in tags
    pct = tags.get("pct", "100")

    if policy == "reject":
        status, summary = PASS, "DMARC is set to reject fake email, which is the strongest setting."
        fix = ""
    elif policy == "quarantine":
        status, summary = PASS, "DMARC sends suspected fake email to spam. Good, with room to tighten."
        fix = "When reports show no legitimate mail being caught, move to p=reject."
    elif policy == "none":
        status, summary = (
            WARN,
            "DMARC is in monitoring mode only. It reports on fake email but does not block it.",
        )
        fix = "Review the reports, then move to p=quarantine and then p=reject."
    else:
        return CheckResult(
            name,
            FAIL,
            "A DMARC record exists but its policy is missing or invalid.",
            detail=record,
            fix="Set p=none, p=quarantine or p=reject.",
        )

    notes = []
    if not has_reports:
        status = WARN if status == PASS else status
        notes.append("Add an rua=mailto:... tag so you receive reports.")
    if pct.isdigit() and int(pct) < 100:
        status = WARN if status == PASS else status
        notes.append(f"Policy only applies to {pct}% of mail (pct={pct}).")
    if notes:
        fix = (fix + " " + " ".join(notes)).strip()
        if not has_reports:
            summary += " No reporting address is set."

    return CheckResult(name, status, summary, detail=record, fix=fix)


# --------------------------------------------------------------------------
# MX
# --------------------------------------------------------------------------
MX_PROVIDERS = {
    "google.com": "Google Workspace",
    "googlemail.com": "Google Workspace",
    "mail.protection.outlook.com": "Microsoft 365",
    "pphosted.com": "Proofpoint",
    "mimecast.com": "Mimecast",
    "mailgun.org": "Mailgun",
    "zoho.com": "Zoho Mail",
}


def detect_provider(hosts: Iterable[str]) -> str | None:
    for host in hosts:
        h = host.lower().rstrip(".")
        for suffix, provider in MX_PROVIDERS.items():
            if h.endswith(suffix):
                return provider
    return None


def check_mx(lookup: Lookup, domain: str) -> CheckResult:
    name = "MX (where your email is delivered)"
    answers = records_for(lookup, domain, "MX")

    entries = []
    for ans in answers:
        parts = ans.split()
        if len(parts) == 2 and parts[0].isdigit():
            entries.append((int(parts[0]), parts[1].rstrip(".")))
    entries.sort()

    if not entries:
        return CheckResult(
            name,
            FAIL,
            "No mail servers are published, so this domain cannot receive email.",
            fix="Add MX records pointing at your email provider.",
        )
    if len(entries) == 1 and entries[0][1] == "":
        return CheckResult(
            name,
            PASS,
            "This domain publishes a 'null MX', meaning it deliberately does not receive email.",
            detail="MX 0 .",
        )

    provider = detect_provider(h for _, h in entries)
    detail = "\n".join(f"{prio} {host}" for prio, host in entries)
    who = f" It looks like {provider}." if provider else ""

    if len(entries) == 1 and provider is None:
        return CheckResult(
            name,
            WARN,
            f"Email is delivered to a single mail server with no backup.{who}",
            detail=detail,
            fix="Consider a secondary MX if your provider does not already handle redundancy.",
        )
    return CheckResult(
        name, PASS, f"Mail servers are published and look healthy.{who}", detail=detail
    )


# --------------------------------------------------------------------------
# DKIM
# --------------------------------------------------------------------------
def check_dkim(lookup: Lookup, domain: str) -> CheckResult:
    name = "DKIM (is your email tamper-proof)"
    found = []
    for selector in DKIM_SELECTORS:
        host = f"{selector}._domainkey.{domain}"
        txts = [t for t in txt_records(lookup, host) if "p=" in t.lower()]
        cnames = records_for(lookup, host, "CNAME")  # Microsoft 365 uses CNAMEs
        if txts or cnames:
            found.append(selector)

    if found:
        return CheckResult(
            name,
            PASS,
            "Email signing (DKIM) keys are published, so receivers can confirm mail was not altered.",
            detail="Selectors found: " + ", ".join(found),
        )
    return CheckResult(
        name,
        WARN,
        "No DKIM signing keys were found at common selector names.",
        detail="Checked: " + ", ".join(DKIM_SELECTORS),
        fix="Enable DKIM in your email provider. If it is already on, it may use a "
        "custom selector name that this tool does not check.",
    )


# --------------------------------------------------------------------------
# Running checks and formatting output
# --------------------------------------------------------------------------
CHECKS = [check_mx, check_spf, check_dkim, check_dmarc]


def analyse_domain(domain: str, lookup: Lookup) -> DomainReport:
    domain = domain.strip().lower().rstrip(".")
    report = DomainReport(domain)

    # Before running any checks, make sure the domain exists. Otherwise a
    # simple typo produces four alarming failures that are really one problem.
    try:
        lookup(domain, "NS")
    except NameNotFound:
        report.exists = False
        report.results.append(
            CheckResult(
                "Domain",
                FAIL,
                "This domain does not exist, so no email checks could be run.",
                fix="Check the spelling of the domain (a mistyped letter is the "
                "most common cause) and try again.",
            )
        )
        return report
    except DNSError:
        pass  # let the individual checks report the connection problem

    for check in CHECKS:
        try:
            report.results.append(check(lookup, domain))
        except DNSError as exc:
            report.results.append(
                CheckResult(check.__name__.replace("check_", "").upper(), WARN,
                            "This check could not be completed.", detail=str(exc))
            )
    return report


OVERALL_TEXT = {
    PASS: "Looks good. Email authentication is in place.",
    WARN: "Mostly set up, but there are improvements worth making.",
    FAIL: "There are gaps that let others impersonate this domain or block delivery.",
}


def overall_text(report: DomainReport) -> str:
    if not report.exists:
        return "Domain not found."
    return OVERALL_TEXT[report.overall]


def format_text(report: DomainReport) -> str:
    lines = [f"Email health check: {report.domain}", "=" * 50]
    lines.append(f"Overall: {ICONS[report.overall]} {overall_text(report)}")
    for r in report.results:
        lines += ["", f"{ICONS[r.status]} {r.name}", f"  {r.summary}"]
        if r.fix:
            lines.append(f"  Fix: {r.fix}")
        if r.detail:
            lines += ["  Detail: " + ln for ln in r.detail.splitlines()]
    return "\n".join(lines)


def format_markdown(report: DomainReport) -> str:
    lines = [f"## Email health check: {report.domain}", ""]
    lines.append(f"**Overall: {report.overall.upper()}.** {overall_text(report)}")
    lines.append("")
    lines.append("| Check | Result | What it means |")
    lines.append("|---|---|---|")
    for r in report.results:
        lines.append(f"| {r.name} | {r.status.upper()} | {r.summary} |")
    fixes = [r for r in report.results if r.fix]
    if fixes:
        lines += ["", "### Recommended actions", ""]
        lines += [f"- **{r.name.split(' (')[0]}:** {r.fix}" for r in fixes]
    return "\n".join(lines)


def format_json(reports: list[DomainReport]) -> str:
    return json.dumps(
        [{**asdict(r), "overall": r.overall} for r in reports], indent=2
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check a domain's email authentication setup.")
    parser.add_argument("domains", nargs="+", help="domain(s) to check, e.g. example.com")
    parser.add_argument("--resolver", choices=RESOLVERS, default="google",
                        help="which DNS-over-HTTPS API to call (default: google)")
    fmt = parser.add_mutually_exclusive_group()
    fmt.add_argument("--markdown", action="store_true", help="output a Markdown report")
    fmt.add_argument("--json", action="store_true", help="output JSON")
    args = parser.parse_args(argv)

    lookup = make_lookup(args.resolver)
    reports = [analyse_domain(d, lookup) for d in args.domains]

    if args.json:
        print(format_json(reports))
    elif args.markdown:
        print("\n\n".join(format_markdown(r) for r in reports))
    else:
        print("\n\n".join(format_text(r) for r in reports))

    # Non-zero exit if any domain has a failing check, so it can run in scripts/CI.
    return 1 if any(r.overall == FAIL for r in reports) else 0


if __name__ == "__main__":
    sys.exit(main())