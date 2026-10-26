"""Tests run against a fake DNS lookup, so they need no network access.

Run with:  python -m unittest -v
"""

import unittest

import email_health_check as ehc


def fake_lookup(records, missing=()):
    """Build a lookup function from {(name, type): [answers]}.

    Names listed in `missing` behave like NXDOMAIN (the name does not exist).
    """

    def lookup(name, rtype):
        if name.lower() in missing:
            raise ehc.NameNotFound(name)
        return records.get((name.lower(), rtype), [])

    return lookup


def txt(value):
    # Real APIs return TXT data wrapped in quotes.
    return f'"{value}"'


class CleanTxtTests(unittest.TestCase):
    def test_single_string(self):
        self.assertEqual(ehc.clean_txt('"v=spf1 -all"'), "v=spf1 -all")

    def test_split_string_is_joined(self):
        self.assertEqual(ehc.clean_txt('"v=spf1 " "include:x.com -all"'), "v=spf1 include:x.com -all")

    def test_unquoted_passthrough(self):
        self.assertEqual(ehc.clean_txt("v=spf1 -all"), "v=spf1 -all")


class SpfTests(unittest.TestCase):
    def run_spf(self, records):
        return ehc.check_spf(fake_lookup(records), "example.com")

    def test_missing(self):
        self.assertEqual(self.run_spf({}).status, ehc.FAIL)

    def test_hard_fail_passes(self):
        r = self.run_spf({("example.com", "TXT"): [txt("v=spf1 include:_spf.google.com -all")],
                          ("_spf.google.com", "TXT"): [txt("v=spf1 ip4:1.2.3.4 -all")]})
        self.assertEqual(r.status, ehc.PASS)

    def test_soft_fail_warns(self):
        r = self.run_spf({("example.com", "TXT"): [txt("v=spf1 mx ~all")]})
        self.assertEqual(r.status, ehc.WARN)

    def test_plus_all_fails(self):
        r = self.run_spf({("example.com", "TXT"): [txt("v=spf1 +all")]})
        self.assertEqual(r.status, ehc.FAIL)

    def test_duplicate_records_fail(self):
        r = self.run_spf({("example.com", "TXT"): [txt("v=spf1 -all"), txt("v=spf1 mx -all")]})
        self.assertEqual(r.status, ehc.FAIL)

    def test_no_all_warns(self):
        r = self.run_spf({("example.com", "TXT"): [txt("v=spf1 mx")]})
        self.assertEqual(r.status, ehc.WARN)

    def test_too_many_lookups_fails(self):
        includes = " ".join(f"include:s{i}.example.net" for i in range(11))
        r = self.run_spf({("example.com", "TXT"): [txt(f"v=spf1 {includes} -all")]})
        self.assertEqual(r.status, ehc.FAIL)
        self.assertIn("too complex", r.summary)

    def test_nested_include_lookups_are_counted(self):
        lookup = fake_lookup({
            ("a.com", "TXT"): [txt("v=spf1 include:b.com mx -all")],
            ("b.com", "TXT"): [txt("v=spf1 include:c.com a -all")],
            ("c.com", "TXT"): [txt("v=spf1 ip4:1.1.1.1 -all")],
        })
        # include:b, include:c, mx, a  -> 4
        self.assertEqual(ehc.count_spf_lookups(lookup, "v=spf1 include:b.com mx -all"), 4)

    def test_circular_include_does_not_loop(self):
        lookup = fake_lookup({("a.com", "TXT"): [txt("v=spf1 include:a.com -all")]})
        ehc.count_spf_lookups(lookup, "v=spf1 include:a.com -all")  # must terminate


class DmarcTests(unittest.TestCase):
    def run_dmarc(self, value):
        records = {("_dmarc.example.com", "TXT"): [txt(value)]} if value else {}
        return ehc.check_dmarc(fake_lookup(records), "example.com")

    def test_missing(self):
        self.assertEqual(self.run_dmarc(None).status, ehc.FAIL)

    def test_reject_with_reports_passes(self):
        self.assertEqual(self.run_dmarc("v=DMARC1; p=reject; rua=mailto:d@example.com").status, ehc.PASS)

    def test_none_warns(self):
        self.assertEqual(self.run_dmarc("v=DMARC1; p=none; rua=mailto:d@example.com").status, ehc.WARN)

    def test_reject_without_rua_warns(self):
        r = self.run_dmarc("v=DMARC1; p=reject")
        self.assertEqual(r.status, ehc.WARN)
        self.assertIn("rua", r.fix)

    def test_partial_pct_warns(self):
        r = self.run_dmarc("v=DMARC1; p=quarantine; pct=25; rua=mailto:d@example.com")
        self.assertEqual(r.status, ehc.WARN)

    def test_invalid_policy_fails(self):
        self.assertEqual(self.run_dmarc("v=DMARC1; p=banana").status, ehc.FAIL)


class MxTests(unittest.TestCase):
    def test_none_fails(self):
        self.assertEqual(ehc.check_mx(fake_lookup({}), "example.com").status, ehc.FAIL)

    def test_microsoft_detected(self):
        r = ehc.check_mx(fake_lookup({("example.com", "MX"): ["0 example-com.mail.protection.outlook.com."]}), "example.com")
        self.assertEqual(r.status, ehc.PASS)
        self.assertIn("Microsoft 365", r.summary)

    def test_single_unknown_host_warns(self):
        r = ehc.check_mx(fake_lookup({("example.com", "MX"): ["10 mail.example.com."]}), "example.com")
        self.assertEqual(r.status, ehc.WARN)

    def test_null_mx(self):
        r = ehc.check_mx(fake_lookup({("example.com", "MX"): ["0 ."]}), "example.com")
        self.assertEqual(r.status, ehc.PASS)


class DkimTests(unittest.TestCase):
    def test_found_via_txt(self):
        r = ehc.check_dkim(fake_lookup({("google._domainkey.example.com", "TXT"): [txt("v=DKIM1; k=rsa; p=ABC")]}), "example.com")
        self.assertEqual(r.status, ehc.PASS)

    def test_found_via_cname(self):
        r = ehc.check_dkim(fake_lookup({("selector1._domainkey.example.com", "CNAME"): ["selector1-example-com._domainkey.x.onmicrosoft.com."]}), "example.com")
        self.assertEqual(r.status, ehc.PASS)

    def test_not_found_warns_not_fails(self):
        self.assertEqual(ehc.check_dkim(fake_lookup({}), "example.com").status, ehc.WARN)


class ReportTests(unittest.TestCase):
    def healthy(self):
        return fake_lookup({
            ("example.com", "MX"): ["0 example-com.mail.protection.outlook.com."],
            ("example.com", "TXT"): [txt("v=spf1 -all")],
            ("selector1._domainkey.example.com", "CNAME"): ["x."],
            ("_dmarc.example.com", "TXT"): [txt("v=DMARC1; p=reject; rua=mailto:d@example.com")],
        })

    def test_healthy_domain_overall_pass(self):
        self.assertEqual(ehc.analyse_domain("Example.com.", self.healthy()).overall, ehc.PASS)

    def test_one_failure_makes_overall_fail(self):
        self.assertEqual(ehc.analyse_domain("example.com", fake_lookup({})).overall, ehc.FAIL)

    def test_dns_error_becomes_warning_not_crash(self):
        def broken(name, rtype):
            raise ehc.DNSError("boom")

        report = ehc.analyse_domain("example.com", broken)
        self.assertEqual(len(report.results), len(ehc.CHECKS))
        self.assertTrue(all(r.status == ehc.WARN for r in report.results))

    def test_mistyped_domain_reports_not_found_once(self):
        report = ehc.analyse_domain("typo.example", fake_lookup({}, missing={"typo.example"}))
        self.assertFalse(report.exists)
        self.assertEqual(len(report.results), 1)
        self.assertEqual(report.overall, ehc.FAIL)
        self.assertIn("does not exist", report.results[0].summary)

    def test_not_found_output_does_not_claim_impersonation_gaps(self):
        report = ehc.analyse_domain("typo.example", fake_lookup({}, missing={"typo.example"}))
        self.assertIn("Domain not found", ehc.format_text(report))
        self.assertNotIn("impersonate", ehc.format_text(report))

    def test_missing_dmarc_name_is_a_normal_fail_not_a_crash(self):
        lookup = fake_lookup({}, missing={"_dmarc.example.com"})
        r = ehc.check_dmarc(lookup, "example.com")
        self.assertEqual(r.status, ehc.FAIL)
        self.assertIn("No DMARC", r.summary)

    def test_missing_dkim_selector_names_are_skipped(self):
        lookup = fake_lookup({}, missing={f"{s}._domainkey.example.com" for s in ehc.DKIM_SELECTORS})
        self.assertEqual(ehc.check_dkim(lookup, "example.com").status, ehc.WARN)

    def test_formats_render(self):
        report = ehc.analyse_domain("example.com", fake_lookup({}))
        self.assertIn("example.com", ehc.format_text(report))
        self.assertIn("| Check |", ehc.format_markdown(report))
        self.assertIn('"overall": "fail"', ehc.format_json([report]))


if __name__ == "__main__":
    unittest.main()