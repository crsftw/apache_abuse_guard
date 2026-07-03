#!/usr/bin/env python3
"""Tests for IP classification in apache_abuse_guard."""
import os
import tempfile
import unittest

import apache_abuse_guard as aag

IP = "185.220.101.5"

UA_BROWSER = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/120.0 Safari/537.36")
UA_SCRAPER = "python-requests/2.31.0"
UA_CURL = "curl/8.5.0"
UA_GOOGLEBOT = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"


class StatDict(dict):
    def __missing__(self, k):
        v = aag.Stat(k)
        self[k] = v
        return v


def log_line(ip, method, url, status, ua):
    return (f'{ip} - - [03/Jul/2026:10:00:00 +0000] '
            f'"{method} {url} HTTP/1.1" {status} 123 "-" "{ua}"\n')


def parse_lines(lines):
    stats = StatDict()
    fd, path = tempfile.mkstemp(suffix=".log")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.writelines(lines)
        aag.parse_access(path, stats)
    finally:
        os.unlink(path)
    return stats


class DominantUaClassification(unittest.TestCase):
    def test_single_spoofed_googlebot_hit_does_not_immunize_scraper(self):
        # 60 scraper-UA hits + 1 Googlebot-UA hit: still scraping.
        lines = [log_line(IP, "GET", f"/page{i}", 200, UA_SCRAPER) for i in range(60)]
        lines.append(log_line(IP, "GET", "/", 200, UA_GOOGLEBOT))
        label, _, _, _ = aag.classify(parse_lines(lines)[IP])
        self.assertEqual(label, "SCRAPING")

    def test_single_curl_hit_does_not_mark_browser_ip_as_scraper(self):
        # 100 browser hits + 1 curl hit: not a scraper.
        lines = [log_line(IP, "GET", f"/page{i}", 200, UA_BROWSER) for i in range(100)]
        lines.append(log_line(IP, "GET", "/health", 200, UA_CURL))
        label, _, _, _ = aag.classify(parse_lines(lines)[IP])
        self.assertEqual(label, "OTHER")

    def test_dominant_scraper_ua_is_scraping(self):
        lines = [log_line(IP, "GET", f"/page{i}", 200, UA_SCRAPER) for i in range(60)]
        label, _, _, _ = aag.classify(parse_lines(lines)[IP])
        self.assertEqual(label, "SCRAPING")

    def test_dominant_legit_ua_is_known_search_engine(self):
        lines = [log_line(IP, "GET", f"/page{i}", 200, UA_GOOGLEBOT) for i in range(100)]
        label, _, reason, _ = aag.classify(parse_lines(lines)[IP])
        self.assertEqual(label, "OTHER")
        self.assertIn("search engine", reason)


class StatusAwareAuthHits(unittest.TestCase):
    def test_successful_login_page_views_are_not_bruteforce(self):
        # A real user rendering /login (GET -> 200) is not an attack.
        lines = [log_line(IP, "GET", "/login", 200, UA_BROWSER) for _ in range(30)]
        label, _, _, _ = aag.classify(parse_lines(lines)[IP])
        self.assertEqual(label, "OTHER")

    def test_failed_auth_posts_are_bruteforce(self):
        lines = [log_line(IP, "POST", "/wp-login.php", 401, UA_BROWSER)
                 for _ in range(30)]
        label, _, _, pre = aag.classify(parse_lines(lines)[IP])
        self.assertEqual(label, "BRUTEFORCE")
        self.assertTrue(pre)

    def test_auth_probing_with_404s_is_bruteforce(self):
        # Exploit scanners GET auth paths that don't exist here.
        lines = [log_line(IP, "GET", "/wp-login.php", 404, UA_BROWSER)
                 for _ in range(12)]
        label, _, _, _ = aag.classify(parse_lines(lines)[IP])
        self.assertEqual(label, "BRUTEFORCE")

    def test_auth_path_in_query_string_is_not_counted(self):
        # '/search?q=/wp-login.php' is not an auth-path hit.
        lines = [log_line(IP, "GET", "/search?q=/wp-login.php", 404, UA_BROWSER)
                 for _ in range(30)]
        label, _, _, _ = aag.classify(parse_lines(lines)[IP])
        self.assertEqual(label, "OTHER")


class RdnsVerification(unittest.TestCase):
    def _googlebot_stats(self):
        # High-volume crawl claiming to be Googlebot.
        lines = [log_line(IP, "GET", f"/a/{i}", 200, UA_GOOGLEBOT) for i in range(400)]
        return parse_lines(lines)[IP]

    def test_spoofed_search_engine_ua_failing_rdns_is_scraping(self):
        label, _, reason, _ = aag.classify(self._googlebot_stats(),
                                           rdns_verify=lambda ip: False)
        self.assertEqual(label, "SCRAPING")
        self.assertIn("fake search-engine UA", reason)

    def test_verified_search_engine_stays_legit(self):
        label, _, reason, _ = aag.classify(self._googlebot_stats(),
                                           rdns_verify=lambda ip: True)
        self.assertEqual(label, "OTHER")
        self.assertIn("verified search engine", reason)

    def test_without_rdns_ua_is_trusted(self):
        label, _, reason, _ = aag.classify(self._googlebot_stats())
        self.assertEqual(label, "OTHER")
        self.assertIn("search engine", reason)


class VerifySearchEngineResolution(unittest.TestCase):
    IP4 = "66.249.66.1"

    @staticmethod
    def _addrinfo(ip):
        return [(2, 1, 6, "", (ip, 0))]

    def test_confirmed_googlebot(self):
        ok = aag._verify_search_engine(
            self.IP4,
            lambda ip: ("crawl-66-249-66-1.googlebot.com", [], [ip]),
            lambda host, port: self._addrinfo(self.IP4))
        self.assertTrue(ok)

    def test_forward_dns_mismatch_is_rejected(self):
        ok = aag._verify_search_engine(
            self.IP4,
            lambda ip: ("crawl-66-249-66-1.googlebot.com", [], [ip]),
            lambda host, port: self._addrinfo("203.0.113.9"))
        self.assertFalse(ok)

    def test_non_search_engine_ptr_is_rejected(self):
        ok = aag._verify_search_engine(
            self.IP4,
            lambda ip: ("host-1-2-3-4.evil.example", [], [ip]),
            lambda host, port: self._addrinfo(self.IP4))
        self.assertFalse(ok)

    def test_lookalike_domain_is_rejected(self):
        ok = aag._verify_search_engine(
            self.IP4,
            lambda ip: ("crawl.evilgooglebot.com", [], [ip]),
            lambda host, port: self._addrinfo(self.IP4))
        self.assertFalse(ok)

    def test_missing_ptr_record_is_rejected(self):
        import socket

        def no_ptr(ip):
            raise socket.herror(1, "Unknown host")
        ok = aag._verify_search_engine(
            self.IP4, no_ptr, lambda host, port: self._addrinfo(self.IP4))
        self.assertFalse(ok)


class ScanningLabel(unittest.TestCase):
    def test_pure_404_scanner_is_scanning(self):
        lines = [log_line(IP, "GET", f"/old/{i}", 404, UA_BROWSER) for i in range(60)]
        label, _, _, _ = aag.classify(parse_lines(lines)[IP])
        self.assertEqual(label, "SCANNING")

    def test_scanner_with_bot_ua_is_scanning_not_scraping(self):
        lines = [log_line(IP, "GET", f"/old/{i}", 404, UA_SCRAPER) for i in range(60)]
        label, _, _, _ = aag.classify(parse_lines(lines)[IP])
        self.assertEqual(label, "SCANNING")

    def test_user_on_broken_site_is_not_scanning(self):
        # Mostly-successful browsing with a missing asset: 404s are a
        # minority of traffic.
        lines = [log_line(IP, "GET", f"/page/{i % 30}", 200, UA_BROWSER)
                 for i in range(140)]
        lines += [log_line(IP, "GET", f"/missing/{i % 10}.css", 404, UA_BROWSER)
                  for i in range(60)]
        label, _, reason, _ = aag.classify(parse_lines(lines)[IP])
        self.assertEqual(label, "OTHER")
        self.assertNotIn("404", reason)


if __name__ == "__main__":
    unittest.main()
