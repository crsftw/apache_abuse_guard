#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
apache_abuse_guard.py  —  Apache log abuse analyzer + interactive iptables blocker

Parses Apache access.log + error.log, identifies likely BRUTEFORCE and SCRAPING
sources, builds a colored report (source IP, hits, country, ISP, behavior), then
lets you tick the IPs you want to ban (SPACE to select) and drops them with
iptables / ip6tables.

  Usage:
      sudo ./apache_abuse_guard.py
      sudo ./apache_abuse_guard.py --access /var/log/apache2/access.log \
                                   --error  /var/log/apache2/error.log \
                                   --min-count 50

  Keys in the selector:  ↑/↓ move · SPACE toggle · a all · n none
                         ENTER ban selected · q/ESC quit
"""

import argparse
import ipaddress
import json
import os
import re
import sys
import time
import urllib.request
from collections import Counter

# -----------------------------------------------------------------------------
# Palette (bpytop-ish: dark, neon accents). 256-color ANSI for the static report.
# -----------------------------------------------------------------------------
class C:
    RST = "\033[0m"
    B   = "\033[1m"
    DIM = "\033[2m"
    # foregrounds (xterm-256)
    GREEN  = "\033[38;5;47m"
    CYAN   = "\033[38;5;51m"
    BLUE   = "\033[38;5;39m"
    MAG    = "\033[38;5;201m"
    PINK   = "\033[38;5;213m"
    RED    = "\033[38;5;196m"
    ORANGE = "\033[38;5;208m"
    YELLOW = "\033[38;5;226m"
    GREY   = "\033[38;5;245m"
    WHITE  = "\033[38;5;255m"
    PURPLE = "\033[38;5;141m"

def supports_color():
    return sys.stdout.isatty() and os.environ.get("TERM", "") not in ("", "dumb")

NOCOLOR = not supports_color()
def col(s, c):
    return s if NOCOLOR else f"{c}{s}{C.RST}"

# -----------------------------------------------------------------------------
# Signatures
# -----------------------------------------------------------------------------
# Paths that strongly imply auth bruteforce / exploit probing.
AUTH_PATH_RE = re.compile(
    r"(wp-login\.php|xmlrpc\.php|/administrator|/admin\b|/wp-admin|phpmyadmin|"
    r"/\.env|/\.git|wp-config|setup\.php|/boaform|/cgi-bin|eval-stdin|"
    r"/vendor/phpunit|/login|/signin|/user/login|/api/login|/owa/|/autodiscover)",
    re.IGNORECASE,
)

# User agents of automated scrapers / harvesters (NOT search engines we keep).
SCRAPER_UA_RE = re.compile(
    r"(bytespider|claudebot|gptbot|ccbot|imagebot|img2dataset|ahrefsbot|semrushbot|"
    r"mj12bot|dotbot|dataforseo|blexbot|petalbot|amazonbot|facebookexternalhit|"
    r"scrapy|python-requests|python-urllib|go-http-client|curl/|wget|libwww|"
    r"httpclient|okhttp|masscan|zgrab|nuclei|httrack|node-fetch|axios|"
    r"\bcrawler\b|\bspider\b|\bharvest\b|\bscan\b)",
    re.IGNORECASE,
)

# Search engines we treat as legitimate (never auto-flagged as scraping).
LEGIT_UA_RE = re.compile(
    r"(googlebot|google-inspectiontool|storebot-google|bingbot|adidxbot|"
    r"duckduckbot|yandexbot|applebot|baiduspider|slurp|uptimerobot|"
    r"pingdom|wordpress/)",
    re.IGNORECASE,
)

# Friendly service/scraper names, matched against the dominant UA (first hit wins).
AGENT_MAP = [
    (r"bytespider",                "Bytespider (ByteDance)"),
    (r"claudebot",                 "ClaudeBot (Anthropic)"),
    (r"gptbot",                    "GPTBot (OpenAI)"),
    (r"oai-searchbot|chatgpt",     "OpenAI SearchBot"),
    (r"ccbot",                     "CCBot (Common Crawl)"),
    (r"img2dataset|imagebot",      "ImageBot / img2dataset"),
    (r"ahrefsbot",                 "AhrefsBot"),
    (r"semrushbot",                "SemrushBot"),
    (r"mj12bot",                   "MJ12bot (Majestic)"),
    (r"dotbot",                    "DotBot (Moz)"),
    (r"dataforseo",                "DataForSeoBot"),
    (r"blexbot",                   "BLEXBot"),
    (r"petalbot",                  "PetalBot (Huawei)"),
    (r"amazonbot",                 "Amazonbot"),
    (r"facebookexternalhit|facebookbot", "Facebook"),
    (r"google-inspectiontool",     "Google InspectionTool"),
    (r"googlebot|storebot-google", "Googlebot"),
    (r"adidxbot|bingbot",          "Bingbot"),
    (r"yandexbot",                 "YandexBot"),
    (r"applebot",                  "Applebot"),
    (r"duckduckbot",               "DuckDuckBot"),
    (r"baiduspider",               "Baiduspider"),
    (r"\bslurp\b",                 "Yahoo! Slurp"),
    (r"uptimerobot",               "UptimeRobot"),
    (r"pingdom",                   "Pingdom"),
    (r"wordpress/",                "WordPress (cron/pingback)"),
    (r"scrapy",                    "Scrapy"),
    (r"python-requests",           "python-requests"),
    (r"python-urllib|urllib",      "python-urllib"),
    (r"go-http-client",            "Go-http-client"),
    (r"node-fetch",                "node-fetch"),
    (r"\baxios\b",                 "axios"),
    (r"okhttp",                    "OkHttp"),
    (r"libwww",                    "libwww-perl"),
    (r"curl/",                     "curl"),
    (r"\bwget\b",                  "Wget"),
    (r"httrack",                   "HTTrack"),
    (r"masscan",                   "masscan"),
    (r"zgrab",                     "zgrab"),
    (r"nuclei",                    "Nuclei"),
    (r"\bbot\b|\bspider\b|\bcrawler\b", "generic bot/crawler"),
    # browsers last — only if nothing more specific matched
    (r"edg/|edge/",                "Edge"),
    (r"firefox/",                  "Firefox"),
    (r"chrome/",                   "Chrome (UA)"),
    (r"safari/",                   "Safari"),
    (r"msie|trident/",             "Internet Explorer"),
]
AGENT_MAP = [(re.compile(p, re.IGNORECASE), name) for p, name in AGENT_MAP]


def agent_label(ua):
    """Map a raw user-agent string to a short service/scraper/browser name."""
    if not ua or ua == "-":
        return "(no UA)"
    for rx, name in AGENT_MAP:
        if rx.search(ua):
            return name
    return ua[:24]  # unknown → show the start of the raw UA


def top_targets(counter, n=3, pathwidth=34):
    """Most-hit paths for an IP, e.g. '/wp-login.php ×550  /xmlrpc.php ×12'."""
    if not counter:
        return "-"
    parts = []
    for path, c in counter.most_common(n):
        p = path if path else "/"
        if len(p) > pathwidth:
            p = p[:pathwidth - 1] + "…"
        parts.append(f"{p} ×{c}")
    extra = len(counter) - n
    s = "   ".join(parts)
    if extra > 0:
        s += f"   (+{extra} more)"
    return s


# Apache combined log line
LINE_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<req>[^"]*)"\s+(?P<status>\d{3}|-)\s+(?P<size>\d+|-)\s+'
    r'"(?P<ref>[^"]*)"\s+"(?P<ua>[^"]*)"'
)
ERR_CLIENT_RE = re.compile(r'\[client (?P<ip>[^\]]+?)\]')


def is_internal(ip):
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local or a.is_reserved
    except ValueError:
        return True  # unparseable → skip


def strip_port(token):
    """'1.2.3.4:567' or '2607:f8b0:...:41194' -> ip without trailing :port."""
    token = token.strip()
    if ":" in token:
        head, _, tail = token.rpartition(":")
        if tail.isdigit() and head:
            token = head
    return token


# -----------------------------------------------------------------------------
# Aggregation
# -----------------------------------------------------------------------------
class Stat:
    __slots__ = ("ip", "hits", "post", "get", "auth_hits", "unauth", "notfound",
                 "path_counts", "bytes", "scraper_ua", "legit_ua", "denied", "ua_counts",
                 "country", "isp")

    def __init__(self, ip):
        self.ip = ip
        self.hits = 0
        self.post = 0
        self.get = 0
        self.auth_hits = 0
        self.unauth = 0        # 401/403
        self.notfound = 0      # 404
        self.path_counts = Counter()
        self.bytes = 0
        self.scraper_ua = False
        self.legit_ua = False
        self.denied = 0        # from error.log
        self.ua_counts = Counter()
        self.country = "?"
        self.isp = "?"


def parse_access(path, stats):
    if not os.path.exists(path):
        print(col(f"[!] access log not found: {path}", C.RED))
        return
    with open(path, "r", errors="replace") as fh:
        for line in fh:
            m = LINE_RE.match(line)
            if not m:
                continue
            ip = m.group("ip")
            if is_internal(ip):
                continue
            s = stats[ip]
            s.hits += 1
            req = m.group("req")
            parts = req.split(" ", 2)
            method = parts[0] if parts else "-"
            url = parts[1] if len(parts) > 1 else ""
            if method == "POST":
                s.post += 1
            elif method == "GET":
                s.get += 1
            if url:
                s.path_counts[url.split("?", 1)[0]] += 1
            if AUTH_PATH_RE.search(url):
                s.auth_hits += 1
            status = m.group("status")
            if status in ("401", "403"):
                s.unauth += 1
            elif status == "404":
                s.notfound += 1
            size = m.group("size")
            if size.isdigit():
                s.bytes += int(size)
            ua = m.group("ua")
            if ua and ua != "-":
                s.ua_counts[ua] += 1
                if SCRAPER_UA_RE.search(ua):
                    s.scraper_ua = True
                if LEGIT_UA_RE.search(ua):
                    s.legit_ua = True
            else:
                s.ua_counts["-"] += 1


def parse_error(path, stats):
    if not os.path.exists(path):
        return
    with open(path, "r", errors="replace") as fh:
        for line in fh:
            m = ERR_CLIENT_RE.search(line)
            if not m:
                continue
            ip = strip_port(m.group("ip"))
            if is_internal(ip):
                continue
            stats[ip].denied += 1


# -----------------------------------------------------------------------------
# Classification
# -----------------------------------------------------------------------------
def classify(s):
    """Return (label, color, reason, preselect)."""
    bf_score = s.auth_hits + s.unauth + s.denied
    # BRUTEFORCE: hammering auth/exploit endpoints or piling up 401/403/denied.
    if (s.auth_hits >= 10 or s.unauth >= 25 or s.denied >= 25 or
            (s.auth_hits >= 5 and s.post >= 5)):
        bits = []
        if s.auth_hits:
            bits.append(f"{s.auth_hits} auth-path hits")
        if s.unauth:
            bits.append(f"{s.unauth}x 401/403")
        if s.denied:
            bits.append(f"{s.denied} denied(err)")
        return "BRUTEFORCE", C.RED, ", ".join(bits) or "auth probing", True

    # SCRAPING: automated UA OR very high-volume, wide-surface crawling.
    if not s.legit_ua and (
        (s.scraper_ua and s.hits >= 50) or
        (s.get >= 300 and len(s.path_counts) >= 100) or
        (s.hits >= 800 and len(s.path_counts) >= 50)
    ):
        bits = []
        if s.scraper_ua:
            bits.append("bot UA")
        bits.append(f"{len(s.path_counts)} URLs / {s.get} GET")
        # Not pre-selected: scraping is often legitimate-ish (AI/SEO bots);
        # leave the choice to the operator. Only bruteforce is pre-ticked.
        return "SCRAPING", C.YELLOW, ", ".join(bits), False

    # Aggressive 404 probing without auth match → still suspicious.
    if s.notfound >= 50 and s.hits >= 80:
        return "OTHER", C.ORANGE, f"{s.notfound}x 404 probing", False

    if s.legit_ua:
        return "OTHER", C.GREY, "known search engine / WP", False

    return "OTHER", C.PURPLE, f"{s.hits} hits, {len(s.path_counts)} URLs", False


# -----------------------------------------------------------------------------
# GeoIP / ISP via ip-api.com batch (free, no key, 100 IPs/req)
# -----------------------------------------------------------------------------
def geo_lookup(rows, enabled):
    if not enabled:
        return
    ips = [r["ip"] for r in rows if ":" not in r["ip"] or True]  # v4+v6 both ok
    fields = "status,country,isp,query"
    headers = {"Content-Type": "application/json", "User-Agent": "abuse-guard/1.0"}
    cache = {}
    for i in range(0, len(ips), 100):
        chunk = ips[i:i + 100]
        payload = json.dumps([{"query": ip, "fields": fields} for ip in chunk]).encode()
        try:
            req = urllib.request.Request("http://ip-api.com/batch", data=payload,
                                         headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode())
            for entry in data:
                q = entry.get("query")
                if entry.get("status") == "success":
                    cache[q] = (entry.get("country", "?"), entry.get("isp", "?"))
                else:
                    cache[q] = ("?", "?")
        except Exception as e:
            sys.stderr.write(col(f"[!] geo lookup failed for a batch: {e}\n", C.RED))
        if i + 100 < len(ips):
            time.sleep(4)  # stay under the 15 req/min batch limit
    for r in rows:
        c, isp = cache.get(r["ip"], ("?", "?"))
        r["country"], r["isp"] = c, isp


# -----------------------------------------------------------------------------
# Static report
# -----------------------------------------------------------------------------
def banner():
    bar = "─" * 78
    print(col(bar, C.PURPLE))
    print(col("  APACHE ABUSE GUARD ", C.B + C.MAG) +
          col("· bruteforce / scraping detector", C.GREY))
    print(col(bar, C.PURPLE))


def print_report(rows):
    hdr = (f"  {'SOURCE IP':<22}{'HITS':>7}  {'COUNTRY':<15}{'ISP':<20}"
           f"{'BEHAVIOR':<11}{'AGENT / SERVICE':<26}{'DETAIL':<34}TARGETED PATHS")
    print(col(hdr, C.B + C.CYAN))
    print(col("  " + "─" * 150, C.DIM + C.GREY))
    for r in rows:
        ipc = col(f"{r['ip']:<22}", C.WHITE)
        hitc = col(f"{r['hits']:>7}", C.GREEN)
        ctry = (r["country"] or "?")[:14]
        isp = (r["isp"] or "?")[:19]
        lbl = col(f"{r['label']:<11}", r["color"])
        agent = col(f"{r['agent'][:25]:<26}", C.PINK)
        detail = col(f"{r['reason'][:33]:<34}", C.GREY)
        targets = col(r["targets"], C.BLUE)
        print(f"  {ipc}{hitc}  {ctry:<15}{isp:<20}{lbl}{agent}{detail}{targets}")
    print(col("  " + "─" * 150, C.DIM + C.GREY))
    bf = sum(1 for r in rows if r["label"] == "BRUTEFORCE")
    sc = sum(1 for r in rows if r["label"] == "SCRAPING")
    ot = sum(1 for r in rows if r["label"] == "OTHER")
    print(col(f"  {len(rows)} suspicious IPs  ", C.B) +
          col(f"{bf} bruteforce", C.RED) + col(" · ", C.GREY) +
          col(f"{sc} scraping", C.YELLOW) + col(" · ", C.GREY) +
          col(f"{ot} other", C.PURPLE))
    print()


# -----------------------------------------------------------------------------
# curses selector
# -----------------------------------------------------------------------------
def run_selector(rows):
    import curses

    LABEL_PAIR = {"BRUTEFORCE": 1, "SCRAPING": 2, "OTHER": 3}

    def _ui(stdscr):
        curses.curs_set(0)
        curses.use_default_colors()
        # neon-ish pairs
        curses.init_pair(1, curses.COLOR_RED, -1)
        curses.init_pair(2, curses.COLOR_YELLOW, -1)
        curses.init_pair(3, curses.COLOR_MAGENTA, -1)
        curses.init_pair(4, curses.COLOR_CYAN, -1)
        curses.init_pair(5, curses.COLOR_GREEN, -1)
        curses.init_pair(6, curses.COLOR_WHITE, -1)
        try:
            curses.init_pair(7, curses.COLOR_BLACK, curses.COLOR_CYAN)
        except curses.error:
            pass

        pos = 0
        top = 0

        while True:
            stdscr.erase()
            h, w = stdscr.getmaxyx()
            stdscr.addstr(0, 0, " APACHE ABUSE GUARD — select IPs to BAN ".ljust(w - 1),
                          curses.color_pair(4) | curses.A_BOLD)
            stdscr.addstr(1, 0, " SPACE toggle · ↑/↓ move · a all · n none · ENTER ban · q quit",
                          curses.color_pair(6) | curses.A_DIM)
            colhdr = (f"     {'SOURCE IP':<22}{'HITS':>7}  {'COUNTRY':<13}"
                      f"{'ISP':<18}{'BEHAVIOR':<11}{'AGENT / SERVICE':<22}TARGETED PATHS")
            stdscr.addstr(2, 0, colhdr[:w - 1].ljust(w - 1),
                          curses.color_pair(4) | curses.A_BOLD)
            list_h = h - 5
            if pos < top:
                top = pos
            elif pos >= top + list_h:
                top = pos - list_h + 1

            for idx in range(top, min(len(rows), top + list_h)):
                r = rows[idx]
                y = 4 + (idx - top)
                mark = "[x]" if r["selected"] else "[ ]"
                line = (f" {mark} {r['ip']:<21}{r['hits']:>7}  "
                        f"{(r['country'] or '?')[:12]:<13}"
                        f"{(r['isp'] or '?')[:16]:<18}"
                        f"{r['label']:<11}{r['agent'][:20]:<22}{r['targets']}")
                line = line[:w - 1].ljust(w - 1)
                attr = curses.color_pair(LABEL_PAIR.get(r["label"], 3))
                if idx == pos:
                    attr = curses.color_pair(7) | curses.A_BOLD
                elif r["selected"]:
                    attr |= curses.A_BOLD
                stdscr.addstr(y, 0, line, attr)

            nsel = sum(1 for r in rows if r["selected"])
            stdscr.addstr(h - 1, 0,
                          f" {nsel} selected / {len(rows)} total ".ljust(w - 1),
                          curses.color_pair(5) | curses.A_BOLD)
            stdscr.refresh()

            k = stdscr.getch()
            if k in (curses.KEY_UP, ord("k")):
                pos = max(0, pos - 1)
            elif k in (curses.KEY_DOWN, ord("j")):
                pos = min(len(rows) - 1, pos + 1)
            elif k == curses.KEY_NPAGE:
                pos = min(len(rows) - 1, pos + list_h)
            elif k == curses.KEY_PPAGE:
                pos = max(0, pos - list_h)
            elif k == ord(" "):
                rows[pos]["selected"] = not rows[pos]["selected"]
            elif k == ord("a"):
                for r in rows:
                    r["selected"] = True
            elif k == ord("n"):
                for r in rows:
                    r["selected"] = False
            elif k in (10, 13, curses.KEY_ENTER):
                return True
            elif k in (27, ord("q")):
                return False

    return curses.wrapper(_ui)


# -----------------------------------------------------------------------------
# iptables blocking
# -----------------------------------------------------------------------------
import subprocess

CHAIN = "APACHE_ABUSE"

def _run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)


def get_blocked_networks():
    """Collect source IPs/CIDRs already blocked anywhere in the firewall.

    Scans both iptables and ip6tables for rules that DROP/REJECT a specific
    source (covers fail2ban's REJECT rules, manual drops, and our own
    APACHE_ABUSE chain). Returns a list of ip_network objects. Requires root
    to read the ruleset; returns [] (no filtering) otherwise.
    """
    nets = []
    src_re = re.compile(r"-s (\S+)")
    for binary in ("iptables", "ip6tables"):
        res = _run([binary, "-S"])
        if res.returncode != 0:
            continue
        for line in res.stdout.splitlines():
            if " -j DROP" not in line and " -j REJECT" not in line:
                continue
            m = src_re.search(line)
            if not m:
                continue
            try:
                nets.append(ipaddress.ip_network(m.group(1), strict=False))
            except ValueError:
                pass
    return nets


def is_blocked(ip, nets):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for n in nets:
        if addr.version == n.version and addr in n:
            return True
    return False


def ensure_chain(bin_):
    # create dedicated chain + hook it into INPUT once (idempotent)
    if _run([bin_, "-n", "-L", CHAIN]).returncode != 0:
        _run([bin_, "-N", CHAIN])
    if _run([bin_, "-C", "INPUT", "-j", CHAIN]).returncode != 0:
        _run([bin_, "-I", "INPUT", "1", "-j", CHAIN])

def save_rules():
    """Persist iptables rules to /etc/iptables/rules.v4 (and rules.v6)."""
    import os
    os.makedirs("/etc/iptables", exist_ok=True)
    for binary, path in (("iptables-save", "/etc/iptables/rules.v4"),
                         ("ip6tables-save", "/etc/iptables/rules.v6")):
        res = _run([binary])
        if res.returncode == 0:
            try:
                with open(path, "w") as f:
                    f.write(res.stdout)
            except OSError:
                pass


def block_source(source):
    """Block an IP address or CIDR subnet (e.g. '1.2.3.4' or '1.2.3.0/24')."""
    # Detect IPv6 by a colon that isn't part of a CIDR prefix
    is6 = ":" in source.split("/")[0]
    bin_ = "ip6tables" if is6 else "iptables"
    ensure_chain(bin_)
    if _run([bin_, "-C", CHAIN, "-s", source, "-j", "DROP"]).returncode == 0:
        return ("skip", "already blocked")
    res = _run([bin_, "-A", CHAIN, "-s", source, "-j", "DROP"])
    if res.returncode == 0:
        save_rules()
        return ("ok", "DROP added")
    return ("err", (res.stderr or res.stdout).strip())


# Keep old name as alias for backward compat
block_ip = block_source


def subnet_report(rows):
    """Aggregate flagged IPs by /24 (IPv4) or /48 (IPv6) and show hot subnets."""
    from collections import defaultdict
    nets = defaultdict(list)
    for r in rows:
        ip = r["ip"]
        try:
            addr = ipaddress.ip_address(ip)
            if addr.version == 4:
                net = str(ipaddress.ip_network(f"{ip}/24", strict=False))
            else:
                net = str(ipaddress.ip_network(f"{ip}/48", strict=False))
        except ValueError:
            continue
        nets[net].append(r)

    clusters = [(net, rs) for net, rs in nets.items() if len(rs) >= 3]
    if not clusters:
        return
    clusters.sort(key=lambda x: -sum(r["hits"] for r in x[1]))

    print(col("\n  ── SUBNET CLUSTERS (3+ offenders in same /24 or /48) ──", C.B + C.CYAN))
    hdr = f"  {'SUBNET':<22}{'IPs':>5}{'TOTAL HITS':>12}  {'COUNTRY':<15}{'ISP / ORG'}"
    print(col(hdr, C.CYAN))
    print(col("  " + "─" * 90, C.DIM + C.GREY))
    for net, rs in clusters:
        total_hits = sum(r["hits"] for r in rs)
        country = rs[0].get("country") or "?"
        isp = rs[0].get("isp") or "?"
        print(f"  {col(net, C.WHITE):<31}{len(rs):>5}{col(str(total_hits), C.GREEN):>20}  "
              f"{country[:14]:<15}{col(isp[:40], C.PINK)}")
    print(col("  " + "─" * 90, C.DIM + C.GREY))
    print(col(f"  Tip: block a whole subnet with  ", C.GREY) +
          col(f"iptables -A {CHAIN} -s <subnet> -j DROP", C.CYAN))
    print()
    return clusters


def apply_bans(selected):
    print()
    print(col("  Applying iptables rules…", C.B + C.CYAN))
    ok = err = skip = 0
    for r in selected:
        st, msg = block_source(r["ip"])
        if st == "ok":
            ok += 1
            print(col(f"  ✔ BLOCKED {r['ip']:<40}", C.GREEN) + col(msg, C.GREY))
        elif st == "skip":
            skip += 1
            print(col(f"  • SKIP    {r['ip']:<40}", C.YELLOW) + col(msg, C.GREY))
        else:
            err += 1
            print(col(f"  ✗ ERROR  {r['ip']:<40}", C.RED) + col(msg, C.GREY))
    print()
    print(col(f"  Done: {ok} blocked, {skip} already present, {err} errors.",
              C.B + (C.GREEN if err == 0 else C.RED)))
    if ok:
        print(col(f"  Rules live in chain '{CHAIN}'. Review: ", C.GREY) +
              col(f"iptables -nL {CHAIN}", C.CYAN))
        print(col("  To undo everything: ", C.GREY) +
              col(f"iptables -F {CHAIN}", C.CYAN))


def apply_subnet_bans(clusters):
    """Interactively block whole /24 subnets identified as swarms."""
    if not clusters:
        return
    print(col("\n  ── SUBNET BLOCK ──", C.B + C.RED))
    print(col("  The subnets below each have 3+ scrapers. Block the whole /24 instead of", C.GREY))
    print(col("  individual IPs to stop respawning scrapers pre-emptively.", C.GREY))
    print()
    choices = []
    for i, (net, rs) in enumerate(clusters):
        total = sum(r["hits"] for r in rs)
        isp = rs[0].get("isp") or "?"
        country = rs[0].get("country") or "?"
        print(col(f"  [{i+1}] {net:<22}", C.WHITE) +
              col(f" {len(rs)} IPs / {total} hits", C.GREEN) +
              col(f"  {country} — {isp}", C.GREY))
        choices.append(net)
    print()
    try:
        ans = input(col("  Enter subnet numbers to block (e.g. 1,3) or 'a' for all, ENTER to skip: ",
                        C.B + C.CYAN)).strip().lower()
    except EOFError:
        return
    if not ans:
        return
    if ans == "a":
        selected_nets = choices
    else:
        try:
            idxs = [int(x.strip()) - 1 for x in ans.split(",")]
            selected_nets = [choices[i] for i in idxs if 0 <= i < len(choices)]
        except (ValueError, IndexError):
            print(col("  Invalid input; skipping subnet blocks.", C.YELLOW))
            return
    if not selected_nets:
        return
    ok = err = skip = 0
    for net in selected_nets:
        st, msg = block_source(net)
        if st == "ok":
            ok += 1
            print(col(f"  ✔ BLOCKED subnet {net:<28}", C.GREEN) + col(msg, C.GREY))
        elif st == "skip":
            skip += 1
            print(col(f"  • SKIP    subnet {net:<28}", C.YELLOW) + col(msg, C.GREY))
        else:
            err += 1
            print(col(f"  ✗ ERROR  subnet {net:<28}", C.RED) + col(msg, C.GREY))
    print(col(f"\n  Subnets: {ok} blocked, {skip} already present, {err} errors.",
              C.B + (C.GREEN if err == 0 else C.RED)))


# -----------------------------------------------------------------------------
# main
# -----------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="Apache abuse analyzer + iptables blocker")
    ap.add_argument("--access", default="/var/log/apache2/access.log")
    ap.add_argument("--error", default="/var/log/apache2/error.log")
    ap.add_argument("--min-count", type=int, default=50,
                    help="min request count for an IP to be considered (default 50)")
    ap.add_argument("--top", type=int, default=200,
                    help="cap report to N worst offenders (default 200)")
    ap.add_argument("--no-geo", action="store_true", help="skip country/ISP lookup")
    ap.add_argument("--no-ban", action="store_true", help="report only, never ban")
    args = ap.parse_args()

    banner()
    print(col(f"  Parsing {args.access} …", C.GREY))

    class _StatDict(dict):
        def __missing__(self, k):
            v = Stat(k)
            self[k] = v
            return v
    stats = _StatDict()

    parse_access(args.access, stats)
    print(col(f"  Parsing {args.error} …", C.GREY))
    parse_error(args.error, stats)

    # Already-blocked sources (fail2ban, manual drops, our own chain) are hidden.
    blocked_nets = get_blocked_networks()
    if blocked_nets:
        print(col(f"  Found {len(blocked_nets)} existing firewall block rule(s); "
                  "matching IPs will be hidden.", C.GREY))

    # classify + filter
    rows = []
    already_blocked = 0
    for ip, s in stats.items():
        label, color, reason, pre = classify(s)
        # keep flagged ones, plus any high-volume IP above min-count
        if label in ("BRUTEFORCE", "SCRAPING") or s.hits >= args.min_count:
            if is_blocked(ip, blocked_nets):
                already_blocked += 1
                continue
            dom_ua = s.ua_counts.most_common(1)[0][0] if s.ua_counts else "-"
            n_distinct = len(s.ua_counts)
            agent = agent_label(dom_ua)
            if n_distinct > 1:
                agent += f" (+{n_distinct - 1})"
            rows.append({
                "ip": ip, "hits": s.hits, "label": label, "color": color,
                "reason": reason, "selected": pre, "country": "?", "isp": "?",
                "agent": agent, "targets": top_targets(s.path_counts),
            })

    if already_blocked:
        print(col(f"  Hid {already_blocked} suspicious IP(s) already blocked in the firewall.",
                  C.GREY))

    if not rows:
        print(col("\n  No (unblocked) suspicious IPs found above thresholds. Nothing to do.",
                  C.GREEN))
        return

    # rank: bruteforce > scraping > other, then by hits
    order = {"BRUTEFORCE": 0, "SCRAPING": 1, "OTHER": 2}
    rows.sort(key=lambda r: (order[r["label"]], -r["hits"]))
    rows = rows[:args.top]

    print(col(f"  Looking up geolocation/ISP for {len(rows)} IPs…", C.GREY)
          if not args.no_geo else col("  Geo lookup skipped.", C.GREY))
    geo_lookup(rows, enabled=not args.no_geo)
    print()

    print_report(rows)

    # Show subnet clusters — groups of 3+ offending IPs in the same /24
    clusters = subnet_report(rows)

    if args.no_ban:
        print(col("  --no-ban set; report only.", C.YELLOW))
        return
    if os.geteuid() != 0:
        print(col("  Not running as root — cannot apply iptables rules. "
                  "Re-run with sudo to ban.", C.YELLOW))
        return

    # Offer subnet-level blocking first when swarms are detected
    if clusters:
        apply_subnet_bans(clusters)

    try:
        ans = input(col("  Open interactive ban selector (individual IPs)? [Y/n] ",
                        C.B + C.CYAN)).strip().lower()
    except EOFError:
        ans = "n"
    if ans in ("n", "no"):
        print(col("  Aborted; no individual IPs banned.", C.YELLOW))
        return

    confirmed = run_selector(rows)
    selected = [r for r in rows if r["selected"]]
    if not confirmed:
        print(col("\n  Cancelled; no IPs banned.", C.YELLOW))
        return
    if not selected:
        print(col("\n  Nothing selected; no IPs banned.", C.YELLOW))
        return

    print(col(f"\n  About to DROP {len(selected)} IP(s) via iptables:", C.B + C.RED))
    for r in selected:
        print(col(f"    {r['ip']:<40}", C.WHITE) + col(r["label"], r["color"]))
    try:
        final = input(col("  Type 'yes' to confirm: ", C.B + C.RED)).strip().lower()
    except EOFError:
        final = "no"
    if final != "yes":
        print(col("  Aborted; no IPs banned.", C.YELLOW))
        return

    apply_bans(selected)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(col("\n  Interrupted.", C.YELLOW))
        sys.exit(130)
