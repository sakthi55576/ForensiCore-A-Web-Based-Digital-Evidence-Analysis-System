"""
Chrome / Edge browser-history analyzer.

Improvements over the first version
-----------------------------------
* The database is opened READ-ONLY and immutable, so analysis can never
  change the evidence (and therefore never break its hash).
* ALL URLs are analysed (the old code read only 100 rows and reported
  "Total URLs: 100"). Downloads, search terms and individual visits are
  read too.
* Times are converted to UTC and labelled as such.
* The risk score no longer treats "visited 50+ times" or plain HTTP as
  suspicious. It is built from real indicators: suspicious search terms
  and pages, dangerous / executable downloads and IP-address URLs.
* Findings and timeline events are produced for the case-level views.
"""

import ipaddress
import re
from collections import Counter
from datetime import datetime, timedelta, timezone

from app.utils.findings import make_finding, level_from_score
from app.utils.sqliteutil import open_readonly

CHROME_EPOCH = datetime(1601, 1, 1)

MAX_STORED_HISTORY = 100      # top URLs shown in the report
MAX_STORED_VISITS = 150       # most recent visits shown as timeline
MAX_STORED_DOWNLOADS = 100
MAX_STORED_SEARCHES = 100
MAX_EVENTS = 250
FULL_HISTORY_LIMIT = 5000

TRANSITIONS = {
    0: "Link", 1: "Typed", 2: "Bookmark", 3: "Subframe",
    4: "Subframe", 5: "Address bar", 6: "Start page",
    7: "Form submit", 8: "Reload", 9: "Keyword", 10: "Keyword"
}

# Keyword categories (regular expressions, matched case-insensitively).
# A match is an INDICATOR for review, never proof of intent.
SUSPICIOUS_TERMS = {
    "Hacking / malware": [
        r"\bhack(ing|er|ers)\b", r"keylogger", r"ransomware",
        r"\bmalware\b", r"\bexploit\b", r"sql injection", r"\bddos\b",
        r"phishing kit", r"reverse shell", r"metasploit",
        r"crack(ing)? password", r"password dump"
    ],
    "Anti-forensics / evasion": [
        r"anti[- ]?forensic", r"wipe (my )?(traces|evidence|history)",
        r"cover (my )?tracks", r"secure(ly)? delete",
        r"delete (browsing )?history permanently"
    ],
    "Dark web / illegal marketplace": [
        r"\bdark ?web\b", r"\bdarknet\b", r"\.onion\b",
        r"\btor browser\b", r"silk road", r"buy (drugs|weapons|guns)"
    ],
    "Piracy / cracked software": [
        r"\bkeygen\b", r"\bwarez\b", r"crack(ed)? (software|version|download)",
        r"serial key", r"\bnulled\b", r"free torrent"
    ],
    "Fraud / identity": [
        r"fake (id|passport|aadhaar|certificate|degree)",
        r"credit card (dump|generator)", r"\bcarding\b",
        r"otp bypass", r"sim swap", r"upi fraud"
    ],
}

_COMPILED = {
    category: [re.compile(p, re.IGNORECASE) for p in patterns]
    for category, patterns in SUSPICIOUS_TERMS.items()
}

EXECUTABLE_EXT = (
    ".exe", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar",
    ".scr", ".apk", ".dmg", ".iso", ".lnk", ".hta"
)

ARCHIVE_EXT = (".zip", ".rar", ".7z", ".tar", ".gz")

# Chrome download danger_type values that mean "Chrome warned about it"
DANGEROUS_TYPES = {1, 2, 3, 7, 8}

IP_URL_RE = re.compile(r"^https?://(?:\d{1,3}\.){3}\d{1,3}(?:[:/]|$)", re.I)


# ==========================================
# TIME
# ==========================================

def chrome_to_datetime(chrome_time):

    """Chrome timestamp (microseconds since 1601, UTC) -> naive UTC."""

    try:

        if not chrome_time or int(chrome_time) <= 0:
            return None

        moment = CHROME_EPOCH + timedelta(microseconds=int(chrome_time))

        if not (1995 <= moment.year <= 2100):
            return None

        return moment

    except (OverflowError, ValueError, TypeError):
        return None


def convert_chrome_time(chrome_time):

    moment = chrome_to_datetime(chrome_time)

    return (
        moment.strftime("%Y-%m-%d %H:%M:%S") if moment else "Unknown"
    )


def _columns(connection, table):

    try:
        return {
            row[1] for row in
            connection.execute("PRAGMA table_info({})".format(table))
        }
    except Exception:
        return set()


def _is_public_ip_url(url):

    """Loopback / LAN addresses (OAuth callbacks, routers) are normal."""

    match = re.match(r"https?://((?:\d{1,3}\.){3}\d{1,3})", url or "", re.I)

    if not match:
        return False

    try:
        ip = ipaddress.ip_address(match.group(1))
    except ValueError:
        return False

    return not (ip.is_private or ip.is_loopback or ip.is_link_local)


def _match_terms(text):

    """Categories whose patterns match text."""

    hits = []

    for category, patterns in _COMPILED.items():

        if any(p.search(text) for p in patterns):
            hits.append(category)

    return hits


def _filename(path):

    return (path or "").replace("\\", "/").rsplit("/", 1)[-1]


# ==========================================
# EXTRACTION (read-only)
# ==========================================

def extract_history(history_file, limit=None):

    """
    All URLs ordered by most recent visit (used by the full-history
    page). Returns {"Total URLs": n, "History": [...]}.
    """

    result = {"Total URLs": 0, "History": []}

    connection = None

    try:

        connection = open_readonly(history_file)

        total = connection.execute(
            "SELECT COUNT(*) FROM urls"
        ).fetchone()[0]

        query = (
            "SELECT url, title, visit_count, last_visit_time "
            "FROM urls ORDER BY last_visit_time DESC"
        )

        if limit:
            query += " LIMIT {}".format(int(limit))

        result["Total URLs"] = total

        for url, title, visit_count, last_visit in connection.execute(query):

            result["History"].append({
                "URL": url,
                "Title": title or "No Title",
                "Visit Count": visit_count or 0,
                "Last Visit": convert_chrome_time(last_visit)
            })

    except Exception as error:

        result["Error"] = str(error)

    finally:

        if connection:
            connection.close()

    return result


def analyze_browser(history_file):

    """
    One pass over the evidence database.

    Returns a dict with: history_data, top_sites, timeline, risk_data,
    findings (unified) and events (timeline).
    """

    connection = open_readonly(history_file)

    try:

        # ------------------ URLs ------------------

        urls = connection.execute(
            "SELECT id, url, title, visit_count, typed_count, "
            "last_visit_time FROM urls"
        ).fetchall()

        # ------------------ visits ------------------

        visits_total = 0
        first_visit = last_visit = None
        hourly = [0] * 24
        typed_visits = 0
        recent_visits = []

        visit_columns = _columns(connection, "visits")

        if visit_columns:

            # Real Chrome databases have visits.transition; small or
            # exported databases may not.
            transition_sql = (
                "v.transition" if "transition" in visit_columns else "0"
            )

            rows = connection.execute(
                "SELECT v.visit_time, " + transition_sql + ", u.url, "
                "u.title, u.visit_count FROM visits v "
                "JOIN urls u ON u.id = v.url "
                "ORDER BY v.visit_time DESC"
            ).fetchall()

            visits_total = len(rows)

            for visit_time, transition, url, title, count in rows:

                moment = chrome_to_datetime(visit_time)

                if not moment:
                    continue

                hourly[moment.hour] += 1

                if last_visit is None:
                    last_visit = moment

                first_visit = moment

                core = (transition or 0) & 0xFF

                if core == 1:
                    typed_visits += 1

                if len(recent_visits) < MAX_STORED_VISITS:

                    recent_visits.append({
                        "Last Visit": moment.strftime("%Y-%m-%d %H:%M:%S"),
                        "URL": (url or "")[:500],
                        "Title": (title or "No Title")[:200],
                        "Visit Count": count or 0,
                        "Transition": TRANSITIONS.get(core, "Other")
                    })

        # ------------------ downloads ------------------

        downloads = []

        download_columns = _columns(connection, "downloads")

        if download_columns:

            wanted = [
                c for c in (
                    "target_path", "tab_url", "site_url", "total_bytes",
                    "start_time", "danger_type", "mime_type"
                ) if c in download_columns
            ]

            if wanted:

                order = "start_time" if "start_time" in wanted else wanted[0]

                rows = connection.execute(
                    "SELECT {} FROM downloads ORDER BY {} DESC LIMIT 1000"
                    .format(", ".join(wanted), order)
                ).fetchall()

                for row in rows:

                    record = dict(zip(wanted, row))

                    name = _filename(record.get("target_path"))

                    moment = chrome_to_datetime(record.get("start_time"))

                    downloads.append({
                        "File": name or "unknown",
                        "Source": (
                            record.get("tab_url")
                            or record.get("site_url") or ""
                        )[:300],
                        "Size": record.get("total_bytes") or 0,
                        "Time": (
                            moment.strftime("%Y-%m-%d %H:%M:%S")
                            if moment else "Unknown"
                        ),
                        "_time": moment,
                        "Danger Type": record.get("danger_type") or 0,
                        "Type": record.get("mime_type") or ""
                    })

        # ------------------ search terms ------------------

        searches = []

        if _columns(connection, "keyword_search_terms"):

            rows = connection.execute(
                "SELECT k.term, u.last_visit_time, u.url "
                "FROM keyword_search_terms k "
                "JOIN urls u ON u.id = k.url_id "
                "ORDER BY u.last_visit_time DESC LIMIT 2000"
            ).fetchall()

            for term, when, url in rows:

                moment = chrome_to_datetime(when)

                searches.append({
                    "Term": term,
                    "Time": (
                        moment.strftime("%Y-%m-%d %H:%M:%S")
                        if moment else "Unknown"
                    ),
                    "_time": moment
                })

    finally:

        connection.close()

    # ==================================================
    # RISK INDICATORS
    # ==================================================

    breakdown = []
    findings = []
    events = []
    score = 0

    # ---- 1. suspicious search terms (max 40) ----

    term_hits = {}

    for search in searches:

        for category in _match_terms(search["Term"] or ""):

            term_hits.setdefault(category, []).append(search)

    term_points = min(
        sum(min(15 * len(hits), 25) for hits in term_hits.values()), 40
    )

    if term_hits:

        score += term_points

        summary = "; ".join(
            "{} ({})".format(cat, ", ".join(
                sorted({h["Term"] for h in hits})[:3]
            ))
            for cat, hits in term_hits.items()
        )

        breakdown.append({
            "Factor": "Suspicious Search Terms", "Score": term_points,
            "Maximum": 40,
            "Observation": "Search terms matched: " + summary
        })

        findings.append(make_finding(
            "Suspicious search terms ({} categor{})".format(
                len(term_hits), "y" if len(term_hits) == 1 else "ies"
            ),
            summary + ". A keyword match is a lead, not proof of intent.",
            term_points, "Search terms"
        ))

        for hits in term_hits.values():

            for hit in hits:

                if hit["_time"]:

                    events.append({
                        "type": "suspicious_search",
                        "time": hit["_time"],
                        "title": "Searched: {}".format(hit["Term"][:120]),
                        "detail": "Matched a suspicious-terms category",
                        "severity": "MEDIUM",
                        "time_note": "UTC (Chrome timestamp)"
                    })

    else:

        breakdown.append({
            "Factor": "Suspicious Search Terms", "Score": 0, "Maximum": 40,
            "Observation": "No suspicious search terms among {} "
                           "searches.".format(len(searches))
        })

    # ---- 2. suspicious pages (max 12, low weight: titles of news / research pages match too) ----

    page_hits = []

    for _id, url, title, visit_count, typed, last in urls:

        text = "{} {}".format(url or "", title or "")

        categories = _match_terms(text)

        if categories:
            page_hits.append((url, title, categories, last))

    # The same page often appears under several URLs (redirects);
    # count each distinct page once.
    unique_pages = {}

    for hit in page_hits:
        unique_pages.setdefault((hit[1] or hit[0] or "").strip(), hit)

    page_hits = list(unique_pages.values())

    page_points = min(4 * len(page_hits), 12)

    if page_hits:

        score += page_points

        sample = "; ".join(
            "{}".format((h[0] or "")[:70]) for h in page_hits[:3]
        )

        breakdown.append({
            "Factor": "Suspicious Pages", "Score": page_points,
            "Maximum": 12,
            "Observation": "{} visited page(s) matched suspicious "
                           "terms: {}".format(len(page_hits), sample)
        })

        findings.append(make_finding(
            "{} visited page(s) matched suspicious terms".format(
                len(page_hits)
            ),
            sample, page_points, "Visited pages"
        ))

        for url, title, categories, last in page_hits[:50]:

            moment = chrome_to_datetime(last)

            if moment:

                events.append({
                    "type": "suspicious_visit",
                    "time": moment,
                    "title": "Visited: {}".format((title or url or "")[:120]),
                    "detail": "{} - {}".format(
                        ", ".join(categories), (url or "")[:200]
                    ),
                    "severity": "MEDIUM",
                    "time_note": "UTC (Chrome timestamp)"
                })

    else:

        breakdown.append({
            "Factor": "Suspicious Pages", "Score": 0, "Maximum": 12,
            "Observation": "No visited page matched the suspicious-terms "
                           "list."
        })

    # ---- 3. downloads (max 35) ----

    executables = [
        d for d in downloads
        if d["File"].lower().endswith(EXECUTABLE_EXT)
    ]

    flagged = [d for d in downloads if d["Danger Type"] in DANGEROUS_TYPES]

    exe_points = min(2 * len(executables), 10)
    flag_points = 20 if flagged else 0

    if executables:

        score += exe_points

        breakdown.append({
            "Factor": "Executable Downloads", "Score": exe_points,
            "Maximum": 10,
            "Observation": "{} program/script file(s) downloaded, e.g. "
                           "{}. Installers are normal; check the source."
                           .format(len(executables),
                                   ", ".join(d["File"] for d in executables[:3]))
        })

        findings.append(make_finding(
            "{} executable/script download(s)".format(len(executables)),
            "e.g. " + ", ".join(d["File"] for d in executables[:5]),
            exe_points, "Downloads"
        ))

    else:

        breakdown.append({
            "Factor": "Executable Downloads", "Score": 0, "Maximum": 10,
            "Observation": "No executable downloads among {} download(s)."
                           .format(len(downloads))
        })

    if flagged:

        score += flag_points

        breakdown.append({
            "Factor": "Browser-Flagged Downloads", "Score": flag_points,
            "Maximum": 20,
            "Observation": "{} download(s) were flagged as dangerous by "
                           "the browser: {}".format(
                               len(flagged),
                               ", ".join(d["File"] for d in flagged[:3]))
        })

        findings.append(make_finding(
            "{} download(s) flagged dangerous by the browser".format(
                len(flagged)
            ),
            ", ".join(d["File"] for d in flagged[:5]),
            flag_points, "Downloads"
        ))

    # ---- 4. IP-address URLs (max 20) ----

    ip_urls = [
        u for u in urls
        if IP_URL_RE.match(u[1] or "") and _is_public_ip_url(u[1])
    ]

    ip_points = min(5 * len(ip_urls), 20)

    if ip_urls:

        score += ip_points

        breakdown.append({
            "Factor": "IP-Address URLs", "Score": ip_points, "Maximum": 20,
            "Observation": "{} URL(s) use a raw IP address, e.g. {}".format(
                len(ip_urls), ip_urls[0][1][:80]
            )
        })

        findings.append(make_finding(
            "{} URL(s) use a raw IP address".format(len(ip_urls)),
            ", ".join(u[1][:60] for u in ip_urls[:3]),
            ip_points, "IP URLs"
        ))

    else:

        breakdown.append({
            "Factor": "IP-Address URLs", "Score": 0, "Maximum": 20,
            "Observation": "No IP-address based URLs detected."
        })

    # ---- 5. plain HTTP (informational, max 5) ----

    http_urls = [
        u for u in urls
        if (u[1] or "").lower().startswith("http://")
        and not re.match(r"http://(localhost|127\.|192\.168\.)", u[1], re.I)
    ]

    http_points = min(len(http_urls), 5)

    score += http_points

    breakdown.append({
        "Factor": "Unencrypted (HTTP) Pages", "Score": http_points,
        "Maximum": 5,
        "Observation": "{} unencrypted page(s) visited.".format(
            len(http_urls)
        ) if http_urls else "No unencrypted pages visited."
    })

    if http_urls:

        findings.append(make_finding(
            "{} page(s) visited over unencrypted HTTP".format(len(http_urls)),
            "Low weight: many older sites still use HTTP.",
            http_points, "HTTP", severity="LOW"
        ))

    score = min(score, 100)

    # ---- informational findings ----

    domains = Counter()

    for _id, url, title, visit_count, typed, last in urls:

        match = re.match(r"https?://([^/:?#]+)", url or "", re.I)

        if match:
            domains[match.group(1).lower()] += visit_count or 0

    if first_visit and last_visit:

        findings.append(make_finding(
            "Browsing activity from {} to {} (UTC)".format(
                first_visit.strftime("%Y-%m-%d"),
                last_visit.strftime("%Y-%m-%d")
            ),
            "{} URLs and {} visits recorded; {} typed visits.".format(
                len(urls), visits_total, typed_visits
            ),
            0, "Activity", severity="INFO"
        ))

    # ---- timeline events from downloads + range markers ----

    for item in downloads[:MAX_STORED_DOWNLOADS]:

        if item["_time"]:

            flagged_download = item["Danger Type"] in DANGEROUS_TYPES

            events.append({
                "type": "download",
                "time": item["_time"],
                "title": "Downloaded: {}".format(item["File"][:120]),
                "detail": "From {}".format(item["Source"][:200]),
                "severity": "HIGH" if flagged_download else (
                    "LOW" if item["File"].lower().endswith(EXECUTABLE_EXT)
                    else None
                ),
                "time_note": "UTC (Chrome timestamp)"
            })

    if first_visit:

        events.append({
            "type": "browsing_start",
            "time": first_visit,
            "title": "Earliest browsing record",
            "detail": "First visit in this history file",
            "time_note": "UTC (Chrome timestamp)"
        })

    if last_visit:

        events.append({
            "type": "browsing_end",
            "time": last_visit,
            "title": "Most recent browsing record",
            "detail": "Last visit in this history file",
            "time_note": "UTC (Chrome timestamp)"
        })

    events.sort(key=lambda e: e["time"], reverse=True)

    events = events[:MAX_EVENTS]

    # ==================================================
    # RESULT PACKAGE
    # ==================================================

    level = level_from_score(score)

    top_urls = sorted(
        urls, key=lambda row: row[3] or 0, reverse=True
    )[:MAX_STORED_HISTORY]

    history = [
        {
            "URL": (row[1] or "")[:500],
            "Title": (row[2] or "No Title")[:200],
            "Visit Count": row[3] or 0,
            "Last Visit": convert_chrome_time(row[5])
        }
        for row in top_urls
    ]

    top_sites = [
        {"URL": h["URL"], "Visit Count": h["Visit Count"]}
        for h in history[:10]
    ]

    top_domains = [
        {"Domain": d, "Visits": v} for d, v in domains.most_common(10)
    ]

    stored_downloads = [
        {k: v for k, v in d.items() if not k.startswith("_")}
        for d in downloads[:MAX_STORED_DOWNLOADS]
    ]

    stored_searches = [
        {k: v for k, v in s.items() if not k.startswith("_")}
        for s in searches[:MAX_STORED_SEARCHES]
    ]

    history_data = {
        "Total URLs": len(urls),
        "Total Visits": visits_total,
        "Typed Visits": typed_visits,
        "Total Downloads": len(downloads),
        "Total Searches": len(searches),
        "First Activity (UTC)": (
            first_visit.strftime("%Y-%m-%d %H:%M:%S") if first_visit else "n/a"
        ),
        "Last Activity (UTC)": (
            last_visit.strftime("%Y-%m-%d %H:%M:%S") if last_visit else "n/a"
        ),
        "History": history,
        "Downloads": stored_downloads,
        "Searches": stored_searches,
        "Top Domains": top_domains,
        "Hourly Activity": hourly,
        "Time Zone": "UTC"
    }

    interpretation = (
        "The browser risk score is built from observable indicators: "
        "suspicious search terms and pages, executable or browser-flagged "
        "downloads, and IP-address URLs. A match is a lead for the "
        "investigator, not proof of malicious intent. All times are UTC "
        "as stored by Chrome. The analysis read the evidence file in "
        "read-only mode, so its hash is unchanged."
    )

    risk_data = {
        "Risk Score": score,
        "Risk Level": level,
        "Risk Breakdown": breakdown,
        "Findings": [f["title"] for f in findings if f["points"] > 0]
        or ["No significant browser-history risk indicators detected."],
        "Forensic Interpretation": interpretation
    }

    return {
        "history_data": history_data,
        "top_sites": top_sites,
        "timeline": recent_visits,
        "risk_data": risk_data,
        "findings": findings,
        "events": events
    }
