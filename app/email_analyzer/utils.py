"""
Email (.eml) forensic analyzer.

Improvements over the first version
-----------------------------------
* SPF / DKIM / DMARC are read independently from Authentication-Results
  (and Received-SPF). Before, an `elif` chain meant that when all three
  results sat in one header only SPF was recognised - real Gmail
  messages showed DKIM/DMARC as "Not Found".
* Message body links are analysed (mismatched anchor text, IP links,
  punycode, URL shorteners).
* Attachments are listed with a SHA-256 each and checked for dangerous
  or double extensions.
* Reply-To mismatch and display-name spoofing checks.
* Date header compared with the Received timestamps.
* Findings + timeline events are produced for the case-level views.
* The external IP geolocation lookup is optional (ENABLE_IP_LOOKUP)
  and limited to a few IPs with a short timeout.
"""

import hashlib
import ipaddress
import re
from datetime import timedelta, timezone
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr, parsedate_to_datetime

from app.config import Config
from app.utils.findings import make_finding, level_from_score

MAX_IP_LOOKUPS = 5
MAX_LINKS = 200

DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".js", ".jse",
    ".vbs", ".vbe", ".wsf", ".ps1", ".jar", ".msi", ".lnk", ".hta",
    ".iso", ".img", ".docm", ".xlsm", ".pptm", ".apk"
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc"
}

# Second-level labels that make a 3-label registrable domain (co.uk ...)
_SLD = {"co", "com", "org", "net", "gov", "ac", "edu", "nic", "res"}

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)
ANCHOR_RE = re.compile(
    r"<a\s[^>]*?href\s*=\s*[\"']([^\"']+)[\"'][^>]*>(.*?)</a>",
    re.IGNORECASE | re.DOTALL
)
TAG_RE = re.compile(r"<[^>]+>")


# ==========================================
# DOMAIN HELPERS
# ==========================================

def extract_domain(address):

    if not address:
        return None

    match = re.search(r"@([\w.-]+)", str(address))

    return match.group(1).lower().rstrip(".") if match else None


def base_domain(host):

    """Approximate registrable domain: mail.google.com -> google.com"""

    if not host:
        return None

    labels = host.lower().rstrip(".").split(".")

    if len(labels) <= 2:
        return ".".join(labels)

    if len(labels[-1]) == 2 and labels[-2] in _SLD:
        return ".".join(labels[-3:])

    return ".".join(labels[-2:])


def host_of(url):

    match = re.match(r"https?://([^/:?#]+)", url, re.IGNORECASE)

    return match.group(1).lower() if match else None


def is_valid_public_ip(ip):

    try:

        ip_obj = ipaddress.ip_address(ip)

        return not (
            ip_obj.is_private or ip_obj.is_loopback
            or ip_obj.is_multicast or ip_obj.is_reserved
            or ip_obj.is_unspecified or ip_obj.is_link_local
        )

    except ValueError:
        return False


def get_ip_location(ip):

    unknown = {
        "IP": ip, "Country": "Unknown", "City": "Unknown",
        "Region": "Unknown", "ISP": "Unknown"
    }

    if not Config.ENABLE_IP_LOOKUP:

        unknown["ISP"] = "Lookup disabled"

        return unknown

    try:

        import requests

        data = requests.get(
            "https://ipinfo.io/{}/json".format(ip),
            timeout=3
        ).json()

        return {
            "IP": ip,
            "Country": data.get("country", "Unknown"),
            "City": data.get("city", "Unknown"),
            "Region": data.get("region", "Unknown"),
            "ISP": data.get("org", "Unknown")
        }

    except Exception:

        return unknown


# ==========================================
# AUTHENTICATION RESULTS
# ==========================================

def _auth_result(header_values, mechanism):

    """
    Look for '<mechanism>=<result>' in the Authentication-Results
    headers. For DKIM (several signatures possible) PASS wins if any
    signature passed.
    """

    pattern = re.compile(
        r"\b{}\s*=\s*(pass|fail|softfail|neutral|none|"
        r"temperror|permerror|policy)\b".format(mechanism),
        re.IGNORECASE
    )

    results = []

    for value in header_values:
        results.extend(m.lower() for m in pattern.findall(value))

    if not results:
        return None

    if "pass" in results:
        return "PASS"

    if "fail" in results:
        return "FAIL"

    return results[0].upper()


def get_authentication(msg):

    # The FIRST Authentication-Results header is the one added by the
    # receiving server; ARC-Authentication-Results is a separate header.
    auth_headers = [
        str(v) for v in (msg.get_all("Authentication-Results") or [])
    ][:1]

    spf = _auth_result(auth_headers, "spf")

    if not spf:

        received_spf = msg.get("Received-SPF")

        if received_spf:

            first = str(received_spf).strip().split()[0].lower()

            if first in (
                "pass", "fail", "softfail", "neutral", "none",
                "temperror", "permerror"
            ):
                spf = first.upper()

    return {
        "SPF": spf or "Not Found",
        "DKIM": _auth_result(auth_headers, "dkim") or "Not Found",
        "DMARC": _auth_result(auth_headers, "dmarc") or "Not Found",
        "Source": (
            "Authentication-Results header"
            if auth_headers else "not present in this message"
        )
    }


# ==========================================
# DATES
# ==========================================

def _to_utc(value):

    try:

        parsed = parsedate_to_datetime(str(value))

        if parsed.tzinfo is None:
            return parsed, "Assumed UTC (no timezone in header)"

        return (
            parsed.astimezone(timezone.utc).replace(tzinfo=None),
            "UTC (converted from header)"
        )

    except Exception:

        return None, None


def _received_times(received_headers):

    times = []

    for header in received_headers:

        if ";" in header:

            parsed, _ = _to_utc(header.rsplit(";", 1)[1].strip())

            if parsed:
                times.append(parsed)

    return times


# ==========================================
# BODY LINKS + ATTACHMENTS
# ==========================================

def _body_text(msg):

    html = plain = ""

    try:

        part = msg.get_body(preferencelist=("html",))

        if part:
            html = part.get_content()

        part = msg.get_body(preferencelist=("plain",))

        if part:
            plain = part.get_content()

    except Exception:
        pass

    return html or "", plain or ""


def extract_links(msg):

    html, plain = _body_text(msg)

    links = []
    seen = set()

    for href, inner in ANCHOR_RE.findall(html):

        href = href.strip()

        if not href.lower().startswith(("http://", "https://")):
            continue

        text = re.sub(r"\s+", " ", TAG_RE.sub("", inner)).strip()

        if (href, text) not in seen:
            seen.add((href, text))
            links.append({"url": href, "text": text[:120]})

    for url in URL_RE.findall(html + " " + plain):

        if (url, "") not in seen and not any(l["url"] == url for l in links):
            seen.add((url, ""))
            links.append({"url": url, "text": ""})

    return links[:MAX_LINKS]


def assess_link(link):

    """Return list of (points, reason) problems for one link."""

    problems = []

    host = host_of(link["url"]) or ""

    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host):
        problems.append((15, "points to a raw IP address"))

    if "xn--" in host:
        problems.append((10, "uses punycode (possible look-alike domain)"))

    if base_domain(host) in SHORTENERS or host in SHORTENERS:
        problems.append((5, "uses a URL shortener"))

    text = link["text"]

    if text and re.fullmatch(
        r"(?:https?://)?(?:www\.)?[\w-]+(?:\.[\w-]+)+(?:/\S*)?", text
    ):

        shown = base_domain(host_of(
            text if text.lower().startswith("http") else "http://" + text
        ))

        real = base_domain(host)

        if shown and real and shown != real:

            problems.append((
                20,
                "displays '{}' but goes to {}".format(text[:60], real)
            ))

    return problems


def extract_attachments(msg):

    attachments = []

    try:
        parts = list(msg.iter_attachments())
    except Exception:
        parts = []

    for part in parts:

        filename = part.get_filename()

        if not filename:
            continue

        try:
            payload = part.get_payload(decode=True) or b""
        except Exception:
            payload = b""

        extension = ""

        if "." in filename:
            extension = "." + filename.rsplit(".", 1)[1].lower()

        name_parts = filename.lower().split(".")

        double_ext = (
            len(name_parts) >= 3
            and ("." + name_parts[-1]) in DANGEROUS_EXTENSIONS
            and len(name_parts[-2]) <= 5
        )

        attachments.append({
            "name": filename,
            "type": part.get_content_type(),
            "size": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
            "dangerous": extension in DANGEROUS_EXTENSIONS,
            "double_extension": double_ext
        })

    return attachments


# ==========================================
# MAIN ANALYSIS
# ==========================================

def _row(category, points, max_points, status, reason):

    return {
        "category": category, "points": points,
        "max_points": max_points, "status": status, "reason": reason
    }


def analyze_eml(file_path):

    with open(file_path, "rb") as handle:
        msg = BytesParser(policy=policy.default).parse(handle)

    def header(name):

        value = msg.get(name)

        return str(value).strip() if value else "Not Available"

    from_raw = header("From")
    return_path = header("Return-Path")
    reply_to = header("Reply-To")

    result = {
        "From": from_raw,
        "To": header("To"),
        "Subject": header("Subject"),
        "Date": header("Date"),
        "Return-Path": return_path,
        "Reply-To": reply_to,
        "Message-ID": header("Message-ID"),
        "Received": [],
        "Sender IP": [],
        "IP Location": [],
        "Links": [],
        "Attachments": [],
        "Findings": [],
        "Risk Breakdown": []
    }

    findings = []
    breakdown = result["Risk Breakdown"]
    score = 0

    # ---------------- Received chain + IPs ----------------

    received_headers = [
        re.sub(r"\s+", " ", str(v)).strip()
        for v in (msg.get_all("Received") or [])
    ]

    result["Received"] = ["Received: " + r for r in received_headers]

    for received in received_headers:

        for ip in IPV4_RE.findall(received):

            if ip not in result["Sender IP"] and is_valid_public_ip(ip):
                result["Sender IP"].append(ip)

    for ip in result["Sender IP"][:MAX_IP_LOOKUPS]:
        result["IP Location"].append(get_ip_location(ip))

    # ---------------- authentication ----------------

    auth = get_authentication(msg)

    result["SPF"] = auth["SPF"]
    result["DKIM"] = auth["DKIM"]
    result["DMARC"] = auth["DMARC"]
    result["Authentication Source"] = auth["Source"]

    for mechanism, fail_points, soft_points in (
        ("SPF", 20, 10),
        ("DKIM", 20, 10),
        ("DMARC", 25, 10)
    ):

        value = auth[mechanism]

        if value == "FAIL":

            score += fail_points

            reason = "The email failed {} authentication.".format(mechanism)

            breakdown.append(_row(
                "{} Authentication".format(mechanism),
                fail_points, fail_points, "FAIL", reason
            ))

            findings.append(make_finding(
                "{} authentication FAILED".format(mechanism),
                reason + " The sender may be forged.",
                fail_points, "Authentication"
            ))

        elif value in ("SOFTFAIL", "PERMERROR", "TEMPERROR"):

            score += soft_points

            reason = "{} returned {}.".format(mechanism, value)

            breakdown.append(_row(
                "{} Authentication".format(mechanism),
                soft_points, fail_points, value, reason
            ))

            findings.append(make_finding(
                "{} result: {}".format(mechanism, value),
                reason, soft_points, "Authentication"
            ))

        elif value == "PASS":

            breakdown.append(_row(
                "{} Authentication".format(mechanism),
                0, fail_points, "PASS",
                "The email passed {} authentication.".format(mechanism)
            ))

        else:

            breakdown.append(_row(
                "{} Authentication".format(mechanism),
                0, fail_points, "Not Found",
                "No {} result is recorded in this message "
                "(informational).".format(mechanism)
            ))

    passed = [m for m in ("SPF", "DKIM", "DMARC") if auth[m] == "PASS"]

    if passed:

        findings.append(make_finding(
            "{} passed".format(" / ".join(passed)),
            "Authentication results were taken from the {}.".format(
                auth["Source"]
            ),
            0, "Authentication", severity="INFO"
        ))

    elif auth["SPF"] == auth["DKIM"] == auth["DMARC"] == "Not Found":

        findings.append(make_finding(
            "No authentication results in the headers",
            "SPF/DKIM/DMARC results are missing, so the sender could "
            "not be validated from this file.",
            0, "Authentication", severity="INFO"
        ))

    # ---------------- domain consistency ----------------

    from_name, from_addr = parseaddr(from_raw)

    from_domain = extract_domain(from_addr)
    return_domain = extract_domain(return_path)
    reply_domain = extract_domain(parseaddr(reply_to)[1])

    if from_domain and return_domain:

        if base_domain(from_domain) != base_domain(return_domain):

            # A third-party sending service is normal when DMARC passes
            points = 5 if auth["DMARC"] == "PASS" else 25

            score += points

            reason = (
                "From domain ({}) and Return-Path domain ({}) differ."
                .format(from_domain, return_domain)
            )

            if points == 5:
                reason += (
                    " DMARC passed, so this is probably a legitimate "
                    "third-party sending service."
                )

            breakdown.append(_row(
                "Domain Consistency", points, 25, "Mismatch", reason
            ))

            findings.append(make_finding(
                "From and Return-Path domains differ", reason,
                points, "Sender domains"
            ))

        else:

            breakdown.append(_row(
                "Domain Consistency", 0, 25, "Consistent",
                "From and Return-Path domains belong to the same "
                "organisation."
            ))

    else:

        breakdown.append(_row(
            "Domain Consistency", 0, 25, "Not Available",
            "Sender or Return-Path domain was not available."
        ))

    if (
        from_domain and reply_domain
        and base_domain(from_domain) != base_domain(reply_domain)
    ):

        score += 15

        reason = (
            "Replies would go to {} instead of the sender's own "
            "domain ({}). A common phishing / BEC technique."
        ).format(reply_domain, from_domain)

        breakdown.append(_row(
            "Reply-To Mismatch", 15, 15, "Mismatch", reason
        ))

        findings.append(make_finding(
            "Reply-To points to a different domain", reason,
            15, "Sender domains"
        ))

    if from_name and "@" in from_name:

        name_domain = extract_domain(from_name)

        if name_domain and from_domain and (
            base_domain(name_domain) != base_domain(from_domain)
        ):

            score += 15

            reason = (
                "The display name shows an address at {} but the "
                "real sender is at {}."
            ).format(name_domain, from_domain)

            breakdown.append(_row(
                "Display-Name Spoofing", 15, 15, "Suspicious", reason
            ))

            findings.append(make_finding(
                "Display name imitates another address", reason,
                15, "Sender identity"
            ))

    # ---------------- date consistency ----------------

    sent_time, sent_note = _to_utc(msg.get("Date"))

    hops = _received_times(received_headers)

    if sent_time and hops:

        earliest, latest = min(hops), max(hops)

        if (
            sent_time < earliest - timedelta(hours=24)
            or sent_time > latest + timedelta(hours=1)
        ):

            score += 10

            reason = (
                "The Date header ({}) does not fit the server "
                "timestamps ({} to {}). The header may be forged or "
                "the sender's clock was wrong."
            ).format(sent_time, earliest, latest)

            breakdown.append(_row(
                "Date Consistency", 10, 10, "Inconsistent", reason
            ))

            findings.append(make_finding(
                "Date header conflicts with server timestamps",
                reason, 10, "Timestamps"
            ))

    # ---------------- links ----------------

    links = extract_links(msg)

    link_points = 0
    flagged_links = []

    for link in links:

        problems = assess_link(link)

        link["problems"] = [reason for _, reason in problems]

        if problems:

            link_points += max(points for points, _ in problems)
            flagged_links.append(link)

    link_points = min(link_points, 40)

    result["Links"] = links

    if flagged_links:

        score += link_points

        sample = "; ".join(
            "{} ({})".format(l["url"][:70], l["problems"][0])
            for l in flagged_links[:3]
        )

        breakdown.append(_row(
            "Suspicious Links", link_points, 40, "Detected",
            "{} of {} link(s) look suspicious: {}".format(
                len(flagged_links), len(links), sample
            )
        ))

        findings.append(make_finding(
            "{} suspicious link(s) in the message body".format(
                len(flagged_links)
            ),
            sample, link_points, "Links"
        ))

    else:

        breakdown.append(_row(
            "Suspicious Links", 0, 40,
            "Clean" if links else "No Links",
            "No suspicious link patterns were found in {} link(s)."
            .format(len(links)) if links else
            "The message body contains no links."
        ))

    # ---------------- attachments ----------------

    attachments = extract_attachments(msg)

    result["Attachments"] = attachments

    attachment_points = 0

    for item in attachments:

        if item["double_extension"]:

            attachment_points += 20

            findings.append(make_finding(
                "Attachment with double extension: {}".format(item["name"]),
                "A disguised executable (e.g. invoice.pdf.exe). "
                "SHA-256 {}".format(item["sha256"]),
                20, "Attachments"
            ))

        elif item["dangerous"]:

            attachment_points += 30

            findings.append(make_finding(
                "Potentially dangerous attachment: {}".format(item["name"]),
                "Executable/script/macro file type. SHA-256 {}".format(
                    item["sha256"]
                ),
                30, "Attachments"
            ))

    attachment_points = min(attachment_points, 40)

    score += attachment_points

    if attachments:

        breakdown.append(_row(
            "Attachments", attachment_points, 40,
            "Dangerous" if attachment_points else "Present",
            "{} attachment(s) found; SHA-256 recorded for each."
            .format(len(attachments))
        ))

        if not attachment_points:

            findings.append(make_finding(
                "{} attachment(s) with no dangerous file type".format(
                    len(attachments)
                ),
                ", ".join(a["name"] for a in attachments[:5]),
                0, "Attachments", severity="INFO"
            ))

    else:

        breakdown.append(_row(
            "Attachments", 0, 40, "None", "No attachments."
        ))

    # ---------------- sender IP info ----------------

    if result["Sender IP"]:

        findings.append(make_finding(
            "{} public sender IP address(es) identified".format(
                len(result["Sender IP"])
            ),
            ", ".join(result["Sender IP"]), 0,
            "Sender IP", severity="INFO"
        ))

    # ---------------- final ----------------

    score = min(score, 100)

    result["Risk Score"] = score
    result["Risk Level"] = level_from_score(score)

    result["Findings"] = [
        f["title"] for f in findings
    ] or ["No spoofing indicators detected."]

    result["_findings"] = findings

    # ---------------- timeline events ----------------

    events = []

    subject = result["Subject"][:80]

    if sent_time:

        events.append({
            "type": "email_sent",
            "time": sent_time,
            "title": "Email sent: {}".format(subject),
            "detail": "From {} to {}".format(from_raw, result["To"]),
            "time_note": sent_note
        })

    if hops:

        events.append({
            "type": "email_received",
            "time": max(hops),
            "title": "Email reached final server: {}".format(subject),
            "detail": "{} server hop(s) recorded".format(len(hops)),
            "time_note": "UTC (from Received header)"
        })

    result["_events"] = events

    return result
