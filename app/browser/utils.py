import sqlite3
from datetime import datetime
import hashlib
import re


# ==========================================
# CHROME / EDGE TIMESTAMP CONVERSION
# ==========================================

def convert_chrome_time(chrome_time):

    try:

        epoch = 11644473600000000

        timestamp = (
            chrome_time - epoch
        ) / 1000000

        return datetime.fromtimestamp(
            timestamp
        ).strftime(
            "%Y-%m-%d %H:%M:%S"
        )

    except Exception:

        return "Unknown"


# ==========================================
# EXTRACT BROWSER HISTORY
# ==========================================

def extract_history(history_file):

    result = {

        "Total URLs": 0,

        "History": []

    }

    connection = None

    try:

        connection = sqlite3.connect(
            history_file
        )

        cursor = connection.cursor()

        print("Database Connected")

        # --------------------------------------
        # Check available tables
        # --------------------------------------

        cursor.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type='table'"
        )

        tables = cursor.fetchall()

        print(
            "Tables Found:",
            tables
        )

        # --------------------------------------
        # Count URL records
        # --------------------------------------

        cursor.execute(
            "SELECT COUNT(*) FROM urls"
        )

        count = cursor.fetchone()[0]

        print(
            "URL Count:",
            count
        )

        # --------------------------------------
        # Extract browser history
        # --------------------------------------

        query = """

        SELECT

        url,
        title,
        visit_count,
        last_visit_time

        FROM urls

        ORDER BY visit_count DESC

        LIMIT 100

        """

        cursor.execute(query)

        rows = cursor.fetchall()

        print(
            "Rows Extracted:",
            len(rows)
        )

        # --------------------------------------
        # Process records
        # --------------------------------------

        for row in rows:

            result["History"].append({

                "URL": row[0],

                "Title":
                    row[1]
                    if row[1]
                    else "No Title",

                "Visit Count":
                    row[2]
                    if row[2] is not None
                    else 0,

                "Last Visit":
                    convert_chrome_time(
                        row[3]
                    )

            })

        result["Total URLs"] = len(rows)

    except Exception as e:

        print(
            "History Extraction Error:",
            e
        )

        result["Error"] = str(e)

    finally:

        if connection:

            connection.close()

    return result


# ==========================================
# TOP VISITED WEBSITES
# ==========================================

def get_top_websites(
    history_data,
    limit=10
):

    websites = []

    for item in history_data.get(
        "History",
        []
    ):

        url = item.get(
            "URL",
            ""
        )

        visits = item.get(
            "Visit Count",
            0
        )

        websites.append({

            "URL": url,

            "Visit Count": visits

        })

    websites = sorted(

        websites,

        key=lambda x:
            x["Visit Count"],

        reverse=True

    )

    return websites[:limit]


# ==========================================
# BROWSING TIMELINE
# ==========================================

def get_browsing_timeline(
    history_data
):

    timeline = []

    for item in history_data.get(
        "History",
        []
    ):

        timeline.append({

            "URL":
                item.get(
                    "URL",
                    ""
                ),

            "Title":
                item.get(
                    "Title",
                    "No Title"
                ),

            "Visit Count":
                item.get(
                    "Visit Count",
                    0
                ),

            "Last Visit":
                item.get(
                    "Last Visit",
                    "Unknown"
                )

        })

    timeline = sorted(

        timeline,

        key=lambda x:
            x["Last Visit"]

    )

    return timeline


# ==========================================
# GENERATE SHA-256 HASH
# ==========================================

def generate_file_hash(
    file_path
):

    sha256_hash = hashlib.sha256()

    try:

        with open(
            file_path,
            "rb"
        ) as file:

            while True:

                chunk = file.read(
                    4096
                )

                if not chunk:

                    break

                sha256_hash.update(
                    chunk
                )

        return sha256_hash.hexdigest()

    except Exception as e:

        print(
            "Hash Generation Error:",
            e
        )

        return "Hash Generation Failed"


# ==========================================
# BROWSER RISK ASSESSMENT
# ==========================================

def analyze_browser_risk(
    history_data
):

    risk_score = 0

    findings = []

    risk_breakdown = []

    http_count = 0

    ip_url_count = 0

    high_visit_count = 0

    history = history_data.get(
        "History",
        []
    )


    # ======================================
    # ANALYZE BROWSER HISTORY
    # ======================================

    for item in history:

        url = str(
            item.get(
                "URL",
                ""
            )
        )

        visit_count = int(
            item.get(
                "Visit Count",
                0
            )
        )

        url_lower = url.lower()


        # ----------------------------------
        # 1. HTTP URL DETECTION
        # ----------------------------------

        if url_lower.startswith(
            "http://"
        ):

            http_count += 1


        # ----------------------------------
        # 2. IP ADDRESS URL DETECTION
        # ----------------------------------

        ip_pattern = (
            r"https?://"
            r"(?:\d{1,3}\.){3}"
            r"\d{1,3}"
        )

        if re.search(
            ip_pattern,
            url,
            re.IGNORECASE
        ):

            ip_url_count += 1


        # ----------------------------------
        # 3. HIGH VISIT FREQUENCY
        # ----------------------------------

        if visit_count >= 50:

            high_visit_count += 1


    # ======================================
    # RISK SCORING
    # ======================================

    # --------------------------------------
    # HTTP Activity
    # --------------------------------------

    if http_count > 0:

        http_score = min(
            http_count * 2,
            10
        )

        risk_score += http_score

        risk_breakdown.append({

            "Factor":
                "HTTP URL Activity",

            "Score":
                http_score,

            "Maximum":
                10,

            "Observation":
                f"{http_count} HTTP URL(s) detected."

        })

        findings.append(
            f"HTTP URLs detected: "
            f"{http_count}"
        )

    else:

        risk_breakdown.append({

            "Factor":
                "HTTP URL Activity",

            "Score":
                0,

            "Maximum":
                10,

            "Observation":
                "No HTTP URLs detected."

        })


    # --------------------------------------
    # IP-Based URLs
    # --------------------------------------

    if ip_url_count > 0:

        ip_score = min(
            ip_url_count * 5,
            25
        )

        risk_score += ip_score

        risk_breakdown.append({

            "Factor":
                "IP-Address URL Activity",

            "Score":
                ip_score,

            "Maximum":
                25,

            "Observation":
                f"{ip_url_count} IP-address-based "
                f"URL(s) detected."

        })

        findings.append(
            f"IP-address based URLs detected: "
            f"{ip_url_count}"
        )

    else:

        risk_breakdown.append({

            "Factor":
                "IP-Address URL Activity",

            "Score":
                0,

            "Maximum":
                25,

            "Observation":
                "No IP-address-based URLs detected."

        })


    # --------------------------------------
    # High-Frequency Browsing
    # --------------------------------------

    if high_visit_count > 0:

        frequency_score = min(
            high_visit_count * 3,
            15
        )

        risk_score += frequency_score

        risk_breakdown.append({

            "Factor":
                "High-Frequency Browsing",

            "Score":
                frequency_score,

            "Maximum":
                15,

            "Observation":
                f"{high_visit_count} URL(s) "
                f"with 50 or more visits detected."

        })

        findings.append(
            f"High-frequency visited URLs detected: "
            f"{high_visit_count}"
        )

    else:

        risk_breakdown.append({

            "Factor":
                "High-Frequency Browsing",

            "Score":
                0,

            "Maximum":
                15,

            "Observation":
                "No high-frequency browsing pattern detected."

        })


    # ======================================
    # TOTAL SCORE
    # ======================================

    if risk_score > 100:

        risk_score = 100


    # ======================================
    # RISK LEVEL
    # ======================================

    if risk_score >= 70:

        risk_level = "HIGH"

    elif risk_score >= 40:

        risk_level = "MEDIUM"

    else:

        risk_level = "LOW"


    # ======================================
    # NO FINDINGS
    # ======================================

    if not findings:

        findings.append(
            "No significant browser-history "
            "risk indicators detected."
        )


    # ======================================
    # FORENSIC INTERPRETATION
    # ======================================

    interpretation = (
        "The browser risk score represents "
        "observable indicators identified "
        "from the available browser-history "
        "records. The presence of HTTP URLs, "
        "IP-address-based URLs, or frequent "
        "visits does not by itself prove "
        "malicious activity. Further forensic "
        "examination may be required to "
        "establish context."
    )


    # ======================================
    # RETURN RESULT
    # ======================================

    return {

        "Risk Score":
            risk_score,

        "Risk Level":
            risk_level,

        "Risk Breakdown":
            risk_breakdown,

        "Findings":
            findings,

        "Forensic Interpretation":
            interpretation

    }