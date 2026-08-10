import sqlite3

from datetime import datetime

import hashlib

import re


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

    except:

        return "Unknown"


def extract_history(history_file):

    result = {

        "Total URLs": 0,

        "History": []

    }

    try:

        connection = sqlite3.connect(
            history_file
        )

        cursor = connection.cursor()

        print("Database Connected")

        # Check available tables

        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )

        tables = cursor.fetchall()

        print(
            "Tables Found:",
            tables
        )

        # Count URL records

        cursor.execute(
            "SELECT COUNT(*) FROM urls"
        )

        count = cursor.fetchone()[0]

        print(
            "URL Count:",
            count
        )

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

        for row in rows:

            result["History"].append({

                "URL": row[0],

                "Title": row[1]
                if row[1]
                else "No Title",

                "Visit Count": row[2],

                "Last Visit": convert_chrome_time(
                    row[3]
                )

            })

        result["Total URLs"] = len(rows)

        connection.close()

    except Exception as e:

        print(
            "History Extraction Error:",
            e
        )

    return result


def get_top_websites(history_data, limit=10):

    websites = []

    for item in history_data["History"]:

        url = item["URL"]

        visits = item["Visit Count"]

        websites.append({

            "URL": url,

            "Visit Count": visits

        })

    websites = sorted(

        websites,

        key=lambda x: x["Visit Count"],

        reverse=True

    )

    return websites[:limit]


def get_browsing_timeline(history_data):

    timeline = []

    for item in history_data["History"]:

        timeline.append({

            "URL": item["URL"],

            "Title": item["Title"],

            "Visit Count": item["Visit Count"],

            "Last Visit": item["Last Visit"]

        })

    timeline = sorted(

        timeline,

        key=lambda x: x["Last Visit"]

    )

    return timeline


def generate_file_hash(file_path):

    sha256_hash = hashlib.sha256()

    try:

        with open(
            file_path,
            "rb"
        ) as file:

            while True:

                chunk = file.read(4096)

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


def analyze_browser_risk(history_data):

    risk_score = 0

    findings = []

    http_count = 0

    ip_url_count = 0

    high_visit_count = 0


    for item in history_data["History"]:

        url = item["URL"]

        visit_count = item["Visit Count"]


        # --------------------------------
        # HTTP URL Detection
        # --------------------------------

        if url.lower().startswith("http://"):

            http_count += 1


        # --------------------------------
        # IP Address URL Detection
        # --------------------------------

        ip_pattern = (
            r"https?://"
            r"(?:\d{1,3}\.){3}\d{1,3}"
        )

        if re.search(
            ip_pattern,
            url,
            re.IGNORECASE
        ):

            ip_url_count += 1


        # --------------------------------
        # High Visit Frequency
        # --------------------------------

        if visit_count >= 50:

            high_visit_count += 1


    # --------------------------------
    # Risk Scoring
    # --------------------------------

    if http_count > 0:

        risk_score += 10

        findings.append(
            f"HTTP URLs detected: {http_count}"
        )


    if ip_url_count > 0:

        risk_score += 20

        findings.append(
            f"IP-address based URLs detected: {ip_url_count}"
        )


    if high_visit_count > 0:

        risk_score += 10

        findings.append(
            f"High-frequency visited URLs detected: {high_visit_count}"
        )


    # Maximum score

    if risk_score > 100:

        risk_score = 100


    # --------------------------------
    # Risk Level
    # --------------------------------

    if risk_score >= 40:

        risk_level = "HIGH"

    elif risk_score >= 20:

        risk_level = "MEDIUM"

    else:

        risk_level = "LOW"


    # No findings

    if not findings:

        findings.append(
            "No significant browser risk indicators detected"
        )


    return {

        "Risk Score": risk_score,

        "Risk Level": risk_level,

        "Findings": findings

    }