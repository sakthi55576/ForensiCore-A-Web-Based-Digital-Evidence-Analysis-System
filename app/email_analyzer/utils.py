import re
import requests
import ipaddress

from email import policy
from email.parser import BytesParser



def extract_domain(email):

    match = re.search(
        r'@([\w\.-]+)',
        email
    )

    if match:
        return match.group(1).lower()

    return None



# .eml file header extraction

def extract_eml_header(file_path):

    try:

        with open(file_path, "rb") as f:

            msg = BytesParser(
                policy=policy.default
            ).parse(f)


        headers = []

        for key, value in msg.items():

            headers.append(
                f"{key}: {value}"
            )


        return "\n".join(headers)


    except Exception as e:

        print(
            "EML Extraction Error:",
            e
        )

        return ""



def get_ip_location(ip):

    try:

        response = requests.get(
            f"https://ipinfo.io/{ip}/json",
            timeout=5
        )


        data = response.json()


        return {

            "IP": ip,

            "Country": data.get(
                "country",
                "Unknown"
            ),

            "City": data.get(
                "city",
                "Unknown"
            ),

            "Region": data.get(
                "region",
                "Unknown"
            ),

            "ISP": data.get(
                "org",
                "Unknown"
            )

        }


    except Exception:


        return {

            "IP": ip,

            "Country": "Unknown",

            "City": "Unknown",

            "Region": "Unknown",

            "ISP": "Unknown"

        }



def is_private_ip(ip):

    try:

        ip_obj = ipaddress.ip_address(ip)

        return (
            ip_obj.is_private or
            ip_obj.is_loopback or
            ip_obj.is_multicast or
            ip_obj.is_reserved or
            ip_obj.is_unspecified
        )

    except:

        return True


def is_valid_public_ip(ip):

    try:

        ip_obj = ipaddress.ip_address(ip)

        return (
            not ip_obj.is_private and
            not ip_obj.is_loopback and
            not ip_obj.is_multicast and
            not ip_obj.is_reserved and
            not ip_obj.is_unspecified
        )

    except:

        return False


def analyze_email(header_text):

    result = {

        "From": "Not Available",
        "To": "Not Available",
        "Subject": "Not Available",
        "Date": "Not Available",
        "Return-Path": "Not Available",
        "Message-ID": "Not Available",

        "Received": [],
        "Sender IP": [],
        "IP Location": [],

        "SPF": "Not Found",
        "DKIM": "Not Found",
        "DMARC": "Not Found",

        "Findings": [],

        "Risk Score": 0,
        "Risk Level": "LOW"

    }

    lines = header_text.splitlines()

    for line in lines:

        lower = line.lower()

        if lower.startswith("from:"):

            result["From"] = line.split(":", 1)[1].strip()

        elif lower.startswith("to:"):

            result["To"] = line.split(":", 1)[1].strip()

        elif lower.startswith("subject:"):

            result["Subject"] = line.split(":", 1)[1].strip()

        elif lower.startswith("date:"):

            result["Date"] = line.split(":", 1)[1].strip()

        elif lower.startswith("return-path:"):

            result["Return-Path"] = line.split(":", 1)[1].strip()

        elif lower.startswith("message-id:"):

            result["Message-ID"] = line.split(":", 1)[1].strip()

        elif lower.startswith("received:"):

            result["Received"].append(line)

            ips = re.findall(
                r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
                line
            )

            for ip in ips:

                if ip not in result["Sender IP"]:

                    if is_valid_public_ip(ip):

                        result["Sender IP"].append(ip)

                        result["IP Location"].append(
                            get_ip_location(ip)
                        )

        elif "spf=" in lower:

            if "pass" in lower:

                result["SPF"] = "PASS"

            elif "fail" in lower:

                result["SPF"] = "FAIL"

        elif "dkim=" in lower:

            if "pass" in lower:

                result["DKIM"] = "PASS"

            elif "fail" in lower:

                result["DKIM"] = "FAIL"

        elif "dmarc=" in lower:

            if "pass" in lower:

                result["DMARC"] = "PASS"

            elif "fail" in lower:

                result["DMARC"] = "FAIL"

    # -------------------------
    # Spoof Detection
    # -------------------------

    from_domain = extract_domain(result["From"])
    return_domain = extract_domain(result["Return-Path"])

    if from_domain and return_domain:

        if (
            return_domain != from_domain
            and not return_domain.endswith("." + from_domain)
        ):

            result["Findings"].append(
                "From domain and Return-Path domain mismatch"
            )

            result["Risk Score"] += 40

    # -------------------------
    # Authentication Checks
    # -------------------------

    if result["SPF"] == "FAIL":

        result["Findings"].append(
            "SPF authentication failed"
        )

        result["Risk Score"] += 20

    elif result["SPF"] == "PASS":

        result["Findings"].append(
            "SPF authentication passed"
        )

    if result["DKIM"] == "FAIL":

        result["Findings"].append(
            "DKIM authentication failed"
        )

        result["Risk Score"] += 20

    elif result["DKIM"] == "PASS":

        result["Findings"].append(
            "DKIM authentication passed"
        )

    if result["DMARC"] == "FAIL":

        result["Findings"].append(
            "DMARC authentication failed"
        )

        result["Risk Score"] += 20

    elif result["DMARC"] == "PASS":

        result["Findings"].append(
            "DMARC authentication passed"
        )

    # -------------------------
    # No Public IP
    # -------------------------

    if len(result["Sender IP"]) == 0:

        result["Findings"].append(
            "No public sender IP found"
        )

    # -------------------------
    # Safe Email
    # -------------------------

    if result["Risk Score"] == 0:

        result["Findings"].append(
            "No spoofing indicators detected"
        )

    # -------------------------
    # Risk Level
    # -------------------------

    if result["Risk Score"] >= 70:

        result["Risk Level"] = "HIGH"

    elif result["Risk Score"] >= 40:

        result["RiskLevel"] = "MEDIUM"
        result["Risk Level"] = "MEDIUM"

    else:

        result["Risk Level"] = "LOW"

    return result