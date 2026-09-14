import re
import requests
import ipaddress
import hashlib

from email import policy
from email.parser import BytesParser


# ==========================================
# EXTRACT DOMAIN
# ==========================================

def extract_domain(email):

    if not email:
        return None

    match = re.search(
        r'@([\w\.-]+)',
        email
    )

    if match:
        return match.group(1).lower()

    return None


# ==========================================
# EXTRACT .EML HEADER
# ==========================================

def extract_eml_header(file_path):

    try:

        with open(
            file_path,
            "rb"
        ) as f:

            msg = BytesParser(
                policy=policy.default
            ).parse(f)


        headers = []

        for key, value in msg.items():

            headers.append(
                f"{key}: {value}"
            )


        return "\n".join(
            headers
        )


    except Exception as e:

        print(
            "EML Extraction Error:",
            e
        )

        return ""


# ==========================================
# SHA-256 FILE HASH
# ==========================================

def generate_file_hash(file_path):

    sha256 = hashlib.sha256()


    with open(
        file_path,
        "rb"
    ) as f:

        while True:

            chunk = f.read(
                4096
            )

            if not chunk:
                break

            sha256.update(
                chunk
            )


    return sha256.hexdigest()


# ==========================================
# IP LOCATION
# ==========================================

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


# ==========================================
# PRIVATE IP CHECK
# ==========================================

def is_private_ip(ip):

    try:

        ip_obj = ipaddress.ip_address(
            ip
        )

        return (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_multicast
            or ip_obj.is_reserved
            or ip_obj.is_unspecified
        )

    except Exception:

        return True


# ==========================================
# PUBLIC IP CHECK
# ==========================================

def is_valid_public_ip(ip):

    try:

        ip_obj = ipaddress.ip_address(
            ip
        )

        return (
            not ip_obj.is_private
            and not ip_obj.is_loopback
            and not ip_obj.is_multicast
            and not ip_obj.is_reserved
            and not ip_obj.is_unspecified
        )

    except Exception:

        return False


# ==========================================
# EMAIL FORENSIC ANALYSIS
# ==========================================

# ==========================================
# EMAIL FORENSIC ANALYSIS
# ==========================================

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

        "File Name": "Not Available",

        "File Hash": "Not Available",

        "Hash Algorithm": "SHA-256",

        "Risk Level": "LOW",

        "Risk Breakdown": []

    }


    # ======================================
    # EMPTY HEADER CHECK
    # ======================================

    if not header_text:

        result["Findings"].append(
            "No email header information available."
        )

        result["Risk Breakdown"] = [

            {
                "category": "Header Availability",
                "points": 0,
                "max_points": 0,
                "status": "Unavailable",
                "reason": "No email header information was available for analysis."
            },

            {
                "category": "Domain Consistency",
                "points": 0,
                "max_points": 40,
                "status": "Not Analyzed",
                "reason": "Sender and Return-Path domains could not be compared."
            },

            {
                "category": "SPF Authentication",
                "points": 0,
                "max_points": 20,
                "status": "Not Found",
                "reason": "No SPF authentication result was identified."
            },

            {
                "category": "DKIM Authentication",
                "points": 0,
                "max_points": 20,
                "status": "Not Found",
                "reason": "No DKIM authentication result was identified."
            },

            {
                "category": "DMARC Authentication",
                "points": 0,
                "max_points": 20,
                "status": "Not Found",
                "reason": "No DMARC authentication result was identified."
            }

        ]

        return result


    # ======================================
    # SPLIT HEADER LINES
    # ======================================

    lines = header_text.splitlines()


    # ======================================
    # HEADER EXTRACTION
    # ======================================

    for line in lines:

        lower = line.lower()


        # ----------------------------------
        # FROM
        # ----------------------------------

        if lower.startswith("from:"):

            result["From"] = (
                line.split(":", 1)[1].strip()
            )


        # ----------------------------------
        # TO
        # ----------------------------------

        elif lower.startswith("to:"):

            result["To"] = (
                line.split(":", 1)[1].strip()
            )


        # ----------------------------------
        # SUBJECT
        # ----------------------------------

        elif lower.startswith("subject:"):

            result["Subject"] = (
                line.split(":", 1)[1].strip()
            )


        # ----------------------------------
        # DATE
        # ----------------------------------

        elif lower.startswith("date:"):

            result["Date"] = (
                line.split(":", 1)[1].strip()
            )


        # ----------------------------------
        # RETURN-PATH
        # ----------------------------------

        elif lower.startswith("return-path:"):

            result["Return-Path"] = (
                line.split(":", 1)[1].strip()
            )


        # ----------------------------------
        # MESSAGE-ID
        # ----------------------------------

        elif lower.startswith("message-id:"):

            result["Message-ID"] = (
                line.split(":", 1)[1].strip()
            )


        # ==================================
        # RECEIVED HEADER
        # ==================================

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


        # ==================================
        # SPF
        # ==================================

        elif "spf=" in lower:

            if "pass" in lower:

                result["SPF"] = "PASS"

            elif "fail" in lower:

                result["SPF"] = "FAIL"


        # ==================================
        # DKIM
        # ==================================

        elif "dkim=" in lower:

            if "pass" in lower:

                result["DKIM"] = "PASS"

            elif "fail" in lower:

                result["DKIM"] = "FAIL"


        # ==================================
        # DMARC
        # ==================================

        elif "dmarc=" in lower:

            if "pass" in lower:

                result["DMARC"] = "PASS"

            elif "fail" in lower:

                result["DMARC"] = "FAIL"


    # ==========================================
    # EXTRACT EMAIL DOMAINS
    # ==========================================

    from_domain = extract_domain(
        result["From"]
    )

    return_domain = extract_domain(
        result["Return-Path"]
    )


    # ==========================================
    # DOMAIN CONSISTENCY
    # ==========================================

    if (
        from_domain
        and return_domain
    ):

        if (
            return_domain != from_domain
            and not return_domain.endswith(
                "." + from_domain
            )
        ):

            result["Findings"].append(
                "From domain and Return-Path domain mismatch."
            )

            result["Risk Score"] += 40

            result["Risk Breakdown"].append({

                "category":
                "Domain Consistency",

                "points":
                40,

                "max_points":
                40,

                "status":
                "Mismatch",

                "reason":
                "The From domain and Return-Path domain do not match."
            })

        else:

            result["Risk Breakdown"].append({

                "category":
                "Domain Consistency",

                "points":
                0,

                "max_points":
                40,

                "status":
                "Consistent",

                "reason":
                "The From domain and Return-Path domain are consistent."
            })

    else:

        result["Risk Breakdown"].append({

            "category":
            "Domain Consistency",

            "points":
            0,

            "max_points":
            40,

            "status":
            "Not Available",

            "reason":
            "Sender or Return-Path domain information was not available for comparison."
        })


    # ==========================================
    # SPF ANALYSIS
    # ==========================================

    if result["SPF"] == "FAIL":

        result["Findings"].append(
            "SPF authentication failed."
        )

        result["Risk Score"] += 20

        result["Risk Breakdown"].append({

            "category":
            "SPF Authentication",

            "points":
            20,

            "max_points":
            20,

            "status":
            "FAIL",

            "reason":
            "The email failed SPF authentication."
        })


    elif result["SPF"] == "PASS":

        result["Findings"].append(
            "SPF authentication passed."
        )

        result["Risk Breakdown"].append({

            "category":
            "SPF Authentication",

            "points":
            0,

            "max_points":
            20,

            "status":
            "PASS",

            "reason":
            "The email passed SPF authentication."
        })


    else:

        result["Risk Breakdown"].append({

            "category":
            "SPF Authentication",

            "points":
            0,

            "max_points":
            20,

            "status":
            "Not Found",

            "reason":
            "No SPF authentication result was identified."
        })


    # ==========================================
    # DKIM ANALYSIS
    # ==========================================

    if result["DKIM"] == "FAIL":

        result["Findings"].append(
            "DKIM authentication failed."
        )

        result["Risk Score"] += 20

        result["Risk Breakdown"].append({

            "category":
            "DKIM Authentication",

            "points":
            20,

            "max_points":
            20,

            "status":
            "FAIL",

            "reason":
            "The email failed DKIM authentication."
        })


    elif result["DKIM"] == "PASS":

        result["Findings"].append(
            "DKIM authentication passed."
        )

        result["Risk Breakdown"].append({

            "category":
            "DKIM Authentication",

            "points":
            0,

            "max_points":
            20,

            "status":
            "PASS",

            "reason":
            "The email passed DKIM authentication."
        })


    else:

        result["Risk Breakdown"].append({

            "category":
            "DKIM Authentication",

            "points":
            0,

            "max_points":
            20,

            "status":
            "Not Found",

            "reason":
            "No DKIM authentication result was identified."
        })


    # ==========================================
    # DMARC ANALYSIS
    # ==========================================

    if result["DMARC"] == "FAIL":

        result["Findings"].append(
            "DMARC authentication failed."
        )

        result["Risk Score"] += 20

        result["Risk Breakdown"].append({

            "category":
            "DMARC Authentication",

            "points":
            20,

            "max_points":
            20,

            "status":
            "FAIL",

            "reason":
            "The email failed DMARC authentication."
        })


    elif result["DMARC"] == "PASS":

        result["Findings"].append(
            "DMARC authentication passed."
        )

        result["Risk Breakdown"].append({

            "category":
            "DMARC Authentication",

            "points":
            0,

            "max_points":
            20,

            "status":
            "PASS",

            "reason":
            "The email passed DMARC authentication."
        })


    else:

        result["Risk Breakdown"].append({

            "category":
            "DMARC Authentication",

            "points":
            0,

            "max_points":
            20,

            "status":
            "Not Found",

            "reason":
            "No DMARC authentication result was identified."
        })


    # ==========================================
    # PUBLIC SENDER IP
    # ==========================================

    if len(result["Sender IP"]) == 0:

        result["Findings"].append(
            "No public sender IP found."
        )

    else:

        result["Findings"].append(
            "Public sender IP information was identified."
        )


    # ==========================================
    # SAFE EMAIL
    # ==========================================

    if result["Risk Score"] == 0:

        result["Findings"].append(
            "No spoofing indicators detected."
        )


    # ==========================================
    # LIMIT SCORE
    # ==========================================

    if result["Risk Score"] > 100:

        result["Risk Score"] = 100


    # ==========================================
    # RISK LEVEL
    # ==========================================

    if result["Risk Score"] >= 70:

        result["Risk Level"] = "HIGH"

    elif result["Risk Score"] >= 40:

        result["Risk Level"] = "MEDIUM"

    else:

        result["Risk Level"] = "LOW"


    # ==========================================
    # FINAL RETURN
    # ==========================================

    return result