# ==========================================
# FORENSICORE - OVERALL RISK ENGINE
# ==========================================


def normalize_risk_level(level):

    if not level:
        return "LOW"

    level = str(level).upper().strip()

    if level in ["HIGH", "MEDIUM", "LOW"]:
        return level

    return "LOW"


# ==========================================
# CONVERT RISK LEVEL TO SCORE
# ==========================================

def risk_level_to_score(level):

    level = normalize_risk_level(level)

    if level == "HIGH":
        return 80

    elif level == "MEDIUM":
        return 50

    else:
        return 10


# ==========================================
# EMAIL RISK SCORE
# ==========================================

def get_email_risk_score(email_data):

    if not email_data:
        return 0

    try:

        score = int(
            email_data.get(
                "Risk Score",
                0
            )
        )

    except (ValueError, TypeError):

        score = 0

    # Keep score within 0-100

    return max(
        0,
        min(score, 100)
    )


# ==========================================
# BROWSER RISK SCORE
# ==========================================

def get_browser_risk_score(browser_data):

    if not browser_data:
        return 0

    try:

        score = int(
            browser_data.get(
                "Risk Score",
                0
            )
        )

    except (ValueError, TypeError):

        score = 0

    return max(
        0,
        min(score, 100)
    )


# ==========================================
# OVERALL RISK LEVEL
# ==========================================

def calculate_overall_level(score):

    if score >= 70:

        return "HIGH"

    elif score >= 40:

        return "MEDIUM"

    else:

        return "LOW"


# ==========================================
# GENERATE OVERALL FORENSIC RISK REPORT
# ==========================================

def generate_overall_risk_report(
    metadata_risk="LOW",
    email_data=None,
    browser_data=None
):

    findings = []


    # ======================================
    # METADATA SCORE
    # ======================================

    metadata_score = risk_level_to_score(
        metadata_risk
    )


    # ======================================
    # EMAIL SCORE
    # ======================================

    email_score = get_email_risk_score(
        email_data
    )


    # ======================================
    # BROWSER SCORE
    # ======================================

    browser_score = get_browser_risk_score(
        browser_data
    )


    # ======================================
    # COLLECT FINDINGS
    # ======================================

    # Metadata

    metadata_level = normalize_risk_level(
        metadata_risk
    )

    if metadata_level == "HIGH":

        findings.append(
            "High-risk indicators detected "
            "during metadata analysis."
        )

    elif metadata_level == "MEDIUM":

        findings.append(
            "Medium-risk indicators detected "
            "during metadata analysis."
        )


    # Email

    if email_data:

        email_level = normalize_risk_level(
            email_data.get(
                "Risk Level",
                "LOW"
            )
        )

        if email_level == "HIGH":

            findings.append(
                "High-risk email security "
                "indicators detected."
            )

        elif email_level == "MEDIUM":

            findings.append(
                "Medium-risk email security "
                "indicators detected."
            )

        email_findings = email_data.get(
            "Findings",
            []
        )

        if email_findings:

            for finding in email_findings:

                findings.append(
                    "Email: " + str(finding)
                )


    # Browser

    if browser_data:

        browser_level = normalize_risk_level(
            browser_data.get(
                "Risk Level",
                "LOW"
            )
        )

        if browser_level == "HIGH":

            findings.append(
                "High-risk indicators detected "
                "in browser history."
            )

        elif browser_level == "MEDIUM":

            findings.append(
                "Medium-risk indicators detected "
                "in browser history."
            )

        browser_findings = browser_data.get(
            "Findings",
            []
        )

        if browser_findings:

            for finding in browser_findings:

                findings.append(
                    "Browser: " + str(finding)
                )


    # ======================================
    # CALCULATE OVERALL SCORE
    # ======================================

    scores = [

        metadata_score,

        email_score,

        browser_score

    ]


    # Only consider modules that have data

    active_scores = []


    if metadata_risk:

        active_scores.append(
            metadata_score
        )


    if email_data:

        active_scores.append(
            email_score
        )


    if browser_data:

        active_scores.append(
            browser_score
        )


    if active_scores:

        overall_score = round(
            sum(active_scores)
            / len(active_scores)
        )

    else:

        overall_score = 0


    # ======================================
    # OVERALL RISK LEVEL
    # ======================================

    overall_level = calculate_overall_level(
        overall_score
    )


    # ======================================
    # DEFAULT FINDING
    # ======================================

    if not findings:

        findings.append(
            "No significant forensic risk "
            "indicators detected."
        )


    # ======================================
    # FINAL RESULT
    # ======================================

    return {

        "Metadata Risk":
        metadata_level,

        "Metadata Score":
        metadata_score,

        "Email Score":
        email_score,

        "Browser Score":
        browser_score,

        "Overall Score":
        overall_score,

        "Overall Risk Level":
        overall_level,

        "Findings":
        findings

    }