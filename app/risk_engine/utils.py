# ==========================================
# FORENSICORE - OVERALL RISK ENGINE
# ==========================================


# ==========================================
# NORMALIZE RISK LEVEL
# ==========================================

def normalize_risk_level(level):

    if not level:
        return "LOW"

    level = str(level).upper().strip()

    if level in ["HIGH", "MEDIUM", "LOW"]:
        return level

    return "LOW"


# ==========================================
# NORMALIZE RISK SCORE
# ==========================================

def normalize_risk_score(score):

    try:
        score = int(score)
    except (ValueError, TypeError):
        score = 0

    return max(
        0,
        min(score, 100)
    )


# ==========================================
# EMAIL RISK SCORE
# ==========================================

def get_email_risk_score(email_data):

    if not email_data:
        return 0

    return normalize_risk_score(
        email_data.get(
            "Risk Score",
            0
        )
    )


# ==========================================
# BROWSER RISK SCORE
# ==========================================

def get_browser_risk_score(browser_data):

    if not browser_data:
        return 0

    return normalize_risk_score(
        browser_data.get(
            "Risk Score",
            0
        )
    )


# ==========================================
# OVERALL RISK LEVEL
# ==========================================

def calculate_overall_level(score):

    score = normalize_risk_score(score)

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
    metadata_score=0,
    metadata_risk="LOW",
    email_data=None,
    browser_data=None
):

    findings = []


    # ======================================
    # METADATA SCORE
    # ======================================

    metadata_score = normalize_risk_score(
        metadata_score
    )

    metadata_level = normalize_risk_level(
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
    # COLLECT METADATA FINDINGS
    # ======================================

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


    # ======================================
    # COLLECT EMAIL FINDINGS
    # ======================================

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


    # ======================================
    # COLLECT BROWSER FINDINGS
    # ======================================

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
    # ACTIVE MODULE SCORES
    # ======================================

    active_scores = []


    # Metadata is active when a score
    # or risk level is available.

    if metadata_score > 0 or metadata_risk:

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


    # ======================================
    # CALCULATE OVERALL SCORE
    # ======================================

    if active_scores:

        overall_score = round(
            sum(active_scores)
            / len(active_scores)
        )

    else:

        overall_score = 0


    overall_score = normalize_risk_score(
        overall_score
    )


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