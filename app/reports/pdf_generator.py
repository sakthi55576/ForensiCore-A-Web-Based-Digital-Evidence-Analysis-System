from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import (
    getSampleStyleSheet,
    ParagraphStyle
)
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    KeepTogether
)


# ============================================================
# COLORS
# ============================================================

DARK = colors.HexColor("#1F2937")
BLUE = colors.HexColor("#6D28D9")
LIGHT_BLUE = colors.HexColor("#F5F3FF")
LIGHT_GREY = colors.HexColor("#F3F4F6")
BORDER = colors.HexColor("#D1D5DB")
TEXT = colors.HexColor("#111827")
MUTED = colors.HexColor("#6B7280")

LOW = colors.HexColor("#166534")
MEDIUM = colors.HexColor("#B45309")
HIGH = colors.HexColor("#B91C1C")


# ============================================================
# SAFE TEXT CONVERSION
# ============================================================

def safe_text(value):

    if value is None:
        return ""

    if isinstance(value, (list, tuple)):

        return ", ".join(
            str(item)
            for item in value
        )

    if isinstance(value, dict):

        return "; ".join(
            f"{key}: {val}"
            for key, val in value.items()
        )

    return str(value)


# ============================================================
# TABLE CELL
# ============================================================

def cell_text(value, style):

    return Paragraph(
        safe_text(value),
        style
    )


# ============================================================
# PROFESSIONAL TABLE
# ============================================================

def make_table(
    rows,
    col_widths,
    header=True
):

    styles = getSampleStyleSheet()

    table_cell = ParagraphStyle(
        "TableCell",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=8.5,
        leading=11,
        textColor=TEXT,
        spaceAfter=0,
        wordWrap="CJK"
    )

    table_header = ParagraphStyle(
        "TableHeader",
        parent=table_cell,
        fontName="Helvetica-Bold",
        fontSize=8.5,
        leading=11,
        textColor=colors.white
    )

    formatted_rows = []

    for row_index, row in enumerate(rows):

        formatted_row = []

        for value in row:

            if header and row_index == 0:

                formatted_row.append(
                    cell_text(
                        value,
                        table_header
                    )
                )

            else:

                formatted_row.append(
                    cell_text(
                        value,
                        table_cell
                    )
                )

        formatted_rows.append(
            formatted_row
        )

    table = Table(
        formatted_rows,
        colWidths=col_widths,
        repeatRows=1 if header else 0,
        hAlign="LEFT"
    )

    commands = [

        (
            "GRID",
            (0, 0),
            (-1, -1),
            0.5,
            BORDER
        ),

        (
            "VALIGN",
            (0, 0),
            (-1, -1),
            "TOP"
        ),

        (
            "LEFTPADDING",
            (0, 0),
            (-1, -1),
            7
        ),

        (
            "RIGHTPADDING",
            (0, 0),
            (-1, -1),
            7
        ),

        (
            "TOPPADDING",
            (0, 0),
            (-1, -1),
            6
        ),

        (
            "BOTTOMPADDING",
            (0, 0),
            (-1, -1),
            6
        )

    ]

    if header:

        commands.extend([

            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                DARK
            ),

            (
                "TEXTCOLOR",
                (0, 0),
                (-1, 0),
                colors.white
            ),

            (
                "LINEBELOW",
                (0, 0),
                (-1, 0),
                1,
                BLUE
            )

        ])

        start_row = 1

    else:

        start_row = 0

    # Alternate row colors

    for row_index in range(
        start_row,
        len(formatted_rows)
    ):

        if row_index % 2 == 0:

            commands.append(
                (
                    "BACKGROUND",
                    (0, row_index),
                    (-1, row_index),
                    colors.white
                )
            )

        else:

            commands.append(
                (
                    "BACKGROUND",
                    (0, row_index),
                    (-1, row_index),
                    LIGHT_GREY
                )
            )

    table.setStyle(
        TableStyle(commands)
    )

    return table


# ============================================================
# PAGE HEADER / FOOTER
# ============================================================

def draw_page_header_footer(
    canvas,
    document
):

    canvas.saveState()

    width, height = A4

    # --------------------------------------------------------
    # HEADER LINE
    # --------------------------------------------------------

    canvas.setStrokeColor(
        BORDER
    )

    canvas.setLineWidth(
        0.5
    )

    canvas.line(
        document.leftMargin,
        height - 18 * mm,
        width - document.rightMargin,
        height - 18 * mm
    )

    # --------------------------------------------------------
    # HEADER LEFT
    # --------------------------------------------------------

    canvas.setFont(
        "Helvetica-Bold",
        8
    )

    canvas.setFillColor(
        DARK
    )

    canvas.drawString(
        document.leftMargin,
        height - 14 * mm,
        "ForensiCore"
    )

    # --------------------------------------------------------
    # HEADER RIGHT
    # --------------------------------------------------------

    canvas.setFont(
        "Helvetica",
        7.5
    )

    canvas.setFillColor(
        MUTED
    )

    canvas.drawRightString(
        width - document.rightMargin,
        height - 14 * mm,
        "Digital Forensic Investigation Report"
    )

    # --------------------------------------------------------
    # FOOTER LINE
    # --------------------------------------------------------

    canvas.line(
        document.leftMargin,
        14 * mm,
        width - document.rightMargin,
        14 * mm
    )

    # --------------------------------------------------------
    # FOOTER LEFT
    # --------------------------------------------------------

    canvas.setFont(
        "Helvetica",
        7.5
    )

    canvas.setFillColor(
        MUTED
    )

    canvas.drawString(
        document.leftMargin,
        9 * mm,
        "Generated by ForensiCore"
    )

    # --------------------------------------------------------
    # FOOTER RIGHT
    # --------------------------------------------------------

    canvas.drawRightString(
        width - document.rightMargin,
        9 * mm,
        f"Page {document.page}"
    )

    canvas.restoreState()


# ============================================================
# FINAL FORENSIC REPORT
# ============================================================


# ============================================================
# EVIDENCE INTEGRITY, CUSTODY, FINDINGS, TIMELINE, LIMITATIONS
# ============================================================

from xml.sax.saxutils import escape as _xml_escape


def _e(value, limit=None):

    text = safe_text(value)

    if limit and len(text) > limit:
        text = text[:limit - 1] + "..."

    return _xml_escape(text)


def build_extra_sections(
    story,
    section_style,
    subsection_style,
    body_style,
    finding_style,
    integrity_rows,
    custody_rows,
    findings_rows,
    timeline_rows,
    correlation_rows
):

    # ---------------- 6. evidence integrity ----------------

    story.append(Paragraph("6. Evidence Integrity", section_style))
    story.append(Spacer(1, 4))

    story.append(Paragraph(
        "Every evidence file was hashed with MD5 and SHA-256 when it "
        "was acquired. Before each analysis the file was hashed again "
        "and compared with these values; an analysis is refused if "
        "they differ.",
        body_style
    ))
    story.append(Spacer(1, 4))

    if integrity_rows:

        for item in integrity_rows[:30]:

            rows = [
                ["Evidence", _e("#{}  {}".format(item["id"], item["name"]))],
                ["Detected type", _e(item["type"])],
                ["Size", _e(item["size"])],
                ["MD5", _e(item["md5"])],
                ["SHA-256", _e(item["sha256"])],
                ["Hash recorded", _e("{} ({})".format(
                    item["recorded_at"], item["baseline"]))],
                ["Integrity status", _e("{} (last checked {})".format(
                    item["status"], item["verified_at"]))],
            ]

            story.append(KeepTogether([
                make_table(rows, [38 * mm, 136 * mm], header=False),
                Spacer(1, 6)
            ]))

    else:

        story.append(Paragraph("No evidence files were recorded.", body_style))

    story.append(Spacer(1, 10))

    # ---------------- 7. chain of custody ----------------

    story.append(Paragraph("7. Chain of Custody", section_style))
    story.append(Spacer(1, 4))

    story.append(Paragraph(
        "Every action on this case (upload, verification, analysis, "
        "report) is recorded with the user, time and IP address. "
        "The log is append-only; the application offers no way to "
        "edit or delete an entry.",
        body_style
    ))
    story.append(Spacer(1, 4))

    if custody_rows:

        rows = [["Time (UTC)", "User", "Action", "Details"]]

        for item in custody_rows[-80:]:

            rows.append([
                _e(item["time"]),
                _e(item["user"], 30),
                _e(item["action"]),
                _e(item["details"], 170)
            ])

        story.append(make_table(
            rows, [32 * mm, 28 * mm, 34 * mm, 80 * mm]
        ))

    else:

        story.append(Paragraph("No custody entries were recorded.", body_style))

    story.append(Spacer(1, 12))

    # ---------------- 8. consolidated findings ----------------

    story.append(Paragraph("8. Consolidated Findings", section_style))
    story.append(Spacer(1, 4))

    if findings_rows:

        rows = [["Severity", "Module", "Finding", "Details"]]

        for item in findings_rows[:60]:

            rows.append([
                _e(item["severity"]),
                _e(item["module"]),
                _e(item["title"], 110),
                _e(item["detail"], 220)
            ])

        story.append(make_table(
            rows, [20 * mm, 20 * mm, 55 * mm, 79 * mm]
        ))

    else:

        story.append(Paragraph(
            "No findings have been recorded yet.", body_style
        ))

    story.append(Spacer(1, 12))

    # ---------------- 9. timeline ----------------

    story.append(Paragraph("9. Event Timeline (UTC)", section_style))
    story.append(Spacer(1, 4))

    if timeline_rows:

        rows = [["Time (UTC)", "Module", "Event", "Time basis"]]

        for item in timeline_rows[-50:]:

            rows.append([
                _e(item["time"]),
                _e(item["module"]),
                _e(item["title"], 110),
                _e(item["note"], 60)
            ])

        story.append(make_table(
            rows, [32 * mm, 20 * mm, 80 * mm, 42 * mm]
        ))

    else:

        story.append(Paragraph("No dated events were extracted.", body_style))

    if correlation_rows:

        story.append(Spacer(1, 6))
        story.append(Paragraph(
            "Cross-evidence correlations (leads, not proof)",
            subsection_style
        ))

        for text in correlation_rows:
            story.append(Paragraph("&bull; " + _e(text), finding_style))

    story.append(Spacer(1, 12))

    # ---------------- 10. methodology ----------------

    story.append(Paragraph(
        "10. Methodology and Limitations", section_style
    ))
    story.append(Spacer(1, 4))

    for line in [
        "Risk scores are built from observable indicators. An "
        "indicator is a lead for the investigator and is NOT proof of "
        "wrongdoing.",
        "The overall risk is the highest module score, plus 10 when at "
        "least two independent modules reach MEDIUM or higher.",
        "Missing image metadata is reported as information only: "
        "screenshots and messaging apps legitimately strip EXIF data.",
        "Photo capture times carry no timezone. When correlated with "
        "UTC sources, the timezone stated in the file is used, "
        "otherwise the assumption noted in the timeline.",
        "Sender IP geolocation (when enabled) uses the external "
        "ipinfo.io service and is approximate.",
        "Evidence is opened read-only during analysis; the recorded "
        "hashes prove the files were not altered by ForensiCore.",
    ]:

        story.append(Paragraph("&bull; " + _e(line), finding_style))

    story.append(Spacer(1, 15))

def generate_forensic_report(
    output_path,
    case_data,
    metadata_data=None,
    email_data=None,
    browser_data=None,
    overall_risk_data=None,
    integrity_rows=None,
    custody_rows=None,
    findings_rows=None,
    timeline_rows=None,
    correlation_rows=None
):

    print(
        "\n=========================================="
    )

    print(
        "PDF GENERATOR STARTED"
    )

    print(
        "=========================================="
    )

    print(
        "Browser data received:",
        bool(browser_data)
    )

    if browser_data:

        print(
            "Browser data keys:",
            list(browser_data.keys())
        )

    else:

        print(
            "WARNING: browser_data is EMPTY"
        )

    # ========================================================
    # DOCUMENT
    # ========================================================

    document = SimpleDocTemplate(

        output_path,

        pagesize=A4,

        rightMargin=18 * mm,

        leftMargin=18 * mm,

        topMargin=25 * mm,

        bottomMargin=20 * mm,

        title="ForensiCore: A ForensiCore - Forensic Investigation Report",

        author="ForensiCore"
    )

    styles = getSampleStyleSheet()

    # ========================================================
    # STYLES
    # ========================================================

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=25,
        leading=30,
        alignment=TA_CENTER,
        textColor=DARK,
        spaceAfter=8
    )

    subtitle_style = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=12,
        leading=16,
        alignment=TA_CENTER,
        textColor=MUTED,
        spaceAfter=20
    )

    section_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=15,
        leading=19,
        textColor=DARK,
        spaceBefore=8,
        spaceAfter=10,
        keepWithNext=True
    )

    subsection_style = ParagraphStyle(
        "SubsectionHeading",
        parent=styles["Heading3"],
        fontName="Helvetica-Bold",
        fontSize=11,
        leading=14,
        textColor=BLUE,
        spaceBefore=7,
        spaceAfter=7,
        keepWithNext=True
    )

    body_style = ParagraphStyle(
        "ReportBody",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=9.5,
        leading=14,
        textColor=TEXT,
        spaceAfter=7
    )

    finding_style = ParagraphStyle(
        "Finding",
        parent=body_style,
        leftIndent=10,
        firstLineIndent=-8,
        bulletIndent=0,
        spaceAfter=5
    )

    story = []

    # ========================================================
    # COVER PAGE
    # ========================================================

    story.append(
        Spacer(
            1,
            25 * mm
        )
    )

    story.append(
        Paragraph(
            "ForensiCore",
            title_style
        )
    )

    story.append(
        Paragraph(
            "A Digital Evidence Analyzer",
            subtitle_style
        )
    )

    story.append(
        Paragraph(
            "Digital Forensic Investigation Report",
            subtitle_style
        )
    )

    story.append(
        Spacer(
            1,
            10 * mm
        )
    )

    cover_rows = [

        [
            "Report Type",
            safe_text(
                case_data.get(
                    "Report Type",
                    "Forensic Investigation Report"
                )
            )
        ],

        [
            "Case ID",
            safe_text(
                case_data.get(
                    "Case ID",
                    "Not Available"
                )
            )
        ],

        [
            "Case Type",
            safe_text(
                case_data.get(
                    "Case Type",
                    "Digital Forensic Investigation"
                )
            )
        ],

        [
            "System",
            safe_text(
                case_data.get(
                    "System",
                    "ForensiCore: A Digital Evidence Analyzer"
                )
            )
        ]

    ]

    story.append(
        make_table(
            cover_rows,
            [45 * mm, 120 * mm],
            header=False
        )
    )

    story.append(
        Spacer(
            1,
            20 * mm
        )
    )

    confidential_style = ParagraphStyle(
        "Confidential",
        parent=body_style,
        alignment=TA_CENTER,
        fontName="Helvetica-Bold",
        fontSize=9,
        textColor=HIGH
    )

    story.append(
        Paragraph(
            "CONFIDENTIAL FORENSIC DOCUMENT",
            confidential_style
        )
    )

    story.append(
        PageBreak()
    )

    # ========================================================
    # 1. CASE INFORMATION
    # ========================================================

    case_section = []

    case_section.append(
        Paragraph(
            "1. Case Information",
            section_style
        )
    )

    case_rows = [
        ["Field", "Value"]
    ]

    for key, value in case_data.items():

        case_rows.append(
            [
                safe_text(key),
                safe_text(value)
            ]
        )

    case_section.append(
        make_table(
            case_rows,
            [50 * mm, 115 * mm]
        )
    )

    story.append(
        KeepTogether(
            case_section
        )
    )

    story.append(
        Spacer(
            1,
            10
        )
    )

    # ========================================================
    # 2. METADATA ANALYSIS
    # ========================================================

    if metadata_data:

        metadata_section = []

        metadata_section.append(
            Paragraph(
                "2. Metadata Analysis",
                section_style
            )
        )

        metadata_rows = [
            ["Field", "Value"]
        ]

        for key, value in metadata_data.items():

            metadata_rows.append(
                [
                    safe_text(key),
                    safe_text(value)
                ]
            )

        metadata_section.append(
            make_table(
                metadata_rows,
                [50 * mm, 115 * mm]
            )
        )

        story.append(
            KeepTogether(
                metadata_section
            )
        )

        story.append(
            Spacer(
                1,
                10
            )
        )

    # ========================================================
    # 3. EMAIL FORENSIC ANALYSIS
    # ========================================================

    if email_data:

        story.append(
            Paragraph(
                "3. Email Forensic Analysis",
                section_style
            )
        )

        email_rows = [
            ["Field", "Value"]
        ]

        normal_email_fields = [

            "File Name",
            "File Hash",
            "Hash Algorithm",
            "From",
            "To",
            "Subject",
            "Date",
            "Return-Path",
            "Message-ID",
            "SPF",
            "DKIM",
            "DMARC",
            "Risk Score",
            "Risk Level"

        ]

        for key in normal_email_fields:

            if key in email_data:

                email_rows.append(
                    [
                        safe_text(key),
                        safe_text(
                            email_data[key]
                        )
                    ]
                )

        story.append(
            make_table(
                email_rows,
                [50 * mm, 115 * mm]
            )
        )

        story.append(
            Spacer(
                1,
                8
            )
        )

        # ----------------------------------------------------
        # SENDER IP
        # ----------------------------------------------------

        if email_data.get(
            "Sender IP"
        ):

            story.append(
                Paragraph(
                    "Sender IP Information",
                    subsection_style
                )
            )

            ip_rows = [
                ["IP Address"]
            ]

            for ip in email_data.get(
                "Sender IP",
                []
            ):

                ip_rows.append(
                    [
                        safe_text(ip)
                    ]
                )

            story.append(
                make_table(
                    ip_rows,
                    [165 * mm]
                )
            )

            story.append(
                Spacer(
                    1,
                    8
                )
            )

        # ----------------------------------------------------
        # IP LOCATION
        # ----------------------------------------------------

        if email_data.get(
            "IP Location"
        ):

            story.append(
                Paragraph(
                    "IP Location",
                    subsection_style
                )
            )

            location_rows = [

                [
                    "IP",
                    "Country",
                    "City",
                    "Region",
                    "ISP"
                ]

            ]

            for location in email_data.get(
                "IP Location",
                []
            ):

                location_rows.append(
                    [

                        safe_text(
                            location.get(
                                "IP",
                                ""
                            )
                        ),

                        safe_text(
                            location.get(
                                "Country",
                                ""
                            )
                        ),

                        safe_text(
                            location.get(
                                "City",
                                ""
                            )
                        ),

                        safe_text(
                            location.get(
                                "Region",
                                ""
                            )
                        ),

                        safe_text(
                            location.get(
                                "ISP",
                                ""
                            )
                        )

                    ]
                )

            story.append(
                make_table(
                    location_rows,
                    [
                        28 * mm,
                        25 * mm,
                        28 * mm,
                        28 * mm,
                        56 * mm
                    ]
                )
            )

            story.append(
                Spacer(
                    1,
                    8
                )
            )

        # ----------------------------------------------------
        # EMAIL FINDINGS
        # ----------------------------------------------------

        findings = email_data.get(
            "Findings",
            []
        )

        story.append(
            Paragraph(
                "Email Security Findings",
                subsection_style
            )
        )

        if findings:

            for finding in findings:

                story.append(
                    Paragraph(
                        "• " + safe_text(finding),
                        finding_style
                    )
                )

        else:

            story.append(
                Paragraph(
                    "No email security findings identified.",
                    body_style
                )
            )

        story.append(
            Spacer(
                1,
                10
            )
        )

    # ========================================================
    # 4. BROWSER HISTORY ANALYSIS
    # ========================================================

    story.append(
        Paragraph(
            "4. Browser History Analysis",
            section_style
        )
    )

    if browser_data is None:

        browser_data = {}

    history_data = browser_data.get(
        "history_data",
        {}
    )

    top_sites = browser_data.get(
        "top_sites",
        []
    )

    timeline = browser_data.get(
        "timeline",
        []
    )

    history_file = browser_data.get(
        "history_file",
        "Not Available"
    )

    file_hash = browser_data.get(
        "file_hash",
        "Not Available"
    )

    risk_data = browser_data.get(
        "risk_data",
        {}
    )

    # ========================================================
    # BROWSER SUMMARY
    # ========================================================

    story.append(
        Paragraph(
            "Browser Summary",
            subsection_style
        )
    )

    total_urls = history_data.get(
        "Total URLs",
        0
    )

    summary_rows = [

        [
            "Field",
            "Value"
        ],

        [
            "Evidence File",
            safe_text(history_file)
        ],

        [
            "Total URLs",
            safe_text(total_urls)
        ]

    ]

    story.append(
        make_table(
            summary_rows,
            [50 * mm, 115 * mm]
        )
    )

    story.append(
        Spacer(
            1,
            10
        )
    )

    # ========================================================
    # TOP WEBSITES
    # ========================================================

    story.append(
        Paragraph(
            "Top Visited Websites",
            subsection_style
        )
    )

    if top_sites:

        top_rows = [

            [
                "Rank",
                "Website",
                "Visits"
            ]

        ]

        for index, site in enumerate(
            top_sites[:15],
            start=1
        ):

            top_rows.append(
                [

                    safe_text(index),

                    safe_text(
                        site.get(
                            "URL",
                            ""
                        )
                    ),

                    safe_text(
                        site.get(
                            "Visit Count",
                            0
                        )
                    )

                ]
            )

        story.append(
            make_table(
                top_rows,
                [
                    15 * mm,
                    130 * mm,
                    20 * mm
                ]
            )
        )

    else:

        story.append(
            Paragraph(
                "No top visited website data available.",
                body_style
            )
        )

    story.append(
        Spacer(
            1,
            10
        )
    )

    # ========================================================
    # BROWSING TIMELINE
    # ========================================================

    story.append(
        Paragraph(
            "Browsing Timeline",
            subsection_style
        )
    )

    if timeline:

        browser_timeline_rows = [

            [
                "Time",
                "Website",
                "Title"
            ]

        ]

        for item in timeline[:50]:

            browser_timeline_rows.append(
                [

                    safe_text(
                        item.get(
                            "Last Visit",
                            ""
                        )
                    ),

                    safe_text(
                        item.get(
                            "URL",
                            ""
                        )
                    ),

                    safe_text(
                        item.get(
                            "Title",
                            ""
                        )
                    )

                ]
            )

        story.append(
            make_table(
                browser_timeline_rows,
                [
                    30 * mm,
                    85 * mm,
                    50 * mm
                ]
            )
        )

    else:

        story.append(
            Paragraph(
                "No browsing timeline available.",
                body_style
            )
        )

    story.append(
        Spacer(
            1,
            10
        )
    )

    # ========================================================
    # EVIDENCE INTEGRITY
    # ========================================================

    story.append(
        Paragraph(
            "Evidence Integrity",
            subsection_style
        )
    )

    browser_integrity_rows = [

        [
            "Field",
            "Value"
        ],

        [
            "Evidence File",
            safe_text(history_file)
        ],

        [
            "Hash Algorithm",
            "SHA-256 (MD5 also recorded - see section 6)"
        ],

        [
            "SHA-256 Hash",
            safe_text(file_hash)
        ]

    ]

    story.append(
        make_table(
            browser_integrity_rows,
            [50 * mm, 115 * mm]
        )
    )

    story.append(
        Spacer(
            1,
            10
        )
    )

    # ========================================================
    # BROWSER RISK ASSESSMENT
    # ========================================================

    story.append(
        Paragraph(
            "Browser Risk Assessment",
            subsection_style
        )
    )

    risk_score = risk_data.get(
        "Risk Score",
        0
    )

    risk_level = risk_data.get(
        "Risk Level",
        "Unknown"
    )

    risk_rows = [

        [
            "Risk Score",
            f"{safe_text(risk_score)} / 100"
        ],

        [
            "Risk Level",
            safe_text(risk_level)
        ]

    ]

    risk_table = make_table(
        risk_rows,
        [50 * mm, 115 * mm],
        header=False
    )

    level = str(
        risk_level
    ).upper()

    if level == "HIGH":

        risk_color = HIGH

    elif level == "MEDIUM":

        risk_color = MEDIUM

    elif level == "LOW":

        risk_color = LOW

    else:

        risk_color = MUTED

    risk_table.setStyle(
        TableStyle([

            (
                "TEXTCOLOR",
                (1, 1),
                (1, 1),
                risk_color
            ),

            (
                "FONTNAME",
                (1, 1),
                (1, 1),
                "Helvetica-Bold"
            )

        ])
    )

    story.append(
        risk_table
    )

    story.append(
        Spacer(
            1,
            8
        )
    )

    # ========================================================
    # SECURITY FINDINGS
    # ========================================================

    story.append(
        Paragraph(
            "Security Findings",
            subsection_style
        )
    )

    findings = risk_data.get(
        "Findings",
        []
    )

    if findings:

        for finding in findings:

            story.append(
                Paragraph(
                    "• " + safe_text(finding),
                    finding_style
                )
            )

    else:

        story.append(
            Paragraph(
                "No security findings identified.",
                body_style
            )
        )

    story.append(
        Spacer(
            1,
            12
        )
    )

    # ========================================================
    # OVERALL RISK ENGINE
    # ========================================================

    print(
        "Loading existing overall forensic risk assessment..."
    )

    if overall_risk_data:

        print(
            "Overall risk data received:",
            overall_risk_data
        )

    else:

        print(
            "WARNING: Overall risk data is not available."
        )

        overall_risk_data = {}

    # ========================================================
    # 5. OVERALL FORENSIC RISK ASSESSMENT
    # ========================================================

    overall_section = []

    overall_section.append(
        Paragraph(
            "5. Overall Forensic Risk Assessment",
            section_style
        )
    )

    overall_section.append(
        Spacer(
            1,
            4
        )
    )

    if overall_risk_data:

        overall_score = overall_risk_data.get(
            "Overall Score",
            0
        )

        overall_level = overall_risk_data.get(
            "Overall Risk Level",
            "UNKNOWN"
        )

        metadata_score = overall_risk_data.get(
            "Metadata Score",
            0
        )

        email_score = overall_risk_data.get(
            "Email Score",
            0
        )

        browser_score = overall_risk_data.get(
            "Browser Score",
            0
        )

        overall_rows = [

            [
                "Assessment",
                "Result"
            ],

            [
                "Overall Risk Score",
                f"{safe_text(overall_score)} / 100"
            ],

            [
                "Overall Risk Level",
                safe_text(overall_level)
            ],

            [
                "Metadata Risk Score",
                f"{safe_text(metadata_score)} / 100"
            ],

            [
                "Email Risk Score",
                f"{safe_text(email_score)} / 100"
            ],

            [
                "Browser Risk Score",
                f"{safe_text(browser_score)} / 100"
            ]

        ]

        overall_section.append(
            make_table(
                overall_rows,
                [50 * mm, 115 * mm]
            )
        )

        overall_section.append(
            Spacer(
                1,
                10
            )
        )

        overall_section.append(
            Paragraph(
                "Overall Security Findings",
                subsection_style
            )
        )

        overall_findings = overall_risk_data.get(
            "Findings",
            []
        )

        if overall_findings:

            for finding in overall_findings:

                overall_section.append(
                    Paragraph(
                        "• " + safe_text(finding),
                        finding_style
                    )
                )

        else:

            overall_section.append(
                Paragraph(
                    "No significant overall forensic risk indicators detected.",
                    body_style
                )
            )

    else:

        overall_section.append(
            Paragraph(
                "Overall Risk Engine data is not available.",
                body_style
            )
        )

    story.append(
        KeepTogether(
            overall_section
        )
    )

    story.append(
        Spacer(
            1,
            15
        )
    )

    build_extra_sections(
        story,
        section_style,
        subsection_style,
        body_style,
        finding_style,
        integrity_rows,
        custody_rows,
        findings_rows,
        timeline_rows,
        correlation_rows
    )

    # ========================================================
    # 11. FINAL CONCLUSION
    # ========================================================

    story.append(
        Paragraph(
            "11. Final Conclusion",
            section_style
        )
    )

    conclusion = (
        "This report consolidates the digital forensic analysis "
        "produced by ForensiCore for this case: evidence hashes and "
        "integrity verification, the chain of custody, the findings "
        "of the metadata, email and browser analyzers, a correlated "
        "event timeline and an overall risk assessment. Findings are "
        "indicators for review by the investigator and should be "
        "corroborated before any conclusion is drawn."
    )
    story.append(
        Paragraph(
            conclusion,
            body_style
        )
    )

    story.append(
        Spacer(
            1,
            20
        )
    )

    # ========================================================
    # END OF REPORT
    # ========================================================

    end_style = ParagraphStyle(
        "EndReport",
        parent=body_style,
        alignment=TA_CENTER,
        fontName="Helvetica-Bold",
        fontSize=9,
        textColor=MUTED
    )

    story.append(
        Paragraph(
            "— End of Forensic Report —",
            end_style
        )
    )

    # ========================================================
    # BUILD PDF
    # ========================================================

    document.build(
        story,
        onFirstPage=draw_page_header_footer,
        onLaterPages=draw_page_header_footer
    )

    print(
        "PDF generated successfully."
    )

    print(
        "PDF path:",
        output_path
    )

    print(
        "==========================================\n"
    )