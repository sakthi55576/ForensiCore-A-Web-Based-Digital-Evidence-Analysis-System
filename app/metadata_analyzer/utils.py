"""
Image metadata analyzer.

What changed compared with the first version
--------------------------------------------
* EXIF is now read from ALL of its parts (main IFD + Exif sub-IFD +
  GPS IFD). Before, capture time, exposure data and GPS were silently
  missed for most JPEG files.
* Text values are cleaned (camera names came back padded with NULs).
* Risk scoring is based on MANIPULATION INDICATORS (editing software,
  timestamp inconsistency, dimension mismatch). Missing metadata is
  reported as information only: screenshots, WhatsApp and social media
  images legitimately have no EXIF.
* Hashing is no longer done here - the hashes recorded at acquisition
  are used (MD5 + SHA-256).
* Findings and timeline events are produced for the case-level views.
"""

import mimetypes
import os
from datetime import datetime, timedelta

from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS

from app.utils.findings import (
    make_finding,
    severity_from_points,
    level_from_score
)
from app.utils.timeutil import (
    parse_exif_datetime,
    parse_offset_minutes,
    local_to_utc,
    utcnow
)

SUPPORTED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".tif", ".tiff"}

EXIF_IFD = 0x8769
GPS_IFD = 0x8825

EDITING_KEYWORDS = [
    "photoshop", "gimp", "lightroom", "snapseed", "picsart",
    "canva", "paint.net", "affinity", "adobe", "pixlr",
    "fotor", "facetune", "meitu", "remini"
]

CAMERA_KEYWORDS = [
    "camera", "mediatek", "qualcomm", "oppo", "samsung", "xiaomi",
    "vivo", "huawei", "apple", "google", "pixel", "sony", "canon",
    "nikon", "fujifilm", "oneplus", "realme", "motorola", "ios"
]


# ==========================================
# HELPERS
# ==========================================

def clean_text(value):

    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="ignore")

    return str(value).replace("\x00", "").strip()


def to_float(value):

    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def convert_to_degrees(value):

    try:
        degrees = float(value[0])
        minutes = float(value[1])
        seconds = float(value[2])
        return degrees + minutes / 60.0 + seconds / 3600.0
    except Exception:
        return None


def classify_software(software):

    if not software:
        return None

    text = str(software).lower()

    if any(keyword in text for keyword in EDITING_KEYWORDS):
        return "Editing Software"

    if any(keyword in text for keyword in CAMERA_KEYWORDS):
        return "Camera / Device Software"

    return "Processing Software"


# ==========================================
# FILE VALIDATION
# ==========================================

def validate_image_file(file_path):

    try:
        with Image.open(file_path) as image:
            image.verify()
        return True, "Valid image file."
    except Exception:
        return False, (
            "The file is corrupted or cannot be processed "
            "as a valid image."
        )


# ==========================================
# EXIF EXTRACTION
# ==========================================

def _read_all_exif(image):

    """Merge main IFD, Exif sub-IFD and GPS sub-IFD into name->value."""

    exif = image.getexif()

    merged = {}

    if not exif:
        return merged, {}

    for tag_id, value in exif.items():
        merged[TAGS.get(tag_id, tag_id)] = value

    try:
        for tag_id, value in exif.get_ifd(EXIF_IFD).items():
            merged[TAGS.get(tag_id, tag_id)] = value
    except Exception:
        pass

    gps = {}

    try:
        for tag_id, value in exif.get_ifd(GPS_IFD).items():
            gps[GPSTAGS.get(tag_id, tag_id)] = value
    except Exception:
        pass

    return merged, gps


def extract_image_metadata(file_path):

    clean = {}

    try:

        with Image.open(file_path) as image:

            width, height = image.size

            clean["Format"] = image.format
            clean["Image Width"] = width
            clean["Image Height"] = height
            clean["Color Mode"] = image.mode

            raw, gps = _read_all_exif(image)

            info = dict(image.info or {})

    except Exception as error:

        clean["Analysis Error"] = str(error)
        clean["Metadata Status"] = "Limited / Not Available"

        return clean

    def text(name):
        value = raw.get(name)
        if value in (None, ""):
            return None
        return clean_text(value)

    mapping = [
        ("Camera Make", "Make"),
        ("Camera Model", "Model"),
        ("Software", "Software"),
        ("Original Capture Time", "DateTimeOriginal"),
        ("Digitized Time", "DateTimeDigitized"),
        ("File Metadata Time", "DateTime"),
        ("Timezone Offset", "OffsetTimeOriginal"),
    ]

    for label, key in mapping:

        value = text(key)

        if value:
            clean[label] = value

    # PNG and some tools keep the software name outside EXIF
    if "Software" not in clean and info.get("Software"):
        clean["Software"] = clean_text(info["Software"])

    if "Timezone Offset" not in clean and raw.get("OffsetTime"):
        clean["Timezone Offset"] = clean_text(raw["OffsetTime"])

    # Shooting details
    exposure = to_float(raw.get("ExposureTime"))
    fnumber = to_float(raw.get("FNumber"))
    focal = to_float(raw.get("FocalLength"))
    iso = raw.get("ISOSpeedRatings") or raw.get("PhotographicSensitivity")

    if exposure:
        clean["Exposure Time"] = (
            "1/{}s".format(round(1 / exposure))
            if 0 < exposure < 1 else "{}s".format(exposure)
        )

    if fnumber:
        clean["F-Number"] = "f/{}".format(round(fnumber, 1))

    if focal:
        clean["Focal Length"] = "{} mm".format(round(focal, 1))

    if iso:
        clean["ISO"] = iso if not isinstance(iso, tuple) else iso[0]

    if raw.get("Flash") is not None:
        clean["Flash"] = raw.get("Flash")

    # Dimensions the camera wrote into EXIF (used for consistency check)
    exif_w = raw.get("ExifImageWidth") or raw.get("PixelXDimension")
    exif_h = raw.get("ExifImageHeight") or raw.get("PixelYDimension")

    if exif_w and exif_h:
        clean["EXIF Width"] = int(exif_w)
        clean["EXIF Height"] = int(exif_h)

    # ---------------- GPS ----------------

    if "GPSLatitude" in gps and "GPSLongitude" in gps:

        latitude = convert_to_degrees(gps["GPSLatitude"])
        longitude = convert_to_degrees(gps["GPSLongitude"])

        if latitude is not None and longitude is not None:

            if gps.get("GPSLatitudeRef") in ("S", b"S"):
                latitude = -latitude

            if gps.get("GPSLongitudeRef") in ("W", b"W"):
                longitude = -longitude

            clean["GPS Status"] = "Available"
            clean["Latitude"] = round(latitude, 6)
            clean["Longitude"] = round(longitude, 6)

            altitude = to_float(gps.get("GPSAltitude"))

            if altitude is not None:
                clean["Altitude"] = "{} m".format(round(altitude, 1))

            stamp = gps.get("GPSTimeStamp")
            date = gps.get("GPSDateStamp")

            if stamp and date:
                try:
                    clean["GPS Time (UTC)"] = "{} {:02d}:{:02d}:{:02d}".format(
                        clean_text(date).replace(":", "-"),
                        int(stamp[0]), int(stamp[1]), int(stamp[2])
                    )
                except Exception:
                    pass

    if "GPS Status" not in clean:
        clean["GPS Status"] = "Not Available"

    # Software classification
    if "Software" in clean:

        software_type = classify_software(clean["Software"])

        if software_type:
            clean["Software Type"] = software_type

    meaningful = [
        "Camera Make", "Camera Model", "Software",
        "Original Capture Time", "Digitized Time",
        "File Metadata Time", "Latitude"
    ]

    clean["Metadata Status"] = (
        "Available"
        if any(field in clean for field in meaningful)
        else "Limited / Not Available"
    )

    return clean


# ==========================================
# FILE INFORMATION (of the stored copy)
# ==========================================

def get_file_information(file_path, original_name=None):

    info = {}

    try:

        info["File Name"] = original_name or os.path.basename(file_path)

        info["File Size"] = "{:.2f} KB".format(
            os.path.getsize(file_path) / 1024
        )

        mime, _ = mimetypes.guess_type(file_path)

        info["MIME Type"] = mime or "Unknown"

        info["File Extension"] = os.path.splitext(
            original_name or file_path
        )[1].lower()

        # These belong to the copy held by ForensiCore, NOT the
        # original device (the template explains this).
        info["Created Date"] = datetime.fromtimestamp(
            os.path.getctime(file_path)
        ).strftime("%d-%m-%Y %H:%M:%S")

        info["Modified Date"] = datetime.fromtimestamp(
            os.path.getmtime(file_path)
        ).strftime("%d-%m-%Y %H:%M:%S")

    except Exception as error:

        info["Error"] = str(error)

    return info


# ==========================================
# OBSERVATIONS
# ==========================================

def generate_observations(metadata):

    observations = []

    if metadata.get("Metadata Status") == "Available":
        observations.append(
            "Useful embedded metadata is available for examination."
        )
    else:
        observations.append(
            "Little or no embedded metadata was found. This is "
            "normal for screenshots and for images that passed "
            "through messaging apps or social media, which strip "
            "EXIF data. The origin and capture time of this file "
            "cannot be established from its metadata."
        )

    if "Camera Make" in metadata or "Camera Model" in metadata:
        observations.append("Camera/device information is available.")
    else:
        observations.append("Camera/device information is not available.")

    if "Original Capture Time" in metadata:
        observations.append("Original capture timestamp is available.")
    elif "File Metadata Time" in metadata:
        observations.append(
            "Only a general metadata timestamp is available; no "
            "explicit original capture time was identified."
        )
    else:
        observations.append("No capture timestamp was identified.")

    software_type = metadata.get("Software Type")

    if software_type == "Editing Software":
        observations.append(
            "Known image-editing software was recorded in the file. "
            "This is an indicator for further examination, not proof "
            "of manipulation."
        )
    elif software_type == "Camera / Device Software":
        observations.append(
            "Camera/device software was recorded. This alone does "
            "not indicate manipulation."
        )
    elif software_type:
        observations.append("Processing software information was recorded.")

    if metadata.get("GPS Status") == "Available":
        observations.append(
            "GPS coordinates are embedded in the image."
        )

    return observations


# ==========================================
# RISK (manipulation indicators)
# ==========================================

def _row(category, points, max_points, status, reason):

    return {
        "category": category,
        "points": points,
        "max_points": max_points,
        "status": status,
        "reason": reason
    }


def calculate_metadata_risk(metadata):

    """
    Returns dict: score, level, reasons, breakdown, findings

    Score = sum of MANIPULATION indicators only:
        editing software ............ 40
        timestamp inconsistency ..... up to 30
        dimension mismatch .......... 20
        unrecognised software ....... 5
    Missing metadata never adds points.
    """

    score = 0
    reasons = []
    breakdown = []
    findings = []

    # ---------- 1. editing software ----------

    software = metadata.get("Software")
    software_type = metadata.get("Software Type")

    if software_type == "Editing Software":

        points = 40
        score += points

        reason = (
            "Image-editing software is recorded in the metadata: "
            "{}.".format(software)
        )

        breakdown.append(_row(
            "Editing Software", points, 40, "Detected", reason
        ))

        reasons.append(reason)

        findings.append(make_finding(
            "Image-editing software recorded in metadata",
            reason + " The image may have been opened and re-saved "
            "after capture.",
            points, "Editing software"
        ))

    else:

        breakdown.append(_row(
            "Editing Software", 0, 40, "No Indicator",
            "No known image-editing software was recorded."
        ))

    # ---------- 2. timestamp consistency ----------

    original = parse_exif_datetime(metadata.get("Original Capture Time"))
    modified = parse_exif_datetime(metadata.get("File Metadata Time"))
    digitized = parse_exif_datetime(metadata.get("Digitized Time"))

    ts_points = 0
    ts_reason = None

    if original and modified:

        delta = modified - original

        if delta > timedelta(hours=24):

            ts_points = 25

            ts_reason = (
                "The metadata was last modified {} after the photo was "
                "captured (captured {}, modified {}). The file was "
                "probably re-saved by other software."
            ).format(
                _human_delta(delta),
                metadata["Original Capture Time"],
                metadata["File Metadata Time"]
            )

        elif delta > timedelta(minutes=2):

            ts_points = 10

            ts_reason = (
                "The metadata modification time is {} later than the "
                "capture time."
            ).format(_human_delta(delta))

        elif delta < -timedelta(minutes=1):

            ts_points = 25

            ts_reason = (
                "The metadata modification time is EARLIER than the "
                "capture time, which should not happen in an "
                "unmodified camera file."
            )

    if original and digitized:

        if abs(digitized - original) > timedelta(hours=24):

            ts_points = min(ts_points + 10, 30)

            extra = (
                "Digitised time differs from capture time by "
                "more than a day."
            )

            ts_reason = (ts_reason + " " + extra) if ts_reason else extra

    reference = original or modified

    if reference and reference > utcnow() + timedelta(days=1):

        ts_points = min(ts_points + 30, 30)

        extra = "A timestamp lies in the future, which is impossible."

        ts_reason = (ts_reason + " " + extra) if ts_reason else extra

    if ts_points:

        score += ts_points
        reasons.append(ts_reason)

        breakdown.append(_row(
            "Timestamp Consistency", ts_points, 30,
            "Inconsistent", ts_reason
        ))

        findings.append(make_finding(
            "Timestamps are inconsistent", ts_reason,
            ts_points, "Timestamps"
        ))

    else:

        breakdown.append(_row(
            "Timestamp Consistency", 0, 30,
            "Consistent" if (original or modified) else "Not Available",
            "Embedded timestamps are consistent with each other."
            if (original or modified)
            else "No timestamps were available to compare."
        ))

    # ---------- 3. dimension consistency ----------

    exif_w = metadata.get("EXIF Width")
    exif_h = metadata.get("EXIF Height")
    real_w = metadata.get("Image Width")
    real_h = metadata.get("Image Height")

    dimension_bad = False

    if exif_w and exif_h and real_w and real_h:

        same = (exif_w, exif_h) == (real_w, real_h)
        swapped = (exif_w, exif_h) == (real_h, real_w)

        dimension_bad = not (same or swapped)

    if dimension_bad:

        points = 20
        score += points

        reason = (
            "The camera recorded {}x{} pixels but the image is now "
            "{}x{}. It was probably resized or cropped after capture."
        ).format(exif_w, exif_h, real_w, real_h)

        reasons.append(reason)

        breakdown.append(_row(
            "Dimension Consistency", points, 20, "Mismatch", reason
        ))

        findings.append(make_finding(
            "Image size differs from the size recorded by the camera",
            reason, points, "Dimensions"
        ))

    else:

        breakdown.append(_row(
            "Dimension Consistency", 0, 20,
            "Consistent" if exif_w else "Not Available",
            "Image dimensions match the camera record."
            if exif_w else
            "The camera dimensions were not recorded, so no "
            "comparison was possible."
        ))

    # ---------- 4. unrecognised processing software ----------

    if software_type == "Processing Software":

        points = 5
        score += points

        reason = (
            "Software '{}' is not a recognised camera or editor; "
            "check what produced this file."
        ).format(software)

        reasons.append(reason)

        breakdown.append(_row(
            "Processing Software", points, 5, "Unrecognised", reason
        ))

        findings.append(make_finding(
            "Unrecognised processing software", reason,
            points, "Software"
        ))

    # ---------- informational rows (never add points) ----------

    if metadata.get("Metadata Status") != "Available":

        info = (
            "No usable EXIF metadata. Common for screenshots and "
            "images shared through messaging apps or social media. "
            "Not suspicious by itself; origin and capture time cannot "
            "be established from this file."
        )

        breakdown.append(_row(
            "Metadata Availability", 0, 0, "Limited", info
        ))

        findings.append(make_finding(
            "No embedded metadata (information only)", info,
            0, "Metadata availability", severity="INFO"
        ))

    else:

        breakdown.append(_row(
            "Metadata Availability", 0, 0, "Available",
            "Useful embedded metadata is available."
        ))

    if "Camera Make" in metadata or "Camera Model" in metadata:

        device = _device_name(metadata)

        breakdown.append(_row(
            "Device Information", 0, 0, "Available",
            "Captured with: {}.".format(device)
        ))

        findings.append(make_finding(
            "Source device identified: {}".format(device),
            "The camera make/model recorded in the file.",
            0, "Device", severity="INFO"
        ))

    else:

        breakdown.append(_row(
            "Device Information", 0, 0, "Not Available",
            "No camera information (informational)."
        ))

    if metadata.get("GPS Status") == "Available":

        location = "{}, {}".format(
            metadata["Latitude"], metadata["Longitude"]
        )

        breakdown.append(_row(
            "GPS Analysis", 0, 0, "Available",
            "GPS coordinates: {}.".format(location)
        ))

        findings.append(make_finding(
            "Photo contains GPS location ({})".format(location),
            "The image records where it was taken. Verify against "
            "other evidence.",
            0, "Location", severity="LOW"
        ))

    else:

        breakdown.append(_row(
            "GPS Analysis", 0, 0, "Not Available",
            "No GPS information (not suspicious by itself)."
        ))

    score = min(score, 100)

    if not reasons:
        reasons.append(
            "No manipulation indicators were identified in the metadata."
        )

    return {
        "score": score,
        "level": level_from_score(score),
        "reasons": reasons,
        "breakdown": breakdown,
        "findings": findings
    }


def _device_name(metadata):

    make = metadata.get("Camera Make", "") or ""
    model = metadata.get("Camera Model", "") or ""

    if make and model.lower().startswith(make.lower()):
        return model.strip()

    return "{} {}".format(make, model).strip()


def _human_delta(delta):

    seconds = int(abs(delta.total_seconds()))

    if seconds >= 86400:
        return "{} day(s)".format(seconds // 86400)

    if seconds >= 3600:
        return "{} hour(s)".format(seconds // 3600)

    return "{} minute(s)".format(max(seconds // 60, 1))


# ==========================================
# TIMELINE EVENTS
# ==========================================

def build_events(metadata, filename):

    events = []

    offset = parse_offset_minutes(metadata.get("Timezone Offset"))

    original = parse_exif_datetime(metadata.get("Original Capture Time"))

    if original:

        utc_time, note = local_to_utc(original, offset)

        location = ""

        if metadata.get("GPS Status") == "Available":
            location = " GPS: {}, {}.".format(
                metadata["Latitude"], metadata["Longitude"]
            )

        device = _device_name(metadata)

        events.append({
            "type": "photo_captured",
            "time": utc_time,
            "title": "Photo captured: {}".format(filename),
            "detail": (
                "Device: {}.{}".format(device or "unknown", location)
            ),
            "time_note": note
        })

    modified = parse_exif_datetime(metadata.get("File Metadata Time"))

    if modified and (
        not original
        or abs(modified - original) > timedelta(minutes=2)
    ):

        utc_time, note = local_to_utc(modified, offset)

        events.append({
            "type": "photo_modified",
            "time": utc_time,
            "title": "Image metadata last modified: {}".format(filename),
            "detail": "Software: {}".format(
                metadata.get("Software", "not recorded")
            ),
            "time_note": note,
            "severity": (
                "MEDIUM"
                if metadata.get("Software Type") == "Editing Software"
                else None
            )
        })

    gps_time = metadata.get("GPS Time (UTC)")

    if gps_time:

        try:
            events.append({
                "type": "gps_fix",
                "time": datetime.strptime(gps_time, "%Y-%m-%d %H:%M:%S"),
                "title": "GPS fix recorded: {}".format(filename),
                "detail": "{}, {}".format(
                    metadata.get("Latitude"), metadata.get("Longitude")
                ),
                "time_note": "UTC (from GPS)"
            })
        except ValueError:
            pass

    return events
