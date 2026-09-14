import hashlib
import mimetypes
import os
from datetime import datetime

from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS


# ==========================================
# SUPPORTED IMAGE TYPES
# ==========================================

SUPPORTED_EXTENSIONS = {
    ".jpg",
    ".jpeg",
    ".png",
    ".tif",
    ".tiff"
}


# ==========================================
# HASH GENERATION
# ==========================================

def generate_hashes(file_path):

    hashes = {}

    for algorithm in ["md5", "sha1", "sha256"]:

        hash_object = hashlib.new(algorithm)

        with open(file_path, "rb") as file:

            while True:

                chunk = file.read(4096)

                if not chunk:
                    break

                hash_object.update(chunk)

        hashes[algorithm.upper()] = (
            hash_object.hexdigest()
        )

    return hashes


# ==========================================
# FILE VALIDATION
# ==========================================

def validate_image_file(file_path):

    extension = (
        os.path.splitext(file_path)[1]
        .lower()
    )

    if extension not in SUPPORTED_EXTENSIONS:

        return False, (
            "Unsupported image format. "
            "Supported formats: JPG, JPEG, PNG, TIFF."
        )

    try:

        with Image.open(file_path) as image:

            image.verify()

        return True, "Valid image file."

    except Exception:

        return False, (
            "The uploaded file is corrupted "
            "or cannot be processed as a valid image."
        )


# ==========================================
# GPS CONVERSION
# ==========================================

def convert_to_degrees(value):

    try:

        degrees = float(value[0])
        minutes = float(value[1])
        seconds = float(value[2])

        return (
            degrees
            + (minutes / 60.0)
            + (seconds / 3600.0)
        )

    except Exception:

        return None


# ==========================================
# GPS COORDINATES
# ==========================================

def get_gps_coordinates(gps_info):

    latitude = None
    longitude = None

    try:

        if (
            "GPSLatitude" in gps_info
            and "GPSLongitude" in gps_info
        ):

            latitude = convert_to_degrees(
                gps_info["GPSLatitude"]
            )

            longitude = convert_to_degrees(
                gps_info["GPSLongitude"]
            )

            if (
                gps_info.get("GPSLatitudeRef")
                == "S"
            ):

                latitude = -latitude

            if (
                gps_info.get("GPSLongitudeRef")
                == "W"
            ):

                longitude = -longitude

    except Exception:

        latitude = None
        longitude = None

    return latitude, longitude


# ==========================================
# SOFTWARE CLASSIFICATION
# ==========================================

def classify_software(software):

    if not software:

        return None

    software_text = str(
        software
    ).lower()

    editing_keywords = [
        "photoshop",
        "gimp",
        "lightroom",
        "snapseed",
        "picsart",
        "canva",
        "paint.net",
        "affinity",
        "adobe"
    ]

    for keyword in editing_keywords:

        if keyword in software_text:

            return "Editing Software"

    camera_keywords = [
        "camera",
        "mediatek",
        "qualcomm",
        "oppo",
        "samsung",
        "xiaomi",
        "vivo",
        "huawei",
        "apple"
    ]

    for keyword in camera_keywords:

        if keyword in software_text:

            return "Camera / Device Software"

    return "Processing Software"


# ==========================================
# IMAGE METADATA EXTRACTION
# ==========================================

def extract_image_metadata(file_path):

    metadata = {}

    try:

        image = Image.open(file_path)

        # ----------------------------------
        # Basic Image Information
        # ----------------------------------

        metadata["Format"] = image.format
        metadata["Image Width"] = image.width
        metadata["Image Height"] = image.height
        metadata["Color Mode"] = image.mode

        # ----------------------------------
        # EXIF
        # ----------------------------------

        exif = image.getexif()

        if exif:

            for tag_id, value in exif.items():

                tag_name = TAGS.get(
                    tag_id,
                    tag_id
                )

                # --------------------------
                # GPS
                # --------------------------

                if tag_name == "GPSInfo":

                    gps_data = {}

                    for key in value:

                        gps_tag = GPSTAGS.get(
                            key,
                            key
                        )

                        gps_data[
                            gps_tag
                        ] = value[key]

                    latitude, longitude = (
                        get_gps_coordinates(
                            gps_data
                        )
                    )

                    if (
                        latitude is not None
                        and longitude is not None
                    ):

                        metadata[
                            "GPS Status"
                        ] = "Available"

                        metadata[
                            "Latitude"
                        ] = latitude

                        metadata[
                            "Longitude"
                        ] = longitude

                    else:

                        metadata[
                            "GPS Status"
                        ] = "Not Available"

                else:

                    metadata[tag_name] = value

        else:

            metadata[
                "EXIF Status"
            ] = "No EXIF metadata found"

    except Exception as error:

        metadata[
            "Analysis Error"
        ] = str(error)

    # ======================================
    # CLEAN FORENSIC METADATA
    # ======================================

    clean_metadata = {}

    field_mapping = {

        "Make":
            "Camera Make",

        "Model":
            "Camera Model",

        "Software":
            "Software",

        "DateTimeOriginal":
            "Original Capture Time",

        "DateTimeDigitized":
            "Digitized Time",

        "DateTime":
            "File Metadata Time",

        "ExposureTime":
            "Exposure Time",

        "FNumber":
            "F-Number",

        "ISOSpeedRatings":
            "ISO",

        "FocalLength":
            "Focal Length",

        "Flash":
            "Flash",

        "XResolution":
            "X Resolution",

        "YResolution":
            "Y Resolution"

    }

    for original_field, display_field in (
        field_mapping.items()
    ):

        if original_field in metadata:

            clean_metadata[
                display_field
            ] = metadata[
                original_field
            ]

    # ======================================
    # IMAGE INFORMATION
    # ======================================

    for field in [
        "Format",
        "Image Width",
        "Image Height",
        "Color Mode"
    ]:

        if field in metadata:

            clean_metadata[field] = (
                metadata[field]
            )

    # ======================================
    # SOFTWARE CLASSIFICATION
    # ======================================

    if "Software" in metadata:

        software_type = classify_software(
            metadata["Software"]
        )

        if software_type:

            clean_metadata[
                "Software Type"
            ] = software_type

    # ======================================
    # GPS
    # ======================================

    if "GPS Status" in metadata:

        clean_metadata[
            "GPS Status"
        ] = metadata[
            "GPS Status"
        ]

    if "Latitude" in metadata:

        clean_metadata[
            "Latitude"
        ] = metadata[
            "Latitude"
        ]

    if "Longitude" in metadata:

        clean_metadata[
            "Longitude"
        ] = metadata[
            "Longitude"
        ]

    # ======================================
    # METADATA STATUS
    # ======================================

    meaningful_fields = [
        "Camera Make",
        "Camera Model",
        "Software",
        "Original Capture Time",
        "Digitized Time",
        "File Metadata Time",
        "Latitude",
        "Longitude"
    ]

    metadata_available = any(
        field in clean_metadata
        for field in meaningful_fields
    )

    if metadata_available:

        clean_metadata[
            "Metadata Status"
        ] = "Available"

    else:

        clean_metadata[
            "Metadata Status"
        ] = "Limited / Not Available"

    return clean_metadata


# ==========================================
# FILE INFORMATION
# ==========================================

def get_file_information(file_path):

    file_info = {}

    try:

        file_info[
            "File Name"
        ] = os.path.basename(
            file_path
        )

        file_size = os.path.getsize(
            file_path
        )

        file_info[
            "File Size"
        ] = (
            f"{file_size / 1024:.2f} KB"
        )

        file_type, _ = (
            mimetypes.guess_type(
                file_path
            )
        )

        file_info[
            "MIME Type"
        ] = (
            file_type
            if file_type
            else "Unknown"
        )

        file_info[
            "File Extension"
        ] = os.path.splitext(
            file_path
        )[1].lower()

        created_time = os.path.getctime(
            file_path
        )

        modified_time = os.path.getmtime(
            file_path
        )

        file_info[
            "Created Date"
        ] = datetime.fromtimestamp(
            created_time
        ).strftime(
            "%d-%m-%Y %H:%M:%S"
        )

        file_info[
            "Modified Date"
        ] = datetime.fromtimestamp(
            modified_time
        ).strftime(
            "%d-%m-%Y %H:%M:%S"
        )

    except Exception as error:

        file_info[
            "Error"
        ] = str(error)

    return file_info


# ==========================================
# FORENSIC OBSERVATIONS
# ==========================================

def generate_observations(metadata):

    observations = []

    # --------------------------------------
    # Metadata
    # --------------------------------------

    if (
        metadata.get(
            "Metadata Status"
        )
        == "Available"
    ):

        observations.append(
            "Useful metadata information "
            "is available for examination."
        )

    else:

        observations.append(
            "Limited metadata information "
            "is available."
        )

    # --------------------------------------
    # Camera
    # --------------------------------------

    if (
        "Camera Make" in metadata
        or "Camera Model" in metadata
    ):

        observations.append(
            "Camera/device information "
            "is available."
        )

    else:

        observations.append(
            "Camera/device information "
            "is not available."
        )

    # --------------------------------------
    # Timestamp
    # --------------------------------------

    if "Original Capture Time" in metadata:

        observations.append(
            "Original capture timestamp "
            "is available."
        )

    elif "File Metadata Time" in metadata:

        observations.append(
            "General metadata timestamp "
            "is available, but an explicit "
            "original capture timestamp "
            "was not identified."
        )

    else:

        observations.append(
            "No useful capture timestamp "
            "was identified."
        )

    # --------------------------------------
    # Software
    # --------------------------------------

    if "Software" in metadata:

        software_type = metadata.get(
            "Software Type"
        )

        if software_type == "Editing Software":

            observations.append(
                "Known image editing software "
                "information was detected. "
                "This is an indicator for "
                "further examination, not proof "
                "of manipulation."
            )

        elif (
            software_type
            == "Camera / Device Software"
        ):

            observations.append(
                "Camera/device software "
                "information was detected. "
                "This alone does not indicate "
                "image manipulation."
            )

        else:

            observations.append(
                "Software/processing information "
                "was detected."
            )

    else:

        observations.append(
            "No software information "
            "was identified."
        )

    # --------------------------------------
    # GPS
    # --------------------------------------

    if (
        metadata.get("GPS Status")
        == "Available"
    ):

        observations.append(
            "GPS location information is "
            "available for investigation."
        )

    else:

        observations.append(
            "GPS location information "
            "was not identified."
        )

    # --------------------------------------
    # Image dimensions
    # --------------------------------------

    if (
        "Image Width" in metadata
        and "Image Height" in metadata
    ):

        observations.append(
            "Image dimensions were "
            "successfully identified."
        )

    return observations


# ==========================================
# METADATA RISK ANALYSIS
# ==========================================

def calculate_metadata_risk(metadata):
    """
    Calculate a metadata-based forensic risk score.

    Score range:
        0 - 29  : LOW
        30 - 69 : MEDIUM
        70 - 100: HIGH

    The score represents metadata-based risk indicators only.
    It does not prove that an image has been manipulated.
    """

    score = 0
    reasons = []
    breakdown = []

    # ==========================================
    # 1. METADATA AVAILABILITY
    # ==========================================

    metadata_status = str(
        metadata.get("Metadata Status", "")
    ).lower()

    if (
        "limited" in metadata_status
        or "not available" in metadata_status
        or "unavailable" in metadata_status
    ):

        points = 30
        score += points

        breakdown.append({
            "category": "Metadata Availability",
            "points": points,
            "max_points": 30,
            "status": "Limited",
            "reason": "Very little embedded metadata was available."
        })

        reasons.append(
            "Useful metadata information is limited or unavailable."
        )

    else:

        breakdown.append({
            "category": "Metadata Availability",
            "points": 0,
            "max_points": 30,
            "status": "Available",
            "reason": "Useful embedded metadata information is available."
        })


    # ==========================================
    # 2. TIMESTAMP ANALYSIS
    # ==========================================

    capture_time = metadata.get(
        "Original Capture Time"
    )

    digitized_time = metadata.get(
        "Digitized Time"
    )

    if (
        not capture_time
        and not digitized_time
    ):

        points = 20
        score += points

        breakdown.append({
            "category": "Timestamp Analysis",
            "points": points,
            "max_points": 20,
            "status": "Missing",
            "reason": "No useful original capture timestamp was identified."
        })

        reasons.append(
            "No useful timestamp was identified."
        )

    else:

        breakdown.append({
            "category": "Timestamp Analysis",
            "points": 0,
            "max_points": 20,
            "status": "Available",
            "reason": "A useful embedded timestamp was identified."
        })


    # ==========================================
    # 3. DEVICE / CAMERA INFORMATION
    # ==========================================

    camera_make = metadata.get(
        "Camera Make"
    )

    camera_model = metadata.get(
        "Camera Model"
    )

    if (
        not camera_make
        and not camera_model
    ):

        points = 15
        score += points

        breakdown.append({
            "category": "Device Information",
            "points": points,
            "max_points": 15,
            "status": "Unavailable",
            "reason": "Camera or device information could not be identified."
        })

        reasons.append(
            "Camera/device information is unavailable."
        )

    else:

        breakdown.append({
            "category": "Device Information",
            "points": 0,
            "max_points": 15,
            "status": "Available",
            "reason": "Camera/device information was identified."
        })


    # ==========================================
    # 4. SOFTWARE ANALYSIS
    # ==========================================

    software_type = str(
        metadata.get(
            "Software Type",
            ""
        )
    ).lower()

    software = str(
        metadata.get(
            "Software",
            ""
        )
    ).lower()

    if (
        "editing" in software_type
        or "editor" in software_type
    ):

        points = 25
        score += points

        breakdown.append({
            "category": "Software Analysis",
            "points": points,
            "max_points": 25,
            "status": "Editing Software",
            "reason": f"Metadata indicates possible image editing software: {software or 'Unknown'}."
        })

        reasons.append(
            "Image editing software was identified in the metadata."
        )

    else:

        breakdown.append({
            "category": "Software Analysis",
            "points": 0,
            "max_points": 25,
            "status": "No Editing Indicator",
            "reason": "No known editing software indicator was identified."
        })


    # ==========================================
    # 5. GPS ANALYSIS
    # ==========================================

    gps_status = str(
        metadata.get(
            "GPS Status",
            ""
        )
    ).lower()

    # GPS absence is INFORMATIONAL.
    # It must NOT increase the risk score.

    if "available" in gps_status:

        breakdown.append({
            "category": "GPS Analysis",
            "points": 0,
            "max_points": 0,
            "status": "Available",
            "reason": "GPS coordinates are available in the metadata."
        })

    else:

        breakdown.append({
            "category": "GPS Analysis",
            "points": 0,
            "max_points": 0,
            "status": "Not Available",
            "reason": "GPS information was not identified. This is not considered suspicious by itself."
        })


    # ==========================================
    # FINAL SCORE
    # ==========================================

    score = min(
        score,
        100
    )


    # ==========================================
    # RISK LEVEL
    # ==========================================

    if score >= 70:

        level = "HIGH"

    elif score >= 30:

        level = "MEDIUM"

    else:

        level = "LOW"


    # ==========================================
    # DEFAULT MESSAGE
    # ==========================================

    if not reasons:

        reasons.append(
            "No significant metadata-based risk indicators were identified."
        )


    # ==========================================
    # RETURN RESULT
    # ==========================================

    return {

        "score": score,

        "level": level,

        "reasons": reasons,

        "breakdown": breakdown

    }
def create_gps_map(latitude, longitude):

    import folium

    map_folder = "app/static/maps"

    os.makedirs(
        map_folder,
        exist_ok=True
    )

    map_object = folium.Map(
        location=[
            latitude,
            longitude
        ],
        zoom_start=16
    )

    folium.Marker(
        [
            latitude,
            longitude
        ],
        popup="Evidence Location"
    ).add_to(map_object)

    map_path = os.path.join(
        map_folder,
        "evidence_location.html"
    )

    map_object.save(
        map_path
    )

    return map_path