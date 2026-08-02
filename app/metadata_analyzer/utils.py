from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
import exifread
import hashlib
import folium
import os
import mimetypes
from datetime import datetime

def generate_hashes(file_path):

    hashes = {}

    algorithms = [
        "md5",
        "sha1",
        "sha256",
    ]

    for algorithm in algorithms:

        hash_obj = hashlib.new(algorithm)

        with open(file_path, "rb") as f:

            while chunk := f.read(4096):
                hash_obj.update(chunk)

        hashes[algorithm.upper()] = hash_obj.hexdigest()

    return hashes
def convert_to_degrees(value):

    d = value[0]
    m = value[1]
    s = value[2]

    return float(d) + (float(m) / 60.0) + (float(s) / 3600.0)


def get_gps_coordinates(gps_info):

    latitude = None
    longitude = None

    if "GPSLatitude" in gps_info and "GPSLongitude" in gps_info:

        latitude = convert_to_degrees(gps_info["GPSLatitude"])
        longitude = convert_to_degrees(gps_info["GPSLongitude"])

        if gps_info.get("GPSLatitudeRef") == "S":
            latitude = -latitude

        if gps_info.get("GPSLongitudeRef") == "W":
            longitude = -longitude

    return latitude, longitudes

def extract_image_metadata(file_path):

    metadata = {}

    try:

        image = Image.open(file_path)

        exif = image.getexif()

        if exif:

            for tag_id, value in exif.items():

                tag = TAGS.get(tag_id, tag_id)

                if tag == "GPSInfo":

                    gps_data = {}

                    for key in value:

                        gps_tag = GPSTAGS.get(key, key)

                        gps_data[gps_tag] = value[key]

                    latitude, longitude = get_gps_coordinates(gps_data)

                    if latitude and longitude:

                        metadata["Latitude"] = latitude
                        metadata["Longitude"] = longitude

                        create_gps_map(latitude, longitude)

                    else:

                        metadata["GPS"] = "Not Available"

                else:

                    metadata[tag] = value

        else:

            metadata["Metadata"] = "No EXIF Metadata Found"

    except Exception as e:

        metadata["Error"] = str(e)

    clean_metadata = {}

    important_fields = [
        "Make",
        "Model",
        "Software",
        "DateTime",
        "DateTimeOriginal",
        "ImageWidth",
        "ImageLength",
        "XResolution",
        "YResolution"
    ]

    for field in important_fields:

        if field in metadata:

            clean_metadata[field] = metadata[field]

    if "Latitude" in metadata:
        clean_metadata["Latitude"] = metadata["Latitude"]

    if "Longitude" in metadata:
        clean_metadata["Longitude"] = metadata["Longitude"]

    if "GPS" in metadata:
        clean_metadata["GPS"] = metadata["GPS"]

    if not clean_metadata:

        clean_metadata["Message"] = "No Important Metadata Found"

    return clean_metadata
def generate_observations(metadata):

    observations = []

    if metadata:

        observations.append(
            "Metadata information extracted successfully."
        )

    else:

        observations.append(
            "No metadata information found."
        )


    if "Make" in metadata or "Model" in metadata:

        observations.append(
            "Camera information is available."
        )


    if "Software" in metadata:

        observations.append(
            f"Editing software detected: {metadata['Software']}"
        )


    if "Latitude" in metadata and "Longitude" in metadata:

        observations.append(
            "GPS location information is available."
        )

    else:

        observations.append(
            "GPS location information is not available."
        )


    return observations
 
def get_file_information(file_path):

    file_info = {}

    try:

        file_info["File Name"] = os.path.basename(file_path)

        file_size = os.path.getsize(file_path)

        file_info["File Size"] = f"{file_size / 1024:.2f} KB"

        file_type, _ = mimetypes.guess_type(file_path)

        file_info["File Type"] = file_type if file_type else "Unknown"

        file_info["File Extension"] = os.path.splitext(file_path)[1]

        created_time = os.path.getctime(file_path)

        modified_time = os.path.getmtime(file_path)

        file_info["Created Date"] = datetime.fromtimestamp(
            created_time
        ).strftime("%d-%m-%Y %H:%M:%S")


        file_info["Modified Date"] = datetime.fromtimestamp(
            modified_time
        ).strftime("%d-%m-%Y %H:%M:%S")


    except Exception as e:

        file_info["Error"] = str(e)


    return file_info    

def generate_observations(metadata):

    observations = []


    if metadata:

        observations.append(
            "Metadata information extracted successfully."
        )

    else:

        observations.append(
            "No metadata information found."
        )


    if "Make" in metadata or "Model" in metadata:

        observations.append(
            "Camera information is available."
        )


    if "Software" in metadata:

        observations.append(
            f"Editing software detected: {metadata['Software']}"
        )


    if "Latitude" in metadata and "Longitude" in metadata:

        observations.append(
            "GPS location information is available."
        )

    else:

        observations.append(
            "GPS location information is not available."
        )


    return observations

def calculate_metadata_risk(metadata):

    risk = "Low"


    if "Software" in metadata:

        risk = "Medium"


    if "GPS" in metadata and metadata["GPS"] == "Not Available":

        if risk == "Medium":
            risk = "Medium"


    if "Message" in metadata:

        risk = "High"


    return risk
def create_gps_map(latitude, longitude):

    map_object = folium.Map(
        location=[latitude, longitude],
        zoom_start=16
    )

    folium.Marker(
        [latitude, longitude],
        popup="Evidence Location"
    ).add_to(map_object)

    map_path = "app/static/maps/evidence_location.html"

    map_object.save(map_path)

    return map_path