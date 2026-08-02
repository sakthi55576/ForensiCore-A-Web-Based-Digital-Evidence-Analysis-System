import os
import json

from flask import render_template, request

from app import db
from app.models.metadata_analysis import MetadataAnalysis

from . import metadata

from .utils import (
    generate_hashes,
    extract_image_metadata,
    get_file_information,
    generate_observations,
    calculate_metadata_risk
)


UPLOAD_FOLDER = "app/uploads"


@metadata.route("/")
def upload():

    return render_template("metadata/upload.html")



@metadata.route("/analyze", methods=["POST"])
def analyze():

    file = request.files["evidence"]


    file_path = os.path.join(
        UPLOAD_FOLDER,
        file.filename
    )


    file.save(file_path)



    # Hash Generation

    hashes = generate_hashes(file_path)



    # Metadata Extraction

    metadata = extract_image_metadata(file_path)



    # File Information

    file_info = get_file_information(file_path)



    # Investigation Observation

    observations = generate_observations(metadata)



    # Risk Level

    risk_level = calculate_metadata_risk(metadata)




    # Save Metadata Analysis

    analysis = MetadataAnalysis(

        evidence_id=1,

        md5_hash=hashes.get("MD5"),

        sha1_hash=hashes.get("SHA1"),

        sha256_hash=hashes.get("SHA256"),

        metadata_data=json.dumps(
            metadata,
            default=str
        ),

        risk_level=risk_level,

        observations=json.dumps(
            observations
        )

    )


    db.session.add(analysis)

    db.session.commit()




    return render_template(

        "metadata/result.html",

        filename=file.filename,

        hashes=hashes,

        metadata=metadata,

        file_info=file_info,

        observations=observations,

        risk_level=risk_level

    )