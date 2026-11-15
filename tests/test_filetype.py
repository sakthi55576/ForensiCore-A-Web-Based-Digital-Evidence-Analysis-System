from app.utils.filetype import detect_file_type


def test_jpeg_detected_by_content(tmp_path):

    path = tmp_path / "photo.jpg"
    path.write_bytes(b"\xff\xd8\xff\xe0" + b"\x00" * 64)

    result = detect_file_type(str(path), "photo.jpg")

    assert result["kind"] == "image"
    assert result["extension_mismatch"] is False


def test_renamed_executable_is_flagged(tmp_path):

    # A Windows program renamed to .jpg
    path = tmp_path / "holiday.jpg"
    path.write_bytes(b"MZ" + b"\x90" * 64)

    result = detect_file_type(str(path), "holiday.jpg")

    assert result["kind"] == "executable"
    assert result["extension_mismatch"] is True


def test_email_detected_from_headers(tmp_path):

    path = tmp_path / "mail.eml"
    path.write_bytes(
        b"From: a@example.com\r\n"
        b"To: b@example.com\r\n"
        b"Subject: hello\r\n\r\nbody\r\n"
    )

    result = detect_file_type(str(path), "mail.eml")

    assert result["kind"] == "email"
    assert result["extension_mismatch"] is False
