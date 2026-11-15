from app.utils.hashing import compute_hashes


def test_known_hashes(tmp_path):

    # Standard test vector: the text "abc"
    path = tmp_path / "abc.bin"
    path.write_bytes(b"abc")

    hashes = compute_hashes(str(path))

    assert hashes["md5"] == "900150983cd24fb0d6963f7d28e17f72"
    assert hashes["sha256"] == (
        "ba7816bf8f01cfea414140de5dae2223"
        "b00361a396177a9cb410ff61f20015ad"
    )


def test_one_changed_byte_changes_both_hashes(tmp_path):

    path = tmp_path / "evidence.bin"

    path.write_bytes(b"original evidence content")
    before = compute_hashes(str(path))

    path.write_bytes(b"original evidence contenT")
    after = compute_hashes(str(path))

    assert before["md5"] != after["md5"]
    assert before["sha256"] != after["sha256"]
