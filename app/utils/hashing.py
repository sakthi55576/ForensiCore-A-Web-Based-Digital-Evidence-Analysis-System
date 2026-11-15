"""
Evidence hashing.

ForensiCore records exactly two algorithms for every evidence file:

    MD5      (legacy identifier, still expected in forensic reports)
    SHA-256  (primary integrity value)

Both are computed in a single pass over the file.
"""

import hashlib

CHUNK_SIZE = 1024 * 1024  # 1 MB


def _md5():

    try:
        return hashlib.md5(usedforsecurity=False)
    except TypeError:
        return hashlib.md5()


def compute_hashes(file_path):

    md5 = _md5()
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:

        while True:

            chunk = file.read(CHUNK_SIZE)

            if not chunk:
                break

            md5.update(chunk)
            sha256.update(chunk)

    return {
        "md5": md5.hexdigest(),
        "sha256": sha256.hexdigest()
    }
