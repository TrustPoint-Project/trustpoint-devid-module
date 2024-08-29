from pathlib import Path
from hashlib import sha256


WORKING_DIR = Path().home() / '.local' /'trustpoint' / 'devid-module'


def get_sha256_fingerprint_as_upper_hex_str(data: bytes) -> str:
    hash_builder = sha256()
    hash_builder.update(data)
    return hash_builder.hexdigest().upper()
