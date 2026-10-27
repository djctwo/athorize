from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

ph = PasswordHasher()

# Verified against when a login names no existing user, so both paths cost one
# argon2 verification (no username-existence timing oracle).
DUMMY_HASH = ph.hash("athorize-timing-equalizer")


def hash_password(password: str) -> str:
    return ph.hash(password)


def verify_password(password: str, hash: str) -> bool:
    try:
        return ph.verify(hash, password)
    except VerifyMismatchError:
        return False
