from typing import List, Tuple

import pyotp

from app.core.config import get_settings
from app.core.security import TokenHelper

RECOVERY_CODE_COUNT = 8


class MFAService:
    """TOTP secret/code handling and recovery-code generation."""

    @staticmethod
    def generate_secret() -> str:
        return pyotp.random_base32()

    @staticmethod
    def get_provisioning_uri(email: str, secret: str) -> str:
        return pyotp.TOTP(secret).provisioning_uri(
            name=email, issuer_name=get_settings().app_name
        )

    @staticmethod
    def verify_code(secret: str, code: str) -> bool:
        return pyotp.TOTP(secret).verify(code, valid_window=1)

    @staticmethod
    def generate_recovery_codes() -> Tuple[List[str], List[str]]:
        """Returns (raw code send to user, hashes for stored)."""
        raw_codes = [TokenHelper.generate()[:10] for _ in range(RECOVERY_CODE_COUNT)]
        hashes = [TokenHelper.hash(code) for code in raw_codes]
        return raw_codes, hashes

    @staticmethod
    def consume_recovery_code(stored_hashes: List[str], code: str) -> List[str] | None:
        """Returns the updated hash list with the matching code removed, or
        None if the code didn't match any stored hash."""
        code_hash = TokenHelper.hash(code)
        if code_hash not in stored_hashes:
            return None
        remaining = list(stored_hashes)
        remaining.remove(code_hash)
        return remaining
