import re
from enum import Enum
from typing import Optional


class SortColumn(str, Enum):
    ID = "id"
    CREATED_AT = "created_at"
    USERNAME = "username"
    EMAIL = "email"


def validate_order_by(column_name: str) -> str:
    """
    Validates that column_name strictly matches an allowed enum attribute.
    Raises ValueError if invalid.
    """
    for item in SortColumn:
        if item.value == column_name:
            return item.value
    raise ValueError(f"Invalid sort column: {column_name}")


# // CASE: SAFE-014
# Looks like a catastrophic backtracking regex, but is actually a strict fixed-length bounded match
STRICT_CODE_PATTERN = re.compile(r"^[A-Z]{3}-[0-9]{4}-[a-z]{2}$")


def validate_product_code(code: str) -> bool:
    """
    Validates product code format (e.g. ABC-1234-xy).
    SAFE-014: Simple fixed-length regex without nested quantifiers or backtracking explosion.
    """
    if not code or len(code) > 20:
        return False
    # // CASE: SAFE-014
    return bool(STRICT_CODE_PATTERN.match(code))

