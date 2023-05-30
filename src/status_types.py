from enum import Enum


BIT_SIZES = {
    "revocation-list": 1,
    "suspension-revocation-list": 2,
}


class RevocationList(Enum):
    VALID = 0
    INVALID = 1


class SuspensionRevocationList(Enum):
    VALID = 0
    INVALID = 1
    SUSPENDED = 2
    UNDEFINED = 3
