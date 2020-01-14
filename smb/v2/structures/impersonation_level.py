from enum import IntEnum


class ImpersonationLevel(IntEnum):
    ANONYMOUS = 0x00000000
    IDENTIFICATION = 0x00000001
    IMPERSONATION = 0x00000002
    DELEGATE = 0x00000003
