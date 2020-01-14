from enum import IntEnum


class ShareType(IntEnum):
    SMB2_SHARE_TYPE_DISK = 0x1
    SMB2_SHARE_TYPE_PIPE = 0x2
    SMB2_SHARE_TYPE_PRINT = 0x3
