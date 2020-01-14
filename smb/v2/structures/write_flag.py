from enum import IntFlag
from msdsalgs.utils import Mask


class WriteFlagMask(IntFlag):
    SMB2_WRITEFLAG_NONE = 0x00000000
    SMB2_WRITEFLAG_WRITE_THROUGH = 0x00000001
    SMB2_WRITEFLAG_WRITE_UNBUFFERED = 0x00000002


WriteFlag = Mask.make_class(WriteFlagMask, prefix='SMB2_WRITEFLAG_')
