from enum import IntFlag
from msdsalgs.utils import Mask


class ReadRequestFlagMask(IntFlag):
    SMB2_READFLAG_READ_UNBUFFERED = 0x01,
    SMB2_READFLAG_REQUEST_COMPRESSED = 0x02


ReadRequestFlag = Mask.make_class(ReadRequestFlagMask, prefix='SMB2_READFLAG_')
