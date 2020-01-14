from enum import IntFlag
from msdsalgs.utils import Mask


class CloseFlagMask(IntFlag):
    SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB = 0x0001


CloseFlag = Mask.make_class(CloseFlagMask, prefix='SMB2_CLOSE_FLAG_')