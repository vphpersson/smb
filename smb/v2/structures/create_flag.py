from enum import IntFlag
from msdsalgs.utils import Mask


class CreateFlagMask(IntFlag):
    SMB2_CREATE_FLAG_REPARSEPOINT = 0x01


CreateFlag = Mask.make_class(CreateFlagMask, prefix='SMB_CREATE_FLAG_')
