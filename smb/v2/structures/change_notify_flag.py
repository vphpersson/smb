from enum import IntFlag
from msdsalgs.utils import Mask


class ChangeNotifyFlagMask(IntFlag):
    SMB2_WATCH_TREE = 0x0001


ChangeNotifyFlag = Mask.make_class(ChangeNotifyFlagMask, prefix='SMB2_')
