from enum import IntFlag
from msdsalgs.utils import Mask


class ShareAccessFlag(IntFlag):
    FILE_SHARE_READ = 0x00000001,
    FILE_SHARE_WRITE = 0x00000002,
    FILE_SHARE_DELETE = 0x00000004


ShareAccess = Mask.make_class(ShareAccessFlag, prefix='FILE_SHARE_')
