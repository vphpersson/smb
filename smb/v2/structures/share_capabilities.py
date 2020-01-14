from enum import IntFlag
from msdsalgs.utils import Mask


class ShareCapabilitiesMask(IntFlag):
    SMB2_SHARE_CAP_DFS = 0x00000008,
    SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY = 0x00000010,
    SMB2_SHARE_CAP_SCALEOUT = 0x00000020,
    SMB2_SHARE_CAP_CLUSTER = 0x00000040,
    SMB2_SHARE_CAP_ASYMMETRIC = 0x00000080,
    SMB2_SHARE_CAP_REDIRECT_TO_OWNER = 0x00000100


ShareCapabilities = Mask.make_class(ShareCapabilitiesMask, prefix='SMB2_SHARE_CAP_')
