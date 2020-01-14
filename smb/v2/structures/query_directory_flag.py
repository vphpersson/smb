from enum import IntFlag
from msdsalgs.utils import Mask


class QueryDirectoryFlagMask(IntFlag):
    SMB2_NONE = 0x00
    SMB2_RESTART_SCANS = 0x01
    SMB2_RETURN_SINGLE_ENTRY = 0x02
    SMB2_INDEX_SPECIFIED = 0x04
    SMB2_REOPEN = 0x10


QueryDirectoryFlag = Mask.make_class(QueryDirectoryFlagMask, prefix='SMB2_')
