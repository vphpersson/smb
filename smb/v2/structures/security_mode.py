from enum import IntFlag

from msdsalgs.utils import Mask


class SecurityModeFlag(IntFlag):
    SMB2_NEGOTIATE_SIGNING_ENABLED = 0x0001
    SMB2_NEGOTIATE_SIGNING_REQUIRED = 0x0002


SecurityMode = Mask.make_class(
    int_flag_class=SecurityModeFlag,
    prefix='SMB2_NEGOTIATE_'
)
