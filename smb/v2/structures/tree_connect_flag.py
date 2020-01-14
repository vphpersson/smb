from enum import IntFlag
from msdsalgs.utils import Mask


class TreeConnectFlagMask(IntFlag):
    SMB2_TREE_CONNECT_FLAG_CLUSTER_RECONNECT = 0x0001
    SMB2_TREE_CONNECT_FLAG_REDIRECT_TO_OWNER = 0x0002
    SMB2_TREE_CONNECT_FLAG_EXTENSION_PRESENT = 0x0004


TreeConnectFlag = Mask.make_class(TreeConnectFlagMask, prefix='SMB2_TREE_CONNECT_FLAG_')
