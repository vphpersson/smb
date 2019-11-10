from __future__ import annotations
from dataclasses import dataclass
from typing import ClassVar
from enum import IntEnum, IntFlag
from struct import unpack as struct_unpack, pack as struct_pack

from msdsalgs.utils import make_mask_class

from smb.v2.smbv2_message import SMBv2Message, register_smbv2_message
from smb.v2.smbv2_header import SMBv2Header, SMBv2Command
from smb.v2.access_mask import FilePipePrinterAccessMask
from smb.smb_message import SMBResponseMessage


class ShareType(IntEnum):
    SMB2_SHARE_TYPE_DISK = 0x1
    SMB2_SHARE_TYPE_PIPE = 0x2
    SMB2_SHARE_TYPE_PRINT = 0x3


class ShareFlagMask(IntFlag):
    SMB2_SHAREFLAG_MANUAL_CACHING = 0x00000000,
    SMB2_SHAREFLAG_AUTO_CACHING = 0x00000010,
    SMB2_SHAREFLAG_VDO_CACHING = 0x00000020,
    SMB2_SHAREFLAG_NO_CACHING = 0x00000030,
    SMB2_SHAREFLAG_DFS = 0x00000001,
    SMB2_SHAREFLAG_DFS_ROOT = 0x00000002,
    SMB2_SHAREFLAG_RESTRICT_EXCLUSIVE_OPENS = 0x00000100,
    SMB2_SHAREFLAG_FORCE_SHARED_DELETE = 0x00000200,
    SMB2_SHAREFLAG_ALLOW_NAMESPACE_CACHING = 0x00000400,
    SMB2_SHAREFLAG_ACCESS_BASED_DIRECTORY_ENUM = 0x00000800,
    SMB2_SHAREFLAG_FORCE_LEVELII_OPLOCK = 0x00001000,
    SMB2_SHAREFLAG_ENABLE_HASH_V1 = 0x00002000,
    SMB2_SHAREFLAG_ENABLE_HASH_V2 = 0x00004000,
    SMB2_SHAREFLAG_ENCRYPT_DATA = 0x00008000,
    SMB2_SHAREFLAG_IDENTITY_REMOTING = 0x00040000


ShareFlag = make_mask_class(ShareFlagMask, prefix='SMB2_SHAREFLAG_')


class ShareCapabilitiesMask(IntFlag):
    SMB2_SHARE_CAP_DFS = 0x00000008,
    SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY = 0x00000010,
    SMB2_SHARE_CAP_SCALEOUT = 0x00000020,
    SMB2_SHARE_CAP_CLUSTER = 0x00000040,
    SMB2_SHARE_CAP_ASYMMETRIC = 0x00000080,
    SMB2_SHARE_CAP_REDIRECT_TO_OWNER = 0x00000100


ShareCapabilities = make_mask_class(ShareCapabilitiesMask, prefix='SMB2_SHARE_CAP_')


@dataclass
@register_smbv2_message
class TreeConnectResponse(SMBv2Message, SMBResponseMessage):
    share_type: ShareType
    share_flag: ShareFlag
    share_capabilities: ShareCapabilities
    maximal_access: FilePipePrinterAccessMask

    structure_size: ClassVar[int] = 16
    _command: ClassVar[SMBv2Command] = SMBv2Command.SMB2_TREE_CONNECT

    @classmethod
    def _from_bytes_and_header(cls, data: bytes, header: SMBv2Header) -> SMBv2Message:

        body_data: bytes = data[len(header):]

        cls.check_structure_size(structure_size_to_test=struct_unpack('<H', body_data[:2])[0])

        # TODO: Use a `ClassVar`.
        # Reserved
        if body_data[3:4] != b'\x00':
            # TODO: Raise proper exception.
            raise ValueError

        return cls(
            header=header,
            share_type=ShareType(body_data[2]),
            share_flag=ShareFlag.from_mask(struct_unpack('<I', body_data[4:8])[0]),
            share_capabilities=ShareCapabilities.from_mask(struct_unpack('<I', body_data[8:12])[0]),
            maximal_access=FilePipePrinterAccessMask.from_mask(struct_unpack('<I', body_data[12:16])[0])
        )

    def __bytes__(self) -> bytes:
        return bytes(self.header) + b''.join([
            struct_pack('<H', self.structure_size),
            struct_pack('<B', self.share_type),
            b'\x00',
            struct_pack('<I', self.share_flag),
            struct_pack('<I', self.share_capabilities),
            struct_pack('<I', self.maximal_access)
        ])

    def __len__(self) -> int:
        return self.structure_size





