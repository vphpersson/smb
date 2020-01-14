from __future__ import annotations
from dataclasses import dataclass
from typing import ClassVar, Type
from abc import ABC
from struct import pack as struct_pack, unpack as struct_unpack

from smb.v2.header import SMBv2Header, SMBv2Command
from smb.v2.messages.message_base import SMBv2RequestMessage, SMBv2ResponseMessage, register_smbv2_message
from smb.v2.structures.dialect import Dialect
from smb.v2.structures.tree_connect_flag import TreeConnectFlag
from smb.v2.structures.access_mask import FilePipePrinterAccessMask
from smb.v2.structures.share_type import ShareType
from smb.v2.structures.share_flag import ShareFlag
from smb.v2.structures.share_capabilities import ShareCapabilities


@dataclass
@register_smbv2_message
class TreeConnectRequest(SMBv2RequestMessage, ABC):
    STRUCTURE_SIZE: ClassVar[int] = 9

    _COMMAND: ClassVar[SMBv2Command] = SMBv2Command.SMB2_TREE_CONNECT
    _dialect_to_class: ClassVar[Dialect, Type[TreeConnectRequest]] = {}
    _dialect: ClassVar[Dialect] = NotImplemented

    @classmethod
    def _from_bytes_and_header(cls, data: bytes, header: SMBv2Header) -> TreeConnectRequest:

        body_data: bytes = data[len(header):]

        cls.check_STRUCTURE_SIZE(STRUCTURE_SIZE_to_test=struct_unpack('<H', body_data[:2])[0])

        path_offset: int = struct_unpack('<H', body_data[4:6])[0]
        path_length: int = struct_unpack('<H', body_data[6:8])[0]

        tree_connect_base_kwargs = dict(
            header=header,
            path=data[path_offset:path_offset + path_length].decode(encoding='utf-16-le')
        )

        if Dialect.SMB_2_0_2 <= header.header_dialect < Dialect.SMB_3_1_1:
            return cls._dialect_to_class[header.header_dialect](**tree_connect_base_kwargs)
        elif header.header_dialect is Dialect.SMB_3_1_1:
            raise NotImplemented
            # return TreeConnect311(
            #     **tree_connect_base_kwargs,
            #     flags=TreeConnectFlag.from_mask(mask=struct_unpack('<H', body_data[2:4])[0])
            # )
        else:
            # TODO: Use proper exception.
            raise ValueError


@dataclass
class TreeConnectRequest2X(TreeConnectRequest, ABC):
    path: str

    def __bytes__(self) -> bytes:
        path_bytes: bytes = self.path.encode(encoding='utf-16-le')

        return bytes(self.header) + b''.join([
            struct_pack('<H', TreeConnectRequest.STRUCTURE_SIZE),
            b'\x00\x00',
            struct_pack('<H', len(self.header) + (TreeConnectRequest.STRUCTURE_SIZE - 1)),
            struct_pack('<H', len(path_bytes)),
            path_bytes
        ])

    def __len__(self) -> int:
        return len(self.header) + 8 + len(self.path.encode(encoding='utf-16-le'))


@dataclass
class TreeConnectRequest202(TreeConnectRequest2X):
    pass


@dataclass
class TreeConnectRequest210(TreeConnectRequest2X):
    pass


@dataclass
class TreeConnectRequest3X(TreeConnectRequest, ABC):
    pass


@dataclass
class TreeConnectRequest300(TreeConnectRequest):
    path: str

    def __len__(self) -> int:
        return len(self.header) + 8 + len(self.path.encode(encoding='utf-16-le'))


@dataclass
class TreeConnectRequest302(TreeConnectRequest):
    path: str

    def __len__(self) -> int:
        return len(self.header) + 8 + len(self.path.encode(encoding='utf-16-le'))


@dataclass
class TreeConnectRequest311(TreeConnectRequest):
    flags: TreeConnectFlag


TreeConnectRequest._dialect_to_class = {
    Dialect.SMB_2_0_2: TreeConnectRequest202,
    Dialect.SMB_2_1: TreeConnectRequest210,
    Dialect.SMB_3_0: TreeConnectRequest300,
    Dialect.SMB_3_0_2: TreeConnectRequest302,
    Dialect.SMB_3_1_1: TreeConnectRequest311
}


@dataclass
@register_smbv2_message
class TreeConnectResponse(SMBv2ResponseMessage):
    share_type: ShareType
    share_flag: ShareFlag
    share_capabilities: ShareCapabilities
    maximal_access: FilePipePrinterAccessMask

    STRUCTURE_SIZE: ClassVar[int] = 16
    _COMMAND: ClassVar[SMBv2Command] = SMBv2Command.SMB2_TREE_CONNECT

    @classmethod
    def _from_bytes_and_header(cls, data: bytes, header: SMBv2Header) -> SMBv2Message:

        body_data: bytes = data[len(header):]

        cls.check_STRUCTURE_SIZE(STRUCTURE_SIZE_to_test=struct_unpack('<H', body_data[:2])[0])

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
            struct_pack('<H', self.STRUCTURE_SIZE),
            struct_pack('<B', self.share_type),
            b'\x00',
            struct_pack('<I', self.share_flag),
            struct_pack('<I', self.share_capabilities),
            struct_pack('<I', self.maximal_access)
        ])

    def __len__(self) -> int:
        return self.STRUCTURE_SIZE
