from __future__ import annotations
from dataclasses import dataclass
from typing import ClassVar, Type
from abc import ABC
from enum import IntFlag, IntEnum
from struct import pack as struct_pack, unpack as struct_unpack

from msdsalgs.utils import make_mask_class

from smb.v2.header import SMBv2Header, SMBv2Command
from smb.v2.messages.message import SMBv2RequestMessage, register_smbv2_message
from smb.v2.dialect import Dialect


class TreeConnectFlagMask(IntFlag):
    SMB2_TREE_CONNECT_FLAG_CLUSTER_RECONNECT = 0x0001
    SMB2_TREE_CONNECT_FLAG_REDIRECT_TO_OWNER = 0x0002
    SMB2_TREE_CONNECT_FLAG_EXTENSION_PRESENT = 0x0004


TreeConnectFlag = make_mask_class(TreeConnectFlagMask, prefix='SMB2_TREE_CONNECT_FLAG_')


@dataclass
class TreeConnectContext:
    ...


class TreeConnectContextType(IntEnum):
    SMB2_RESERVED_TREE_CONNECT_CONTEXT_ID = 0x0000
    SMB2_REMOTED_IDENTITY_TREE_CONNECT_CONTEXT_ID = 0x0001


@dataclass
class TreeConnectRequestExtension:
    path_name: str

    @classmethod
    def from_bytes(cls, data: bytes, path_name_len: int) -> 'TreeConnectRequestExtension':
        tree_connect_context_type = TreeConnectContextType(struct_unpack('<H', data[:2])[0])
        if tree_connect_context_type is TreeConnectContextType.SMB2_REMOTED_IDENTITY_TREE_CONNECT_CONTEXT_ID:
            raise NotImplementedError
        elif tree_connect_context_type is TreeConnectContextType.SMB2_RESERVED_TREE_CONNECT_CONTEXT_ID:
            raise NotImplementedError
        else:
            # TODO: Use proper exception.
            raise ValueError


@dataclass
class RemotedIdentityTreeConnectContext(TreeConnectRequestExtension):
    ...


@dataclass
@register_smbv2_message
class TreeConnectRequest(SMBv2RequestMessage, ABC):
    structure_size: ClassVar[int] = 9

    _command: ClassVar[SMBv2Command] = SMBv2Command.SMB2_TREE_CONNECT
    _dialect_to_class: ClassVar[Dialect, Type[TreeConnectRequest]] = {}
    _dialect: ClassVar[Dialect] = NotImplemented

    @classmethod
    def _from_bytes_and_header(cls, data: bytes, header: SMBv2Header) -> TreeConnectRequest:

        body_data: bytes = data[len(header):]

        cls.check_structure_size(structure_size_to_test=struct_unpack('<H', body_data[:2])[0])

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
            struct_pack('<H', TreeConnectRequest.structure_size),
            b'\x00\x00',
            struct_pack('<H', len(self.header) + (TreeConnectRequest.structure_size - 1)),
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