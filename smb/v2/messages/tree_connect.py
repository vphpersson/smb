from __future__ import annotations
from dataclasses import dataclass
from typing import ClassVar, Type
from abc import ABC
from struct import pack as struct_pack, unpack as struct_unpack

from smb.v2.header import Header, SMBv2Command
from smb.v2.messages import Message, RequestMessage, ResponseMessage
from smb.v2.structures.dialect import Dialect
from smb.v2.structures.tree_connect_flag import TreeConnectFlag
from smb.v2.structures.access_mask import FilePipePrinterAccessMask
from smb.v2.structures.share_type import ShareType
from smb.v2.structures.share_flag import ShareFlag
from smb.v2.structures.share_capabilities import ShareCapabilities
from smb.exceptions import MalformedSMBv2MessageError, MalformedTreeConnectRequestError,\
    MalformedTreeConnectResponseError


@dataclass
@Message.register
class TreeConnectResponse(ResponseMessage):
    STRUCTURE_SIZE: ClassVar[int] = 16
    COMMAND: ClassVar[SMBv2Command] = SMBv2Command.SMB2_TREE_CONNECT
    MALFORMED_ERROR_CLASS: ClassVar[Type[MalformedSMBv2MessageError]] = MalformedTreeConnectResponseError
    _RESERVED: ClassVar[bytes] = bytes(1)

    share_type: ShareType
    share_flag: ShareFlag
    share_capabilities: ShareCapabilities
    maximal_access: FilePipePrinterAccessMask

    @classmethod
    def _from_bytes_and_header(cls, data: bytes, header: Header) -> SMBv2Message:
        super()._from_bytes_and_header(data=data, header=header)

        body_data: bytes = data[len(header):]

        if body_data[3:4] != cls._RESERVED:
            # TODO: Raise proper exception.
            raise ValueError

        return cls(
            header=header,
            share_type=ShareType(body_data[2]),
            share_flag=ShareFlag.from_int(struct_unpack('<I', body_data[4:8])[0]),
            share_capabilities=ShareCapabilities.from_int(struct_unpack('<I', body_data[8:12])[0]),
            maximal_access=FilePipePrinterAccessMask.from_int(struct_unpack('<I', body_data[12:16])[0])
        )

    def __bytes__(self) -> bytes:
        return bytes(self.header) + b''.join([
            struct_pack('<H', self.STRUCTURE_SIZE),
            struct_pack('<B', self.share_type),
            self._RESERVED,
            struct_pack('<I', self.share_flag),
            struct_pack('<I', self.share_capabilities),
            struct_pack('<I', self.maximal_access)
        ])

    def __len__(self) -> int:
        return self.STRUCTURE_SIZE


@dataclass
@Message.register
class TreeConnectRequest(RequestMessage, ABC):
    STRUCTURE_SIZE: ClassVar[int] = 9
    COMMAND: ClassVar[SMBv2Command] = SMBv2Command.SMB2_TREE_CONNECT
    RESPONSE_MESSAGE_CLASS: ClassVar[ResponseMessage] = TreeConnectResponse
    MALFORMED_ERROR_CLASS: ClassVar[Type[MalformedSMBv2MessageError]] = MalformedTreeConnectRequestError
    _DIALECT_TO_CLASS: ClassVar[Dialect, Type[TreeConnectRequest]] = {}
    _DIALECT: ClassVar[Dialect] = NotImplemented

    @classmethod
    def _from_bytes_and_header(cls, data: bytes, header: Header) -> TreeConnectRequest:
        super()._from_bytes_and_header(data=data, header=header)

        body_data: bytes = data[len(header):]

        path_offset: int = struct_unpack('<H', body_data[4:6])[0]
        path_length: int = struct_unpack('<H', body_data[6:8])[0]

        tree_connect_base_kwargs = dict(
            header=header,
            path=data[path_offset:path_offset + path_length].decode(encoding='utf-16-le')
        )

        if Dialect.SMB_2_0_2 <= header.DIALECT < Dialect.SMB_3_1_1:
            return cls._DIALECT_TO_CLASS[header.DIALECT](**tree_connect_base_kwargs)
        elif header.DIALECT is Dialect.SMB_3_1_1:
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


TreeConnectRequest._DIALECT_TO_CLASS = {
    Dialect.SMB_2_0_2: TreeConnectRequest202,
    Dialect.SMB_2_1: TreeConnectRequest210,
    Dialect.SMB_3_0: TreeConnectRequest300,
    Dialect.SMB_3_0_2: TreeConnectRequest302,
    Dialect.SMB_3_1_1: TreeConnectRequest311
}
