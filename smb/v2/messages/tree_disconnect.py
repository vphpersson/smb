from __future__ import annotations
from dataclasses import dataclass
from typing import ClassVar
from struct import pack as struct_pack

from smb.v2.messages import RequestMessage, ResponseMessage, register_smbv2_message
from smb.v2.header import Header, SMBv2Command


@dataclass
@register_smbv2_message
class TreeDisconnectRequest(RequestMessage):
    STRUCTURE_SIZE: ClassVar[int] = 4
    _RESERVED: ClassVar[bytes] = 2 * b'\x00'
    _COMMAND: ClassVar[SMBv2Command] = SMBv2Command.SMB2_TREE_DISCONNECT

    @classmethod
    def _from_bytes_and_header(cls, data: bytes, header: Header) -> TreeDisconnectRequest:
        return cls(header=header)

    def __bytes__(self) -> bytes:
        return bytes(self.header) + b''.join([struct_pack('<H', self.STRUCTURE_SIZE), self._RESERVED])

    def __len__(self) -> int:
        return len(self.header) + self.STRUCTURE_SIZE


@dataclass
@register_smbv2_message
class TreeDisconnectResponse(ResponseMessage):
    STRUCTURE_SIZE: ClassVar[int] = 4
    _RESERVED: ClassVar[bytes] = 2 * b'\x00'
    _COMMAND: ClassVar[SMBv2Command] = SMBv2Command.SMB2_TREE_DISCONNECT

    @classmethod
    def _from_bytes_and_header(cls, data: bytes, header: Header) -> TreeDisconnectResponse:
        return cls(header=header)

    def __bytes__(self) -> bytes:
        return bytes(self.header) + b''.join([struct_pack('<H', self.STRUCTURE_SIZE),self._RESERVED])

    def __len__(self) -> int:
        return len(self.header) + self.STRUCTURE_SIZE
