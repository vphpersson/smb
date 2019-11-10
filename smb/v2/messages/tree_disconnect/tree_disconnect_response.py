from __future__ import annotations
from dataclasses import dataclass
from typing import ClassVar
from struct import pack as struct_pack

from smb.v2.smbv2_message import SMBv2Message
from smb.v2.smbv2_header import SMBv2Header


@dataclass
class TreeDisconnectResponse(SMBv2Message):

    structure_size: ClassVar[int] = 4
    _reserved: ClassVar[bytes] = 2 * b'\x00'

    @classmethod
    def from_bytes_and_header(cls, data: bytes, header: SMBv2Header) -> TreeDisconnectResponse:
        return cls(header=header)

    def __bytes__(self) -> bytes:
        return bytes(self.header) + b''.join([
            struct_pack('<H', self.structure_size),
            self._reserved
        ])

    def __len__(self) -> int:
        return len(self.header) + self.structure_size
