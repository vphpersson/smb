from __future__ import annotations
from dataclasses import dataclass
from typing import ClassVar
from struct import pack as struct_pack

from smb.v2.smbv2_message import SMBv2Message, register_smbv2_message
from smb.v2.smbv2_header import SMBv2Header, SMBv2Command
from smb.smb_message import SMBResponseMessage


@dataclass
@register_smbv2_message
class TreeDisconnectResponse(SMBv2Message, SMBResponseMessage):

    structure_size: ClassVar[int] = 4
    _reserved: ClassVar[bytes] = 2 * b'\x00'
    _command: ClassVar[SMBv2Command] = SMBv2Command.SMB2_TREE_DISCONNECT

    @classmethod
    def _from_bytes_and_header(cls, data: bytes, header: SMBv2Header) -> TreeDisconnectResponse:
        return cls(header=header)

    def __bytes__(self) -> bytes:
        return bytes(self.header) + b''.join([
            struct_pack('<H', self.structure_size),
            self._reserved
        ])

    def __len__(self) -> int:
        return len(self.header) + self.structure_size