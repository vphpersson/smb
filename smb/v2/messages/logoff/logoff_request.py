from __future__ import annotations
from dataclasses import dataclass
from typing import ClassVar
from struct import pack as struct_pack, unpack as struct_unpack

from smb.v2.messages.message import SMBv2RequestMessage, register_smbv2_message
from smb.v2.header import SMBv2Header, SMBv2Command
from smb.exceptions import IncorrectStructureSizeError, MalformedLogoffRequestError


@dataclass
@register_smbv2_message
class LogoffRequest(SMBv2RequestMessage):
    structure_size: ClassVar[int] = 4
    _command: ClassVar[SMBv2Command] = SMBv2Command.SMB2_LOGOFF
    _reserved: ClassVar[int] = 2 * b'\x00'

    @classmethod
    def _from_bytes_and_header(cls, data: bytes, header: SMBv2Header) -> LogoffRequest:

        body_data: bytes = data[len(header):]

        try:
            cls.check_structure_size(structure_size_to_test=struct_unpack('<H', body_data[:2])[0])
        except IncorrectStructureSizeError as e:
            raise MalformedLogoffRequestError(str(e)) from e

        return cls(header=header)

    def __bytes__(self) -> bytes:
        return bytes(self.header) + b''.join([
            struct_pack('<H', self.structure_size),
            self._reserved
        ])

    def __len__(self) -> int:
        return len(self.header) + self.structure_size


