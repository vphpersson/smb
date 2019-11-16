from __future__ import annotations
from dataclasses import dataclass
from typing import ClassVar
from struct import pack as struct_pack, unpack as struct_unpack

from smb.v2.smbv2_message import SMBv2ResponseMessage, register_smbv2_message
from smb.v2.smbv2_header import SMBv2Header, SMBv2Command
from smb.exceptions import IncorrectStructureSizeError, MalformedLogoffResponseError


@dataclass
@register_smbv2_message
class LogoffResponse(SMBv2ResponseMessage):
    structure_size: ClassVar[int] = 4
    _reserved: ClassVar[int] = 2 * b'\x00'
    _command: ClassVar[SMBv2Command] = SMBv2Command.SMB2_LOGOFF

    @classmethod
    def _from_bytes_and_header(cls, data: bytes, header: SMBv2Header) -> LogoffResponse:
        body_data: bytes = data[len(header):]

        try:
            cls.check_structure_size(structure_size_to_test=struct_unpack('<H', body_data[:2])[0])
        except IncorrectStructureSizeError as e:
            raise MalformedLogoffResponseError(str(e)) from e

        return cls(header=header)

    def __bytes__(self) -> bytes:
        return bytes(self.header) + b''.join([
            struct_pack('<H', self.structure_size),
            self._reserved
        ])

    def __len__(self) -> int:
        return len(self.header) + self.structure_size
