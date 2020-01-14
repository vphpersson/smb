from __future__ import annotations
from dataclasses import dataclass
from typing import ClassVar
from struct import pack as struct_pack, unpack as struct_unpack

from smb.v2.messages.message_base import SMBv2RequestMessage, SMBv2ResponseMessage, register_smbv2_message
from smb.v2.header import SMBv2Header, SMBv2Command
from smb.exceptions import IncorrectStructureSizeError, MalformedLogoffRequestError, MalformedLogoffResponseError


@dataclass
@register_smbv2_message
class LogoffRequest(SMBv2RequestMessage):
    STRUCTURE_SIZE: ClassVar[int] = 4
    _COMMAND: ClassVar[SMBv2Command] = SMBv2Command.SMB2_LOGOFF
    _reserved: ClassVar[int] = 2 * b'\x00'

    @classmethod
    def _from_bytes_and_header(cls, data: bytes, header: SMBv2Header) -> LogoffRequest:

        body_data: bytes = data[len(header):]

        try:
            cls.check_STRUCTURE_SIZE(STRUCTURE_SIZE_to_test=struct_unpack('<H', body_data[:2])[0])
        except IncorrectStructureSizeError as e:
            raise MalformedLogoffRequestError(str(e)) from e

        return cls(header=header)

    def __bytes__(self) -> bytes:
        return bytes(self.header) + b''.join([
            struct_pack('<H', self.STRUCTURE_SIZE),
            self._reserved
        ])

    def __len__(self) -> int:
        return len(self.header) + self.STRUCTURE_SIZE


@dataclass
@register_smbv2_message
class LogoffResponse(SMBv2ResponseMessage):
    STRUCTURE_SIZE: ClassVar[int] = 4
    _reserved: ClassVar[int] = 2 * b'\x00'
    _COMMAND: ClassVar[SMBv2Command] = SMBv2Command.SMB2_LOGOFF

    @classmethod
    def _from_bytes_and_header(cls, data: bytes, header: SMBv2Header) -> LogoffResponse:
        body_data: bytes = data[len(header):]

        try:
            cls.check_STRUCTURE_SIZE(STRUCTURE_SIZE_to_test=struct_unpack('<H', body_data[:2])[0])
        except IncorrectStructureSizeError as e:
            raise MalformedLogoffResponseError(str(e)) from e

        return cls(header=header)

    def __bytes__(self) -> bytes:
        return bytes(self.header) + b''.join([
            struct_pack('<H', self.STRUCTURE_SIZE),
            self._reserved
        ])

    def __len__(self) -> int:
        return len(self.header) + self.STRUCTURE_SIZE
