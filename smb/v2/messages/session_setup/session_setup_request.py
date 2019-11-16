from __future__ import annotations
from dataclasses import dataclass
from enum import IntEnum
from struct import unpack as struct_unpack, pack as struct_pack
from typing import ClassVar

from smb.v2.smbv2_header import SMBv2Header, SMBv2Command
from smb.v2.smbv2_message import SMBv2RequestMessage, register_smbv2_message
from smb.v2.security_mode import SecurityMode
from smb.v2.capabilities import CapabilitiesFlag
from smb.exceptions import MalformedSessionSetupRequestError, IncorrectStructureSizeError


# TODO: Rather than being an `IntEnum`, shouldn't this be a flag, to indicate that it can be empty?
class SessionSetupRequestFlag(IntEnum):
    # NOTE: Not part of the flag according to the spec.
    SMB2_SESSION_FLAG_NONE = 0x00
    SMB2_SESSION_FLAG_BINDING = 0x01


@dataclass
@register_smbv2_message
class SessionSetupRequest(SMBv2RequestMessage):
    security_mode: SecurityMode
    security_buffer: bytes
    flags: SessionSetupRequestFlag = SessionSetupRequestFlag.SMB2_SESSION_FLAG_NONE
    capabilities: CapabilitiesFlag = CapabilitiesFlag()
    previous_session_id: bytes = 8 * b'\x00'

    structure_size: ClassVar[int] = 25
    _command: ClassVar[SMBv2Command] = SMBv2Command.SMB2_SESSION_SETUP
    _reserved_channel: ClassVar[bytes] = 4 * b'\x00'

    @classmethod
    def _from_bytes_and_header(cls, data: bytes, header: SMBv2Header):

        body_data: bytes = data[len(header):]

        try:
            cls.check_structure_size(structure_size_to_test=struct_unpack('<H', body_data[:2])[0])
        except IncorrectStructureSizeError as e:
            raise MalformedSessionSetupRequestError(str(e)) from e

        if body_data[8:12] != cls._reserved_channel:
            # TODO: Use proper exception.
            raise ValueError

        security_buffer_offset: int = struct_unpack('<H', body_data[12:14])[0]
        security_buffer_length: int = struct_unpack('<H', body_data[14:16])[0]

        return cls(
            header=header,
            flags=SessionSetupRequestFlag(struct_unpack('<B', body_data[2:3])[0]),
            security_mode=SecurityMode(struct_unpack('<B', body_data[3:4])[0]),
            capabilities=CapabilitiesFlag.from_mask(struct_unpack('<I', body_data[4:8])[0]),
            previous_session_id=body_data[16:24],
            security_buffer=data[security_buffer_offset:security_buffer_offset+security_buffer_length]
        )

    def __len__(self) -> int:
        return len(self.header) + 24 + len(self.security_buffer)

    def __bytes__(self) -> bytes:
        return bytes(self.header) + b''.join([
            struct_pack('<H', 25),
            struct_pack('<B', self.flags.value),
            struct_pack('<B', self.security_mode.value),
            struct_pack('<I', self.capabilities.to_mask()),
            self._reserved_channel,
            struct_pack('<H', len(self.header) + 24),
            struct_pack('<H', len(self.security_buffer)),
            self.previous_session_id,
            self.security_buffer
        ])
