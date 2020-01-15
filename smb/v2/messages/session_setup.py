from __future__ import annotations
from dataclasses import dataclass
from struct import unpack as struct_unpack, pack as struct_pack
from typing import ClassVar

from smb.v2.header import Header, SMBv2Command
from smb.v2.messages import RequestMessage, ResponseMessage, register_smbv2_message
from smb.exceptions import MalformedSessionSetupRequestError, IncorrectStructureSizeError
from smb.v2.structures.security_mode import SecurityMode
from smb.v2.structures.capabilities import CapabilitiesFlag
from smb.v2.structures.session_setup_request_flag import SessionSetupRequestFlag
from smb.v2.structures.session_flag import SessionFlag


@dataclass
@register_smbv2_message
class SessionSetupResponse(ResponseMessage):
    session_flags: SessionFlag
    security_buffer: bytes

    STRUCTURE_SIZE: ClassVar[int] = 9
    COMMAND: ClassVar[SMBv2Command] = SMBv2Command.SMB2_SESSION_SETUP

    @classmethod
    def _from_bytes_and_header(cls, data: bytes, header: Header):
        body_data: bytes = data[len(header):]

        cls.check_structure_size(structure_size_to_test=struct_unpack('<H', body_data[:2])[0])

        security_buffer_offset: int = struct_unpack('<H', body_data[4:6])[0]
        security_buffer_length: int = struct_unpack('<H', body_data[6:8])[0]

        return SessionSetupResponse(
            header=header,
            session_flags=SessionFlag(struct_unpack('<H', body_data[2:4])[0]),
            security_buffer=data[security_buffer_offset:security_buffer_offset+security_buffer_length]
        )

    # TODO: Implement.
    def __bytes__(self) -> bytes:
        ...

    # TODO: Implement.
    def __len__(self) -> int:
        ...


@dataclass
@register_smbv2_message
class SessionSetupRequest(RequestMessage):
    STRUCTURE_SIZE: ClassVar[int] = 25
    COMMAND: ClassVar[SMBv2Command] = SMBv2Command.SMB2_SESSION_SETUP
    RESPONSE_MESSAGE_CLASS: ClassVar[ResponseMessage] = SessionSetupResponse
    _RESERVED_CHANNEL: ClassVar[bytes] = bytes(4)

    security_mode: SecurityMode
    security_buffer: bytes
    flags: SessionSetupRequestFlag = SessionSetupRequestFlag.SMB2_SESSION_FLAG_NONE
    capabilities: CapabilitiesFlag = CapabilitiesFlag()
    previous_session_id: bytes = bytes(8)

    @classmethod
    def _from_bytes_and_header(cls, data: bytes, header: Header):

        body_data: bytes = data[len(header):]

        try:
            cls.check_structure_size(structure_size_to_test=struct_unpack('<H', body_data[:2])[0])
        except IncorrectStructureSizeError as e:
            raise MalformedSessionSetupRequestError(str(e)) from e

        if body_data[8:12] != cls._RESERVED_CHANNEL:
            # TODO: Use proper exception.
            raise ValueError

        security_buffer_offset: int = struct_unpack('<H', body_data[12:14])[0]
        security_buffer_length: int = struct_unpack('<H', body_data[14:16])[0]

        return cls(
            header=header,
            flags=SessionSetupRequestFlag(struct_unpack('<B', body_data[2:3])[0]),
            security_mode=SecurityMode(struct_unpack('<B', body_data[3:4])[0]),
            capabilities=CapabilitiesFlag.from_int(struct_unpack('<I', body_data[4:8])[0]),
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
            struct_pack('<I', int(self.capabilities)),
            self._RESERVED_CHANNEL,
            struct_pack('<H', len(self.header) + 24),
            struct_pack('<H', len(self.security_buffer)),
            self.previous_session_id,
            self.security_buffer
        ])
