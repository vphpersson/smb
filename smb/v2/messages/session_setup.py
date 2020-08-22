from __future__ import annotations
from dataclasses import dataclass
from struct import pack, unpack_from
from typing import ClassVar, Type

from smb.v2.header import Header, SMBv2Command
from smb.v2.messages import Message, RequestMessage, ResponseMessage
from smb.exceptions import MalformedSMBv2MessageError, MalformedSessionSetupRequestError, \
    MalformedSessionSetupResponseError
from smb.v2.structures.security_mode import SecurityMode
from smb.v2.structures.capabilities import CapabilitiesFlag
from smb.v2.structures.session_setup_request_flag import SessionSetupRequestFlag
from smb.v2.structures.session_flag import SessionFlag


@dataclass
@Message.register
class SessionSetupResponse(ResponseMessage):
    session_flags: SessionFlag
    security_buffer: bytes

    STRUCTURE_SIZE: ClassVar[int] = 9
    COMMAND: ClassVar[SMBv2Command] = SMBv2Command.SMB2_SESSION_SETUP
    MALFORMED_ERROR_CLASS: ClassVar[Type[MalformedSMBv2MessageError]] = MalformedSessionSetupResponseError

    @classmethod
    def _from_bytes_and_header(cls, data: memoryview, header: Header) -> SessionSetupResponse:
        super()._from_bytes_and_header(data=data, header=header)

        body_data: memoryview = data[len(header):]

        security_buffer_offset: int = unpack_from('<H', buffer=body_data, offset=4)[0]
        security_buffer_length: int = unpack_from('<H', buffer=body_data, offset=6)[0]

        return SessionSetupResponse(
            header=header,
            session_flags=SessionFlag(unpack_from('<H', buffer=body_data, offset=2)[0]),
            security_buffer=bytes(data[security_buffer_offset:security_buffer_offset+security_buffer_length])
        )

    # TODO: Implement.
    def __bytes__(self) -> bytes:
        ...

    # TODO: Implement.
    def __len__(self) -> int:
        ...


@dataclass
@Message.register
class SessionSetupRequest(RequestMessage):
    STRUCTURE_SIZE: ClassVar[int] = 25
    COMMAND: ClassVar[SMBv2Command] = SMBv2Command.SMB2_SESSION_SETUP
    MALFORMED_ERROR_CLASS: ClassVar[Type[MalformedSMBv2MessageError]] = MalformedSessionSetupRequestError
    RESPONSE_MESSAGE_CLASS: ClassVar[ResponseMessage] = SessionSetupResponse
    _RESERVED_CHANNEL: ClassVar[bytes] = bytes(4)

    security_mode: SecurityMode
    security_buffer: bytes
    flags: SessionSetupRequestFlag = SessionSetupRequestFlag.SMB2_SESSION_FLAG_NONE
    capabilities: CapabilitiesFlag = CapabilitiesFlag()
    previous_session_id: bytes = bytes(8)

    @classmethod
    def _from_bytes_and_header(cls, data: memoryview, header: Header) -> SessionSetupRequest:
        super()._from_bytes_and_header(data=data, header=header)

        body_data: memoryview = data[len(header):]

        if bytes(body_data[8:12]) != cls._RESERVED_CHANNEL:
            # TODO: Use proper exception.
            raise ValueError

        security_buffer_offset: int = unpack_from('<H', buffer=body_data, offset=12)[0]
        security_buffer_length: int = unpack_from('<H', buffer=body_data, offset=14)[0]

        return cls(
            header=header,
            flags=SessionSetupRequestFlag(unpack_from('<B', buffer=body_data, offset=2)[0]),
            security_mode=SecurityMode(unpack_from('<B', buffer=body_data, offset=3)[0]),
            capabilities=CapabilitiesFlag.from_int(unpack_from('<I', buffer=body_data, offset=4)[0]),
            previous_session_id=bytes(body_data[16:24]),
            security_buffer=bytes(data[security_buffer_offset:security_buffer_offset+security_buffer_length])
        )

    def __len__(self) -> int:
        return len(self.header) + 24 + len(self.security_buffer)

    def __bytes__(self) -> bytes:
        return bytes(self.header) + b''.join([
            pack('<H', 25),
            pack('<B', self.flags.value),
            pack('<B', int(self.security_mode)),
            pack('<I', int(self.capabilities)),
            self._RESERVED_CHANNEL,
            pack('<H', len(self.header) + 24),
            pack('<H', len(self.security_buffer)),
            self.previous_session_id,
            self.security_buffer
        ])
