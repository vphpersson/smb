from __future__ import annotations
from dataclasses import dataclass
from typing import ClassVar, Type
from struct import pack

from smb.v2.messages import Message, RequestMessage, ResponseMessage
from smb.v2.header import Header, SMBv2Command
from smb.exceptions import MalformedLogoffRequestError, MalformedLogoffResponseError, \
    MalformedSMBv2MessageError


@dataclass
@Message.register
class LogoffResponse(ResponseMessage):
    STRUCTURE_SIZE: ClassVar[int] = 4
    COMMAND: ClassVar[SMBv2Command] = SMBv2Command.SMB2_LOGOFF
    MALFORMED_ERROR_CLASS: ClassVar[Type[MalformedSMBv2MessageError]] = MalformedLogoffResponseError
    _RESERVED: ClassVar[int] = bytes(2)

    @classmethod
    def _from_bytes_and_header(cls, data: memoryview, header: Header) -> LogoffResponse:
        super()._from_bytes_and_header(data=data, header=header)

        return cls(header=header)

    def __bytes__(self) -> bytes:
        return bytes(self.header) + b''.join([pack('<H', self.STRUCTURE_SIZE), self._RESERVED])

    def __len__(self) -> int:
        return len(self.header) + self.STRUCTURE_SIZE


@dataclass
@Message.register
class LogoffRequest(RequestMessage):
    STRUCTURE_SIZE: ClassVar[int] = 4
    COMMAND: ClassVar[SMBv2Command] = SMBv2Command.SMB2_LOGOFF
    MALFORMED_ERROR_CLASS: ClassVar[Type[MalformedSMBv2MessageError]] = MalformedLogoffRequestError
    RESPONSE_MESSAGE_CLASS: ClassVar[ResponseMessage] = LogoffResponse
    _RESERVED: ClassVar[int] = bytes(2)

    @classmethod
    def _from_bytes_and_header(cls, data: memoryview, header: Header) -> LogoffRequest:
        super()._from_bytes_and_header(data=data, header=header)

        return cls(header=header)

    def __bytes__(self) -> bytes:
        return bytes(self.header) + b''.join([pack('<H', self.STRUCTURE_SIZE), self._RESERVED])

    def __len__(self) -> int:
        return len(self.header) + self.STRUCTURE_SIZE
