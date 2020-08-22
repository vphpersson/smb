from __future__ import annotations
from dataclasses import dataclass
from typing import ClassVar, Type
from struct import pack as struct_pack

from smb.v2.messages import Message, RequestMessage, ResponseMessage
from smb.v2.header import Header, SMBv2Command
from smb.exceptions import MalformedSMBv2MessageError, MalformedTreeDisconnectRequestError, \
    MalformedTreeDisconnectResponseError


@dataclass
@Message.register
class TreeDisconnectResponse(ResponseMessage):
    STRUCTURE_SIZE: ClassVar[int] = 4
    COMMAND: ClassVar[SMBv2Command] = SMBv2Command.SMB2_TREE_DISCONNECT
    MALFORMED_ERROR_CLASS: ClassVar[Type[MalformedSMBv2MessageError]] = MalformedTreeDisconnectResponseError
    _RESERVED: ClassVar[bytes] = bytes(2)

    @classmethod
    def _from_bytes_and_header(cls, data: memoryview, header: Header) -> TreeDisconnectResponse:
        super()._from_bytes_and_header(data=data, header=header)

        return cls(header=header)

    def __bytes__(self) -> bytes:
        return bytes(self.header) + b''.join([struct_pack('<H', self.STRUCTURE_SIZE), self._RESERVED])

    def __len__(self) -> int:
        return len(self.header) + self.STRUCTURE_SIZE


@dataclass
@Message.register
class TreeDisconnectRequest(RequestMessage):
    STRUCTURE_SIZE: ClassVar[int] = 4
    COMMAND: ClassVar[SMBv2Command] = SMBv2Command.SMB2_TREE_DISCONNECT
    MALFORMED_ERROR_CLASS: ClassVar[Type[MalformedSMBv2MessageError]] = MalformedTreeDisconnectRequestError
    RESPONSE_MESSAGE_CLASS: ClassVar[ResponseMessage] = TreeDisconnectResponse
    _RESERVED: ClassVar[bytes] = bytes(2)

    @classmethod
    def _from_bytes_and_header(cls, data: memoryview, header: Header) -> TreeDisconnectRequest:
        super()._from_bytes_and_header(data=data, header=header)

        return cls(header=header)

    def __bytes__(self) -> bytes:
        return bytes(self.header) + b''.join([struct_pack('<H', self.STRUCTURE_SIZE), self._RESERVED])

    def __len__(self) -> int:
        return len(self.header) + self.STRUCTURE_SIZE
