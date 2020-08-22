from __future__ import annotations
from dataclasses import dataclass
from typing import ClassVar, Tuple, Type
from struct import pack, unpack_from

from msdsalgs.utils import extract_elements
from msdsalgs.fscc.file_notify_information import FileNotifyInformation

from smb.v2.messages import Message, RequestMessage, ResponseMessage
from smb.v2.header import Header, SMBv2Command
from smb.v2.structures.file_id import FileId
from smb.v2.structures.change_notify_flag import ChangeNotifyFlag
from smb.v2.structures.completion_filter_flag import CompletionFilterFlag
from smb.exceptions import MalformedSMBv2MessageError, MalformedChangeNotifyRequestError, \
    MalformedChangeNotifyResponseError


@dataclass
@Message.register
class ChangeNotifyResponse(ResponseMessage):
    STRUCTURE_SIZE: ClassVar[int] = 9
    COMMAND: ClassVar[SMBv2Command] = SMBv2Command.SMB2_CHANGE_NOTIFY
    MALFORMED_ERROR_CLASS: ClassVar[Type[MalformedSMBv2MessageError]] = MalformedChangeNotifyResponseError

    file_notify_entries: Tuple[FileNotifyInformation, ...]

    @classmethod
    def _from_bytes_and_header(cls, data: memoryview, header: Header) -> ChangeNotifyResponse:
        super()._from_bytes_and_header(data=data, header=header)

        body_data: memoryview = data[len(header):]

        output_buffer_offset: int = unpack_from('<H', buffer=body_data, offset=2)[0]
        output_buffer_length: int = unpack_from('<I', buffer=body_data, offset=4)[0]

        return cls(
            header=header,
            file_notify_entries=tuple(
                extract_elements(
                    data=data[output_buffer_offset:output_buffer_offset+output_buffer_length],
                    create_element=lambda data: FileNotifyInformation.from_bytes(data=data),
                    get_next_offset=lambda element: element.next_entry_offset
                )
            )
        )

    def __len__(self) -> int:
        return self.header.STRUCTURE_SIZE + (self.STRUCTURE_SIZE - 1) + sum(len(entry) for entry in self.file_notify_entries)

    def __bytes__(self) -> bytes:
        output_buffer_offset: int = self.header.STRUCTURE_SIZE + self.STRUCTURE_SIZE - 1
        output_buffer_bytes: bytes = b''.join(bytes(entry) for entry in self.file_notify_entries)

        return bytes(self.header) + b''.join([
            pack('<H', self.STRUCTURE_SIZE),
            pack('<H', output_buffer_offset),
            pack('<I', len(output_buffer_bytes)),
            output_buffer_bytes
        ])


@dataclass
@Message.register
class ChangeNotifyRequest(RequestMessage):
    STRUCTURE_SIZE: ClassVar[int] = 32
    COMMAND: ClassVar[SMBv2Command] = SMBv2Command.SMB2_CHANGE_NOTIFY
    MALFORMED_ERROR_CLASS: ClassVar[Type[MalformedSMBv2MessageError]] = MalformedChangeNotifyRequestError
    RESPONSE_MESSAGE_CLASS: ClassVar[ResponseMessage] = ChangeNotifyResponse
    _RESERVED: ClassVar[bytes] = bytes(4)

    flags: ChangeNotifyFlag
    file_id: FileId
    completion_filter: CompletionFilterFlag
    # TODO: Arbitrary value. Reconsider.
    output_buffer_length: int = 8192

    @classmethod
    def _from_bytes_and_header(cls, data: memoryview, header: Header) -> SMBv2Message:
        super()._from_bytes_and_header(data=data, header=header)

        body_data: memoryview = data[len(header):]

        if bytes(body_data[28:32]) != cls._RESERVED:
            # TODO: Use proper exception.
            raise ValueError

        return cls(
            header=header,
            flags=ChangeNotifyFlag.from_int(pack('<H', body_data[2:4])),
            output_buffer_length=unpack_from('<I', buffer=body_data, offset=4)[0],
            file_id=FileId.from_bytes(data=body_data, base_offset=8),
            completion_filter=CompletionFilterFlag.from_int(unpack_from('<I', buffer=body_data, offset=24)[0])
        )

    def __bytes__(self):
        return bytes(self.header) + b''.join([
            pack('<H', self.STRUCTURE_SIZE),
            pack('<H', int(self.flags)),
            pack('<I', self.output_buffer_length),
            bytes(self.file_id),
            pack('<I', int(self.completion_filter)),
            self._RESERVED
        ])

    def __len__(self) -> int:
        return self.header.STRUCTURE_SIZE + self.STRUCTURE_SIZE
