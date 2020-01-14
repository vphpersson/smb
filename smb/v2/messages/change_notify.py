from __future__ import annotations
from dataclasses import dataclass
from typing import ClassVar, Tuple
from struct import pack as struct_pack, unpack as struct_unpack

from msdsalgs.utils import extract_elements
from msdsalgs.fscc.file_notify_information import FileNotifyInformation

from smb.v2.messages import RequestMessage, ResponseMessage, register_smbv2_message
from smb.v2.header import Header, SMBv2Command
from smb.exceptions import IncorrectStructureSizeError
from smb.v2.structures.file_id import FileId
from smb.v2.structures.change_notify_flag import ChangeNotifyFlag
from smb.v2.structures.completion_filter_flag import CompletionFilterFlag


@dataclass
@register_smbv2_message
class ChangeNotifyRequest(RequestMessage):

    STRUCTURE_SIZE: ClassVar[int] = 32
    _COMMAND: ClassVar[SMBv2Command] = SMBv2Command.SMB2_CHANGE_NOTIFY
    _RESERVED: ClassVar[bytes] = bytes(4)

    flags: ChangeNotifyFlag
    file_id: FileId
    completion_filter: CompletionFilterFlag
    # TODO: Arbitrary value. Reconsider.
    output_buffer_length: int = 8192

    @classmethod
    def _from_bytes_and_header(cls, data: bytes, header: Header) -> SMBv2Message:
        body_data: bytes = data[len(header):]

        try:
            cls.check_structure_size(structure_size_to_test=struct_unpack('<H', body_data[:2])[0])
        except IncorrectStructureSizeError as e:
            ...

        if body_data[28:32] != cls._RESERVED:
            # TODO: Use proper exception.
            raise ValueError

        return cls(
            header=header,
            flags=ChangeNotifyFlag.from_int(struct_pack('<H', body_data[2:4])),
            output_buffer_length=struct_unpack('<I', body_data[4:8])[0],
            file_id=FileId.from_bytes(data=body_data[8:24]),
            completion_filter=CompletionFilterFlag.from_int(struct_unpack('<I', body_data[24:28])[0])
        )

    def __bytes__(self):
        return bytes(self.header) + b''.join([
            struct_pack('<H', self.STRUCTURE_SIZE),
            struct_pack('<H', int(self.flags)),
            struct_pack('<I', self.output_buffer_length),
            bytes(self.file_id),
            struct_pack('<I', int(self.completion_filter)),
            self._RESERVED
        ])

    def __len__(self) -> int:
        return self.header.STRUCTURE_SIZE + self.STRUCTURE_SIZE


@dataclass
@register_smbv2_message
class ChangeNotifyResponse(ResponseMessage):
    STRUCTURE_SIZE: ClassVar[int] = 9
    _COMMAND: ClassVar[SMBv2Command] = SMBv2Command.SMB2_CHANGE_NOTIFY

    file_notify_entries: Tuple[FileNotifyInformation, ...]

    @classmethod
    def _from_bytes_and_header(cls, data: bytes, header: Header) -> ChangeNotifyResponse:
        body_data: bytes = data[len(header):]

        try:
            cls.check_structure_size(structure_size_to_test=struct_unpack('<H', body_data[:2])[0])
        except IncorrectStructureSizeError as e:
            ...

        output_buffer_offset: int = struct_unpack('<H', body_data[2:4])[0]
        output_buffer_length: int = struct_unpack('<I', body_data[4:8])[0]

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
            struct_pack('<H', self.STRUCTURE_SIZE),
            struct_pack('<H', output_buffer_offset),
            struct_pack('<I', len(output_buffer_bytes)),
            output_buffer_bytes
        ])
