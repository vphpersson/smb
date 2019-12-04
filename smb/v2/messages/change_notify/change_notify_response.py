from __future__ import annotations
from dataclasses import dataclass
from typing import ClassVar, Tuple
from struct import pack as struct_pack, unpack as struct_unpack

from smb.v2.messages.message import SMBv2ResponseMessage, register_smbv2_message
from smb.v2.header import SMBv2Header, SMBv2Command
from smb.exceptions import IncorrectStructureSizeError

from msdsalgs.utils import extract_elements
from msdsalgs.fscc.file_notify_information import FileNotifyInformation


@dataclass
@register_smbv2_message
class ChangeNotifyResponse(SMBv2ResponseMessage):
    structure_size: ClassVar[int] = 9
    _command: ClassVar[SMBv2Command] = SMBv2Command.SMB2_CHANGE_NOTIFY

    file_notify_entries: Tuple[FileNotifyInformation, ...]

    @classmethod
    def _from_bytes_and_header(cls, data: bytes, header: SMBv2Header) -> ChangeNotifyResponse:
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
        return self.header.structure_size + (self.structure_size - 1) + sum(len(entry) for entry in self.file_notify_entries)

    def __bytes__(self) -> bytes:
        output_buffer_offset: int = self.header.structure_size + self.structure_size - 1
        output_buffer_bytes: bytes = b''.join(bytes(entry) for entry in self.file_notify_entries)

        return bytes(self.header) + b''.join([
            struct_pack('<H', self.structure_size),
            struct_pack('<H', output_buffer_offset),
            struct_pack('<I', len(output_buffer_bytes)),
            output_buffer_bytes
        ])
