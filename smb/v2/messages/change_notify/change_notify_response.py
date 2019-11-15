from __future__ import annotations
from dataclasses import dataclass
from typing import ClassVar, Tuple
from struct import pack as struct_pack, unpack as struct_unpack
from enum import IntEnum

from smb.smb_message import SMBResponseMessage
from smb.v2.smbv2_message import SMBv2Message, register_smbv2_message
from smb.v2.smbv2_header import SMBv2Header, SMBv2Command
from smb.exceptions import IncorrectStructureSizeError

from msdsalgs.utils import extract_elements


class FileNotifyAction(IntEnum):
    FILE_ACTION_ADDED = 0x00000001,
    FILE_ACTION_REMOVED = 0x00000002,
    FILE_ACTION_MODIFIED = 0x00000003,
    FILE_ACTION_RENAMED_OLD_NAME = 0x00000004,
    FILE_ACTION_RENAMED_NEW_NAME = 0x00000005,
    FILE_ACTION_ADDED_STREAM = 0x00000006,
    FILE_ACTION_REMOVED_STREAM = 0x00000007,
    FILE_ACTION_MODIFIED_STREAM = 0x00000008,
    FILE_ACTION_REMOVED_BY_DELETE = 0x00000009,
    FILE_ACTION_ID_NOT_TUNNELLED = 0x0000000A,
    FILE_ACTION_TUNNELLED_ID_COLLISION = 0x0000000B


@dataclass
class FileNotifyInformation:
    next_entry_offset: int
    action: FileNotifyAction
    file_name: str

    # NOTE: I defined this, not the docs.
    structure_size: ClassVar[int] = 12

    @classmethod
    def from_bytes(cls, data: bytes) -> FileNotifyInformation:

        file_name_len: int = struct_unpack('<I', data[8:12])[0]

        return cls(
            next_entry_offset=struct_unpack('<I', data[:4])[0],
            action=FileNotifyAction(struct_unpack('<I', data[4:8])[0]),
            file_name=data[12:12+file_name_len].decode(encoding='utf-16-le')
        )

    def __len__(self) -> int:
        return self.structure_size + len(self.file_name.encode(encoding='utf-16-le'))

    def __bytes__(self) -> bytes:
        file_name_bytes: bytes = self.file_name.encode(encoding='utf-16-le')
        return b''.join([
            struct_pack('<I', self.next_entry_offset),
            struct_pack('<I', self.action.value),
            struct_pack('<I', len(file_name_bytes)),
            file_name_bytes
        ])


@dataclass
@register_smbv2_message
class ChangeNotifyResponse(SMBv2Message, SMBResponseMessage):
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
