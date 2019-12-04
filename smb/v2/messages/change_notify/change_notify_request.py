from __future__ import annotations
from dataclasses import dataclass
from typing import ClassVar
from struct import pack as struct_pack, unpack as struct_unpack
from enum import IntFlag

from smb.v2.messages.message import SMBv2RequestMessage, register_smbv2_message
from smb.v2.header import SMBv2Header, SMBv2Command
from smb.v2.file_id import FileId
from smb.exceptions import IncorrectStructureSizeError

from msdsalgs.utils import make_mask_class


class CompletionFilterFlagMask(IntFlag):
    FILE_NOTIFY_CHANGE_FILE_NAME = 0x00000001,
    FILE_NOTIFY_CHANGE_DIR_NAME = 0x00000002,
    FILE_NOTIFY_CHANGE_ATTRIBUTES = 0x00000004,
    FILE_NOTIFY_CHANGE_SIZE = 0x00000008,
    FILE_NOTIFY_CHANGE_LAST_WRITE = 0x00000010,
    FILE_NOTIFY_CHANGE_LAST_ACCESS = 0x00000020,
    FILE_NOTIFY_CHANGE_CREATION = 0x00000040,
    FILE_NOTIFY_CHANGE_EA = 0x00000080,
    FILE_NOTIFY_CHANGE_SECURITY = 0x00000100,
    FILE_NOTIFY_CHANGE_STREAM_NAME = 0x00000200,
    FILE_NOTIFY_CHANGE_STREAM_SIZE = 0x00000400,
    FILE_NOTIFY_CHANGE_STREAM_WRITE = 0x00000800


CompletionFilterFlag = make_mask_class(CompletionFilterFlagMask, prefix='FILE_NOTIFY_CHANGE_')


class ChangeNotifyFlagMask(IntFlag):
    SMB2_WATCH_TREE = 0x0001


ChangeNotifyFlag = make_mask_class(ChangeNotifyFlagMask, prefix='SMB2_')


@dataclass
@register_smbv2_message
class ChangeNotifyRequest(SMBv2RequestMessage):

    structure_size: ClassVar[int] = 32
    _command: ClassVar[SMBv2Command] = SMBv2Command.SMB2_CHANGE_NOTIFY
    _reserved: ClassVar[bytes] = bytes(4)

    flags: ChangeNotifyFlag
    file_id: FileId
    completion_filter: CompletionFilterFlag
    # TODO: Arbitrary value. Reconsider.
    output_buffer_length: int = 8192

    @classmethod
    def _from_bytes_and_header(cls, data: bytes, header: SMBv2Header) -> SMBv2Message:
        body_data: bytes = data[len(header):]

        try:
            cls.check_structure_size(structure_size_to_test=struct_unpack('<H', body_data[:2])[0])
        except IncorrectStructureSizeError as e:
            ...

        if body_data[28:32] != cls._reserved:
            # TODO: Use proper exception.
            raise ValueError

        return cls(
            header=header,
            flags=ChangeNotifyFlag.from_mask(struct_pack('<H', body_data[2:4])),
            output_buffer_length=struct_unpack('<I', body_data[4:8])[0],
            file_id=FileId.from_bytes(data=body_data[8:24]),
            completion_filter=CompletionFilterFlag.from_mask(struct_unpack('<I', body_data[24:28])[0])
        )

    def __bytes__(self):
        return bytes(self.header) + b''.join([
            struct_pack('<H', self.structure_size),
            struct_pack('<H', self.flags.to_mask()),
            struct_pack('<I', self.output_buffer_length),
            bytes(self.file_id),
            struct_pack('<I', self.completion_filter.to_mask()),
            self._reserved
        ])

    def __len__(self) -> int:
        return self.header.structure_size + self.structure_size
