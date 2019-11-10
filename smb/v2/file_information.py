from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime
from struct import pack as struct_pack, unpack as struct_unpack
from typing import ClassVar

from smb.v2.messages.create.create_request import FileAttributes

from msdsalgs.time import filetime_to_datetime


@dataclass
class FileInformation:
    _creation_time: int
    _last_access_time: int
    _last_write_time: int
    _change_time: int
    allocation_size: int
    endof_file: int
    file_attributes: FileAttributes

    structure_size: ClassVar[int] = 52

    @property
    def creation_time(self) -> datetime:
        return filetime_to_datetime(filetime=self._creation_time)

    @property
    def last_access_time(self) -> datetime:
        return filetime_to_datetime(filetime=self._last_access_time)

    @property
    def last_write_time(self) -> datetime:
        return filetime_to_datetime(filetime=self._last_write_time)

    @property
    def change_time(self) -> datetime:
        return filetime_to_datetime(filetime=self._change_time)

    @classmethod
    def from_bytes(cls, data: bytes) -> FileInformation:
        return cls(
            _creation_time=struct_unpack('<Q', data[:8])[0],
            _last_access_time=struct_unpack('<Q', data[8:16])[0],
            _last_write_time=struct_unpack('<Q', data[16:24])[0],
            _change_time=struct_unpack('<Q', data[24:32])[0],
            allocation_size=struct_unpack('<Q', data[32:40])[0],
            endof_file=struct_unpack('<Q', data[40:48])[0],
            file_attributes=FileAttributes.from_mask(struct_unpack('<I', data[48:56])[0])
        )

    def __bytes__(self) -> bytes:
        return b''.join([
            struct_pack('<Q', self._creation_time),
            struct_pack('<Q', self._last_access_time),
            struct_pack('<Q', self._last_write_time),
            struct_pack('<Q', self._change_time),
            struct_pack('<Q', self.allocation_size),
            struct_pack('<Q', self.endof_file),
            struct_pack('<I', self.file_attributes.to_mask())
        ])

    def __len__(self) -> int:
        return self.structure_size
