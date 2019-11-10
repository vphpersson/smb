from __future__ import annotations
from dataclasses import dataclass
from typing import ClassVar, Optional
from enum import IntEnum, IntFlag
from datetime import datetime
from struct import unpack as struct_unpack, pack as struct_pack

from smb.v2.smbv2_message import SMBv2Message
from smb.v2.smbv2_header import SMBv2Header, SMB311SyncHeader, SMB311AsyncHeader
from smb.v2.messages.create.create_context import CreateContextList
from smb.v2.messages.create.create_request import OplockLevel, FileAttributes
from smb.v2.file_id import FileId
from smb.exceptions import IncorrectStructureSizeError, MalformedCreateResponseError, \
    InvalidCreateResponseOplockLevelError, InvalidCreateResponseFlagError, InvalidCreateResponseActionError, \
    InvalidCreateResponseFileAttributesError

from msdsalgs.time import filetime_to_datetime
from msdsalgs.utils import make_mask_class


class CreateAction(IntEnum):
    FILE_SUPERSEDED = 0x00000000,
    FILE_OPENED = 0x00000001,
    FILE_CREATED = 0x00000002,
    FILE_OVERWRITTEN = 0x00000003


class CreateFlagMask(IntFlag):
    SMB2_CREATE_FLAG_REPARSEPOINT = 0x01


CreateFlag = make_mask_class(CreateFlagMask, prefix='SMB_CREATE_FLAG_')


@dataclass
class CreateResponse(SMBv2Message):
    oplock_level: OplockLevel
    flags: Optional[CreateFlag]
    create_action: CreateAction
    _creation_time: int
    _last_access_time: int
    _last_write_time: int
    _change_time: int
    allocation_size: int
    endof_file: int
    file_attributes: FileAttributes
    file_id: FileId
    create_contexts: CreateContextList

    structure_size: ClassVar[int] = 89
    _reserved_2: ClassVar[bytes] = 4 * b'\x00'

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
    def from_bytes_and_header(cls, data: bytes, header: SMBv2Header) -> CreateResponse:

        body_data: bytes = data[len(header):]

        try:
            cls.check_structure_size(structure_size_to_test=struct_unpack('<H', body_data[:2])[0])
        except IncorrectStructureSizeError as e:
            raise MalformedCreateResponseError(str(e)) from e

        try:
            oplock_level = OplockLevel(body_data[2])
        except ValueError as e:
            raise InvalidCreateResponseOplockLevelError from e

        if isinstance(header, (SMB311SyncHeader, SMB311AsyncHeader)):
            try:
                flags = CreateFlag.from_mask(body_data[3])
            except ValueError as e:
                raise InvalidCreateResponseFlagError from e
        elif body_data[3] != 0x00:
            # TODO: Hm.
            raise InvalidCreateResponseFlagError
        else:
            flags = None

        try:
            create_action = CreateAction(struct_unpack('<I', body_data[4:8])[0])
        except ValueError as e:
            raise InvalidCreateResponseActionError from e

        try:
            file_attributes = FileAttributes.from_mask(struct_unpack('<I', body_data[56:60])[0])
        except ValueError as e:
            raise InvalidCreateResponseFileAttributesError from e

        # Client should ignore value of `Reserved2`?

        create_context_offset: int = struct_unpack('<I', body_data[80:84])[0]
        create_context_length: int = struct_unpack('<I', body_data[84:88])[0]

        return cls(
            header=header,
            oplock_level=oplock_level,
            flags=flags,
            create_action=create_action,
            _creation_time=struct_unpack('<Q', body_data[8:16])[0],
            _last_access_time=struct_unpack('<Q', body_data[16:24])[0],
            _last_write_time=struct_unpack('<Q', body_data[24:32])[0],
            _change_time=struct_unpack('<Q', body_data[32:40])[0],
            allocation_size=struct_unpack('<Q', body_data[40:48])[0],
            endof_file=struct_unpack('<Q', body_data[48:56])[0],
            file_attributes=file_attributes,
            file_id=FileId.from_bytes(data=body_data[64:80]),
            create_contexts=CreateContextList.from_bytes(
                data=data[create_context_offset:create_context_offset+create_context_length]
            ) if create_context_offset != 0 else CreateContextList()
        )

    def __bytes__(self) -> bytes:
        create_contexts_bytes = bytes(self.create_contexts)
        create_contexts_len: int = len(create_contexts_bytes)

        return bytes(self.header) + b''.join([
            struct_pack('<H', self.structure_size),
            struct_pack('<B', self.oplock_level.value),
            struct_pack('<B', self.flags) if self.flags is not None else b'\x00',
            struct_pack('<I', self.create_action.value),
            struct_pack('<Q', self._creation_time),
            struct_pack('<Q', self._last_access_time),
            struct_pack('<Q', self._last_write_time),
            struct_pack('<Q', self._change_time),
            struct_pack('<Q', self.allocation_size),
            struct_pack('<Q', self.endof_file),
            struct_pack('<I', self.file_attributes.to_mask()),
            self._reserved_2,
            bytes(self.file_id),
            struct_pack('<I', self.structure_size - 2),
            struct_pack('<I', create_contexts_len),
            create_contexts_bytes
        ])

    def __len__(self) -> int:
        return len(self.header) + (self.structure_size - 1) + self.create_contexts.bytes_len()
