from __future__ import annotations
from dataclasses import dataclass
from typing import ClassVar, Union, Optional
from struct import pack as struct_pack, unpack as struct_unpack, error as struct_error
from pathlib import PureWindowsPath
from math import ceil
from datetime import datetime

from msdsalgs.fscc.file_attributes import FileAttributes
from msdsalgs.time import filetime_to_datetime

from smb.v2.messages import RequestMessage, ResponseMessage, register_smbv2_message
from smb.v2.header import Header, SMBv2Command, SMB311SyncRequestHeader, SMB311AsyncHeader
from smb.exceptions import IncorrectStructureSizeError, MalformedCreateRequestError, \
    NonEmptySecurityFlagsError, NonEmptySmbCreateFlagsError, InvalidCreateDesiredAccessValueError, \
    InvalidCreateDispositionValueError, InvalidCreateFileAttributesValueError, \
    InvalidCreateImpersonationLevelValueError, InvalidCreateOplockLevelValueError, \
    InvalidCreateOptionsValueError, InvalidCreateShareAccessValueError, NonEmptyCreateReservedError, \
    InvalidCreateNameError, MalformedCreateResponseError, \
    InvalidCreateResponseOplockLevelError, InvalidCreateResponseFlagError, InvalidCreateResponseActionError, \
    InvalidCreateResponseFileAttributesError
from smb.v2.structures.access_mask import FilePipePrinterAccessMask, DirectoryAccessMask
from smb.v2.structures.oplock_level import OplockLevel
from smb.v2.structures.impersonation_level import ImpersonationLevel
from smb.v2.structures.share_access import ShareAccess
from smb.v2.structures.create_disposition import CreateDisposition
from smb.v2.structures.create_options import CreateOptions
from smb.v2.structures.create_context import CreateContextList
from smb.v2.structures.create_flag import CreateFlag
from smb.v2.structures.create_action import CreateAction
from smb.v2.structures.file_id import FileId


@dataclass
@register_smbv2_message
class CreateRequest(RequestMessage):
    STRUCTURE_SIZE: ClassVar[int] = 57
    _COMMAND: ClassVar[SMBv2Command] = SMBv2Command.SMB2_CREATE
    _RESERVED: ClassVar[bytes] = 8 * b'\x00'

    # TODO: What are `security_flags` and `smb_create_flags` class vars?
    security_flags: ClassVar[int] = 0
    smb_create_flags: ClassVar[bytes] = bytes(8)

    requested_oplock_level: OplockLevel
    impersonation_level: ImpersonationLevel
    desired_access: Union[FilePipePrinterAccessMask, DirectoryAccessMask]
    file_attributes: FileAttributes
    share_access: ShareAccess
    create_disposition: CreateDisposition
    create_options: CreateOptions
    name: str
    create_context_list: CreateContextList

    @property
    def name_path(self) -> PureWindowsPath:
        return PureWindowsPath(self.name)

    @classmethod
    def _from_bytes_and_header(cls, data: bytes, header: Header) -> SMBv2Message:

        body_data: bytes = data[len(header):]

        try:
            cls.check_structure_size(structure_size_to_test=struct_unpack('<H', body_data[:2])[0])
        except IncorrectStructureSizeError as e:
            raise MalformedCreateRequestError(str(e)) from e

        security_flags_value = body_data[2]
        if security_flags_value != 0x00:
            raise NonEmptySecurityFlagsError(observed_security_flags_value=security_flags_value)

        try:
            requested_oplock_level = OplockLevel(body_data[3])
        except ValueError as e:
            raise InvalidCreateOplockLevelValueError from e

        try:
            impersonation_level = ImpersonationLevel(struct_unpack('<I', body_data[4:8])[0])
        except (ValueError, struct_error) as e:
            raise InvalidCreateImpersonationLevelValueError from e

        smb_create_flags = body_data[8:16]
        if smb_create_flags != cls.smb_create_flags:
            raise NonEmptySmbCreateFlagsError(observed_smb_create_flags_value=smb_create_flags)

        reserved = body_data[16:24]
        if reserved != cls._RESERVED:
            raise NonEmptyCreateReservedError(observed_reserved_value=reserved)

        try:
            file_attributes = FileAttributes.from_int(struct_unpack('<I', body_data[28:32])[0])
        except (ValueError, struct_error) as e:
            raise InvalidCreateFileAttributesValueError from e

        try:
            share_access = ShareAccess.from_int(struct_unpack('<I', body_data[32:36])[0])
        except (ValueError, struct_error) as e:
            raise InvalidCreateShareAccessValueError from e

        try:
            create_disposition = CreateDisposition(struct_unpack('<I', body_data[36:40])[0])
        except (ValueError, struct_error) as e:
            raise InvalidCreateDispositionValueError from e

        try:
            create_options = CreateOptions.from_int(struct_unpack('<I', body_data[40:44])[0])
        except (ValueError, struct_error) as e:
            raise InvalidCreateOptionsValueError from e

        try:
            desired_access: Union[DirectoryAccessMask, FilePipePrinterAccessMask] = (
                DirectoryAccessMask if create_options.directory_file else FilePipePrinterAccessMask
            ).from_int(struct_unpack('<I', body_data[24:28])[0])
        except (ValueError, struct_error) as e:
            raise InvalidCreateDesiredAccessValueError from e

        try:
            name_offset: int = struct_unpack('<H', body_data[44:46])[0]
            name_length: int = struct_unpack('<H', body_data[46:48])[0]
            name: str = data[name_offset:name_offset+name_length].decode('utf-16-le')
        except (SyntaxError, struct_error) as e:
            raise InvalidCreateNameError from e

        create_context_offset: int = struct_unpack('<I', data[48:52])[0]
        create_context_length: int = struct_unpack('<I', data[52:56])[0]

        create_context_list: Optional[CreateContextList] = CreateContextList.from_bytes(
            data=data[create_context_offset:create_context_offset+create_context_length]
        ) if create_context_offset != 0 else CreateContextList()

        return cls(
            header=header,
            requested_oplock_level=requested_oplock_level,
            impersonation_level=impersonation_level,
            desired_access=desired_access,
            file_attributes=file_attributes,
            share_access=share_access,
            create_disposition=create_disposition,
            create_options=create_options,
            name=name,
            create_context_list=create_context_list
        )

    def __bytes__(self) -> bytes:
        current_buffer_offset = len(self.header) + (self.STRUCTURE_SIZE - 1)

        name_bytes = self.name.encode(encoding='utf-16-le')
        name_len: int = len(name_bytes)
        num_name_padding = int(ceil(name_len / 8)) * 8 - name_len
        name_offset = current_buffer_offset
        current_buffer_offset += name_len + num_name_padding

        create_contexts_bytes = bytes(self.create_context_list) if self.create_context_list is not None else b''
        create_contexts_len = len(create_contexts_bytes)
        create_contexts_offset = current_buffer_offset if create_contexts_bytes else 0

        return bytes(self.header) + b''.join([
            struct_pack('<H', self.STRUCTURE_SIZE),
            struct_pack('<B', self.security_flags),
            struct_pack('<B', self.requested_oplock_level.value),
            struct_pack('<I', self.impersonation_level.value),
            self.smb_create_flags,
            self._RESERVED,
            struct_pack('<I', int(self.desired_access)),
            struct_pack('<I', int(self.file_attributes)),
            struct_pack('<I', int(self.share_access)),
            struct_pack('<I', self.create_disposition),
            struct_pack('<I', int(self.create_options)),
            struct_pack('<H', name_offset),
            struct_pack('<H', name_len),
            struct_pack('<I', create_contexts_offset),
            struct_pack('<I', create_contexts_len),
            name_bytes or b'\x00',
            num_name_padding * b'\x00',
            create_contexts_bytes
        ])

    def __len__(self) -> int:
        name_bytes = self.name.encode(encoding='utf-16-le')
        name_len: int = len(name_bytes)
        num_name_padding = int(ceil(name_len / 8)) * 8 - name_len

        # NOTE: "the Buffer field MUST be at least one byte in length"
        return sum([
            len(self.header),
            self.STRUCTURE_SIZE - 1,
            name_len or 1,
            num_name_padding,
            self.create_context_list.bytes_len()
        ])


@dataclass
@register_smbv2_message
class CreateResponse(ResponseMessage):
    STRUCTURE_SIZE: ClassVar[int] = 89
    _COMMAND: ClassVar[SMBv2Command] = SMBv2Command.SMB2_CREATE
    _RESERVED_2: ClassVar[bytes] = 4 * b'\x00'

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
    def _from_bytes_and_header(cls, data: bytes, header: Header) -> CreateResponse:

        body_data: bytes = data[len(header):]

        try:
            cls.check_structure_size(structure_size_to_test=struct_unpack('<H', body_data[:2])[0])
        except IncorrectStructureSizeError as e:
            raise MalformedCreateResponseError(str(e)) from e

        try:
            oplock_level = OplockLevel(body_data[2])
        except ValueError as e:
            raise InvalidCreateResponseOplockLevelError from e

        if isinstance(header, (SMB311SyncRequestHeader, SMB311AsyncHeader)):
            try:
                flags = CreateFlag.from_int(body_data[3])
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
            file_attributes = FileAttributes.from_int(struct_unpack('<I', body_data[56:60])[0])
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
            struct_pack('<H', self.STRUCTURE_SIZE),
            struct_pack('<B', self.oplock_level.value),
            struct_pack('<B', self.flags) if self.flags is not None else b'\x00',
            struct_pack('<I', self.create_action.value),
            struct_pack('<Q', self._creation_time),
            struct_pack('<Q', self._last_access_time),
            struct_pack('<Q', self._last_write_time),
            struct_pack('<Q', self._change_time),
            struct_pack('<Q', self.allocation_size),
            struct_pack('<Q', self.endof_file),
            struct_pack('<I', int(self.file_attributes)),
            self._RESERVED_2,
            bytes(self.file_id),
            struct_pack('<I', self.STRUCTURE_SIZE - 2),
            struct_pack('<I', create_contexts_len),
            create_contexts_bytes
        ])

    def __len__(self) -> int:
        return len(self.header) + (self.STRUCTURE_SIZE - 1) + self.create_contexts.bytes_len()
