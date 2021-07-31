from __future__ import annotations
from dataclasses import dataclass
from typing import ClassVar, Union, Optional, Type
from struct import pack, error as struct_error, unpack_from
from pathlib import PureWindowsPath
from math import ceil
from datetime import datetime
from functools import partial

from msdsalgs.fscc.file_attributes import FileAttributes
from msdsalgs.time import filetime_to_datetime

from smb.v2.messages import Message, RequestMessage, ResponseMessage
from smb.v2.header import Header, SMBv2Command, SMB311SyncRequestHeader, SMB311AsyncHeader
from smb.exceptions import MalformedCreateRequestError, \
    NonEmptySecurityFlagsError, NonEmptySmbCreateFlagsError, InvalidCreateDesiredAccessValueError, \
    InvalidCreateDispositionValueError, InvalidCreateFileAttributesValueError, \
    InvalidCreateImpersonationLevelValueError, InvalidCreateOplockLevelValueError, \
    InvalidCreateOptionsValueError, InvalidCreateShareAccessValueError, NonEmptyCreateReservedError, \
    InvalidCreateNameError, MalformedCreateResponseError, \
    InvalidCreateResponseOplockLevelError, InvalidCreateResponseFlagError, InvalidCreateResponseActionError, \
    InvalidCreateResponseFileAttributesError, MalformedSMBv2MessageError
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
@Message.register
class CreateResponse(ResponseMessage):
    STRUCTURE_SIZE: ClassVar[int] = 89
    COMMAND: ClassVar[SMBv2Command] = SMBv2Command.SMB2_CREATE
    MALFORMED_ERROR_CLASS: ClassVar[Type[MalformedSMBv2MessageError]] = MalformedCreateResponseError
    _RESERVED_FLAG_VALUE: ClassVar[int] = 0x00
    _RESERVED_2: ClassVar[bytes] = bytes(4)

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
    def _from_bytes_and_header(cls, data: memoryview, header: Header) -> CreateResponse:
        super()._from_bytes_and_header(data=data, header=header)

        body_data: memoryview = data[len(header):]

        partial_unpack_from = partial(unpack_from, buffer=body_data)

        try:
            oplock_level = OplockLevel(body_data[2])
        except ValueError as e:
            raise InvalidCreateResponseOplockLevelError from e

        #  "If the server implements the SMB 3.x dialect family, this field MUST be constructed using the following
        #  value. Otherwise, this field MUST NOT be used and MUST be reserved."
        try:
            flags = CreateFlag.from_int(body_data[3]) if body_data[3] != cls._RESERVED_FLAG_VALUE else None
        except ValueError as e:
            raise InvalidCreateResponseFlagError(
                observed_create_response_flag_value=body_data[3],
                expected_response_flag_values=[cls._RESERVED_FLAG_VALUE] + list(CreateFlag)
            ) from e

        raw_create_action_value: int = partial_unpack_from('<I', offset=4)[0]
        try:
            create_action = CreateAction(raw_create_action_value)
        except ValueError as e:
            raise InvalidCreateResponseActionError(
                observed_create_action_value=raw_create_action_value,
                expected_create_action_values=list(CreateAction)
            ) from e

        raw_file_attributes_value: int = partial_unpack_from('<I', offset=56)[0]
        try:
            file_attributes = FileAttributes.from_int(value=raw_file_attributes_value)
        except ValueError as e:
            raise InvalidCreateResponseFileAttributesError(
                observed_file_attributes_value=raw_file_attributes_value,
                expected_file_attribute_values=list(FileAttributes.INT_FLAG_CLASS)
            ) from e

        # Client should ignore value of `Reserved2`?

        create_context_offset: int = partial_unpack_from('<I', offset=80)[0]
        create_context_length: int = partial_unpack_from('<I', offset=84)[0]

        return cls(
            header=header,
            oplock_level=oplock_level,
            flags=flags,
            create_action=create_action,
            _creation_time=partial_unpack_from('<Q', offset=8)[0],
            _last_access_time=partial_unpack_from('<Q', offset=16)[0],
            _last_write_time=partial_unpack_from('<Q', offset=24)[0],
            _change_time=partial_unpack_from('<Q', offset=32)[0],
            allocation_size=partial_unpack_from('<Q', offset=40)[0],
            endof_file=partial_unpack_from('<Q', offset=48)[0],
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
            pack('<H', self.STRUCTURE_SIZE),
            pack('<B', self.oplock_level.value),
            pack('<B', self.flags) if self.flags is not None else b'\x00',
            pack('<I', self.create_action.value),
            pack('<Q', self._creation_time),
            pack('<Q', self._last_access_time),
            pack('<Q', self._last_write_time),
            pack('<Q', self._change_time),
            pack('<Q', self.allocation_size),
            pack('<Q', self.endof_file),
            pack('<I', int(self.file_attributes)),
            self._RESERVED_2,
            bytes(self.file_id),
            pack('<I', self.STRUCTURE_SIZE - 2),
            pack('<I', create_contexts_len),
            create_contexts_bytes
        ])

    def __len__(self) -> int:
        return len(self.header) + (self.STRUCTURE_SIZE - 1) + self.create_contexts.bytes_len()


@dataclass
@Message.register
class CreateRequest(RequestMessage):
    STRUCTURE_SIZE: ClassVar[int] = 57
    COMMAND: ClassVar[SMBv2Command] = SMBv2Command.SMB2_CREATE
    MALFORMED_ERROR_CLASS: ClassVar[Type[MalformedSMBv2MessageError]] = MalformedCreateRequestError
    RESPONSE_MESSAGE_CLASS: ClassVar[ResponseMessage] = CreateResponse
    _RESERVED: ClassVar[bytes] = bytes(8)
    _RESERVED_SECURITY_FLAGS: ClassVar[int] = 0
    _REVERSED_CREATE_FLAGS: ClassVar[bytes] = bytes(8)

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
    def _from_bytes_and_header(cls, data: memoryview, header: Header) -> SMBv2Message:

        body_data: memoryview = data[len(header):]

        if (security_flags_value := body_data[2]) != 0x00:
            raise NonEmptySecurityFlagsError(observed_security_flags_value=security_flags_value)

        try:
            requested_oplock_level = OplockLevel(body_data[3])
        except ValueError as e:
            raise InvalidCreateOplockLevelValueError from e

        try:
            impersonation_level = ImpersonationLevel(unpack_from('<I', buffer=body_data, offset=4)[0])
        except (ValueError, struct_error) as e:
            raise InvalidCreateImpersonationLevelValueError from e

        if (smb_create_flags := body_data[8:16]) != cls._REVERSED_CREATE_FLAGS:
            raise NonEmptySmbCreateFlagsError(observed_smb_create_flags_value=smb_create_flags)

        if (reserved := body_data[16:24]) != cls._RESERVED:
            raise NonEmptyCreateReservedError(observed_reserved_value=reserved)

        try:
            file_attributes = FileAttributes.from_int(unpack_from('<I', buffer=body_data, offset=28)[0])
        except (ValueError, struct_error) as e:
            raise InvalidCreateFileAttributesValueError from e

        try:
            share_access = ShareAccess.from_int(unpack_from('<I', buffer=body_data, offset=32)[0])
        except (ValueError, struct_error) as e:
            raise InvalidCreateShareAccessValueError from e

        try:
            create_disposition = CreateDisposition(unpack_from('<I', buffer=body_data, offset=36)[0])
        except (ValueError, struct_error) as e:
            raise InvalidCreateDispositionValueError from e

        try:
            create_options = CreateOptions.from_int(unpack_from('<I', buffer=body_data, offset=40)[0])
        except (ValueError, struct_error) as e:
            raise InvalidCreateOptionsValueError from e

        try:
            desired_access: Union[DirectoryAccessMask, FilePipePrinterAccessMask] = (
                DirectoryAccessMask if create_options.directory_file else FilePipePrinterAccessMask
            ).from_int(unpack_from('<I', buffer=body_data, offset=24)[0])
        except (ValueError, struct_error) as e:
            raise InvalidCreateDesiredAccessValueError from e

        try:
            name_offset: int = unpack_from('<H', buffer=body_data, offset=44)[0]
            name_length: int = unpack_from('<H', buffer=body_data, offset=46)[0]
            name: str = bytes(data[name_offset:name_offset+name_length]).decode(encoding='utf-16-le')
        except (SyntaxError, struct_error) as e:
            raise InvalidCreateNameError from e

        create_context_offset: int = unpack_from('<I', buffer=data, offset=48)[0]
        create_context_length: int = unpack_from('<I', buffer=data, offset=52)[0]

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
            pack('<H', self.STRUCTURE_SIZE),
            pack('<B', self._RESERVED_SECURITY_FLAGS),
            pack('<B', self.requested_oplock_level.value),
            pack('<I', self.impersonation_level.value),
            self._REVERSED_CREATE_FLAGS,
            self._RESERVED,
            pack('<I', int(self.desired_access)),
            pack('<I', int(self.file_attributes)),
            pack('<I', int(self.share_access)),
            pack('<I', self.create_disposition),
            pack('<I', int(self.create_options)),
            pack('<H', name_offset),
            pack('<H', name_len),
            pack('<I', create_contexts_offset),
            pack('<I', create_contexts_len),
            name_bytes or b'\x00',
            bytes(num_name_padding),
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
