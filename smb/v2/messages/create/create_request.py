from __future__ import annotations
from dataclasses import dataclass
from typing import ClassVar, Union, Optional
from struct import pack as struct_pack, unpack as struct_unpack, error as struct_error
from enum import IntEnum, IntFlag
from pathlib import PureWindowsPath
from math import ceil

from msdsalgs.utils import make_mask_class

from smb.v2.smbv2_message import SMBv2RequestMessage, register_smbv2_message
from smb.v2.smbv2_header import SMBv2Header, SMBv2Command
from smb.exceptions import IncorrectStructureSizeError, MalformedCreateRequestError, \
    NonEmptySecurityFlagsError, NonEmptySmbCreateFlagsError, InvalidCreateDesiredAccessValueError, \
    InvalidCreateDispositionValueError, InvalidCreateFileAttributesValueError, \
    InvalidCreateImpersonationLevelValueError, InvalidCreateOplockLevelValueError, \
    InvalidCreateOptionsValueError, InvalidCreateShareAccessValueError, NonEmptyCreateReservedError, \
    InvalidCreateNameError
from smb.v2.access_mask import FilePipePrinterAccessMask, DirectoryAccessMask
from smb.v2.messages.create.create_context import CreateContextList


class OplockLevel(IntEnum):
    SMB2_OPLOCK_LEVEL_NONE = 0x00,
    SMB2_OPLOCK_LEVEL_II = 0x01,
    SMB2_OPLOCK_LEVEL_EXCLUSIVE = 0x08,
    SMB2_OPLOCK_LEVEL_BATCH = 0x09,
    SMB2_OPLOCK_LEVEL_LEASE = 0xFF


class ImpersonationLevel(IntEnum):
    ANONYMOUS = 0x00000000,
    IDENTIFICATION = 0x00000001,
    IMPERSONATION = 0x00000002,
    DELEGATE = 0x00000003


class FileAttributesFlag(IntFlag):
    FILE_ATTRIBUTE_ARCHIVE = 0x00000020,
    FILE_ATTRIBUTE_COMPRESSED = 0x00000800,
    FILE_ATTRIBUTE_DIRECTORY = 0x00000010,
    FILE_ATTRIBUTE_ENCRYPTED = 0x00004000,
    FILE_ATTRIBUTE_HIDDEN = 0x00000002,
    FILE_ATTRIBUTE_NORMAL = 0x00000080,
    FILE_ATTRIBUTE_NOT_CONTENT_INDEXED = 0x00002000,
    FILE_ATTRIBUTE_OFFLINE = 0x00001000,
    FILE_ATTRIBUTE_READONLY = 0x00000001,
    FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400,
    FILE_ATTRIBUTE_SPARSE_FILE = 0x00000200,
    FILE_ATTRIBUTE_SYSTEM = 0x00000004,
    FILE_ATTRIBUTE_TEMPORARY = 0x00000100,
    FILE_ATTRIBUTE_INTEGRITY_STREAM = 0x00008000,
    FILE_ATTRIBUTE_NO_SCRUB_DATA = 0x00020000


FileAttributes = make_mask_class(FileAttributesFlag, prefix='FILE_ATTRIBUTE_')


class ShareAccessFlag(IntFlag):
    FILE_SHARE_READ = 0x00000001,
    FILE_SHARE_WRITE = 0x00000002,
    FILE_SHARE_DELETE = 0x00000004


ShareAccess = make_mask_class(ShareAccessFlag, prefix='FILE_SHARE_')


class CreateDisposition(IntEnum):
    FILE_SUPERSEDE = 0x00000000,
    FILE_OPEN = 0x00000001,
    FILE_CREATE = 0x00000002,
    FILE_OPEN_IF = 0x00000003,
    FILE_OVERWRITE = 0x00000004,
    FILE_OVERWRITE_IF = 0x00000005


class CreateOptionsFlag(IntFlag):
    FILE_DIRECTORY_FILE = 0x00000001,
    FILE_WRITE_THROUGH = 0x00000002,
    FILE_SEQUENTIAL_ONLY = 0x00000004,
    FILE_NO_INTERMEDIATE_BUFFERING = 0x00000008,
    FILE_SYNCHRONOUS_IO_ALERT = 0x00000010,
    FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020,
    FILE_NON_DIRECTORY_FILE = 0x00000040,
    FILE_COMPLETE_IF_OPLOCKED = 0x00000100,
    FILE_NO_EA_KNOWLEDGE = 0x00000200,
    FILE_RANDOM_ACCESS = 0x00000800,
    FILE_DELETE_ON_CLOSE = 0x00001000,
    FILE_OPEN_BY_FILE_ID = 0x00002000,
    FILE_OPEN_FOR_BACKUP_INTENT = 0x00004000,
    FILE_NO_COMPRESSION = 0x00008000,
    FILE_OPEN_REMOTE_INSTANCE = 0x00000400,
    FILE_OPEN_REQUIRING_OPLOCK = 0x00010000,
    FILE_DISALLOW_EXCLUSIVE = 0x00020000,
    FILE_RESERVE_OPFILTER = 0x00100000,
    FILE_OPEN_REPARSE_POINT = 0x00200000,
    FILE_OPEN_NO_RECALL = 0x00400000,
    FILE_OPEN_FOR_FREE_SPACE_QUERY = 0x00800000


CreateOptions = make_mask_class(CreateOptionsFlag, prefix='FILE_')


@dataclass
@register_smbv2_message
class CreateRequest(SMBv2RequestMessage):
    requested_oplock_level: OplockLevel
    impersonation_level: ImpersonationLevel
    desired_access: Union[FilePipePrinterAccessMask, DirectoryAccessMask]
    file_attributes: FileAttributes
    share_access: ShareAccess
    create_disposition: CreateDisposition
    create_options: CreateOptions
    name: str
    create_context_list: CreateContextList

    structure_size: ClassVar[int] = 57
    # TODO: What are `security_flags` and `smb_create_flags` class vars?
    security_flags: ClassVar[int] = 0
    smb_create_flags: ClassVar[bytes] = 8 * b'\x00'
    _command: ClassVar[SMBv2Command] = SMBv2Command.SMB2_CREATE
    _reserved: ClassVar[bytes] = 8 * b'\x00'

    @property
    def name_path(self) -> PureWindowsPath:
        return PureWindowsPath(self.name)

    @classmethod
    def _from_bytes_and_header(cls, data: bytes, header: SMBv2Header) -> SMBv2Message:

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
        if reserved != cls._reserved:
            raise NonEmptyCreateReservedError(observed_reserved_value=reserved)

        try:
            file_attributes = FileAttributes.from_mask(struct_unpack('<I', body_data[28:32])[0])
        except (ValueError, struct_error) as e:
            raise InvalidCreateFileAttributesValueError from e

        try:
            share_access = ShareAccess.from_mask(struct_unpack('<I', body_data[32:36])[0])
        except (ValueError, struct_error) as e:
            raise InvalidCreateShareAccessValueError from e

        try:
            create_disposition = CreateDisposition(struct_unpack('<I', body_data[36:40])[0])
        except (ValueError, struct_error) as e:
            raise InvalidCreateDispositionValueError from e

        try:
            create_options = CreateOptions.from_mask(struct_unpack('<I', body_data[40:44])[0])
        except (ValueError, struct_error) as e:
            raise InvalidCreateOptionsValueError from e

        try:
            desired_access: Union[DirectoryAccessMask, FilePipePrinterAccessMask] = (
                DirectoryAccessMask if create_options.directory_file else FilePipePrinterAccessMask
            ).from_mask(struct_unpack('<I', body_data[24:28])[0])
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
        current_buffer_offset = len(self.header) + (self.structure_size - 1)

        name_bytes = self.name.encode(encoding='utf-16-le')
        name_len: int = len(name_bytes)
        num_name_padding = int(ceil(name_len / 8)) * 8 - name_len
        name_offset = current_buffer_offset
        current_buffer_offset += name_len + num_name_padding

        create_contexts_bytes = bytes(self.create_context_list) if self.create_context_list is not None else b''
        create_contexts_len = len(create_contexts_bytes)
        create_contexts_offset = current_buffer_offset if create_contexts_bytes else 0

        return bytes(self.header) + b''.join([
            struct_pack('<H', self.structure_size),
            struct_pack('<B', self.security_flags),
            struct_pack('<B', self.requested_oplock_level.value),
            struct_pack('<I', self.impersonation_level.value),
            self.smb_create_flags,
            self._reserved,
            struct_pack('<I', self.desired_access.to_mask()),
            struct_pack('<I', self.file_attributes.to_mask()),
            struct_pack('<I', self.share_access.to_mask()),
            struct_pack('<I', self.create_disposition),
            struct_pack('<I', self.create_options.to_mask()),
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
            self.structure_size - 1,
            name_len or 1,
            num_name_padding,
            self.create_context_list.bytes_len()
        ])
