from __future__ import annotations
from dataclasses import dataclass
from typing import ClassVar
from struct import pack as struct_pack, unpack as struct_unpack, error as struct_error
from enum import IntFlag

from msdsalgs.utils import make_mask_class
from msdsalgs.fscc.file_information_classes import FileInformationClass

from smb.v2.smbv2_message import SMBv2RequestMessage, register_smbv2_message
from smb.v2.smbv2_header import SMBv2Header, SMBv2Command
from smb.exceptions import IncorrectStructureSizeError, MalformedQueryDirectoryRequestError,\
    InvalidQueryDirectoryFileIndexValueError, InvalidQueryDirectoryFlagsValueError,\
    InvalidQueryDirectoryRequestFileInformationClassValueError
from smb.v2.file_id import FileId


class QueryDirectoryFlagMask(IntFlag):
    SMB2_NONE = 0x00
    SMB2_RESTART_SCANS = 0x01
    SMB2_RETURN_SINGLE_ENTRY = 0x02
    SMB2_INDEX_SPECIFIED = 0x04
    SMB2_REOPEN = 0x10


QueryDirectoryFlag = make_mask_class(QueryDirectoryFlagMask, prefix='SMB2_')


@dataclass
@register_smbv2_message
class QueryDirectoryRequest(SMBv2RequestMessage):
    """
    [MS-SMB2]: SMB2 QUERY_DIRECTORY Request | Microsoft Docs
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/10906442-294c-46d3-8515-c277efe1f752
    """

    file_information_class: FileInformationClass
    flags: QueryDirectoryFlag
    file_id: FileId
    file_name: str
    output_buffer_length: int
    file_index: int = 0

    structure_size: ClassVar[int] = 33
    _command: ClassVar[SMBv2Command] = SMBv2Command.SMB2_QUERY_DIRECTORY

    @classmethod
    def _from_bytes_and_header(cls, data: bytes, header: SMBv2Header) -> QueryDirectoryRequest:
        body_data: bytes = data[len(header):]

        try:
            cls.check_structure_size(structure_size_to_test=struct_unpack('<H', body_data[:2])[0])
        except IncorrectStructureSizeError as e:
            raise MalformedQueryDirectoryRequestError(str(e)) from e

        try:
            file_information_class = FileInformationClass(struct_unpack('<B', body_data[2:3])[0])
        except (ValueError, struct_error) as e:
            raise InvalidQueryDirectoryRequestFileInformationClassValueError(str(e)) from e

        try:
            flags = QueryDirectoryFlag.from_mask(struct_unpack('<B', body_data[3:4])[0])
        except (ValueError, struct_error) as e:
            raise InvalidQueryDirectoryFlagsValueError(str(e)) from e

        file_index: int = struct_unpack('<I', body_data[4:8])[0]
        if file_index != 0 and not flags.index_specified:
            raise InvalidQueryDirectoryFileIndexValueError(observed_file_index_value=file_index)

        file_name_offset = struct_unpack('<H', body_data[24:26])
        file_name_length = struct_unpack('<H', body_data[26:28])
        file_name: str = data[file_name_offset:file_name_offset+file_name_length].decode(encoding='utf-16-le')

        return cls(
            header=header,
            file_information_class=file_information_class,
            flags=flags,
            file_id=FileId.from_bytes(data=body_data[8:24]),
            file_name=file_name,
            output_buffer_length=struct_unpack('<I', body_data[28:32])[0],
            file_index=file_index
        )

    def __len__(self) -> int:
        return len(self.header) + (self.structure_size - 1) + len(self.file_name.encode(encoding='utf-16-le'))

    def __bytes__(self) -> bytes:
        file_name_bytes = self.file_name.encode(encoding='utf-16-le')
        file_name_offset = len(self.header) + self.structure_size - 1
        file_name_len = len(file_name_bytes)

        # TODO: Not sure whether the `file_name_bytes` must be at least of length 1.

        return bytes(self.header) + b''.join([
            struct_pack('<H', self.structure_size),
            struct_pack('<B', self.file_information_class.value),
            struct_pack('<B', self.flags.to_mask()),
            struct_pack('<I', self.file_index),
            bytes(self.file_id),
            struct_pack('<H', file_name_offset),
            struct_pack('<H', file_name_len),
            struct_pack('<I', self.output_buffer_length),
            file_name_bytes or b'\x00'
        ])
