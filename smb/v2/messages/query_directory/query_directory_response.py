from __future__ import annotations
from dataclasses import dataclass
from typing import ClassVar, List
from struct import pack as struct_pack, unpack as struct_unpack

from msdsalgs.utils import extract_elements

from smb.v2.smbv2_message import SMBv2Message
from smb.v2.smbv2_header import SMBv2Header
from smb.v2.file_information import FileInformation
from smb.exceptions import IncorrectStructureSizeError, MalformedQueryDirectoryResponseError


@dataclass
class FileDirectoryInformation:
    next_entry_offset: int
    file_index: int
    file_information: FileInformation
    file_name: str

    @classmethod
    def from_bytes(cls, data: bytes) -> FileDirectoryInformation:
        file_name_length: int = struct_unpack('<I', data[60:64])[0]
        return cls(
            next_entry_offset=struct_unpack('<I', data[:4])[0],
            file_index=struct_unpack('<I', data[4:8])[0],
            file_information=FileInformation.from_bytes(data=data[8:8+FileInformation.structure_size]),
            file_name=data[64:64+file_name_length].decode(encoding='utf-16-le')
        )


@dataclass
class FileIdFullDirectoryInformation(FileDirectoryInformation):
    ea_size: int
    file_id: bytes

    _reserved: ClassVar[int] = 4 * b'\x00'

    @classmethod
    def from_bytes(cls, data: bytes) -> FileIdFullDirectoryInformation:
        file_name_length: int = struct_unpack('<I', data[60:64])[0]
        return cls(
            next_entry_offset=struct_unpack('<I', data[:4])[0],
            file_index=struct_unpack('<I', data[4:8])[0],
            file_information=FileInformation.from_bytes(data=data[8:8+FileInformation.structure_size]),
            # TODO: Support "Reparse Tag" content.
            ea_size=struct_unpack('<I', data[64:68])[0],
            file_id=data[72:80],
            file_name=data[80:80+file_name_length].decode(encoding='utf-16-le')
        )


@dataclass
class QueryDirectoryResponse(SMBv2Message):

    _buffer: bytes
    structure_size: ClassVar[int] = 9

    @classmethod
    def from_bytes_and_header(cls, data: bytes, header: SMBv2Header) -> QueryDirectoryResponse:

        body_data: bytes = data[len(header):]

        try:
            cls.check_structure_size(structure_size_to_test=struct_unpack('<H', body_data[:2])[0])
        except IncorrectStructureSizeError as e:
            raise MalformedQueryDirectoryResponseError(str(e)) from e

        output_buffer_offset: int = struct_unpack('<H', body_data[2:4])[0]
        output_buffer_length: int = struct_unpack('<I', body_data[4:8])[0]

        return cls(header=header, _buffer=data[output_buffer_offset:output_buffer_offset+output_buffer_length])

    def __len__(self) -> int:
        return len(self.header) + (self.structure_size - 1) + len(self._buffer)

    def __bytes__(self) -> bytes:
        output_buffer_offset: int = len(self.header) + self.structure_size - 1
        return bytes(self.header) + b''.join([
            struct_pack('<H', self.structure_size),
            output_buffer_offset,
            len(self._buffer),
            self._buffer
        ])

    def file_directory_information(self) -> List[FileDirectoryInformation]:
        return extract_elements(
            data=self._buffer,
            create_element=lambda data: FileDirectoryInformation.from_bytes(data=data),
            get_next_offset=lambda element: element.next_entry_offset
        )

    def file_id_full_directory_information(self) -> List[FileIdFullDirectoryInformation]:
        return extract_elements(
            data=self._buffer,
            create_element=lambda data: FileIdFullDirectoryInformation.from_bytes(data=data),
            get_next_offset=lambda element: element.next_entry_offset
        )
