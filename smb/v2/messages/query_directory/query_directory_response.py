from __future__ import annotations
from dataclasses import dataclass
from typing import ClassVar, List
from struct import pack as struct_pack, unpack as struct_unpack

from msdsalgs.utils import extract_elements
from msdsalgs.fscc.file_information_classes import FileDirectoryInformation, FileIdFullDirectoryInformation

from smb.v2.smbv2_message import SMBv2ResponseMessage, register_smbv2_message
from smb.v2.smbv2_header import SMBv2Header, SMBv2Command
from smb.exceptions import IncorrectStructureSizeError, MalformedQueryDirectoryResponseError


@dataclass
@register_smbv2_message
class QueryDirectoryResponse(SMBv2ResponseMessage):

    _buffer: bytes
    structure_size: ClassVar[int] = 9
    _command: ClassVar[SMBv2Command] = SMBv2Command.SMB2_QUERY_DIRECTORY

    @classmethod
    def _from_bytes_and_header(cls, data: bytes, header: SMBv2Header) -> QueryDirectoryResponse:

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
            struct_pack('<H', output_buffer_offset),
            struct_pack('<I', len(self._buffer)),
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
