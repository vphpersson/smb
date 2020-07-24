from __future__ import annotations
from dataclasses import dataclass
from typing import ClassVar, List, Type
from struct import pack as struct_pack, unpack as struct_unpack, error as struct_error

from msdsalgs.utils import extract_elements
from msdsalgs.fscc.file_information_classes import FileInformationClass, FileDirectoryInformation, \
    FileIdFullDirectoryInformation

from smb.v2.messages import Message, RequestMessage, ResponseMessage
from smb.v2.header import Header, SMBv2Command
from smb.exceptions import MalformedQueryDirectoryRequestError,\
    InvalidQueryDirectoryFileIndexValueError, InvalidQueryDirectoryFlagsValueError,\
    InvalidQueryDirectoryRequestFileInformationClassValueError, MalformedQueryDirectoryResponseError, \
    MalformedSMBv2MessageError
from smb.v2.structures.file_id import FileId
from smb.v2.structures.query_directory_flag import QueryDirectoryFlag


@dataclass
@Message.register
class QueryDirectoryResponse(ResponseMessage):
    STRUCTURE_SIZE: ClassVar[int] = 9
    COMMAND: ClassVar[SMBv2Command] = SMBv2Command.SMB2_QUERY_DIRECTORY
    MALFORMED_ERROR_CLASS: ClassVar[Type[MalformedSMBv2MessageError]] = MalformedQueryDirectoryResponseError

    # TODO: `InitVar`?
    _buffer: bytes

    @classmethod
    def _from_bytes_and_header(cls, data: bytes, header: Header) -> QueryDirectoryResponse:
        super()._from_bytes_and_header(data=data, header=header)

        body_data: bytes = data[len(header):]

        output_buffer_offset: int = struct_unpack('<H', body_data[2:4])[0]
        output_buffer_length: int = struct_unpack('<I', body_data[4:8])[0]

        return cls(header=header, _buffer=data[output_buffer_offset:output_buffer_offset+output_buffer_length])

    def __len__(self) -> int:
        return len(self.header) + (self.STRUCTURE_SIZE - 1) + len(self._buffer)

    def __bytes__(self) -> bytes:
        output_buffer_offset: int = len(self.header) + self.STRUCTURE_SIZE - 1
        return bytes(self.header) + b''.join([
            struct_pack('<H', self.STRUCTURE_SIZE),
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


@dataclass
@Message.register
class QueryDirectoryRequest(RequestMessage):
    """
    [MS-SMB2]: SMB2 QUERY_DIRECTORY Request | Microsoft Docs
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/10906442-294c-46d3-8515-c277efe1f752
    """
    STRUCTURE_SIZE: ClassVar[int] = 33
    COMMAND: ClassVar[SMBv2Command] = SMBv2Command.SMB2_QUERY_DIRECTORY
    MALFORMED_ERROR_CLASS: ClassVar[Type[MalformedSMBv2MessageError]] = MalformedQueryDirectoryRequestError
    RESPONSE_MESSAGE_CLASS: ClassVar[ResponseMessage] = QueryDirectoryResponse

    file_information_class: FileInformationClass
    flags: QueryDirectoryFlag
    file_id: FileId
    file_name: str
    output_buffer_length: int
    file_index: int = 0

    @classmethod
    def _from_bytes_and_header(cls, data: bytes, header: Header) -> QueryDirectoryRequest:
        super()._from_bytes_and_header(data=data, header=header)

        body_data: bytes = data[len(header):]

        try:
            file_information_class = FileInformationClass(struct_unpack('<B', body_data[2:3])[0])
        except (ValueError, struct_error) as e:
            raise InvalidQueryDirectoryRequestFileInformationClassValueError(str(e)) from e

        try:
            flags = QueryDirectoryFlag.from_int(struct_unpack('<B', body_data[3:4])[0])
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
        return len(self.header) + (self.STRUCTURE_SIZE - 1) + len(self.file_name.encode(encoding='utf-16-le'))

    def __bytes__(self) -> bytes:
        file_name_bytes = self.file_name.encode(encoding='utf-16-le')
        file_name_offset = len(self.header) + self.STRUCTURE_SIZE - 1
        file_name_len = len(file_name_bytes)

        # TODO: Not sure whether the `file_name_bytes` must be at least of length 1.

        return bytes(self.header) + b''.join([
            struct_pack('<H', self.STRUCTURE_SIZE),
            struct_pack('<B', self.file_information_class.value),
            struct_pack('<B', int(self.flags)),
            struct_pack('<I', self.file_index),
            bytes(self.file_id),
            struct_pack('<H', file_name_offset),
            struct_pack('<H', file_name_len),
            struct_pack('<I', self.output_buffer_length),
            file_name_bytes or b'\x00'
        ])
