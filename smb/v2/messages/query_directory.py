from __future__ import annotations
from dataclasses import dataclass
from typing import ClassVar, List, Type
from struct import pack, error as struct_error, unpack_from

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
    def _from_bytes_and_header(cls, data: memoryview, header: Header) -> QueryDirectoryResponse:
        super()._from_bytes_and_header(data=data, header=header)

        body_data: memoryview = data[len(header):]

        output_buffer_offset: int = unpack_from('<H', buffer=body_data, offset=2)[0]
        output_buffer_length: int = unpack_from('<I', buffer=body_data, offset=4)[0]

        return cls(header=header, _buffer=bytes(data[output_buffer_offset:output_buffer_offset+output_buffer_length]))

    def __len__(self) -> int:
        return len(self.header) + (self.STRUCTURE_SIZE - 1) + len(self._buffer)

    def __bytes__(self) -> bytes:
        output_buffer_offset: int = len(self.header) + self.STRUCTURE_SIZE - 1
        return bytes(self.header) + b''.join([
            pack('<H', self.STRUCTURE_SIZE),
            pack('<H', output_buffer_offset),
            pack('<I', len(self._buffer)),
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
    def _from_bytes_and_header(cls, data: memoryview, header: Header) -> QueryDirectoryRequest:
        super()._from_bytes_and_header(data=data, header=header)

        body_data: memoryview = data[len(header):]

        try:
            file_information_class = FileInformationClass(unpack_from('<B', buffer=body_data, offset=2)[0])
        except (ValueError, struct_error) as e:
            raise InvalidQueryDirectoryRequestFileInformationClassValueError(str(e)) from e

        try:
            flags = QueryDirectoryFlag.from_int(unpack_from('<B', buffer=body_data, offset=3)[0])
        except (ValueError, struct_error) as e:
            raise InvalidQueryDirectoryFlagsValueError(str(e)) from e

        file_index: int = unpack_from('<I', buffer=body_data, offset=4)[0]
        if file_index != 0 and not flags.index_specified:
            raise InvalidQueryDirectoryFileIndexValueError(observed_file_index_value=file_index)

        file_name_offset: int = unpack_from('<H', buffer=body_data, offset=24)[0]
        file_name_length: int = unpack_from('<H', buffer=body_data, offset=26)[0]
        file_name: str = bytes(data[file_name_offset:file_name_offset+file_name_length]).decode(encoding='utf-16-le')

        return cls(
            header=header,
            file_information_class=file_information_class,
            flags=flags,
            file_id=FileId.from_bytes(data=body_data, base_offset=8),
            file_name=file_name,
            output_buffer_length=unpack_from('<I', buffer=body_data, offset=28)[0],
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
            pack('<H', self.STRUCTURE_SIZE),
            pack('<B', self.file_information_class.value),
            pack('<B', int(self.flags)),
            pack('<I', self.file_index),
            bytes(self.file_id),
            pack('<H', file_name_offset),
            pack('<H', file_name_len),
            pack('<I', self.output_buffer_length),
            file_name_bytes or b'\x00'
        ])
