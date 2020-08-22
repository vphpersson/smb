from __future__ import annotations
from dataclasses import dataclass
from typing import ClassVar, Optional, Dict, Type
from struct import pack as struct_pack, unpack as struct_unpack, unpack_from
from abc import ABC

from smb.v2.messages import Message, RequestMessage, ResponseMessage
from smb.v2.header import Header, SMBv2Command, SMB2XSyncHeader, SMB3XSyncHeader, Dialect
from smb.v2.structures.file_id import FileId
from smb.v2.structures.write_flag import WriteFlag
from smb.exceptions import MalformedSMBv2MessageError, MalformedWriteRequestError, MalformedWriteResponseError


@dataclass
@Message.register
class WriteResponse(ResponseMessage):
    STRUCTURE_SIZE: ClassVar[int] = 17
    COMMAND: ClassVar[SMBv2Command] = SMBv2Command.SMB2_WRITE
    MALFORMED_ERROR_CLASS: ClassVar[Type[MalformedSMBv2MessageError]] = MalformedWriteResponseError

    _RESERVED: ClassVar[bytes] = bytes(2)
    _RESERVED_REMAINING: ClassVar[bytes] = bytes(4)
    _RESERVED_WRITE_CHANNEL_INFO_OFFSET: ClassVar[bytes] = bytes(2)
    _RESERVED_WRITE_CHANNEL_INFO_LENGTH: ClassVar[bytes] = bytes(2)

    count: int

    @classmethod
    def _from_bytes_and_header(cls, data: memoryview, header: Header) -> WriteResponse:
        super()._from_bytes_and_header(data=data, header=header)

        body_bytes: memoryview = data[len(header):]

        if bytes(body_bytes[2:4]) != cls._RESERVED:
            # TODO: Use proper exception.
            raise ValueError

        if bytes(body_bytes[8:12]) != cls._RESERVED_REMAINING:
            # TODO: Use proper exception.
            raise ValueError

        if bytes(body_bytes[12:14]) != cls._RESERVED_WRITE_CHANNEL_INFO_OFFSET:
            # TODO: Use proper exception.
            raise ValueError

        if bytes(body_bytes[14:16]) != cls._RESERVED_WRITE_CHANNEL_INFO_LENGTH:
            # TODO: Use proper exception.
            raise ValueError

        return cls(header=header, count=unpack_from('<I', buffer=body_bytes, offset=4)[0])

    def __bytes__(self) -> bytes:
        return bytes(self.header) + b''.join([
            struct_pack('<H', self.STRUCTURE_SIZE),
            self._RESERVED,
            struct_pack('<I', self.count),
            self._RESERVED_REMAINING,
            self._RESERVED_WRITE_CHANNEL_INFO_OFFSET,
            self._RESERVED_WRITE_CHANNEL_INFO_LENGTH
        ])

    def __len__(self) -> int:
        return self.header.STRUCTURE_SIZE + self.STRUCTURE_SIZE


@dataclass
@Message.register
class WriteRequest(RequestMessage, ABC):
    # TODO: Actual size is 48. Must the buffer contain at least one byte?
    STRUCTURE_SIZE: ClassVar[int] = 49
    COMMAND: ClassVar[SMBv2Command] = SMBv2Command.SMB2_WRITE
    MALFORMED_ERROR_CLASS: ClassVar[Type[MalformedSMBv2MessageError]] = MalformedWriteRequestError
    RESPONSE_MESSAGE_CLASS: ClassVar[ResponseMessage] = WriteResponse
    _DIALECT_TO_CLASS: ClassVar[Dict[Dialect, Type[WriteRequest]]] = {}

    _RESERVED_CHANNEL: ClassVar[bytes] = bytes(4)
    _RESERVED_WRITE_CHANNEL_OFFSET: ClassVar[bytes] = bytes(2)
    _RESERVED_WRITE_CHANNEL_LENGTH: ClassVar[bytes] = bytes(2)

    write_data: bytes
    offset: int
    file_id: FileId
    # TODO: Let this be the size of `write_data` by default? post init?
    remaining_bytes: int
    flags: WriteFlag

    @classmethod
    def _from_bytes_and_header(cls, data: memoryview, header: Header) -> WriteRequest:
        body_bytes: bytes = data[len(header):]

        cls._check_structure_size(structure_size_to_test=struct_unpack('<H', body_bytes[:2])[0])

        data_offset: int = struct_unpack('<H', body_bytes[2:4])[0]
        length: int = struct_unpack('<I', body_bytes[4:8])[0]
        offset: int = struct_unpack('<Q', body_bytes[8:16])[0]
        file_id: FileId = FileId.from_bytes(data=body_bytes[16:32])
        channel: bytes = body_bytes[32:36]
        remaining_bytes: int = struct_unpack('<I', body_bytes[36:40])[0]
        write_channel_info_offset_raw: bytes = body_bytes[40:42]
        write_channel_info_length_raw: bytes = body_bytes[42:44]
        flags = WriteFlag.from_int(struct_unpack('<I', body_bytes[44:48])[0])

        write_data: bytes = bytes(data[data_offset:data_offset + length])

        if isinstance(header, SMB2XSyncHeader):
            if channel != cls._RESERVED_CHANNEL:
                # TODO: Use proper exception.
                raise ValueError

            if write_channel_info_offset_raw != cls._RESERVED_WRITE_CHANNEL_OFFSET:
                # TODO: Use proper exception.
                raise ValueError

            if write_channel_info_length_raw != cls._RESERVED_WRITE_CHANNEL_LENGTH:
                # TODO: Use proper exception.
                raise ValueError

            return cls._DIALECT_TO_CLASS[header.DIALECT](
                write_data=write_data,
                offset=offset,
                file_id=file_id,
                remaining_bytes=remaining_bytes,
                flags=flags
            )
        elif isinstance(header, SMB3XSyncHeader):
            write_channel_info_offset: int = struct_unpack('<H', write_channel_info_offset_raw)[0]
            write_channel_info_length: int = struct_unpack('<H', write_channel_info_length_raw)[0]

            return cls._DIALECT_TO_CLASS[header.DIALECT](
                write_data=write_data,
                offset=offset,
                file_id=file_id,
                remaining_bytes=remaining_bytes,
                flags=flags,
                channel=channel,
                write_channel_info=data[write_channel_info_offset:write_channel_info_offset + write_channel_info_length]
            )
        else:
            # TODO: Raise proper exception.
            raise ValueError

    def _to_bytes(
            self,
            channel_bytes: Optional[bytes] = None,
            write_channel_info_buffer: Optional[bytes] = None
    ) -> bytes:

        if write_channel_info_buffer is not None:
            write_channel_info_offset = (self.header.STRUCTURE_SIZE - 1) + self.STRUCTURE_SIZE
            write_channel_info_length = len(write_channel_info_buffer)
            data_offset = write_channel_info_offset + write_channel_info_length
        else:
            write_channel_info_offset = 0
            write_channel_info_length = 0
            data_offset = (self.header.STRUCTURE_SIZE - 1) + self.STRUCTURE_SIZE

        return bytes(self.header) + b''.join([
            struct_pack('<H', self.STRUCTURE_SIZE),
            struct_pack('<H', data_offset),
            struct_pack('<I', len(self.write_data)),
            struct_pack('<Q', self.offset),
            bytes(self.file_id),
            channel_bytes if channel_bytes is not None else self._RESERVED_CHANNEL,
            struct_pack('<I', self.remaining_bytes),
            struct_pack('<H', write_channel_info_offset),
            struct_pack('<H', write_channel_info_length),
            struct_pack('<I', int(self.flags)),
            write_channel_info_buffer if write_channel_info_buffer is not None else b'',
            # TODO: Must it be at least one byte?
            self.write_data
        ])


@dataclass
class WriteRequest2X(WriteRequest, ABC):

    def __bytes__(self) -> bytes:
        return self._to_bytes()

    def __len__(self) -> int:
        return self.header.STRUCTURE_SIZE + (self.STRUCTURE_SIZE - 1) + len(self.write_data)


@dataclass
class WriteRequest202(WriteRequest2X):
    _dialect: ClassVar[Dialect] = Dialect.SMB_2_0_2


@dataclass
class WriteRequest210(WriteRequest2X):
    _dialect: ClassVar[Dialect] = Dialect.SMB_2_1


@dataclass
class WriteRequest3X(WriteRequest, ABC):
    # TODO: Ok, so `channel` is only a tag indicating what structure `write_channel_info` is.
    channel: bytes
    # TODO: Use proper structure.
    write_channel_info: bytes

    def __bytes__(self):
        return super()._to_bytes(
            channel_bytes=self.channel,
            write_channel_info_buffer=self.write_channel_info
        )

    def __len__(self) -> int:
        return sum([
            self.header.STRUCTURE_SIZE,
            (self.STRUCTURE_SIZE - 1),
            len(self.write_data),
            len(self.write_channel_info)
        ])


@dataclass
class WriteRequest300(WriteRequest3X):
    _dialect: ClassVar[Dialect] = Dialect.SMB_3_0


@dataclass
class WriteRequest302(WriteRequest3X):
    _dialect: ClassVar[Dialect] = Dialect.SMB_3_0_2


@dataclass
class WriteRequest311(WriteRequest3X):
    _dialect: ClassVar[Dialect] = Dialect.SMB_3_1_1


WriteRequest._DIALECT_TO_CLASS = {
    Dialect.SMB_2_0_2: WriteRequest202,
    Dialect.SMB_2_1: WriteRequest210,
    Dialect.SMB_3_0: WriteRequest300,
    Dialect.SMB_3_0_2: WriteRequest302,
    Dialect.SMB_3_1_1: WriteRequest311
}
