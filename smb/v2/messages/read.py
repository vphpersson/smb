from __future__ import annotations
from dataclasses import dataclass
from typing import ClassVar, Dict, Any, Type
from struct import pack, unpack as struct_unpack, unpack_from
from abc import ABC

from smb.v2.messages import RequestMessage, ResponseMessage, Message
from smb.v2.header import Header, SMBv2Command
from smb.exceptions import MalformedReadRequestError, InvalidReadRequestFlagError,\
    InvalidReadRequestChannelError, InvalidReadRequestReadChannelInfoOffsetError,\
    InvalidReadRequestReadChannelLengthError, MalformedReadResponseError, \
    NonEmptyReadResponseReservedValueError, NonEmptyReadResponseReserved2ValueError, MalformedSMBv2MessageError
from smb.v2.structures.file_id import FileId
from smb.v2.structures.dialect import Dialect
from smb.v2.structures.read_request_channel import ReadRequestChannel
from smb.v2.structures.read_request_flag import ReadRequestFlag


@dataclass
@Message.register
class ReadResponse(ResponseMessage):
    STRUCTURE_SIZE: ClassVar[int] = 17
    COMMAND: ClassVar[SMBv2Command] = SMBv2Command.SMB2_READ
    MALFORMED_ERROR_CLASS: ClassVar[Type[MalformedSMBv2MessageError]] = MalformedReadResponseError
    _RESERVED: ClassVar[bytes] = bytes(1)
    _RESERVED_2: ClassVar[bytes] = bytes(4)

    # TODO: Should this really be `bytes`?
    buffer: bytes
    data_remaining_length: int

    @property
    def data_length(self) -> int:
        return len(self.buffer)

    @classmethod
    def _from_bytes_and_header(cls, data: memoryview, header: Header) -> ReadResponse:
        super()._from_bytes_and_header(data=data, header=header)

        body_data: memoryview = data[len(header):]

        if (reserved := bytes(body_data[3:4])) != cls._RESERVED:
            raise NonEmptyReadResponseReservedValueError(
                observed_reserved_value=reserved,
                expected_reserved_value=cls._RESERVED
            )

        if (reserved_2 := bytes(body_data[12:16])) != cls._RESERVED_2:
            raise NonEmptyReadResponseReserved2ValueError(
                observed_reserved_value=reserved_2,
                expected_reserved_value=cls._RESERVED_2
            )

        data_offset: int = unpack_from('<B', buffer=body_data, offset=2)[0]
        data_length: int = unpack_from('<I', buffer=body_data, offset=4)[0]

        return cls(
            header=header,
            data_remaining_length=unpack_from('<I', buffer=body_data, offset=8)[0],
            buffer=bytes(data[data_offset:data_offset+data_length])
        )

    def __bytes__(self) -> bytes:

        data_offset = len(self.header) + self.STRUCTURE_SIZE - 1

        return bytes(self.header) + b''.join([
            pack('<H', self.STRUCTURE_SIZE),
            pack('<B', data_offset),
            self._RESERVED,
            pack('<I', len(self.buffer)),
            pack('<I', self.data_remaining_length),
            self._RESERVED_2,
            self.buffer
        ])

    def __len__(self) -> int:
        return len(self.header) + (self.STRUCTURE_SIZE - 1) + len(self.buffer)


@dataclass
@Message.register
class ReadRequest(RequestMessage, ABC):
    STRUCTURE_SIZE: ClassVar[int] = 49
    COMMAND: ClassVar[SMBv2Command] = SMBv2Command.SMB2_READ
    MALFORMED_ERROR_CLASS: ClassVar[Type[MalformedSMBv2MessageError]] = MalformedReadRequestError
    RESPONSE_MESSAGE_CLASS: ClassVar[ResponseMessage] = ReadResponse
    _DIALECT_TO_CLASS: ClassVar[Dict[Dialect, Type[ReadRequest]]] = {}
    _DIALECT: ClassVar[Dialect] = NotImplemented

    _RESERVED_FLAGS_VALUE: ClassVar[bytes] = bytes(1)
    _RESERVED_CHANNEL_VALUE: ClassVar[bytes] = bytes(4)
    _RESERVED_READ_CHANNEL_OFFSET: ClassVar[bytes] = bytes(2)
    _RESERVED_READ_CHANNEL_LENGTH: ClassVar[bytes] = bytes(2)

    padding: int
    length: int
    offset: int
    file_id: FileId
    minimum_count: int
    remaining_bytes: int

    @classmethod
    def _from_bytes_and_header(cls, data: memoryview, header: Header) -> ReadRequest:
        super()._from_bytes_and_header(data=data, header=header)

        body_bytes: memoryview = data[len(header):]

        read_request_base_args: Dict[str, Any] = dict(
            padding=unpack_from('<B', buffer=body_bytes, offset=2)[0],
            length=unpack_from('<I', buffer=body_bytes, offset=4)[0],
            offset=unpack_from('<Q', buffer=body_bytes, offset=8)[0],
            file_id=FileId.from_bytes(data=body_bytes, base_offset=16),
            minimum_count=unpack_from('<I', buffer=body_bytes, offset=32)[0],
            remaining_bytes=unpack_from('<I', buffer=body_bytes, offset=40)[0]
        )

        flags_raw = bytes(body_bytes[3:4])
        channel_raw = bytes(body_bytes[36:40])
        read_channel_info_offset_raw = bytes(body_bytes[44:46])
        read_channel_info_length_raw = bytes(body_bytes[46:48])

        if header.DIALECT in {Dialect.SMB_2_0_2, Dialect.SMB_2_1}:
            if flags_raw != cls._RESERVED_FLAGS_VALUE:
                raise InvalidReadRequestFlagError

            if channel_raw != cls._RESERVED_CHANNEL_VALUE:
                raise InvalidReadRequestChannelError

            if read_channel_info_offset_raw != cls._RESERVED_READ_CHANNEL_OFFSET:
                raise InvalidReadRequestReadChannelInfoOffsetError

            if read_channel_info_length_raw != cls._RESERVED_READ_CHANNEL_LENGTH:
                raise InvalidReadRequestReadChannelLengthError

            return cls._DIALECT_TO_CLASS[header.DIALECT](header=header, **read_request_base_args)

        read_channel_info_offset: int = struct_unpack('<H', read_channel_info_offset_raw)[0]
        read_channel_info_length: int = struct_unpack('<H', read_channel_info_length_raw)[0]
        read_channel_buffer: bytes = bytes(data[read_channel_info_offset:read_channel_info_offset + read_channel_info_length])
        channel = ReadRequestChannel(struct_unpack('<I', channel_raw)[0])

        if header.DIALECT is Dialect.SMB_3_0:
            if flags_raw != cls._RESERVED_FLAGS_VALUE:
                raise InvalidReadRequestFlagError
            return ReadRequest300(
                header=header,
                **read_request_base_args,
                read_channel_buffer=read_channel_buffer,
                channel=channel
            )

        try:
            flags = ReadRequestFlag.from_int(unpack_from('<B', buffer=body_bytes, offset=3)[0])
        except ValueError as e:
            raise InvalidReadRequestFlagError from e

        if header.DIALECT in {Dialect.SMB_3_0_2, Dialect.SMB_3_1_1}:
            return cls._DIALECT_TO_CLASS[header.DIALECT](
                header=header,
                **read_request_base_args,
                read_channel_buffer=read_channel_buffer,
                flags=flags,
                channel=channel
            )

        # TODO: Raise proper exception.
        raise ValueError

    def _to_bytes(
        self,
        flags_bytes_value: bytes,
        channel_bytes_value: bytes,
        read_channel_offset_bytes_value: bytes,
        read_channel_length_bytes_value: bytes,
        read_channel_buffer: bytes
    ) -> bytes:
        return bytes(self.header) + b''.join([
            pack('<H', self.STRUCTURE_SIZE),
            pack('<B', self.padding),
            flags_bytes_value,
            pack('<I', self.length),
            pack('<Q', self.offset),
            bytes(self.file_id),
            pack('<I', self.minimum_count),
            channel_bytes_value,
            pack('<I', self.remaining_bytes),
            read_channel_offset_bytes_value,
            read_channel_length_bytes_value,
            read_channel_buffer
        ])


@dataclass
class ReadRequest2X(ReadRequest, ABC):

    def __len__(self) -> int:
        return len(self.header) + self.STRUCTURE_SIZE

    def __bytes__(self) -> bytes:
        return super()._to_bytes(
            flags_bytes_value=self._RESERVED_FLAGS_VALUE,
            channel_bytes_value=self._RESERVED_CHANNEL_VALUE,
            read_channel_offset_bytes_value=self._RESERVED_READ_CHANNEL_OFFSET,
            read_channel_length_bytes_value=self._RESERVED_READ_CHANNEL_LENGTH,
            read_channel_buffer=b'\x00'
        )


@dataclass
class ReadRequest202(ReadRequest2X):
    _DIALECT: ClassVar[Dialect] = Dialect.SMB_2_0_2


@dataclass
class ReadRequest210(ReadRequest2X):
    _DIALECT: ClassVar[Dialect] = Dialect.SMB_2_1


@dataclass
class ReadRequest3X(ReadRequest, ABC):
    channel: ReadRequestChannel
    # TODO: Support the various structures as specified by channel.
    read_channel_buffer: bytes

    def __len__(self) -> int:
        return len(self.header) + (self.STRUCTURE_SIZE - 1) + len(self.read_channel_buffer)


@dataclass
class ReadRequest300(ReadRequest3X):
    _DIALECT: ClassVar[Dialect] = Dialect.SMB_3_0

    def __bytes__(self) -> bytes:
        return super()._to_bytes(
            flags_bytes_value=self._RESERVED_FLAGS_VALUE,
            channel_bytes_value=pack('<I', self.channel.value),
            read_channel_offset_bytes_value=pack('<H', self.STRUCTURE_SIZE - 1),
            read_channel_length_bytes_value=pack('<H', len(self.read_channel_buffer)),
            read_channel_buffer=self.read_channel_buffer
        )


@dataclass
class ReadRequest302(ReadRequest3X):
    _DIALECT: ClassVar[Dialect] = Dialect.SMB_3_0_2
    flags: ReadRequestFlag

    def __bytes__(self) -> bytes:
        return super()._to_bytes(
            flags_bytes_value=pack('<B', int(self.flags)),
            channel_bytes_value=pack('<I', self.channel.value),
            read_channel_offset_bytes_value=pack('<H', self.STRUCTURE_SIZE - 1),
            read_channel_length_bytes_value=pack('<H', len(self.read_channel_buffer)),
            read_channel_buffer=self.read_channel_buffer
        )


@dataclass
class ReadRequest311(ReadRequest3X):
    _DIALECT: ClassVar[Dialect] = Dialect.SMB_3_1_1
    flags: ReadRequestFlag

    def __bytes__(self) -> bytes:
        return super()._to_bytes(
            flags_bytes_value=pack('<B', int(self.flags)),
            channel_bytes_value=pack('<I', self.channel.value),
            read_channel_offset_bytes_value=pack('<H', self.STRUCTURE_SIZE - 1),
            read_channel_length_bytes_value=pack('<H', len(self.read_channel_buffer)),
            read_channel_buffer=self.read_channel_buffer
        )


ReadRequest._DIALECT_TO_CLASS = {
    Dialect.SMB_2_0_2: ReadRequest202,
    Dialect.SMB_2_1: ReadRequest210,
    Dialect.SMB_3_0: ReadRequest300,
    Dialect.SMB_3_0_2: ReadRequest302,
    Dialect.SMB_3_1_1: ReadRequest311
}
