from __future__ import annotations
from dataclasses import dataclass
from typing import ClassVar, Dict, Any, Type
from struct import pack as struct_pack, unpack as struct_unpack
from abc import ABC

from smb.v2.messages.message_base import SMBv2RequestMessage, SMBv2ResponseMessage, register_smbv2_message
from smb.v2.header import SMBv2Header, SMBv2Command
from smb.exceptions import IncorrectStructureSizeError, MalformedReadRequestError, InvalidReadRequestFlagError,\
    InvalidReadRequestChannelError, InvalidReadRequestReadChannelInfoOffsetError,\
    InvalidReadRequestReadChannelLengthError, MalformedReadResponseError, \
    NonEmptyReadResponseReservedValueError, NonEmptyReadResponseReserved2ValueError
from smb.v2.structures.file_id import FileId
from smb.v2.structures.dialect import Dialect
from smb.v2.structures.read_request_channel import ReadRequestChannel
from smb.v2.structures.read_request_flag import ReadRequestFlag


@dataclass
@register_smbv2_message
class ReadRequest(SMBv2RequestMessage, ABC):
    STRUCTURE_SIZE: ClassVar[int] = 49
    _reserved_flags_value: ClassVar[bytes] = b'\x00'
    _reserved_channel_value: ClassVar[bytes] = 4 * b'\x00'
    _reserved_read_channel_offset: ClassVar[bytes] = 2 * b'\x00'
    _reserved_read_channel_length: ClassVar[bytes] = 2 * b'\x00'

    _COMMAND: ClassVar[SMBv2Command] = SMBv2Command.SMB2_READ
    _dialect_to_class: ClassVar[Dict[Dialect, Type[ReadRequest]]] = {}
    _dialect: ClassVar[Dialect] = NotImplemented

    padding: int
    length: int
    offset: int
    file_id: FileId
    minimum_count: int
    remaining_bytes: int

    @classmethod
    def _from_bytes_and_header(cls, data: bytes, header: SMBv2Header) -> ReadRequest:
        body_bytes: bytes = data[len(header):]

        try:
            cls.check_STRUCTURE_SIZE(STRUCTURE_SIZE_to_test=struct_unpack('<H', body_bytes[:2])[0])
        except IncorrectStructureSizeError as e:
            raise MalformedReadRequestError(str(e)) from e

        read_request_base_args: Dict[str, Any] = dict(
            padding=struct_unpack('<B', body_bytes[2:3])[0],
            length=struct_unpack('<I', body_bytes[4:8])[0],
            offset=struct_unpack('<Q', body_bytes[8:16])[0],
            file_id=FileId.from_bytes(body_bytes[16:32]),
            minimum_count=struct_unpack('<I', body_bytes[32:36])[0],
            remaining_bytes=struct_unpack('<I', body_bytes[40:44])[0]
        )

        flags_raw: bytes = body_bytes[3:4]
        channel_raw: bytes = body_bytes[36:40]
        read_channel_info_offset_raw: bytes = body_bytes[44:46]
        read_channel_info_length_raw: bytes = body_bytes[46:48]

        if header.header_dialect in {Dialect.SMB_2_0_2, Dialect.SMB_2_1}:
            if flags_raw != cls._reserved_flags_value:
                raise InvalidReadRequestFlagError

            if channel_raw != cls._reserved_channel_value:
                raise InvalidReadRequestChannelError

            if read_channel_info_offset_raw != cls._reserved_read_channel_offset:
                raise InvalidReadRequestReadChannelInfoOffsetError

            if read_channel_info_length_raw != cls._reserved_read_channel_length:
                raise InvalidReadRequestReadChannelLengthError

            return cls._dialect_to_class[header.header_dialect](header=header, **read_request_base_args)

        read_channel_info_offset: int = struct_unpack('<H', read_channel_info_offset_raw)[0]
        read_channel_info_length: int = struct_unpack('<H', read_channel_info_length_raw)[0]
        read_channel_buffer: bytes = data[read_channel_info_offset:read_channel_info_offset + read_channel_info_length]
        channel = ReadRequestChannel(struct_unpack('<I', channel_raw)[0])

        if header.header_dialect is Dialect.SMB_3_0:
            if flags_raw != cls._reserved_flags_value:
                raise InvalidReadRequestFlagError
            return ReadRequest300(
                header=header,
                **read_request_base_args,
                read_channel_buffer=read_channel_buffer,
                channel=channel
            )

        try:
            flags = ReadRequestFlag.from_mask(struct_unpack('<B', body_bytes[3:4])[0])
        except ValueError as e:
            raise InvalidReadRequestFlagError from e

        if header.header_dialect in {Dialect.SMB_3_0_2, Dialect.SMB_3_1_1}:
            return cls._dialect_to_class[header.header_dialect](
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
            struct_pack('<H', self.STRUCTURE_SIZE),
            struct_pack('<B', self.padding),
            flags_bytes_value,
            struct_pack('<I', self.length),
            struct_pack('<Q', self.offset),
            bytes(self.file_id),
            struct_pack('<I', self.minimum_count),
            channel_bytes_value,
            struct_pack('<I', self.remaining_bytes),
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
            flags_bytes_value=self._reserved_flags_value,
            channel_bytes_value=self._reserved_channel_value,
            read_channel_offset_bytes_value=self._reserved_read_channel_offset,
            read_channel_length_bytes_value=self._reserved_read_channel_length,
            read_channel_buffer=b'\x00'
        )


@dataclass
class ReadRequest202(ReadRequest2X):
    _dialect: ClassVar[Dialect] = Dialect.SMB_2_0_2


@dataclass
class ReadRequest210(ReadRequest2X):
    _dialect: ClassVar[Dialect] = Dialect.SMB_2_1


@dataclass
class ReadRequest3X(ReadRequest, ABC):
    channel: ReadRequestChannel
    # TODO: Support the various structures as specified by channel.
    read_channel_buffer: bytes

    def __len__(self) -> int:
        return len(self.header) + (self.STRUCTURE_SIZE - 1) + len(self.read_channel_buffer)


@dataclass
class ReadRequest300(ReadRequest3X):
    _dialect: ClassVar[Dialect] = Dialect.SMB_3_0

    def __bytes__(self) -> bytes:
        return super()._to_bytes(
            flags_bytes_value=self._reserved_flags_value,
            channel_bytes_value=struct_pack('<I', self.channel.value),
            read_channel_offset_bytes_value=struct_pack('<H', self.STRUCTURE_SIZE - 1),
            read_channel_length_bytes_value=struct_pack('<H', len(self.read_channel_buffer)),
            read_channel_buffer=self.read_channel_buffer
        )


@dataclass
class ReadRequest302(ReadRequest3X):
    _dialect: ClassVar[Dialect] = Dialect.SMB_3_0_2
    flags: ReadRequestFlag

    def __bytes__(self) -> bytes:
        return super()._to_bytes(
            flags_bytes_value=struct_pack('<B', self.flags.to_mask()),
            channel_bytes_value=struct_pack('<I', self.channel.value),
            read_channel_offset_bytes_value=struct_pack('<H', self.STRUCTURE_SIZE - 1),
            read_channel_length_bytes_value=struct_pack('<H', len(self.read_channel_buffer)),
            read_channel_buffer=self.read_channel_buffer
        )


@dataclass
class ReadRequest311(ReadRequest3X):
    _dialect: ClassVar[Dialect] = Dialect.SMB_3_1_1
    flags: ReadRequestFlag

    def __bytes__(self) -> bytes:
        return super()._to_bytes(
            flags_bytes_value=struct_pack('<B', self.flags.to_mask()),
            channel_bytes_value=struct_pack('<I', self.channel.value),
            read_channel_offset_bytes_value=struct_pack('<H', self.STRUCTURE_SIZE - 1),
            read_channel_length_bytes_value=struct_pack('<H', len(self.read_channel_buffer)),
            read_channel_buffer=self.read_channel_buffer
        )


ReadRequest._dialect_to_class = {
    Dialect.SMB_2_0_2: ReadRequest202,
    Dialect.SMB_2_1: ReadRequest210,
    Dialect.SMB_3_0: ReadRequest300,
    Dialect.SMB_3_0_2: ReadRequest302,
    Dialect.SMB_3_1_1: ReadRequest311
}


@dataclass
@register_smbv2_message
class ReadResponse(SMBv2ResponseMessage):
    buffer: bytes
    data_remaining_length: int

    STRUCTURE_SIZE: ClassVar[int] = 17
    _COMMAND: ClassVar[SMBv2Command] = SMBv2Command.SMB2_READ
    _reserved: ClassVar[bytes] = b'\x00'
    _reserved_2: ClassVar[bytes] = 4 * b'\x00'

    @property
    def data_length(self) -> int:
        return len(self.buffer)

    @classmethod
    def _from_bytes_and_header(cls, data: bytes, header: SMBv2Header) -> ReadResponse:

        body_data = data[len(header):]

        try:
            cls.check_STRUCTURE_SIZE(STRUCTURE_SIZE_to_test=struct_unpack('<H', body_data[:2])[0])
        except IncorrectStructureSizeError as e:
            raise MalformedReadResponseError(str(e)) from e

        # TODO: The docs says that it should be ignored by the client; use strict mode?
        reserved = body_data[3:4]
        if reserved != cls._reserved:
            raise NonEmptyReadResponseReservedValueError(observed_reserved_value=reserved)

        reserved_2 = body_data[12:16]
        if reserved_2 != cls._reserved_2:
            raise NonEmptyReadResponseReserved2ValueError(observed_reserved_2_value=reserved_2)

        data_offset: int = struct_unpack('<B', body_data[2:3])[0]
        data_length: int = struct_unpack('<I', body_data[4:8])[0]

        return cls(
            header=header,
            data_remaining_length=struct_unpack('<I', body_data[8:12])[0],
            buffer=data[data_offset:data_offset+data_length]
        )

    def __bytes__(self) -> bytes:

        data_offset = len(self.header) + self.STRUCTURE_SIZE - 1

        return bytes(self.header) + b''.join([
            struct_pack('<H', self.STRUCTURE_SIZE),
            struct_pack('<B', data_offset),
            self._reserved,
            struct_pack('<I', len(self.buffer)),
            struct_pack('<I', self.data_remaining_length),
            self._reserved_2,
            self.buffer
        ])

    def __len__(self) -> int:
        return len(self.header) + (self.STRUCTURE_SIZE - 1) + len(self.buffer)
