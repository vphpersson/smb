from __future__ import annotations
from dataclasses import dataclass
from typing import ClassVar, Optional, Dict, Type
from struct import pack as struct_pack, unpack as struct_unpack
from abc import ABC

from smb.v2.messages.message_base import SMBv2RequestMessage, SMBv2ResponseMessage, register_smbv2_message
from smb.v2.header import SMBv2Header, SMBv2Command, SMB2XSyncHeader, SMB3XSyncHeader, Dialect
from smb.exceptions import IncorrectStructureSizeError
from smb.v2.structures.file_id import FileId
from smb.v2.structures.write_flag import WriteFlag


@dataclass
@register_smbv2_message
class WriteRequest(SMBv2RequestMessage, ABC):
    # TODO: Actual size is 48. Must the buffer contain at least one byte?
    STRUCTURE_SIZE: ClassVar[int] = 49

    _COMMAND: ClassVar[SMBv2Command] = SMBv2Command.SMB2_WRITE
    _dialect_to_class: ClassVar[Dict[Dialect, Type[WriteRequest]]] = {}

    _reserved_channel: ClassVar[bytes] = 4 * b'\x00'
    _reserved_write_channel_offset: ClassVar[bytes] = 2 * b'\x00'
    _reserved_write_channel_length: ClassVar[bytes] = 2 * b'\x00'

    write_data: bytes
    offset: int
    file_id: FileId
    # TODO: Let this be the size of `write_data` by default? post init?
    remaining_bytes: int
    flags: WriteFlag

    @classmethod
    def _from_bytes_and_header(cls, data: bytes, header: SMBv2Header) -> WriteRequest:
        body_bytes: bytes = data[len(header):]

        try:
            cls.check_STRUCTURE_SIZE(STRUCTURE_SIZE_to_test=struct_unpack('<H', body_bytes[:2])[0])
        except IncorrectStructureSizeError as e:
            ...

        data_offset: int = struct_unpack('<H', body_bytes[2:4])[0]
        length: int = struct_unpack('<I', body_bytes[4:8])[0]
        offset: int = struct_unpack('<Q', body_bytes[8:16])[0]
        file_id: FileId = FileId.from_bytes(data=body_bytes[16:32])
        channel: bytes = body_bytes[32:36]
        remaining_bytes: int = struct_unpack('<I', body_bytes[36:40])[0]
        write_channel_info_offset_raw: bytes = body_bytes[40:42]
        write_channel_info_length_raw: bytes = body_bytes[42:44]
        flags = WriteFlag.from_mask(struct_unpack('<I', body_bytes[44:48])[0])

        write_data: bytes = data[data_offset:data_offset + length]

        if isinstance(header, SMB2XSyncHeader):
            if channel != cls._reserved_channel:
                # TODO: Use proper exception.
                raise ValueError

            if write_channel_info_offset_raw != cls._reserved_write_channel_offset:
                # TODO: Use proper exception.
                raise ValueError

            if write_channel_info_length_raw != cls._reserved_write_channel_length:
                # TODO: Use proper exception.
                raise ValueError

            return cls._dialect_to_class[header.header_dialect](
                write_data=write_data,
                offset=offset,
                file_id=file_id,
                remaining_bytes=remaining_bytes,
                flags=flags
            )
        elif isinstance(header, SMB3XSyncHeader):
            write_channel_info_offset: int = struct_unpack('<H', write_channel_info_offset_raw)[0]
            write_channel_info_length: int = struct_unpack('<H', write_channel_info_length_raw)[0]

            return cls._dialect_to_class[header.header_dialect](
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
            channel_bytes if channel_bytes is not None else self._reserved_channel,
            struct_pack('<I', self.remaining_bytes),
            struct_pack('<H', write_channel_info_offset),
            struct_pack('<H', write_channel_info_length),
            struct_pack('<I', self.flags.to_mask()),
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


WriteRequest._dialect_to_class = {
    Dialect.SMB_2_0_2: WriteRequest202,
    Dialect.SMB_2_1: WriteRequest210,
    Dialect.SMB_3_0: WriteRequest300,
    Dialect.SMB_3_0_2: WriteRequest302,
    Dialect.SMB_3_1_1: WriteRequest311
}


@dataclass
@register_smbv2_message
class WriteResponse(SMBv2ResponseMessage):

    STRUCTURE_SIZE: ClassVar[int] = 17

    _COMMAND: ClassVar[SMBv2Command] = SMBv2Command.SMB2_WRITE

    _reserved: ClassVar[bytes] = bytes(2)
    _reserved_remaining: ClassVar[bytes] = bytes(4)
    _reserved_write_channel_info_offset: ClassVar[bytes] = bytes(2)
    _reserved_write_channel_info_length: ClassVar[bytes] = bytes(2)

    count: int

    @classmethod
    def _from_bytes_and_header(cls, data: bytes, header: SMBv2Header) -> WriteResponse:
        body_bytes: bytes = data[len(header):]

        try:
            cls.check_STRUCTURE_SIZE(STRUCTURE_SIZE_to_test=struct_unpack('<H', body_bytes[:2])[0])
        except IncorrectStructureSizeError as e:
            ...

        reserved_bytes: bytes = body_bytes[2:4]
        if reserved_bytes != cls._reserved:
            # TODO: Use proper exception.
            raise ValueError

        remaining_bytes: bytes = body_bytes[8:12]
        if remaining_bytes != cls._reserved_remaining:
            # TODO: Use proper exception.
            raise ValueError

        write_channel_info_offset_bytes: bytes = body_bytes[12:14]
        if write_channel_info_offset_bytes != cls._reserved_write_channel_info_offset:
            # TODO: Use proper exception.
            raise ValueError

        write_channel_info_length_bytes: bytes = body_bytes[14:16]
        if write_channel_info_length_bytes != cls._reserved_write_channel_info_length:
            # TODO: Use proper exception.
            raise ValueError

        return cls(header=header, count=struct_unpack('<I', body_bytes[4:8])[0])

    def __bytes__(self) -> bytes:
        return bytes(self.header) + b''.join([
            struct_pack('<H', self.STRUCTURE_SIZE),
            self._reserved,
            struct_pack('<I', self.count),
            self._reserved_remaining,
            self._reserved_write_channel_info_offset,
            self._reserved_write_channel_info_length
        ])

    def __len__(self) -> int:
        return self.header.STRUCTURE_SIZE + self.STRUCTURE_SIZE
