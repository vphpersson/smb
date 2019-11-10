from __future__ import annotations
from dataclasses import dataclass
from typing import ClassVar, Dict, Any
from struct import pack as struct_pack, unpack as struct_unpack
from enum import IntEnum, IntFlag
from abc import ABC

from smb.v2.smbv2_message import SMBv2Message, register_smbv2_message
from smb.v2.smbv2_header import SMBv2Header, SMB202SyncHeader, SMB202AsyncHeader, SMB210SyncHeader, \
    SMB210AsyncHeader, SMB300SyncHeader, SMB300AsyncHeader, SMB302SyncHeader, SMB302AsyncHeader, SMB311SyncHeader, \
    SMB311AsyncHeader, SMBv2Command
from smb.exceptions import IncorrectStructureSizeError, MalformedReadRequestError, InvalidReadRequestFlagError,\
    InvalidReadRequestChannelError, InvalidReadRequestReadChannelInfoOffsetError,\
    InvalidReadRequestReadChannelLengthError
from smb.v2.file_id import FileId
from smb.smb_message import SMBRequestMessage

from msdsalgs.utils import make_mask_class


class ReadRequestFlagMask(IntFlag):
    SMB2_READFLAG_READ_UNBUFFERED = 0x01,
    SMB2_READFLAG_REQUEST_COMPRESSED = 0x02


ReadRequestFlag = make_mask_class(ReadRequestFlagMask, prefix='SMB2_READFLAG_')


class ReadRequestChannel(IntEnum):
    SMB2_CHANNEL_NONE = 0x00000000,
    SMB2_CHANNEL_RDMA_V1 = 0x00000001,
    SMB2_CHANNEL_RDMA_V1_INVALIDATE = 0x00000002


@dataclass
@register_smbv2_message
class ReadRequest(SMBv2Message, SMBRequestMessage, ABC):

    padding: int
    length: int
    offset: int
    file_id: FileId
    minimum_count: int
    remaining_bytes: int

    structure_size: ClassVar[int] = 49
    _command: ClassVar[SMBv2Command] = SMBv2Command.SMB2_READ
    _reserved_flags_value: ClassVar[bytes] = b'\x00'

    @classmethod
    def _from_bytes_and_header(cls, data: bytes, header: SMBv2Header) -> ReadRequest:
        body_bytes: bytes = data[len(header):]

        try:
            cls.check_structure_size(structure_size_to_test=struct_unpack('<H', body_bytes[:2])[0])
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

        flags_value: int = struct_unpack('<B', body_bytes[3:4])[0]
        channel_value: int = struct_unpack('<I', body_bytes[36:40])[0]
        read_channel_info_offset: int = struct_unpack('<H', body_bytes[44:46])[0]
        read_channel_info_length: int = struct_unpack('<H', body_bytes[46:48])[0]

        if isinstance(header, (SMB202SyncHeader, SMB202AsyncHeader)):
            if flags_value != 0x00:
                raise InvalidReadRequestFlagError

            if channel_value != 0x00:
                raise InvalidReadRequestChannelError

            if read_channel_info_offset != 0x00:
                raise InvalidReadRequestReadChannelInfoOffsetError

            if read_channel_info_length != 0x00:
                raise InvalidReadRequestReadChannelLengthError

            return ReadRequest202(header=header, **read_request_base_args)

        if isinstance(header, (SMB210SyncHeader, SMB210AsyncHeader)):
            if flags_value != 0x00:
                raise InvalidReadRequestFlagError

            if channel_value != 0x00:
                raise InvalidReadRequestChannelError

            return ReadRequest210(header=header, **read_request_base_args)

        read_channel_buffer = data[read_channel_info_offset:read_channel_info_offset + read_channel_info_length]

        if isinstance(header, (SMB300SyncHeader, SMB300AsyncHeader)):
            if flags_value != 0x00:
                raise InvalidReadRequestFlagError
            return ReadRequest300(header=header, **read_request_base_args, read_channel_buffer=read_channel_buffer)

        try:
            flags = ReadRequestFlag.from_mask(flags_value)
        except ValueError as e:
            raise InvalidReadRequestFlagError from e

        if isinstance(header, (SMB302SyncHeader, SMB302AsyncHeader)):
            return ReadRequest302(
                header=header,
                **read_request_base_args,
                read_channel_buffer=read_channel_buffer,
                flags=flags
            )

        if isinstance(header, (SMB311SyncHeader, SMB311AsyncHeader)):
            return ReadRequest311(
                header=header,
                **read_request_base_args,
                read_channel_buffer=read_channel_buffer,
                flags=flags
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
            struct_pack('<H', self.structure_size),
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
    _reserved_channel_value: ClassVar[bytes] = 4 * b'\x00'
    _reserved_read_channel_offset: ClassVar[bytes] = 2 * b'\x00'
    _reserved_read_channel_length: ClassVar[bytes] = 2 * b'\x00'

    def __len__(self) -> int:
        return len(self.header) + self.structure_size

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
    pass


@dataclass
class ReadRequest210(ReadRequest2X):
    pass


@dataclass
class ReadRequest3X(ReadRequest, ABC):
    channel: ReadRequestChannel
    # TODO: Support the various structures as specified by channel.
    read_channel_buffer: bytes

    def __len__(self) -> int:
        return len(self.header) + (self.structure_size - 1) + len(self.read_channel_buffer)


@dataclass
class ReadRequest300(ReadRequest3X):

    def __bytes__(self) -> bytes:
        return super()._to_bytes(
            flags_bytes_value=self._reserved_flags_value,
            channel_bytes_value=struct_pack('<I', self.channel.value),
            read_channel_offset_bytes_value=struct_pack('<H', self.structure_size - 1),
            read_channel_length_bytes_value=struct_pack('<H', len(self.read_channel_buffer)),
            read_channel_buffer=self.read_channel_buffer
        )


@dataclass
class ReadRequest302(ReadRequest3X):
    flags: ReadRequestFlag

    def __bytes__(self) -> bytes:
        return super()._to_bytes(
            flags_bytes_value=struct_pack('<B', self.flags.to_mask()),
            channel_bytes_value=struct_pack('<I', self.channel.value),
            read_channel_offset_bytes_value=struct_pack('<H', self.structure_size - 1),
            read_channel_length_bytes_value=struct_pack('<H', len(self.read_channel_buffer)),
            read_channel_buffer=self.read_channel_buffer
        )


@dataclass
class ReadRequest311(ReadRequest3X):
    flags: ReadRequestFlag

    def __bytes__(self) -> bytes:
        return super()._to_bytes(
            flags_bytes_value=struct_pack('<B', self.flags.to_mask()),
            channel_bytes_value=struct_pack('<I', self.channel.value),
            read_channel_offset_bytes_value=struct_pack('<H', self.structure_size - 1),
            read_channel_length_bytes_value=struct_pack('<H', len(self.read_channel_buffer)),
            read_channel_buffer=self.read_channel_buffer
        )
