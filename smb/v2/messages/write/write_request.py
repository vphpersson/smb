from __future__ import annotations
from dataclasses import dataclass
from typing import ClassVar, Optional
from struct import pack as struct_pack, unpack as struct_unpack
from enum import IntFlag
from abc import ABC

from smb.smb_message import SMBRequestMessage
from smb.v2.smbv2_message import SMBv2Message, register_smbv2_message
from smb.v2.smbv2_header import SMBv2Header, SMBv2Command, SMB2XSyncHeader, SMB3XSyncHeader
from smb.v2.file_id import FileId
from smb.exceptions import IncorrectStructureSizeError
from smb.v2.messages.read.read_request import ReadRequestChannel

from msdsalgs.utils import make_mask_class


class WriteFlagMask(IntFlag):
    SMB2_WRITEFLAG_NONE = 0x00000000
    SMB2_WRITEFLAG_WRITE_THROUGH = 0x00000001
    SMB2_WRITEFLAG_WRITE_UNBUFFERED = 0x00000002


WriteFlag = make_mask_class(WriteFlagMask, prefix='SMB2_WRITEFLAG_')


@dataclass
class WriteRequest(SMBv2Message, SMBRequestMessage, ABC):

    length: int
    offset: int
    file_id: FileId
    remaining_bytes: int
    flags: WriteFlag

    structure_size: ClassVar[int] = 49
    _command: ClassVar[SMBv2Command] = SMBv2Command.SMB2_WRITE

    @classmethod
    def _from_bytes_and_header(cls, data: bytes, header: SMBv2Header) -> WriteRequest:
        body_bytes: bytes = data[len(header):]

        try:
            cls.check_structure_size(structure_size_to_test=struct_unpack('<H', body_bytes[:2])[0])
        except IncorrectStructureSizeError as e:
            ...

        data_offset: int = struct_unpack('<H', body_bytes[2:4])[0]
        length: int = struct_unpack('<I', body_bytes[4:8])[0]
        offset: int = struct_unpack('<Q', body_bytes[8:16])[0]
        file_id: FileId = FileId.from_bytes(data=body_bytes[16:32])
        channel: bytes = body_bytes[32:36]
        remaining_bytes: int = struct_unpack('<I', body_bytes[36:40])[0]
        write_channel_info_offset: int = struct_unpack('<H', body_bytes[40:42])[0]
        write_channel_info_len: int = struct_unpack('<H', body_bytes[42:44])[0]
        flags = WriteFlag.from_mask(struct_unpack('<I', body_bytes[44:48])[0])

        if isinstance(header, SMB2XSyncHeader):
            ...







@dataclass
class WriteRequest2X(WriteRequest, ABC):
    _reserved_channel_value: ClassVar[bytes] = 4 * b'\x00'
    _reserved_read_channel_offset: ClassVar[bytes] = 2 * b'\x00'
    _reserved_read_channel_length: ClassVar[bytes] = 2 * b'\x00'

    def __bytes__(self) -> bytes:
        ...




@dataclass
class WriteRequest3X(WriteRequest, ABC):
    ...

