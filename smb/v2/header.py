from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass
from struct import unpack as struct_unpack, pack as struct_pack
from typing import Dict, Union, Optional, ClassVar, Tuple, Type, Awaitable

from smb.header import Header as SMBHeaderBase
from smb.v2.structures.dialect import Dialect
from smb.v2.structures.ntstatus import NTSTATUS
from smb.v2.structures.smbv2_command import SMBv2Command
from smb.v2.structures.smbv2_flag import SMBv2Flag


@dataclass
class Header(SMBHeaderBase, ABC):
    STRUCTURE_SIZE: ClassVar[int] = 64
    PROTOCOL_IDENTIFIER: ClassVar[bytes] = b'\xfeSMB'
    _RESERVED: ClassVar[bytes] = bytes(4)
    _RESERVED_2: ClassVar[bytes] = bytes(2)
    _RESERVED_STATUS: ClassVar[bytes] = bytes(4)
    _RESERVED_CREDIT_CHARGE: ClassVar[bytes] = bytes(2)
    _EMPTY_SIGNATURE: ClassVar[bytes] = bytes(16)

    DIALECT: ClassVar[Dialect] = NotImplemented
    dialect_async_status_is_response_to_class: ClassVar[Dict[Tuple[Dialect, bool], Type[Header]]] = {}

    command: SMBv2Command
    session_id: int = 0
    flags: SMBv2Flag = SMBv2Flag()
    signature: bytes = _EMPTY_SIGNATURE
    message_id: Optional[int] = None
    # TODO: Arbitrary number. Reconsider.
    num_credits: int = 8192
    next_command_offset: int = 0

    @staticmethod
    def _base_from_bytes(data: bytes) -> Dict[str, Union[str, bytes, SMBv2Flag, SMBv2Command]]:
        structure_size = struct_unpack('<H', data[4:6])[0]
        if structure_size != Header.STRUCTURE_SIZE:
            # TODO: Use proper exception.
            raise ValueError

        return dict(
            command=SMBv2Command(struct_unpack('<H', data[12:14])[0]),
            num_credits=struct_unpack('<H', data[14:16])[0],
            flags=SMBv2Flag.from_int(struct_unpack('<I', data[16:20])[0]),
            next_command_offset=struct_unpack('<I', data[20:24])[0],
            message_id=struct_unpack('<Q', data[24:32])[0],
            session_id=struct_unpack('<Q', data[40:48])[0],
            signature=data[48:64]
        )

    @classmethod
    def from_dialect(cls, dialect: Dialect, async_status: bool, is_response: bool, **header_kwargs) -> Header:
        return cls.dialect_async_status_is_response_to_class[(dialect, async_status, is_response)](**header_kwargs)

    @classmethod
    def _from_bytes(cls, data: bytes, dialect: Dialect = Dialect.SMB_2_1) -> Header:
        flags = SMBv2Flag.from_int(struct_unpack('<I', data[16:20])[0])
        return cls.dialect_async_status_is_response_to_class[(dialect, flags.async_command, flags.server_to_redir)]._from_bytes(data=data, dialect=dialect)

    def __len__(self) -> int:
        return 64

    @abstractmethod
    def __bytes__(self) -> bytes:
        pass


@dataclass
class RequestHeader(Header, ABC):
    pass


@dataclass
class ResponseHeader(Header, ABC):
    status: NTSTATUS = Header._RESERVED_STATUS


@dataclass
class AsyncHeader(ResponseHeader, Header, ABC):
    async_id: int = 0

    def __post_init__(self):
        self.async_response_message_future: Optional[Awaitable[Message]] = None

    @property
    def async_key(self) -> Tuple[int, int]:
        return self.message_id, self.async_id

    @classmethod
    def _from_bytes(cls, data: bytes, dialect: Dialect = Dialect.SMB_2_1):

        header_kwargs: Dict[str, Union[bytes, int, SMBv2Flag, SMBv2Command, NTSTATUS]] = super()._base_from_bytes(data)
        # NOTE: I believe all async headers are in responses, thus all should have a `Status` field and consequently
        # no `ChannelSequnece` field.
        header_kwargs['status'] = NTSTATUS.from_bytes(data=data[8:12])
        header_kwargs['async_id'] = struct_unpack('<Q', data[36:44])[0]

        if Dialect.SMB_2_1 <= dialect <= dialect.SMB_3_1_1:
            header_kwargs['credit_charge'] = struct_unpack('<H', data[6:8])[0]

        return cls.dialect_async_status_is_response_to_class[(dialect, True, True)](**header_kwargs)

    def __bytes__(self) -> bytes:
        return b''.join([
            self.PROTOCOL_IDENTIFIER,
            struct_pack('<H', self.STRUCTURE_SIZE),
            (
                self._RESERVED_CREDIT_CHARGE if isinstance(self, SMB202AsyncHeader)
                else struct_pack('<H', getattr(self, 'credit_charge'))
            ),
            bytes(self.status),
            struct_pack('<H', self.command.value),
            struct_pack('<H', self.num_credits),
            struct_pack('<I', int(self.flags)),
            struct_pack('<I', self.next_command_offset),
            struct_pack('<Q', self.message_id),
            struct_pack('<Q', self.async_id),
            struct_pack('<Q', self.session_id),
            self.signature
        ])


@dataclass
class SyncHeader(Header, ABC):
    tree_id: int = 0

    @classmethod
    def _from_bytes(cls, data: bytes, dialect: Dialect = Dialect.SMB_2_1):

        header_kwargs: Dict[str, Union[bytes, int, SMBv2Flag, SMBv2Command, NTSTATUS]] = cls._base_from_bytes(data=data)
        header_kwargs['tree_id'] = struct_unpack('<I', data[36:40])[0]

        # TODO Not sure if this is the case which should be used when the wildcard dialect is used
        #   but it appears to be used in the protocol examples in the docs (credit charge present)
        if Dialect.SMB_2_1 <= dialect <= Dialect.SMB_3_1_1 or dialect is Dialect.SMB_2_WILDCARD:
            header_kwargs['credit_charge'] = struct_unpack('<H', data[6:8])[0]

        is_response: bool = header_kwargs['flags'].server_to_redir

        if is_response:
            header_kwargs['status'] = NTSTATUS.from_bytes(data=data[8:12])
        elif Dialect.SMB_3_0 <= dialect <= Dialect.SMB_3_1_1:
            header_kwargs['channel_sequence'] = data[8:10]

        return cls.dialect_async_status_is_response_to_class[(dialect, False, is_response)](**header_kwargs)

    def __bytes__(self) -> bytes:

        if isinstance(self, ResponseHeader):
            chunk: bytes = bytes(self.status)
        elif isinstance(self, SMB3XSyncHeader) and isinstance(self, RequestHeader):
            chunk: bytes = getattr(self, 'channel_sequence')
        else:
            chunk: bytes = self._RESERVED_STATUS

        return b''.join([
            self.PROTOCOL_IDENTIFIER,
            struct_pack('<H', self.STRUCTURE_SIZE),
            (
                self._RESERVED_CREDIT_CHARGE if isinstance(self, SMB202SyncRequestHeader)
                else struct_pack('<H', getattr(self, 'credit_charge'))
            ),
            chunk,
            struct_pack('<H', self.command.value),
            struct_pack('<H', self.num_credits),
            struct_pack('<I', int(self.flags)),
            struct_pack('<I', self.next_command_offset),
            struct_pack('<Q', self.message_id),
            self._RESERVED,
            struct_pack('<I', self.tree_id),
            struct_pack('<Q', self.session_id),
            self.signature
        ])


@dataclass
class SMB2XSyncHeader(SyncHeader, ABC):
    credit_charge: int = 1


@dataclass
class SMB202SyncRequestHeader(RequestHeader, SMB2XSyncHeader):
    DIALECT: ClassVar[Dialect] = Dialect.SMB_2_0_2


@dataclass
class SMB202SyncResponseHeader(ResponseHeader, SMB2XSyncHeader):
    DIALECT: ClassVar[Dialect] = Dialect.SMB_2_0_2


@dataclass
class SMB210SyncRequestHeader(RequestHeader, SMB2XSyncHeader):
    credit_charge: int = 1
    DIALECT: ClassVar[Dialect] = Dialect.SMB_2_1


@dataclass
class SMB210SyncResponseHeader(ResponseHeader, SMB2XSyncHeader):
    credit_charge: int = 1
    DIALECT: ClassVar[Dialect] = Dialect.SMB_2_1


@dataclass
class SMB3XSyncHeader(SyncHeader, ABC):
    credit_charge: int = 1


@dataclass
class SMB300SyncRequestHeader(RequestHeader, SMB3XSyncHeader):
    DIALECT: ClassVar[Dialect] = Dialect.SMB_3_0
    channel_sequence: bytes = b'\x00\x00'


@dataclass
class SMB300SyncResponseHeader(ResponseHeader, SMB3XSyncHeader):
    DIALECT: ClassVar[Dialect] = Dialect.SMB_3_0


@dataclass
class SMB302SyncRequestHeader(RequestHeader, SMB3XSyncHeader):
    DIALECT: ClassVar[Dialect] = Dialect.SMB_3_0_2
    channel_sequence: bytes = b'\x00\x00'


@dataclass
class SMB302SyncResponseHeader(ResponseHeader, SMB3XSyncHeader):
    DIALECT: ClassVar[Dialect] = Dialect.SMB_3_0_2


@dataclass
class SMB311SyncRequestHeader(RequestHeader, SMB3XSyncHeader):
    DIALECT: ClassVar[Dialect] = Dialect.SMB_3_1_1
    channel_sequence: bytes = b'\x00\x00'


@dataclass
class SMB311SyncResponseHeader(ResponseHeader, SMB3XSyncHeader):
    DIALECT: ClassVar[Dialect] = Dialect.SMB_3_1_1


@dataclass
class SMB202AsyncHeader(AsyncHeader):
    DIALECT: ClassVar[Dialect] = Dialect.SMB_2_0_2


@dataclass
class SMB210AsyncHeader(AsyncHeader):
    credit_charge: int = 1
    DIALECT: ClassVar[Dialect] = Dialect.SMB_2_1


@dataclass
class SMB3XAsyncHeader(AsyncHeader, ABC):
    credit_charge: int = 1
    channel_sequence: bytes = b'\x00\x00'


@dataclass
class SMB300AsyncHeader(SMB3XAsyncHeader):
    DIALECT: ClassVar[Dialect] = Dialect.SMB_3_0


@dataclass
class SMB302AsyncHeader(SMB3XAsyncHeader):
    DIALECT: ClassVar[Dialect] = Dialect.SMB_3_0_2


@dataclass
class SMB311AsyncHeader(SMB3XAsyncHeader):
    DIALECT: ClassVar[Dialect] = Dialect.SMB_3_1_1


Header.dialect_async_status_is_response_to_class = {
    (Dialect.SMB_2_0_2, False, False): SMB202SyncRequestHeader,
    (Dialect.SMB_2_0_2, False, True): SMB202SyncResponseHeader,
    (Dialect.SMB_2_0_2, True, True): SMB202AsyncHeader,

    (Dialect.SMB_2_1, False, False): SMB210SyncRequestHeader,
    (Dialect.SMB_2_1, False, True): SMB210SyncResponseHeader,
    (Dialect.SMB_2_1, True, True): SMB210AsyncHeader,

    (Dialect.SMB_3_0, False, False): SMB300SyncRequestHeader,
    (Dialect.SMB_3_0, False, True): SMB300SyncRequestHeader,
    (Dialect.SMB_3_0, True, True): SMB300AsyncHeader,

    (Dialect.SMB_3_0_2, False, False): SMB302SyncRequestHeader,
    (Dialect.SMB_3_0_2, False, True): SMB302SyncResponseHeader,
    (Dialect.SMB_3_0_2, True, True): SMB302AsyncHeader,

    (Dialect.SMB_3_1_1, False, False): SMB311SyncRequestHeader,
    (Dialect.SMB_3_1_1, False, True): SMB311SyncResponseHeader,
    (Dialect.SMB_3_1_1, True, True): SMB311AsyncHeader
}
