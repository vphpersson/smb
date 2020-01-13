from __future__ import annotations
from abc import ABC, abstractmethod
from enum import IntEnum, IntFlag
from dataclasses import dataclass
from struct import unpack as struct_unpack, pack as struct_pack
from typing import Dict, Union, Optional, ClassVar, Tuple, Type, Awaitable

from smb.protocol_identifier import ProtocolIdentifier
from smb.smb_header import SMBHeader
from smb.v2.dialect import Dialect
from smb.v2.ntstatus import NTSTATUS

from msdsalgs.utils import make_mask_class


class SMBv2Command(IntEnum):
    SMB2_NEGOTIATE = 0x0000
    SMB2_SESSION_SETUP = 0x0001
    SMB2_LOGOFF = 0x0002
    SMB2_TREE_CONNECT = 0x0003
    SMB2_TREE_DISCONNECT = 0x0004
    SMB2_CREATE = 0x0005
    SMB2_CLOSE = 0x0006
    SMB2_FLUSH = 0x0007
    SMB2_READ = 0x0008
    SMB2_WRITE = 0x0009
    SMB2_LOCK = 0x000A
    SMB2_IOCTL = 0x000B
    SMB2_CANCEL = 0x000C
    SMB2_ECHO = 0x000D
    SMB2_QUERY_DIRECTORY = 0x000E
    SMB2_CHANGE_NOTIFY = 0x000F
    SMB2_QUERY_INFO = 0x0010
    SMB2_SET_INFO = 0x0011
    SMB2_OPLOCK_BREAK = 0x0012


class SMBv2FlagMask(IntFlag):
    SMB2_FLAGS_SERVER_TO_REDIR = 0x00000001
    SMB2_FLAGS_ASYNC_COMMAND = 0x00000002
    SMB2_FLAGS_RELATED_OPERATIONS = 0x00000004
    SMB2_FLAGS_SIGNED = 0x00000008
    SMB2_FLAGS_PRIORITY_MASK = 0x00000070
    SMB2_FLAGS_DFS_OPERATIONS = 0x10000000
    SMB2_FLAGS_REPLAY_OPERATION = 0x20000000


SMBv2Flag = make_mask_class(SMBv2FlagMask, prefix='SMB2_FLAGS_')


@dataclass
class SMBv2Header(SMBHeader, ABC):
    structure_size: ClassVar[int] = 64
    protocol_identifier: ClassVar[ProtocolIdentifier] = ProtocolIdentifier.SMB_VERSION_2
    _reserved: ClassVar[bytes] = bytes(4)
    _reserved_2: ClassVar[bytes] = bytes(2)
    _reserved_status: ClassVar[bytes] = bytes(4)
    _reserved_credit_change: ClassVar[bytes] = bytes(2)
    _empty_signature: ClassVar[bytes] = bytes(16)

    header_dialect: ClassVar[Dialect] = NotImplemented
    dialect_async_status_is_response_to_class: ClassVar[Dict[Tuple[Dialect, bool], Type[SMBv2Header]]] = {}

    command: SMBv2Command
    session_id: int = 0
    flags: SMBv2Flag = SMBv2Flag()
    signature: bytes = _empty_signature
    message_id: Optional[int] = None
    # TODO: Arbitrary number. Reconsider.
    num_credits: int = 8192
    next_command_offset: int = 0

    @staticmethod
    def _base_from_bytes(data: bytes) -> Dict[str, Union[str, bytes, SMBv2Flag, SMBv2Command]]:
        structure_size = struct_unpack('<H', data[4:6])[0]
        if structure_size != SMBv2Header.structure_size:
            # TODO: Use proper exception.
            raise ValueError

        return dict(
            command=SMBv2Command(struct_unpack('<H', data[12:14])[0]),
            num_credits=struct_unpack('<H', data[14:16])[0],
            flags=SMBv2Flag.from_mask(struct_unpack('<I', data[16:20])[0]),
            next_command_offset=struct_unpack('<I', data[20:24])[0],
            message_id=struct_unpack('<Q', data[24:32])[0],
            session_id=struct_unpack('<Q', data[40:48])[0],
            signature=data[48:64]
        )

    @classmethod
    def from_dialect(cls, dialect: Dialect, async_status: bool, is_response: bool, **header_kwargs) -> SMBv2Header:
        return cls.dialect_async_status_is_response_to_class[(dialect, async_status, is_response)](**header_kwargs)

    @classmethod
    def _from_bytes(cls, data: bytes, dialect: Dialect = Dialect.SMB_2_1) -> SMBv2Header:
        flags = SMBv2Flag.from_mask(struct_unpack('<I', data[16:20])[0])
        return cls.dialect_async_status_is_response_to_class[
            (dialect, flags.async_command, flags.server_to_redir)
        ]._from_bytes(data=data, dialect=dialect)

    def __len__(self) -> int:
        return 64

    @abstractmethod
    def __bytes__(self) -> bytes:
        pass


@dataclass
class SMBv2RequestHeader(SMBv2Header, ABC):
    pass


@dataclass
class SMBv2ResponseHeader(SMBv2Header, ABC):
    status: NTSTATUS = SMBv2Header._reserved_status


@dataclass
class SMBv2AsyncHeader(SMBv2ResponseHeader, SMBv2Header, ABC):
    async_id: int = 0

    def __post_init__(self):
        self.async_response_message_future: Optional[Awaitable[SMBv2Message]] = None

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
            SMBv2Header.protocol_identifier.value,
            struct_pack('<H', self.structure_size),
            (
                self._reserved_credit_change if isinstance(self, SMB202AsyncHeader)
                else struct_pack('<H', getattr(self, 'credit_charge'))
            ),
            bytes(self.status),
            struct_pack('<H', self.command.value),
            struct_pack('<H', self.num_credits),
            struct_pack('<I', self.flags.to_mask()),
            struct_pack('<I', self.next_command_offset),
            struct_pack('<Q', self.message_id),
            struct_pack('<Q', self.async_id),
            struct_pack('<Q', self.session_id),
            self.signature
        ])


@dataclass
class SMBv2SyncHeader(SMBv2Header, ABC):
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

        if isinstance(self, SMBv2ResponseHeader):
            chunk: bytes = bytes(self.status)
        elif isinstance(self, SMB3XSyncHeader) and isinstance(self, SMBv2RequestHeader):
            chunk: bytes = getattr(self, 'channel_sequence')
        else:
            chunk: bytes = self._reserved_status

        return b''.join([
            SMBv2Header.protocol_identifier.value,
            struct_pack('<H', self.structure_size),
            (
                self._reserved_credit_change if isinstance(self, SMB202SyncRequestHeader)
                else struct_pack('<H', getattr(self, 'credit_charge'))
            ),
            chunk,
            struct_pack('<H', self.command.value),
            struct_pack('<H', self.num_credits),
            struct_pack('<I', self.flags.to_mask()),
            struct_pack('<I', self.next_command_offset),
            struct_pack('<Q', self.message_id),
            self._reserved,
            struct_pack('<I', self.tree_id),
            struct_pack('<Q', self.session_id),
            self.signature
        ])


@dataclass
class SMB2XSyncHeader(SMBv2SyncHeader, ABC):
    credit_charge: int = 1


@dataclass
class SMB202SyncRequestHeader(SMBv2RequestHeader, SMB2XSyncHeader):
    header_dialect: ClassVar[Dialect] = Dialect.SMB_2_0_2


@dataclass
class SMB202SyncResponseHeader(SMBv2ResponseHeader, SMB2XSyncHeader):
    header_dialect: ClassVar[Dialect] = Dialect.SMB_2_0_2


@dataclass
class SMB210SyncRequestHeader(SMBv2RequestHeader, SMB2XSyncHeader):
    credit_charge: int = 1
    header_dialect: ClassVar[Dialect] = Dialect.SMB_2_1


@dataclass
class SMB210SyncResponseHeader(SMBv2ResponseHeader, SMB2XSyncHeader):
    credit_charge: int = 1
    header_dialect: ClassVar[Dialect] = Dialect.SMB_2_1


@dataclass
class SMB3XSyncHeader(SMBv2SyncHeader, ABC):
    credit_charge: int = 1


@dataclass
class SMB300SyncRequestHeader(SMBv2RequestHeader, SMB3XSyncHeader):
    header_dialect: ClassVar[Dialect] = Dialect.SMB_3_0
    channel_sequence: bytes = b'\x00\x00'


@dataclass
class SMB300SyncResponseHeader(SMBv2ResponseHeader, SMB3XSyncHeader):
    header_dialect: ClassVar[Dialect] = Dialect.SMB_3_0


@dataclass
class SMB302SyncRequestHeader(SMBv2RequestHeader, SMB3XSyncHeader):
    header_dialect: ClassVar[Dialect] = Dialect.SMB_3_0_2
    channel_sequence: bytes = b'\x00\x00'


@dataclass
class SMB302SyncResponseHeader(SMBv2ResponseHeader, SMB3XSyncHeader):
    header_dialect: ClassVar[Dialect] = Dialect.SMB_3_0_2


@dataclass
class SMB311SyncRequestHeader(SMBv2RequestHeader, SMB3XSyncHeader):
    header_dialect: ClassVar[Dialect] = Dialect.SMB_3_1_1
    channel_sequence: bytes = b'\x00\x00'


@dataclass
class SMB311SyncResponseHeader(SMBv2ResponseHeader, SMB3XSyncHeader):
    header_dialect: ClassVar[Dialect] = Dialect.SMB_3_1_1


@dataclass
class SMB202AsyncHeader(SMBv2AsyncHeader):
    header_dialect: ClassVar[Dialect] = Dialect.SMB_2_0_2


@dataclass
class SMB210AsyncHeader(SMBv2AsyncHeader):
    credit_charge: int = 1
    header_dialect: ClassVar[Dialect] = Dialect.SMB_2_1


@dataclass
class SMB3XAsyncHeader(SMBv2AsyncHeader, ABC):
    credit_charge: int = 1
    channel_sequence: bytes = b'\x00\x00'


@dataclass
class SMB300AsyncHeader(SMB3XAsyncHeader):
    header_dialect: ClassVar[Dialect] = Dialect.SMB_3_0


@dataclass
class SMB302AsyncHeader(SMB3XAsyncHeader):
    header_dialect: ClassVar[Dialect] = Dialect.SMB_3_0_2


@dataclass
class SMB311AsyncHeader(SMB3XAsyncHeader):
    header_dialect: ClassVar[Dialect] = Dialect.SMB_3_1_1


SMBv2Header.dialect_async_status_is_response_to_class = {
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
