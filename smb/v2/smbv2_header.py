from __future__ import annotations
from abc import ABC, abstractmethod
from enum import IntEnum, IntFlag
from dataclasses import dataclass
from struct import unpack as struct_unpack, pack as struct_pack
from typing import Dict, Union, Optional, ClassVar

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
    EMPTY_SIGNATURE: ClassVar[bytes] = 16 * b'\x00'
    EMPTY_STATUS: ClassVar[bytes] = 4 * b'\x00'
    _reserved: ClassVar[bytes] = 4 * b'\x00'

    command: SMBv2Command
    session_id: int = 0
    flags: SMBv2Flag = SMBv2Flag()
    signature: bytes = EMPTY_SIGNATURE
    message_id: Optional[int] = None
    num_credits: int = 8192
    next_command_offset: int = 0

    @staticmethod
    def _base_from_bytes(data: bytes) -> Dict[str, Union[str, bytes]]:
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
    def _from_bytes(cls, data: bytes, dialect: Dialect = Dialect.SMB_2_1) -> SMBv2Header:

        flags = SMBv2Flag.from_mask(struct_unpack('<I', data[16:20])[0])
        if flags.async_command:
            ...
        else:
            return SMBv2SyncHeader._from_bytes(data=data, dialect=dialect)

    def __len__(self) -> int:
        return 64

    @abstractmethod
    def __bytes__(self) -> bytes:
        pass


@dataclass
class SMBv2SyncHeader(SMBv2Header):
    tree_id: int = 0

    @classmethod
    def _from_bytes(cls, data: bytes, dialect: Dialect = Dialect.SMB_2_1):

        base_kwargs: Dict[str, Union[bytes, int]] = super()._base_from_bytes(data)
        base_kwargs['tree_id'] = struct_unpack('<I', data[36:40])[0]

        if dialect == Dialect.SMB_2_0_2:
            return SMB202SyncHeader(
                status=NTSTATUS.from_bytes(data=data[8:12]) if data[8:12] != cls.EMPTY_STATUS else None,
                **base_kwargs
            )

        credit_charge = struct_unpack('<H', data[6:8])[0]

        # TODO Not sure if this is the case which should be used when the wildcard dialect is used
        #   but it appears to be used in the protocol examples in the docs (credit charge present)
        if dialect in {Dialect.SMB_2_1, Dialect.SMB_2_WILDCARD}:
            return SMB210SyncHeader(
                status=NTSTATUS.from_bytes(data=data[8:12]) if data[8:12] != cls.EMPTY_STATUS else None,
                credit_charge=credit_charge,
                **base_kwargs
            )

        # TODO: Figure out what type this should be.
        channel_sequence = data[8:10]

        if dialect is Dialect.SMB_3_0:
            return SMB300SyncHeader(
                credit_charge=credit_charge,
                channel_sequence=channel_sequence,
                **base_kwargs
            )

        if dialect is Dialect.SMB_3_0_2:
            return SMB302SyncHeader(
                credit_charge=credit_charge,
                channel_sequence=channel_sequence,
                **base_kwargs
            )

        if dialect is Dialect.SMB_3_1_1:
            return SMB311SyncHeader(
                credit_charge=credit_charge,
                channel_sequence=channel_sequence,
                **base_kwargs
            )

    def __bytes__(self) -> bytes:

        nt_status: Optional[NTSTATUS] = getattr(self, 'status', None)
        nt_status_bytes = bytes(nt_status) if nt_status is not None else self.EMPTY_STATUS

        return b''.join([
            SMBv2Header.protocol_identifier.value,
            struct_pack('<H', self.structure_size),
            b'\x00\x00' if isinstance(self, SMB202SyncHeader) else struct_pack('<H', getattr(self, 'credit_charge')),
            (
                b''.join([struct_pack('<H', getattr(self, 'channel_sequence')), b'\x00\x00'])
                if issubclass(type(self), SMB3XSyncHeader) else nt_status_bytes
            ),
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
    status: Optional[NTSTATUS] = None


@dataclass
class SMB202SyncHeader(SMB2XSyncHeader):
    pass


@dataclass
class SMB210SyncHeader(SMB2XSyncHeader):
    credit_charge: int = 1


@dataclass
class SMB3XSyncHeader(SMBv2SyncHeader, ABC):
    credit_charge: int = 1
    channel_sequence: bytes = b'\x00\x00'


@dataclass
class SMB300SyncHeader(SMB3XSyncHeader):
    pass


@dataclass
class SMB302SyncHeader(SMB3XSyncHeader):
    pass


@dataclass
class SMB311SyncHeader(SMB3XSyncHeader):
    pass


@dataclass
class SMBv2AsyncHeader(SMBv2Header):
    async_id: bytes = 8 * b'\x00'

    @classmethod
    def _from_bytes(cls, data: bytes, dialect: Dialect = Dialect.SMB_3_1_1):

        base_kwargs: Dict[str, Union[bytes, int]] = super()._base_from_bytes(data)
        base_kwargs['async_id'] = data[36:44]

        if dialect == Dialect.SMB_2_0_2:
            return SMB202AsyncHeader(
                status=NTSTATUS.from_bytes(data=struct_unpack('<H', data[8:12])[0]),
                **base_kwargs
            )

        credit_charge = struct_unpack('<I', data[6:8])[0]

        if dialect == Dialect.SMB_2_1:
            return SMB210AsyncHeader(
                status=NTSTATUS.from_bytes(data=struct_unpack('<H', data[8:12])[0]),
                credit_charge=credit_charge,
                **base_kwargs
            )

        # TODO: Figure out what type this should be.
        channel_sequence = data[8:10]

        if dialect == Dialect.SMB_3_0:
            return SMB300AsyncHeader(
                credit_charge=credit_charge,
                channel_sequence=channel_sequence,
                **base_kwargs
            )

        if dialect == Dialect.SMB_3_0_2:
            return SMB302AsyncHeader(
                credit_charge=credit_charge,
                channel_sequence=channel_sequence,
                **base_kwargs
            )

        if dialect == Dialect.SMB_3_1_1:
            return SMB311AsyncHeader(
                credit_charge=credit_charge,
                channel_sequence=channel_sequence,
                **base_kwargs
            )


@dataclass
class SMB202AsyncHeader(SMBv2SyncHeader):
    status: Optional[NTSTATUS] = None


@dataclass
class SMB210AsyncHeader(SMBv2SyncHeader):
    status: Optional[NTSTATUS] = None
    credit_charge: int = 1


@dataclass
class SMB300AsyncHeader(SMBv2SyncHeader):
    credit_charge: int = 1
    channel_sequence: bytes = b'\x00\x00'


@dataclass
class SMB302AsyncHeader(SMBv2SyncHeader):
    credit_charge: int = 1
    channel_sequence: bytes = b'\x00\x00'


@dataclass
class SMB311AsyncHeader(SMBv2SyncHeader):
    credit_charge: int = 1
    channel_sequence: bytes = b'\x00\x00'
