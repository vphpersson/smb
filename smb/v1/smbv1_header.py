from __future__ import annotations
from dataclasses import dataclass
from struct import unpack as struct_unpack, pack as struct_pack
from enum import IntEnum, IntFlag

from msdsalgs.utils import make_mask_class

from smb.protocol_identifier import ProtocolIdentifier
from smb.smb_header import SMBHeader


class SMBv1Command(IntEnum):
    SMB_COM_CREATE_DIRECTORY = 0x00
    SMB_COM_DELETE_DIRECTORY = 0x01
    SMB_COM_OPEN = 0x02
    SMB_COM_CREATE = 0x03
    SMB_COM_CLOSE = 0x04
    SMB_COM_FLUSH = 0x05
    SMB_COM_DELETE = 0x06
    SMB_COM_RENAME = 0x07
    SMB_COM_QUERY_INFORMATION = 0x08
    SMB_COM_SET_INFORMATION = 0x09
    SMB_COM_READ = 0x0A
    SMB_COM_WRITE = 0x0B
    SMB_COM_LOCK_BYTE_RANGE = 0x0C
    SMB_COM_UNLOCK_BYTE_RANGE = 0x0D
    SMB_COM_CREATE_TEMPORARY = 0x0E
    SMB_COM_CREATE_NEW = 0x0F
    SMB_COM_CHECK_DIRECTORY = 0x10
    SMB_COM_PROCESS_EXIT = 0x11
    SMB_COM_SEEK = 0x12
    SMB_COM_LOCK_AND_READ = 0x13
    SMB_COM_WRITE_AND_UNLOCK = 0x14
    SMB_COM_READ_RAW = 0x1A
    SMB_COM_READ_MPX = 0x1B
    SMB_COM_READ_MPX_SECONDARY = 0x1C
    SMB_COM_WRITE_RAW = 0x1D
    SMB_COM_WRITE_MPX = 0x1E
    SMB_COM_WRITE_MPX_SECONDARY = 0x1F
    SMB_COM_WRITE_COMPLETE = 0x20
    SMB_COM_QUERY_SERVER = 0x21
    SMB_COM_SET_INFORMATION2 = 0x22
    SMB_COM_QUERY_INFORMATION2 = 0x23
    SMB_COM_LOCKING_ANDX = 0x24
    SMB_COM_TRANSACTION = 0x25
    SMB_COM_TRANSACTION_SECONDARY = 0x26
    SMB_COM_IOCTL = 0x27
    SMB_COM_IOCTL_SECONDARY = 0x28
    SMB_COM_COPY = 0x29
    SMB_COM_MOVE = 0x2A
    SMB_COM_ECHO = 0x2B
    SMB_COM_WRITE_AND_CLOSE = 0x2C
    SMB_COM_OPEN_ANDX = 0x2D
    SMB_COM_READ_ANDX = 0x2E
    SMB_COM_WRITE_ANDX = 0x2F
    SMB_COM_NEW_FILE_SIZE = 0x30
    SMB_COM_CLOSE_AND_TREE_DISC = 0x31
    SMB_COM_TRANSACTION2 = 0x32
    SMB_COM_TRANSACTION2_SECONDARY = 0x33
    SMB_COM_FIND_CLOSE2 = 0x34
    SMB_COM_FIND_NOTIFY_CLOSE = 0x35
    SMB_COM_TREE_CONNECT = 0x70
    SMB_COM_TREE_DISCONNECT = 0x71
    SMB_COM_NEGOTIATE = 0x72
    SMB_COM_SESSION_SETUP_ANDX = 0x73
    SMB_COM_LOGOFF_ANDX = 0x74
    SMB_COM_TREE_CONNECT_ANDX = 0x75
    SMB_COM_SECURITY_PACKAGE_ANDX = 0x7E
    SMB_COM_QUERY_INFORMATION_DISK = 0x80
    SMB_COM_SEARCH = 0x81
    SMB_COM_FIND = 0x82
    SMB_COM_FIND_UNIQUE = 0x83
    SMB_COM_FIND_CLOSE = 0x84
    SMB_COM_NT_TRANSACT = 0xA0
    SMB_COM_NT_TRANSACT_SECONDARY = 0xA1
    SMB_COM_NT_CREATE_ANDX = 0xA2
    SMB_COM_NT_CANCEL = 0xA4
    SMB_COM_NT_RENAME = 0xA5
    SMB_COM_OPEN_PRINT_FILE = 0xC0
    SMB_COM_WRITE_PRINT_FILE = 0xC1
    SMB_COM_CLOSE_PRINT_FILE = 0xC2
    SMB_COM_GET_PRINT_QUEUE = 0xC3
    SMB_COM_READ_BULK = 0xD8
    SMB_COM_WRITE_BULK = 0xD9
    SMB_COM_WRITE_BULK_DATA = 0xDA
    SMB_COM_INVALID = 0xFE
    SMB_COM_NO_ANDX_COMMAND = 0xFF


class SMBStatus(IntEnum):
    STATUS_SUCCESS = 0x00000000
    STATUS_INVALID_SMB = 0x00010002
    STATUS_SMB_BAD_TID = 0x00050002
    STATUS_SMB_BAD_COMMAND = 0x00160002
    STATUS_SMB_BAD_UID = 0x005B0002
    STATUS_SMB_USE_STANDARD = 0x00FB0002
    STATUS_BUFFER_OVERFLOW = 0x80000005
    STATUS_NO_MORE_FILES = 0x80000006
    STATUS_STOPPED_ON_SYMLINK = 0x8000002D
    STATUS_NOT_IMPLEMENTED = 0xC0000002
    STATUS_INVALID_PARAMETER = 0xC000000D
    STATUS_NO_SUCH_DEVICE = 0xC000000E
    STATUS_INVALID_DEVICE_REQUEST = 0xC0000010
    STATUS_MORE_PROCESSING_REQUIRED = 0xC0000016
    STATUS_ACCESS_DENIED = 0xC0000022
    STATUS_BUFFER_TOO_SMALL = 0xC0000023
    STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034
    STATUS_OBJECT_NAME_COLLISION = 0xC0000035
    STATUS_OBJECT_PATH_NOT_FOUND = 0xC000003A
    STATUS_BAD_IMPERSONATION_LEVEL = 0xC00000A5
    STATUS_IO_TIMEOUT = 0xC00000B5
    STATUS_FILE_IS_A_DIRECTORY = 0xC00000BA
    STATUS_NOT_SUPPORTED = 0xC00000BB
    STATUS_NETWORK_NAME_DELETED = 0xC00000C9
    STATUS_USER_SESSION_DELETED = 0xC0000203
    STATUS_NETWORK_SESSION_EXPIRED = 0xC000035C
    STATUS_SMB_TOO_MANY_UIDS = 0xC000205A


class SMBv1FlagMask(IntFlag):
    SMB_FLAGS_LOCK_AND_READ_OK = 0x01
    SMB_FLAGS_BUF_AVAIL = 0x02
    SMB_FLAGS_CASE_INSENSITIVE = 0x08
    SMB_FLAGS_CANONICALIZED_PATHS = 0x10
    SMB_FLAGS_OPLOCK = 0x20
    SMB_FLAGS_OPBATCH = 0x40
    SMB_FLAGS_REPLY = 0x80


SMBv1Flag = make_mask_class(SMBv1FlagMask, prefix='SMB_FLAGS_')


class SMBv1Flag2Mask(IntFlag):
    SMB_FLAGS2_LONG_NAMES = 0x0001
    SMB_FLAGS2_EAS = 0x0002
    SMB_FLAGS2_SMB_SECURITY_SIGNATURE = 0x0004
    SMB_FLAGS2_IS_LONG_NAME = 0x0040
    SMB_FLAGS2_DFS = 0x1000
    SMB_FLAGS2_PAGING_IO = 0x2000
    SMB_FLAGS2_NT_STATUS = 0x4000
    SMB_FLAGS2_UNICODE = 0x8000

    # SMB Header Extensions [MS-SMB] 2.2.3.1 SMB Header Extensions

    SMB_FLAGS2_COMPRESSED = 0x0008
    SMB_FLAGS2_SMB_SECURITY_SIGNATURE_REQUIRED = 0x0010
    SMB_FLAGS2_REPARSE_PATH = 0x0400
    SMB_FLAGS2_EXTENDED_SECURITY = 0x0800


SMBv1Flag2 = make_mask_class(SMBv1Flag2Mask, prefix='SMB_FLAGS2_')


@dataclass
class SMBv1Header(SMBHeader):
    protocol: ProtocolIdentifier
    command: SMBv1Command
    status: SMBStatus
    flags: SMBv1Flag
    flags2: SMBv1Flag2
    pid: int
    tid: int
    uid: int
    mid: int

    @staticmethod
    def protocol_identifier() -> ProtocolIdentifier:
        return ProtocolIdentifier.SMB_VERSION_1

    @classmethod
    def from_bytes(cls, data: bytes) -> SMBv1Header:

        protocol_id = ProtocolIdentifier(data[:4])
        if protocol_id != ProtocolIdentifier.SMB_VERSION_1:
            # TODO: Raise proper exception.
            raise ValueError

        return cls(
            protocol=protocol_id,
            command=SMBv1Command(data[4]),
            status=SMBStatus(struct_unpack('<I', data[5:9])[0]),
            flags=SMBv1Flag.from_mask(mask=SMBv1FlagMask(data[9])),
            flags2=SMBv1Flag2.from_mask(mask=SMBv1Flag2Mask(struct_unpack('<H', data[10:12])[0])),
            pid=struct_unpack('<I', data[26:28] + data[12:14])[0],
            tid=struct_unpack('<H', data[24:26])[0],
            uid=struct_unpack('<H', data[28:30])[0],
            mid=struct_unpack('<H', data[30:32])[0]
        )

    def __bytes__(self) -> bytes:

        pid_bytes = struct_pack('<I', self.pid)

        return b''.join([
            self.protocol.value,
            bytes([self.command.value]),
            struct_pack('<I', self.status.value),
            bytes([self.flags.to_mask()]),
            struct_pack('<H', self.flags2.to_mask()),
            # `PIDHigh` , i.e. the high-order bytes of the PID. Note that little-endian is in use.
            pid_bytes[2:4],
            # Security features. TODO
            8 * b'\x00',
            # Reserved
            2 * b'\x00',
            struct_pack('<H', self.tid),
            # `PIDLow` , i.e. the lower-order bytes of the PID. Note that little-endian is in use.
            pid_bytes[0:2],
            struct_pack('<H', self.uid),
            struct_pack('<H', self.mid)
        ])

    def __len__(self) -> int:
        return 32
