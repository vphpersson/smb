from __future__ import annotations
from dataclasses import dataclass
from typing import ClassVar
from abc import ABC
from enum import IntFlag, IntEnum
from struct import pack as struct_pack, unpack as struct_unpack

from smb.v2.smbv2_header import SMBv2Header, SMB202SyncHeader, SMB202AsyncHeader, SMB210SyncHeader, \
    SMB210AsyncHeader, SMB300SyncHeader, SMB300AsyncHeader, SMB302SyncHeader, SMB302AsyncHeader, SMB311SyncHeader, \
    SMB311AsyncHeader, SMBv2Command, SMBv2Flag
from smb.v2.smbv2_message import SMBv2Message, calculate_credit_charge
from smb.v2.dialect import Dialect

from msdsalgs.utils import make_mask_class


class TreeConnectFlagMask(IntFlag):
    SMB2_TREE_CONNECT_FLAG_CLUSTER_RECONNECT = 0x0001
    SMB2_TREE_CONNECT_FLAG_REDIRECT_TO_OWNER = 0x0002
    SMB2_TREE_CONNECT_FLAG_EXTENSION_PRESENT = 0x0004


TreeConnectFlag = make_mask_class(TreeConnectFlagMask, prefix='SMB2_TREE_CONNECT_FLAG_')


@dataclass
class TreeConnectContext:
    ...


class TreeConnectContextType(IntEnum):
    SMB2_RESERVED_TREE_CONNECT_CONTEXT_ID = 0x0000
    SMB2_REMOTED_IDENTITY_TREE_CONNECT_CONTEXT_ID = 0x0001


@dataclass
class TreeConnectRequestExtension:
    path_name: str

    @classmethod
    def from_bytes(cls, data: bytes, path_name_len: int) -> 'TreeConnectRequestExtension':
        tree_connect_context_type = TreeConnectContextType(struct_unpack('<H', data[:2])[0])
        if tree_connect_context_type is TreeConnectContextType.SMB2_REMOTED_IDENTITY_TREE_CONNECT_CONTEXT_ID:
            ...
        elif tree_connect_context_type is TreeConnectContextType.SMB2_RESERVED_TREE_CONNECT_CONTEXT_ID:
            ...
        else:
            # TODO: Use proper exception.
            raise ValueError


@dataclass
class RemotedIdentityTreeConnectContext(TreeConnectRequestExtension):
    ...


@dataclass
class TreeConnectRequest(SMBv2Message, ABC):
    structure_size: ClassVar[int] = 9

    @classmethod
    def from_bytes_and_header(cls, data: bytes, header: SMBv2Header) -> TreeConnectRequest:

        body_data: bytes = data[len(header):]

        cls.check_structure_size(structure_size_to_test=struct_unpack('<H', body_data[:2])[0])

        path_offset: int = struct_unpack('<H', body_data[4:6])[0]
        path_length: int = struct_unpack('<H', body_data[6:8])[0]

        tree_connect_base_kwargs = dict(
            header=header,
            path=data[path_offset:path_offset + path_length].decode(encoding='utf-16-le')
        )

        if isinstance(header, (SMB202SyncHeader, SMB202AsyncHeader)):
            return TreeConnectRequest202(**tree_connect_base_kwargs)
        elif isinstance(header, (SMB210SyncHeader, SMB210AsyncHeader)):
            return TreeConnectRequest210(**tree_connect_base_kwargs)
        elif isinstance(header, (SMB300SyncHeader, SMB300AsyncHeader)):
            return TreeConnectRequest300(**tree_connect_base_kwargs)
        elif isinstance(header, (SMB302SyncHeader, SMB302AsyncHeader)):
            return TreeConnectRequest302(**tree_connect_base_kwargs)
        elif isinstance(header, (SMB311SyncHeader, SMB311AsyncHeader)):
            raise NotImplementedError
            # return TreeConnect311(
            #     **tree_connect_base_kwargs,
            #     flags=TreeConnectFlag.from_mask(mask=struct_unpack('<H', body_data[2:4])[0])
            # )
        else:
            # TODO: Use proper exception.
            raise ValueError

    @classmethod
    def make_tree_connect_request(
        cls,
        path: str,
        session_id: int,
        dialect: Dialect,
        num_request_credits: int = 8192
    ) -> TreeConnectRequest:
        """

        :param path: The UNC of the share which to connect to.
        :param session_id: The id of the session which to be used for connecting.
        :param dialect: The dialect of the request message.
        :param num_request_credits: The number of credits to request.
        :return:
        """

        headers_base_kwargs = dict(
            command=SMBv2Command.SMB2_TREE_CONNECT,
            flags=SMBv2Flag(),
            session_id=session_id,
            num_credits=num_request_credits,
        )

        # # TODO: Not sure about this value.
        channel_sequence = b''

        if dialect is Dialect.SMB_3_1_1:
            raise NotImplementedError

        if dialect is Dialect.SMB_2_0_2:
            return TreeConnectRequest202(header=SMB202SyncHeader(**headers_base_kwargs), path=path)

        credit_charge: int = calculate_credit_charge(variable_payload_size=0, expected_maximum_response_size=0)

        if dialect is Dialect.SMB_2_1:
            return TreeConnectRequest210(
                header=SMB210SyncHeader(**headers_base_kwargs, credit_charge=credit_charge),
                path=path
            )
        elif dialect is Dialect.SMB_3_0:
            return TreeConnectRequest300(
                header=SMB300SyncHeader(
                    **headers_base_kwargs,
                    credit_charge=credit_charge,
                    channel_sequence=channel_sequence
                ),
                path=path
            )
        elif dialect is Dialect.SMB_3_0_2:
            return TreeConnectRequest302(
                header=SMB302SyncHeader(
                    **headers_base_kwargs,
                    credit_charge=credit_charge,
                    channel_sequence=channel_sequence
                ),
                path=path
            )
        else:
            # TODO: Use proper exception.
            raise ValueError


@dataclass
class TreeConnectRequest2X(TreeConnectRequest, ABC):
    path: str

    def __bytes__(self) -> bytes:
        path_bytes: bytes = self.path.encode(encoding='utf-16-le')

        return bytes(self.header) + b''.join([
            struct_pack('<H', TreeConnectRequest.structure_size),
            b'\x00\x00',
            struct_pack('<H', len(self.header) + (TreeConnectRequest.structure_size - 1)),
            struct_pack('<H', len(path_bytes)),
            path_bytes
        ])

    def __len__(self) -> int:
        return len(self.header) + 8 + len(self.path.encode(encoding='utf-16-le'))


@dataclass
class TreeConnectRequest202(TreeConnectRequest2X):
    pass


@dataclass
class TreeConnectRequest210(TreeConnectRequest2X):
    pass


@dataclass
class TreeConnectRequest3X(TreeConnectRequest, ABC):
    pass


@dataclass
class TreeConnectRequest300(TreeConnectRequest):
    path: str

    def __len__(self) -> int:
        return len(self.header) + 8 + len(self.path.encode(encoding='utf-16-le'))


@dataclass
class TreeConnectRequest302(TreeConnectRequest):
    path: str

    def __len__(self) -> int:
        return len(self.header) + 8 + len(self.path.encode(encoding='utf-16-le'))


@dataclass
class TreeConnectRequest311(TreeConnectRequest):
    flags: TreeConnectFlag

