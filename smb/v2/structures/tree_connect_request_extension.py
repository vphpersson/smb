from __future__ import annotations
from dataclasses import dataclass
from struct import unpack as struct_unpack

from smb.v2.structures.tree_connect_context_type import TreeConnectContextType


@dataclass
class TreeConnectRequestExtension:
    path_name: str

    @classmethod
    def from_bytes(cls, data: bytes, path_name_len: int) -> TreeConnectRequestExtension:
        tree_connect_context_type = TreeConnectContextType(struct_unpack('<H', data[:2])[0])
        if tree_connect_context_type is TreeConnectContextType.SMB2_REMOTED_IDENTITY_TREE_CONNECT_CONTEXT_ID:
            raise NotImplementedError
        elif tree_connect_context_type is TreeConnectContextType.SMB2_RESERVED_TREE_CONNECT_CONTEXT_ID:
            raise NotImplementedError
        else:
            # TODO: Use proper exception.
            raise ValueError
