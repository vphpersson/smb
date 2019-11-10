from __future__ import annotations
from dataclasses import dataclass


@dataclass
class TreeConnectObject:
    tree_connect_id: int
    session: SMBv2Session
    is_dfs_share: bool
    is_ca_share: bool
    share_name: str

# TODO: SMB 3.x has additional fields.
