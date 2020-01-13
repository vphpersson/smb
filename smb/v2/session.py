from __future__ import annotations
from dataclasses import dataclass
from abc import ABC
from typing import Dict, Any, ClassVar, Type

from smb.v2.dialect import Dialect


@dataclass
class SMBv2Session(ABC):
    session_id: int
    connection: SMBv2Connection
    # TODO: Must figure out how to retrieve this from the GSS token.
    # TODO: "MUST be set to the first 16 bytes of the cryptographic key queried from the GSS protocol for this
    #  authenticated context
    # session_key=...,
    # user_credentials: ...,

    dialect: ClassVar[Dialect] = NotImplemented
    _dialect_to_class: ClassVar[Dict[Dialect, Type[SMBv2Session]]] = {}

    def __post_init__(self):
        # "A table of tree connects, as specified in section 3.2.1.4. The table MUST allow lookup by both
        # TreeConnect.TreeConnectId and by share name."
        self.tree_connect_id_to_tree_connect_object: Dict[int, TreeConnectObject] = {}
        self.share_name_to_tree_connect_object: Dict[str, TreeConnectObject] = {}
        # "A table of opens, as specified in section 3.2.1.6. The table MUST allow lookup by either file name or by
        # Open.FileId."
        self.file_id_to_open: Dict[int, Any] = {}

    @classmethod
    def from_dialect(cls, dialect: Dialect, session_id: int, connection: SMBv2Connection, **dialect_session_kwargs):
        if cls != SMBv2Session:
            if cls.dialect != dialect:
                # TODO: Use proper exception.
                raise ValueError
            return cls(session_id=session_id, connection=connection, **dialect_session_kwargs)
        else:
            return cls._dialect_to_class[dialect](
                session_id=session_id,
                connection=connection,
                **dialect_session_kwargs
            )

    @property
    def signing_required(self):
        # TODO: Do some kind of exception re-raise?
        return self.connection.negotiated_details.require_signing

    # TODO: Add a method called close, that disconnects the session?


@dataclass
class SMB2XSession(SMBv2Session, ABC):
    pass


@dataclass
class SMB202Session(SMB2XSession):
    dialect: ClassVar[Dialect] = Dialect.SMB_2_0_2


@dataclass
class SMB210Session(SMB2XSession):
    dialect: ClassVar[Dialect] = Dialect.SMB_2_1


@dataclass
class SMB3XSession(SMBv2Session, ABC):
    channel_list: ...
    channel_sequence: bytes
    encrypt_data: bool
    encryption_key: bytes
    decryption_key: bytes
    signing_key: bytes
    application_key: bytes


@dataclass
class SMB300Session(SMB3XSession):
    dialect: ClassVar[Dialect] = Dialect.SMB_3_0


@dataclass
class SMB302Session(SMB3XSession):
    dialect: ClassVar[Dialect] = Dialect.SMB_3_0_2


@dataclass
class SMB311Session(SMB3XSession):
    preauth_integrity_hash_value: bytes
    dialect: ClassVar[Dialect] = Dialect.SMB_3_1_1


SMBv2Session._dialect_to_class = {
    Dialect.SMB_2_0_2: SMB202Session,
    Dialect.SMB_2_1: SMB210Session,
    Dialect.SMB_3_0: SMB300Session,
    Dialect.SMB_3_0_2: SMB302Session,
    Dialect.SMB_3_1_1: SMB311Session
}

