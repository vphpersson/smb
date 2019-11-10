from __future__ import annotations
from abc import ABC
from dataclasses import dataclass
from typing import ClassVar
from math import ceil

from smb.smb_message import SMBMessage
from smb.v2.smbv2_header import SMBv2Header, SMBv2Command
from smb.exceptions import IncorrectStructureSizeError


# TODO: Does this make sense?
def calculate_credit_charge(variable_payload_size: int, expected_maximum_response_size: int) -> int:
    return ceil(((max(variable_payload_size, expected_maximum_response_size) - 1) / 65536) + 1)


@dataclass
class SMBv2Message(SMBMessage, ABC):
    header: SMBv2Header

    structure_size: ClassVar[int] = NotImplemented

    @classmethod
    def check_structure_size(cls, structure_size_to_test: int) -> None:
        if structure_size_to_test != cls.structure_size:
            raise IncorrectStructureSizeError(
                observed_structure_size=structure_size_to_test,
                expected_structure_size=cls.structure_size
            )

    @classmethod
    def from_bytes_and_header(cls, data: bytes, header: SMBv2Header) -> SMBv2Message:

        from smb.v2.messages.negotiate.negotiate_request import NegotiateRequest
        from smb.v2.messages.negotiate.negotiate_response import NegotiateResponse
        from smb.v2.messages.session_setup.session_setup_request import SessionSetupRequest
        from smb.v2.messages.session_setup.session_setup_response import SessionSetupResponse
        from smb.v2.messages.tree_connect.tree_connect_request import TreeConnectRequest
        from smb.v2.messages.tree_connect.tree_connect_response import TreeConnectResponse
        from smb.v2.messages.create.create_request import CreateRequest
        from smb.v2.messages.create.create_response import CreateResponse
        from smb.v2.messages.read.read_request import ReadRequest
        from smb.v2.messages.read.read_response import ReadResponse
        from smb.v2.messages.query_directory.query_directory_request import QueryDirectoryRequest
        from smb.v2.messages.query_directory.query_directory_response import QueryDirectoryResponse
        from smb.v2.messages.close.close_request import CloseRequest
        from smb.v2.messages.close.close_response import CloseResponse
        from smb.v2.messages.tree_disconnect.tree_disconnect_request import TreeDisconnectRequest
        from smb.v2.messages.tree_disconnect.tree_disconnect_response import TreeDisconnectResponse
        from smb.v2.messages.logoff.logoff_request import LogoffRequest
        from smb.v2.messages.logoff.logoff_response import LogoffResponse

        if header.command is SMBv2Command.SMB2_NEGOTIATE:
            return (NegotiateResponse if header.flags.server_to_redir else NegotiateRequest).from_bytes_and_header(
                data=data,
                header=header
            )
        elif header.command is SMBv2Command.SMB2_SESSION_SETUP:
            return (SessionSetupResponse if header.flags.server_to_redir else SessionSetupRequest).from_bytes_and_header(
                data=data,
                header=header
            )
        elif header.command is SMBv2Command.SMB2_TREE_CONNECT:
            return (TreeConnectResponse if header.flags.server_to_redir else TreeConnectRequest).from_bytes_and_header(
                data=data,
                header=header
            )
        elif header.command is SMBv2Command.SMB2_CREATE:
            return (CreateResponse if header.flags.server_to_redir else CreateRequest).from_bytes_and_header(
                data=data,
                header=header
            )
        elif header.command is SMBv2Command.SMB2_READ:
            return (ReadResponse if header.flags.server_to_redir else ReadRequest).from_bytes_and_header(
                data=data,
                header=header
            )
        elif header.command is SMBv2Command.SMB2_QUERY_DIRECTORY:
            return (QueryDirectoryResponse if header.flags.server_to_redir else QueryDirectoryRequest).from_bytes_and_header(
                data=data,
                header=header
            )
        elif header.command is SMBv2Command.SMB2_CLOSE:
            return (CloseResponse if header.flags.server_to_redir else CloseRequest).from_bytes_and_header(
                data=data,
                header=header
            )
        elif header.command is SMBv2Command.SMB2_TREE_DISCONNECT:
            return (TreeDisconnectResponse if header.flags.server_to_redir else TreeDisconnectRequest).from_bytes_and_header(
                data=data,
                header=header
            )
        elif header.command is SMBv2Command.SMB2_LOGOFF:
            return (LogoffResponse if header.flags.server_to_redir else LogoffRequest).from_bytes_and_header(
                data=data,
                header=header
            )
        else:
            # TODO: Use proper exception.
            raise ValueError
