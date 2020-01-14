from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import ClassVar, Tuple, Dict, Type
from math import ceil

from smb.message import Message as SMBMessageBase
from smb.v2.header import Header, SMBv2Command, RequestHeader, ResponseHeader
from smb.exceptions import IncorrectStructureSizeError, MalformedSMBv2MessageError


# TODO: Does this make sense?
def calculate_credit_charge(variable_payload_size: int, expected_maximum_response_size: int) -> int:
    return ceil(((max(variable_payload_size, expected_maximum_response_size) - 1) / 65536) + 1)


@dataclass
class Message(SMBMessageBase, ABC):
    header: Header

    STRUCTURE_SIZE: ClassVar[int] = NotImplemented
    _COMMAND: ClassVar[SMBv2Command] = NotImplemented
    _command_and_type_to_class: ClassVar[Dict[Tuple[SMBv2Command, bool], Type[Message]]] = {}

    @classmethod
    def check_structure_size(cls, structure_size_to_test: int) -> None:
        if structure_size_to_test != cls.STRUCTURE_SIZE:
            raise IncorrectStructureSizeError(
                observed_structure_size=structure_size_to_test,
                expected_structure_size=cls.STRUCTURE_SIZE
            )

    @classmethod
    @abstractmethod
    def _from_bytes_and_header(cls, data: bytes, header: Header) -> Message:
        pass

    @classmethod
    def from_bytes_and_header(cls, data: bytes, header: Header) -> Message:

        # Import the SMBv2 messages to make sure that they are registered in the map.
        from smb.v2.messages.negotiate import NegotiateRequest, NegotiateResponse
        from smb.v2.messages.session_setup import SessionSetupRequest, SessionSetupResponse
        from smb.v2.messages.tree_connect import TreeConnectRequest, TreeConnectResponse
        from smb.v2.messages.create import CreateRequest, CreateResponse
        from smb.v2.messages.read import ReadRequest, ReadResponse
        from smb.v2.messages.query_directory import QueryDirectoryRequest, QueryDirectoryResponse
        from smb.v2.messages.close import CloseRequest, CloseResponse
        from smb.v2.messages.tree_disconnect import TreeDisconnectRequest, TreeDisconnectResponse
        from smb.v2.messages.logoff import LogoffRequest, LogoffResponse
        from smb.v2.messages.error import ErrorResponse

        lookup_key_tuple: Tuple[SMBv2Command, bool] = (header.command, header.flags.server_to_redir)

        try:
            if cls != Message:
                if lookup_key_tuple != (cls._COMMAND, issubclass(cls, ResponseMessage)):
                    # TODO: Use proper exception.
                    raise ValueError
                return cls._from_bytes_and_header(data=data, header=header)
            else:
                return cls._command_and_type_to_class[lookup_key_tuple]._from_bytes_and_header(data=data, header=header)
        except MalformedSMBv2MessageError as e:
            try:
                return ErrorResponse._from_bytes_and_header(data=data, header=header)
            except MalformedSMBv2MessageError:
                raise e


@dataclass
class RequestMessage(Message, ABC):
    header: RequestHeader


@dataclass
class ResponseMessage(Message, ABC):
    header: ResponseHeader


def register_smbv2_message(cls: Type[Message]):
    cls._command_and_type_to_class[(cls._COMMAND, issubclass(cls, ResponseMessage))] = cls
    return cls
