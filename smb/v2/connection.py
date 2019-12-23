from __future__ import annotations
from dataclasses import dataclass
from abc import ABC
from uuid import UUID, uuid1
from typing import Set, Dict, Optional, Tuple, Awaitable, Union, AsyncGenerator, AsyncContextManager, List, Any, Final
from asyncio import Future, create_task
from ipaddress import IPv4Address, IPv6Address
from enum import Enum, auto
from contextlib import asynccontextmanager
from pathlib import PureWindowsPath
from functools import partial

from ntlm.messages.challenge import ChallengeMessage as NTLMChallengeMessage
from ntlm.utils import make_ntlm_context
from spnego.negotiation_tokens.neg_token_init import NegTokenInit
from spnego.negotiation_tokens.neg_token_resp import NegTokenResp
from spnego.token_attributes import NegTokenRespNegState
from asn1.oid import OID
from msdsalgs.fscc.file_information_classes import FileDirectoryInformation, FileIdFullDirectoryInformation

from smb.smb_connection import SMBConnection, NegotiatedDetails
from smb.transport import Transport, TCPIPTransport
from smb.v2.dialect import Dialect
from smb.v2.client import PREFERRED_DIALECT, CLIENT_GUID, SECURITY_MODE, REQUIRE_MESSAGE_SIGNING
from smb.v2.negotiate_context import HashAlgorithm, Cipher, CompressionAlgorithm
from smb.v2.messages.message import SMBv2Message, calculate_credit_charge
from smb.v2.messages.negotiate import NegotiateRequest, NegotiateResponse
from smb.v2.messages.session_setup import SessionSetupRequest, SessionSetupResponse
from smb.v2.messages.tree_connect import TreeConnectRequest210, TreeConnectResponse, ShareType
from smb.v2.messages.create import CreateRequest, CreateResponse, OplockLevel, ImpersonationLevel, FileAttributes,\
    ShareAccess, CreateDisposition, CreateOptions
from smb.v2.messages.query_directory import QueryDirectoryRequest, QueryDirectoryResponse, FileInformationClass, \
    QueryDirectoryFlag
from smb.v2.messages.read import ReadRequest210, ReadResponse
from smb.v2.messages.write import WriteRequest210, WriteResponse, WriteFlag
from smb.v2.messages.change_notify import ChangeNotifyRequest, ChangeNotifyResponse, CompletionFilterFlag, \
    ChangeNotifyFlag
from smb.v2.messages.close import CloseRequest, CloseResponse, CloseFlag
from smb.v2.messages.tree_disconnect import TreeDisconnectRequest, TreeDisconnectResponse
from smb.v2.messages.logoff import LogoffRequest, LogoffResponse
# TODO: Reconsider whether this is necessary.
from smb.v2.messages.negotiate.negotiate_response import SMB202NegotiateResponse, \
    SMB210NegotiateResponse, SMB300NegotiateResponse, SMB302NegotiateResponse, SMB311NegotiateResponse
from smb.v2.negotiate_context import PreauthIntegrityCapabilitiesContext, EncryptionCapabilitiesContext, \
    CompressionCapabilitiesContext, NetnameNegotiateContextIdContext
from smb.v2.header import SMBv2Header, SMBv2Command, SMBv2AsyncHeader, SMB210SyncRequestHeader
from smb.status import Status
from smb.v2.security_mode import SecurityMode
from smb.v2.tree_connect_object import TreeConnectObject
from smb.v2.messages.create.create_context import CreateContextList
from smb.v2.access_mask import FilePipePrinterAccessMask, DirectoryAccessMask
from smb.v2.file_id import FileId
from smb.v2.session import SMB210Session


class CreditsNotAvailable(Exception):
    def __init__(self, num_requested_credits: int):
        super().__init__(f'The request for {num_requested_credits} could not be fulfilled.')
        self.num_requested_credits = num_requested_credits


@dataclass
class SMBv2NegotiatedDetails(NegotiatedDetails, ABC):
    dialect: Dialect
    require_signing: bool
    server_guid: UUID
    max_transact_size: int
    max_read_size: int
    max_write_size: int


@dataclass
class SMB2XNegotiatedDetails(SMBv2NegotiatedDetails):
    pass


@dataclass
class SMB202NegotiatedDetails(SMB2XNegotiatedDetails):
    pass


@dataclass
class SMB210NegotiatedDetails(SMB2XNegotiatedDetails):
    supports_file_leasing: bool
    supports_multi_credit: bool


@dataclass
class SMB3XNegotiatedDetails(SMBv2NegotiatedDetails, ABC):
    supports_file_leasing: bool
    supports_multi_credit: bool
    supports_directory_leasing: bool
    supports_multi_channel: bool
    supports_persistent_handles: bool
    supports_encryption: bool
    # client_capabilities: CapabilitiesFlag
    # server_capabilities: CapabilitiesFlag
    # client_security_mode: SecurityMode
    # server_security_mode: SecurityMode


@dataclass
class SMB300NegotiatedDetails(SMB3XNegotiatedDetails):
    pass


@dataclass
class SMB302NegotiatedDetails(SMB3XNegotiatedDetails):
    pass


@dataclass
class SMB311NegotiateDetails(SMB3XNegotiatedDetails):
    preauth_integrity_hash_id: Optional[HashAlgorithm] = None
    preauth_integrity_hash_value: Optional[bytes] = None
    cipher_id: Optional[Cipher] = None
    compression_ids: Optional[Set[CompressionAlgorithm]] = None


class SessionSetupAuthenticationMethod(Enum):
    LM_NTLM_v1 = auto()
    LM_NTLM_v2 = auto()


class SMBv2Connection(SMBConnection):

    def __init__(self, tcp_ip_transport: TCPIPTransport):

        from smb.v2.session import SMBv2Session

        # TODO: It would be nice if in was possible to adjust the read size during runtime!
        super().__init__(
            reader=partial(tcp_ip_transport.reader.read, tcp_ip_transport.read_size),
            writer=tcp_ip_transport.write
        )
        self._host_address: Final[Union[IPv4Address, IPv6Address, str]] = tcp_ip_transport.address

        # TODO: Not sure which UUID function to use.
        self._client_guid: UUID = uuid1()
        # TODO: How to get this?
        self._server_name: Optional[str] = None
        self.negotiated_details: Optional[SMBv2NegotiatedDetails] = None
        # TODO: "The table MUST allow lookup by both Session.SessionId and by the security context of the user that
        #  established the connection."
        # A.k.a. SessionTable, with SessionId lookup.
        self._session_id_to_session: Dict[bytes, SMBv2Session] = {}
        # A.k.a. PreauthSessionTable
        self._session_id_to_unauthenticated_session: Dict[bytes, SMBv2Session] = {}
        # A.k.a. OutstandingRequests, with MessageId lookup
        self._outstanding_request_message_id_to_smb_message_request: Dict[int, SMBv2Message] = {}
        # A.k.a. OutstandingRequests, with CancelId lookup
        self._outstanding_request_cancel_id_to_smb_message_request: Dict[bytes, SMBv2Message] = {}
        # TODO: What is this?
        self._gss_negotiate_token: Optional[bytes] = None

        # A.k.a. SequenceWindow
        self._sequence_window_lower: int = 0
        self._sequence_window_upper: int = 1

        # Custom

        self._outstanding_request_message_id_to_response_message_future: Dict[int, Future] = {}
        self._message_id_and_async_id_to_response_message_future: Dict[Tuple[int, int], Future] = {}

    @property
    def client_guid(self) -> UUID:
        return self._client_guid

    @property
    def server_name(self) -> Optional[str]:
        return self._server_name

    def _transport_from_bytes(self, data: bytes) -> Transport:
        return Transport.from_bytes(
            data=data,
            version_specific_header_options=dict(
                dialect=self.negotiated_details.dialect if self.negotiated_details else Dialect.SMB_2_1
            )
        )

    async def _claim_message_ids(self, credit_charge: int) -> int:
        """
        Claim a credits from the connection's sequence window.

        See also:

        [MS-SMB2]: Associating the Message with a MessageId
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5c5f5316-9936-417b-9221-4686de25d414

        [MS-SMB2]: Algorithm for Handling Available Message Sequence Numbers by the Client
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/bed7a84e-33a7-4289-9de9-6042cf8aa7cc

        :param credit_charge: The number of credits to be claimed from the sequence window.
        :return: A sequence of `MessageId`s fulfilling the request.
        """

        message_id = self._sequence_window_lower

        next_message_id: int = self._sequence_window_lower + credit_charge
        if next_message_id > self._sequence_window_upper:
            raise CreditsNotAvailable(num_requested_credits=credit_charge)
        self._sequence_window_lower = next_message_id

        return message_id

    # TODO: Make this async. If credits are not available, we should wait.
    async def _assign_message_id(self, request_message: SMBv2Message) -> None:
        """
        Assign a message id to an SMB message.

        :param request_message: The SMB message to be assigned a message id.
        :return: None
        """

        request_message.header.message_id = await self._claim_message_ids(
            credit_charge=getattr(request_message.header, 'credit_charge', 1)
        )

    async def _receive_message(self):
        while True:
            incoming_message: SMBv2Message = await self._incoming_smb_messages_queue.get()

            self._sequence_window_upper += incoming_message.header.num_credits

            if isinstance(incoming_message.header, SMBv2AsyncHeader):
                async_key: Tuple[int, int] = (incoming_message.header.message_id, incoming_message.header.async_id)

                # A `STATUS_PENDING` response contains the async id for the message that will eventually contain
                # the requested data.
                if incoming_message.header.status.real_status is not Status.STATUS_PENDING:
                    # TODO: It would be nice if the data that resolve is message-specific.
                    self._message_id_and_async_id_to_response_message_future[async_key].set_result(incoming_message)
                    continue
                else:
                    async_response_message_future = Future()
                    self._message_id_and_async_id_to_response_message_future[async_key] = async_response_message_future
                    # TODO: This is not a good solution either, is it?
                    async_response_message_future.add_done_callback(
                        lambda _: self._message_id_and_async_id_to_response_message_future.pop(async_key)
                    )

            self._outstanding_request_message_id_to_smb_message_request.pop(incoming_message.header.message_id)
            # TODO: Pop the cancel id map.

            response_message_future: Future = self._outstanding_request_message_id_to_response_message_future.pop(
                incoming_message.header.message_id
            )

            if not response_message_future.cancelled():
                response_message_future.set_result(incoming_message)

    async def _send_message(self, request_message: SMBv2Message) -> Awaitable[SMBv2Message]:
        """
        Assign an available message id to a request message and then put the message in the outgoing messages queue.

        If message ids fulfilling the message request are not currently available, the function waits until it is the
        case.

        :param request_message: The SMBv2 message to be send over the connection.
        :return: A future that resolves to the response to the request message.
        """

        # TODO: Make special case for cancel requests.

        await self._assign_message_id(request_message=request_message)

        self._outstanding_request_message_id_to_smb_message_request[request_message.header.message_id] = request_message
        # self._cancel_id_to_smb_message_request[...] = request_message

        response_message_future = Future()
        self._outstanding_request_message_id_to_response_message_future[request_message.header.message_id] = response_message_future

        create_task(self._outgoing_smb_messages_queue.put(request_message))

        return response_message_future

    async def negotiate(self) -> None:
        """
        Negotiate the SMB dialect to be used.

        :return: None
        """

        # TODO: In future, I want to support more dialects.
        negotiate_response: SMBv2Message = await (
            await self._send_message(
                NegotiateRequest(
                    header=SMB210SyncRequestHeader(
                        command=SMBv2Command.SMB2_NEGOTIATE
                    ),
                    dialects=(PREFERRED_DIALECT,),
                    client_guid=CLIENT_GUID,
                    security_mode=SECURITY_MODE
                )
            )
        )
        if not isinstance(negotiate_response, NegotiateResponse):
            # TODO: Use proper exception.
            raise ValueError

        negotiated_details_base_kwargs = dict(
            dialect=negotiate_response.dialect_revision,
            require_signing=(
                bool(negotiate_response.security_mode is SecurityMode.SMB2_NEGOTIATE_SIGNING_REQUIRED)
                or REQUIRE_MESSAGE_SIGNING
            ),
            server_guid=negotiate_response.server_guid,
            max_transact_size=negotiate_response.max_transact_size,
            max_read_size=negotiate_response.max_read_size,
            max_write_size=negotiate_response.max_write_size
        )

        negotiated_details_base_kwargs_2 = dict(
            supports_file_leasing=negotiate_response.capabilities.leasing,
            supports_multi_credit=negotiate_response.capabilities.large_mtu
        )

        negotiated_details_base_kwargs_3 = dict(
            supports_directory_leasing=negotiate_response.capabilities.directory_leasing,
            supports_multi_channel=negotiate_response.capabilities.multi_channel,
            supports_persistent_handles=negotiate_response.capabilities.persistent_handles,
            supports_encryption=negotiate_response.capabilities.encryption
        )

        if isinstance(negotiate_response, SMB202NegotiateResponse):
            self.negotiated_details = SMB202NegotiatedDetails(**negotiated_details_base_kwargs)
        elif isinstance(negotiate_response, SMB210NegotiateResponse):
            self.negotiated_details = SMB210NegotiatedDetails(
                **negotiated_details_base_kwargs,
                **negotiated_details_base_kwargs_2
            )
        elif isinstance(negotiate_response, SMB300NegotiateResponse):
            self.negotiated_details = SMB300NegotiatedDetails(
                **negotiated_details_base_kwargs,
                **negotiated_details_base_kwargs_2,
                **negotiated_details_base_kwargs_3
            )
        elif isinstance(negotiate_response, SMB302NegotiateResponse):
            self.negotiated_details = SMB302NegotiatedDetails(
                **negotiated_details_base_kwargs,
                **negotiated_details_base_kwargs_2,
                **negotiated_details_base_kwargs_3
            )
        elif isinstance(negotiate_response, SMB311NegotiateResponse):

            negotiated_context_map = dict(
                preauth_integrity_hash_id=None,
                # TODO: Not sure from where I would get this.
                preauth_integrity_hash_value=None,
                cipher_id=None,
                compression_ids=None
            )

            for negotiate_context in negotiate_response.negotiate_context_list:
                if isinstance(negotiate_context, PreauthIntegrityCapabilitiesContext):
                    negotiated_context_map['preauth_integrity_hash_id'] = next(negotiate_context.hash_algorithms)
                elif isinstance(negotiate_context, EncryptionCapabilitiesContext):
                    negotiated_context_map['cipher_id'] = next(negotiate_context.ciphers)
                elif isinstance(negotiate_context, CompressionCapabilitiesContext):
                    negotiated_context_map['compression_ids'] = set(negotiate_context.compression_algorithms)
                elif isinstance(negotiate_context, NetnameNegotiateContextIdContext):
                    # TODO: Do something with this.
                    ...
                else:
                    # TODO: Use a proper exception.
                    raise ValueError

            self.negotiated_details = SMB311NegotiateDetails(
                **negotiated_details_base_kwargs,
                **negotiated_details_base_kwargs_2,
                **negotiated_details_base_kwargs_3,
                **negotiated_context_map
            )
        else:
            # TODO: Use proper exception.
            raise ValueError

    # TODO: Figure out what "WORKSTATION" means.
    # TODO: I think it is possible to setup anonymous sessions.
    async def _setup_session(
        self,
        username: str,
        authentication_secret: Union[str, bytes],
        domain_name: str = 'WORKSTATION',
        workstation_name: Optional[Union[str, IPv4Address, IPv6Address]] = None,
        authentication_method: SessionSetupAuthenticationMethod = SessionSetupAuthenticationMethod.LM_NTLM_v2
    ) -> SMBSession:
        if authentication_method in {SessionSetupAuthenticationMethod.LM_NTLM_v1, SessionSetupAuthenticationMethod.LM_NTLM_v2}:
            # TODO: Let this reference a constant defined somewhere?
            mech_type: OID = OID.from_string(string='1.3.6.1.4.1.311.2.2.10')
            ntlm_context = make_ntlm_context(
                username=username,
                authentication_secret=authentication_secret,
                domain_name=domain_name,
                workstation_name=workstation_name,
                lm_compatibility_level=3 if authentication_method is SessionSetupAuthenticationMethod.LM_NTLM_v2 else 1
            )
        else:
            raise NotImplementedError

        session_setup_response_1: SMBv2Message = await (
            await self._send_message(
                SessionSetupRequest(
                    header=SMBv2Header.from_dialect(
                        dialect=self.negotiated_details.dialect,
                        async_status=False,
                        is_response=False,
                        command=SMBv2Command.SMB2_SESSION_SETUP
                    ),
                    security_mode=SECURITY_MODE,
                    security_buffer=bytes(
                        NegTokenInit(
                            mech_types=[mech_type],
                            # A serialized NTLM Negotiate message.
                            mech_token=bytes(next(ntlm_context))
                        )
                    )
                )
            )
        )
        if not isinstance(session_setup_response_1, SessionSetupResponse):
            # TODO: Use proper exception.
            raise ValueError

        # TODO: "The client MUST attempt to locate a session in Connection.SessionTable by using the SessionId in the
        #  SMB2 header"

        if session_setup_response_1.header.status.real_status is not Status.STATUS_MORE_PROCESSING_REQUIRED:
            raise NotImplementedError

        neg_token_resp_1 = NegTokenResp.from_bytes(session_setup_response_1.security_buffer)
        if neg_token_resp_1.neg_state is not NegTokenRespNegState.ACCEPT_INCOMPLETE:
            # TODO: Use proper exception.
            raise ValueError

        if neg_token_resp_1.supported_mech != mech_type:
            # TODO: Use proper exception.
            raise ValueError

        smb_session = SMB210Session.from_dialect(
            dialect=self.negotiated_details.dialect,
            session_id=session_setup_response_1.header.session_id,
            connection=self
        )

        session_setup_response_2: SMBv2Message = await (
            await self._send_message(
                request_message=SessionSetupRequest(
                    header=SMBv2Header.from_dialect(
                        dialect=self.negotiated_details.dialect,
                        async_status=False,
                        is_response=False,
                        command=SMBv2Command.SMB2_SESSION_SETUP,
                        session_id=smb_session.session_id
                    ),
                    security_mode=SECURITY_MODE,
                    security_buffer=bytes(
                        NegTokenResp(
                            # A serialized NTLM Authenticate message.
                            response_token=bytes(
                                ntlm_context.send(
                                    NTLMChallengeMessage.from_bytes(
                                        message_bytes=neg_token_resp_1.response_token
                                    )
                                )
                            )
                        )
                    )
                )
            )
        )
        if not isinstance(session_setup_response_2, SessionSetupResponse):
            # TODO: Use proper exception.
            raise ValueError

        if session_setup_response_2.header.status.real_status is not Status.STATUS_SUCCESS:
            # TODO: Use proper exception.
            raise ValueError

        neg_token_resp_2 = NegTokenResp.from_bytes(data=session_setup_response_2.security_buffer)
        if neg_token_resp_2.neg_state is not NegTokenRespNegState.ACCEPT_COMPLETE:
            # TODO: Use proper exception.
            raise ValueError

        # TODO: Add session to connection table?

        return smb_session

    async def logoff(self, session: SMBv2Session) -> None:
        """
        Terminate a session.

        :param session: The session to be terminated.
        :return: None
        """

        if self.negotiated_details.dialect is not Dialect.SMB_2_1:
            raise NotImplementedError

        logoff_response: SMBv2Message = await (
            await self._send_message(
                request_message=LogoffRequest(
                    header=SMB210SyncRequestHeader(command=SMBv2Command.SMB2_LOGOFF, session_id=session.session_id)
                )
            )
        )

        if not isinstance(logoff_response, LogoffResponse):
            # TODO: Raise proper exception.
            raise ValueError

    @asynccontextmanager
    async def setup_session(
        self,
        username: str,
        authentication_secret: Union[str, bytes],
        domain_name: str = 'WORKSTATION',
        workstation_name: Optional[Union[str, IPv4Address, IPv6Address]] = None,
        authentication_method: SessionSetupAuthenticationMethod = SessionSetupAuthenticationMethod.LM_NTLM_v2
    ) -> SMBv2Session:
        """
        Request a new authenticated SMB session and log off it once consumed.

        :param username: The username with which to authenticate.
        :param authentication_secret: The password or NT hash of the user which to authenticate, differentiated by type.
        :param domain_name: The name of the domain to which the user belongs.
        :param workstation_name: The name of the client workstation.
        :param authentication_method: The authentication method to be used.
        :return: An authenticated SMB session.
        """

        session: SMBv2Session = await self._setup_session(
            username=username,
            authentication_secret=authentication_secret,
            domain_name=domain_name,
            workstation_name=workstation_name,
            authentication_method=authentication_method
        )

        yield session
        await self.logoff(session=session)

    async def _tree_connect(
        self,
        share_name: str,
        session: SMBv2Session,
        server_address: Optional[Union[str, IPv4Address, IPv6Address]] = None
    ) -> Tuple[int, ShareType]:

        tree_connect_response: SMBv2Message = await (
            await self._send_message(
                request_message=TreeConnectRequest210(
                    header=SMB210SyncRequestHeader(
                        command=SMBv2Command.SMB2_TREE_CONNECT,
                        session_id=session.session_id,
                    ),
                    path=f'\\\\{server_address or self._host_address}\\{share_name}'
                )
            )
        )
        if not isinstance(tree_connect_response, TreeConnectResponse):
            # TODO: Raise proper exception.
            raise ValueError

        tree_connect_object = TreeConnectObject(
            tree_connect_id=tree_connect_response.header.tree_id,
            session=session,
            is_dfs_share=tree_connect_response.share_capabilities.dfs,
            is_ca_share=tree_connect_response.share_capabilities.continuous_availability,
            share_name=share_name
        )

        session.tree_connect_id_to_tree_connect_object[tree_connect_response.header.tree_id] = tree_connect_object
        session.share_name_to_tree_connect_object[share_name] = tree_connect_object

        return tree_connect_response.header.tree_id, tree_connect_response.share_type

    async def tree_disconnect(self, session: SMBv2Session, tree_id: int):
        """
        Request that a tree connect is disconnected.

        :param session: An SMB session that has access to the tree connect.
        :param tree_id: The ID of the tree connect to be disconnected.
        :return: None
        """

        if self.negotiated_details.dialect is not Dialect.SMB_2_1:
            raise NotImplementedError

        tree_disconnect_response: SMBv2Message = await (
            await self._send_message(
                request_message=TreeDisconnectRequest(
                    header=SMB210SyncRequestHeader(
                        command=SMBv2Command.SMB2_TREE_DISCONNECT,
                        session_id=session.session_id,
                        tree_id=tree_id
                    )
                )
            )
        )

        if not isinstance(tree_disconnect_response, TreeDisconnectResponse):
            # TODO: Raise proper exception.
            raise ValueError

    @asynccontextmanager
    async def tree_connect(
        self,
        share_name: str,
        session: SMBv2Session,
        server_address: Optional[Union[str, IPv4Address, IPv6Address]] = None
    ) -> AsyncContextManager[Tuple[int, ShareType]]:
        """
        Obtain access to a particular share on a remote server and disconnect once finished with it.

        :param share_name: The name of the share to obtain access to.
        :param session: An SMB session with which to access the share.
        :param server_address: The address of the server on which the share exists.
        :return: The tree id and share type of the SMB share accessed.
        """

        tree_id, share_type = await self._tree_connect(
            share_name=share_name,
            session=session,
            server_address=server_address
        )
        yield tree_id, share_type

        await self.tree_disconnect(session=session, tree_id=tree_id)

    async def _create(
        self,
        path: Union[str, PureWindowsPath],
        session: SMBv2Session,
        tree_id: int,
        requested_oplock_level: OplockLevel = OplockLevel.SMB2_OPLOCK_LEVEL_BATCH,
        impersonation_level: ImpersonationLevel = ImpersonationLevel.IMPERSONATION,
        desired_access: Union[FilePipePrinterAccessMask, DirectoryAccessMask] = FilePipePrinterAccessMask(
            file_read_data=True,
            file_read_ea=True,
            file_read_attributes=True
        ),
        file_attributes: FileAttributes = FileAttributes(normal=True),
        share_access: ShareAccess = ShareAccess(read=True),
        create_disposition: CreateDisposition = CreateDisposition.FILE_OPEN,
        create_options: CreateOptions = CreateOptions(non_directory_file=True),
        create_context_list: CreateContextList = None
    ) -> CreateResponse:
        from smb.v2.messages.create.create_context import CreateContextList

        create_context_list = create_context_list if create_context_list is not None else CreateContextList()

        if self.negotiated_details.dialect is not Dialect.SMB_2_1:
            raise NotImplementedError

        create_response: SMBv2Message = await (
            await self._send_message(
                request_message=CreateRequest(
                    header=SMB210SyncRequestHeader(
                        command=SMBv2Command.SMB2_CREATE,
                        session_id=session.session_id,
                        tree_id=tree_id,
                    ),
                    requested_oplock_level=requested_oplock_level,
                    impersonation_level=impersonation_level,
                    desired_access=desired_access,
                    file_attributes=file_attributes,
                    share_access=share_access,
                    create_disposition=create_disposition,
                    create_options=create_options,
                    name=str(path),
                    create_context_list=create_context_list
                )
            )
        )

        if not isinstance(create_response, CreateResponse):
            # TODO: Raise proper exception.
            raise ValueError

        # TODO: I need to add stuff to some connection table, don't I?

        # TODO: Consider what to return from this function. There is a lot of information in the response.
        return create_response

    async def close(self, session: SMBv2Session, tree_id: int, file_id: FileId) -> None:
        """
        Close an instance of a file opened with a CREATE request.

        :param session: The SMB session with which to close the file instance.
        :param tree_id: The tree id of the share in which the opened file resides.
        :param file_id: The file id of the file instance to be closed.
        :return: None
        """

        if self.negotiated_details.dialect is not Dialect.SMB_2_1:
            raise NotImplementedError

        close_response: SMBv2Message = await (
            await self._send_message(
                request_message=CloseRequest(
                    header=SMB210SyncRequestHeader(
                        command=SMBv2Command.SMB2_CLOSE,
                        session_id=session.session_id,
                        tree_id=tree_id
                    ),
                    flags=CloseFlag(),
                    file_id=file_id
                )
            )
        )

        if not isinstance(close_response, CloseResponse):
            # TODO: Use proper exception.
            raise ValueError

    @asynccontextmanager
    async def create(
        self,
        path: Union[str, PureWindowsPath],
        session: SMBv2Session,
        tree_id: int,
        requested_oplock_level: OplockLevel = OplockLevel.SMB2_OPLOCK_LEVEL_BATCH,
        impersonation_level: ImpersonationLevel = ImpersonationLevel.IMPERSONATION,
        desired_access: Union[FilePipePrinterAccessMask, DirectoryAccessMask] = FilePipePrinterAccessMask(
            file_read_data=True,
            file_read_attributes=True
        ),
        file_attributes: FileAttributes = FileAttributes(normal=True),
        share_access: ShareAccess = ShareAccess(read=True),
        create_disposition: CreateDisposition = CreateDisposition.FILE_OPEN,
        create_options: CreateOptions = CreateOptions(non_directory_file=True),
        create_context_list: CreateContextList = None
    ) -> AsyncContextManager[CreateResponse]:
        """
        Create/open a file or directory in an SMB share and close it once finished with it.

        The default parameters reflect read only access to an existing file.

        :param path: The share relative path of the file or directory which to operate on.
        :param session: An SMB session with to access the file or directory.
        :param tree_id: The tree ID of the SMB share where the specified file or directory will be or is located.
        :param requested_oplock_level:
        :param impersonation_level:
        :param desired_access:
        :param file_attributes:
        :param share_access:
        :param create_disposition:
        :param create_options:
        :param create_context_list:
        :return:
        """

        create_response: CreateResponse = (
            await self._create(
                path=path,
                session=session,
                tree_id=tree_id,
                requested_oplock_level=requested_oplock_level,
                impersonation_level=impersonation_level,
                desired_access=desired_access,
                file_attributes=file_attributes,
                share_access=share_access,
                create_disposition=create_disposition,
                create_options=create_options,
                create_context_list=create_context_list
            )
        )

        yield create_response

        await self.close(session=session, tree_id=tree_id, file_id=create_response.file_id)

    @asynccontextmanager
    async def create_dir(
        self,
        path: Union[str, PureWindowsPath],
        session: SMBv2Session,
        tree_id: int,
        requested_oplock_level: OplockLevel = OplockLevel.SMB2_OPLOCK_LEVEL_NONE,
        impersonation_level: ImpersonationLevel = ImpersonationLevel.IMPERSONATION,
        desired_access: DirectoryAccessMask = DirectoryAccessMask(
            file_list_directory=True,
            file_read_attributes=True
        ),
        file_attributes: FileAttributes = FileAttributes(directory=True),
        share_access: ShareAccess = ShareAccess(read=True),
        create_disposition: CreateDisposition = CreateDisposition.FILE_OPEN,
        create_options: CreateOptions = CreateOptions(directory_file=True),
        create_context_list: CreateContextList = None
    ):
        """


        :param path:
        :param session:
        :param tree_id:
        :param requested_oplock_level:
        :param impersonation_level:
        :param desired_access:
        :param file_attributes:
        :param share_access:
        :param create_disposition:
        :param create_options:
        :param create_context_list:
        :return:
        """

        create_response: CreateResponse = (
            await self._create(
                path=path,
                session=session,
                tree_id=tree_id,
                requested_oplock_level=requested_oplock_level,
                impersonation_level=impersonation_level,
                desired_access=desired_access,
                file_attributes=file_attributes,
                share_access=share_access,
                create_disposition=create_disposition,
                create_options=create_options,
                create_context_list=create_context_list
            )
        )

        yield create_response

        await self.close(session=session, tree_id=tree_id, file_id=create_response.file_id)

    def read(
        self,
        file_id: FileId,
        file_size: int,
        session: SMBv2Session,
        tree_id: int,
        use_generator: bool = False
    ) -> Union[Awaitable[bytes], AsyncGenerator[bytes, None]]:
        """
        Read data from a file in an SMB share.

        :param file_id: An identifier of the file which to read.
        :param file_size: The number of bytes to read from the file.
        :param session: An SMB session with access to the file.
        :param tree_id: The tree ID of the SMB share that stores the file.
        :param use_generator: Whether to return the read data via a generator.
        :return: The data of the file or a generator that yields the data.
        """

        if self.negotiated_details.dialect is not Dialect.SMB_2_1:
            raise NotImplementedError

        async def read_chunks():
            data_remains = True
            offset = 0
            while data_remains:
                read_response: SMBv2Message = await (
                    await self._send_message(
                        request_message=ReadRequest210(
                            header=SMB210SyncRequestHeader(
                                command=SMBv2Command.SMB2_READ,
                                session_id=session.session_id,
                                tree_id=tree_id,
                                credit_charge=calculate_credit_charge(
                                    variable_payload_size=0,
                                    expected_maximum_response_size=file_size
                                )
                            ),
                            padding=SMBv2Header.structure_size + (ReadResponse.structure_size-1),
                            length=file_size,
                            offset=offset,
                            file_id=file_id,
                            minimum_count=0,
                            remaining_bytes=0
                        )
                    )
                )

                if not isinstance(read_response, ReadResponse):
                    # TODO: Use proper exception.
                    raise ValueError

                yield read_response.buffer

                data_remains = read_response.data_remaining_length != 0
                offset += read_response.data_length

        async def merge_read_chunks() -> bytes:
            return b''.join([chunk async for chunk in read_chunks()])

        return create_task(merge_read_chunks()) if not use_generator else read_chunks()

    async def write(
        self,
        write_data: bytes,
        file_id: FileId,
        session: SMBv2Session,
        tree_id: int,
        offset: int = 0,
        remaining_bytes: int = 0,
        flags: WriteFlag = WriteFlag()
    ) -> int:
        """
        Write data to a file in an SMB share.

        :param write_data: The data to be written.
        :param file_id: An identifier of the file whose data is to be written.
        :param session: An SMB session with access to the file.
        :param tree_id: The tree id of the SMB share that stores the file.
        :param offset: The offset, in bytes, of where to write the data in the destination file.
        :param remaining_bytes: The number of subsequent bytes the client intends to write to the file after this
            operation completes. Not binding.
        :param flags: Flags indicating how to process the operation.
        :return: The number of bytes written.
        """

        # TODO: Support more dialects.
        if self.negotiated_details.dialect is not Dialect.SMB_2_1:
            raise NotImplementedError

        write_response: SMBv2Message = await (
            await self._send_message(
                request_message=WriteRequest210(
                    header=SMB210SyncRequestHeader(
                        command=SMBv2Command.SMB2_WRITE,
                        session_id=session.session_id,
                        tree_id=tree_id,
                        credit_charge=calculate_credit_charge(
                            variable_payload_size=0,
                            expected_maximum_response_size=SMBv2Header.structure_size + WriteResponse.structure_size
                        )
                    ),
                    write_data=write_data,
                    offset=offset,
                    file_id=file_id,
                    remaining_bytes=remaining_bytes,
                    flags=flags
                )
            )
        )

        if not isinstance(write_response, WriteResponse):
            # TODO: Use proper exception.
            raise ValueError

        return write_response.count

    # TODO: Extend the return type once more types are supported.
    async def query_directory(
        self,
        file_id: FileId,
        file_information_class: FileInformationClass,
        query_directory_flag: QueryDirectoryFlag,
        session: SMBv2Session,
        tree_id: int,
        file_name_pattern: str = '',
        file_index: int = 0,
        output_buffer_length: int = 256_000
    ) -> List[Union[FileDirectoryInformation, FileIdFullDirectoryInformation]]:
        """
        Obtain information about a directory in an SMB share.

        :param file_id: An identifier for the directory about which to obtain information.
        :param file_information_class: A specification of the type of information to obtain.
        :param query_directory_flag: A flag indicating how the operation is to be processed.
        :param session: An SMB session with access to the directory.
        :param tree_id: The tree id of the SMB share that stores the directory.
        :param file_name_pattern: A search pattern specifying which entries in the the directory to retrieve information
            about.
        :param file_index: The byte offset within the directory, indicating the position at which to resume the
            enumeration.
        :param output_buffer_length: The maximum number of bytes the server is allowed to return in the response.
        :return: A collection of information entries about the content of the directory.
        """

        if self.negotiated_details.dialect is not Dialect.SMB_2_1:
            raise NotImplementedError

        query_directory_response: SMBv2Message = await (
            await self._send_message(
                request_message=QueryDirectoryRequest(
                    header=SMB210SyncRequestHeader(
                        command=SMBv2Command.SMB2_QUERY_DIRECTORY,
                        session_id=session.session_id,
                        tree_id=tree_id,
                        # TODO: Consider this value.
                        credit_charge=64
                    ),
                    file_information_class=file_information_class,
                    flags=query_directory_flag,
                    file_id=file_id,
                    file_name=file_name_pattern,
                    file_index=file_index,
                    output_buffer_length=output_buffer_length
                )
            )
        )

        if not isinstance(query_directory_response, QueryDirectoryResponse):
            # TODO: Use proper exception.
            raise ValueError

        if file_information_class is FileInformationClass.FileDirectoryInformation:
            return query_directory_response.file_directory_information()
        elif file_information_class is FileInformationClass.FileIdFullDirectoryInformation:
            return query_directory_response.file_id_full_directory_information()
        else:
            raise NotImplementedError

    async def change_notify(
        self,
        file_id: FileId,
        session: SMBV2Session,
        tree_id: int,
        completion_filter_flag: Optional[CompletionFilterFlag] = None,
        watch_tree: bool = False
    ) -> Awaitable[ChangeNotifyResponse]:
        """
        Monitor a directory in an SMB share for changes and notify.

        Only one notification is sent per change notify request. The notification is sent asynchronously.

        :param file_id: An identifier for the directory to be monitored for changes.
        :param session: An SMB session with access to the directory to be monitored.
        :param tree_id: The tree ID of the share that stores the directory to be monitored.
        :param completion_filter_flag: A flag that specifies which type of changes to notify about.
        :param watch_tree: Whether to monitor the subdirectories of the directory.
        :return: A `Future` object that resolves to a `ChangeNotifyResponse` containing a notification.
        """
        # TODO: Update doc string once async responses are message-specific.

        if completion_filter_flag is None:
            completion_filter_flag = CompletionFilterFlag()
            completion_filter_flag.set_all()

        if self.negotiated_details.dialect is not Dialect.SMB_2_1:
            raise NotImplementedError

        change_notify_response = await (
            await self._send_message(
                ChangeNotifyRequest(
                    header=SMB210SyncRequestHeader(
                        command=SMBv2Command.SMB2_CHANGE_NOTIFY,
                        session_id=session.session_id,
                        tree_id=tree_id,
                        # TODO: Arbitrary number. Reconsider.
                        credit_charge=64
                    ),
                    flags=ChangeNotifyFlag(watch_tree=watch_tree),
                    file_id=file_id,
                    completion_filter=completion_filter_flag
                )
            )
        )

        if not isinstance(change_notify_response, ChangeNotifyResponse):
            # TODO: Use proper exception.
            raise ValueError

        if not isinstance(change_notify_response.header, SMBv2AsyncHeader):
            # TODO: Use proper exception.
            raise ValueError

        # TODO: It is here I should register a done callback popping the dict, yes?
        return self._message_id_and_async_id_to_response_message_future[
            (change_notify_response.header.message_id, change_notify_response.header.async_id)
        ]

    @asynccontextmanager
    async def make_smbv2_transport(
        self,
        session: SMBv2Session,
        # TODO: Is this the correct name?
        pipe: str,
        # TODO: This argument does not make much sense to me...
        server_address: Optional[Union[str, IPv4Address, IPv6Address]] = None,
    ):

        async with self.tree_connect(share_name='IPC$', session=session, server_address=server_address) as (tree_id, share_type):
            if share_type is not ShareType.SMB2_SHARE_TYPE_PIPE:
                # TODO: Use proper exception.
                raise ValueError

            create_options: Dict[str, Any] = dict(
                path=pipe,
                session=session,
                tree_id=tree_id,
                requested_oplock_level=OplockLevel.SMB2_OPLOCK_LEVEL_NONE,
                desired_access=FilePipePrinterAccessMask(file_read_data=True, file_write_data=True),
                file_attributes=FileAttributes(normal=True),
                # TODO: Why does Impacket only have the `read` attribute set to `True` (not `write`)?
                share_access=ShareAccess(read=True, write=True),
                create_disposition=CreateDisposition.FILE_OPEN,
                create_options=CreateOptions(non_directory_file=True)
            )

            async with self.create(**create_options) as create_response:

                # TODO: Not sure whether `read` should accept an argument specifying the maximum number of bytes to
                #   read.
                yield (
                    partial(
                        self.read,
                        file_id=create_response.file_id,
                        # TODO: Not sure about this value.
                        file_size=self.negotiated_details.max_read_size,
                        session=session,
                        tree_id=tree_id,
                        use_generator=False
                    ),
                    partial(
                        self.write,
                        file_id=create_response.file_id,
                        session=session,
                        tree_id=tree_id,
                        offset=0,
                        remaining_bytes=0,
                        flags=WriteFlag()
                    )
                )

