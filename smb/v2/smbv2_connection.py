from __future__ import annotations
from dataclasses import dataclass
from abc import ABC
from uuid import UUID, uuid1
from typing import Set, Dict, Optional, Tuple, Awaitable, Union, AsyncGenerator, AsyncContextManager, List
from asyncio import Future, create_task
from ipaddress import IPv4Address, IPv6Address
from enum import Enum, auto
from contextlib import asynccontextmanager
from pathlib import PureWindowsPath

from ntlm.messages.challenge import ChallengeMessage as NTLMChallengeMessage
from ntlm.utils import make_ntlm_context
from spnego.negotiation_tokens.neg_token_init import NegTokenInit
from spnego.negotiation_tokens.neg_token_resp import NegTokenResp
from spnego.token_attributes import NegTokenRespNegState
from asn1.oid import OID

from smb.v2.client import PREFERRED_DIALECT, CLIENT_GUID, SECURITY_MODE, REQUIRE_MESSAGE_SIGNING
from smb.smb_connection import SMBConnection, NegotiatedDetails
from smb.v2.negotiate_context import HashAlgorithm, Cipher, CompressionAlgorithm
from smb.transport import Transport
from smb.v2.dialect import Dialect
from smb.v2.smbv2_message import SMBv2Message, calculate_credit_charge
from smb.v2.messages.negotiate.negotiate_request import NegotiateRequest
from smb.v2.messages.negotiate.negotiate_response import NegotiateResponse, SMB202NegotiateResponse, \
    SMB210NegotiateResponse, SMB300NegotiateResponse, SMB302NegotiateResponse, SMB311NegotiateResponse
from smb.v2.messages.session_setup.session_setup_request import SessionSetupRequest
from smb.v2.messages.session_setup.session_setup_response import SessionSetupResponse
from smb.v2.messages.tree_connect.tree_connect_request import TreeConnectRequest210
from smb.v2.messages.tree_connect.tree_connect_response import TreeConnectResponse, ShareType
from smb.v2.messages.create.create_request import CreateRequest
from smb.v2.messages.create.create_response import CreateResponse
from smb.v2.messages.query_directory.query_directory_request import QueryDirectoryRequest, FileInformationClass,\
    QueryDirectoryFlag
from smb.v2.messages.query_directory.query_directory_response import QueryDirectoryResponse, FileDirectoryInformation, \
    FileIdFullDirectoryInformation
from smb.v2.messages.read.read_request import ReadRequest210
from smb.v2.messages.read.read_response import ReadResponse
from smb.v2.messages.close.close_request import CloseRequest, CloseFlag
from smb.v2.messages.close.close_response import CloseResponse
from smb.v2.messages.tree_disconnect.tree_disconnect_request import TreeDisconnectRequest
from smb.v2.messages.tree_disconnect.tree_disconnect_response import TreeDisconnectResponse
from smb.v2.messages.logoff.logoff_request import LogoffRequest
from smb.v2.messages.logoff.logoff_response import LogoffResponse
from smb.v2.messages.write.write_request import WriteRequest210, WriteFlag
from smb.v2.messages.write.write_response import WriteResponse
from smb.v2.messages.change_notify.change_notify_request import ChangeNotifyRequest, CompletionFilterFlag, \
    ChangeNotifyFlag
from smb.v2.messages.change_notify.change_notify_response import ChangeNotifyResponse
from smb.v2.negotiate_context import PreauthIntegrityCapabilitiesContext, EncryptionCapabilitiesContext, \
    CompressionCapabilitiesContext, NetnameNegotiateContextIdContext
from smb.v2.smbv2_header import SMBv2Header, SMBv2Command, SMBv2AsyncHeader, SMB210SyncRequestHeader
from smb.status import Status
from smb.v2.security_mode import SecurityMode
from smb.v2.tree_connect_object import TreeConnectObject
from smb.v2.messages.create.create_request import OplockLevel, ImpersonationLevel, FileAttributes,\
    ShareAccess, CreateDisposition, CreateOptions
from smb.v2.messages.create.create_context import CreateContextList
from smb.v2.access_mask import FilePipePrinterAccessMask, DirectoryAccessMask
from smb.v2.file_id import FileId
from smb.v2.smbv2_session import SMB210Session


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

    def __init__(self):

        from smb.v2.smbv2_session import SMBv2Session

        super().__init__()
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

        create_task(self._receive_message())

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
            self._outstanding_request_message_id_to_response_message_future.pop(incoming_message.header.message_id).set_result(incoming_message)

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
    async def setup_session(
        self,
        username: str,
        authentication_secret: Union[str, bytes],
        domain_name: str = 'WORKSTATION',
        workstation_name: Optional[Union[str, IPv4Address, IPv6Address]] = None,
        authentication_method: SessionSetupAuthenticationMethod = SessionSetupAuthenticationMethod.LM_NTLM_v2
    ) -> SMBSession:
        """
        Request a new authenticated SMB session.

        :param username: The username with which to authenticate.
        :param authentication_secret: The password or NT hash of the user which to authenticate, differentiated by type.
        :param domain_name: The name of the domain to which the user belongs.
        :param workstation_name: The name of the client workstation.
        :param authentication_method: The authentication method to be used.
        :return: An authenticated SMB session.
        """

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

        :param session: The session which to terminate.
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
    async def setup_session_cm(
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

        session: SMBv2Session = await self.setup_session(
            username=username,
            authentication_secret=authentication_secret,
            domain_name=domain_name,
            workstation_name=workstation_name,
            authentication_method=authentication_method
        )

        yield session
        await self.logoff(session=session)

    async def tree_connect(
        self,
        share_name: str,
        session: SMBv2Session,
        server_address: Optional[Union[str, IPv4Address, IPv6Address]] = None
    ) -> Tuple[int, ShareType]:
        """
        Obtain access to a particular share on a remote server.

        :param share_name: The name of the share to obtain access to.
        :param session: An SMB session with which to access the share.
        :param server_address: The address of the server on which the share exists.
        :return: The tree id and share type of the SMB share accessed.
        """

        tree_connect_response: SMBv2Message = await (
            await self._send_message(
                request_message=TreeConnectRequest210(
                    header=SMB210SyncRequestHeader(
                        command=SMBv2Command.SMB2_TREE_CONNECT,
                        session_id=session.session_id,
                    ),
                    path=f'\\\\{server_address or self._remote_host_address}\\{share_name}'
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
    async def tree_connect_cm(
        self,
        share_name: str,
        session: SMBv2Session,
        server_address: Optional[Union[str, IPv4Address, IPv6Address]] = None
    ) -> AsyncContextManager[Tuple[int, ShareType]]:
        """
        Obtain access to a particular share on a remote server and disconnect from it once consumed.

        :param share_name: The name of the share to obtain access to.
        :param session: An SMB session with which to access the share.
        :param server_address: The address of the server on which the share exists.
        :return: The tree id and share type of the SMB share accessed.
        """

        tree_id, share_type = await self.tree_connect(
            share_name=share_name,
            session=session,
            server_address=server_address
        )
        yield tree_id, share_type
        # create_task(await self.tree_disconnect(session=session, tree_id=tree_id))
        await self.tree_disconnect(session=session, tree_id=tree_id)

    async def create(
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
    async def create_cm(
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

        :param path: The share relative path of the file or directory which to operate on.
        :param session: An SMB session with which to access the file.
        :param tree_id: The tree id of the share in which the file or directory resides or will reside.
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
            await self.create(
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
    async def create_dir_cm(
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
            await self.create(
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
        session: SMBv2Session,
        tree_id: int,
        file_id: FileId,
        file_size: int,
        use_generator: bool = False
    ) -> Union[Awaitable[bytes], AsyncGenerator[bytes, None]]:

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
    ) -> Awaitable[SMBv2Message]:
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

        return self._message_id_and_async_id_to_response_message_future[
            (change_notify_response.header.message_id, change_notify_response.header.async_id)
        ]
