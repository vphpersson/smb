from __future__ import annotations
from uuid import UUID, uuid4
from typing import Dict, Optional, Tuple, Awaitable, Union, Final, NoReturn
from asyncio import Future, create_task
from ipaddress import IPv4Address, IPv6Address
from contextlib import asynccontextmanager
from functools import partial
from logging import getLogger
from hmac import digest as hmac_digest

from ntlm import NTLMContext
from ntlm.messages.challenge import ChallengeMessage as NTLMChallengeMessage
from spnego.negotiation_tokens.neg_token_init import NegTokenInit
from spnego.negotiation_tokens.neg_token_resp import NegTokenResp
from spnego.token_attributes import NegTokenRespNegState
from asn1.oid import OID
from asn1.universal_types import SequenceOf, ObjectIdentifier
from msdsalgs.ntstatus_value import NTStatusValue, NTStatusValueError

from smb.transport import Transport, TCPIPTransport
from smb.connection import Connection as SMBConnectionBase
from smb.v2.header import Header, SMBv2Command, AsyncHeader, SMB210SyncRequestHeader
from smb.v2.session import SMB210Session
from smb.v2.messages import Message, RequestMessage, ResponseMessage
from smb.v2.messages.negotiate import NegotiateRequest, NegotiateResponse
from smb.v2.messages.session_setup import SessionSetupRequest, SessionSetupResponse
# TODO: Reconsider whether this is necessary.
from smb.v2.messages.negotiate import SMB202NegotiateResponse, \
    SMB210NegotiateResponse, SMB300NegotiateResponse, SMB302NegotiateResponse, SMB311NegotiateResponse
from smb.v2.messages.error import ErrorResponse
from smb.v2.structures.dialect import Dialect
from smb.v2.structures.negotiate_context import PreauthIntegrityCapabilitiesContext, EncryptionCapabilitiesContext, \
    CompressionCapabilitiesContext, NetnameNegotiateContextIdContext
from smb.v2.structures.security_mode import SecurityMode
from smb.v2.structures.negotiated_details import SMBv2NegotiatedDetails, SMB202NegotiatedDetails, \
    SMB210NegotiatedDetails, SMB300NegotiatedDetails, SMB302NegotiatedDetails, SMB311NegotiateDetails
from smb.v2.structures.sequence_window import SequenceWindow
from smb.v2.structures.session_state import SessionState
from smb.exceptions import CreditsNotAvailable


LOG = getLogger(__name__)


class Connection(SMBConnectionBase):

    def __init__(self, tcp_ip_transport: TCPIPTransport, client_guid: UUID = uuid4()):
        """

        :param tcp_ip_transport:
        :param client_guid:
        """

        from smb.v2.session import Session

        # TODO: It would be nice if in was possible to adjust the read size during runtime!
        super().__init__(
            reader=partial(tcp_ip_transport.reader.read, tcp_ip_transport.read_size),
            writer=tcp_ip_transport.write
        )

        self._client_guid: UUID = client_guid
        self._server_name: Final[str] = str(tcp_ip_transport.address)

        self.negotiated_details: Optional[SMBv2NegotiatedDetails] = None
        # TODO: "The table MUST allow lookup by both Session.SessionId and by the security context of the user that
        #  established the connection."
        # A.k.a. SessionTable, with SessionId lookup.
        self._session_id_to_session: Dict[bytes, Session] = {}
        # A.k.a. PreauthSessionTable
        # (Derive it from `SessionTable` instead of making a new variable.)
        # A.k.a. OutstandingRequests, with MessageId lookup
        self._outstanding_request_message_id_to_smb_message_request: Dict[int, Message] = {}
        # A.k.a. OutstandingRequests, with CancelId lookup
        self._outstanding_request_cancel_id_to_smb_message_request: Dict[bytes, Message] = {}
        # TODO: What is this?
        self._gss_negotiate_token: Optional[bytes] = None
        self._sequence_window = SequenceWindow()

        # Custom

        self._outstanding_request_message_id_to_response_message_future: Dict[int, Future] = {}
        # TODO: Make a new type, `AsyncKey`, for the `Tuple[int, int]`.
        self.async_key_to_response_message_future: Dict[Tuple[int, int], Future] = {}

    @property
    def client_guid(self) -> UUID:
        return self._client_guid

    @property
    def server_name(self) -> str:
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

        message_id = self._sequence_window.lower

        next_message_id: int = self._sequence_window.lower + credit_charge
        if next_message_id > self._sequence_window.upper:
            raise CreditsNotAvailable(num_requested_credits=credit_charge)
        self._sequence_window.lower = next_message_id

        return message_id

    # TODO: Make this async. If credits are not available, we should wait.
    async def _assign_message_id(self, request_message: Message) -> None:
        """
        Assign a message id to an SMB message.

        :param request_message: The SMB message to be assigned a message id.
        :return: None
        """

        request_message.header.message_id = await self._claim_message_ids(
            credit_charge=getattr(request_message.header, 'credit_charge', 1)
        )

    def _write_signature(self, request_message: Message, sign_key: bytes) -> None:
        """
        Write a signature to a request message.

        See also:

        [MS-SMB2]: Signing An Outgoing Message | Microsoft Docs
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/a3e9ea1e-53c8-4cff-94bd-d98fb20417c0

        :param request_message: The message to be signed.
        :param sign_key: The key to be used in the signing.
        :return: None
        """

        if self.negotiated_details.dialect in {Dialect.SMB_2_0_2, Dialect.SMB_2_1}:
            request_message.header.flags.signed = True
            request_message.header.signature = hmac_digest(
                key=sign_key,
                msg=bytes(request_message),
                digest='sha256'
            )[:16]
        elif self.negotiated_details.dialect in {Dialect.SMB_3_0, Dialect.SMB_3_0_2, Dialect.SMB_3_0_2}:
            raise NotImplementedError
        else:
            # TODO: Use proper exception.
            raise ValueError

    async def _receive_message(self) -> NoReturn:
        try:
            while True:
                incoming_message: Message = await self._incoming_smb_messages_queue.get()

                self._sequence_window.upper += incoming_message.header.num_credits

                if isinstance(incoming_message.header, AsyncHeader):
                    async_key = incoming_message.header.async_key

                    # A `STATUS_PENDING` response contains the async id for the message that will eventually contain
                    # the requested data.
                    if incoming_message.header.status.real_status is NTStatusValue.STATUS_PENDING:
                        async_response_message_future = Future()
                        self.async_key_to_response_message_future[async_key] = async_response_message_future
                        incoming_message.header.async_response_message_future = async_response_message_future
                    else:
                        self.async_key_to_response_message_future.pop(async_key).set_result(incoming_message)
                        continue

                self._outstanding_request_message_id_to_smb_message_request.pop(incoming_message.header.message_id)
                # TODO: Pop the cancel id map.

                response_message_future: Future = self._outstanding_request_message_id_to_response_message_future.pop(
                    incoming_message.header.message_id
                )

                if not response_message_future.cancelled():
                    response_message_future.set_result(incoming_message)
        except Exception as e:
            LOG.exception(e)

    async def _send_message(self, request_message: Message, sign_key: Optional[bytes] = None) -> Awaitable[Message]:
        """
        Assign an available message id to a request message and then put the message in the outgoing messages queue.

        If message ids fulfilling the message request are not currently available, the function waits until it is the
        case.

        :param request_message: The SMBv2 message to be send over the connection.
        :return: A future that resolves to the response to the request message.
        """

        # TODO: Make special case for cancel requests.

        await self._assign_message_id(request_message=request_message)

        if sign_key is not None:
            self._write_signature(request_message=request_message, sign_key=sign_key)

        self._outstanding_request_message_id_to_smb_message_request[request_message.header.message_id] = request_message
        # self._cancel_id_to_smb_message_request[...] = request_message

        response_message_future = Future()
        self._outstanding_request_message_id_to_response_message_future[request_message.header.message_id] = response_message_future

        create_task(self._outgoing_smb_messages_queue.put(request_message))

        return response_message_future

    async def _obtain_response(
        self,
        request_message: RequestMessage,
        await_async_response: bool = True,
        sign_key: Optional[bytes] = None
    ):
        """

        :param request_message:
        :param await_async_response:
        :param sign_key:
        :return:
        """

        response_message: Message = await (await self._send_message(request_message=request_message, sign_key=sign_key))

        if not isinstance(response_message, ResponseMessage):
            # TODO: Raise proper exception.
            raise ValueError

        if isinstance(response_message, ErrorResponse):
            if response_message.header.status.real_status is NTStatusValue.STATUS_PENDING and isinstance(response_message.header, AsyncHeader):
                return (await response_message.header.async_response_message_future) if await_async_response else response_message
            else:
                raise NTStatusValueError.from_nt_status(response_message.header.status.real_status)

        if not isinstance(response_message, request_message.RESPONSE_MESSAGE_CLASS):
            # TODO: Raise proper exception.
            raise ValueError

        return response_message

    async def negotiate(
        self,
        preferred_dialect: Dialect = Dialect.SMB_2_1,
        security_mode: SecurityMode = SecurityMode(signing_required=True)
    ) -> None:
        """
        Negotiate the SMB configuration to be used.

        :return: None
        """

        # TODO: In future, I want to support more dialects.
        negotiate_response: NegotiateResponse = await self._obtain_response(
            request_message=NegotiateRequest(
                header=SMB210SyncRequestHeader(
                    command=SMBv2Command.SMB2_NEGOTIATE
                ),
                dialects=(preferred_dialect,),
                client_guid=self.client_guid,
                security_mode=security_mode
            )
        )

        # TODO: Check if the server is also accepting signing?

        negotiated_details_base_kwargs = dict(
            dialect=negotiate_response.dialect_revision,
            require_signing=negotiate_response.security_mode.signing_required,
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

    # TODO: I think it is possible to setup anonymous sessions.
    async def _setup_session(
        self,
        username: str,
        authentication_secret: Union[str, bytes],
        domain_name: str = '',
        workstation_name: str = ''
    ):

        # TODO: Let this reference a constant defined somewhere? (spnego)
        mech_type: OID = OID.from_string(string='1.3.6.1.4.1.311.2.2.10')
        ntlm_context = NTLMContext(
            username=username,
            authentication_secret=authentication_secret,
            domain_name=domain_name,
            workstation_name=workstation_name
        )

        ntlm_context_authenticate = ntlm_context.initiate()

        session_setup_response_1: SessionSetupResponse = await self._obtain_response(
            request_message=SessionSetupRequest(
                header=Header.from_dialect(
                    dialect=self.negotiated_details.dialect,
                    async_status=False,
                    is_response=False,
                    command=SMBv2Command.SMB2_SESSION_SETUP
                ),
                security_mode=(
                    SecurityMode(
                        signing_required=self.negotiated_details.require_signing,
                        signing_enabled=not self.negotiated_details.require_signing
                    )
                ),
                security_buffer=bytes(
                    NegTokenInit(
                        mech_types=[mech_type],
                        # A serialized NTLM Negotiate message.
                        mech_token=bytes(next(ntlm_context_authenticate))
                    )
                )
            )
        )

        if (nt_status := session_setup_response_1.header.status.real_status) is not NTStatusValue.STATUS_MORE_PROCESSING_REQUIRED:
            raise NTStatusValueError.from_nt_status(nt_status=nt_status)

        # TODO: "The client MUST attempt to locate a session in Connection.SessionTable by using the SessionId in the
        #  SMB2 header"

        neg_token_resp_1 = NegTokenResp.from_bytes(session_setup_response_1.security_buffer)
        if neg_token_resp_1.neg_state is not NegTokenRespNegState.ACCEPT_INCOMPLETE:
            # TODO: Use proper exception.
            raise ValueError

        if neg_token_resp_1.supported_mech != mech_type:
            # TODO: Use proper exception.
            raise ValueError

        response_token = bytes(
            ntlm_context_authenticate.send(
                NTLMChallengeMessage.from_bytes(
                    neg_token_resp_1.response_token
                )
            )
        )

        smb_session = SMB210Session.from_dialect(
            dialect=self.negotiated_details.dialect,
            session_id=session_setup_response_1.header.session_id,
            connection=self,
            session_key=ntlm_context.exported_session_key
        )

        session_setup_response_2: SessionSetupResponse = await self._obtain_response(
            request_message=SessionSetupRequest(
                header=Header.from_dialect(
                    dialect=self.negotiated_details.dialect,
                    async_status=False,
                    is_response=False,
                    command=SMBv2Command.SMB2_SESSION_SETUP,
                    session_id=smb_session.session_id
                ),
                security_mode=SecurityMode(
                    signing_required=self.negotiated_details.require_signing,
                    signing_enabled=not self.negotiated_details.require_signing
                ),
                security_buffer=bytes(
                    NegTokenResp(
                        response_token=response_token,
                        mech_list_mic=ntlm_context.sign(
                            data=bytes(
                                SequenceOf(
                                    elements=tuple(ObjectIdentifier(oid=oid).tlv_triplet() for oid in [mech_type])
                                )
                            ),
                            as_bytes=True
                        )
                    )
                )
            )
        )

        if (nt_status := session_setup_response_2.header.status.real_status) is not NTStatusValue.STATUS_SUCCESS:
            raise NTStatusValueError.from_nt_status(nt_status=nt_status)

        neg_token_resp_2 = NegTokenResp.from_bytes(data=session_setup_response_2.security_buffer)
        if neg_token_resp_2.neg_state is not NegTokenRespNegState.ACCEPT_COMPLETE:
            # TODO: Use proper exception.
            raise ValueError

        # TODO: Add session to connection table?

        smb_session.state = SessionState.VALID

        return smb_session

    @asynccontextmanager
    async def setup_session(
        self,
        username: str,
        authentication_secret: Union[str, bytes],
        domain_name: str = '',
        workstation_name: str = ''
    ):
        """
        Request a new authenticated SMB session and log off it once consumed.

        :param username: The username with which to authenticate.
        :param authentication_secret: The password or NT hash of the user which to authenticate, differentiated by type.
        :param domain_name: The name of the domain to which the user belongs.
        :param workstation_name: The name of the client workstation.
        :return: An authenticated SMB session.
        """

        async with await self._setup_session(
            username=username,
            authentication_secret=authentication_secret,
            domain_name=domain_name,
            workstation_name=workstation_name,
        ) as session:
            yield session





