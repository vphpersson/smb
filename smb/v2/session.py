from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, Any, ClassVar, Union, Type, AsyncContextManager, Tuple, Awaitable, AsyncGenerator, List, Optional
from abc import ABC
from asyncio import create_task
from contextlib import asynccontextmanager
from pathlib import PureWindowsPath
from functools import partial
from datetime import datetime

from msdsalgs.fscc.file_information_classes import FileDirectoryInformation, FileIdFullDirectoryInformation

from smb.v2.header import Header, SMBv2Command, SMB210SyncRequestHeader
from smb.v2.messages import calculate_credit_charge
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
from smb.v2.structures.dialect import Dialect
from smb.v2.structures.tree_connect_object import TreeConnectObject
from smb.v2.structures.create_context import CreateContextList
from smb.v2.structures.access_mask import FilePipePrinterAccessMask, DirectoryAccessMask
from smb.v2.structures.file_id import FileId
from smb.v2.structures.session_state import SessionState


@dataclass
class Session(ABC):

    DIALECT: ClassVar[Dialect] = NotImplemented
    DIALECT_TO_CLASS: ClassVar[Dict[Dialect, Type[Session]]] = {}

    connection: SMBv2Connection
    session_id: int
    session_key: bytes

    def __post_init__(self):

        # NOTE: I use this because I cannot use default arguments above, because of inheritance, yes?

        self.state: SessionState = SessionState.IN_PROGRESS
        self.is_anonymous: bool = False
        self.is_guest: bool = False
        self.creation_time: datetime = datetime.now()
        # TODO: Add expiration time?
        self.idle_time: datetime = self.creation_time
        self.user_name: Optional[str] = None

        # "A table of tree connects, as specified in section 3.2.1.4. The table MUST allow lookup by both
        # TreeConnect.TreeConnectId and by share name."
        self.tree_connect_id_to_tree_connect_object: Dict[int, TreeConnectObject] = {}
        self.share_name_to_tree_connect_object: Dict[str, TreeConnectObject] = {}
        # "A table of opens, as specified in section 3.2.1.6. The table MUST allow lookup by either file name or by
        # Open.FileId."
        self.file_id_to_open: Dict[int, Any] = {}

    @classmethod
    def from_dialect(
        cls,
        dialect: Dialect,
        session_id: int,
        connection: SMBv2Connection,
        session_key: bytes,
        **dialect_session_kwargs
    ) -> Session:
        if cls != Session:
            if cls.DIALECT != dialect:
                # TODO: Use proper exception.
                raise ValueError
            return cls(session_id=session_id, connection=connection, session_key=session_key, **dialect_session_kwargs)
        else:
            return cls.DIALECT_TO_CLASS[dialect](
                session_id=session_id,
                connection=connection,
                session_key=session_key,
                **dialect_session_kwargs
            )

    @property
    def signing_required(self):
        # TODO: Do some kind of exception re-raise?
        return self.connection.negotiated_details.require_signing

    @asynccontextmanager
    async def make_smbv2_transport(self, pipe: str, server_address: str = '*'):

        async with self.tree_connect(share_name='IPC$', server_address=server_address) as (tree_id, share_type):
            # if share_type is not ShareType.SMB2_SHARE_TYPE_PIPE:
            #     # TODO: Use proper exception.
            #     raise ValueError

            create_options: Dict[str, Any] = dict(
                path=pipe,
                tree_id=tree_id,
                requested_oplock_level=OplockLevel.SMB2_OPLOCK_LEVEL_NONE,
                desired_access=FilePipePrinterAccessMask(file_read_data=True, file_write_data=True),
                file_attributes=FileAttributes(normal=True),
                share_access=ShareAccess(),
                create_disposition=CreateDisposition.FILE_OPEN,
                create_options=CreateOptions(non_directory_file=True)
            )

            async with self.create(**create_options) as create_response:
                yield (
                    partial(
                        self.read,
                        file_id=create_response.file_id,
                        # TODO: Not sure about this value.
                        file_size=self.connection.negotiated_details.max_read_size,
                        tree_id=tree_id,
                        use_generator=False
                    ),
                    partial(
                        self.write,
                        file_id=create_response.file_id,
                        tree_id=tree_id,
                        offset=0,
                        remaining_bytes=0,
                        flags=WriteFlag()
                    )
                )

    async def logoff(self) -> LogoffResponse:
        """
        Terminate a session.

        :return: A `LOGOFF` response.
        """

        if self.connection.negotiated_details.dialect is not Dialect.SMB_2_1:
            raise NotImplementedError

        return await self.connection._obtain_response(
            request_message=LogoffRequest(
                header=SMB210SyncRequestHeader(command=SMBv2Command.SMB2_LOGOFF, session_id=self.session_id)
            ),
            sign_key=self.session_key
        )

    async def close(self, tree_id: int, file_id: FileId) -> CloseResponse:
        """
        Close an instance of a file opened with a CREATE request.

        :param tree_id: The tree id of the share in which the opened file resides.
        :param file_id: The file id of the file instance to be closed.
        :return: A `CLOSE` response.
        """

        if self.connection.negotiated_details.dialect is not Dialect.SMB_2_1:
            raise NotImplementedError

        return await self.connection._obtain_response(
            request_message=CloseRequest(
                header=SMB210SyncRequestHeader(
                    command=SMBv2Command.SMB2_CLOSE,
                    session_id=self.session_id,
                    tree_id=tree_id
                ),
                flags=CloseFlag(),
                file_id=file_id
            ),
            sign_key=self.session_key
        )

    async def _tree_connect(
            self,
            share_name: str,
            server_address: str = '*'
    ) -> Tuple[int, ShareType]:

        if self.connection.negotiated_details.dialect is not Dialect.SMB_2_1:
            raise NotImplementedError

        tree_connect_response: TreeConnectResponse = await self.connection._obtain_response(
            request_message=TreeConnectRequest210(
                header=SMB210SyncRequestHeader(
                    command=SMBv2Command.SMB2_TREE_CONNECT,
                    session_id=self.session_id,
                ),
                path=f'\\\\{server_address}\\{share_name}'
            ),
            sign_key=self.session_key
        )

        tree_connect_object = TreeConnectObject(
            tree_connect_id=tree_connect_response.header.tree_id,
            session=self,
            is_dfs_share=tree_connect_response.share_capabilities.dfs,
            is_ca_share=tree_connect_response.share_capabilities.continuous_availability,
            share_name=share_name
        )

        self.tree_connect_id_to_tree_connect_object[tree_connect_response.header.tree_id] = tree_connect_object
        self.share_name_to_tree_connect_object[share_name] = tree_connect_object

        return tree_connect_response.header.tree_id, tree_connect_response.share_type

    async def tree_disconnect(self, tree_id: int) -> TreeDisconnectResponse:
        """
        Request that a tree connect is disconnected.

        :param tree_id: The ID of the tree connect to be disconnected.
        :return: A `TREE_DISCONNECT` resposne.
        """

        if self.connection.negotiated_details.dialect is not Dialect.SMB_2_1:
            raise NotImplementedError

        return await self.connection._obtain_response(
            request_message=TreeDisconnectRequest(
                header=SMB210SyncRequestHeader(
                    command=SMBv2Command.SMB2_TREE_DISCONNECT,
                    session_id=self.session_id,
                    tree_id=tree_id
                )
            ),
            sign_key=self.session_key
        )

    @asynccontextmanager
    async def tree_connect(
        self,
        share_name: str,
        server_address: str = '*'
    ) -> AsyncContextManager[Tuple[int, ShareType]]:
        """
        Obtain access to a particular share on a remote server and disconnect once finished with it.

        :param share_name: The name of the share to obtain access to.
        :param server_address: The address of the server on which the share exists.
        :return: The tree id and share type of the SMB share accessed.
        """

        tree_id, share_type = await self._tree_connect(share_name=share_name, server_address=server_address or '*')
        yield tree_id, share_type

        await self.tree_disconnect(tree_id=tree_id)

    async def _create(
        self,
        path: Union[str, PureWindowsPath],
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
        create_context_list = create_context_list if create_context_list is not None else CreateContextList()

        if self.connection.negotiated_details.dialect is not Dialect.SMB_2_1:
            raise NotImplementedError

        create_response: CreateResponse = await self.connection._obtain_response(
            request_message=CreateRequest(
                header=SMB210SyncRequestHeader(
                    command=SMBv2Command.SMB2_CREATE,
                    session_id=self.session_id,
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
            ),
            sign_key=self.session_key
        )

        # TODO: I need to add stuff to some connection table, don't I?
        # TODO: Consider what to return from this function. There is a lot of information in the response.
        return create_response

    @asynccontextmanager
    async def create(
        self,
        path: Union[str, PureWindowsPath],
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

        await self.close(tree_id=tree_id, file_id=create_response.file_id)

    @asynccontextmanager
    async def create_dir(
        self,
        path: Union[str, PureWindowsPath],
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

        await self.close(tree_id=tree_id, file_id=create_response.file_id)

    # TODO: Extend the return type once more types are supported.
    async def query_directory(
        self,
        file_id: FileId,
        file_information_class: FileInformationClass,
        query_directory_flag: QueryDirectoryFlag,
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
        :param tree_id: The tree id of the SMB share that stores the directory.
        :param file_name_pattern: A search pattern specifying which entries in the the directory to retrieve information
            about.
        :param file_index: The byte offset within the directory, indicating the position at which to resume the
            enumeration.
        :param output_buffer_length: The maximum number of bytes the server is allowed to return in the response.
        :return: A collection of information entries about the content of the directory.
        """

        if self.connection.negotiated_details.dialect is not Dialect.SMB_2_1:
            raise NotImplementedError

        query_directory_response: QueryDirectoryResponse = await self.connection._obtain_response(
            request_message=QueryDirectoryRequest(
                header=SMB210SyncRequestHeader(
                    command=SMBv2Command.SMB2_QUERY_DIRECTORY,
                    session_id=self.session_id,
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
            ),
            sign_key=self.session_key
        )

        if file_information_class is FileInformationClass.FileDirectoryInformation:
            return query_directory_response.file_directory_information()
        elif file_information_class is FileInformationClass.FileIdFullDirectoryInformation:
            return query_directory_response.file_id_full_directory_information()
        else:
            raise NotImplementedError

    def read(
        self,
        file_id: FileId,
        file_size: int,
        tree_id: int,
        use_generator: bool = False
    ) -> Union[Awaitable[bytes], AsyncGenerator[bytes, None]]:
        """
        Read data from a file in an SMB share.

        :param file_id: An identifier of the file which to read.
        :param file_size: The number of bytes to read from the file.
        :param tree_id: The tree ID of the SMB share that stores the file.
        :param use_generator: Whether to return the read data via a generator.
        :return: The data of the file or a generator that yields the data.
        """

        if self.connection.negotiated_details.dialect is not Dialect.SMB_2_1:
            raise NotImplementedError

        async def read_chunks():
            num_bytes_remaining = file_size
            offset = 0
            while num_bytes_remaining != 0:
                num_bytes_to_read = min(num_bytes_remaining, self.connection.negotiated_details.max_read_size)
                read_response: ReadResponse = await self.connection._obtain_response(
                    request_message=ReadRequest210(
                        header=SMB210SyncRequestHeader(
                            command=SMBv2Command.SMB2_READ,
                            session_id=self.session_id,
                            tree_id=tree_id,
                            credit_charge=calculate_credit_charge(
                                variable_payload_size=0,
                                expected_maximum_response_size=file_size
                            )
                        ),
                        padding=Header.STRUCTURE_SIZE + (ReadResponse.STRUCTURE_SIZE - 1),
                        length=num_bytes_to_read,
                        offset=offset,
                        file_id=file_id,
                        minimum_count=0,
                        remaining_bytes=0
                    ),
                    sign_key=self.session_key
                )

                yield read_response.buffer

                num_bytes_remaining -= num_bytes_to_read
                offset += num_bytes_to_read

        async def merge_read_chunks() -> bytes:
            return b''.join([chunk async for chunk in read_chunks()])

        return create_task(merge_read_chunks()) if not use_generator else read_chunks()

    async def write(
        self,
        write_data: bytes,
        file_id: FileId,
        tree_id: int,
        offset: int = 0,
        remaining_bytes: int = 0,
        flags: WriteFlag = WriteFlag()
    ) -> int:
        """
        Write data to a file in an SMB share.

        :param write_data: The data to be written.
        :param file_id: An identifier of the file whose data is to be written.
        :param tree_id: The tree id of the SMB share that stores the file.
        :param offset: The offset, in bytes, of where to write the data in the destination file.
        :param remaining_bytes: The number of subsequent bytes the client intends to write to the file after this
            operation completes. Not binding.
        :param flags: Flags indicating how to process the operation.
        :return: The number of bytes written.
        """

        if self.connection.negotiated_details.dialect is not Dialect.SMB_2_1:
            raise NotImplementedError

        write_response: WriteResponse = await self.connection._obtain_response(
            request_message=WriteRequest210(
                header=SMB210SyncRequestHeader(
                    command=SMBv2Command.SMB2_WRITE,
                    session_id=self.session_id,
                    tree_id=tree_id,
                    credit_charge=calculate_credit_charge(
                        variable_payload_size=0,
                        expected_maximum_response_size=Header.STRUCTURE_SIZE + WriteResponse.STRUCTURE_SIZE
                    )
                ),
                write_data=write_data,
                offset=offset,
                file_id=file_id,
                remaining_bytes=remaining_bytes,
                flags=flags
            ),
            sign_key=self.session_key
        )

        return write_response.count

    async def change_notify(
        self,
        file_id: FileId,
        tree_id: int,
        completion_filter_flag: Optional[CompletionFilterFlag] = None,
        watch_tree: bool = False
    ) -> Awaitable[ChangeNotifyResponse]:
        """
        Monitor a directory in an SMB share for changes and notify.

        Only one notification is sent per change notify request. The notification is sent asynchronously.

        :param file_id: An identifier for the directory to be monitored for changes.
        :param tree_id: The tree ID of the share that stores the directory to be monitored.
        :param completion_filter_flag: A flag that specifies which type of changes to notify about.
        :param watch_tree: Whether to monitor the subdirectories of the directory.
        :return: A `Future` object that resolves to a `ChangeNotifyResponse` containing a notification.
        """

        if completion_filter_flag is None:
            completion_filter_flag = CompletionFilterFlag()
            completion_filter_flag.set_all()

        if self.connection.negotiated_details.dialect is not Dialect.SMB_2_1:
            raise NotImplementedError

        return await self.connection._obtain_response(
            request_message=ChangeNotifyRequest(
                header=SMB210SyncRequestHeader(
                    command=SMBv2Command.SMB2_CHANGE_NOTIFY,
                    session_id=self.session_id,
                    tree_id=tree_id,
                    # TODO: Arbitrary number. Reconsider.
                    credit_charge=64
                ),
                flags=ChangeNotifyFlag(watch_tree=watch_tree),
                file_id=file_id,
                completion_filter=completion_filter_flag
            ),
            await_async_response=False,
            sign_key=self.session_key
        )

    async def __aenter__(self) -> Session:
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.logoff()


@dataclass
class SMB2XSession(Session, ABC):
    pass


@dataclass
class SMB202Session(SMB2XSession):
    DIALECT: ClassVar[Dialect] = Dialect.SMB_2_0_2


@dataclass
class SMB210Session(SMB2XSession):
    DIALECT: ClassVar[Dialect] = Dialect.SMB_2_1


@dataclass
class SMB3XSession(Session, ABC):
    channel_list: ...
    channel_sequence: bytes
    encrypt_data: bool
    encryption_key: bytes
    decryption_key: bytes
    signing_key: bytes
    application_key: bytes


@dataclass
class SMB300Session(SMB3XSession):
    DIALECT: ClassVar[Dialect] = Dialect.SMB_3_0


@dataclass
class SMB302Session(SMB3XSession):
    DIALECT: ClassVar[Dialect] = Dialect.SMB_3_0_2


@dataclass
class SMB311Session(SMB3XSession):
    preauth_integrity_hash_value: bytes
    DIALECT: ClassVar[Dialect] = Dialect.SMB_3_1_1


Session.DIALECT_TO_CLASS = {
    Dialect.SMB_2_0_2: SMB202Session,
    Dialect.SMB_2_1: SMB210Session,
    Dialect.SMB_3_0: SMB300Session,
    Dialect.SMB_3_0_2: SMB302Session,
    Dialect.SMB_3_1_1: SMB311Session
}

