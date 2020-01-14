from dataclasses import dataclass
from typing import Optional, Callable, Awaitable, NoReturn
from abc import ABC, abstractmethod
from asyncio import Queue as AsyncioQueue, create_task as asyncio_create_task, Task
from logging import getLogger

from smb.message import Message
from smb.transport import Transport, NotEnoughDataError

LOG = getLogger(__name__)


@dataclass
class NegotiatedDetails(ABC):
    pass


class Connection(ABC):
    """
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/a1df6781-a507-48a7-bcdb-be9ef0c09c97
    """

    def __init__(self, reader: Callable[[], Awaitable[bytes]], writer: Callable[[bytes], Awaitable[None]]):
        self._read: Callable[[], Awaitable[bytes]] = reader
        self._write: Callable[[bytes], Awaitable[None]] = writer

        # Objects for reading and writing data to the remote host when the connection has been established.
        self._receive_message_task: Optional[Task] = None
        self._handle_incoming_bytes_task: Optional[Task] = None
        self._handle_outgoing_bytes_task: Optional[Task] = None

        # Data structures for handling incoming and outgoing messages.
        self._incoming_smb_messages_queue = AsyncioQueue()
        self._outgoing_smb_messages_queue = AsyncioQueue()

    @abstractmethod
    def _transport_from_bytes(self, data: bytes) -> Transport:
        pass

    @abstractmethod
    async def negotiate(self):
        pass

    @abstractmethod
    async def _receive_message(self):
        pass

    async def _handle_incoming_bytes(self) -> NoReturn:
        try:
            # TODO: Maybe there is a better way to use a buffer.
            buffer = b''
            while True:
                if len(buffer) < 4:
                    buffer += await self._read()
                    continue

                try:
                    transport = self._transport_from_bytes(data=buffer)
                except NotEnoughDataError:
                    buffer += await self._read()
                    continue

                await self._incoming_smb_messages_queue.put(transport.smb_message)
                buffer = buffer[len(transport):]
        except Exception as e:
            LOG.exception(e)

    async def _handle_outgoing_bytes(self) -> NoReturn:
        try:
            while True:
                smb_message: Message = await self._outgoing_smb_messages_queue.get()
                await self._write(
                    bytes(
                        Transport(
                            stream_protocol_length=len(smb_message),
                            smb_message=smb_message
                        )
                    )
                )
        except Exception as e:
            LOG.exception(e)

    async def __aenter__(self):
        self._receive_message_task: Task = asyncio_create_task(coro=self._receive_message())
        self._handle_incoming_bytes_task: Task = asyncio_create_task(coro=self._handle_incoming_bytes())
        self._handle_outgoing_bytes_task: Task = asyncio_create_task(coro=self._handle_outgoing_bytes())

        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        self._handle_outgoing_bytes_task.cancel()
        self._handle_incoming_bytes_task.cancel()
        self._receive_message_task.cancel()
