from dataclasses import dataclass
from typing import Optional, Callable, Awaitable
from abc import ABC, abstractmethod
from asyncio import Queue as AsyncioQueue, Event as AsyncioEvent, CancelledError, create_task as asyncio_create_task, Task

from smb.smb_message import SMBMessage
from smb.transport import Transport, NotEnoughDataError


@dataclass
class NegotiatedDetails(ABC):
    pass


class SMBConnection(ABC):
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

    async def _handle_incoming_bytes(self):

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

    async def _handle_outgoing_bytes(self):
        while True:
            smb_message: SMBMessage = await self._outgoing_smb_messages_queue.get()
            await self._write(
                bytes(
                    Transport(
                        stream_protocol_length=len(smb_message),
                        smb_message=smb_message
                    )
                )
            )

    async def __aenter__(self):
        self._receive_message_task: Task = asyncio_create_task(coro=self._receive_message())
        self._handle_incoming_bytes_task: Task = asyncio_create_task(coro=self._handle_incoming_bytes())
        self._handle_outgoing_bytes_task: Task = asyncio_create_task(coro=self._handle_outgoing_bytes())

        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        self._handle_outgoing_bytes_task.cancel()
        self._handle_incoming_bytes_task.cancel()
        self._receive_message_task.cancel()
