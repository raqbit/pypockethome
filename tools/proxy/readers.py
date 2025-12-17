import asyncio
from typing import Protocol


class Reader(Protocol):
    async def read_exactly(self, n: int) -> bytes: ...


class BytesReader:
    _buf: bytes
    _idx: int

    def __init__(self, buf: bytes):
        self._buf = buf
        self.reset()

    async def read_exactly(self, n: int) -> bytes:
        idx = self._idx
        self._idx += n
        return self._buf[idx : idx + n]

    def reset(self):
        self._idx = 0

    def at_eof(self):
        return self._idx >= len(self._buf)


class RewindableReader:
    _read: asyncio.StreamReader

    _buffer: bytearray

    def __init__(self, reader: asyncio.StreamReader):
        self._read = reader
        self._buffer = bytearray()

    async def read_exactly(self, n: int) -> bytes:
        data = await self._read.readexactly(n)
        self._buffer += data
        return data

    def rewind(self) -> bytes:
        read = bytes(self._buffer)
        self._buffer.clear()
        return read
