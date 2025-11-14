from __future__ import annotations

import asyncio
import struct
import typing
from typing import Iterable, Final, AsyncIterable

from .packet import Packet, RequestPacket, GetUsedRoomsMessage, UsedRoomsResponse

JUMBO_MESSAGE_BIT: Final[int] = 0b00000001


class Connection:
    _reader: asyncio.StreamReader
    _writer: asyncio.StreamWriter

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self._reader = reader
        self._writer = writer

    @typing.overload
    async def send[RT1: Packet, RT2: Packet, RT3: Packet](
            self, pkt1: RequestPacket[RT1], pkt2: RequestPacket[RT2], pkt3: RequestPacket[RT3], /,
    ) -> tuple[RT1, RT2, RT3]:
        ...

    @typing.overload
    async def send[RT1: Packet, RT2: Packet](
            self, pkt1: RequestPacket[RT1], pkt2: RequestPacket[RT2], /
    ) -> tuple[RT1, RT2]:
        ...

    @typing.overload
    async def send(self, pkt1: GetUsedRoomsMessage, /) -> tuple[UsedRoomsResponse]:
        ...

    @typing.overload
    async def send(self, *packets: RequestPacket[Packet]) -> tuple[Packet, ...]:
        ...

    async def send(self, *packets: RequestPacket[Packet]) -> tuple[Packet, ...]:  # type: ignore[misc]
        return tuple([response async for response in self._send(packets)])

    async def _send(self, packets: Iterable[RequestPacket[Packet]]) -> AsyncIterable[Packet]:
        for packet in packets:
            await self._write_packet(packet)
            await self._writer.drain()
            yield await self._read_response(packet.response_type)

    async def _write_packet(self, packet: Packet) -> None:
        data = packet.to_bytes()
        self._writer.write(struct.pack("!HH", packet.ID, len(data)))
        self._writer.write(data)

    async def _read_response[RT: Packet](self, response_pkt_type: type[RT]) -> RT:
        id_, flags, size = struct.unpack("!HBB", await self._reader.readexactly(4))

        if flags & JUMBO_MESSAGE_BIT:
            size += 256

        recv_payload = await self._reader.readexactly(size)

        if id_ == response_pkt_type.ID:
            return response_pkt_type.from_bytes(recv_payload)

        raise UnexpectedResponseError(id_, recv_payload)

    def close(self):
        self._writer.close()


class UnexpectedResponseError(Exception):
    id_: int
    data: bytes

    def __init__(self, id_: int, data: bytes):
        super().__init__(f"unexpected response: 0x{id_:x} {data.hex()}")
