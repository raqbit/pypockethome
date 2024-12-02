import asyncio
import struct
from collections.abc import Mapping
from typing import Iterable, Final, AsyncIterable

from .packet import Packet, ALL_KNOWN_RESPONSE_PACKETS, UnknownResponse, RequestPacket

JUMBO_MESSAGE_BIT: Final[int] = 0b00000001


class Connection:
    _reader: asyncio.StreamReader
    _writer: asyncio.StreamWriter

    _known_response_packets: Mapping[int, Packet]

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self._reader = reader
        self._writer = writer

        self._known_response_packets = {
            type_.ID: type_ for type_ in ALL_KNOWN_RESPONSE_PACKETS
        }

    async def send_one[RT](self, packet: RequestPacket[RT]) -> RT | UnknownResponse:
        return (await self.send([packet]))[0]

    async def send[RT](self, packets: Iterable[RequestPacket[RT]]) -> list[RT | UnknownResponse]:
        return [response async for response in self._send(packets)]

    async def _send(self, packets: Iterable[Packet]) -> AsyncIterable[Packet | UnknownResponse]:
        for packet in packets:
            await self._write_packet(packet)
            await self._writer.drain()
            yield await self._read_response()

    async def _write_packet(self, packet: Packet) -> None:
        data = packet.to_bytes()
        self._writer.write(struct.pack("!HH", packet.ID, len(data)))
        self._writer.write(data)

    async def _read_response(self) -> Packet | UnknownResponse:
        id_, flags, size = struct.unpack("!HBB", await self._reader.readexactly(4))

        if flags & JUMBO_MESSAGE_BIT:
            size += 256

        recv_payload = await self._reader.readexactly(size)

        if pkt := self._known_response_packets.get(id_):
            return pkt.from_bytes(recv_payload)

        return UnknownResponse(id_, recv_payload)

    def close(self):
        self._writer.close()
