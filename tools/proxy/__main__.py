"""
A small proxy for reverse-engineering PocketHome communication.
"""

import asyncio
import struct
from asyncio import StreamReader, StreamWriter
from collections.abc import Mapping
from typing import Callable

from binascii import hexlify

PORT = 8888

UPSTREAM_HOST = "192.168.0.112"
UPSTREAM_PORT = 4000


async def pipe(
    reader: StreamReader,
    writer: StreamWriter,
    tap: Callable[[bytes], None] = lambda _: None,
) -> None:
    try:
        while not reader.at_eof():
            data = await reader.read(1024)
            if not data:
                break
            tap(data)
            writer.write(data)
    finally:
        writer.close()


APP_TO_UPSTREAM: Mapping[int, str] = {
    0x0003: "GetHardwareId",
    0x0007: "SendTime",
    0x0037: "GetDeviceWhichActivatedBoiler",
    0x7FFF: "MultiMessage",
    0x8008: "GetBaseCounterTwoBytes",
    0x8009: "GetProgramCounter",
    0x800A: "GetConstantsCounter",
    0x800B: "GetScenes",
    0x802F: "GetUniqueNumberPh",
    0x8031: "GetUsedRooms",
    0x803A: "GetCentralSettings",
    0x8041: "GetActualTemp",
    0xD450: "GetPhType",
}


def parse_app_message(data: bytes) -> (str, int, bytes, bytes):
    m_type, size = struct.unpack(">HH", data[:4])
    m_type_str = APP_TO_UPSTREAM.get(m_type, f"{data[0]:02X}{data[1]:02X}")
    payload = data[4:4+size]
    remainder = data[4+size:]
    return m_type_str, size, payload, remainder


def tap_app_to_upstream(data: bytes) -> None:
    m_type, size, payload, _ = parse_app_message(data)

    print(f"A->U: {m_type}[{size}B] " + hexlify(payload).decode("utf-8"))

    if m_type == "MultiMessage":
        remainder = payload
        while True:
            m_type, size, payload, remainder = parse_app_message(remainder)
            print(f"\tA->U: {m_type}[{size}B] " + hexlify(payload).decode("utf-8"))
            if not remainder:
                break


def tap_upstream_to_app(data: bytes) -> None:
    print("U->A: " + hexlify(data).decode("utf-8"))


async def handle_connection(reader: StreamReader, writer: StreamWriter):
    host, port = writer.get_extra_info("peername")[:2]
    print(f"New connection from [{host}]:{port}")

    try:
        upstream_read, upstream_writer = await asyncio.open_connection(
            UPSTREAM_HOST, UPSTREAM_PORT
        )
    except OSError:
        print("Could not connect to upstream")
        writer.close()
        return

    pipe1 = pipe(reader, upstream_writer, tap=tap_app_to_upstream)
    pipe2 = pipe(upstream_read, writer, tap=tap_upstream_to_app)
    await asyncio.gather(pipe1, pipe2)
    print(f"Client [{host}]:{port} closed the connection")


async def main():
    server = await asyncio.start_server(handle_connection, host="0.0.0.0", port=PORT)
    print("Listening on :8888")
    await server.start_serving()
    await server.wait_closed()


if __name__ == "__main__":
    try:
        asyncio.run(main(), debug=True)
    except KeyboardInterrupt:
        print("Exiting")
