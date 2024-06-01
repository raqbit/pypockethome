"""
A small proxy for reverse-engineering PocketHome communication.
"""

import asyncio
import struct
from asyncio import StreamReader, StreamWriter
from binascii import hexlify
from collections.abc import Callable, Mapping

PORT = 4000

HUB_HOST = "192.168.0.112"
HUB_PORT = 4000


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

JUMBO_MESSAGE_BIT = 0b00000001

APP_TO_HUB: Mapping[int, str] = {
    0x0003: "GetHardwareIdMessage",
    0x0007: "SendTimeMessage",
    0x0037: "GetDeviceWhichActivatedBoilerMessage",
    0x7FFF: "MultiMessage",
    0x8008: "GetBaseCounterTwoBytesMessage",
    0x8009: "GetProgramCounterMessage",
    0x800A: "GetConstantsCounterMessage",
    0x800B: "GetScenesMessage",
    0x800D: "GetProgramMessage",
    0x802F: "GetUniqueNumberPhMessage",
    0x8031: "GetUsedRoomsMessage",
    0x8033: "GetRoomMessage",
    0x8034: "GetScenesLengthDevicesCount",
    0x803A: "GetCentralSettingsMessage",
    0x8041: "GetActualTempMessage",
    0x8050: "GetDeviceDataMessage",
    0xD450: "GetPhTypeMessage",
}

# The ID of responses either equal the ID of the request or have (positive) offset 0x8000
HUB_TO_APP: Mapping[int, str] = {
    # 0x8001: "CounterResponse", # Seems to only occur sometimes??
    0x8003: "HardwareIdResponse",
    0x8007: "TimeResponse",
    0x8008: "BaseCounterTwoBytesResponse",
    0x8009: "ProgramCounterResponse",
    0x800A: "ConstantsCounterResponse",
    0x800B: "ScenesCounterResponse",
    0x800D: "ProgramResponse",
    0x802f: "UniqueNumberPhResponse",
    0x8037: "DeviceWhichActivatedBoilerResponse",
    0x8031: "UsedRoomsResponse",
    0x8033: "RoomResponse",
    0x8034: "GetScenesLengthDevicesCount",
    0x8041: "ActualTempResponse",
    0x8050: "DeviceDataResponse",
    0x803a: "CentralSettingsResponse",
    0xD450: "PhTypeResponse",
    0xFFFF: "MultiResponse",
}

def parse_app_message(data: bytes) -> (str, int, bytes, bytes):
    m_type, size = struct.unpack(">HH", data[:4])
    m_type_str = APP_TO_HUB.get(m_type, f"{data[0]:02X}{data[1]:02X}")
    payload = data[4:4+size]
    remainder = data[4+size:]
    return m_type_str, size, payload, remainder

def parse_hub_message(data: bytes) -> (str, int, int, bytes, bytes):
    m_type, flags, size = struct.unpack(">HBB", data[:4])

    if flags & JUMBO_MESSAGE_BIT:
        size += 256

    m_type_str = HUB_TO_APP.get(m_type, f"{data[0]:02X}{data[1]:02X}")
    payload = data[4:4+size]
    remainder = data[4+size:]
    return m_type_str, flags, size, payload, remainder


def tap_app_to_hub(data: bytes) -> None:
    # TODO: `data` might not be a full packet, this should be handled correctly
    m_type, size, payload, _ = parse_app_message(data)

    print(f"A->H: {m_type}[{size}B] " + hexlify(payload).decode("utf-8"))

    if m_type == "MultiMessage":
        remainder = payload
        while True:
            m_type, size, payload, remainder = parse_app_message(remainder)
            print(f"\tA->H: {m_type}[{size}B] " + hexlify(payload).decode("utf-8"))
            if not remainder:
                break


def tap_hub_to_app(data: bytes) -> None:
    m_type, flags, size, payload, _ = parse_hub_message(data)

    print(f"H->A: {m_type}{{{flags:08b}}}[{size}B] " + hexlify(payload).decode("utf-8"))

    if m_type == "MultiResponse":
        remainder = payload
        while True:
            m_type, flags, size, payload, remainder = parse_hub_message(remainder)
            print(f"\tH->A: {m_type}{{{flags:08b}}}[{size}B] " + hexlify(payload).decode("utf-8"))
            if not remainder:
                break


async def handle_connection(reader: StreamReader, writer: StreamWriter):
    host, port = writer.get_extra_info("peername")[:2]
    print(f"New connection from [{host}]:{port}")

    try:
        hub_reader, hub_writer = await asyncio.open_connection(HUB_HOST, HUB_PORT)
    except OSError:
        print("Could not connect to hub")
        writer.close()
        return

    await asyncio.gather(
        pipe(reader, hub_writer, tap=tap_app_to_hub),
        pipe(hub_reader, writer, tap=tap_hub_to_app),
    )
    print(f"Client [{host}]:{port} closed the connection")


async def main():
    server = await asyncio.start_server(handle_connection, host="0.0.0.0", port=PORT)
    print(f"Listening on :{PORT}")
    await server.start_serving()
    await server.wait_closed()


if __name__ == "__main__":
    try:
        asyncio.run(main(), debug=True)
    except KeyboardInterrupt:
        print("Exiting")
