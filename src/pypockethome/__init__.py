""" """

import asyncio


class Connection:
    _reader: asyncio.StreamReader
    _writer: asyncio.StreamWriter

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self._reader = reader
        self._writer = writer


async def connect(
    host: str,
    *,
    port: int,
) -> Connection:
    reader, writer = await asyncio.open_connection(
        host=host,
        port=port,
    )

    return Connection(reader, writer)
