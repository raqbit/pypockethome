""" """

import asyncio
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator

from ._connection import Connection


@asynccontextmanager
async def connect(
    host: str,
    port: int,
) -> AsyncGenerator[Connection, Any]:
    reader, writer = await asyncio.open_connection(
        host=host,
        port=port,
    )

    connection = Connection(reader, writer)

    try:
        yield connection
    finally:
        connection.close()


__all__ = [
    "Connection",
    "connect",
]
