import asyncio

import pypockethome
from pypockethome import Connection
from pypockethome.packet import GetUsedRoomsMessage, GetRoomMessage, UnknownResponse, RoomResponse


async def main():
    client: Connection

    # TODO: Somehow this is going right via the proxy, but not directly
    #   Seems like an issue with how the bytes are buffered/written to the socket.
    async with pypockethome.connect("localhost", 4000) as client:
        # while True:
        res = await client.send_one(GetUsedRoomsMessage())
        print("Rooms", res)

        rooms = await client.send(GetRoomMessage(room) for room in res.used_ids)

        for room in rooms:
            match room:
                case UnknownResponse():
                    print("Fail", room)
                case RoomResponse():
                    print("Room", room)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
