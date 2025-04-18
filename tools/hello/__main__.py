import asyncio

import pypockethome
from pypockethome import Connection
from pypockethome.packet import GetUsedRoomsMessage, GetRoomMessage, UnknownResponse, RoomResponse


async def main():
    client: Connection

    # TODO: Somehow this is going right via the proxy, but not directly
    #   Seems like an issue with how the bytes are buffered/written to the socket.
    async with pypockethome.connect("192.168.0.112", 4000) as client:
        # while True:
        res = await client.send(GetRoomMessage(i) for i in range(7))
        print("Rooms", res)

        # rooms = await client.send(GetRoomMessage(room) for room in res.used_ids)
        #
        # for room in rooms:
        #     match room:
        #         case RoomResponse():
        #             print("Room", room)
        #         case _:
        #             print("Fail", room)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
