import abc
import struct
from abc import ABC
from dataclasses import dataclass
from typing import Self

def _format_packet_repr(name: str, id_: int, attrs: dict[str, object]) -> str:
    attrs = " ".join("{}={!r}".format(k, v) for k, v in attrs.items())
    return f"<{name}(0x{id_:02X}) {attrs}>"

class Packet(abc.ABC):
    @staticmethod
    @property
    @abc.abstractmethod
    def ID(): ...

    @classmethod
    @abc.abstractmethod
    def from_bytes(cls, raw: bytes) -> Self: ...

    @abc.abstractmethod
    def to_bytes(self) -> bytes: ...

    def __repr__(self):
        return _format_packet_repr(self.__class__.__name__, self.ID, self.__dict__)


@dataclass(frozen=True, slots=True)
class UnknownResponse:
    id_: int
    data: bytes

    def __repr__(self):
        return _format_packet_repr(self.__class__.__name__, self.id_, {"length": len(self.data)})


class EmptyPacket(Packet, ABC):
    def to_bytes(self) -> bytes:
        return bytes()

    @classmethod
    def from_bytes(cls, raw: bytes) -> Self:
        return cls()


class RequestPacket[R: Packet | UnknownResponse](Packet, ABC): ...


class GetHardwareId(EmptyPacket, RequestPacket[UnknownResponse]):
    ID = 0x0003


class GetApSSIDMessage(EmptyPacket, RequestPacket[UnknownResponse]):
    ID = 0x378C


@dataclass(frozen=True, slots=True)
class UsedRoomsResponse(Packet):
    ID = 0x8031

    # Two longs (total 128 bits), every bit is a room that can be set/unset
    _used: bytes

    @property
    def used_ids(self) -> set[int]:
        return {i for i in range(128) if self._used[i // 8] & (1 << (i % 8))}

    def to_bytes(self) -> bytes:
        return struct.pack("!16s", self._used)

    @classmethod
    def from_bytes(cls, raw: bytes) -> Self:
        (bitfield,) = struct.unpack("!16s", raw)
        return cls(bitfield)

    def __repr__(self):
        return _format_packet_repr(self.__class__.__name__, self.ID, {"rooms": self.used_ids})



class GetUsedRoomsMessage(EmptyPacket, RequestPacket[UsedRoomsResponse]):
    ID = 0x8031

@dataclass(frozen=True, slots=True)
class RoomResponse(Packet):
    ID = 0x8033

    room: int
    image_id: int
    name: str

    def to_bytes(self) -> bytes:
        return struct.pack("!B", self.room)

    @classmethod
    def from_bytes(cls, raw: bytes) -> Self:
        room, image_id = struct.unpack("!BB", raw[:2])
        return cls(room, image_id, str(raw[2:]))


@dataclass(frozen=True, slots=True)
class GetRoomMessage(RequestPacket[RoomResponse]):
    ID = 0x8033

    room: int

    def to_bytes(self) -> bytes:
        return struct.pack("!B", self.room)

    @classmethod
    def from_bytes(cls, raw: bytes) -> Self:
        return cls(raw[0])


# TODO: Packets should have a client bound / server bound marker, and this should just be a list of all packets
#   That way the proxy can also make use of this
ALL_KNOWN_RESPONSE_PACKETS = [RoomResponse, UsedRoomsResponse]
