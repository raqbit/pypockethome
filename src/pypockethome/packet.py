from __future__ import annotations

import abc
import dataclasses
import struct
from abc import ABC
from dataclasses import dataclass
from typing import Self

import abstractcp as acp


def _format_packet_repr(name: str, id_: int, fields: dict[str, object]) -> str:
    attrs = " ".join("{}={!r}".format(k, v) for k, v in fields.items())
    return f"<{name}(0x{id_:02X}) {attrs}>"


class Packet(abc.ABC, acp.Abstract):
    ID: int = acp.abstract_class_property(int)

    @classmethod
    @abc.abstractmethod
    def from_bytes(cls, raw: bytes) -> Self: ...

    @abc.abstractmethod
    def to_bytes(self) -> bytes: ...

    def __repr__(self):
        return _format_packet_repr(
            self.__class__.__name__, self.ID,
            dataclasses.asdict(self) if dataclasses.is_dataclass(self) else self.__dict__
        )


class EmptyPacket(Packet, ABC, acp.Abstract):
    def to_bytes(self) -> bytes:
        return bytes()

    @classmethod
    def from_bytes(cls, raw: bytes) -> Self:
        return cls()


class RequestPacket[RT: Packet](Packet, ABC, acp.Abstract):
    response_type: type[RT] = acp.abstract_class_property(type)


# @dataclass(frozen=True, slots=True, repr=False)
# class GetHardwareId(EmptyPacket, RequestPacket[?]):
#     ID = 0x0003
#
#     response_type = ?
#
#
# @dataclass(frozen=True, slots=True, repr=False)
# class GetApSSIDMessage(EmptyPacket, RequestPacket[?]):
#     ID = 0x378C
#
#     response_type = ?


@dataclass(frozen=True, slots=True, repr=False)
class WrongDataResponse(EmptyPacket):
    ID = 0x37DD


@dataclass(frozen=True, slots=True, repr=False)
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


@dataclass(frozen=True, slots=True, repr=False)
class GetUsedRoomsMessage(EmptyPacket, RequestPacket[UsedRoomsResponse]):
    ID = 0x8031
    response_type = UsedRoomsResponse


@dataclass(frozen=True, slots=True, repr=False)
class RoomResponse(Packet):
    ID = 0x8033

    room: int
    image_id: int
    name: str

    def to_bytes(self) -> bytes:
        return struct.pack("!B", self.room)

    @classmethod
    def from_bytes(cls, raw: bytes) -> Self:
        assert len(raw) == 17
        room, image_id = struct.unpack("!BB", raw[:2])
        return cls(room, image_id, str(raw[2:].replace(b"\x00", b" ")))


@dataclass(frozen=True, slots=True)
class GetRoomMessage(RequestPacket[RoomResponse]):
    ID = 0x8033
    response_type = RoomResponse

    room: int

    def to_bytes(self) -> bytes:
        return struct.pack("!B", self.room)

    @classmethod
    def from_bytes(cls, raw: bytes) -> Self:
        return cls(raw[0])
