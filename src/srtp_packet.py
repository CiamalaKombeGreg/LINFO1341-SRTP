# -- imports --
from dataclasses import dataclass
from enum import IntEnum
import struct
import zlib

# -- constants --
MAX_PAYLOAD_SIZE = (
    1024  # The fixed size of the payload is 1024 bytes, but it can be shorter.
)
FIXED_HEADER_WITHOUT_CRC1 = 8  # first 4 bytes + timestamp(4 bytes)
CRC_SIZE = 4  # Size of CRC1 and CRC2 in bytes
MIN_PACKET_SIZE = (
    FIXED_HEADER_WITHOUT_CRC1 + CRC_SIZE
)  # 12 bytes, any packet must be at least this long to be valid.


# -- classes --
class PacketType(IntEnum):
    """Packet types:
    00: reserved (invalid)
    01: DATA
    10: ACK
    11: SACK

        Note: they represent the two highest bits of the first 32-bit word, so their values are 1, 2, and 3 respectively.
    """

    DATA = 1  # 01
    ACK = 2  # 10
    SACK = 3  # 11


class PacketDecodeError(ValueError):
    """Raised when decoding a packet who failed due to invalid format or content."""


@dataclass(
    frozen=True
)  # Packet are immutable after creation, which is a good fit for this use case.
class SRTPPacket:
    ptype: PacketType
    window: int
    seqnum: int
    timestamp: bytes  # exactly 4 raw bytes
    payload: bytes = b""
    # Note: we don't store CRC1 and CRC2 as fields since they are always derived from the other fields.
    # Length is also derived from the payload, so we don't store it as a separate field either.

    def __post_init__(
        self,
    ) -> (
        None
    ):  # We return None here since __post_init__ is only for validation and doesn't produce a new instance.
        if self.ptype not in (PacketType.DATA, PacketType.ACK, PacketType.SACK):
            raise ValueError("invalid packet type")

        if not (0 <= self.window <= 63):
            raise ValueError("window must be in [0, 63]")

        if not (0 <= self.seqnum <= 2047):
            raise ValueError("seqnum must be in [0, 2047]")

        if (
            not isinstance(
                self.timestamp, (bytes, bytearray)
            )  # Timestamp must be bytes-like since it is treated as opaque raw bytes.
            or len(self.timestamp) != 4
        ):
            raise ValueError("timestamp must be exactly 4 bytes")

        if not isinstance(
            self.payload, (bytes, bytearray)
        ):  # Payload must be bytes-like since it is treated as opaque raw bytes.
            raise ValueError("payload must be bytes-like")

        if len(self.payload) > MAX_PAYLOAD_SIZE:
            raise ValueError("payload too large")

        # SACK with length 0 is equivalent to ACK. On the encoding side to keep emitted packets clean.
        if self.ptype == PacketType.SACK and len(self.payload) == 0:
            raise ValueError("SACK with empty payload should be encoded as ACK")

    @property
    def length(
        self,
    ) -> int:  # Length is derived from the payload, so we compute it on the fly.
        return len(self.payload)

    def to_bytes(self) -> bytes:
        """
        Encode the packet according to the SRTP format.

        First 32 bits (first line of the packet):
            type   : 2 bits
            window : 6 bits
            length : 13 bits
            seqnum : 11 bits

        Endianness (for the rest of the packet):
            - the 32-bit first word is encoded in network byte order (big-endian)
            - CRC1 and CRC2 are encoded in network byte order
            - timestamp is opaque raw bytes
        """
        first_word = (
            ((int(self.ptype) & 0b11) << 30)
            | ((self.window & 0b111111) << 24)
            | (
                (self.length & 0x1FFF) << 11
            )  # This is 13 bits for length, so we mask with 0x1FFF to ensure it fits in that field.
            | (
                self.seqnum & 0x7FF
            )  # This is 11 bits for seqnum, so we mask with 0x7FF to ensure it fits in that field.
        )  # 32 bits total, with the fields packed according to the specification.

        first_part = struct.pack("!I", first_word) + bytes(
            self.timestamp
        )  # !I means big-endian unsigned int, which is the format for the first 32-bit word.

        crc1 = (
            zlib.crc32(first_part) & 0xFFFFFFFF
        )  # Integers are unbounded in Python, but we need to ensure CRC values fit in 32 bits, so we mask with 0xFFFFFFFF.
        encoded = first_part + struct.pack("!I", crc1)

        if self.length > 0:
            crc2 = zlib.crc32(self.payload) & 0xFFFFFFFF
            encoded += bytes(self.payload) + struct.pack("!I", crc2)

        return encoded

    @classmethod  # Because we want to create an instance of the class from bytes, we use a class method.
    def from_bytes(cls, data: bytes) -> "SRTPPacket":
        """
        Decode and validate an SRTP packet.

        Validation performed:
            - minimal size
            - valid type
            - length <= 1024
            - CRC1 correct
            - payload not truncated
            - if CRC2 is present, it must match
        """
        if len(data) < MIN_PACKET_SIZE:
            raise PacketDecodeError("packet too short")

        first_word = struct.unpack("!I", data[0:4])[
            0
        ]  # We unpack the first 4 bytes as a big-endian unsigned int to get the first word, which contains the type, window, length, and seqnum fields.

        ptype_value = (first_word >> 30) & 0b11
        window = (first_word >> 24) & 0b111111
        length = (first_word >> 11) & 0x1FFF
        seqnum = first_word & 0x7FF

        if ptype_value not in (1, 2, 3):
            raise PacketDecodeError("invalid packet type")

        if length > MAX_PAYLOAD_SIZE:
            raise PacketDecodeError("invalid payload length (>1024)")

        timestamp = data[4:8]

        expected_crc1 = struct.unpack("!I", data[8:12])[0]
        computed_crc1 = zlib.crc32(data[0:8]) & 0xFFFFFFFF
        if expected_crc1 != computed_crc1:
            raise PacketDecodeError("invalid CRC1")

        remaining = data[12:]

        if length == 0:
            # ACKs normally end here.
            # If extra bytes exist, they are malformed for this specification since ACKs should not have a payload or CRC2.
            if remaining:
                raise PacketDecodeError(
                    "unexpected trailing bytes for zero-length packet"
                )

            return cls(
                ptype=PacketType(ptype_value),
                window=window,
                seqnum=seqnum,
                timestamp=timestamp,
                payload=b"",
            )

        # Need payload + CRC2
        if len(remaining) < length:
            raise PacketDecodeError("truncated payload")

        if len(remaining) < length + CRC_SIZE:
            raise PacketDecodeError("missing CRC2")

        payload = remaining[:length]
        crc2_bytes = remaining[length : length + CRC_SIZE]
        trailing = remaining[length + CRC_SIZE :]

        if trailing:
            raise PacketDecodeError("unexpected trailing bytes after CRC2")

        expected_crc2 = struct.unpack("!I", crc2_bytes)[0]
        computed_crc2 = zlib.crc32(payload) & 0xFFFFFFFF
        if expected_crc2 != computed_crc2:
            raise PacketDecodeError("invalid CRC2")

        return cls(
            ptype=PacketType(ptype_value),
            window=window,
            seqnum=seqnum,
            timestamp=timestamp,
            payload=payload,
        )
