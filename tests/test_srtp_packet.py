import struct
import pytest

from src.srtp_packet import (
    SRTPPacket,
    PacketType,
    PacketDecodeError,
    MAX_PAYLOAD_SIZE,
)

# Helpers


def make_packet(
    ptype=PacketType.DATA,
    window=1,
    seqnum=1,
    timestamp=b"ABCD",
    payload=b"hello",
):
    """
    Small helper to create packets more quickly in tests.
    This avoids repeating the same constructor everywhere.
    """
    return SRTPPacket(
        ptype=ptype,
        window=window,
        seqnum=seqnum,
        timestamp=timestamp,
        payload=payload,
    )


# Valid packets


def test_encode_decode_data_packet():
    """
    A normal DATA packet should:
    - encode to bytes
    - decode back to the same packet
    """
    pkt = make_packet(
        ptype=PacketType.DATA,
        window=12,
        seqnum=345,
        timestamp=b"\x01\x02\x03\x04",
        payload=b"hello",
    )

    raw = pkt.to_bytes()
    decoded = SRTPPacket.from_bytes(raw)

    assert decoded == pkt


def test_encode_decode_ack_packet():
    """
    A normal ACK packet has no payload.
    It should also round-trip correctly.
    """
    pkt = make_packet(
        ptype=PacketType.ACK,
        window=3,
        seqnum=10,
        timestamp=b"WXYZ",
        payload=b"",
    )

    raw = pkt.to_bytes()
    decoded = SRTPPacket.from_bytes(raw)

    assert decoded == pkt


# Header field packing


def test_contains_correct_fields():
    """
    Check that the first 32 bits are packed correctly:

    - type   : 2 bits
    - window : 6 bits
    - length : 13 bits
    - seqnum : 11 bits
    """
    pkt = make_packet(
        ptype=PacketType.ACK,
        window=12,
        seqnum=341,
        timestamp=b"\x00\x00\x00\x00",
        payload=b"",
    )

    raw = pkt.to_bytes()
    first_word = struct.unpack("!I", raw[:4])[0]

    decoded_type = (first_word >> 30) & 0b11
    decoded_window = (first_word >> 24) & 0b111111
    decoded_length = (first_word >> 11) & 0x1FFF
    decoded_seqnum = first_word & 0x7FF

    assert decoded_type == PacketType.ACK
    assert decoded_window == 12
    assert decoded_length == 0
    assert decoded_seqnum == 341


# CRC checks


def test_bad_crc1():
    """
    If CRC1 is modified, decoding must fail.
    """
    pkt = make_packet(payload=b"payload")
    raw = bytearray(pkt.to_bytes())

    # Corrupt one byte inside CRC1
    raw[8] ^= 0x01  # This is a XOR to flip a single bit

    with pytest.raises(PacketDecodeError, match="CRC1"):
        SRTPPacket.from_bytes(bytes(raw))


def test_bad_crc2():
    """
    If CRC2 is modified, decoding must fail.
    """
    pkt = make_packet(payload=b"payload")
    raw = bytearray(pkt.to_bytes())

    # Corrupt the last byte (inside CRC2)
    raw[-1] ^= 0x01

    with pytest.raises(PacketDecodeError, match="CRC2"):
        SRTPPacket.from_bytes(bytes(raw))


# Invalid packet structure


def test_packet_too_short():
    """
    A packet shorter than the minimum header size is invalid.
    """
    with pytest.raises(PacketDecodeError, match="too short"):
        SRTPPacket.from_bytes(b"\x00\x01\x02")


def test_invalid_type():
    """
    Type 00 is invalid in this protocol. We build a valid ACK packet, then overwrite its type bits with 00.
    """
    pkt = make_packet(ptype=PacketType.ACK, payload=b"")
    raw = bytearray(pkt.to_bytes())

    first_word = struct.unpack("!I", raw[:4])[0]

    # Force top 2 bits (type) to 00
    first_word &= 0x3FFFFFFF  # This is an AND to clear the top 2 bits
    raw[:4] = struct.pack("!I", first_word)

    with pytest.raises(PacketDecodeError, match="invalid packet type"):
        SRTPPacket.from_bytes(bytes(raw))


def test_length_above_1024():
    """
    If the header says Length > 1024, the packet must be rejected.
    """
    pkt = make_packet(ptype=PacketType.ACK, payload=b"")
    raw = bytearray(pkt.to_bytes())

    first_word = struct.unpack("!I", raw[:4])[0]

    # Clear the length field, then set it to 1025
    first_word &= ~((0x1FFF) << 11)
    first_word |= 1025 << 11

    raw[:4] = struct.pack("!I", first_word)

    with pytest.raises(PacketDecodeError, match="length"):
        SRTPPacket.from_bytes(bytes(raw))


def test_incomplete_payload():
    """
    If the payload is incomplete, decoding must fail.
    """
    pkt = make_packet(payload=b"payload")
    raw = pkt.to_bytes()

    # Remove a few bytes at the end
    truncated = raw[:-3]

    with pytest.raises(PacketDecodeError):
        SRTPPacket.from_bytes(truncated)


def test_zero_length_packet_with_extra_bytes():
    """
    If Length = 0 (for example an ACK),
    but there are still extra bytes after CRC1,
    the packet should be rejected.
    """
    pkt = make_packet(
        ptype=PacketType.ACK,
        window=2,
        seqnum=99,
        timestamp=b"ABCD",
        payload=b"",
    )

    raw = pkt.to_bytes()

    # Append unexpected extra bytes after a zero-length packet
    malformed = raw + b"EXTRA"

    with pytest.raises(PacketDecodeError, match="unexpected trailing bytes"):
        SRTPPacket.from_bytes(malformed)


# Encode-time validation


def test_payload_too_large():
    """
    Creating a packet with more than 1024 bytes of payload must fail.
    """
    with pytest.raises(ValueError, match="payload too large"):
        make_packet(payload=b"x" * (MAX_PAYLOAD_SIZE + 1))


def test_empty_sack():
    """
    In our implementation, an empty SACK is refused.
    The sender should use ACK instead.
    """
    with pytest.raises(ValueError):
        make_packet(ptype=PacketType.SACK, payload=b"")
