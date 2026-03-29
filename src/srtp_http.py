#!/usr/bin/env python3

# -- imports --
import os
import time
from pathlib import Path
from urllib.parse import urlparse

from srtp_packet import SRTPPacket, PacketType, MAX_PAYLOAD_SIZE


# -- Constants --
DEFAULT_SAVE_PATH = "llm.model"  # Default path to save the model file for the client.
MAX_SINGLE_RESPONSE = 1024
SEQ_MODULO = 2**11  # Seqnum is on 11 bits.


# -- SRTP helper functions --
def make_timestamp() -> bytes:
    """
    Build a 4-byte opaque timestamp.
    """
    return int(time.time()).to_bytes(4, byteorder="big", signed=False)


def next_seqnum(seqnum: int) -> int:
    """
    Return the next sequence number modulo 2^11.
    """
    return (seqnum + 1) % SEQ_MODULO

def seq_add(seqnum: int, offset: int) -> int:
    """to progress in the circular space"""
    return (seqnum + offset) % SEQ_MODULO


def seq_in_window(seqnum: int, base: int, window_size: int) -> bool:
    """
    Check if the seqnum is in the windows. The client use it to decides if it accepts
    or not the packets
    """
    if window_size <= 0:
        return False
    distance = (seqnum - base) % SEQ_MODULO
    return distance < window_size




def make_data_packet(payload: bytes, seqnum: int = 0, window: int = 1) -> SRTPPacket:
    """
    Build a SRTP DATA packet.
    """
    return SRTPPacket(
        ptype=PacketType.DATA,
        window=window,
        seqnum=seqnum % SEQ_MODULO,
        timestamp=make_timestamp(),
        payload=payload,
    )


def make_ack_for(packet: SRTPPacket, window: int = 1) -> SRTPPacket:
    """
    Build an ACK for a received DATA packet.

    Reminder:
    - ACK Seqnum = next expected sequence number
    - ACK Timestamp = Timestamp of the last received DATA packet
    """
    return SRTPPacket(
        ptype=PacketType.ACK,
        window=window,
        seqnum=next_seqnum(packet.seqnum),
        timestamp=packet.timestamp,
        payload=b"",
    )

def make_ack(seqnum: int, window: int, timestamp: bytes) -> SRTPPacket:
    """
    Creates an ACK without an input DATA packet
    Required in receive_file() when the client needs to ACK without a source packet
    """
    return SRTPPacket(
        ptype=PacketType.ACK,
        window=window,
        seqnum=seqnum % SEQ_MODULO,
        timestamp=timestamp,
        payload=b"",
    )

def encode_sack_payload(out_of_order_seqnums: list) -> bytes:
    """
    Encode a seqnum list out of sequence
 
    """
    if not out_of_order_seqnums:
        return b""
 
    # Concatenate all sequences into a bitstream
    bit_string = ""
    for seq in out_of_order_seqnums:
        bit_string += format(seq & 0x7FF, "011b") 
 
    
    remainder = len(bit_string) % 32
    if remainder != 0:
        bit_string += "0" * (32 - remainder)
 
    
    payload = bytearray()
    for i in range(0, len(bit_string), 8):
        payload.append(int(bit_string[i : i + 8], 2))
 
    return bytes(payload)
 
 
def decode_sack_payload(payload: bytes, count_hint: int = -1) -> list:
    """
    Decodes the payload of a SACK packet into a list of sequences
    The sequences are read 11 bits at a time
    """
    if not payload:
        return []
 
    bit_string = ""
    for byte in payload:
        bit_string += format(byte, "08b")
 
    seqnums = []
    total_bits = len(bit_string)
    max_seqnums = total_bits // 11 
 
    for i in range(max_seqnums):
        start = i * 11
        chunk = bit_string[start : start + 11]
        seq = int(chunk, 2)
        seqnums.append(seq)
 
    return seqnums
 
 
def make_sack(seqnum: int, window: int, timestamp: bytes, out_of_order: list) -> SRTPPacket:
    """
        Creates a SACK if the buffer contains out-of-sequence packets.
        If the list is empty, returns a normal ACK 
    """
    if not out_of_order:
        
        return make_ack(seqnum, window, timestamp)
 
    payload = encode_sack_payload(out_of_order)
    return SRTPPacket(
        ptype=PacketType.SACK,
        window=window,
        seqnum=seqnum % SEQ_MODULO,
        timestamp=timestamp,
        payload=payload,
    )

def split_file_into_chunks(data: bytes, chunk_size: int = MAX_PAYLOAD_SIZE) -> list:
    """Splits a file into blocks of up to 1024 bytes
        Each block will become the payload of a DATA packet
    """
    if not data:
        return []
    return [data[i : i + chunk_size] for i in range(0, len(data), chunk_size)]


# -- HTTP 0.9 functions --
def parse_http09_url(url: str) -> tuple[str, int, str]:
    """
    Parse a URL like http://hostname:port/path and return the components.

    Returns:
        (host, port, path)
    """
    parsed = urlparse(url)

    if parsed.scheme != "http":
        raise ValueError("Only http:// URLs are supported")

    if not parsed.hostname:
        raise ValueError("Missing hostname in URL")

    if parsed.port is None:
        raise ValueError("URL must contain an explicit port")

    path = parsed.path or "/"

    return parsed.hostname, parsed.port, path


def build_http09_get(path: str) -> bytes:
    """
    Build the HTTP 0.9 request.
    """
    return f"GET {path}".encode("ascii")


def parse_http09_get(payload: bytes) -> str:
    """
    Parse an incoming HTTP 0.9 GET request.
    """
    try:
        text = payload.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("request is not valid ASCII") from exc

    if "\n" in text or "\r" in text:
        raise ValueError("HTTP 0.9 headers / extra lines are not supported")

    if not text.startswith("GET "):
        raise ValueError("only GET is supported")

    path = text[4:].strip()

    if not path.startswith("/"):
        raise ValueError("request path must start with '/'")

    return path


def resolve_requested_file(root: str, request_path: str) -> Path:
    """
    Resolve the requested HTTP path under the server root safely.

    Example:
        root = /home/www
        request_path = /llm/small
        => /home/www/llm/small
    """
    root_path = Path(root).resolve()

    # Remove the leading slash before joining.
    relative_path = request_path.lstrip("/")

    candidate = (root_path / relative_path).resolve()

    # Prevent path traversal outside the root.
    if os.path.commonpath([str(root_path), str(candidate)]) != str(root_path):
        raise ValueError("requested path escapes server root")

    return candidate


def load_single_response(root: str, request_path: str) -> bytes:
    """
    Load the file requested by HTTP 0.9.

    Only supports a single SRTP response packet for now, so:
    - if file does not exist -> return empty payload
    - if file is too large (>1024 bytes) -> return empty payload for now
    """

    try:
        file_path = resolve_requested_file(root, request_path)
    except ValueError:
        return b""

    if not file_path.exists() or not file_path.is_file():
        return b""

    content = file_path.read_bytes()

    #why this condition ? 
    """
    if len(content) > MAX_SINGLE_RESPONSE:
        return b""
    """

    return content
