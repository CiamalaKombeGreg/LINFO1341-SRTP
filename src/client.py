#!/usr/bin/env python3

# -- imports --
import argparse
import socket
import sys
import time

from srtp_packet import SRTPPacket, PacketType, PacketDecodeError


# -- Functions --
def parse_args():
    parser = argparse.ArgumentParser(description="SimpleSRTP UDP IPv6 client")
    parser.add_argument(
        "host", help="IPv6 host"
    )  # We expect the user to provide an IPv6 address or hostname that resolves to an IPv6 address.
    parser.add_argument(
        "port", type=int, help="Server UDP port"
    )  # We expect the user to provide the UDP port number of the server to which we will send the SRTP packet.
    parser.add_argument(
        "--message",
        default="Hello from SRTP client!",
        help="Payload to send in one DATA packet",
    )  # We have a default message that we will send in the payload of the DATA packet, but the user can override it.
    parser.add_argument(
        "--timeout",
        type=float,
        default=3.0,
        help="Receive timeout in seconds",
    )  # We have a default timeout of 3 seconds for receiving a response from the server, but the user can override it.
    return parser.parse_args()


def resolve_target(host: str, port: int):
    """
    Resolve the destination using IPv6 only. Returns a sockaddr usable with sendto(): (ipv6_address, port, flowinfo, scope_id)
    """

    infos = socket.getaddrinfo(
        host, port, socket.AF_INET6, socket.SOCK_DGRAM
    )  # Help resolve the host and port into a sockaddr tuple that we can use with sendto().

    if not infos:
        raise OSError(f"Could not resolve IPv6 host: {host}")

    _, _, _, _, sockaddr = infos[
        0
    ]  # We use _ for the fields we don't care about and just take the sockaddr which is what we need for sending the packet.

    # Usually already 4-tuple for IPv6, but in case it's a 2-tuple (address, port), we convert it to the full 4-tuple by adding flowinfo and scope_id as 0.
    if len(sockaddr) == 2:
        sockaddr = (sockaddr[0], sockaddr[1], 0, 0)

    return sockaddr


def make_data_packet(message: str) -> SRTPPacket:
    """
    Build one simple DATA packet.
    """
    timestamp = int(time.time()).to_bytes(4, byteorder="big", signed=False)

    return SRTPPacket(
        ptype=PacketType.DATA,
        window=1,
        seqnum=0,
        timestamp=timestamp,
        payload=message.encode("utf-8"),
    )


def main():
    args = parse_args()

    try:
        dest = resolve_target(
            args.host, args.port
        )  # It is the sockaddr tuple that we will use to send the packet to the server.
    except OSError as err:
        print(f"[!] IPv6 resolution failed: {err}", file=sys.stderr)
        sys.exit(1)

    packet = make_data_packet(args.message)
    raw_packet = packet.to_bytes()

    print(f"[+] Destination: {dest}", file=sys.stderr)
    print(
        f"[>] Sending: type={packet.ptype.name}, seq={packet.seqnum}, len={packet.length}",
        file=sys.stderr,
    )

    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sock:
        sock.settimeout(
            args.timeout
        )  # We set the default or selected timeout for receiving a response from the server.

        sock.sendto(
            raw_packet, dest
        )  # Sent the raw bytes of the packet to the server using the resolved sockaddr.

        try:
            data, addr = sock.recvfrom(
                4096
            )  # We wait for a response from the server. 4096 bytes is the maximum size of the buffer we will read from the socket.
        except socket.timeout:
            print("[!] Timeout: no response received", file=sys.stderr)
            sys.exit(1)

        print(f"[<] Received {len(data)} bytes from {addr}", file=sys.stderr)

        try:
            reply = SRTPPacket.from_bytes(data)
        except PacketDecodeError as exc:
            print(f"[!] Invalid SRTP response: {exc}", file=sys.stderr)
            sys.exit(1)

        print(
            f"[<] Decoded response: type={reply.ptype.name}, seq={reply.seqnum}, win={reply.window}, len={reply.length}",
            file=sys.stderr,
        )

        if reply.ptype != PacketType.ACK:
            print("[!] Warning: expected an ACK packet", file=sys.stderr)


if __name__ == "__main__":
    main()
