#!/usr/bin/env python3

# -- imports --
import argparse
import socket
import sys
import time

from srtp_packet import SRTPPacket, PacketType, PacketDecodeError
from srtp_http import (
    parse_http09_get,
    load_single_response,
    make_data_packet,
    make_ack_for,
)


# -- Functions --
def parse_args():
    parser = argparse.ArgumentParser(description="Simple SRTP UDP IPv6 server")
    parser.add_argument(
        "--root",
        default=".",
        help="Directory from which requested files are served (default: current directory)",
    )  # Root directory for serving files. This is used when we receive an HTTP/0.9 GET request.
    parser.add_argument(
        "host", help="IPv6 bind address or hostname"
    )  # Ipv6 address or hostname we listen on.
    parser.add_argument("port", type=int, help="UDP port to listen on")
    return parser.parse_args()


def resolve_bind_address(host: str, port: int):
    """
    Resolve the bind address using IPv6 only. Returns a sockaddr usable with bind(): (ipv6_address, port, flowinfo, scope_id)
    """
    infos = socket.getaddrinfo(
        host,
        port,
        socket.AF_INET6,
        socket.SOCK_DGRAM,
        0,
        socket.AI_PASSIVE,
    )  # We use AI_PASSIVE to indicate that we want to bind to the address for listening.

    if not infos:
        raise OSError(f"could not resolve IPv6 bind address: {host}")

    _, _, _, _, sockaddr = infos[
        0
    ]  # We use _ for the fields we don't care about and just take the sockaddr which is what we need for sending the packet.

    # Usually already 4-tuple for IPv6, but in case it's a 2-tuple (address, port), we convert it to the full 4-tuple by adding flowinfo and scope_id as 0.
    if len(sockaddr) == 2:
        sockaddr = (sockaddr[0], sockaddr[1], 0, 0)

    return sockaddr


def main():
    args = parse_args()

    try:
        bind_addr = resolve_bind_address(
            args.host, args.port
        )  # It is the sockaddr tuple that we will use to send the packet to the server.
    except OSError as exc:
        print(f"[!] IPv6 bind resolution failed: {exc}", file=sys.stderr)
        sys.exit(1)

    print("[+] Starting SRTP UDP IPv6 server", file=sys.stderr)
    print(f"[+] Bind addr : {bind_addr}", file=sys.stderr)
    print(f"[+] Serving files from: {args.root}", file=sys.stderr)

    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sock:
        sock.bind(
            bind_addr
        )  # We bind the socket to the resolved bind address so that we can receive packets sent to that address and port.

        while True:
            try:
                data, addr = sock.recvfrom(4096)
            except ConnectionResetError as err:
                print(f"[!] Ignoring UDP reset by peer: {err}", file=sys.stderr)
                continue

            print(f"[<] Received {len(data)} bytes from {addr}", file=sys.stderr)

            try:
                packet = SRTPPacket.from_bytes(data)
            except PacketDecodeError as err:
                print(f"[!] Ignoring invalid packet: {err}", file=sys.stderr)
                continue

            print(
                f"[<] Decoded: type={packet.ptype.name}, "
                f"seq={packet.seqnum}, win={packet.window}, len={packet.length}",
                file=sys.stderr,
            )

            # At this level, the client sends one DATA packet containing the HTTP 0.9 request.
            if packet.ptype != PacketType.DATA:
                print("[!] Ignoring non-DATA packet", file=sys.stderr)
                continue

            # ACK the request packet.
            ack = make_ack_for(packet, window=1)
            sock.sendto(ack.to_bytes(), addr)
            print(
                f"[>] Sent ACK for request, next expected seq={ack.seqnum}",
                file=sys.stderr,
            )

            # Then parse the HTTP 0.9 GET request.
            try:
                request_path = parse_http09_get(packet.payload)
                print(f"[<] HTTP 0.9 request for: {request_path}", file=sys.stderr)
            except ValueError as err:
                print(f"[!] Invalid HTTP 0.9 request: {err}", file=sys.stderr)

                # We answer with an empty DATA packet, which for HTTP 0.9 means "no content / end".
                response_packet = make_data_packet(b"", seqnum=0, window=1)
                sock.sendto(response_packet.to_bytes(), addr)
                print("[>] Sent empty DATA response", file=sys.stderr)
                continue

            # Load the requested file. If the file does not exist, is invalid, or is too large for a single packet, we return an empty payload.
            response_payload = load_single_response(args.root, request_path)

            response_packet = make_data_packet(response_payload, seqnum=0, window=1)
            sock.sendto(response_packet.to_bytes(), addr)

            print(
                f"[>] Sent DATA response: seq={response_packet.seqnum}, len={response_packet.length}",
                file=sys.stderr,
            )


if __name__ == "__main__":
    main()
