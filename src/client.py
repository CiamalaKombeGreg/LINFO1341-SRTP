#!/usr/bin/env python3

# -- imports --
import argparse
import socket
import sys
import time
from pathlib import Path

from srtp_packet import SRTPPacket, PacketType, PacketDecodeError
from srtp_http import (
    DEFAULT_SAVE_PATH,
    parse_http09_url,
    build_http09_get,
    make_data_packet,
    make_ack_for,
)


# -- Functions --
def parse_args():
    parser = argparse.ArgumentParser(description="SRTP UDP IPv6 client")
    parser.add_argument(
        "url",
        help="HTTP 0.9 URL to request, for example http://localhost:8080/llm/small",
    )  # We expect the user to provide a URL in the format of HTTP 0.9, which we will parse to extract the host and port for sending the SRTP packet.
    parser.add_argument(
        "--save",
        default=DEFAULT_SAVE_PATH,
        help="Where to save the received file (default: llm.model)",
    )  # We allow the user to specify where to save the received file, with a default of "llm.model".
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


def save_response(path: str, payload: bytes):
    """
    Save the received payload to disk.
    """
    Path(path).write_bytes(payload)


def main():
    args = parse_args()

    try:
        host, port, request_path = parse_http09_url(args.url)
        dest = resolve_target(
            host, port
        )  # It is the sockaddr tuple that we will use to send the packet to the server.
    except (ValueError, OSError) as err:
        print(f"[!] Invalid URL/destination: {err}", file=sys.stderr)
        sys.exit(1)

    # In HTTP 0.9, the client sends: GET /path in ASCII, without headers.
    request_payload = build_http09_get(request_path)

    # We send one SRTP DATA packet containing the whole request.
    request_packet = make_data_packet(request_payload, seqnum=0, window=1)
    raw_request = request_packet.to_bytes()

    print(f"[+] Destination: {dest}", file=sys.stderr)
    print(f"[+] Request path: {request_path}", file=sys.stderr)
    print(
        f"[>] Sending request: type={request_packet.ptype.name}, seq={request_packet.seqnum}, len={request_packet.length}",
        file=sys.stderr,
    )

    response_saved = False  # We use this flag to track whether we have already saved the response to disk, so that we don't save it multiple times if we receive multiple packets.

    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sock:
        sock.settimeout(
            args.timeout
        )  # We set the default or selected timeout for receiving a response from the server.

        sock.sendto(
            raw_request, dest
        )  # Sent the raw bytes of the request packet to the server using the resolved sockaddr.
        while not response_saved:
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
            except PacketDecodeError as err:
                print(f"[!] Invalid SRTP response: {err}", file=sys.stderr)
                sys.exit(1)

            print(
                f"[<] Decoded response: type={reply.ptype.name}, seq={reply.seqnum}, win={reply.window}, len={reply.length}",
                file=sys.stderr,
            )

            if reply.ptype == PacketType.ACK:
                # The ACK confirms that the server received our request packet.
                print("[<] Request acknowledged by server", file=sys.stderr)
                continue  # We continue waiting for the DATA packet that contains the file content.

            elif reply.ptype == PacketType.DATA:
                # The DATA packet contains the file content.
                print("[<] Received DATA packet", file=sys.stderr)
            else:
                print("[!] Ignoring non-DATA, non-ACK packet", file=sys.stderr)
                continue  # We ignore any other type of packet, as we only expect ACKs and DATA packets from the server in response to our request.

            # Save the file content.
            save_response(args.save, reply.payload)
            response_saved = True

            print(
                f"[+] Saved {len(reply.payload)} bytes to {args.save}", file=sys.stderr
            )

            # ACK the DATA packet we just received.
            ack = make_ack_for(reply, window=1)
            sock.sendto(ack.to_bytes(), dest)
            print(
                f"[>] Sent ACK for received DATA, next expected seq={ack.seqnum}",
                file=sys.stderr,
            )


if __name__ == "__main__":
    main()
