#!/usr/bin/env python3

# -- imports --
import argparse
import socket
import sys
import time

from srtp_packet import SRTPPacket, PacketType, PacketDecodeError


# -- Functions --
def parse_args():
    parser = argparse.ArgumentParser(description="Simple SRTP UDP IPv6 server")
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


def make_ack(seqnum: int, window: int = 1) -> SRTPPacket:
    """
    Build one simple ACK packet.
    """
    timestamp = int(time.time()).to_bytes(4, byteorder="big", signed=False)

    return SRTPPacket(
        ptype=PacketType.ACK,
        window=window,
        seqnum=seqnum,
        timestamp=timestamp,
        payload=b"",
    )


def main():
    args = parse_args()

    try:
        bind_addr = resolve_bind_address(
            args.host, args.port
        )  # It is the sockaddr tuple that we will use to send the packet to the server.
    except OSError as exc:
        print(f"[!] IPv6 bind resolution failed: {exc}", file=sys.stderr)
        sys.exit(1)

    print("[+] Starting simple SRTP UDP IPv6 server", file=sys.stderr)
    print(f"[+] Bind addr : {bind_addr}", file=sys.stderr)

    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sock:
        sock.bind(
            bind_addr
        )  # We bind the socket to the resolved bind address so that we can receive packets sent to that address and port.

        while True:
            data, addr = sock.recvfrom(4096)
            print(f"[<] Received {len(data)} bytes from {addr}", file=sys.stderr)

            try:
                packet = SRTPPacket.from_bytes(data)
            except PacketDecodeError as exc:
                print(f"[!] Ignoring invalid packet: {exc}", file=sys.stderr)
                continue

            print(
                f"[<] Decoded: type={packet.ptype.name}, "
                f"seq={packet.seqnum}, win={packet.window}, len={packet.length}",
                file=sys.stderr,
            )

            if packet.ptype == PacketType.DATA:
                try:
                    text = packet.payload.decode("utf-8")
                    print(f"[<] Payload : {text}", file=sys.stderr)
                except UnicodeDecodeError:
                    print("[<] Payload : <Received non-UTF-8 bytes>", file=sys.stderr)

            ack = make_ack(seqnum=packet.seqnum, window=1)
            sock.sendto(ack.to_bytes(), addr)
            print(f"[>] Sent ACK for seq={packet.seqnum} to {addr}", file=sys.stderr)


if __name__ == "__main__":
    main()
