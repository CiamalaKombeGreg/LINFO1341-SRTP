#!/usr/bin/env python3

# -- imports --
import argparse
import socket
import sys
import time
from pathlib import Path
import select

from srtp_packet import SRTPPacket, PacketType, PacketDecodeError
from srtp_http import (
    DEFAULT_SAVE_PATH,
    parse_http09_url,
    build_http09_get,
    make_data_packet,
    make_ack_for,
    make_ack,       
    seq_in_window,  
    seq_add,  
    SEQ_MODULO,
    make_sack,
)


RECV_BUFFER_SIZE = 32  
TIMEOUT = 5.0 


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

def send_request(sock, dest, request_path):
    """
    Sends the HTTP 0.9 request and waits for the server ACK
    Retransmits if there is no response. Returns True if ACKed
    """
    request_payload = build_http09_get(request_path)
    request_packet = make_data_packet(request_payload, seqnum=0, window=RECV_BUFFER_SIZE)
    raw_request = request_packet.to_bytes()
 
    for attempt in range(10):
        sock.sendto(raw_request, dest)
        print(f"[>] Sent GET {request_path} (attempt {attempt + 1})", file=sys.stderr)
 
        readable, _, _ = select.select([sock], [], [], TIMEOUT)
        if not readable:
            print("[!] Timeout, retransmitting...", file=sys.stderr)
            continue
 
        try:
            data, addr = sock.recvfrom(4096)
            pkt = SRTPPacket.from_bytes(data)
        except (PacketDecodeError, ConnectionResetError):
            continue
 
        if pkt.ptype in (PacketType.ACK, PacketType.SACK):
            print(f"[<] Request ACKed", file=sys.stderr)
            return True
 
        
        if pkt.ptype == PacketType.DATA:
            print("[<] Server already sending data", file=sys.stderr)
            return True
 
    print("[!] Request never acknowledged", file=sys.stderr)
    return False

def receive_file(sock, dest):
    """
    Receiving the file with selective repeat
    """
    expected_seq = 0
    buffer = {}               
    assembled = bytearray()   
    last_timestamp = b"\x00\x00\x00\x00"
 
    stall_count = 0
 
    while True:
        readable, _, _ = select.select([sock], [], [], TIMEOUT)
 
        if not readable:
            stall_count += 1
            if stall_count > 30:
                print("[!] Transfer stalled, giving up", file=sys.stderr)
                return bytes(assembled) if assembled else b""
 
            # send again the last ack if the server didn't receive it
            free = RECV_BUFFER_SIZE - len(buffer)
            ack = make_sack(expected_seq, window=free, timestamp=last_timestamp, out_of_order=list(buffer.keys()))
            sock.sendto(ack.to_bytes(), dest)
            continue
 
        stall_count = 0
 
        try:
            data, addr = sock.recvfrom(4096)
            pkt = SRTPPacket.from_bytes(data)
        except (PacketDecodeError, ConnectionResetError):
            continue
 
        if pkt.ptype != PacketType.DATA:
            continue
 
        last_timestamp = pkt.timestamp
        seq = pkt.seqnum
 
        # detect the end
        if pkt.length == 0:
            if seq == expected_seq % SEQ_MODULO:
                print(f"[<] FIN received, transfer complete", file=sys.stderr)
                fin_ack = make_ack(seq_add(seq, 1), window=RECV_BUFFER_SIZE, timestamp=last_timestamp)
                
                for _ in range(3):
                    sock.sendto(fin_ack.to_bytes(), dest)
                return bytes(assembled)
            continue
 
        # check if the packet is in the window
        exp_mod = expected_seq % SEQ_MODULO
        if not seq_in_window(seq, exp_mod, RECV_BUFFER_SIZE):
            
            
            free = RECV_BUFFER_SIZE - len(buffer)
            ack = make_sack(exp_mod, window=free, timestamp=last_timestamp, out_of_order=list(buffer.keys()))
            sock.sendto(ack.to_bytes(), dest)
            continue
 
        
        if seq == exp_mod:
            assembled.extend(pkt.payload)
            expected_seq += 1
 
            
            while (expected_seq % SEQ_MODULO) in buffer:
                assembled.extend(buffer.pop(expected_seq % SEQ_MODULO))
                expected_seq += 1
 
        
        elif seq not in buffer:
            buffer[seq] = pkt.payload
 
        
        free = RECV_BUFFER_SIZE - len(buffer)
        ack = make_sack(expected_seq, window=free, timestamp=last_timestamp, out_of_order=list(buffer.keys()))
        sock.sendto(ack.to_bytes(), dest)
        print(
            f"[<] seq={seq} | expected={exp_mod} | assembled={len(assembled)} | buffered={len(buffer)}",
            file=sys.stderr,
        )


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

    print(f"[+] Destination: {dest}", file=sys.stderr)
    print(f"[+] Request path: {request_path}", file=sys.stderr)
    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sock:
 
        # send the request GET
        if not send_request(sock, dest, request_path):
            sys.exit(1)
 
        # receive the file 
        file_data = receive_file(sock, dest)
 
        Path(args.save).write_bytes(file_data)
        print(f"[+] Saved {len(file_data)} bytes to {args.save}", file=sys.stderr)
 
    



if __name__ == "__main__":
    main()
