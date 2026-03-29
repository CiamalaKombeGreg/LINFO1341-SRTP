#!/usr/bin/env python3

# -- imports --
import argparse
import socket
import sys
import time
import select

from srtp_packet import SRTPPacket, PacketType, PacketDecodeError
from srtp_http import (
    parse_http09_get,
    load_single_response,
    make_data_packet,
    make_ack_for,
    split_file_into_chunks,
    SEQ_MODULO,
    decode_sack_payload,

)

RTO = 2.0  
MAX_RETRIES = 50 


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

def wait_for_request(sock):
    """
    Expects a DATA entry containing a valid HTTP 0.9 GET request
    Returns (request_path, client_address)
    """
    while True:
        data, addr = sock.recvfrom(4096)
        print(f"[<] Received {len(data)} bytes from {addr}", file=sys.stderr)
 
        try:
            packet = SRTPPacket.from_bytes(data)
        except PacketDecodeError as err:
            print(f"[!] Ignoring invalid packet: {err}", file=sys.stderr)
            continue
 
        if packet.ptype != PacketType.DATA:
            print("[!] Ignoring non-DATA packet", file=sys.stderr)
            continue
 
        try:
            request_path = parse_http09_get(packet.payload)
        except ValueError as err:
            print(f"[!] Invalid HTTP 0.9 request: {err}", file=sys.stderr)
            fin = make_data_packet(b"", seqnum=0, window=0)
            sock.sendto(fin.to_bytes(), addr)
            continue
 
        print(f"[<] HTTP 0.9 GET {request_path} from {addr}", file=sys.stderr)
 
        
        ack = make_ack_for(packet, window=0)
        sock.sendto(ack.to_bytes(), addr)
        print(f"[>] Sent ACK for GET request", file=sys.stderr)
 
        return request_path, addr
    
def send_file(sock, client_addr, chunks):
    total_chunks = len(chunks)
 
    base = 0         
    next_send = 0    
    window = 1       
 
    
    send_times = {}
    sacked = set()
    no_progress_count = 0
 
    print(f"[+] Sending {total_chunks} chunks", file=sys.stderr)
 
    while base < total_chunks:
        # send new packet in the windows
        while next_send < total_chunks and next_send < base + window:
            seqnum = next_send % SEQ_MODULO
            pkt = make_data_packet(chunks[next_send], seqnum=seqnum, window=0)
            sock.sendto(pkt.to_bytes(), client_addr)
            send_times[next_send] = time.time()
            print(f"[>] Sent DATA seq={seqnum} ({len(chunks[next_send])} bytes)", file=sys.stderr)
            next_send += 1
 
        # wait ack
        readable, _, _ = select.select([sock], [], [], min(RTO, 0.5))
 
        if readable:
            try:
                data, addr = sock.recvfrom(4096)
            except ConnectionResetError:
                continue
 
            try:
                pkt = SRTPPacket.from_bytes(data)
            except PacketDecodeError:
                continue
 
            
            if pkt.ptype == PacketType.DATA:
                try:
                    parse_http09_get(pkt.payload)
                    ack = make_ack_for(pkt, window=0)
                    sock.sendto(ack.to_bytes(), addr)
                except ValueError:
                    pass
                continue
 
            if pkt.ptype not in (PacketType.ACK, PacketType.SACK):
                continue
 
            
            ack_seqnum = pkt.seqnum
            new_window = pkt.window
 
            
            base_seq = base % SEQ_MODULO
            advance = (ack_seqnum - base_seq) % SEQ_MODULO
 
            
            if advance > (next_send - base):
                continue
 
            if advance > 0:
                old_base = base
                base = base + advance
                for i in range(old_base, base):
                    send_times.pop(i, None)
                    sacked.discard(i)
                no_progress_count = 0
                print(f"[<] ACK seq={ack_seqnum}: base {old_base} → {base}, window={new_window}", file=sys.stderr)

            if pkt.ptype == PacketType.SACK and pkt.length > 0:
                sack_seqnums = decode_sack_payload(pkt.payload)
                for sack_seq in sack_seqnums:
                    
                    distance = (sack_seq - (base % SEQ_MODULO)) % SEQ_MODULO
                    logical_idx = base + distance
                    if base <= logical_idx < next_send:
                        sacked.add(logical_idx)
                        send_times.pop(logical_idx, None)  
                print(f"    SACK: {len(sack_seqnums)} paquets hors-séquence déjà reçus", file=sys.stderr)
 
            if new_window > 0:
                window = new_window
 
        else:
            no_progress_count += 1
            if no_progress_count > MAX_RETRIES:
                print("[!] Too many retries, giving up", file=sys.stderr)
                return
 
        # send again the packets expired
        now = time.time()
        for idx in range(base, next_send):
            if idx in sacked:
                continue  
            if idx in send_times and (now - send_times[idx]) > RTO:
                seqnum = idx % SEQ_MODULO
                pkt = make_data_packet(chunks[idx], seqnum=seqnum, window=0)
                sock.sendto(pkt.to_bytes(), client_addr)
                send_times[idx] = now
                print(f"[>] RETRANSMIT seq={seqnum}", file=sys.stderr)
 
    
    send_fin(sock, client_addr, base)


def send_fin(sock, client_addr, base):
    """sends a DATA(length=0) to signal the end of the transfer
    """
    fin_seq = base % SEQ_MODULO
    for attempt in range(MAX_RETRIES):
        fin_pkt = make_data_packet(b"", seqnum=fin_seq, window=0)
        sock.sendto(fin_pkt.to_bytes(), client_addr)
        print(f"[>] Sent FIN (seq={fin_seq})", file=sys.stderr)
 
        readable, _, _ = select.select([sock], [], [], RTO)
        if readable:
            try:
                data, _ = sock.recvfrom(4096)
                pkt = SRTPPacket.from_bytes(data)
                if pkt.ptype in (PacketType.ACK, PacketType.SACK):
                    print(f"[<] FIN ACKed", file=sys.stderr)
                    return
            except (PacketDecodeError, ConnectionResetError):
                pass
 
    print("[!] FIN never ACKed", file=sys.stderr)


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

        # I put the fonctions outside the main to simplify
        while True:
            
            request_path, client_addr = wait_for_request(sock)
 
            
            file_data = load_single_response(args.root, request_path)
 
            if not file_data:
                print(f"[!] File not found: {request_path}", file=sys.stderr)
                fin = make_data_packet(b"", seqnum=0, window=0)
                sock.sendto(fin.to_bytes(), client_addr)
                continue
 
            
            chunks = split_file_into_chunks(file_data)
            print(f"[+] File: {len(file_data)} bytes → {len(chunks)} chunks", file=sys.stderr)
 
            
            send_file(sock, client_addr, chunks)
            print(f"[+] Transfer complete for {request_path}", file=sys.stderr)
            


if __name__ == "__main__":
    main()
