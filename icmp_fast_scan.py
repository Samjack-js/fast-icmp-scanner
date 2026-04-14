import argparse
import ipaddress
import random
import socket
import struct
import time
from threading import Event, Thread

ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0
PAYLOAD_SIZE = 192


def checksum(data):
    if len(data) % 2:
        data += b"\x00"

    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]

    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)

    return ~total & 0xFFFF


def create_packet(packet_id, sequence):
    payload = struct.pack("!d", time.time()) + (b"X" * (PAYLOAD_SIZE - 8))
    header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, 0, packet_id, sequence)
    packet_checksum = checksum(header + payload)
    header = struct.pack(
        "!BBHHH",
        ICMP_ECHO_REQUEST,
        0,
        packet_checksum,
        packet_id,
        sequence,
    )
    return header + payload


def create_icmp_socket():
    try:
        return socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError as exc:
        raise RuntimeError("Run this script as admin/root to use raw ICMP sockets.") from exc


def ping(sock, ip, packet_id, sequence):
    packet = create_packet(packet_id, sequence)
    sock.sendto(packet, (ip, 0))


def parse_icmp_reply(packet):
    if len(packet) < 28:
        return None

    ip_header_length = (packet[0] & 0x0F) * 4
    if len(packet) < ip_header_length + 8:
        return None

    src_ip = socket.inet_ntoa(packet[12:16])
    icmp_header = packet[ip_header_length : ip_header_length + 8]
    icmp_type, code, _, packet_id, sequence = struct.unpack("!BBHHH", icmp_header)

    return src_ip, icmp_type, code, packet_id, sequence


def listen(sock, responses, network, stop_event, expected_packet_id):
    sock.settimeout(0.5)

    while not stop_event.is_set():
        try:
            packet, _ = sock.recvfrom(1024)
        except socket.timeout:
            continue
        except OSError:
            break

        parsed = parse_icmp_reply(packet)
        if parsed is None:
            continue

        src_ip, icmp_type, code, packet_id, _ = parsed
        if icmp_type != ICMP_ECHO_REPLY or code != 0 or packet_id != expected_packet_id:
            continue

        if ipaddress.ip_address(src_ip) in network and src_ip not in responses:
            print(f"[+] Host alive: {src_ip}")
            responses.add(src_ip)


def scan(network, delay, timeout):
    if network.version != 4:
        raise ValueError("This scanner currently supports IPv4 networks only.")

    responses = set()
    stop_event = Event()
    packet_id = random.randint(0, 0xFFFF)

    send_sock = create_icmp_socket()
    recv_sock = create_icmp_socket()

    try:
        recv_sock.bind(("", 0))

        listener = Thread(
            target=listen,
            args=(recv_sock, responses, network, stop_event, packet_id),
            daemon=True,
        )
        listener.start()

        print(f"[+] Scanning {network}...")

        for sequence, ip in enumerate(network.hosts(), start=1):
            ping(send_sock, str(ip), packet_id, sequence)
            time.sleep(delay)

        time.sleep(timeout)
        stop_event.set()
        listener.join()
    finally:
        send_sock.close()
        recv_sock.close()

    found_hosts = sorted(responses, key=ipaddress.ip_address)
    print("\n[+] Scan complete!")
    print(f"[+] Hosts found: {len(found_hosts)}")

    return found_hosts


def main():
    parser = argparse.ArgumentParser(description="Fast ICMP network scanner")
    parser.add_argument("target", help="Target network (example: 192.168.1.0/24)")
    parser.add_argument(
        "--delay",
        type=float,
        default=0.01,
        help="Delay between ICMP packets in seconds",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=2.0,
        help="How long to wait for replies after sending packets",
    )

    args = parser.parse_args()
    network = ipaddress.ip_network(args.target, strict=False)
    scan(network, args.delay, args.timeout)


if __name__ == "__main__":
    main()
