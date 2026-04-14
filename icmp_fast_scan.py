import socket
import struct
import time
import random
import ipaddress
import argparse
from threading import Thread

SIGNAL = True


def checksum(data):
    s = 0
    for i in range(0, len(data) - 1, 2):
        s += data[i] + (data[i + 1] << 8)
    if len(data) % 2:
        s += data[-1]
    s = (s >> 16) + (s & 0xffff)
    s += (s >> 16)
    return ~s & 0xffff


def create_packet(packet_id):
    header = struct.pack('bbHHh', 8, 0, 0, packet_id, 1)
    data = b'X' * 192
    chk = checksum(header + data)
    header = struct.pack('bbHHh', 8, 0, socket.htons(chk), packet_id, 1)
    return header + data


def ping(ip):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        packet_id = random.randint(0, 65535)
        packet = create_packet(packet_id)
        sock.sendto(packet, (ip, 1))
        sock.close()
    except PermissionError:
        print("[!] Run as root/admin!")
    except Exception:
        pass


def listen(responses, network):
    global SIGNAL
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    sock.bind(('', 1))

    while SIGNAL:
        packet = sock.recv(1024)[20:28]
        ip = struct.unpack('BBBB', packet[4:8])
        ip_str = ".".join(map(str, ip))

        if ip_str not in responses and ipaddress.ip_address(ip_str) in network:
            print(f"[+] Host alive: {ip_str}")
            responses.append(ip_str)

    sock.close()


def scan(network, delay):
    responses = []

    listener = Thread(target=listen, args=(responses, network))
    listener.start()

    print(f"[+] Scanning {network}...")

    for ip in network:
        ping(str(ip))
        time.sleep(delay)

    time.sleep(2)

    global SIGNAL
    SIGNAL = False
    ping('127.0.0.1')

    listener.join()

    print("\n[+] Scan complete!")
    print(f"[+] Hosts found: {len(responses)}")

    return responses


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fast ICMP Network Scanner")
    parser.add_argument("target", help="Target network (e.g. 192.168.1.0/24)")
    parser.add_argument("--delay", type=float, default=0.001, help="Delay between packets")

    args = parser.parse_args()

    network = ipaddress.ip_network(args.target, strict=False)

    scan(network, args.delay)
