import socket
import struct
import time
import os

def checksum(data):
    s = 0
    for i in range(0, len(data)-1, 2):
        s += (data[i] << 8) + data[i+1]
    if len(data) % 2:
        s += data[-1] << 8
    s = (s >> 16) + (s & 0xffff)
    s += (s >> 16)
    return ~s & 0xffff

def create_packet(ident, seq):
    header = struct.pack('!BBHHH', 8, 0, 0, ident, seq)
    payload = b'pingtest'
    chksum = checksum(header + payload)
    header = struct.pack('!BBHHH', 8, 0, chksum, ident, seq)
    return header + payload

def ping_once(target_ip):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:
            sock.settimeout(1)
            packet = create_packet(os.getpid() & 0xFFFF, 1)
            sock.sendto(packet, (target_ip, 0))
            print(f"Sent ping to {target_ip}...")

            recv_data, addr = sock.recvfrom(1024)
            print(f"Reply received from {addr[0]}")
            return True
    except socket.timeout:
        print(f"Timeout waiting for reply from {target_ip}")
        return False
    except PermissionError:
        print("❗ Permission denied! Run as root (use sudo)")
        return False

if __name__ == "__main__":
    ping_once("8.8.8.8")  # Google DNS でテスト
