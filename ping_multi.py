import socket
import struct
import os
import time
import asyncio
from tabulate import tabulate

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

async def ping_once(target_ip, seq, success_count, failure_count):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:
            sock.settimeout(1)
            packet = create_packet(os.getpid() & 0xFFFF, seq)
            sock.sendto(packet, (target_ip, 0))
            
            # 受信データのTTLを取得
            recv_data, addr = sock.recvfrom(1024)
            ttl = recv_data[8]  # TTLは受信データの8バイト目にあります

            return ttl, True
    except socket.timeout:
        return None, False
    except PermissionError:
        print("❗ Permission denied! Run as root (use sudo)")
        return None, False

async def ping_multiple_hosts(host_list):
    results = []
    total_success = 0
    total_failure = 0

    for host in host_list:
        success_count = 0
        failure_count = 0
        ttl_values = []  # TTLの値を保持

        for i in range(4):  # 4回pingを送信
            ttl, result = await ping_once(host, i, success_count, failure_count)
            if result:
                success_count += 1
                ttl_values.append(ttl)  # TTLを記録
            else:
                failure_count += 1

        # TTLの平均値を計算
        avg_ttl = sum(ttl_values) / len(ttl_values) if ttl_values else None
        loss_percentage = (failure_count / 4) * 100

        results.append([host, success_count, failure_count, f"{loss_percentage:.2f}%", avg_ttl])

        total_success += success_count
        total_failure += failure_count

    return results, total_success, total_failure

def print_results(results, total_success, total_failure):
    headers = ["Host", "Success", "Failure", "Loss", "Average TTL"]
    table = tabulate(results, headers=headers, tablefmt="pretty")

    print(table)
    
    # 総計のパケットロス
    total_tests = total_success + total_failure
    total_loss_percentage = (total_failure / total_tests) * 100
    print(f"\nTotal Loss: {total_loss_percentage:.2f}%")
    
async def main():
    hosts = ["8.8.8.8", "1.1.1.1", "192.168.1.1"]
    results, total_success, total_failure = await ping_multiple_hosts(hosts)
    print_results(results, total_success, total_failure)

if __name__ == "__main__":
    asyncio.run(main())
