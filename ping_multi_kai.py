import socket
import struct
import os
import time
import asyncio
import select
from tabulate import tabulate # type: ignore
from collections import deque, OrderedDict

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

def get_hostname(ip):
    try:
        host = socket.gethostbyaddr(ip)
        return host[0]  # 逆引きDNSで得られたホスト名を返す
    except socket.herror:
        return "Unknown Host"  # 逆引きできなかった場合

async def ping_once(target_ip, seq, success_count, failure_count):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:
            sock.setblocking(0)
            sock.settimeout(1)
            packet = create_packet(os.getpid() & 0xFFFF, seq)
            start_time = time.time()
            sock.sendto(packet, (target_ip, 0))
            
            # selectを使ってタイムアウト判定
            ready = select.select([sock], [], [], 1)
            if ready[0] == []:
                return None, False, None  # タイムアウト

            recv_data, addr = sock.recvfrom(1024)
            rtt = (time.time() - start_time) * 1000
            ttl = recv_data[8]

            return ttl, True, rtt
    except (socket.timeout, BlockingIOError):
        return None, False, None
    except PermissionError:
        print("❗ Permission denied! Run as root (use sudo)")
        return None, False, None
    except Exception as e:
        print(f"❗ Unexpected error in ping_once: {e}")
        return None, False, None
async def check_tcp_port(ip, port, timeout=1):
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
        writer.close()
        await writer.wait_closed()
        return True
    except:
        return False


async def ping_loop(host, result_dict):
    seq = 0

    while True:
        ttl, ok, rtt = await ping_once(host, seq, 0, 0)
        ssh_ok = await check_tcp_port(host, 22)
        http_ok = await check_tcp_port(host, 80)

        result_dict[host]["hostname"] = get_hostname(host)
        result_dict[host]["ssh"] = ssh_ok
        result_dict[host]["http"] = http_ok
        result_dict[host]["history"].append("○" if ok else "×")
        result_dict[host]["sent"] += 1
        if ok:
            result_dict[host]["received"] += 1
            if rtt is not None:
                result_dict[host]["rtts"].append(rtt)

        seq += 1
        elapsed = rtt/1000
        sleep_time = max(0, 5 - elapsed)  # 常に5秒間隔を保つ
        await asyncio.sleep(sleep_time)


async def monitor_loop(hosts):
    result_dict = OrderedDict()
    for host in hosts:
        result_dict[host] = {
            "hostname": get_hostname(host),
            "history": deque(maxlen=20),
            "ssh": False,
            "http": False,
            "rtts": [],
            "sent": 0,
            "received": 0
        }

    asyncio.create_task(display_loop(result_dict))

    seq = 0
    while True:
        start_time = time.time()
        for host in hosts:
            ttl, ok, rtt = await ping_once(host, seq, 0, 0)
            ssh_ok = await check_tcp_port(host, 22)
            http_ok = await check_tcp_port(host, 80)

            result_dict[host]["hostname"] = get_hostname(host)
            result_dict[host]["ssh"] = ssh_ok
            result_dict[host]["http"] = http_ok
            result_dict[host]["history"].append("○" if ok else "×")
            result_dict[host]["sent"] += 1
            if ok:
                result_dict[host]["received"] += 1
                if rtt is not None:
                    result_dict[host]["rtts"].append(rtt)

        seq += 1
        elapsed = time.time() - start_time
        sleep_time = max(0, 5 - elapsed)
        await asyncio.sleep(sleep_time)

async def display_loop(result_dict):
    while True:
        os.system("clear")
        table = []
        for ip, data in result_dict.items():
            sent = data.get("sent", 0)
            received = data.get("received", 0)
            loss = 100 * (1 - received / sent) if sent else 0
            rtts = data.get("rtts", [])
            last_rtt = f"{rtts[-1]:.1f}ms" if rtts else "-"
            avg_rtt = f"{sum(rtts)/len(rtts):.1f}ms" if rtts else "-"

            table.append([
                data.get("hostname", "Unknown"),
                ip,
                f"{loss:.0f}%",
                last_rtt,
                avg_rtt,
                "OK" if data.get("ssh") else "NG",
                "OK" if data.get("http") else "NG",
                "".join(data.get("history", []))
            ])
        headers = ["Hostname", "IP", "Loss", "RTT", "AVG", "SSH", "HTTP", "履歴"]
        print(tabulate(table, headers=headers, tablefmt="pretty"))
        await asyncio.sleep(1)


async def main():
    hosts = ["8.8.8.8", "1.1.1.1", "127.0.0.1","192.0.0.2"]
    await monitor_loop(hosts)

if __name__ == "__main__":
    asyncio.run(main())
