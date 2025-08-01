import asyncio
import socket
import struct
import time
import curses
import os
import select
from collections import deque, OrderedDict
from datetime import datetime
import ipaddress
import yaml  # YAML読み込み用

# --- ICMPユーティリティ関数 ---
def checksum(data):
    s = 0
    for i in range(0, len(data) - 1, 2):
        s += (data[i] << 8) + data[i + 1]
    if len(data) % 2:
        s += data[-1] << 8
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff

def create_icmp_packet(ident, seq, ipv6=False):
    if ipv6:
        header = struct.pack('!BbHHh', 128, 0, 0, ident, seq)
    else:
        header = struct.pack('!BBHHH', 8, 0, 0, ident, seq)
    payload = b'DEADMAN_MONITOR'
    chksum = checksum(header + payload)
    if ipv6:
        header = struct.pack('!BbHHh', 128, 0, chksum, ident, seq)
    else:
        header = struct.pack('!BBHHH', 8, 0, chksum, ident, seq)
    return header + payload

def ping_once_sync(host, ident, seq):
    try:
        ipv6 = ':' in host
        proto = socket.IPPROTO_ICMPV6 if ipv6 else socket.IPPROTO_ICMP
        family = socket.AF_INET6 if ipv6 else socket.AF_INET
        with socket.socket(family, socket.SOCK_RAW, proto) as sock:
            packet = create_icmp_packet(ident, seq, ipv6=ipv6)
            start = time.time()
            sock.sendto(packet, (host, 0, 0, 0) if ipv6 else (host, 0))
            ready = select.select([sock], [], [], 0.2)[0]
            if ready:
                data, addr = sock.recvfrom(1024)
                if addr[0] == socket.gethostbyname(host):
                    elapsed = (time.time() - start) * 1000
                    return True, round(elapsed, 2)
            return False, None
    except PermissionError:
        print("❗ root権限が必要です（sudoで実行）")
        exit(1)
    except Exception:
        return False, None

async def check_tcp_port(host, port):
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=0.5)
        writer.close()
        await writer.wait_closed()
        return True
    except:
        return False

def get_bar_char(rtt):
    if rtt is None:
        return "X"
    if rtt < 1: return "▁"
    if rtt < 3: return "▂"
    if rtt < 5: return "▃"
    if rtt < 10: return "▄"
    if rtt < 20: return "▅"
    if rtt < 40: return "▆"
    if rtt < 80: return "▇"
    return "█"

def draw_screen(stdscr, results, shared, start_time):
    curses.curs_set(0)
    stdscr.nodelay(True)
    stdscr.keypad(True)
    if curses.has_colors():
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_WHITE, -1)
        curses.init_pair(4, curses.COLOR_GREEN, -1)
        curses.init_pair(5, curses.COLOR_RED, -1)

    sort_key = 'host'

    while True:
        stdscr.erase()
        height, width = stdscr.getmaxyx()
        elapsed = int(time.time() - start_time)
        h, m, s = elapsed // 3600, (elapsed % 3600) // 60, elapsed % 60
        elapsed_str = f"{h:02}:{m:02}:{s:02}"
        stdscr.addstr(0, 0, f"Elapsed {elapsed_str}   Press 'r'=refresh, 's'=sort, 'q'=quit", curses.A_BOLD)
        stdscr.addstr(1, 0, f"Sorted by: {sort_key.upper()}", curses.A_DIM)

        header = "{:<17} {:<25} {:^7} {:^9} {:^9} {:^5} {:^5} {:^7} {}".format(
            "Name", "Host", "Loss", "Last RTT", "Avg RTT", "SSH", "HTTP", "SNT", "History")
        stdscr.addstr(2, 0, header[:width], curses.A_BOLD)

        items = list(results.items())
        if sort_key == 'rtt':
            items.sort(key=lambda x: (x[1]['rtts'][-1] if x[1]['rtts'] else float('inf')))
        elif sort_key == 'ip':
            items.sort(key=lambda x: (0, ipaddress.ip_address(x[0])))

        for i, (host, data) in enumerate(items, 3):
            if i >= height:
                break
            sent = data["sent"]
            recv = data["received"]
            loss = 100 * (1 - recv / sent) if sent else 0
            rtts = data["rtts"]
            avg_rtt = f"{sum(rtts)/len(rtts):.1f}ms" if rtts else "-"
            last_rtt = f"{rtts[-1]:.1f}ms" if rtts else "-"
            ssh = "OK" if data["ssh"] else "NG"
            http = "OK" if data["http"] else "NG"
            hostname = data.get("hostname", "unknown")

            is_current = (host == shared["current"])
            marker = ">" if is_current else " "

            line_prefix = f"{marker}{hostname:<16} {host:<24} {loss:^7.0f} {last_rtt:^9} {avg_rtt:^9} "
            ssh_http = f"{ssh:^5} {http:^5} {sent:^7} "

            history_list = list(data["history"])
            max_history_len = max(0, width - len(line_prefix + ssh_http))
            clipped_history = history_list[-max_history_len:] if max_history_len > 0 else []

            try:
                stdscr.addstr(i, 0, line_prefix + ssh_http, curses.color_pair(1))
                for j, (symbol, success) in enumerate(clipped_history):
                    bar_color = curses.color_pair(4 if success else 5)
                    stdscr.addstr(i, len(line_prefix + ssh_http) + j, symbol, bar_color)
            except curses.error:
                pass

        stdscr.refresh()
        ch = stdscr.getch()
        if ch == ord('r'):
            return 'refresh'
        elif ch == ord('s'):
            sort_key = 'ip' if sort_key == 'host' else ('rtt' if sort_key == 'ip' else 'host')
        elif ch == ord('q'):
            return 'quit'
        else:
            time.sleep(0.1)

# --- ホスト名逆引き ---
def resolve_hostname(ip_or_host):
    try:
        return socket.gethostbyaddr(ip_or_host)[0]
    except:
        return "unknown"

async def monitor_loop(hosts, results, shared):
    ident = os.getpid() & 0xFFFF
    seq = 0
    loop = asyncio.get_event_loop()
    while True:
        for entry in hosts:
            host = entry["host"]
            shared["current"] = host
            data = results[host]

            ping_task = loop.run_in_executor(None, ping_once_sync, host, ident, seq)
            ssh_task = asyncio.create_task(check_tcp_port(host, 22))
            http_task = asyncio.create_task(check_tcp_port(host, 80))

            ok, rtt = await ping_task
            ssh_ok = await ssh_task
            http_ok = await http_task

            data["sent"] += 1
            data["ssh"] = ssh_ok
            data["http"] = http_ok

            if ok:
                data["received"] += 1
                data["rtts"].append(rtt)
                data["history"].append((get_bar_char(rtt), True))
            else:
                data["history"].append(("X", False))

            seq += 1
            wait_time = max(0.01, 0.5 - (rtt / 1000 if rtt else 0))
            await asyncio.sleep(wait_time)

def load_hosts_from_file(filename="hosts.yaml"):
    with open(filename, 'r') as f:
        return yaml.safe_load(f)

async def main():
    hosts = load_hosts_from_file("hosts.yaml")
    results = OrderedDict()
    for entry in hosts:
        host = entry["host"]
        name = entry.get("name") or resolve_hostname(host)
        results[host] = {
            "sent": 0,
            "received": 0,
            "rtts": [],
            "history": deque(maxlen=200),
            "ssh": False,
            "http": False,
            "hostname": name
        }

    shared = {"current": hosts[0]["host"]}
    start_time = time.time()
    asyncio.create_task(monitor_loop(hosts, results, shared))

    while True:
        result = await asyncio.get_event_loop().run_in_executor(
            None, curses.wrapper, lambda stdscr: draw_screen(stdscr, results, shared, start_time)
        )
        if result == 'quit':
            break

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n監視を終了します。")

