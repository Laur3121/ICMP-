import asyncio
import socket
import struct
import time
import curses
import os
import select
import signal
from collections import deque, OrderedDict

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

def create_icmp_packet(ident, seq):
    header = struct.pack('!BBHHH', 8, 0, 0, ident, seq)
    payload = b'DEADMAN_MONITOR'
    chksum = checksum(header + payload)
    header = struct.pack('!BBHHH', 8, 0, chksum, ident, seq)
    return header + payload

# --- ICMP Ping 実行 ---
def ping_once_sync(host, ident, seq):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:
            packet = create_icmp_packet(ident, seq)
            start = time.time()
            sock.sendto(packet, (host, 0))
            ready = select.select([sock], [], [], 0.3)[0]
            if ready:
                data, addr = sock.recvfrom(1024)
                if addr[0] == host:
                    elapsed = (time.time() - start) * 1000
                    return True, round(elapsed, 2)
            return False, None
    except PermissionError:
        print("\u2757 root権限が必要です（sudoで実行）")
        exit(1)
    except Exception as e:
        print(f"\u2757 ping失敗: {e}")
        return False, None

# --- TCP接続確認 ---
async def check_tcp_port(host, port):
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=1)
        writer.close()
        await writer.wait_closed()
        return True
    except:
        return False

# --- RTTに応じたバー文字の選択 ---
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

# --- Curses 表示 ---
def draw_screen(stdscr, results, shared):
    curses.curs_set(0)
    stdscr.nodelay(True)
    stdscr.keypad(True)
    if curses.has_colors():
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_WHITE, -1)
        curses.init_pair(2, curses.COLOR_RED, -1)
        curses.init_pair(3, curses.COLOR_GREEN, -1)
        curses.init_pair(4, curses.COLOR_GREEN, -1)
        curses.init_pair(5, curses.COLOR_RED, -1)
    else:
        for i in range(1, 6):
            curses.init_pair(i, curses.COLOR_WHITE, -1)

    while True:
        stdscr.erase()
        height, width = stdscr.getmaxyx()
        header = "{:<16} {:<7} {:<9} {:<9} {:<6} {:<6} {}".format(
            "Host", "Loss", "Last RTT", "Avg RTT", "SSH", "HTTP", "History"
        )
        stdscr.addstr(0, 0, header, curses.A_BOLD)

        for i, (host, data) in enumerate(results.items(), 1):
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

            is_current = (host == shared["current"])
            marker = ">" if is_current else " "
            line_prefix = f"{marker}{host:<15} {loss:<7.0f} {last_rtt:<9} {avg_rtt:<9} "
            ssh_color = curses.color_pair(3 if ssh == "OK" else 2)
            http_color = curses.color_pair(3 if http == "OK" else 2)
            ssh_http = f"{ssh:<6} {http:<6} "

            history_list = list(data["history"])
            max_history_len = max(0, width - len(line_prefix + ssh_http))
            clipped_history = history_list[-max_history_len:] if max_history_len > 0 else []

            stdscr.addstr(i, 0, line_prefix, curses.color_pair(1))
            stdscr.addstr(i, len(line_prefix), ssh[:6], ssh_color)
            stdscr.addstr(i, len(line_prefix) + 6, http[:6], http_color)

            for j, (symbol, success) in enumerate(clipped_history):
                bar_color = curses.color_pair(4 if success else 5)
                stdscr.addstr(i, len(line_prefix) + len(ssh_http) + j, symbol, bar_color)

        stdscr.refresh()
        time.sleep(0.1)

# --- 並列監視ループ ---
async def monitor_loop(hosts, results, shared):
    ident = os.getpid() & 0xFFFF
    seq = 0
    loop = asyncio.get_event_loop()
    while True:
        for host in hosts:
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

            await asyncio.sleep(0.01)
            seq += 1

# --- メイン処理 ---
async def main():
    hosts = [
        "8.8.8.8", "1.1.1.1", "192.0.2.1", "127.0.0.1", "93.184.216.34",
        "192.0.2.2", "192.0.2.3", "192.0.2.4", "192.0.2.5", "192.0.2.6",
        "192.0.2.7", "192.0.2.8", "192.0.2.9", "192.0.2.10", "192.0.2.11",
        "192.0.2.12", "192.0.2.13", "192.0.2.14", "192.0.2.15", "192.0.2.16",
        "192.168.0.1"
    ]
    results = OrderedDict()
    for host in hosts:
        results[host] = {
            "sent": 0,
            "received": 0,
            "rtts": [],
            "history": deque(maxlen=200),
            "ssh": False,
            "http": False
        }

    shared = {"current": hosts[0]}
    asyncio.create_task(monitor_loop(hosts, results, shared))

    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, curses.wrapper, draw_screen, results, shared)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n監視を終了します。")
