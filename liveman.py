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
import yaml

# --- チェックサム計算 ---
def checksum(data):
    s = 0
    for i in range(0, len(data) - 1, 2):
        s += (data[i] << 8) + data[i + 1]
    if len(data) % 2:
        s += data[-1] << 8
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff

# --- IPv4 IPヘッダ作成 ---
def create_ipv4_header(src_ip, dst_ip, payload_len):
    version_ihl = (4 << 4) + 5
    tos = 0
    total_length = 20 + payload_len
    identification = os.getpid() & 0xFFFF
    flags_fragment = 0
    ttl = 64
    proto = socket.IPPROTO_ICMP
    checksum_ip = 0
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)

    header = struct.pack('!BBHHHBBH4s4s',
        version_ihl, tos, total_length, identification,
        flags_fragment, ttl, proto, checksum_ip, src, dst)
    checksum_ip = checksum(header)
    return struct.pack('!BBHHHBBH4s4s',
        version_ihl, tos, total_length, identification,
        flags_fragment, ttl, proto, checksum_ip, src, dst)

# --- IPv6 Pseudo Header + Checksum用 ---
def checksum_ipv6(src, dst, payload, next_header):
    pseudo_header = struct.pack('!16s16sI3xB',
        socket.inet_pton(socket.AF_INET6, src),
        socket.inet_pton(socket.AF_INET6, dst),
        len(payload), next_header)
    return checksum(pseudo_header + payload)

# --- ICMPパケット作成 ---
def create_icmp_packet(ident, seq, ipv6=False, src_ip=None, dst_ip=None):
    payload = b'LIVEMAN_MONITOR'
    if ipv6:
        header = struct.pack('!BbHHh', 128, 0, 0, ident, seq)
        chksum = checksum_ipv6(src_ip, dst_ip, header + payload, socket.IPPROTO_ICMPV6)
        header = struct.pack('!BbHHh', 128, 0, chksum, ident, seq)
    else:
        header = struct.pack('!BBHHH', 8, 0, 0, ident, seq)
        chksum = checksum(header + payload)
        header = struct.pack('!BBHHH', 8, 0, chksum, ident, seq)
    return header + payload

# --- 有効なIPv4アドレスの取得 ---
def get_valid_ipv4_src():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except:
        return "127.0.0.1"

# --- 有効なIPv6アドレスの取得 ---
def get_valid_ipv6_src():
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as s:
            s.connect(("2001:4860:4860::8888", 80))
            return s.getsockname()[0]
    except:
        return "::1"

# --- 簡単なICMP ping (fallback) ---
def ping_once_simple(host, timeout=0.5):
    """簡易ping実装（RAWソケットが使えない場合のfallback）"""
    try:
        # まず名前解決を試す
        try:
            if ':' in host:
                socket.getaddrinfo(host, None, socket.AF_INET6)
                family = socket.AF_INET6
            else:
                socket.gethostbyname(host)
                family = socket.AF_INET
        except (socket.gaierror, socket.herror):
            return False, None
            
        # 複数のポートで接続試行
        test_ports = [80, 443, 22, 21, 25, 53]  # よく使われるポート
        
        for port in test_ports:
            try:
                start = time.time()
                with socket.socket(family, socket.SOCK_STREAM) as s:
                    s.settimeout(timeout)
                    result = s.connect_ex((host, port))
                    elapsed = (time.time() - start) * 1000
                    
                    # 接続成功(0)、接続拒否(111)、リセット(104)なら到達可能
                    if result in [0, 111, 104]:
                        return True, round(elapsed, 2)
                        
            except Exception:
                continue
                
        # TCP接続がすべて失敗した場合、UDP probe試行
        try:
            start = time.time()
            with socket.socket(family, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                # DNSクエリ風のパケットを送信
                s.sendto(b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x01', (host, 53))
                try:
                    data = s.recv(512)
                    elapsed = (time.time() - start) * 1000
                    return True, round(elapsed, 2)
                except socket.timeout:
                    # タイムアウトでもパケットが送信できたなら到達可能の可能性
                    elapsed = timeout * 1000
                    return True, round(elapsed, 2)
        except Exception:
            pass
            
        return False, None
        
    except Exception:
        return False, None

# --- IPv4用完全自作RAWパケット送信 ---
def ping_once_ipv4_raw(host, ident, seq):
    try:
        dst_ip = socket.gethostbyname(host)
        src_ip = get_valid_ipv4_src()
        
        # まずICMPソケットを試す（より確実）
        try:
            icmp_packet = create_icmp_packet(ident, seq, ipv6=False)
            with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as s:
                s.settimeout(0.5)
                start = time.time()
                s.sendto(icmp_packet, (dst_ip, 0))
                
                while time.time() - start < 0.5:
                    ready = select.select([s], [], [], 0.1)[0]
                    if ready:
                        data, addr = s.recvfrom(1024)
                        if len(data) >= 20:  # 最小IPヘッダ長
                            ip_header_len = (data[0] & 0x0F) * 4
                            if len(data) >= ip_header_len + 8:  # ICMP最小長
                                icmp_type = data[ip_header_len]
                                if icmp_type == 0:  # Echo Reply
                                    try:
                                        recv_id = struct.unpack('!H', data[ip_header_len + 4:ip_header_len + 6])[0]
                                        recv_seq = struct.unpack('!H', data[ip_header_len + 6:ip_header_len + 8])[0]
                                        if recv_id == ident and recv_seq == seq:
                                            elapsed = (time.time() - start) * 1000
                                            return True, round(elapsed, 2)
                                    except struct.error:
                                        continue
                return False, None
        except OSError as icmp_error:
            # ICMPソケットが失敗した場合、RAWソケット + IPヘッダを試す
            try:
                icmp_packet = create_icmp_packet(ident, seq, ipv6=False)
                ip_header = create_ipv4_header(src_ip, dst_ip, len(icmp_packet))
                packet = ip_header + icmp_packet

                recv_sock = None
                send_sock = None
                try:
                    recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                    recv_sock.settimeout(0.5)
                    recv_sock.bind(('', 0))  # バインドを追加
                    
                    send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
                    send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                    
                    start = time.time()
                    send_sock.sendto(packet, (dst_ip, 0))

                    while time.time() - start < 0.5:
                        ready = select.select([recv_sock], [], [], 0.1)[0]
                        if ready:
                            data, addr = recv_sock.recvfrom(1024)
                            if len(data) >= 20:
                                ip_header_len = (data[0] & 0x0F) * 4
                                if len(data) >= ip_header_len + 8:
                                    icmp_type = data[ip_header_len]
                                    if icmp_type == 0:
                                        try:
                                            recv_id = struct.unpack('!H', data[ip_header_len + 4:ip_header_len + 6])[0]
                                            recv_seq = struct.unpack('!H', data[ip_header_len + 6:ip_header_len + 8])[0]
                                            if recv_id == ident and recv_seq == seq:
                                                elapsed = (time.time() - start) * 1000
                                                return True, round(elapsed, 2)
                                        except struct.error:
                                            continue
                    return False, None
                    
                finally:
                    if send_sock:
                        send_sock.close()
                    if recv_sock:
                        recv_sock.close()
                        
            except OSError as raw_error:
                raise raw_error
                
    except PermissionError:
        return ping_once_simple(host)
    except Exception as e:
        print(f"ping_once_ipv4_raw error: {e} - fallbackを使用")
        return ping_once_simple(host)

# --- IPv6自作ICMPヘッダ + RAW送信 ---
def ping_once_ipv6_raw(host, ident, seq):
    try:
        dst_ip = socket.getaddrinfo(host, None, socket.AF_INET6)[0][4][0]
        src_ip = get_valid_ipv6_src()
        icmp_packet = create_icmp_packet(ident, seq, ipv6=True, src_ip=src_ip, dst_ip=dst_ip)

        with socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6) as s:
            s.settimeout(0.5)
            start = time.time()
            s.sendto(icmp_packet, (dst_ip, 0, 0, 0))
            
            while time.time() - start < 0.5:
                ready = select.select([s], [], [], 0.1)[0]
                if ready:
                    data, addr = s.recvfrom(1024)
                    if len(data) >= 8:
                        icmp_type = data[0]
                        if icmp_type == 129:  # Echo Reply
                            try:
                                recv_id = struct.unpack('!H', data[4:6])[0]
                                recv_seq = struct.unpack('!H', data[6:8])[0]
                                if recv_id == ident and recv_seq == seq:
                                    elapsed = (time.time() - start) * 1000
                                    return True, round(elapsed, 2)
                            except struct.error:
                                continue
            return False, None
            
    except PermissionError:
        return ping_once_simple(host)
    except Exception as e:
        # IPv6が利用できない環境の場合はfallbackを使用
        return ping_once_simple(host)

# --- IPv4/IPv6共通ping dispatcher ---
def ping_once_sync(host, ident, seq):
    try:
        if ':' in host:
            return ping_once_ipv6_raw(host, ident, seq)
        else:
            return ping_once_ipv4_raw(host, ident, seq)
    except Exception as e:
        print(f"ping_once_sync error: {e}")
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
            try:
                items.sort(key=lambda x: (0, ipaddress.ip_address(x[0])))
            except:
                items.sort(key=lambda x: x[0])  # fallback to string sort

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

            # 並列実行
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
            # 短い間隔で次のホストへ
            await asyncio.sleep(0.1)

def load_hosts_from_file(filename="hosts.yaml"):
    try:
        with open(filename, 'r') as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        # デフォルト設定を作成
        default_hosts = [
            {"host": "google.com", "name": "Google"},
            {"host": "1.1.1.1", "name": "Cloudflare"},
            {"host": "127.0.0.1", "name": "localhost"},
        ]
        with open(filename, 'w') as f:
            yaml.dump(default_hosts, f, default_flow_style=False)
        print(f"デフォルトの{filename}を作成しました。")
        return default_hosts

async def main():
    # 初回にRAWソケット権限をチェック
    print("🔍 RAWソケット権限をチェック中...")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP):
            print("✅ RAWソケット使用可能")
    except PermissionError:
        print("⚠️  RAWソケット使用不可 - fallback pingを使用")
    
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