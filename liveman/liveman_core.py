import socket
import struct
import os
import time
import select
import ipaddress
import functools
import yaml
import asyncio
import subprocess
from collections import deque, OrderedDict
from datetime import datetime

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

# --- IPv4ヘッダ生成 ---
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

# --- IPv6チェックサム用擬似ヘッダ ---
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

# --- 有効な送信元IP取得 ---
def get_valid_ipv4_src():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except:
        return "127.0.0.1"

def get_valid_ipv6_src():
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as s:
            s.connect(("2001:4860:4860::8888", 80))
            return s.getsockname()[0]
    except:
        return "::1"

# --- ICMP送受信 ---
def ping_once_ipv4_raw(host, ident, seq):
    try:
        dst_ip = socket.gethostbyname(host)
        src_ip = get_valid_ipv4_src()
        icmp_packet = create_icmp_packet(ident, seq, ipv6=False)
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as s:
            s.settimeout(0.5)
            start = time.time()
            s.sendto(icmp_packet, (dst_ip, 0))
            while time.time() - start < 0.5:
                ready = select.select([s], [], [], 0.1)[0]
                if ready:
                    data, addr = s.recvfrom(1024)
                    if len(data) >= 20:
                        ip_header_len = (data[0] & 0x0F) * 4
                        if len(data) >= ip_header_len + 8:
                            icmp_type = data[ip_header_len]
                            if icmp_type == 0:
                                recv_id = struct.unpack('!H', data[ip_header_len + 4:ip_header_len + 6])[0]
                                recv_seq = struct.unpack('!H', data[ip_header_len + 6:ip_header_len + 8])[0]
                                if recv_id == ident and recv_seq == seq:
                                    elapsed = (time.time() - start) * 1000
                                    return True, round(elapsed, 2)
            return False, None
    except:
        return False, None

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
                    if len(data) >= 8 and data[0] == 129:
                        recv_id = struct.unpack('!H', data[4:6])[0]
                        recv_seq = struct.unpack('!H', data[6:8])[0]
                        if recv_id == ident and recv_seq == seq:
                            elapsed = (time.time() - start) * 1000
                            return True, round(elapsed, 2)
            return False, None
    except:
        return False, None

def ping_once_sync(host, ident, seq):
    try:
        if ':' in host:
            return ping_once_ipv6_raw(host, ident, seq)
        else:
            return ping_once_ipv4_raw(host, ident, seq)
    except:
        return False, None

# --- TCPポート監視（ソケット版） ---
def check_tcp_sync(host, port, timeout=0.5):
    try:
        family = socket.AF_INET6 if ':' in host else socket.AF_INET
        with socket.socket(family, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((host, port))
            return result in (0, 111, 104)
    except:
        return False

async def check_tcp_port(host, port, timeout=0.5):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, functools.partial(check_tcp_sync, host, port, timeout))

# --- Traceroute機能 ---
def run_traceroute_sync(host, max_hops=30, timeout=5):
    """
    システムのtracerouteコマンドを実行してテキスト結果を返す
    """
    try:
        # IPv6アドレスかどうかチェック
        is_ipv6 = ':' in host
        
        # OSに応じてコマンドを選択
        if os.name == 'nt':  # Windows
            if is_ipv6:
                cmd = ['tracert', '-6', '-h', str(max_hops), '-w', str(timeout * 1000), host]
            else:
                cmd = ['tracert', '-4', '-h', str(max_hops), '-w', str(timeout * 1000), host]
        else:  # Unix/Linux
            if is_ipv6:
                for traceroute_cmd in ['traceroute6', 'traceroute -6']:
                    try:
                        cmd = traceroute_cmd.split() + ['-n', '-m', str(max_hops), '-w', str(timeout), host]
                        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                        if result.returncode == 0:
                            return result.stdout.strip()
                    except (subprocess.TimeoutExpired, FileNotFoundError):
                        continue
                return "IPv6 traceroute command not available"
            else:
                cmd = ['sudo', 'traceroute', '-P', 'tcp', '-p', '80', '-n', '-m', '30', '-w', '3', host]

        
        # tracerouteコマンド実行
        print(f"Running traceroute command: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            return result.stdout.strip()
        else:
            error_msg = result.stderr.strip() if result.stderr else "Unknown error"
            return f"Traceroute failed (exit code {result.returncode}): {error_msg}"
            
    except subprocess.TimeoutExpired:
        return "Traceroute timeout (60 seconds exceeded)"
    except FileNotFoundError:
        return "Traceroute command not found on this system"
    except Exception as e:
        return f"Traceroute error: {str(e)}"

async def run_traceroute(host, max_hops=30, timeout=5):
    """
    非同期でtracerouteを実行
    """
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, functools.partial(run_traceroute_sync, host, max_hops, timeout))

async def update_traceroute(host):
    """
    指定ホストのtracerouteを更新（重複実行防止付き）
    """
    if results[host]["traceroute_running"]:
        print(f"Traceroute already running for {host}, skipping...")
        return  # 既に実行中
    
    current_time = time.time()
    # 5分以内に実行済みの場合は実行しない
    if current_time - results[host]["last_traceroute_time"] < 300:
        print(f"Traceroute for {host} executed recently, skipping...")
        return
    
    results[host]["traceroute_running"] = True
    try:
        print(f"Starting traceroute for {host}...")
        traceroute_result = await run_traceroute(host)
        results[host]["traceroute"] = traceroute_result
        results[host]["last_traceroute_time"] = current_time
        print(f"Traceroute completed for {host}")
    except Exception as e:
        results[host]["traceroute"] = f"Traceroute error: {str(e)}"
        print(f"Traceroute failed for {host}: {e}")
    finally:
        results[host]["traceroute_running"] = False

# --- ホスト設定ファイル読み込み ---
def load_hosts_from_file(filename="hosts.yaml"):
    try:
        with open(filename, 'r') as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        default_hosts = [
            {"host": "google.com", "name": "Google"},
            {"host": "1.1.1.1", "name": "Cloudflare"},
            {"host": "127.0.0.1", "name": "localhost"},
        ]
        with open(filename, 'w') as f:
            yaml.dump(default_hosts, f, default_flow_style=False)
        print(f"デフォルトの{filename}を作成しました。")
        return default_hosts

# --- ホスト情報初期化 ---
hosts = load_hosts_from_file("hosts.yaml")
results = OrderedDict()
for entry in hosts:
    host = entry["host"]
    name = entry.get("name") or host
    results[host] = {
        "sent": 0,
        "received": 0,
        "rtts": [],
        "history": deque(maxlen=200),
        "ssh": False,
        "http": False,
        "hostname": name,
        "traceroute": None,  # 最新のtraceroute結果
        "traceroute_running": False,  # traceroute実行中フラグ
        "last_traceroute_time": 0  # 最後にtracerouteを実行した時刻
    }

# --- 現在選択中のホスト名（GUIと連携） ---
shared = {"current": hosts[0]["host"] if hosts else ""}

# --- 非同期モニタリングループ ---
async def monitor_loop():
    ident = os.getpid() & 0xFFFF
    seq = 0
    traceroute_counter = 0  # traceroute実行カウンター
    
    while True:
        seq += 1
        traceroute_counter += 1
        tasks = []

        for entry in hosts:
            host = entry["host"]
            ports = entry.get("ports", {"ssh": 22, "http": 80})
            ssh_port = ports.get("ssh", 22)
            http_port = ports.get("http", 80)

            async def check(host=host, ssh_port=ssh_port, http_port=http_port):
                ok, rtt = ping_once_sync(host, ident, seq)
                results[host]["sent"] += 1
                if ok:
                    results[host]["received"] += 1
                    results[host]["rtts"].append(rtt)
                    results[host]["rtt"] = rtt  # ← 最新RTT
                    rtts_valid = [x for x in results[host]["rtts"] if x is not None]
                    results[host]["avg_rtt"] = round(sum(rtts_valid) / len(rtts_valid), 2) if rtts_valid else None
                    results[host]["history"].append("O")
                else:
                    results[host]["rtts"].append(None)
                    results[host]["rtt"] = None
                    results[host]["avg_rtt"] = None
                    results[host]["history"].append("X")

                # TCP ポート監視
                results[host]["ssh"] = await check_tcp_port(host, ssh_port)
                results[host]["http"] = await check_tcp_port(host, http_port)

            tasks.append(check())

        await asyncio.gather(*tasks)
        
        # 20回に1回（約1分に1回）tracerouteを実行
        if traceroute_counter >= 20:
            traceroute_counter = 0
            print("Running periodic traceroute for all hosts...")
            for entry in hosts:
                host = entry["host"]
                # 各ホストのtracerouteを非同期で更新（重複実行防止付き）
                asyncio.create_task(update_traceroute(host))
        
        await asyncio.sleep(3)