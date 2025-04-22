import socket
import os
import time

def ping(host):
    """ICMPを使ってホストの生死確認"""
    response = os.system(f"ping -c 1 {host}")
    return response == 0

def check_port(host, port):
    """指定したポートにTCP接続を試みて到達可能かチェック"""
    try:
        sock = socket.create_connection((host, port), timeout=3)
        sock.close()
        return True
    except (socket.timeout, socket.error):
        return False

def check_ssh(host):
    """SSHポート(22)が開いているか確認"""
    return check_port(host, 22)

def check_http(host):
    """HTTPポート(80)が開いているか確認"""
    return check_port(host, 80)

def check_https(host):
    """HTTPSポート(443)が開いているか確認"""
    return check_port(host, 443)

def monitor_hosts(hosts):
    """複数のホストとポートを監視して結果を表示"""
    for host in hosts:
        print(f"Checking {host}...")
        icmp = ping(host)
        ssh = check_ssh(host)
        http = check_http(host)
        https = check_https(host)

        # 結果を表示
        print(f"{host} - ICMP: {'Reachable' if icmp else 'Unreachable'}")
        print(f"{host} - SSH: {'Open' if ssh else 'Closed'}")
        print(f"{host} - HTTP: {'Open' if http else 'Closed'}")
        print(f"{host} - HTTPS: {'Open' if https else 'Closed'}")
        print("-" * 40)

if __name__ == "__main__":
    # 監視対象のホスト
    hosts = ["8.8.8.8", "1.1.1.1", "192.168.1.1"]
    
    monitor_hosts(hosts)
