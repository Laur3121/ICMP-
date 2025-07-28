from flask import Flask, jsonify, render_template
from threading import Thread
import asyncio
from liveman_core import monitor_loop, results, shared, update_traceroute

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/status")
def api_status():
    display = {}
    for host, data in results.items():
        sent = data["sent"]
        received = data["received"]
        loss = round((1 - received / sent) * 100, 1) if sent else 100.0
        
        # RTT履歴を数値の配列として準備
        rtt_history = []
        if "rtts" in data and data["rtts"]:
            for rtt in list(data["rtts"])[-50:]:  # 最新50件
                if rtt is not None:
                    rtt_history.append(rtt)
                else:
                    rtt_history.append(None)
        
        # tracerouteデータを取得（デバッグ用ログ付き）
        traceroute_data = data.get("traceroute")
        if traceroute_data:
            print(f"Traceroute data found for {host}: {traceroute_data[:100]}...")  # デバッグログ
        else:
            print(f"No traceroute data for {host}")  # デバッグログ
        
        display[host] = {
            "name": data["hostname"],
            "icmp": received > 0,
            "rtt": data.get("rtt"),
            "avg_rtt": data.get("avg_rtt"),
            "snt": sent,
            "loss": loss,
            "ssh": data.get("ssh", False),
            "http": data.get("http", False),
            "history": "".join(data["history"]),
            "rtt_history": rtt_history,  # 追加: 数値履歴
            "traceroute": traceroute_data  # 追加: tracerouteデータ
        }
    return jsonify(display)

@app.route("/api/traceroute/<host>")
def api_traceroute(host):
    """特定ホストのtracerouteを手動実行"""
    if host in results:
        # すぐにtracerouteを実行（強制実行）
        import time
        
        # 現在時刻を記録してから実行
        current_time = time.time()
        results[host]["last_traceroute_time"] = current_time - 301  # 5分前に設定して強制実行可能にする
        
        def run_traceroute_sync():
            from liveman_core import run_traceroute_sync
            traceroute_result = run_traceroute_sync(host)
            results[host]["traceroute"] = traceroute_result
            print(f"Manual traceroute completed for {host}: {traceroute_result[:100]}...")
        
        # 別スレッドで実行
        thread = Thread(target=run_traceroute_sync)
        thread.daemon = True
        thread.start()
        
        return jsonify({"status": "traceroute started", "host": host})
    else:
        return jsonify({"error": "host not found"}), 404

@app.route("/api/traceroute-test/<host>")
def api_traceroute_test(host):
    """テスト用：即座にtracerouteを実行して結果を返す"""
    if host in results:
        from liveman_core import run_traceroute_sync
        print(f"Running test traceroute for {host}...")
        traceroute_result = run_traceroute_sync(host)
        results[host]["traceroute"] = traceroute_result
        print(f"Test traceroute result: {traceroute_result[:200]}...")
        return jsonify({"host": host, "traceroute": traceroute_result})
    else:
        return jsonify({"error": "host not found"}), 404

def start_monitor_loop():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(monitor_loop())

if __name__ == "__main__":
    t = Thread(target=start_monitor_loop)
    t.daemon = True
    t.start()
    app.run(host="0.0.0.0", port=8000, debug=True)