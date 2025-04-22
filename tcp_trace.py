from bcc import BPF

# eBPFプログラム（Cで書く）
bpf_source = """
int trace_connect(struct pt_regs *ctx) {
    bpf_trace_printk("TCP connect detected\\n");
    return 0;
}
"""

# bccで読み込み＆アタッチ
b = BPF(text=bpf_source)
b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect")

print("✅ eBPF: Monitoring TCP connect calls... Ctrl+C to stop.")
b.trace_print()
