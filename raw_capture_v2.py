#!/usr/bin/env python3
"""
双向协议捕获器 v2
==================
参考 raw_capture.py 改进：
  1. 客户端/服务器 payload 分开捕获、分开保存
  2. 每轮输出摘要（包数、数据类型统计）
  3. 支持命令行参数指定时长和输出目录
  4. 自动检测游戏流量接口

服务器端点: 42.186.51.49:8001

用法:
  python raw_capture_v2.py              # 默认15秒一轮
  python raw_capture_v2.py --duration 10 --out ./my_data
"""
import subprocess, zlib, os, sys, time, threading, tempfile, struct, argparse
from datetime import datetime
from collections import defaultdict

TSHARK = r"C:\Program Files\Wireshark\tshark.exe"
HOST = "42.186.51.49"
PORT = 8001


def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


def detect_interface():
    log("[检测] 扫描网络接口...")
    for i in range(1, 9):
        try:
            r = subprocess.run(
                [TSHARK, "-i", str(i), "-f", f"host {HOST}",
                 "-a", "duration:2", "-w", os.devnull],
                capture_output=True, timeout=5
            )
            if r.returncode == 0:
                cap = subprocess.run(
                    [TSHARK, "-i", str(i), "-f", f"host {HOST}",
                     "-a", "duration:2", "-T", "fields", "-e", "frame.number"],
                    capture_output=True, text=True, encoding="utf-8", errors="ignore", timeout=5
                )
                lines = [l.strip() for l in cap.stdout.split("\n") if l.strip().isdigit()]
                if lines:
                    log(f"  接口 {i} 检测到 {len(lines)} 个包")
                    return i
        except:
            pass
    return None


def parse_protocol_packets(data):
    """按4字节大端长度前缀切分协议消息"""
    pkts = []
    off = 0
    while off < len(data) - 4:
        try:
            bl = struct.unpack(">I", data[off:off+4])[0]
            if 4 < bl <= len(data) - off - 4 and bl < 200000:
                pkts.append(data[off:off+bl+4])
                off += bl + 4
            else:
                off += 1
        except:
            off += 1
    return pkts


def decompress_body(body):
    """解压 zlib 数据，返回文本"""
    for magic in [b"\x78\x9c", b"\x78\xda"]:
        if magic in body:
            try:
                zp = body.find(magic)
                text = zlib.decompressobj(15).decompress(body[zp:]).decode("utf-8", errors="replace")
                return text
            except:
                pass
    return None


def analyze_text(text):
    """快速分析文本内容类型"""
    stats = defaultdict(int)
    if not text:
        return stats
    # 简单特征匹配
    if "world_unit" in text.lower() or "cfg_npc" in text:
        stats["world_unit"] += text.count("cfg_")
    if "[0,0,2," in text:
        stats["格式B容器"] += 1
    if '5,4,' in text and ',5,4,' in text:
        stats["Tb_user_card"] += 1
    # 精确统计
    cfg_world = text.count("cfg_world_item")
    if cfg_world:
        stats["世界物品"] = cfg_world
    if "cfg_union" in text:
        stats["联合体"] += 1
    if "notice" in text.lower() or "公告" in text:
        stats["公告"] += 1
    if "planet" in text.lower() or "行星" in text:
        stats["行星"] += 1
    # 统计9位wid数量
    import re
    wids = re.findall(r'\b1\d{8}\b', text)
    if wids:
        stats["wid数量"] = len(wids)
    return stats


def extract_payloads(pcap_path):
    """从 pcapng 提取客户端和服务器的 payload"""
    res = subprocess.run(
        [TSHARK, "-r", pcap_path,
         "-T", "fields", "-e", "tcp.srcport", "-e", "tcp.payload"],
        capture_output=True, text=True, encoding="utf-8", errors="ignore"
    )

    server_bytes = bytearray()
    client_bytes = bytearray()

    for line in res.stdout.strip().split("\n"):
        parts = line.strip().split("\t")
        if len(parts) >= 2 and parts[1].strip():
            try:
                src_port = parts[0].strip()
                payload = bytes.fromhex(parts[1].strip().replace(":", ""))
                if src_port == str(PORT):
                    server_bytes.extend(payload)
                else:
                    client_bytes.extend(payload)
            except:
                pass

    return bytes(client_bytes), bytes(server_bytes)


def save_decoded(pkts, out_dir, seq, tag):
    """解压所有消息并保存，返回保存数量和统计"""
    saved = 0
    total_chars = 0
    all_stats = defaultdict(int)

    for i, p in enumerate(pkts):
        if len(p) < 16:
            continue
        body = p[16:]
        text = decompress_body(body)
        if not text or not text.strip():
            continue

        fn = f"{out_dir}/{tag}_{seq:06d}_{i:03d}_{len(text)}chars.txt"
        with open(fn, "w", encoding="utf-8") as f:
            f.write(text)
        saved += 1
        total_chars += len(text)

        stats = analyze_text(text)
        for k, v in stats.items():
            all_stats[k] += v

    return saved, total_chars, all_stats


def capture_round(iface, sec, tmp_path):
    subprocess.run(
        [TSHARK, "-i", str(iface), "-f", f"host {HOST}",
         "-a", f"duration:{sec}", "-w", tmp_path],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=sec + 10
    )


def worker(iface, sec, out_dir):
    """单线程worker：每轮同时捕获双向，解析后分别保存"""
    seq = 0
    while True:
        seq += 1
        fd, tmp = tempfile.mkstemp(suffix=".pcapng")
        os.close(fd)

        capture_round(iface, sec, tmp)
        client_raw, server_raw = extract_payloads(tmp)
        os.remove(tmp)

        # 解析客户端
        c_pkts = parse_protocol_packets(client_raw)
        c_n, c_chars, c_stats = save_decoded(c_pkts, out_dir, seq, "C")

        # 解析服务器
        s_pkts = parse_protocol_packets(server_raw)
        s_n, s_chars, s_stats = save_decoded(s_pkts, out_dir, seq, "S")

        # 输出摘要
        parts = []
        if c_n > 0:
            c_stat = ", ".join(f"{k}={v}" for k, v in sorted(c_stats.items())[:3])
            parts.append(f"C:{c_n}包/{c_chars}字符({c_stat})")
        if s_n > 0:
            s_stat = ", ".join(f"{k}={v}" for k, v in sorted(s_stats.items())[:3])
            parts.append(f"S:{s_n}包/{s_chars}字符({s_stat})")

        if parts:
            log(f"  [#{seq}] {' | '.join(parts)}")
        else:
            log(f"  [#{seq}] 无数据")


def main():
    parser = argparse.ArgumentParser(description="双向协议捕获器")
    parser.add_argument("--duration", type=int, default=15, help="每轮捕获秒数 (默认15)")
    parser.add_argument("--out", default="decoded_messages", help="输出目录")
    parser.add_argument("--host", default=HOST, help=f"目标服务器IP (默认{HOST})")
    args = parser.parse_args()

    out_dir = args.out
    os.makedirs(out_dir, exist_ok=True)

    print("=" * 60)
    print("  双向协议捕获器 v2")
    print(f"  目标: {args.host}:{PORT}")
    print(f"  输出: {out_dir}/")
    print(f"  每轮: {args.duration} 秒")
    print("=" * 60)

    iface = detect_interface()
    if not iface:
        log("[!] 未检测到游戏流量")
        return 1

    log(f"使用接口 #{iface}")
    log("按 Ctrl+C 停止\n")

    t = threading.Thread(target=worker, args=(iface, args.duration, out_dir), daemon=True)
    t.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log("\n停止捕获")

    return 0


if __name__ == "__main__":
    sys.exit(main())
