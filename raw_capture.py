#!/usr/bin/env python3
"""双向纯包捕获+解压器"""
import subprocess,zlib,os,sys,time,threading,tempfile,struct
from datetime import datetime

TSHARK=r"C:\Program Files\Wireshark\tshark.exe"
HOST="42.186.51.49"
OUT_DIR="decoded_messages"
os.makedirs(OUT_DIR,exist_ok=True)

def detect():
    print("[detect] scanning...",flush=True)
    for i in range(1,9):
        try:
            r=subprocess.run([TSHARK,"-i",str(i),"-f",f"host {HOST}","-a","duration:2","-w",os.devnull],capture_output=True,timeout=5)
            if r.returncode==0:
                cap=subprocess.run([TSHARK,"-i",str(i),"-f",f"host {HOST}","-a","duration:2","-T","fields","-e","frame.number"],capture_output=True,text=True,encoding="utf-8",errors="ignore",timeout=5)
                ln=[l.strip() for l in cap.stdout.split("\n") if l.strip().isdigit()]
                if ln: print(f"  IF#{i} {len(ln)}pkt"); return i
        except: pass
    return None

def parse_packets(data):
    """按4字节长度前缀切分协议消息"""
    pkts=[]; off=0
    while off<len(data)-4:
        try:
            bl=struct.unpack(">I",data[off:off+4])[0]
            if 4<bl<=len(data)-off-4 and bl<200000:
                pkts.append(data[off:off+bl+4]); off+=bl+4
            else: off+=1
        except: off+=1
    return pkts

def save_decoded(pkts,dir,seq,tag):
    """解压所有消息并存为文件"""
    saved=0
    for i,p in enumerate(pkts):
        if len(p)<16: continue
        body=p[16:]
        if b"\x78\x9c" not in body: continue
        try:
            zp=body.find(b"\x78\x9c")
            text=zlib.decompressobj(15).decompress(body[zp:]).decode("utf-8",errors="replace")
            if not text.strip(): continue
            fn=f"{dir}/{tag}_{seq:06d}_{i:03d}.txt"
            with open(fn,"w",encoding="utf-8") as f: f.write(text)
            saved+=1
        except: pass
    return saved

def capture_round(iface,sec,tmp):
    subprocess.run([TSHARK,"-i",str(iface),"-f",f"host {HOST}","-a",f"duration:{sec}","-w",tmp],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=sec+10)

def extract_and_save(tmp,seq,tag):
    """从pcap提取payload, 解压, 保存"""
    res=subprocess.run([TSHARK,"-r",tmp,"-T","fields","-e","tcp.payload"],capture_output=True,text=True,encoding="utf-8",errors="ignore")
    buf=bytearray()
    for ln in res.stdout.strip().split("\n"):
        ln=ln.strip().replace(":","")
        if ln:
            try: buf.extend(bytes.fromhex(ln))
            except: pass
    pkts=parse_packets(bytes(buf))
    n=save_decoded(pkts,OUT_DIR,seq,tag)
    return n

def capture():
    seq=[0]
    def worker(label,delay):
        if delay: time.sleep(delay)
        while True:
            seq[0]+=1
            s=seq[0]
            fd,t=tempfile.mkstemp(suffix=".pcapng"); os.close(fd)
            capture_round(iface,15,t)
            n=extract_and_save(t,s,label)
            os.remove(t)
            print(f"  [{label}#{s}] {n} messages saved")

    t1=threading.Thread(target=worker,args=("S",0),daemon=True)
    t2=threading.Thread(target=worker,args=("C",7),daemon=True)
    t1.start(); t2.start()
    try:
        while True: time.sleep(1)
    except KeyboardInterrupt:
        print("\nstop")

print("="*60)
print("Bidirectional Capture + Decompress")
print("Saves decompressed protocol messages only")
print("="*60)
iface=detect()
if not iface: print("[!] no traffic"); exit(1)
print(f"IF#{iface}, Ctrl+C stop\n")
capture()
