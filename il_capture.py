#!/usr/bin/env python3
import subprocess,zlib,ast,json,os,sys,time,threading,queue,tempfile,struct,re
TSHARK=r"C:\Program Files\Wireshark\tshark.exe"
HOST="42.186.51.49"
NPC=("cfg_npc","HD-","Locale","{[B_SP_]}","cfg_world_item","npc指挥官","埃迪卡拉前哨站")

def wid_to_xy(w):
    s=str(w)
    if len(s)==9:
        try: return int(s[1:5]),int(s[5:9])
        except: pass
    return None,None

def extract_arrays(text):
    r=[]; i,n=0,len(text)
    while i<n:
        if text[i]=="[":
            s=i;d=0;q=False;e=False
            for j in range(i,n):
                c=text[j]
                if e: e=False; continue
                if c=="\\": e=True; continue
                if c=='"': q=not q; continue
                if not q:
                    if c=="[": d+=1
                    elif c=="]":
                        d-=1
                        if d==0:
                            try:
                                a=ast.literal_eval(text[s:j+1])
                                if isinstance(a,list): r.append(a)
                            except: pass
                            i=j+1; break
            else: i+=1
        else: i+=1
    return r

def parse_packets(data):
    pkts=[]; off=0
    while off<len(data)-4:
        try:
            bl=struct.unpack(">I",data[off:off+4])[0]
            if 4<bl<=len(data)-off-4 and bl<200000:
                pkts.append(data[off:off+bl+4]); off+=bl+4
            else: off+=1
        except: off+=1
    return pkts

def scan(a,db):
    if not isinstance(a,list) or len(a)<2: return
    nm=None; wid=None; uid=0; tid2=0
    for v in a:
        if isinstance(v,str) and len(v)>=2 and not any(k in v for k in NPC): nm=v
        if isinstance(v,int) and len(str(v))==9: wid=v
    if nm and wid:
        x,y=wid_to_xy(wid)
        if x and 0<x<=9000 and 0<y<=9000:
            if 45<=len(a)<=50 and isinstance(a[0],int):
                uid=a[0]; tid2=a[33] if len(a)>33 and a[33] else None
            if nm not in db: db[nm]={"name":nm,"uid":uid,"x":x,"y":y,"union_id":tid2}
            else:
                if uid: db[nm]["uid"]=uid
                if tid2: db[nm]["union_id"]=tid2
                db[nm]["x"]=x; db[nm]["y"]=y
    for v in a:
        if isinstance(v,list): scan(v,db)

def scan_text(text,db):
    NPC2=("cfg_npc","HD-","Locale","{[B_SP_]}","cfg_world_item","npc指挥官","埃迪卡拉前哨站")
    for m in re.finditer(r"\[(\d+),(\d+),.*?\"([^\"]+)\"",text):
        try:
            nm=m.group(3); wid=int(m.group(2))
            if len(str(wid))!=9: continue
            if any(k in nm for k in NPC2) or len(nm)<2: continue
            x,y=wid_to_xy(wid)
            if x and 0<x<=9000 and 0<y<=9000:
                if nm not in db: db[nm]={"name":nm,"uid":None,"x":x,"y":y,"union_id":None}
                db[nm]["x"]=x; db[nm]["y"]=y
        except: pass

def process_pcap(pcap,db):
    arrs=[]; all_text=""
    res=subprocess.run([TSHARK,"-r",pcap,"-Y","tcp.srcport == 8001","-T","fields","-e","tcp.payload"],capture_output=True,text=True,encoding="utf-8",errors="ignore")
    buf=bytearray()
    for ln in res.stdout.strip().split(chr(10)):
        ln=ln.strip().replace(":","")
        if ln:
            try: buf.extend(bytes.fromhex(ln))
            except: pass
    for p in parse_packets(bytes(buf)):
        if len(p)>=16:
            body=p[16:]
            if b"\x78\x9c" in body:
                try:
                    zp=body.find(b"\x78\x9c")
                    t=zlib.decompressobj(15).decompress(body[zp:]).decode("utf-8",errors="replace")
                    arrs.extend(extract_arrays(t)); all_text+=t
                except: pass
    for a in arrs:
        if isinstance(a,list): scan(a,db)
    scan_text(all_text,db)
    for line in res.stdout.strip().split(chr(10)):
        line=line.strip()
        if not line: continue
        try:
            p=bytes.fromhex(line.replace(":",""))
            if len(p)<16: continue
            b=p[16:]
            if b"\x78\x9c" not in b: continue
            zp=b.find(b"\x78\x9c")
            t=zlib.decompressobj(15).decompress(b[zp:]).decode("utf-8",errors="replace")
            for a in extract_arrays(t):
                if isinstance(a,list): scan(a,db)
            scan_text(t,db)
        except: pass

def save(db):
    o=[db[k] for k in sorted(db)]
    with open("il_capture.json","w",encoding="utf-8") as f: json.dump(o,f,indent=2,ensure_ascii=False)
    sc=sum(1 for p in o if p.get("x")); uc=sum(1 for p in o if p.get("union_id"))
    print(f"  saved: {len(o)}pl ({sc}coord,{uc}union)")

def detect():
    print("[detect] scanning...",flush=True)
    for i in range(1,9):
        try:
            r=subprocess.run([TSHARK,"-i",str(i),"-f",f"host {HOST}","-a","duration:2","-w",os.devnull],capture_output=True,timeout=5)
            if r.returncode==0:
                cap=subprocess.run([TSHARK,"-i",str(i),"-f",f"host {HOST}","-a","duration:2","-T","fields","-e","frame.number"],capture_output=True,text=True,encoding="utf-8",errors="ignore",timeout=5)
                ln=[l.strip() for l in cap.stdout.split(chr(10)) if l.strip().isdigit()]
                if ln: print(f"  IF#{i} {len(ln)}pkt"); return i
        except: pass
    return None

def capturer(iface,q):
    while True:
        fd,t=tempfile.mkstemp(suffix=".pcapng",prefix="il_"); os.close(fd)
        try:
            subprocess.run([TSHARK,"-i",str(iface),"-f",f"host {HOST}","-a","duration:15","-w",t],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=25)
            q.put(t)
        except:
            try: os.remove(t)
            except: pass

def processor(db,q):
    r=0
    try:
        while True:
            t=q.get(); r+=1
            t0=time.time(); old=len(db); process_pcap(t,db); os.remove(t)
            print(f"  R{r}: +{len(db)-old:3d}pl tot={len(db):4d} ({time.time()-t0:.1f}s)")
            save(db)
    except KeyboardInterrupt:
        print(chr(10)+"stop"); save(db)

print("="*50)
print("IL Player Capture v6")
print("reassembly + segments + regex fallback")
print("="*50)
print()
iface=detect()
if not iface: print("[!] no traffic"); exit(1)
print(f"IF#{iface}, Ctrl+C stop\n")
db={}; q=queue.Queue()
threading.Thread(target=capturer,args=(iface,q),daemon=True).start()
processor(db,q)
