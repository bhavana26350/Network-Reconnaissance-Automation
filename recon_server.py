#!/usr/bin/env python3
"""
NetRecon Automator v5 — Maximum Speed
· Every command runs in its own thread (fully parallel)
· Aggressive timeouts — fast scan, fast feedback
· Per-command SSE streaming
Run as root: sudo python3 recon_server.py
"""
from flask import Flask, request, send_from_directory, Response, stream_with_context
import subprocess, threading, datetime, os, re, json, time, socket

app = Flask(__name__, static_folder='.')
RESULTS_DIR = os.path.expanduser("~/netrecon_results")
os.makedirs(RESULTS_DIR, exist_ok=True)

def sanitize(t):
    return bool(re.match(r'^[a-zA-Z0-9._/\-:\[\]]+$', t.strip()))

def run_cmd(cmd, timeout=12):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        out = (r.stdout or "").strip()
        err = (r.stderr or "").strip()
        if err and not out: out = err
        elif err and out:   out += "\n--- stderr ---\n" + err
        return out or "[No output]"
    except subprocess.TimeoutExpired:
        return f"[TIMEOUT] exceeded {timeout}s"
    except Exception as e:
        return f"[ERROR] {e}"

def get_host_info(target):
    info = {}
    try:    info['ip']       = socket.gethostbyname(target)
    except: info['ip']       = target
    try:    info['hostname'] = socket.gethostbyaddr(target)[0]
    except: info['hostname'] = 'N/A'
    info['whois'] = run_cmd(f"whois {target} 2>&1 | head -35", timeout=8)
    return info

# ── TOOL COMMANDS — tight timeouts for speed ─────────────────────
# (label, cmd_template, timeout_sec)
TOOL_COMMANDS = {
  "nmap": [
    ("Ping Sweep",         "nmap -sn --host-timeout 6s {T}",                              8),
    ("Quick Top-100",      "nmap -T5 -F --host-timeout 10s {T}",                         12),
    ("Service Version",    "nmap -sV -T4 -p 21,22,23,25,53,80,110,143,443,3306,8080 --version-intensity 3 --host-timeout 15s {T}", 18),
    ("SYN Stealth",        "nmap -sS -T5 -p 1-1024 --host-timeout 12s {T}",              15),
    ("OS Detection",       "nmap -O --osscan-guess --host-timeout 10s {T}",              12),
    ("Aggressive -500",    "nmap -A -T4 -p 1-500 --host-timeout 18s {T}",               20),
    ("UDP Top-15",         "nmap -sU --top-ports 15 -T4 --host-timeout 12s {T}",         15),
    ("Vuln Scripts",       "nmap --script vuln -T4 -p 80,443,21,22 --host-timeout 18s {T}", 20),
    ("HTTP Scripts",       "nmap --script http-title,http-headers -p 80,443,8080 --host-timeout 10s {T}", 12),
    ("SMB Scripts",        "nmap --script smb-os-discovery -p 445,139 --host-timeout 10s {T}", 12),
    ("All Ports Fast",     "nmap -p- -T5 --min-rate 3000 --host-timeout 25s {T}",       28),
    ("ACK Firewall",       "nmap -sA -T5 -p 80,443,22 --host-timeout 8s {T}",           10),
  ],
  "tcpdump": [
    ("Capture 10 Pkts",    "timeout 6 tcpdump -c 10 -n host {T} 2>&1 || true",           8),
    ("TCP Only",           "timeout 6 tcpdump -c 10 -n 'tcp and host {T}' 2>&1 || true", 8),
    ("UDP Only",           "timeout 6 tcpdump -c 10 -n 'udp and host {T}' 2>&1 || true", 8),
    ("ICMP Only",          "timeout 6 tcpdump -c 10 -n 'icmp and host {T}' 2>&1 || true",8),
    ("HTTP p80",           "timeout 6 tcpdump -c 10 -n 'port 80 and host {T}' 2>&1 || true", 8),
    ("HTTPS p443",         "timeout 6 tcpdump -c 10 -n 'port 443 and host {T}' 2>&1 || true",8),
    ("DNS p53",            "timeout 5 tcpdump -c 10 -n 'port 53' 2>&1 || true",          7),
    ("Verbose",            "timeout 6 tcpdump -c 8 -vv -n host {T} 2>&1 || true",        8),
    ("Hex Dump",           "timeout 5 tcpdump -c 5 -XX -n host {T} 2>&1 || true",        7),
    ("No DNS",             "timeout 6 tcpdump -c 10 -nn host {T} 2>&1 || true",          8),
  ],
  "masscan": [
    ("Web Ports",          "masscan {T} -p80,443,8080,8443,8888 --rate=3000 --wait=1",   12),
    ("Top Services",       "masscan {T} -p21,22,23,25,53,110,143,3306,3389,5432 --rate=3000 --wait=1", 12),
    ("SSH/FTP/Telnet",     "masscan {T} -p21,22,23 --rate=3000 --wait=1",                8),
    ("Mail Ports",         "masscan {T} -p25,110,143,465,587,993,995 --rate=3000 --wait=1", 8),
    ("DB Ports",           "masscan {T} -p3306,5432,1433,1521,6379,27017 --rate=3000 --wait=1", 8),
    ("SMB/Windows",        "masscan {T} -p135,137,138,139,445 --rate=3000 --wait=1",     8),
    ("Remote Desktop",     "masscan {T} -p3389,5900,5901 --rate=3000 --wait=1",          8),
    ("Dev/API",            "masscan {T} -p3000,4000,5000,8000,8080,9000,9200 --rate=3000 --wait=1", 8),
    ("Top 1000",           "masscan {T} -p1-1000 --rate=5000 --wait=1",                 15),
    ("Full Range",         "masscan {T} -p0-65535 --rate=8000 --wait=1",                25),
  ],
  "netcat": [
    ("SSH p22",            "nc -zv -w2 {T} 22 2>&1",                                     5),
    ("HTTP p80",           "nc -zv -w2 {T} 80 2>&1",                                     5),
    ("HTTPS p443",         "nc -zv -w2 {T} 443 2>&1",                                    5),
    ("FTP p21",            "nc -zv -w2 {T} 21 2>&1",                                     5),
    ("SMTP p25",           "nc -zv -w2 {T} 25 2>&1",                                     5),
    ("MySQL p3306",        "nc -zv -w2 {T} 3306 2>&1",                                   5),
    ("Postgres p5432",     "nc -zv -w2 {T} 5432 2>&1",                                   5),
    ("Redis p6379",        "nc -zv -w2 {T} 6379 2>&1",                                   5),
    ("MongoDB p27017",     "nc -zv -w2 {T} 27017 2>&1",                                  5),
    ("RDP p3389",          "nc -zv -w2 {T} 3389 2>&1",                                   5),
    ("HTTP Banner",        "printf 'HEAD / HTTP/1.0\\r\\n\\r\\n'|nc -w3 {T} 80 2>&1|head -12", 6),
    ("SSH Banner",         "echo ''|nc -w3 {T} 22 2>&1|head -4",                         6),
    ("SMTP Banner",        "echo ''|nc -w3 {T} 25 2>&1|head -4",                         6),
    ("FTP Banner",         "echo ''|nc -w3 {T} 21 2>&1|head -4",                         6),
    ("Port Range 1-1024",  "nc -zv -w1 {T} 1-1024 2>&1|grep -iE 'open|succeeded|Connected'|head -40", 25),
  ],
  "hping3": [
    ("ICMP x5",            "hping3 --icmp -c 5 -q {T}",                                 10),
    ("SYN p80",            "hping3 -S -p 80 -c 5 -q {T}",                               10),
    ("SYN p443",           "hping3 -S -p 443 -c 5 -q {T}",                              10),
    ("ACK p80",            "hping3 -A -p 80 -c 5 -q {T}",                               10),
    ("UDP p53",            "hping3 --udp -p 53 -c 5 -q {T}",                            10),
    ("FIN p80",            "hping3 -F -p 80 -c 5 -q {T}",                               10),
    ("XMAS Scan",          "hping3 -F -S -R -p 80 -c 5 -q {T}",                         10),
    ("NULL Scan",          "hping3 -p 80 -c 5 -q {T}",                                  10),
    ("Traceroute",         "hping3 --traceroute -V -1 -c 8 {T} 2>&1|head -15",          15),
    ("SYN p22",            "hping3 -S -p 22 -c 5 -q {T}",                               10),
    ("SYN p3306",          "hping3 -S -p 3306 -c 3 -q {T}",                              8),
    ("Timestamp",          "hping3 --icmp -C 13 -c 3 -q {T}",                            8),
  ],
  "arp-scan": [
    ("Local Network",      "arp-scan --localnet 2>&1",                                   15),
    ("Target Host",        "arp-scan {T} 2>&1",                                          10),
    ("Verbose Local",      "arp-scan -v --localnet 2>&1|head -35",                       15),
    ("Retry x3",           "arp-scan --localnet --retry=3 2>&1",                         18),
    ("Randomized",         "arp-scan --localnet --random 2>&1",                          15),
    ("Slow IDS Evasion",   "arp-scan --localnet --interval=15 2>&1",                     18),
    ("CIDR /24",           "arp-scan {T}/24 2>&1 || arp-scan --localnet 2>&1",           15),
    ("Interface eth0",     "arp-scan -I eth0 --localnet 2>&1 || arp-scan --localnet 2>&1", 15),
    ("OUI Lookup",         "arp-scan --localnet 2>&1|grep -v '^$'|head -25",             15),
    ("Bandwidth 1024",     "arp-scan --localnet --bandwidth=1024 2>&1",                  15),
  ],
}

def make_worker(tool, idx, label, cmd_tpl, timeout, target, queue, lock, event):
    def w():
        cmd = cmd_tpl.replace("{T}", target)
        t0  = time.time()
        out = run_cmd(cmd, timeout)
        elapsed = round(time.time()-t0, 2)
        with lock:
            queue.append({"tool":tool,"idx":idx,"label":label,"cmd":cmd,"output":out,"elapsed":elapsed})
        event.set()
    return w

@app.route('/')
def index():
    return send_from_directory('.', 'recon_ui.html')

@app.route('/hostinfo')
def hostinfo():
    t = request.args.get("target","").strip()
    if not t or not sanitize(t):
        return {"error":"invalid"}, 400
    return get_host_info(t)

@app.route('/scan_stream')
def scan_stream():
    target = request.args.get("target","").strip()
    tools  = [t for t in request.args.get("tools","").split(",") if t]
    if not target or not sanitize(target):
        def bad():
            yield f"data: {json.dumps({'type':'error','msg':'Invalid target'})}\n\n"
        return Response(stream_with_context(bad()), mimetype='text/event-stream')

    all_tasks = [(tool,idx,lbl,cmd,to)
                 for tool in tools
                 for idx,(lbl,cmd,to) in enumerate(TOOL_COMMANDS.get(tool,[]))]
    total = len(all_tasks)
    queue, lock, event = [], threading.Lock(), threading.Event()
    all_results = {t:[] for t in tools}

    threads = []
    for tool,idx,lbl,cmd,to in all_tasks:
        th = threading.Thread(target=make_worker(tool,idx,lbl,cmd,to,target,queue,lock,event), daemon=True)
        th.start()
        threads.append(th)

    def generate():
        yield f"data: {json.dumps({'type':'start','tools':tools,'target':target,'total':total})}\n\n"
        sent = set()
        deadline = time.time() + 180
        while len(sent) < total and time.time() < deadline:
            event.wait(timeout=0.15)
            event.clear()
            with lock:
                pending = list(queue)
            for r in pending:
                key = (r['tool'],r['idx'])
                if key not in sent:
                    sent.add(key)
                    all_results[r['tool']].append(r)
                    yield f"data: {json.dumps({'type':'cmd','data':r})}\n\n"

        for t in all_results:
            all_results[t].sort(key=lambda x: x['idx'])

        ts   = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        safe = re.sub(r'[^a-zA-Z0-9_\-]','_',target)
        txt  = os.path.join(RESULTS_DIR, f"report_{safe}_{ts}.txt")
        jsn  = os.path.join(RESULTS_DIR, f"report_{safe}_{ts}.json")
        with open(txt,'w') as f:
            f.write(f"NetRecon v5 | Target:{target} | {datetime.datetime.now()}\n{'='*70}\n")
            for tool,cmds in all_results.items():
                f.write(f"\n{'─'*70}\nTOOL: {tool.upper()}\n{'─'*70}\n")
                for c in cmds:
                    f.write(f"\n  [{c['label']}] {c['elapsed']}s\n  $ {c['cmd']}\n")
                    for l in c['output'].splitlines(): f.write(f"    {l}\n")
        with open(jsn,'w') as f:
            json.dump({"target":target,"ts":ts,"results":all_results},f,indent=2)
        yield f"data: {json.dumps({'type':'done','txt':txt,'json':jsn,'sent':len(sent)})}\n\n"

    return Response(stream_with_context(generate()), mimetype='text/event-stream',
        headers={'Cache-Control':'no-cache','X-Accel-Buffering':'no'})

@app.route('/download', methods=['POST'])
def download():
    d=request.get_json(); tool=d.get('tool',''); target=d.get('target',''); cmds=d.get('commands',[]); fmt=d.get('fmt','txt')
    ts=datetime.datetime.now().strftime("%Y%m%d_%H%M%S"); safe=re.sub(r'[^a-zA-Z0-9_\-]','_',target)
    if fmt=='json':
        return Response(json.dumps({"tool":tool,"target":target,"commands":cmds},indent=2),
            mimetype='application/json',headers={'Content-Disposition':f'attachment; filename="{tool}_{safe}_{ts}.json"'})
    lines=[f"Tool:{tool.upper()}  Target:{target}  {datetime.datetime.now()}","="*60]
    for c in sorted(cmds,key=lambda x:x.get('idx',0)):
        lines+=[f"\n[{c['label']}] {c.get('elapsed','?')}s",f"$ {c['cmd']}","─"*50,c['output']]
    return Response("\n".join(lines),mimetype='text/plain',
        headers={'Content-Disposition':f'attachment; filename="{tool}_{safe}_{ts}.txt"'})

@app.route('/download_all', methods=['POST'])
def download_all():
    d=request.get_json(); target=d.get('target',''); all_r=d.get('all_results',{}); fmt=d.get('fmt','txt')
    ts=datetime.datetime.now().strftime("%Y%m%d_%H%M%S"); safe=re.sub(r'[^a-zA-Z0-9_\-]','_',target)
    if fmt=='json':
        return Response(json.dumps({"target":target,"ts":ts,"tools":all_r},indent=2),
            mimetype='application/json',headers={'Content-Disposition':f'attachment; filename="REPORT_{safe}_{ts}.json"'})
    lines=[f"NetRecon Full Report | Target:{target} | {datetime.datetime.now()}","="*70]
    for tool,cmds in all_r.items():
        lines+=[f"\n{'─'*70}",f"TOOL: {tool.upper()}","─"*70]
        for c in sorted(cmds,key=lambda x:x.get('idx',0)):
            lines+=[f"\n  [{c['label']}] {c.get('elapsed','?')}s",f"  $ {c['cmd']}","  "+"·"*50]
            lines+=["  "+l for l in c['output'].splitlines()]
    return Response("\n".join(lines),mimetype='text/plain',
        headers={'Content-Disposition':f'attachment; filename="REPORT_{safe}_{ts}.txt"'})

if __name__=='__main__':
    print(f"\n{'='*50}\n  NetRecon v5 — {sum(len(v) for v in TOOL_COMMANDS.values())} total commands\n  Save: {RESULTS_DIR}\n  URL : http://127.0.0.1:5000\n{'='*50}\n")
    app.run(host='0.0.0.0',port=5000,debug=False,threaded=True)
