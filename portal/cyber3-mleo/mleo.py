#!/usr/bin/env python3
# MLEO — Multi Layer Enforcement Orchestrator. Etapele 0-3 (RISC ZERO, observare).
#  0 Colectare: ARP (mac<->ip) de pe senzori + blocari din indexer
#  1 Tabela de reconciliere: mac | ip_curent | ip_istoric | sensor | first/last_seen
#  2 Imbogatire: fiecare blocare interna capata +mac (+sensor)
#  3 Match 1 (OBSERVARE): acelasi MAC, IP-uri diferite, fereastra 15 min -> alerta evaziune
# NU face NICIUN enforcement. Etapa 4+ (quarantine VLAN) = separat, cu allowlist+rollback.
import sqlite3, subprocess, json, time, re, sys, ssl, base64, urllib.request, os, calendar

DB  = "/opt/cyber3/mleo/mleo.db"
LOG = "/opt/cyber3/mleo/mleo.log"
ENV = "/opt/fasterup-portal/.env"
MATCH1_WINDOW = 15*60           # 15 min
SSHOPTS = ["-o","ConnectTimeout=6","-o","StrictHostKeyChecking=no","-o","BatchMode=yes"]

# name -> wg1 IP (socadmin, key-based). icisoc110=root/atipic -> ARP omis din serviciu.
SENSORS = {
 "f001":"10.1.1.1","f002":"10.1.2.1","f005":"10.1.5.1","f007":"10.1.7.1","f008":"10.1.8.1",
 "f009":"10.1.9.1","f010":"10.1.10.1","f011":"10.1.11.1","f012":"10.1.12.1",
 "icisoc101":"10.1.22.1","icisoc102":"10.1.25.1","icisoc103":"10.1.26.1","icisoc104":"10.1.27.1",
 "icisoc105":"10.1.28.1","icisoc106":"10.1.29.1","icisoc107":"10.1.30.1","icisoc108":"10.1.31.1",
 "icisoc109":"10.1.32.1"}
AGENT2NAME = {"005":"f001","012":"f002","018":"f005","020":"f007","021":"f008","022":"f009",
 "023":"f010","024":"f011","025":"f012","003":"icisoc101","007":"icisoc102","006":"icisoc103",
 "008":"icisoc104","009":"icisoc105","010":"icisoc106","011":"icisoc107","013":"icisoc108",
 "015":"icisoc109","016":"icisoc110"}

def now(): return int(time.time())
def logline(s):
    line = f"[{time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())} UTC] {s}"
    try:
        with open(LOG,"a") as f: f.write(line+"\n")
    except Exception: pass
    print(line)

def db():
    os.makedirs(os.path.dirname(DB), exist_ok=True)
    c = sqlite3.connect(DB, timeout=20); c.execute("PRAGMA journal_mode=WAL"); return c

def init_db(c):
    c.executescript("""
    CREATE TABLE IF NOT EXISTS recon(mac TEXT, ip TEXT, sensor TEXT, vlan TEXT,
        first_seen INT, last_seen INT, PRIMARY KEY(mac,ip,sensor));
    CREATE TABLE IF NOT EXISTS blocks(ts INT, ip TEXT, agent TEXT, sensor TEXT, rule TEXT,
        mac TEXT, enriched INT DEFAULT 0, PRIMARY KEY(ts,ip,agent));
    CREATE TABLE IF NOT EXISTS matches(ts INT, kind TEXT, mac TEXT, ips TEXT, sensor TEXT, note TEXT);
    CREATE TABLE IF NOT EXISTS tx(txid TEXT PRIMARY KEY, ts INT, sensor TEXT, mac TEXT, ips TEXT, state TEXT);
    CREATE TABLE IF NOT EXISTS contain(txid TEXT PRIMARY KEY, ts INT, sensor TEXT, ip TEXT, mac TEXT, source TEXT,
        reason TEXT, ref TEXT, action TEXT, critical INT DEFAULT 0, state TEXT, last_signal INT, signals INT DEFAULT 1);
    CREATE INDEX IF NOT EXISTS i_contain_si ON contain(sensor, ip);
    CREATE INDEX IF NOT EXISTS i_recon_ip ON recon(ip);
    CREATE INDEX IF NOT EXISTS i_recon_mac ON recon(mac);
    CREATE INDEX IF NOT EXISTS i_blk_mac ON blocks(mac);
    """); c.commit()

# ---------- Etapa 0/1: colectare ARP -> tabela reconciliere ----------
    cols={r[1] for r in c.execute("PRAGMA table_info(contain)")}
    for col,typ in (("approved_by","TEXT"),("approved_at","INT"),("expires","INT"),("released_by","TEXT"),("released_at","INT"),("exec_out","TEXT")):
        if col not in cols: c.execute(f"ALTER TABLE contain ADD COLUMN {col} {typ}")
    c.commit()

def collect_arp(c):
    t=now(); nnew=0
    for name,ip in SENSORS.items():
        try:
            out = subprocess.run(["ssh",*SSHOPTS,f"socadmin@{ip}","ip -4 neigh show"],
                capture_output=True,text=True,timeout=12).stdout
        except Exception: continue
        for ln in out.splitlines():
            m = re.match(r'^(\d{1,3}(?:\.\d{1,3}){3})\s+dev\s+\S+\s+lladdr\s+([0-9a-fA-F:]{17})\s+(\w+)', ln)
            if not m: continue
            ipa, mac, state = m.group(1), m.group(2).lower(), m.group(3)
            if state in ("FAILED","INCOMPLETE") or mac=="00:00:00:00:00:00": continue
            cur=c.execute("SELECT 1 FROM recon WHERE mac=? AND ip=? AND sensor=?",(mac,ipa,name)).fetchone()
            if cur:
                c.execute("UPDATE recon SET last_seen=? WHERE mac=? AND ip=? AND sensor=?",(t,mac,ipa,name))
            else:
                c.execute("INSERT INTO recon(mac,ip,sensor,vlan,first_seen,last_seen) VALUES(?,?,?,?,?,?)",
                          (mac,ipa,name,None,t,t)); nnew+=1
    c.commit(); return nnew

# ---------- Etapa 0: blocari din indexer ----------
def _env():
    e={}
    for l in open(ENV):
        l=l.strip()
        if l and not l.startswith("#") and "=" in l:
            k,v=l.split("=",1); e[k]=v.strip().strip('"').strip("'")
    return e
def collect_blocks(c):
    e=_env(); url=(e.get("WAZUH_INDEXER_URL") or "https://127.0.0.1:9200").rstrip("/")
    usr=e.get("WAZUH_INDEXER_USER") or "readall"; pw=e.get("WAZUH_INDEXER_PASS") or ""
    ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    body={"size":500,"sort":[{"timestamp":{"order":"desc"}}],
     "query":{"bool":{"must":[{"range":{"timestamp":{"gte":"now-30m"}}}],
       "should":[{"terms":{"rule.id":["651","100651","657","100710"]}},
                 {"match_phrase":{"rule.groups":"active_response"}}],"minimum_should_match":1}},
     "_source":["timestamp","rule.id","data.srcip","agent.id"]}
    req=urllib.request.Request(url+"/wazuh-alerts-*/_search",data=json.dumps(body).encode(),
        headers={"Content-Type":"application/json","Authorization":"Basic "+base64.b64encode(f"{usr}:{pw}".encode()).decode()})
    try: r=json.load(urllib.request.urlopen(req,context=ctx,timeout=30))
    except Exception as ex: logline(f"WARN indexer: {ex}"); return 0
    n=0
    for h in r.get("hits",{}).get("hits",[]):
        s=h["_source"]; ip=(s.get("data") or {}).get("srcip"); ag=(s.get("agent") or {}).get("id")
        rid=(s.get("rule") or {}).get("id"); ts=s.get("timestamp","")
        if not ip or not ag: continue
        try: epoch=int(time.mktime(time.strptime(ts[:19],"%Y-%m-%dT%H:%M:%S")))
        except Exception: epoch=now()
        sensor=AGENT2NAME.get(ag,ag)
        try:
            c.execute("INSERT OR IGNORE INTO blocks(ts,ip,agent,sensor,rule) VALUES(?,?,?,?,?)",(epoch,ip,ag,sensor,rid)); n+=c.execute("SELECT changes()").fetchone()[0]
        except Exception: pass
    c.commit(); return n

# ---------- Etapa 2: imbogatire blocari cu MAC ----------
def enrich(c):
    n=0
    for ts,ip,sensor in c.execute("SELECT ts,ip,sensor FROM blocks WHERE enriched=0").fetchall():
        # identitate STRICT pe același senzor: IP-urile private se repetă între clienți (fără căutare globală)
        row=c.execute("SELECT mac FROM recon WHERE ip=? AND sensor=? ORDER BY last_seen DESC LIMIT 1",(ip,sensor)).fetchone()
        mac=row[0] if row else None
        c.execute("UPDATE blocks SET mac=?,enriched=1 WHERE ts=? AND ip=? AND sensor=?",(mac,ts,ip,sensor))
        if mac: n+=1
    c.commit(); return n

# ---------- C1: propunere carantina (DRY-RUN; armarea reala = operator, cu mleo_q.sh dovedit) ----------
def _own_or_critical(ip):
    # allowlist DUR: infra SOC + IP-uri tip gateway (.1/.254) + fisier operator. NICIODATA carantina.
    if ip.startswith(("10.0.0.","10.1.","127.")): return True
    o=ip.split(".")
    if len(o)==4 and o[3] in ("1","254"): return True
    try:
        for l in open("/opt/cyber3/mleo/mleo-allow.conf"):
            l=l.strip()
            if l and not l.startswith("#") and ip.startswith(l.rstrip("*")): return True
    except Exception: pass
    return False

def propose_quarantine(c, sensor, mac, ips):
    ips=sorted(ips)
    for ip in ips:
        if _own_or_critical(ip):
            logline(f"[QUARANTINE][SKIP-ALLOWLIST] mac={mac} ip={ip} (SOC/gateway/allowlist) — NU propun"); return None
    tx=f"mleoq-{now()}-{mac.replace(':','')[-6:]}"
    if c.execute("SELECT 1 FROM tx WHERE mac=? AND state='proposed'",(mac,)).fetchone(): return None
    c.execute("INSERT OR IGNORE INTO tx(txid,ts,sensor,mac,ips,state) VALUES(?,?,?,?,?,?)",(tx,now(),sensor,mac,json.dumps(ips),"proposed")); c.commit()
    logline(f"[QUARANTINE][PROPUNERE dry-run] tx={tx} sensor={sensor} mac={mac} ips={ips} — armare MANUALA operator: `sudo mleo_q.sh add {mac} {tx} {','.join(ips)}` pe {sensor}")
    return tx

# ---------- Etapa 3: Match 1 (observare) ----------
def match1(c):
    t=now(); found=0
    rows=c.execute("SELECT mac,ip,sensor,ts FROM blocks WHERE mac IS NOT NULL AND ts>=?",(t-MATCH1_WINDOW,)).fetchall()
    by={}
    for mac,ip,sensor,ts in rows: by.setdefault(mac,{}).setdefault(ip,sensor)
    for mac,ips in by.items():
        if len(ips)>=2:
            note=f"EVAZIUNE-IP: MAC {mac} blocat pe {len(ips)} IP-uri diferite in {MATCH1_WINDOW//60}min: {sorted(ips)}"
            exist=c.execute("SELECT 1 FROM matches WHERE kind='match1' AND mac=? AND ts>=?",(mac,t-MATCH1_WINDOW)).fetchone()
            if not exist:
                sensor=list(ips.values())[0]
                c.execute("INSERT INTO matches(ts,kind,mac,ips,sensor,note) VALUES(?,?,?,?,?,?)",
                          (t,"match1",mac,json.dumps(sorted(ips)),sensor,note))
                logline("[MATCH1][OBSERVARE] "+note); found+=1
                # C1: auto-PROPUNE carantina (dry-run, allowlist dur) — armarea reala ramane operator
                propose_quarantine(c, sensor, mac, list(ips.keys()))
    c.commit(); return found

# ---------- Etapa 4 revizuită: stație INTERNĂ compromisă -> propunere de carantină (OBSERVARE) ----------
HUNT_FILE = "/opt/fasterup-portal/data/threat_hunt/latest.json"
CRITICAL_FILE = "/opt/cyber3/mleo/mleo-critical.conf"   # "<senzor> <ip|prefix*> <comentariu>" — dispozitive DOAR notificare
HUNT_CONTAIN = {"H3", "H4", "H6"}                        # stager->C2, C2 din interior, honeytoken
CB_CONTAIN_RULES = {"100216"}                            # CyberBot: troian / C2 (fără BEACON-volum, fără web-attack)
LOOKBACK = 72*3600

def _private(ip):
    try:
        import ipaddress
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False

def _critical(sensor, ip):
    """dispozitiv critic (server, centrală, gateway, DNS, echipament medical) -> doar notificare, NICIODATĂ carantină"""
    if _own_or_critical(ip): return "gateway / infrastructură SOC"
    try:
        for l in open(CRITICAL_FILE, encoding="utf-8"):
            l=l.strip()
            if not l or l.startswith("#"): continue
            p=l.split(None,2)
            if len(p)>=2 and p[0] in (sensor,"*") and (ip==p[1] or (p[1].endswith("*") and ip.startswith(p[1][:-1]))):
                return p[2] if len(p)>2 else "dispozitiv critic"
    except Exception: pass
    return None

def _signals_hunt():
    out=[]
    try:
        d=json.load(open(HUNT_FILE, encoding="utf-8"))
    except Exception:
        return out
    t=now()
    for f in d.get("findings",[]):
        if f.get("hunt") not in HUNT_CONTAIN or f.get("severity") not in ("CRITIC","ÎNALT"): continue
        ip=f.get("host") or ""
        if not _private(ip): continue
        try: last=calendar.timegm(time.strptime(str(f.get("last_seen",""))[:19],"%Y-%m-%dT%H:%M:%S"))
        except Exception: last=t
        out.append((f.get("agent"), ip, "HUNT-"+f["hunt"], f.get("title",""), f.get("id",""), last))
    return out

def _signals_cyberbot():
    out=[]
    e=_env(); host=e.get("WAZUH_SERVER_HOST"); user=e.get("WAZUH_SERVER_USER") or "socadmin"
    if not host: return out
    try:
        txt=subprocess.run(["ssh",*SSHOPTS,f"{user}@{host}","tail -n 60000 /var/ossec/logs/cyberbot.log"],
                           capture_output=True,text=True,timeout=30).stdout
    except Exception as ex:
        logline(f"WARN cyberbot.log: {ex}"); return out
    t=now()
    for ln in txt.splitlines():
        m=re.search(r'^\[(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) UTC\] \[OK\] decision=BLOCARE_IMEDIATA agent_id=(\d+) client=.*? ip=(\S+) rule=(\d+)', ln)
        if not m or m.group(4) not in CB_CONTAIN_RULES: continue
        ip=m.group(3)
        if not _private(ip): continue
        try: ts=calendar.timegm(time.strptime(m.group(1),"%Y-%m-%d %H:%M:%S"))
        except Exception: continue
        if ts < t-LOOKBACK: continue
        out.append((AGENT2NAME.get(m.group(2),m.group(2)), ip, "CYBERBOT-"+m.group(4), "CyberBot BLOCARE_IMEDIATA pe stație internă (troian/C2)", m.group(2)+":"+m.group(1), ts))
    return out

def contain_proposals(c):
    """Propune carantina de ieșire pentru stații interne compromise. OBSERVARE: nu execută nimic."""
    new=0; t=now()
    for sensor,ip,source,reason,ref,last in _signals_hunt()+_signals_cyberbot():
        if sensor not in AGENT2NAME.values(): continue
        prev=c.execute("SELECT txid,state,COALESCE(released_at,0) FROM contain WHERE sensor=? AND ip=? ORDER BY ts DESC LIMIT 1",(sensor,ip)).fetchone()
        if prev and prev[1] in ("rejected","released","expired") and last<=max(prev[2], c.execute("SELECT COALESCE(expires,0) FROM contain WHERE txid=?",(prev[0],)).fetchone()[0]):
            continue                     # semnal deja judecat de supervisor
        row=prev if prev and prev[1] in ("proposed","notify","active") else None
        if row:
            if last > (c.execute("SELECT COALESCE(last_signal,0) FROM contain WHERE txid=?",(row[0],)).fetchone()[0]):
                c.execute("UPDATE contain SET last_signal=?, signals=signals+1 WHERE txid=?",(last,row[0]))
            continue
        mrow=c.execute("SELECT mac FROM recon WHERE ip=? AND sensor=? AND last_seen>=? ORDER BY last_seen DESC LIMIT 1",(ip,sensor,t-7*86400)).fetchone()
        mac=mrow[0] if mrow else None
        crit=_critical(sensor,ip)
        if crit:
            action=f"DOAR NOTIFICARE — dispozitiv critic ({crit})"; state="notify"
        else:
            action="CARANTINĂ DE IEȘIRE (blocare spre Internet, LAN păstrat)"+(f", după IP și MAC {mac}" if mac else ", după IP")
            state="proposed"
        tx=f"mleoc-{t}-{ip.replace('.','')[-6:]}"
        c.execute("INSERT INTO contain(txid,ts,sensor,ip,mac,source,reason,ref,action,critical,state,last_signal,signals) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,1)",
                  (tx,t,sensor,ip,mac,source,reason,ref,action,1 if crit else 0,state,last))
        logline(f"[CONTAIN][OBSERVARE] tx={tx} sensor={sensor} ip={ip} mac={mac or '-'} sursa={source} actiune={action} — așteaptă aprobarea supervisorului în ▸ HUNT")
        new+=1
    c.commit(); return new

# ---------- Etapa 2: execuție DOAR la aprobarea supervisorului (▸ HUNT) ----------
EXEC = "/usr/local/sbin/cyber3-mleo-contain"
TTL_HOURS = 24
NO_EXEC_SENSORS = {"icisoc110"}          # senzor atipic (root, fără socadmin)

def _sensor_exec(sensor, args):
    ipw=SENSORS.get(sensor)
    if not ipw: return 1, f"senzor necunoscut sau fără executor: {sensor}"
    try:
        r=subprocess.run(["ssh",*SSHOPTS,f"socadmin@{ipw}","sudo","-n",EXEC,*args],capture_output=True,text=True,timeout=40,stdin=subprocess.DEVNULL)
        return r.returncode, (r.stdout+r.stderr).strip()[-600:]
    except Exception as ex:
        return 1, f"ssh: {ex}"

def _safe_mac(c, sensor, ip, mac):
    """MAC folosit doar dacă identifică o singură stație pe acel senzor (nu router/NAT/punct de acces)."""
    if not mac: return None
    rows=c.execute("SELECT DISTINCT ip FROM recon WHERE mac=? AND sensor=? AND last_seen>=?",(mac,sensor,now()-7*86400)).fetchall()
    ips={r[0] for r in rows}
    if ips!={ip}: return None
    if any(x.split(".")[-1] in ("1","254") for x in ips): return None
    return mac

def cmd_approve(txid, user):
    c=db(); init_db(c)
    r=c.execute("SELECT sensor,ip,mac,state,critical FROM contain WHERE txid=?",(txid,)).fetchone()
    if not r: print(json.dumps({"ok":False,"error":"propunere inexistentă"})); return 2
    sensor,ip,mac,state,crit=r
    if state!="proposed" or crit: print(json.dumps({"ok":False,"error":f"nu se poate aproba (stare {state}{', dispozitiv critic' if crit else ''})"})); return 2
    if sensor in NO_EXEC_SENSORS: print(json.dumps({"ok":False,"error":f"{sensor} nu are executor de carantină"})); return 2
    if _critical(sensor, ip): print(json.dumps({"ok":False,"error":"dispozitiv critic"})); return 2
    m=_safe_mac(c,sensor,ip,mac)
    rc,out=_sensor_exec(sensor,["add",txid,ip,str(TTL_HOURS)]+([m] if m else []))
    t=now()
    if rc==0 and ("CARANTINĂ ACTIVĂ" in out or "DEJA ACTIV" in out):
        c.execute("UPDATE contain SET state='active',approved_by=?,approved_at=?,expires=?,exec_out=? WHERE txid=?",(user,t,t+TTL_HOURS*3600,out,txid))
        c.commit(); logline(f"[CONTAIN][APROBAT] tx={txid} de={user} sensor={sensor} ip={ip} mac={m or '-'} ttl={TTL_HOURS}h :: {out}")
        print(json.dumps({"ok":True,"state":"active","sensor_output":out})); return 0
    c.execute("UPDATE contain SET exec_out=? WHERE txid=?",(out,txid)); c.commit()
    logline(f"[CONTAIN][EȘEC] tx={txid} de={user} sensor={sensor} ip={ip} rc={rc} :: {out}")
    print(json.dumps({"ok":False,"error":"senzorul a refuzat sau nu răspunde","sensor_output":out})); return 1

def cmd_release(txid, user):
    c=db(); init_db(c)
    r=c.execute("SELECT sensor,ip,state FROM contain WHERE txid=?",(txid,)).fetchone()
    if not r: print(json.dumps({"ok":False,"error":"inexistent"})); return 2
    sensor,ip,state=r
    t=now()
    if state=="active":
        rc,out=_sensor_exec(sensor,["remove",txid])
        if rc!=0 or "ELIBERAT" not in out:
            logline(f"[CONTAIN][EȘEC ELIBERARE] tx={txid} de={user} :: {out}")
            print(json.dumps({"ok":False,"error":"senzorul nu a confirmat eliberarea","sensor_output":out})); return 1
    else:
        out="propunere respinsă (nimic aplicat)"
    newstate="released" if state=="active" else "rejected"
    c.execute("UPDATE contain SET state=?,released_by=?,released_at=?,exec_out=? WHERE txid=?",(newstate,user,t,out,txid)); c.commit()
    logline(f"[CONTAIN][{newstate.upper()}] tx={txid} de={user} sensor={sensor} ip={ip} :: {out}")
    print(json.dumps({"ok":True,"state":newstate,"sensor_output":out})); return 0

def contain_housekeeping(c):
    t=now()
    c.execute("UPDATE contain SET state='expired' WHERE state='active' AND expires IS NOT NULL AND expires<=?",(t,))
    c.execute("UPDATE contain SET state='stale' WHERE state IN ('proposed','notify') AND COALESCE(last_signal,ts)<?",(t-7*86400,))
    c.commit()

def cmd_contain():
    c=db(); init_db(c)
    rows=c.execute("SELECT txid,ts,sensor,ip,mac,source,action,state,signals FROM contain ORDER BY ts DESC LIMIT 40").fetchall()
    if not rows: print("nicio propunere de carantină"); return
    for tx,ts,sen,ip,mac,src,act,st,n in rows:
        print(f"{st:8} {time.strftime('%m-%d %H:%M',time.gmtime(ts))} {sen:10} {ip:16} mac={mac or '-':17} {src:14} semnale={n} | {act}")

def cmd_tx():
    c=db(); init_db(c)
    rows=c.execute("SELECT txid,ts,sensor,mac,ips,state FROM tx ORDER BY ts DESC LIMIT 30").fetchall()
    if not rows: print("nicio tranzactie de carantina (0 Match1 declansat)"); return
    for tx,ts,sensor,mac,ips,state in rows:
        print(f"{state:9} {tx:28} sensor={sensor:10} mac={mac} ips={ips}")

# ---------- CLI ----------
def cmd_query(ip, sensor=None):
    c=db(); init_db(c)
    q="SELECT mac,sensor,first_seen,last_seen FROM recon WHERE ip=?"+(" AND sensor=?" if sensor else "")+" ORDER BY sensor,last_seen DESC"
    rows=c.execute(q,(ip,sensor) if sensor else (ip,)).fetchall()
    if not rows: print(f"IP {ip}: necunoscut în reconciliere{' pe '+sensor if sensor else ''} (extern, rutat sau necolectat)"); return
    seen=set()
    for mac,sen,fs,ls in rows:
        if sen in seen: continue
        seen.add(sen)
        print(f"[{sen}] IP {ip} -> MAC {mac} (last_seen {time.strftime('%Y-%m-%d %H:%M',time.gmtime(ls))})")
        for i2,f2,l2 in c.execute("SELECT ip,first_seen,last_seen FROM recon WHERE mac=? AND sensor=? ORDER BY last_seen DESC",(mac,sen)):
            print(f"    {i2:16} {time.strftime('%m-%d %H:%M',time.gmtime(f2))} .. {time.strftime('%m-%d %H:%M',time.gmtime(l2))}")
    if len(seen)>1: print(f"ATENȚIE: {ip} există pe {len(seen)} senzori (clienți diferiți) — folosiți `query {ip} <senzor>`")

def cmd_stats():
    c=db(); init_db(c)
    print("recon rows:", c.execute("SELECT COUNT(*) FROM recon").fetchone()[0],
          "| distinct MAC:", c.execute("SELECT COUNT(DISTINCT mac) FROM recon").fetchone()[0],
          "| MAC cu >1 IP:", c.execute("SELECT COUNT(*) FROM (SELECT mac FROM recon GROUP BY mac HAVING COUNT(DISTINCT ip)>1)").fetchone()[0])
    print("blocks:", c.execute("SELECT COUNT(*) FROM blocks").fetchone()[0],
          "| cu MAC (interne):", c.execute("SELECT COUNT(*) FROM blocks WHERE mac IS NOT NULL").fetchone()[0],
          "| fara MAC (externe):", c.execute("SELECT COUNT(*) FROM blocks WHERE mac IS NULL AND enriched=1").fetchone()[0])
    print("match1 (observare):", c.execute("SELECT COUNT(*) FROM matches WHERE kind='match1'").fetchone()[0])

def cmd_run():
    c=db(); init_db(c)
    a=collect_arp(c); b=collect_blocks(c); e=enrich(c); m=match1(c)
    try: contain_housekeeping(c); k=contain_proposals(c)
    except Exception as ex: logline(f"WARN contain: {ex}"); k=-1
    logline(f"RUN: arp_new={a} blocks_new={b} enriched={e} match1={m} contain_new={k}")

if __name__=="__main__":
    cmd=sys.argv[1] if len(sys.argv)>1 else "run"
    if cmd=="run": cmd_run()
    elif cmd=="query" and len(sys.argv)>2: cmd_query(sys.argv[2], sys.argv[3] if len(sys.argv)>3 else None)
    elif cmd=="contain": cmd_contain()
    elif cmd=="approve" and len(sys.argv)>3: sys.exit(cmd_approve(sys.argv[2], sys.argv[3]))
    elif cmd=="release" and len(sys.argv)>3: sys.exit(cmd_release(sys.argv[2], sys.argv[3]))
    elif cmd=="stats": cmd_stats()
    elif cmd=="tx": cmd_tx()
    elif cmd=="init": c=db(); init_db(c); print("db init ok:",DB)
    else: print("usage: mleo.py [run|stats|tx|contain|query <ip> [senzor]|init]")
