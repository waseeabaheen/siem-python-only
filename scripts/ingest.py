
#!/usr/bin/env python3
import os, json, sqlite3, datetime
from dateutil import parser as du
BASE=os.path.dirname(__file__); ROOT=os.path.abspath(os.path.join(BASE,"..")); LOG_DIR=os.path.join(ROOT,"logs"); DB=os.path.join(ROOT,"siem.db")
os.makedirs(LOG_DIR, exist_ok=True)
schema={
 "auth": "CREATE TABLE IF NOT EXISTS logs_auth(ts TEXT, host TEXT, src_ip TEXT, username TEXT, status TEXT, method TEXT)",
 "web":  "CREATE TABLE IF NOT EXISTS logs_web(ts TEXT, host TEXT, src_ip TEXT, method TEXT, path TEXT, status INTEGER, ua TEXT)",
 "net":  "CREATE TABLE IF NOT EXISTS logs_net(ts TEXT, host TEXT, src_ip TEXT, dst_ip TEXT, dst_port INTEGER, transport TEXT)"
}
def ts(v):
    try: return du.parse(v).isoformat()
    except: return datetime.datetime.utcnow().isoformat()
def p_auth(r): return (ts(r.get("@timestamp")),r.get("host"),(r.get("source") or {}).get("ip"),(r.get("user") or {}).get("name"),(r.get("auth") or {}).get("status"),(r.get("auth") or {}).get("method"))
def p_web(r):  return (ts(r.get("@timestamp")),r.get("host"),(r.get("source") or {}).get("ip"),r.get("method"),r.get("path"),int(r.get("status") or 0),((r.get("user_agent") or {}).get("original")))
def p_net(r):  return (ts(r.get("@timestamp")),r.get("host"),(r.get("source") or {}).get("ip"),(r.get("destination") or {}).get("ip"),int((r.get("destination") or {}).get("port") or 0),((r.get("network") or {}).get("transport")))
def load(cur, table, path, pipe, cols):
    if not os.path.exists(path): return 0
    n=0
    with open(path,"r",encoding="utf-8") as f:
        for line in f:
            line=line.strip()
            if not line: continue
            try:
                rec=json.loads(line)
                cur.execute(f"INSERT INTO {table} VALUES ({','.join(['?']*cols)})", pipe(rec)); n+=1
            except Exception as e: pass
    return n
if __name__=="__main__":
    conn=sqlite3.connect(DB); cur=conn.cursor()
    for ddl in schema.values(): cur.execute(ddl)
    n1=load(cur,"logs_auth",os.path.join(LOG_DIR,"auth.log"),p_auth,6)
    n2=load(cur,"logs_web", os.path.join(LOG_DIR,"web.log"), p_web,7)
    n3=load(cur,"logs_net", os.path.join(LOG_DIR,"net.log"), p_net,6)
    conn.commit(); conn.close()
    print(f"Ingested auth={n1}, web={n2}, net={n3} into {DB}")
