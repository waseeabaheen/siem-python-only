
#!/usr/bin/env python3
import os, sqlite3, json, datetime
from jinja2 import Environment, FileSystemLoader
BASE=os.path.dirname(__file__); ROOT=os.path.abspath(os.path.join(BASE,"..")); DB=os.path.join(ROOT,"siem.db"); REPORTS=os.path.join(ROOT,"reports"); TPL_DIR=os.path.join(REPORTS,"templates")
os.makedirs(REPORTS, exist_ok=True)
def q(cur, sql): cur.execute(sql); cols=[c[0] for c in cur.description]; return [dict(zip(cols,r)) for r in cur.fetchall()]
def rules(cur):
    alerts=[]
    for r in q(cur, "SELECT src_ip, COUNT(*) AS fails FROM logs_auth WHERE status='failure' AND ts>=datetime('now','-3 minutes') GROUP BY src_ip HAVING COUNT(*)>=5"):
        alerts.append({"rule":"Linux Brute Force","severity":"High","summary":f\"{r['fails']} failed logins from {r['src_ip']} (3m)\"})
    for r in q(cur, "SELECT src_ip, COUNT(*) AS c404 FROM logs_web WHERE status=404 AND ts>=datetime('now','-2 minutes') GROUP BY src_ip HAVING COUNT(*)>=20"):
        alerts.append({"rule":"Web 404 Spray","severity":"Medium","summary":f\"{r['c404']} HTTP 404s from {r['src_ip']} (2m)\"})
    for r in q(cur, "SELECT src_ip, COUNT(DISTINCT dst_port) AS ports FROM logs_net WHERE ts>=datetime('now','-1 minutes') GROUP BY src_ip HAVING COUNT(DISTINCT dst_port)>=10"):
        alerts.append({"rule":"Port Scan","severity":"Medium","summary":f\"{r['ports']} distinct ports from {r['src_ip']} (1m)\"})
    return alerts
if __name__=='__main__':
    env=Environment(loader=FileSystemLoader(TPL_DIR)); tpl=env.get_template("report.html")
    conn=sqlite3.connect(DB); cur=conn.cursor()
    stats={k:list(q(cur, f\"SELECT COUNT(*) AS n FROM {tbl} WHERE ts>=datetime('now','-5 minutes')\"))[0]['n'] for k,tbl in [('auth_5m','logs_auth'),('web_5m','logs_web'),('net_5m','logs_net')]}
    data={"generated_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "stats": type("X",(object,),stats)(), "alerts": rules(cur)}
    html=tpl.render(**data)
    os.makedirs(REPORTS, exist_ok=True)
    with open(os.path.join(REPORTS,"siem_report.html"),"w",encoding="utf-8") as f: f.write(html)
    with open(os.path.join(REPORTS,"alerts.json"),"w",encoding="utf-8") as f: json.dump({"stats":stats,"alerts":data["alerts"]}, f, indent=2)
    print("Report written to reports/siem_report.html")
