
#!/usr/bin/env python3
import argparse, json, os, random, time, datetime, ipaddress
BASE = os.path.dirname(__file__)
LOG_DIR = os.path.abspath(os.path.join(BASE, "..", "logs"))
os.makedirs(LOG_DIR, exist_ok=True)
def now_iso(): return datetime.datetime.utcnow().isoformat(timespec="milliseconds")+"Z"
def rand_ip(): return str(ipaddress.IPv4Address(random.randint(0x0A000001, 0xDF0000FE)))
def write(name, rec):
    with open(os.path.join(LOG_DIR, name), "a", encoding="utf-8") as f: f.write(json.dumps(rec)+"\n")
def gen_auth(minutes, burst):
    end = time.time()+minutes*60; users=["root","admin","ubuntu","alice","bob"]; srcs=[rand_ip() for _ in range(8)]
    while time.time()<end:
        src=random.choice(srcs); user=random.choice(users); success=random.random()>0.7
        rec={"@timestamp":now_iso(),"host":"lab-linux-1","source":{"ip":src},"user":{"name":user},
             "event":{"action":"ssh_login"},"auth":{"status":"success" if success else "failure","method":"password"}}
        write("auth.log", rec)
        if burst=="brute_force" and not success:
            for _ in range(5):
                rec2=dict(rec); rec2["@timestamp"]=now_iso(); rec2["auth"]={"status":"failure","method":"password"}; write("auth.log", rec2)
        time.sleep(0.1)
def gen_web(minutes, traffic):
    end=time.time()+minutes*60; methods=["GET","POST"]; paths=["/","/login","/admin","/robots.txt","/wp-login.php","/.git/config","/asdf","/doesnotexist"]
    while time.time()<end:
        status=200
        if traffic=="web" and random.random()<0.5: status=random.choice([302,401,403,404,500])
        rec={"@timestamp":now_iso(),"host":"lab-web-1","source":{"ip":rand_ip()},"method":random.choice(methods),
             "path":random.choice(paths),"status":status,"user_agent":{"original":"Mozilla/5.0"}}
        write("web.log", rec); time.sleep(0.05)
def gen_net(minutes):
    end=time.time()+minutes*60; dst_ports=list(range(20,1024)); src=rand_ip()
    while time.time()<end:
        rec={"@timestamp":now_iso(),"host":"lab-net-1","source":{"ip":src},"destination":{"ip":rand_ip(),"port":random.choice(dst_ports)},"network":{"transport":"tcp"}}
        write("net.log", rec); time.sleep(0.02)
if __name__=="__main__":
    ap=argparse.ArgumentParser(); ap.add_argument("--minutes",type=int,default=1)
    ap.add_argument("--burst",choices=["none","brute_force"],default="none")
    ap.add_argument("--traffic",choices=["none","web"],default="none"); args=ap.parse_args()
    gen_auth(args.minutes,args.burst); 
    if args.traffic=="web": gen_web(args.minutes,"web")
    gen_net(max(1,args.minutes//2))
