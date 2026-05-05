#!/usr/bin/env python3
"""
Harbor Privacy DNS Whoami Server
Handles queries for *.whoami.harborprivacy.com
Logs the resolver IP and makes it available via API
"""
import socket, threading, time, json, os
from dnslib import DNSRecord, DNSHeader, RR, A, QTYPE
from dnslib.server import DNSServer, BaseResolver

WHOAMI_ZONE = "whoami.harborprivacy.com"
RESULTS_FILE = "/tmp/harbor-whoami-results.json"
RESULTS_LOCK = threading.Lock()
SERVER_IP = "152.70.197.252"

def load_results():
    try:
        if os.path.exists(RESULTS_FILE):
            return json.loads(open(RESULTS_FILE).read())
    except:
        pass
    return {}

def save_result(token, resolver_ip):
    with RESULTS_LOCK:
        results = load_results()
        results[token] = {"ip": resolver_ip, "ts": time.time()}
        # Clean old entries (older than 5 minutes)
        now = time.time()
        results = {k: v for k, v in results.items() if now - v["ts"] < 300}
        open(RESULTS_FILE, "w").write(json.dumps(results))

class WhoamiResolver(BaseResolver):
    def resolve(self, request, handler):
        qname = str(request.q.qname).rstrip(".")
        resolver_ip = handler.client_address[0]
        
        # Extract token from subdomain e.g. abc123.whoami.harborprivacy.com
        if qname.endswith("." + WHOAMI_ZONE) or qname == WHOAMI_ZONE:
            parts = qname.replace("." + WHOAMI_ZONE, "").replace(WHOAMI_ZONE, "")
            token = parts.strip(".")
            if token:
                save_result(token, resolver_ip)
                print(f"DNS query: token={token} resolver={resolver_ip}")
        
        reply = request.reply()
        reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A(SERVER_IP), ttl=1))
        return reply

if __name__ == "__main__":
    resolver = WhoamiResolver()
    server = DNSServer(resolver, port=53, address="0.0.0.0")
    print(f"Harbor Whoami DNS server starting on port 5354")
    server.start_thread()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        server.stop()
