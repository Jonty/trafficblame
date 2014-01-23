# TODO
# * Extract mac/ip at offset but don't decode due to cpu-expensiveness
# ** Decode at render time and cache
# * Save mac with hostname data and re-lookup if it changes
# * Configure options from command line
# * Deuglify code
# * Requirements.txt
# * Query param for period
# * Nicer template output
# * Json output

import os
import signal
import socket
import time
from collections import defaultdict

from pcapy import open_live
from impacket import ImpactDecoder
from netaddr import all_matching_cidrs

from twisted.internet import reactor, task
from twisted.web.wsgi import WSGIResource
from twisted.web.server import Site

from flask import Flask, Response#, render_template

PERIOD = 30
CIDR_RANGES = ['172.31.24.0/24']
STRIPHOST = '.dhcp.lan.london.hackspace.org.uk'

DEV          = 'en0'    # Network interface
MAX_LEN      = 1514     # Max packet size to capture
PROMISCUOUS  = 1        # Get everything we can recv
READ_TIMEOUT = 100      # In millis
PCAP_FILTER  = ''       # Empty == Recv all packets
MAX_PKTS     = -1       # Num packets to capture. -1 == No no, no no no no, no no no no, no no there's no limit.


def run_pcap(f):
    def recv_packet(hdr, data):
        decoder = ImpactDecoder.EthDecoder()
        ether = decoder.decode(data)
        ip_header = ether.child()

        try:
            src_ip = ip_header.get_ip_src()
            dst_ip = ip_header.get_ip_dst()
            reactor.callFromThread(f, src_ip, dst_ip, len(data))

        except AttributeError:
            # Loopback packets missing IPs
            # FIXME: Should avoid ever getting here with a better pcap filter
            return
         
    p = open_live(DEV, MAX_LEN, PROMISCUOUS, READ_TIMEOUT)
    p.setfilter(PCAP_FILTER)
    p.loop(MAX_PKTS, recv_packet)
 

data_received = defaultdict(lambda: defaultdict(int))
data_sent = defaultdict(lambda: defaultdict(int))

def remove_old_data():
    now = int(time.time())
    timerange = set(range(now, now - (PERIOD+1), -1))
    
    old_received_timestamps = set(data_received.keys()) - timerange
    for timestamp in old_received_timestamps:
        del data_received[timestamp]

    old_sent_timestamps = set(data_sent.keys()) - timerange
    for timestamp in old_sent_timestamps:
        del data_sent[timestamp]

    return PERIOD


hostname_cache = dict()

def populate_hostname_cache(ip):
    print "MISS CACHE for %s" % ip
    
    try:
        host = socket.gethostbyaddr(ip)[0]
    except socket.herror:
        host = None

    if not host:
        host = ip

    host = host.replace(STRIPHOST, '')

    hostname_cache[ip] = host


def pcapDataReceived(src_ip, dst_ip, data_len):
    # Ignore broadcast
    if dst_ip in ('255.255.255.255'):
        return

    # Ignore multicast
    if all_matching_cidrs(dst_ip, ['224.0.0.0/24']):
        return

    now = int(time.time())

    src_match = all_matching_cidrs(src_ip, CIDR_RANGES)
    dst_match = all_matching_cidrs(dst_ip, CIDR_RANGES)

    matched_ips = []

    # We only want to monitor traffic leaving our network ranges
    if src_match and not dst_match:
        data_sent[now][src_ip] += data_len
        matched_ips.append(src_ip)
    
    if dst_match and not src_match:
        data_received[now][dst_ip] += data_len
        matched_ips.append(dst_ip)
 
    # Populate hostname cache
    for ip in matched_ips:
        if ip not in hostname_cache:
            hostname_cache[ip] = ip
            reactor.callInThread(populate_hostname_cache, ip)
 

app = Flask(__name__)
@app.route("/")
def serve_stats():

    sum_overall = defaultdict(int)
    sum_recieved = defaultdict(int)
    sum_sent = defaultdict(int)

    now = int(time.time())
    for timestamp in range(now, now - PERIOD, -1):
        ips = data_received.get(timestamp, dict())
        for ip, data_len in ips.items():
            sum_recieved[ip] += data_len
            sum_overall[ip] += data_len
        
        ips = data_sent.get(timestamp, dict())
        for ip, data_len in ips.items():
            sum_sent[ip] += data_len
            sum_overall[ip] += data_len


    totals = sorted(sum_overall.items(), lambda x,y: cmp(x[1], y[1]))
    totals.reverse()

    format_string = '{0:<30}{1:<10}{2:<10}{3:<10}\n'
    response = format_string.format('HOST', 'IN', 'OUT', 'TOTAL')
    response += '\n'

    for ip, total in totals:
        response += format_string.format(hostname_cache[ip], sum_recieved[ip], sum_sent[ip], total)

    headers = dict()
    headers['Content-Type'] = 'text/plain'

    return Response(response, headers=headers)


def main():
    # Register signal handlers to allow us to shut down the twisted event loop
    def die(x, y):
        print "Exiting"
        os._exit(0)

    signal.signal(signal.SIGINT, die)
    signal.signal(signal.SIGTERM, die)

    resource = WSGIResource(reactor, reactor.getThreadPool(), app)
    site = Site(resource)
    
    clean_call = task.LoopingCall(remove_old_data)
    clean_call.start(1)

    reactor.listenTCP(8080, site)

    reactor.callInThread(run_pcap, pcapDataReceived)

    reactor.run(installSignalHandlers=False)
 
if __name__ == "__main__":
    main()
