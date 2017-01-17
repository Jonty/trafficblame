#!/usr/bin/env python
import os
import signal
import socket
import time
import struct
import ConfigParser
from collections import defaultdict

from pcapy import open_live

from netaddr import all_matching_cidrs

from twisted.internet import reactor, task
from twisted.web.wsgi import WSGIResource
from twisted.web.server import Site

from flask import Flask, Response

config = ConfigParser.ConfigParser()
config.read(['trafficblame.conf'])

DEV = config.get('Network', 'SniffInterface')
CIDR_RANGE = config.get('Network', 'CidrRange')
PERIOD = int(config.get('Network', 'SamplePeriod'))

LISTEN_PORT = int(config.get('WebInterface', 'HttpPort'))
STRIPHOST = config.get('WebInterface', 'StripHost')


current_data_received = defaultdict(int)
current_data_sent = defaultdict(int)
now = int(time.time())

def run_pcap(f):
    def recv_packet(hdr, data):
        global now, current_data_received, current_data_sent

        # Fire off the aggregates to the main thread once per second.
        # This is both because we work on second resolution, and because
        # firing this for every packet is VERY expensive in Twisted
        if int(time.time()) != now:
            reactor.callFromThread(f, now, current_data_received, current_data_sent)

            current_data_received = defaultdict(int)
            current_data_sent = defaultdict(int)
            now = int(time.time())

        #src_mac = data[0:6]
        #dst_mac = data[6:12]
        src_ip = data[26:30]
        dst_ip = data[30:34]
        data_len = hdr.getlen()
        
        current_data_received[dst_ip] += data_len
        current_data_sent[src_ip] += data_len

    # IP traffic that is leaving or arriving in the specified network, and not staying within it
    PCAP_FILTER  = 'ip and ((src net %s and not dst net %s) or (dst net %s and src net not %s))' \
        % tuple([CIDR_RANGE] * 4)
    
    MAX_LEN      = 35 # We only need the first 35 bytes of a packet
    MAX_PKTS     = -1 # -1 == No limit
    PROMISCUOUS  = 0
    READ_TIMEOUT = 100 

    p = open_live(DEV, MAX_LEN, PROMISCUOUS, READ_TIMEOUT)
    p.setfilter(PCAP_FILTER)
    p.loop(MAX_PKTS, recv_packet)
 

data_received = defaultdict(lambda: defaultdict(int))
data_sent = defaultdict(lambda: defaultdict(int))
hostname_cache = {}

def remove_old_data():
    # Remove data outside the window
    now = int(time.time())
    timerange = set(range(now, now - (PERIOD+1), -1))
    
    old_received_timestamps = set(data_received.keys()) - timerange
    for timestamp in old_received_timestamps:
        del data_received[timestamp]

    old_sent_timestamps = set(data_sent.keys()) - timerange
    for timestamp in old_sent_timestamps:
        del data_sent[timestamp]

    # Remove inactive IP's from the hostname cache
    live_ips = set()
    for _, data in data_received.items():
        live_ips.update(data.keys())
    for _, data in data_sent.items():
        live_ips.update(data.keys())

    for ip in (set(hostname_cache.keys()) - live_ips):
        del hostname_cache[ip]

    return PERIOD


def populate_hostname_cache(ip):
    try:
        host = socket.gethostbyaddr(ip)[0]
    except socket.herror:
        host = None

    if not host:
        host = ip

    host = host.replace(STRIPHOST, '')
    hostname_cache[ip] = host


def process_packet_data(now, current_data_received, current_data_sent):
    matched_ips = []
    datasets = [
        (current_data_received, data_received),
        (current_data_sent, data_sent)
    ]

    for new_data, data in datasets:
        for bin_ip, data_len in new_data.items():
            ip, = struct.unpack('!4s', bin_ip)
            ip = socket.inet_ntoa(ip)

            if all_matching_cidrs(ip, [CIDR_RANGE]):
                data[now][ip] += data_len
                matched_ips.append(ip)
 
    # Populate hostname cache
    for ip in matched_ips:
        if ip not in hostname_cache:
            hostname_cache[ip] = ip
            reactor.callInThread(populate_hostname_cache, ip)

 
def format_amount(amount, seconds):
    amount = amount / seconds
    for x in ['b/s','kb/s','Mb/s']:
        if amount < 1000.0:
            return "%3.1f %s" % (amount, x)
        amount /= 1000.0


app = Flask(__name__)
@app.route("/")
def serve_stats():

    sum_overall = defaultdict(int)
    sum_received = defaultdict(int)
    sum_sent = defaultdict(int)

    seconds_of_data = 0
    now = int(time.time())

    for timestamp in range(now, now - PERIOD, -1):
        have_data = False

        ips = data_received.get(timestamp, {})
        for ip, data_len in ips.items():
            sum_received[ip] += data_len
            sum_overall[ip] += data_len
            have_data = True
        
        ips = data_sent.get(timestamp, {})
        for ip, data_len in ips.items():
            sum_sent[ip] += data_len
            sum_overall[ip] += data_len
            have_data = True

        if have_data:
            seconds_of_data += 1

    totals = sorted(sum_overall.items(), lambda x,y: cmp(x[1], y[1]))
    totals.reverse()

    format_string = '{0:<20}{1:<35}{2:<14}{3:<13}{4:<13}\n'
    response = format_string.format('IP', 'HOST', 'IN', 'OUT', 'TOTAL')
    response += '\n'

    for ip, total in totals:
        response += format_string.format(
            ip, hostname_cache[ip],
            format_amount(sum_received[ip], seconds_of_data),
            format_amount(sum_sent[ip], seconds_of_data),
            format_amount(total, seconds_of_data)
        )

    headers = {
        'Content-Type': 'text/plain'
    }
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
    reactor.listenTCP(LISTEN_PORT, site)
    print "Server running on http://0.0.0.0:%s" % LISTEN_PORT
    
    clean_call = task.LoopingCall(remove_old_data)
    clean_call.start(1)

    reactor.callInThread(run_pcap, process_packet_data)

    reactor.run(installSignalHandlers=False)
 

if __name__ == "__main__":
    main()
