from scapy.all import *
from netfilterqueue import NetfilterQueue
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, IPv6ExtHdrFragment, TCP, UDP
import os
import time
import threading
import queue

count = 0  
warning_queue = queue.Queue() 
first_warning_time = None  
last_warning_time = None  

def findlasthd(p):
    while p.payload:
        if not hasattr(p.payload, 'nh'):
            return p.nh
        p = p.payload
    return p.nh

def hdchainDection(packet, p):
    global count, first_warning_time, last_warning_time

    frag = p.getlayer(IPv6ExtHdrFragment)
    if not frag or frag.offset != 0 or frag.m == 0:
        packet.accept()
        return

    lh = findlasthd(p)

    is_attack = False
    if lh not in [58, 6, 17]:
        is_attack = True
        lh = 60  
    elif lh == 58 and not p.haslayer(ICMPv6EchoRequest):
        is_attack = True
    elif lh == 6 and (not p.haslayer(TCP) or len(p[TCP].original) < 20):
        is_attack = True
    elif lh == 17 and not p.haslayer(UDP):
        is_attack = True

    if is_attack:
        warning_msg = f"Fragment evasion attack detected, dropping packet!! Upper-layer protocol: {lh}"
        warning_queue.put(warning_msg)
        if not first_warning_time:
            first_warning_time = time.time()
        last_warning_time = time.time()
        count += 1
        packet.drop()
    else:
        packet.accept()

def packet_handler(packet):
    pkt = IPv6(packet.get_payload())
    if pkt.haslayer(IPv6ExtHdrFragment):
        hdchainDection(packet, pkt)
    else:
        packet.accept()

def warning_printer():
    while True:
        try:
            warning_msg = warning_queue.get(timeout=1)
            print(warning_msg)
        except queue.Empty:
            continue

print("Starting packet processing, press Ctrl+C to stop...")

os.system('ip6tables -A INPUT -j NFQUEUE --queue-num 0')

nfqueue = NetfilterQueue()
nfqueue.bind(0, packet_handler)

warning_thread = threading.Thread(target=warning_printer)
warning_thread.daemon = True
warning_thread.start()

try:
    nfqueue.run()
except KeyboardInterrupt:
    print("\nProcessing stopped")
    print(f"Number of detected attack packets: {count}")
    if first_warning_time and last_warning_time:
        detection_delay = (last_warning_time - first_warning_time) / (count-1) if count > 0 else 0
        print(f"Average detection delay: {detection_delay*1000:.6f}s")
    else:
        print("No attacks detected")
    detection_rate = count / 5000 * 100
    print(f"Detection rate: {detection_rate:.2f}%")

    os.system('ip6tables -D INPUT -j NFQUEUE --queue-num 0')
    nfqueue.unbind()

print("Program ended")