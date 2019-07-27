import scapy.all as scapy
import netfilterqueue
import re
import subprocess


class Injector:
    def set_load(self, pkt, load):
        pkt[scapy.Raw].load = load
        del pkt[scapy.IP].len
        del pkt[scapy.IP].chksum
        del pkt[scapy.TCP].chksum
        return pkt

    def process_packet(self, pkt):
        scapy_packet = scapy.IP(pkt.get_payload())

        if not scapy_packet.haslayer(scapy.TCP):
            scapy_packet.show()

        pkt.accept()

    def iptables(self):
        subprocess.call(
            "iptables -I OUTPUT -j NFQUEUE --queue-num 0", shell=True)
        subprocess.call(
            "iptables -I INPUT -j NFQUEUE --queue-num 0", shell=True)

    def start(self):
        print("Hello World")
        queue = netfilterqueue.NetfilterQueue()
        queue.bind(0, self.process_packet)
        try:
            queue.run()
        except KeyboardInterrupt:
            print('')
            subprocess.call("iptables --flush", shell=True)


code_injector = Injector()
code_injector.iptables()
code_injector.start()
