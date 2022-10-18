from scapy.all import *
from scapy.layers.l2 import Ether


class PacketScanner:
    def __init__(self):
        self.interface = "Realtek PCIe GbE Family Controller"
        self.packet = None
        self.stop_sniff = None
        self.stop_now = False
        self.start_time = 0.0
        self.interval_measured = 0.0

    def stop_sniffer(self, *args, **kwargs):
        if self.stop_now:
            self.interval_measured = time.time() - self.start_time
            return True

    def look_for_spec_packet(self, packet):
        if packet[Ether].dst == "MacAddress" :
            self.packet = packet
            self.stop_now = True

    def start_sniffer(self):
        self.start_time = time.time()
        sniff(iface=self.interface, prn=self.look_for_spec_packet, stop_filter=self.stop_sniffer)


if __name__=="__main__":
    runner = PacketScanner
    runner.start_sniffer()
