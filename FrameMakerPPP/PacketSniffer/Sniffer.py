from datetime import time

from scapy.all import *
from scapy.layers.l2 import Ether
from scapy.sendrecv import sniff


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
        if packet[Ether].dst == "01:80:c2:00:00:0e":
            print("Got one")
            print(time.time() - self.start_time)
            packet.show()
            self.packet = packet
            self.stop_now = True

    def start_sniffer(self):
        self.start_time = time.time()
        sniff(iface=self.interface, prn=self.look_for_spec_packet)


if __name__ == "__main__":
    runner = PacketScanner()
    runner.start_sniffer()
