from FrameMakerPPP.PacketCrafting.LLDP.CreateLLDP import SocketCreator, LLDP_Tests
import time

class LLDPRunner():

    def create_frames(self):

        interface = "Realtek PCIe GbE Family Controller"

        socketCreator = LLDP_Tests(interface)

        for i in range (100):
            time.sleep(5)
            socketCreator.make_full_LLDP_packet(interface)


if __name__=="__main__":
    runner = LLDPRunner()
    runner.create_frames()

