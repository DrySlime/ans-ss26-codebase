import os
import sys

# Ensure parent directory is in path to resolve the 'util' package
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from util import controller


class MyController(controller.Client):
    def __init__(self):
        super().__init__("s1", topo="log/topology.json")
        print("Hello from MyController")

    def setup(self):
        # 1. Reset standard switch state (dmac, registers, multicast groups)
        self.reset()

        # 2. Setup the multicast flood group for flooded/unknown packets
        self.setup_flood()

        # 3. Setup static MAC forwarding in dmac table
        self.setup_mac()

        # 4. Setup ARP proxy entries in arp_table
        hosts = self.topo.get_hosts_connected_to(self.sw)
        for host in hosts:
            mac = self.topo.get_host_mac(host)
            ip = self.topo.get_host_ip(host).split("/")[0]
            self.table_add("arp_table", "arp_reply", [ip], [mac])

if __name__ == "__main__":
    c = controller.App(MyController())

