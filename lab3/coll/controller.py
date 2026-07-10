import os
import sys

# Ensure parent directory is in path to resolve the 'util' package
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from util import controller


class CollController(controller.Client):
    def __init__(self):
        super().__init__("s1", topo="log/topology.json")
        print("Hello from CollController")

    def setup(self):
        # 1. Reset standard switch state (dmac, smac, flood group, flood_mgid)
        self.reset()

        # 2. Setup the multicast flood group for flooded/unknown packets
        self.setup_flood()

        # 3. Setup static MAC forwarding in dmac table
        self.setup_mac()

        # 4. Reset SwitchML registers
        print(f"[{self.sw}] resetting SwitchML registers")
        self.register_reset("ingress.expected_chunk_id")
        self.register_reset("ingress.count")
        self.register_reset("ingress.bitmap")
        self.register_reset("ingress.pool0")
        self.register_reset("ingress.pool1")


if __name__ == "__main__":
    c = controller.App(CollController())

