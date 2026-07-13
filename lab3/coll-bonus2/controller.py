import os
import sys

# Ensure parent directory is in path to resolve the 'util' package
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from util import controller


class CollController(controller.Client):
    def __init__(self, name):
        super().__init__(name, topo="log/topology.json")
        print(f"Initializing CollController for {self.sw} (Bonus 4.5)")

    def setup(self):
        self.reset()
        self.setup_flood()
        self.setup_mac()

        # Reset SwitchML state registers
        self.register_reset("ingress.expected_chunk_id")
        self.register_reset("ingress.count")
        self.register_reset("ingress.bitmap")
        self.register_reset("ingress.is_globally_complete")
        self.register_reset("ingress.pool0")
        self.register_reset("ingress.pool1")
        self.register_reset("ingress.pool2")
        self.register_reset("ingress.pool3")
        self.register_reset("ingress.pool4")
        self.register_reset("ingress.pool5")

        if self.sw == "s1":
            # ToR 1 (Level 1): 2 local workers (h1, h2), rank 0 to Spine, Spine on port 3
            self.register_write("ingress.is_spine", 0, 0)
            self.register_write("ingress.expected_count", 0, 2)
            self.register_write("ingress.tor_rank", 0, 0)
            self.register_write("ingress.spine_port", 0, 3)
            # Multicast group 1 for broadcasting down to local workers (ports 1, 2)
            self.add_multicast_group(1, [1, 2])
        elif self.sw == "s2":
            # ToR 2 (Level 1): 2 local workers (h3, h4), rank 1 to Spine, Spine on port 3
            self.register_write("ingress.is_spine", 0, 0)
            self.register_write("ingress.expected_count", 0, 2)
            self.register_write("ingress.tor_rank", 0, 1)
            self.register_write("ingress.spine_port", 0, 3)
            # Multicast group 1 for broadcasting down to local workers (ports 1, 2)
            self.add_multicast_group(1, [1, 2])
        elif self.sw == "s3":
            # Spine (Level 2): 2 ToR switches (s1, s2) on ports 1 and 2
            self.register_write("ingress.is_spine", 0, 1)
            self.register_write("ingress.expected_count", 0, 2)
            # Multicast group 1 for broadcasting down to both ToR switches (ports 1, 2)
            self.add_multicast_group(1, [1, 2])


if __name__ == "__main__":
    for sw in ["s1", "s2", "s3"]:
        c = CollController(sw)
        c.setup()
