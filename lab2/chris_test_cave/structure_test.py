import unittest
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from topo import Fattree

class TestFattreeTopology(unittest.TestCase):
    """
    Unit-Tests zur Validierung der strukturellen Invarianten einer k-ary Fat-Tree Topologie.
    """

    def setUp(self):
        self.k = 32

        self.ft = Fattree(num_ports=self.k)
        
        # Lookup-Strukturen zur O(1) Knotenauflösung
        self.switches = {s.id: s for s in self.ft.switches}
        self.servers = {s.id: s for s in getattr(self.ft, 'servers', [])}

    def test_node_counts(self):
        """Überprüft die exakte Anzahl der Netzelemente gemäß Spezifikation."""
        k = self.k
        expected_servers = (k**3) // 4
        expected_core = (k // 2)**2
        expected_agg = k * (k // 2)
        expected_edge = k * (k // 2)

        self.assertEqual(len(self.servers), expected_servers, "Fehlerhafte Server-Anzahl.")

        core_count = sum(1 for s in self.switches.values() if s.type == "core")
        agg_count = sum(1 for s in self.switches.values() if s.type == "aggregation")
        edge_count = sum(1 for s in self.switches.values() if s.type == "edge")

        self.assertEqual(core_count, expected_core, "Fehlerhafte Core-Switch-Anzahl.")
        self.assertEqual(agg_count, expected_agg, "Fehlerhafte Aggregation-Switch-Anzahl.")
        self.assertEqual(edge_count, expected_edge, "Fehlerhafte Edge-Switch-Anzahl.")

    def test_switch_degrees(self):
        """Jeder Switch in einem non-blocking k-ary Fat-Tree belegt exakt k Ports."""
        for s in self.switches.values():
            self.assertEqual(
                len(s.edges), 
                self.k, 
                f"Switch {s.id} ({s.type}) verletzt den Knotengrad: {len(s.edges)} != {self.k}"
            )

    def test_server_degrees(self):
        """Hosts sind als Blätter des Graphen definiert (Grad = 1)."""
        for s in self.servers.values():
            self.assertEqual(
                len(s.edges), 
                1, 
                f"Server {s.id} besitzt mehr als eine physische Verbindung."
            )

    def test_topology_hierarchy(self):
        """
        Validiert die strikt hierarchische (bipartite) Verkabelung zwischen den Layern.
        """
        for s in self.switches.values():
            if s.type == "core":
                # Core-Switches verbinden ausschließlich zu den k Pods
                for edge in s.edges:
                    neighbor = edge.lnode if edge.rnode.id == s.id else edge.rnode
                    self.assertEqual(neighbor.type, "aggregation", f"Core {s.id} illegal verbunden mit {neighbor.type}")
                    
            elif s.type == "aggregation":
                # Aggregation terminiert k/2 Links am Core und k/2 Links an Edge-Switches
                core_links = 0
                edge_links = 0
                for edge in s.edges:
                    neighbor = edge.lnode if edge.rnode.id == s.id else edge.rnode
                    if neighbor.type == "core": core_links += 1
                    elif neighbor.type == "edge": edge_links += 1
                self.assertEqual(core_links, self.k // 2)
                self.assertEqual(edge_links, self.k // 2)
                
            elif s.type == "edge":
                # Edge terminiert k/2 Links am Aggregation-Layer und k/2 Links an Servern
                agg_links = 0
                server_links = 0
                for edge in s.edges:
                    neighbor = edge.lnode if edge.rnode.id == s.id else edge.rnode
                    if neighbor.type == "aggregation": 
                        agg_links += 1
                    # Fallback für Server, falls Typ-Attribut abweicht
                    elif getattr(neighbor, "type", "server") == "server": 
                        server_links += 1
                self.assertEqual(agg_links, self.k // 2)
                self.assertEqual(server_links, self.k // 2)

if __name__ == "__main__":
    print("----------------------------------------")
    print(f"TESTE FATTREE Topologie mit k={32}")
    print("----------------------------------------")
    unittest.main(verbosity=2)