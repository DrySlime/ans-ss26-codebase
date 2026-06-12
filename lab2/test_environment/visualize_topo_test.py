import matplotlib.pyplot as plt
import networkx as nx
import os
import sys
# Fügt das übergeordnete Verzeichnis (..) zum Python-Suchpfad hinzu
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Jetzt kann die Klasse aus der topo.py importiert werden
from topo import Fattree

def visualize_fattree(k):
    """
    Generiert die Fattree-Topologie für ein gegebenes k und zeichnet diese 
    mit einem mathematisch exakten, geschichteten Layout.
    """
    # 1. Topologie instanziieren
    ft = Fattree(num_ports=k)
    n = k // 2
    
    # 2. NetworkX-Graphen aufbauen
    G = nx.Graph()
    pos = {}  # Dictionary für Koordinaten: { node_id: (x, y) }
    colors = []
    
    # Listen zur Typtrennung für das Rendering
    core_nodes = []
    agg_nodes = []
    edge_nodes = []
    server_nodes = []

    # 3. Core-Switches positionieren (Y = 3)
    # Breite des Plots wird durch die Gesamtanzahl der Server definiert, um Zentrierung zu wahren
    total_servers = (k**3) // 4
    core_spacing = total_servers / (len(ft.switches) - (k * n * 2) + 1)
    
    core_idx = 0
    for switch in ft.switches:
        if switch.type == "core":
            G.add_node(switch.id)
            core_nodes.append(switch.id)
            # Gleichmäßige Verteilung im Core-Layer
            pos[switch.id] = ((core_idx + 1) * core_spacing, 3)
            core_idx += 1

    # 4. Pod-Strukturen positionieren (Y = 2 für Agg, Y = 1 für Edge, Y = 0 für Server)
    pod_width = total_servers / k  # Jeder Pod bekommt exakt seinen Raumanteil
    
    for pod in range(k):
        pod_start_x = pod * pod_width
        
        # Aggregation-Switches dieses Pods (Y = 2)
        agg_idx = 0
        for switch in ft.switches:
            if switch.type == "aggregation" and f"pod_{pod}_" in switch.id:
                G.add_node(switch.id)
                agg_nodes.append(switch.id)
                # Positionierung innerhalb des Pod-Abschnitts
                x = pod_start_x + (pod_width / (n + 1)) * (agg_idx + 1)
                pos[switch.id] = (x, 2)
                agg_idx += 1

        # Edge-Switches dieses Pods (Y = 1)
        edge_idx = 0
        for switch in ft.switches:
            if switch.type == "edge" and f"pod_{pod}_" in switch.id:
                G.add_node(switch.id)
                edge_nodes.append(switch.id)
                x = pod_start_x + (pod_width / (n + 1)) * (edge_idx + 1)
                pos[switch.id] = (x, 1)
                edge_idx += 1

    # Server positionieren (Y = 0)
    # Fortlaufende Platzierung von links nach rechts, direkt unter ihren Edge-Switches
    for s_idx, server in enumerate(ft.servers):
        G.add_node(server.id)
        server_nodes.append(server.id)
        pos[server.id] = (s_idx + 0.5, 0)

    # 5. Kanten (Edges) aus der Datenstruktur in NetworkX übernehmen
    # Um Duplikate zu vermeiden, iterieren wir über alle Switche und deren Kanten
    for switch in ft.switches:
        for edge in switch.edges:
            G.add_edge(edge.lnode.id, edge.rnode.id)

    # 6. Zeichnen des Graphen mit Matplotlib
    plt.figure(figsize=(14, 8))
    plt.title(f"Fat-Tree Data Center Topologie (k = {k})", fontsize=14, fontweight="bold")

    # Zeichne unterschiedliche Layer mit spezifischen Farben/Formen
    nx.draw_networkx_nodes(G, pos, nodelist=core_nodes, node_color="crimson", node_shape="s", node_size=500, label="Core Switch")
    nx.draw_networkx_nodes(G, pos, nodelist=agg_nodes, node_color="royalblue", node_shape="s", node_size=400, label="Aggregation Switch")
    nx.draw_networkx_nodes(G, pos, nodelist=edge_nodes, node_color="mediumseagreen", node_shape="s", node_size=400, label="Edge Switch")
    nx.draw_networkx_nodes(G, pos, nodelist=server_nodes, node_color="darkgray", node_shape="o", node_size=300, label="Server")

    # Kanten zeichnen
    nx.draw_networkx_edges(G, pos, alpha=0.6, edge_color="gray", width=1.2)

    # Labels für die Knoten hinzufügen (nur IDs, Schriftgröße skaliert mit k)
    font_size = 8 if k <= 4 else 5
    nx.draw_networkx_labels(G, pos, font_size=font_size, font_family="sans-serif", font_color="black")

    # Layout-Optimierungen
    plt.legend(loc="upper right", scatterpoints=1)
    plt.axis("off")
    plt.tight_layout()
    plt.show()

if __name__ == "__main__":
    # Teste die Visualisierung für k=4 (Empfohlen zum Validieren, da übersichtlich)
    # Für k=6 oder k=8 wächst der Graph exponentiell, bleibt aber mathematisch korrekt.
    visualize_fattree(k=4)