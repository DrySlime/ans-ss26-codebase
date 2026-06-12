# plot.py (Local Execution)
import json
import matplotlib.pyplot as plt
import numpy as np

# Konfigurierbare Basis-Kapazität eines einzelnen Links in Mininet (in Mbps)
# WICHTIG: An den Parameter 'bw' der TCLink-Konfiguration in der Topologie anpassen!
LINK_CAPACITY_MBPS = 15.0  

def load_results(filename):
    with open(filename, "r") as f:
        data = json.load(f)
    return [
        data.get('test1_intra_edge_mbps', 0),
        data.get('test2_intra_pod_mbps', 0),
        data.get('test3_inter_pod_single_mbps', 0),
        data.get('test4_inter_pod_bisection_mbps', 0),
        data.get('test5_stride_1_mbps', 0),
        data.get('test6_stride_4_mbps', 0),
        data.get('test7_random_mbps', 0)
    ]

# Daten laden
single_path_vals = load_results("sp_results.json")
multi_path_vals = load_results("ft_results.json")

# Berechnung des theoretischen Maximums (0% Verlust, kein Blocking)
# Basiert auf der Anzahl der iperf-Streams pro Testlauf im Hauptskript:
# T1 (Intra-Edge): 4 Paare
# T2 (Intra-Pod): 4 Paare
# T3 (Single-Flow): 1 Paar
# T4 (Bisection Worst-Case): 8 Paare
# T5 (Stride 1): 16 Paare
# T6 (Stride 4): 16 Paare
# T7 (Random): 16 Paare
ideal_vals = [
    4 * LINK_CAPACITY_MBPS,
    4 * LINK_CAPACITY_MBPS,
    1 * LINK_CAPACITY_MBPS,
    8 * LINK_CAPACITY_MBPS,
    16 * LINK_CAPACITY_MBPS,
    16 * LINK_CAPACITY_MBPS,
    16 * LINK_CAPACITY_MBPS
]

labels = [
    'T1: Intra-Edge\n(L2 Switching)', 
    'T2: Intra-Pod\n(Aggregation)', 
    'T3: Inter-Pod\n(Single-Flow)', 
    'T4: Inter-Pod\n(Worst-Case)',
    'T5: Intra-Pod\n(Stride 1)',
    'T6: Inter-Pod\n(Stride 4)',
    'T7: Inter-Pod\n(Random)'
]

x = np.arange(len(labels))
width = 0.25  # Balkenbreite reduziert, um 3 Balken pro Kategorie zu fassen

fig, ax = plt.subplots(figsize=(16, 7))

# Drei gruppierte Balken erzeugen
rects1 = ax.bar(x - width, single_path_vals, width, label='Single-Path Routing', color='#e74c3c')
rects2 = ax.bar(x, multi_path_vals, width, label='Multi-Path Routing (Fat-Tree)', color='#2ecc71')
rects3 = ax.bar(x + width, ideal_vals, width, label='Theoretical Max (0% Loss)', color='#3498db')

# Achsen und Titel
ax.set_ylabel('Aggregate Throughput (Mbps)', fontsize=12, fontweight='bold')
ax.set_title('Performance Comparison: Routing vs. Theoretical Maximum Capacity', fontsize=14, fontweight='bold')
ax.set_xticks(x)
ax.set_xticklabels(labels, fontsize=11)

# Legende außerhalb des Datenbereichs platzieren, um Überlappungen zu vermeiden
ax.legend(fontsize=11, loc='upper left', bbox_to_anchor=(0.01, 0.99))

# Grid für bessere Lesbarkeit
ax.grid(axis='y', linestyle='--', alpha=0.7)

# Labeling-Funktion
def autolabel(rects):
    for rect in rects:
        height = rect.get_height()
        if height > 0:
            ax.annotate(f'{height:.1f}',
                        xy=(rect.get_x() + rect.get_width() / 2, height),
                        xytext=(0, 3),  # 3 Punkte vertikaler Versatz
                        textcoords="offset points",
                        ha='center', va='bottom', fontsize=9, fontweight='bold')

autolabel(rects1)
autolabel(rects2)
autolabel(rects3)

# Layout optimieren und speichern
fig.tight_layout()
plt.savefig('routing_performance_comprehensive.png', dpi=300)
print("Plot successfully saved as 'routing_performance_comprehensive.png'.")