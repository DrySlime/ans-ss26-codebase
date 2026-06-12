# plot.py (Lokale Ausführung)
import json
import matplotlib.pyplot as plt
import numpy as np

def load_results(filename):
    with open(filename, "r") as f:
        data = json.load(f)
    # Extraktion der erweiterten 7 Metriken
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

# Labels für die x-Achse entsprechend der 7 Tests
labels = [
    'T1: Intra-Edge\n(L2 Switching)', 
    'T2: Intra-Pod\n(Aggregation)', 
    'T3: Inter-Pod\n(Single-Flow)', 
    'T4: Inter-Pod\n(Worst-Case)',
    'T5: Inter-Pod\n(Stride 1)',
    'T6: Inter-Pod\n(Stride 4)',
    'T7: Inter-Pod\n(Random)'
]

x = np.arange(len(labels))
width = 0.35  # Balkenbreite

# Figure-Größe erhöht, um 7 Tests übersichtlich darzustellen
fig, ax = plt.subplots(figsize=(14, 6))

# Gruppierte Balken erstellen
rects1 = ax.bar(x - width/2, single_path_vals, width, label='Single-Path Routing', color='#e74c3c')
rects2 = ax.bar(x + width/2, multi_path_vals, width, label='Multi-Path Routing (Fat-Tree)', color='#2ecc71')

# Achsen und Titel
ax.set_ylabel('Aggregierter Durchsatz (Mbps)', fontsize=12, fontweight='bold')
ax.set_title('Performance-Vergleich: Single-Path vs. Multi-Path nach Topologie-Ebenen', fontsize=14, fontweight='bold')
ax.set_xticks(x)
ax.set_xticklabels(labels, fontsize=11)
ax.legend(fontsize=11, loc='upper left')

# Grid für bessere Lesbarkeit
ax.grid(axis='y', linestyle='--', alpha=0.7)

# Werte-Label über den Balken anbringen
def autolabel(rects):
    for rect in rects:
        height = rect.get_height()
        if height > 0:
            ax.annotate(f'{height:.1f}',
                        xy=(rect.get_x() + rect.get_width() / 2, height),
                        xytext=(0, 3),  # 3 Punkte vertikaler Offset
                        textcoords="offset points",
                        ha='center', va='bottom', fontsize=9, fontweight='bold')

autolabel(rects1)
autolabel(rects2)

# Layout optimieren und speichern
fig.tight_layout()
plt.savefig('routing_performance_comprehensive.png', dpi=300)
print("Plot erfolgreich als 'routing_performance_comprehensive.png' gespeichert.")