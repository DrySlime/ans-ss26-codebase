"""
 Copyright (c) 2025 Computer Networks Group @ UPB

 Permission is hereby granted, free of charge, to any person obtaining a copy of
 this software and associated documentation files (the "Software"), to deal in
 the Software without restriction, including without limitation the rights to
 use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 the Software, and to permit persons to whom the Software is furnished to do so,
 subject to the following conditions:

 The above copyright notice and this permission notice shall be included in all
 copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 """

# Class for an edge in the graph
class Edge:
	def __init__(self):
		self.lnode = None
		self.rnode = None
	
	def remove(self):
		self.lnode.edges.remove(self)
		self.rnode.edges.remove(self)
		self.lnode = None
		self.rnode = None

# Class for a node in the graph
class Node:
	def __init__(self, id, type):
		self.edges = []
		self.id = id
		self.type = type

	# Add an edge connected to another node
	def add_edge(self, node):
		edge = Edge()
		edge.lnode = self
		edge.rnode = node
		self.edges.append(edge)
		node.edges.append(edge)
		return edge

	# Remove an edge from the node
	def remove_edge(self, edge):
		self.edges.remove(edge)

	# Decide if another node is a neighbor
	def is_neighbor(self, node):
		for edge in self.edges:
			if edge.lnode == node or edge.rnode == node:
				return True
		return False


class Fattree:

	def __init__(self, num_ports):
		self.servers = []
		self.switches = []
		self.numports = num_ports
		self.generate(num_ports)

	def generate(self, num_ports):
		k = num_ports
		n = k // 2  # Anzahl der Ports pro Layer-Richtung (k/2)

        # 1. Core-Ebene generieren
        # (k/2)^2 Core-Switches, aufgeteilt in k/2 logische Gruppen der Größe k/2

		core_switches = []
		for i in range(n * n):
			core = Node(id=f"core_{i}", type="core")
			core_switches.append(core)
			self.switches.append(core)

		# 2. Pods generieren und iterativ verkabeln
		for pod in range(k):
			agg_switches = []
			edge_switches = []

			# Aggregation- und Edge-Switches für Pod p anlegen
			for i in range(n):
				agg = Node(id=f"pod_{pod}_agg_{i}", type="aggregation")
				edge = Node(id=f"pod_{pod}_edge_{i}", type="edge")

				agg_switches.append(agg)
				edge_switches.append(edge)

				self.switches.extend([agg, edge])

			# Edge <-> Server Verkabelung (Southbound)
			# Jeder Edge-Switch verbindet k/2 dedizierte Server
			for i, edge in enumerate(edge_switches):
				for j in range(n):
					server = Node(id=f"pod_{pod}_edge_{i}_server_{j}", type="server")
					self.servers.append(server)
					edge.add_edge(server)

				# Aggregation <-> Edge Verkabelung (Intra-Pod)
				# Vollständiger bipartiter Graph zwischen Aggregation und Edge innerhalb eines Pods
			for agg in agg_switches:
				for edge in edge_switches:
					agg.add_edge(edge)

			# Core <-> Aggregation Verkabelung (Northbound)
			# Deterministisches Wiring-Muster des Clos-Netzwerks:
			# Der i-te Aggregation-Switch des Pods p wird mit der i-ten logischen 
			# Gruppe der Core-Switches verbunden (jeweils n Verbindungen).
			for i, agg in enumerate(agg_switches):
				for j in range(n):
					core_index = i * n + j  # Mappt auf die i-te Gruppe
					agg.add_edge(core_switches[core_index])