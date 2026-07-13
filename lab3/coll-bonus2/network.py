#!/usr/bin/env python3

import os
import sys

from p4utils.mininetlib.network_API import NetworkAPI

log = os.path.join(os.path.abspath(os.path.dirname(__file__)), "log")
net = NetworkAPI()

# --- Level 1 (ToR) and Level 2 (Spine) Switches ---
s1 = net.addP4Switch("s1")  # ToR 1
s2 = net.addP4Switch("s2")  # ToR 2
s3 = net.addP4Switch("s3")  # Spine (Level 2)

net.setP4Source("s1", "switch.p4")
net.setP4Source("s2", "switch.p4")
net.setP4Source("s3", "switch.p4")

# --- Local Workers ---
# ToR 1 Workers: h1, h2
h1 = net.addHost("h1")
h2 = net.addHost("h2")
net.addLink(h1, s1)
net.addLink(h2, s1)
net.setIntfMac(h1, s1, "00:00:00:00:00:01")
net.setIntfIp(h1, s1, "10.0.0.1/24")
net.setIntfMac(h2, s1, "00:00:00:00:00:02")
net.setIntfIp(h2, s1, "10.0.0.2/24")

# ToR 2 Workers: h3, h4
h3 = net.addHost("h3")
h4 = net.addHost("h4")
net.addLink(h3, s2)
net.addLink(h4, s2)
net.setIntfMac(h3, s2, "00:00:00:00:00:03")
net.setIntfIp(h3, s2, "10.0.0.3/24")
net.setIntfMac(h4, s2, "00:00:00:00:00:04")
net.setIntfIp(h4, s2, "10.0.0.4/24")

# --- Inter-Switch Links (ToR <-> Spine) ---
# s1 port 3 <-> s3 port 1
net.addLink(s1, s3)
# s2 port 3 <-> s3 port 2
net.addLink(s2, s3)

net.setLogLevel("info")
net.disableArpTables()
net.setCompiler(outdir=log)
net.setTopologyFile(f"{log}/topology.json")
net.startNetwork()
net.enableCli()
