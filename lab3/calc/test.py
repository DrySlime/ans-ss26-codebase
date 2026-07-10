#!/usr/bin/env python3
import subprocess
import threading
import sys
import time

def run_command(cmd):
    """Run a system command and return the exit code, stdout, and stderr."""
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return res.returncode, res.stdout, res.stderr

def run_client_test(host_name, mode=""):
    """Run client.py on a specific mininet host."""
    cmd = ["mx", host_name, "python3", "client.py"]
    if mode:
        cmd.append(mode)
    
    print(f"[{host_name}] Running: {' '.join(cmd)}")
    code, stdout, stderr = run_command(cmd)
    
    print(f"[{host_name}] Exit Code: {code}")
    if stdout:
        print(f"[{host_name}] stdout:\n{stdout.strip()}")
    if stderr:
        print(f"[{host_name}] stderr:\n{stderr.strip()}")
    return code == 0

import json

def get_hosts():
    try:
        with open("log/topology.json", "r") as f:
            topo = json.load(f)
        return sorted([node["id"] for node in topo["nodes"] if node.get("isHost", False)])
    except Exception:
        return ["h1", "h2"]

def test_parallel():
    hosts = get_hosts()
    print(f"=== STARTING PARALLEL STATELESS TESTS ON {len(hosts)} HOSTS ({', '.join(hosts)}) ===")
    
    results = {}
    threads = []
    
    def worker(host, res):
        res[host] = run_client_test(host, "stateless")
        
    for host in hosts:
        t = threading.Thread(target=worker, args=(host, results))
        threads.append(t)
        t.start()
        
    for t in threads:
        t.join()
        
    if all(results.values()):
        print(f"=== PARALLEL STATELESS TESTS PASSED ON ALL {len(hosts)} HOSTS! ===")
        return True
    else:
        print("=== PARALLEL STATELESS TESTS FAILED! ===")
        return False

def test_sequential_full():
    print("=== STARTING FULL SEQUENTIAL TEST SUITE ===")
    success = run_client_test("h1")
    if success:
        print("=== FULL SEQUENTIAL TEST SUITE PASSED! ===")
    else:
        print("=== FULL SEQUENTIAL TEST SUITE FAILED! ===")
    return success

if __name__ == "__main__":
    print("Calculator Integration Test Runner")
    print("---------------------------------")
    
    # Check if we can reach the switch via mx (test if mininet is up)
    code, _, _ = run_command(["mx", "h1", "echo", "test"])
    if code != 0:
        print("Error: Mininet network does not seem to be running.")
        print("Please run 'sudo python3 network.py' in a separate terminal first.")
        sys.exit(1)
        
    parallel_ok = test_parallel()
    print()
    time.sleep(1) # short pause
    full_ok = test_sequential_full()
    
    if parallel_ok and full_ok:
        print("\nALL TESTS PASSED SUCCESSFULLY!")
        sys.exit(0)
    else:
        print("\nSOME TESTS FAILED.")
        sys.exit(1)
