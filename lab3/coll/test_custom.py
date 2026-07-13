import argparse
import socket
import struct
import sys
import os
import datetime
import time

# Ensure parent directory is in path to resolve the 'util' package
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from util.collectives import Collectives
from util.network import get_ip, set_drop_prob, recv, send
from worker import MyCollectives

# Fix Mininet 'mx' staircased terminal output by converting \n to \r\n
class CRLFStream:
    def __init__(self, stream):
        self.stream = stream

    def write(self, data):
        self.stream.write(data.replace("\r\n", "\n").replace("\n", "\r\n"))

    def flush(self):
        self.stream.flush()

sys.stdout = CRLFStream(sys.stdout)

DEBUG = False  # Set to True for verbose per-test progress logs

def run_test(coll, rank, world, size, loss_rate):
    set_drop_prob(send=loss_rate, recv=loss_rate, seed=42 + rank)
    
    inp = [i + rank for i in range(size)]
    expected = [sum(i + r for r in range(world)) for i in range(size)]
    out = [0] * size
    
    if DEBUG:
        print(f"\n--- [Rank {rank}] Running test: Size {size}, Loss {loss_rate*100:.0f}% ---", flush=True)
    
    start_time = time.time()
    try:
        coll.AllReduce(inp, out)
        elapsed_ms = (time.time() - start_time) * 1000
        if out == expected:
            if DEBUG:
                print(f"[Rank {rank}] SUCCESS: size {size}, loss {loss_rate*100:.0f}%", flush=True)
            return True, elapsed_ms
        else:
            print(f"[Rank {rank}] FAILURE: size {size}, loss {loss_rate*100:.0f}%", flush=True)
            print(f"  Expected: {expected[:10]} ...")
            print(f"  Got:      {out[:10]} ...")
            return False, elapsed_ms
    except Exception as e:
        elapsed_ms = (time.time() - start_time) * 1000
        print(f"[Rank {rank}] ERROR during test: {e}", flush=True)
        return False, elapsed_ms

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("rank", type=int)
    p.add_argument("world", type=int)
    args = p.parse_args()

    sys.stdout.flush()
    print(f"=== Starting Custom AllReduce Test Suite for Rank {args.rank} (World Size {args.world}) ===")
    
    coll = MyCollectives(args.rank, args.world)
    results = []
    
    test_cases = [
        {"desc": "Size smaller than CHUNK_SIZE", "size": 1, "loss": 0.0},
        {"desc": "Size equal to CHUNK_SIZE", "size": 2, "loss": 0.0},
        {"desc": "Size not a multiple of CHUNK_SIZE", "size": 5, "loss": 0.0},
        {"desc": "Large size (window pipelining)", "size": 66, "loss": 0.1},
        {"desc": "Large size (loss resilience)", "size": 66, "loss": 0.2},
    ]

    for tc in test_cases:
        passed, duration = run_test(coll, args.rank, args.world, tc["size"], tc["loss"])
        results.append({
            "desc": tc["desc"],
            "size": tc["size"],
            "loss": tc["loss"],
            "passed": passed,
            "duration": duration
        })

    success = all(r["passed"] for r in results)

    print("\n==============================================")
    if success:
        print(f"=== [Rank {args.rank}] ALL CUSTOM TESTS PASSED! ===")
    else:
        print(f"=== [Rank {args.rank}] SOME TESTS FAILED! ===")
    print("==============================================")
    
    print("\n---------------- TEST SUMMARY ----------------")
    print(f"{'Test Description':<32} | {'Size':<5} | {'Loss':<5} | {'Status':<8} | {'Time':<10}")
    print("-" * 72)
    for r in results:
        status_str = "PASSED" if r["passed"] else "FAILED"
        loss_str = f"{r['loss']*100:.0f}%"
        time_str = f"{r['duration']:.1f}ms"
        print(f"{r['desc']:<32} | {r['size']:<5} | {loss_str:<5} | {status_str:<8} | {time_str:<10}")
    print("-" * 72, flush=True)
