import argparse
import socket
import struct
import sys
import os
import datetime
import time

# Ensure parent directory is in path to resolve the 'util' package
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from util.collectives import Collectives, Test
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

def compute_expected(rank, world, size, op):
    a, b = Test.allreduce(Test.pattern.iota_rot, rank, world, size, op)
    return a, b

def run_test(coll, rank, world, size, op, loss_rate):
    set_drop_prob(send=loss_rate, recv=loss_rate, seed=42 + rank)
    
    inp, expected = compute_expected(rank, world, size, op)
    out = [0] * size
    
    if DEBUG:
        print(f"\n--- [Rank {rank}] Test ({op.upper()}): Size {size}, Loss {loss_rate*100:.0f}% ---", flush=True)
    
    start_time = time.time()
    try:
        coll.AllReduce(inp, out, op)
        elapsed_ms = (time.time() - start_time) * 1000
        if list(out) == expected:
            if DEBUG:
                print(f"[Rank {rank}] SUCCESS ({op.upper()}): size {size}, loss {loss_rate*100:.0f}%", flush=True)
            return True, elapsed_ms
        else:
            print(f"[Rank {rank}] FAILURE ({op.upper()}): size {size}, loss {loss_rate*100:.0f}%", flush=True)
            print(f"  Expected: {expected[:10]} ...")
            print(f"  Got:      {list(out)[:10]} ...")
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
    print(f"=== Starting Custom AllReduce Operators Test Suite for Rank {args.rank} (World Size {args.world}) ===")
    
    coll = MyCollectives(args.rank, args.world)
    results = []
    
    ops = ["sum", "min", "max", "avg"]
    sizes = [1, 5, 66]
    losses = [0.0, 0.2]

    for op in ops:
        for size in sizes:
            for loss in losses:
                passed, duration = run_test(coll, args.rank, args.world, size, op, loss)
                results.append({
                    "op": op.upper(),
                    "size": size,
                    "loss": loss,
                    "passed": passed,
                    "duration": duration
                })

    success = all(r["passed"] for r in results)

    print("\n==============================================")
    if success:
        print(f"=== [Rank {args.rank}] ALL OPERATOR TESTS PASSED! ===")
    else:
        print(f"=== [Rank {args.rank}] SOME TESTS FAILED! ===")
    print("==============================================")
    
    print("\n---------------- TEST SUMMARY ----------------")
    print(f"{'Op':<6} | {'Size':<5} | {'Loss':<5} | {'Status':<8} | {'Time':<10}")
    print("-" * 50)
    for r in results:
        status_str = "PASSED" if r["passed"] else "FAILED"
        loss_str = f"{r['loss']*100:.0f}%"
        time_str = f"{r['duration']:.1f}ms"
        print(f"{r['op']:<6} | {r['size']:<5} | {loss_str:<5} | {status_str:<8} | {time_str:<10}")
    print("-" * 50, flush=True)
