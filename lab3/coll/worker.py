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

# Fix Mininet 'mx' staircased terminal output by converting \n to \r\n
class CRLFStream:
    def __init__(self, stream):
        self.stream = stream

    def write(self, data):
        self.stream.write(data.replace("\r\n", "\n").replace("\n", "\r\n"))

    def flush(self):
        self.stream.flush()

sys.stdout = CRLFStream(sys.stdout)

DEBUG = False  # Set to True to enable detailed logging per chunk

class MyCollectives(Collectives):
    def __init__(self, rank, world):
        self.rank = rank
        self.world = world
        
        # Create a UDP socket
        self.soc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Enable broadcast so we don't need ARP to send packets
        self.soc.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        # Bind to port 9999 to receive broadcast responses from the switch
        self.soc.bind(('', 9999))
        # Switch address: subnet broadcast IP, port 0xbee0 (48864)
        my_ip = get_ip()
        subnet_broadcast = ".".join(my_ip.split(".")[:-1] + ["255"])
        self.switch_addr = (subnet_broadcast, 48864)
        
        # Keep track of a global chunk_id counter across multiple AllReduce calls
        self.next_chunk_id = 0

    def log(self, msg):
        if DEBUG:
            current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            print(f"[{current_time}] [Rank {self.rank}] {msg}", flush=True)

    def AllReduce(self, input: list[int], output: list[int], op : str = "sum"):
        assert len(input), "input cannot be empty"
        assert len(input) == len(output), "input and output must have the same size"
        
        CHUNK_SIZE = 6
        W = 4  # Sliding window size
        TIMEOUT = 0.5  # Retransmission timeout (500 milliseconds)
        num_elements = len(input)
        num_chunks = (num_elements + CHUNK_SIZE - 1) // CHUNK_SIZE
        
        self.log(f"Starting AllReduce ({op}) with {num_chunks} chunks (vector size {num_elements})")
        start_time = time.time()

        # Set socket to non-blocking
        self.soc.setblocking(False)
        
        base_chunk_idx = 0
        next_to_send_idx = 0
        
        completed = [False] * num_chunks
        results = [None] * num_chunks
        
        # Track when each chunk was last sent and attempt count
        sent_time = [0.0] * num_chunks
        tx_attempts = [0] * num_chunks
        
        # Helper function to send/retransmit a chunk
        def send_chunk(c_idx):
            global_chunk_id = self.next_chunk_id + c_idx
            pos = c_idx * CHUNK_SIZE
            chunk_vals = input[pos : pos + CHUNK_SIZE]
            chunk_len = len(chunk_vals)
            
            vals = [chunk_vals[i] if i < chunk_len else 0 for i in range(6)]
            
            data = struct.pack(">IHHHiiiiii", global_chunk_id, self.rank, self.world, chunk_len, *vals)
            send(self.soc, data, self.switch_addr)
            
            tx_attempts[c_idx] += 1
            action = "Sent" if tx_attempts[c_idx] == 1 else "Retransmitted"
            self.log(f"{action} chunk {c_idx} (global ID {global_chunk_id}), attempt {tx_attempts[c_idx]}")
            
            sent_time[c_idx] = time.time()
        
        while base_chunk_idx < num_chunks:
            # 1. Send new chunks within the window
            while next_to_send_idx < num_chunks and next_to_send_idx < base_chunk_idx + W:
                send_chunk(next_to_send_idx)
                next_to_send_idx += 1
                
            # 2. Try to receive all pending responses currently in the socket buffer
            received_any = False
            while True:
                try:
                    res_data, addr = recv(self.soc, 1024)
                    unpacked = struct.unpack(">IHHHiiiiii", res_data)
                    res_chunk_id, res_rank, res_world, res_chunk_len = unpacked[:4]
                    res_vals = unpacked[4:]
                    received_any = True
                    
                    # Check if this completed chunk belongs to the current AllReduce invocation
                    c_idx = res_chunk_id - self.next_chunk_id
                    if 0 <= c_idx < num_chunks:
                        if not completed[c_idx]:
                            completed[c_idx] = True
                            results[c_idx] = (res_vals, res_chunk_len)
                            
                            # Slide window base as far as possible
                            old_base = base_chunk_idx
                            while base_chunk_idx < num_chunks and completed[base_chunk_idx]:
                                res_vals, clen = results[base_chunk_idx]
                                pos = base_chunk_idx * CHUNK_SIZE
                                for i in range(clen):
                                    output[pos + i] = res_vals[i]
                                base_chunk_idx += 1
                except (BlockingIOError, socket.timeout, OSError):
                    # No more packets to read in this iteration
                    break
            
            # 3. Check for timeouts and retransmit in-flight chunks
            now = time.time()
            for c_idx in range(base_chunk_idx, next_to_send_idx):
                if not completed[c_idx] and (now - sent_time[c_idx] > TIMEOUT):
                    send_chunk(c_idx)
                    
            # 4. If no packets were read in this iteration, yield CPU to the switch
            if not received_any:
                time.sleep(0.001)
                
        # Advance the global chunk ID counter
        self.next_chunk_id += num_chunks
        elapsed_total_ms = (time.time() - start_time) * 1000
        self.log(f"Finished AllReduce in {elapsed_total_ms:.1f}ms")

    def ReduceScatter(self, input: list[int], output: list[int]):
        assert len(input), "input cannot be empty"
        assert len(input) == (len(output) * self.world), "input size must be N * output size"

    def AllGather(self, input: list[int], output: list[int]):
        assert len(input), "input cannot be empty"
        assert len(output) == (len(input) * self.world), "input size must be N * input size"


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("rank", type=int)
    p.add_argument("world", type=int)
    args = p.parse_args()

    set_drop_prob(send=0.2, recv=0.2, seed=42 + args.rank)
    coll = MyCollectives(args.rank, args.world)

    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    print(f"[{current_time}] --- Running AllReduce tests for rank {args.rank} ---")
    Test.test_allreduce(coll, args.rank, args.world, 66)
