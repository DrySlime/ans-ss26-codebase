import os
import sys

# Ensure parent directory is in path to resolve the 'util' package
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scapy.all import Packet, ByteField, IntField, bind_layers, Ether, srp1

from util.calculator import Op, Calculator, CalculatorTester, s32

class Calc(Packet):
  name = "Calc"
  fields_desc = [
      ByteField("op", 0),
      IntField("a", 0),
      IntField("b", 0)
  ]

# Bind Calc to Ethernet layer on EtherType 0x1234
bind_layers(Ether, Calc, type=0x1234)

class MyCalculator(Calculator):
    def exec(self, op : Op, a : int = 0, b : int = 0):
      # Cast signed integers to unsigned 32-bit integers for Scapy's IntField
      a_unsigned = a & 0xffffffff
      b_unsigned = b & 0xffffffff
      
      # Construct the calculator packet
      pkt = Ether(dst="ff:ff:ff:ff:ff:ff", type=0x1234) / Calc(op=int(op), a=a_unsigned, b=b_unsigned)
      
      # Send the packet on interface 'eth0' and wait for a single response
      resp = srp1(pkt, iface="eth0", timeout=2, verbose=False)
      
      if resp and resp.haslayer(Calc):
          return s32(resp[Calc].a)
      else:
          raise RuntimeError("No response from calculator switch")

if __name__ == "__main__":
    c = MyCalculator()
    
    # Run in parallel-safe stateless mode if argument is provided for my couple tests
    if len(sys.argv) > 1 and sys.argv[1] == "stateless":
        print("Running parallel-safe stateless tests...")
        assert c.add(5, 10) == 15, f"add failed: got {c.add(5, 10)}"
        assert c.sub(20, 5) == 15, f"sub failed: got {c.sub(20, 5)}"
        assert c.min(3, 9) == 3, f"min failed: got {c.min(3, 9)}"
        assert c.max(-2, 5) == 5, f"max failed: got {c.max(-2, 5)}"
        assert c.neg(100) == -100, f"neg failed: got {c.neg(100)}"
        assert c.shl(8) == 16, f"shl failed: got {c.shl(8)}"
        assert c.shr(32) == 16, f"shr failed: got {c.shr(32)}"
        print("Stateless parallel tests passed!")
    else:
        # Otherwise run the full test suite
        CalculatorTester().test(c)

