import os
import time
import argparse
from ctypes import *
from vale_bpf_native import VALE_BPF_NATIVE


class ValStructure(Structure):
    _fields_ = (
            ("rip", c_uint32),
            ("mac", c_uint8 * 6),
            ("_pad", c_uint8 * 6)
    )


MAC_ADDR = c_uint8 * 6


parser = argparse.ArgumentParser(description='vale-bpf-native switch daemon for debugging')
parser.add_argument('--vale_name', required=True, action='store')
args = parser.parse_args()
pwd = os.getcwd()
v = VALE_BPF_NATIVE(src_file="l4lb.c", cflags=["-I%s/../include" % pwd])

m = v["table"]

test_mac = MAC_ADDR(0xa, 0xb, 0xc, 0xd, 0xe, 0xf)
dummy = MAC_ADDR(0xa, 0xb, 0xc, 0xd, 0xe, 0xf)
test_val = ValStructure(0x0a00000b, test_mac, dummy)
m[0] = test_val

try:
    v.install_prog(args.vale_name, "lookup")
    print("Printing drops per IP protocol-number, hit CTRL+C to stop")
    v.trace_print()
except IOError as e:
    print e
