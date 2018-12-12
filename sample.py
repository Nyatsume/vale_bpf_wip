import os
import time
import argparse
from ctypes import *
from vale_bpf_native import VALE_BPF_NATIVE


class ValStructure(Structure):
    _fields_ = (
            ("rip", c_uint32),
            ("mac", c_uint8 * 6),
            ("port", c_uint8),
            ("_pad", c_uint8 * 5)
    )


MAC_ADDR = c_uint8 * 6
PADDING = c_uint8 * 5


parser = argparse.ArgumentParser(description='vale-bpf-native switch daemon for debugging')
parser.add_argument('--vale_name', required=True, action='store')
args = parser.parse_args()
pwd = os.getcwd()
v = VALE_BPF_NATIVE(src_file="l4lb.c", cflags=["-I%s/../include" % pwd])

m = v.get_table("table")

be1_mac = MAC_ADDR(0x0a, 0x00, 0x00, 0x00, 0x00, 0x0b)
be2_mac = MAC_ADDR(0x0a, 0x00, 0x00, 0x00, 0x00, 0x0c)
be3_mac = MAC_ADDR(0x0a, 0x00, 0x00, 0x00, 0x00, 0x0d)
v_mac = MAC_ADDR(0x0a, 0x00, 0x00, 0x00, 0x00, 0x0a)

dummy = PADDING(0x00, 0x00, 0x00, 0x00, 0x00)

be1_info = ValStructure(0x0b00000a, be1_mac, 1, dummy)
be2_info = ValStructure(0x0c00000a, be2_mac, 2, dummy)
be3_info = ValStructure(0x0d00000a, be3_mac, 3, dummy)
v_info = ValStructure(0x0a00000a, v_mac, 0, dummy)

m[m.Key(0)] = be1_info
m[m.Key(1)] = be2_info
m[m.Key(2)] = be3_info
m[m.Key(3)] = v_info

try:
    v.install_prog(args.vale_name, "lookup")
    print("Printing drops per IP protocol-number, hit CTRL+C to stop")
    v.trace_print()
except IOError as e:
    print e
