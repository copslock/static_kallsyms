#!/usr/bin/env python

# Capstone Python bindings, by Nguyen Anh Quynnh <aquynh@gmail.com>

from __future__ import print_function
from capstone import *
from capstone.arm64 import *
import sys



ARM64_CODE = b"\x09\x00\x38\xd5\xbf\x40\x00\xd5\x0c\x05\x13\xd5\x20\x50\x02\x0e\x20\xe4\x3d\x0f\x00\x18\xa0\x5f\xa2\x00\xae\x9e\x9f\x37\x03\xd5\xbf\x33\x03\xd5\xdf\x3f\x03\xd5\x21\x7c\x02\x9b\x21\x7c\x00\x53\x00\x40\x21\x4b\xe1\x0b\x40\xb9\x20\x04\x81\xda\x20\x08\x02\x8b\x10\x5b\xe8\x3c"
FILE_read = None

def print_bytes(insn):
    return ''.join("%02x %02x %02x %02x" % (insn.bytes[0], insn.bytes[1], insn.bytes[2], insn.bytes[3]))

# ## Test class Cs
def test_class():
    f = open(FILE_read, "rb")
    CODE = f.read()

    print("*" * 32)
    print("Platform: %s" % "ARM-64")
    print("Code size: %d" % len(CODE))
    print("Disasm:")

    try:
        md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        #md.detail = True
        md.detail = False
        for insn in md.disasm(CODE, 0x00):
            #print_insn_detail(insn)
            print("0x%x:\t%s\t%s\t%s" % (insn.address, print_bytes(insn), insn.mnemonic, insn.op_str))
            #print ()
        #print("0x%x:\n" % (insn.address + insn.size))
    except CsError as e:
        print("ERROR: %s" % e)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("%s <file>" % sys.argv[0])
        sys.exit(-1)
    else:
        FILE_read = sys.argv[1]
    test_class()
