#!/usr/bin/env python
import sys
import os
import struct

from capstone import *
from capstone.arm64 import *
import binascii

DEFAULT_KERNEL_TEXT_START = 0xffffffc000080000 

KERNEL_START = 0xffffffc000000000

DWORD_SIZE = struct.calcsize("Q")

WORD_SIZE = struct.calcsize("H")

LABEL_ALIGN = 8

def read_dword(data, offset):
    return struct.unpack("<Q", data[offset : offset + DWORD_SIZE])[0]

def read_word(data, offset):
    return struct.unpack("<H", data[offset : offset + WORD_SIZE])[0] 

def read_byte(data, offset):
    return struct.unpack("<B", data[offset : offset + 1])[0] 

def read_c_string(data, offset):
    current_offset = offset
    result_str = ""
    while data[current_offset] != '\x00':
        result_str += data[current_offset]
        current_offset += 1
    return result_str

def label_align(address):
    return ((address + LABEL_ALIGN - 1) / LABEL_ALIGN) * LABEL_ALIGN

def find_kallsyms_address(kernel_data, kernel_text_start):
    count = 0
    offset = 0
    kernel_size = len(kernel_data)
    start = 0
    while offset < kernel_size:
        value = read_dword(kernel_data, offset)
        if value >= KERNEL_START:
            count += 1
        else:
            count = 0
            start = offset + DWORD_SIZE
        if count > 20000:
            break
        offset = offset + DWORD_SIZE
    return start 
def kernel_symbol_table(kernel_data, kernel_text_start):
    kallsyms_address_table_start = find_kallsyms_address(kernel_data, kernel_text_start)
    if kallsyms_address_table_start == 0:
        return None 
    print 'kernel address table offset:%d' % kallsyms_address_table_start
    kallsyms_address_table_end = kernel_data.find(struct.pack("<Q", 0), kallsyms_address_table_start)
    calc_symbols_number = (kallsyms_address_table_end - kallsyms_address_table_start) / DWORD_SIZE
    kallsyms_num_syms_offset = kallsyms_address_table_end

    kallsyms_num_syms = read_dword(kernel_data, kallsyms_num_syms_offset)
    
    while kallsyms_num_syms == 0:
        kallsyms_num_syms_offset += DWORD_SIZE
        kallsyms_num_syms = read_dword(kernel_data, kallsyms_num_syms_offset)

    if kallsyms_num_syms != calc_symbols_number:
        print("Actual symbol table size: %d, read symbol table size %d" % (calc_symbols_number, kallsyms_num_syms))
        return None
    print 'kernel symbols number %d' % kallsyms_num_syms

    kallsyms_names_offset = kallsyms_num_syms_offset + DWORD_SIZE

    value = read_dword(kernel_data, kallsyms_names_offset)
    while value == 0:
        kallsyms_names_offset += DWORD_SIZE
        value = read_dword(kernel_data, kallsyms_names_offset)

    current_offset = kallsyms_names_offset

    for i in range(0, kallsyms_num_syms):
        current_offset += read_byte(kernel_data, current_offset) + 1
    kallsyms_markers_offset = label_align(current_offset)

    value = read_dword(kernel_data, kallsyms_markers_offset)
    while value == 0:
        kallsyms_markers_offset += DWORD_SIZE
        value = read_dword(kernel_data, kallsyms_markers_offset) 
    kallsyms_markers_offset -= DWORD_SIZE

    markers_number = (kallsyms_num_syms / 256 + 1) if kallsyms_num_syms % 256 != 0 else kallsyms_num_syms

    kallsyms_token_table_offset = kallsyms_markers_offset + markers_number * DWORD_SIZE
    value = read_dword(kernel_data, kallsyms_token_table_offset)
    while value == 0:
        kallsyms_token_table_offset += DWORD_SIZE
        value = read_dword(kernel_data, kallsyms_token_table_offset)

    current_offset = kallsyms_token_table_offset
    for i in range(0, 256):
        token_str = read_c_string(kernel_data, current_offset)
        current_offset += len(token_str) + 1
    
    kallsyms_token_index_offset = label_align(current_offset)

    value = read_word(kernel_data, kallsyms_token_index_offset)
    while value == 0:
        kallsyms_token_index_offset += WORD_SIZE
        value = read_word(kernel_data, kallsyms_token_index_offset)
    kallsyms_token_index_offset -= WORD_SIZE
    
    token_table = []

    for i in range(0, 256):
        index = read_word(kernel_data, kallsyms_token_index_offset + i * WORD_SIZE)
        token_table.append(read_c_string(kernel_data, kallsyms_token_table_offset + index))
    offset = kallsyms_names_offset
    symbols_table = []
    for i in range(0, kallsyms_num_syms):
        num_tokens = read_byte(kernel_data, offset)
        offset += 1
        symbol_name = ""
        for j in range(num_tokens, 0, -1):
            token_table_index = read_byte(kernel_data, offset)
            symbol_name += token_table[token_table_index]
            offset += 1

        symbol_address = read_dword(kernel_data, kallsyms_address_table_start + i * DWORD_SIZE)
        symbols_table.append((symbol_address, symbol_name[0], symbol_name[1:]))
    return symbols_table

def kernel_kallsyms(kernel, start_address):
    kallsyms_list = kernel_symbol_table(kernel, start_address)
    dict_kallsyms = {}
    f = open('kallsyms.out','w')
    for i in kallsyms_list:
        f.write("%08x %s %s\n" % i)
        address = i[0]
        name = i[2]
        dict_kallsyms[address] = name
    f.close()
    return dict_kallsyms

def disassem_kernel(binary, address, address_of_name):
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = False
    md.skipdata = True

    for insn in md.disasm(binary, address):
        bytes = binascii.hexlify(insn.bytes) 
        if address_of_name.has_key(insn.address):
            print '%16x <%s>:' % (insn.address, address_of_name[insn.address])
        function_name = ''
        if insn.id == 16 or insn.id == 21:
            offset = insn.op_str.find('#') + 1
            address = int(insn.op_str[offset:], 16)
            if address_of_name.has_key(address):
                function_name = '<%s>' % address_of_name[address]
        print("%016x\t%s\t%s\t%s\t%s" % (insn.address, bytes, insn.mnemonic, insn.op_str, function_name))

if __name__ == '__main__':

    start_address = 0x00

    if len(sys.argv) < 2:
        print 'Usge: diskernel kernel <start_address>'
        exit(-1)

    if len(sys.argv) == 3:
        start_address = int(sys.argv[2], 16) 
    
    path = sys.argv[1]

    if start_address == 0:
        print 'start address default'
    
    start_address = 0xffffffc000080000

    print('kernel to asm @%16x' % start_address)

    bin = open(path, 'rb')

    code = bin.read()
    
    address_to_name = kernel_kallsyms(code, start_address)

    disassem_kernel(code, start_address, address_to_name)

    bin.close()
