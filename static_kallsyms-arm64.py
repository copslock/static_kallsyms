#!/usr/bin/python

import sys
import struct

#The default address at which the kernel text segment is loaded
DEFAULT_KERNEL_TEXT_START = 0xffffffc000080000

# kernel address start
KERNEL_START = 0xffffffc000000000

#The size of the DWORD in a 64-bit architecture
DWORD_SIZE = struct.calcsize("Q")

#The size of the WORD in a 64-bit architecture
WORD_SIZE = struct.calcsize("H")

#The alignment of labels in the resulting kernel file
LABEL_ALIGN = 8

#The minimal number of repeating addresses pointing to the kernel's text start address
#which are used as a heuristic in order to find the beginning of the kernel's symbol
#table. Since usually there are at least two symbols pointing to the beginning of the
#text segment ("stext", "_text"), the minimal number for the heuristic is 2.
KALLSYMS_ADDRESSES_MIN_HEURISTIC = 2

def read_dword(kernel_data, offset):
	'''
	Reads a DWORD from the given offset within the kernel data
	'''
	return struct.unpack("<Q", kernel_data[offset : offset + DWORD_SIZE])[0]

def read_word(kernel_data, offset):
	'''
	Reads a WORD from the given offset within the kernel data
	'''
	return struct.unpack("<H", kernel_data[offset : offset + WORD_SIZE])[0]

def read_byte(kernel_data, offset):
	'''
	Reads an unsigned byte from the given offset within the kernel data
	'''
	return struct.unpack("<B", kernel_data[offset : offset + 1])[0]

def read_c_string(kernel_data, offset):
	'''
	Reads a NUL-delimited C-string from the given offset
	'''
	current_offset = offset
	result_str = ""
	while kernel_data[current_offset] != '\x00':
		result_str += kernel_data[current_offset]
		current_offset += 1
	return result_str

def label_align(address):
	'''
	Aligns the given value to the closest label output boundry
	'''
	return ((address + LABEL_ALIGN - 1) / LABEL_ALIGN) * LABEL_ALIGN

def find_kallsyms_addresses(kernel_data, kernel_text_start):
	'''
	Searching for the beginning of the kernel's symbol table
	Returns the offset of the kernel's symbol table, or -1 if the symbol table could not be found
	'''
        '''
        search_str = struct.pack("<4Q", DEFAULT_KERNEL_TEXT_START, DEFAULT_KERNEL_TEXT_START + 0x40
                                 , DEFAULT_KERNEL_TEXT_START + 0x80, DEFAULT_KERNEL_TEXT_START + 0x80 )
        offset =  kernel_data.find(search_str)
        '''
        # based on symbol number count

        count = 0
        offset = 0
        offset2 = 0
        find = False

        while offset < len(kernel_data):
            value = read_dword(kernel_data, offset)

            offset2 = offset
            while value >= KERNEL_START:
                count += 1
                offset2 += DWORD_SIZE
                value = read_dword(kernel_data, offset2)

                if count > 20000:
                    find = True
                    break

            if find:
                break
            else:
                count = 0
                offset = offset2 + DWORD_SIZE

        return offset

def get_kernel_symbol_table(kernel_data, kernel_text_start):
        '''
	Retrieves the kernel's symbol table from the given kernel file
	'''

        #Getting the beginning and end of the kallsyms_addresses table
        kallsyms_addresses_off = find_kallsyms_addresses(kernel_data, kernel_text_start)
        print "kernel symbol table offset: %d" % kallsyms_addresses_off
        if kallsyms_addresses_off == -1:
            return None

	kallsyms_addresses_end_off = kernel_data.find(struct.pack("<Q", 0), kallsyms_addresses_off)
        #print "kallsyms_address_end_off = %d" % kallsyms_addresses_end_off
	num_symbols = (kallsyms_addresses_end_off - kallsyms_addresses_off) / DWORD_SIZE
        print "symbol number: %d" % num_symbols

	#Making sure that kallsyms_num_syms matches the table size
	kallsyms_num_syms_off = kallsyms_addresses_end_off
        #print "kallsyms_num_syms_off = %d" % kallsyms_num_syms_off

        # skip 0UL
        kallsyms_num_syms = read_dword(kernel_data, kallsyms_num_syms_off)
        while kallsyms_num_syms == 0:
            kallsyms_num_syms_off += DWORD_SIZE
            kallsyms_num_syms = read_dword(kernel_data, kallsyms_num_syms_off)
            #print "kallsyms_num_syms = %d" % kallsyms_num_syms

	if kallsyms_num_syms != num_symbols:
		print "[-] Actual symbol table size: %d, read symbol table size: %d" % (num_symbols, kallsyms_num_syms)
		return None

	#Calculating the location of the markers table
	kallsyms_names_off = kallsyms_num_syms_off + DWORD_SIZE

        # skip 0UL
        value = read_dword(kernel_data, kallsyms_names_off)
        while value == 0:
            kallsyms_names_off += DWORD_SIZE
            value = read_dword(kernel_data, kallsyms_names_off)
            #print "value1 = %d" % value

	current_offset = kallsyms_names_off
	for i in range(0, num_symbols):
		current_offset += read_byte(kernel_data, current_offset) + 1

	kallsyms_markers_off = label_align(current_offset)

        # skip 0UL
        value = read_dword(kernel_data, kallsyms_markers_off)
        while value == 0:
            kallsyms_markers_off += DWORD_SIZE
            value = read_dword(kernel_data, kallsyms_markers_off)
            #print "value2 = %d" % value

        # start with 0x0
        kallsyms_markers_off -= DWORD_SIZE

        mark_num = (num_symbols / 256 + 1) if num_symbols % 256 != 0  else num_symbols / 256
	kallsyms_token_table_off = kallsyms_markers_off + mark_num * DWORD_SIZE

        # skip 0UL
        value = read_dword(kernel_data, kallsyms_token_table_off)
        while value == 0:
            kallsyms_token_table_off += DWORD_SIZE
            value = read_dword(kernel_data, kallsyms_token_table_off)
            #print "value3 = %d" % value

	#Reading the token table
	current_offset = kallsyms_token_table_off
	for i in range(0, 256):
		token_str = read_c_string(kernel_data, current_offset)
                #print "str = %s" % token_str
		current_offset += len(token_str) + 1

	kallsyms_token_index_off = label_align(current_offset)

        #print "index_off = %x" % kallsyms_token_index_off

        # skip 0x00
        value = read_word(kernel_data, kallsyms_token_index_off)
        while value == 0:
            kallsyms_token_index_off += WORD_SIZE
            value = read_word(kernel_data, kallsyms_token_index_off)
            #print "value4 = %d" %value

        # start with 0x00
        kallsyms_token_index_off -= WORD_SIZE

	#Creating the token table
	token_table = []
	for i in range(0, 256):
		index = read_word(kernel_data, kallsyms_token_index_off + i * WORD_SIZE)
		token_table.append(read_c_string(kernel_data, kallsyms_token_table_off + index))

	#Decompressing the symbol table using the token table
	offset = kallsyms_names_off
	symbol_table = []
	for i in range(0, num_symbols):
		num_tokens = read_byte(kernel_data, offset)
		offset += 1
		symbol_name = ""
		for j in range(num_tokens, 0, -1):
			token_table_idx = read_byte(kernel_data, offset)
			symbol_name += token_table[token_table_idx]
			offset += 1

		symbol_address = read_dword(kernel_data, kallsyms_addresses_off + i * DWORD_SIZE)
		symbol_table.append((symbol_address, symbol_name[0], symbol_name[1:]))

	return symbol_table

def main():

	#Verifying the arguments
	if len(sys.argv) < 2:
		print "USAGE: %s: <KERNEL_FILE> [optional: <0xKERNEL_TEXT_START>]" % sys.argv[0]
		return
	kernel_data = open(sys.argv[1], "rb").read()
	kernel_text_start = int(sys.argv[2], 16) if len(sys.argv) == 3 else DEFAULT_KERNEL_TEXT_START

	#Getting the kernel symbol table
	symbol_table = get_kernel_symbol_table(kernel_data, kernel_text_start)
        if symbol_table != None:
            print "write kallsyms.out ..."
            f = open("kallsyms.out", "w");
	    for symbol in symbol_table:
                f.write("%08x %s %s\n" % symbol)
	        #print "%08X %s %s" % symbol
            f.close()
            print "Done!"
        else:
            print "can not find symbol table, quit!"


if __name__ == "__main__":
	main()
