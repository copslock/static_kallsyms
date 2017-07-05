#!/usr/bin/env python
#coding=utf-8
import sys
import os
import struct


def kernel_version(k):
    kernel = 'Unknow'
    f = os.popen('strings %s' % k, 'r')
    lines = f.readlines()
    f.close()
    for l in lines:
        if l.startswith('Linux') > 0 and l.find('GCC') > 0:
            kernel = l
    return kernel.replace('\n', '') 

boot = sys.argv[1]

f = open(boot, "rb")

content = f.read()

f.close()

boot_img_hdr_format = 'IIIIIIII'

BOOT_MAGIC_SIZE = 8

kernel_magic = content[0 : BOOT_MAGIC_SIZE]

print 'boot maigc [%s]' % kernel_magic

kernel_size, kernel_addr, ramdisk_size, ramdisk_addr, second_size, second_addr, tags_addr, page_size =  struct.unpack_from(boot_img_hdr_format, content[BOOT_MAGIC_SIZE : BOOT_MAGIC_SIZE + (4 * 8)])

print "内核: %d 字节, 页面 : %d , 内核起始地址: %x" % (kernel_size, page_size, kernel_addr)

kernel_pages = (kernel_size + page_size - 1) / page_size

kernel = content[page_size : (page_size + kernel_size)]

boot_kernel = 'boot_kernel'

print('BOOT解压内核原始文件 %s' % boot_kernel)

f = open(boot_kernel, "wb")

f.write(kernel)

f.close()

f = os.popen('file %s' % boot_kernel, 'r')

r = f.read()

f.close()

last = boot_kernel

if r.find('gzip compressed data, from Unix') > 0:
    gz = boot_kernel + '.gz'
    os.rename(boot_kernel, gz)
    unzip = 'gunzip %s' % gz 
    os.system(unzip)

print '内核文件解压完毕 %s' % last 

print '内核版本 [%s]' % kernel_version(last)

"""
#define BOOT_MAGIC "ANDROID!"
#define BOOT_MAGIC_SIZE 8
#define BOOT_NAME_SIZE 16
#define BOOT_ARGS_SIZE 512
#define BOOT_EXTRA_ARGS_SIZE 1024

    struct boot_img_hdr
{
    unsigned char magic[BOOT_MAGIC_SIZE];

    unsigned kernel_size;  /* size in bytes */
    unsigned kernel_addr;  /* physical load addr */

    unsigned ramdisk_size; /* size in bytes */
    unsigned ramdisk_addr; /* physical load addr */

    unsigned second_size;  /* size in bytes */
    unsigned second_addr;  /* physical load addr */

    unsigned tags_addr;    /* physical addr for kernel tags */
    unsigned page_size;    /* flash page size we assume */
    unsigned unused[2];    /* future expansion: should be 0 */

    unsigned char name[BOOT_NAME_SIZE]; /* asciiz product name */

    unsigned char cmdline[BOOT_ARGS_SIZE];

    unsigned id[8]; /* timestamp / checksum / sha1 / etc */

    /* Supplemental command line data; kept here to maintain
     * binary compatibility with older versions of mkbootimg */
    unsigned char extra_cmdline[BOOT_EXTRA_ARGS_SIZE];
};
"""
