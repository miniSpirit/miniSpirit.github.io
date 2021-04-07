#-*- coding:utf-8 -*-

enc = "********CENSORED********"
m = [0x410A4335494A0942, 0x0B0EF2F50BE619F0, 0x4F0A3A064A35282B]

import binascii

flag = b''
for i in range(3):
    p = enc[i*8:(i+1)*8]
    a = binascii.b2a_hex(p.encode('ascii')[::-1])
    b = binascii.a2b_hex(hex(int(a,16) + m[i])[2:])[::-1]
    flag += b
print (flag)