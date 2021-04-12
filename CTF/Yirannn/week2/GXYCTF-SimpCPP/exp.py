from z3 import *

v0 = BitVec('v0', 64)
v1 = BitVec('v1', 64)
v2 = BitVec('v2', 64)
v3 = BitVec('v3', 64)

s = Solver()

#直接肉眼递归写表达式就好了
s.add(v2 & (~v0) == 0x11204161012)
s.add(v3 == 0x32310600)
s.add((v2 & (~v0)) | (v1 & v0) | (v2 & ~v1) | (v0 & ~v1) == 0x3E3A4717373E7F1F)
s.add(((v2 & ~v0) | (v1 & v0) | v1 & v2) == (~v0 & v2 | 0xC00020130082C0C))
s.add(v2 & (~v1) & v0 | v2 & (v1 & v0 | v1 & (~v0) | (~(v1 | v0))) == 0x8020717153E3013)


print(s.check())
print(s.model())