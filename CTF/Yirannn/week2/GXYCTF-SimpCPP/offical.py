from z3 import * 
xor_str="i_will_check_is_debug_or_not" 
s = Solver()
x = BitVec('x',64)
y = BitVec('y',64)
z = BitVec('z',64)
l = BitVec('l',64)
s.add(y==0xd44335b301b2c3e)
s.add((z&(~x))==0x11204161012) 
s.add((z&~y) & x | z & ((x&y) | y & (~x) | ~(y | x))==0x8020717153E3013) 
s.add(((z&(~x)) | (x&y) | (z&(~y)) | (x&(~y))) == 0x3E3A4717373E7F1F) 
s.add((((z&(~x)) | (x&y) | (z&(~y)) | (x&(~y))) ^ l) == 0x3E3A4717050F791F) 
s.add(((z&(~x)) | (x&y) | y & z) == (((~x)& z)|0xC00020130082C0C))
if s.check() ==sat: 
	m = s.model()
	print(m) 
	flag=""
	ls=[] 
	ls.append(hex(int(str(m[x]),10))[2:].rjust(16,"0")) 
	ls.append(hex(int(str(m[y]),10))[2:].rjust(16,"0")) 
	ls.append(hex(int(str(m[z]),10))[2:].rjust(16,"0")) 
	ls.append(hex(int(str(m[l]),10))[2:-2]) 
	print(ls) 
	sum=0 
	for i in ls: 
		for j in range(0,len(i),2): 
			xx=i[j]+i[j+1] 
			flag+=chr(int(xx,16)^ord(xor_str[(sum)%27])) 
			sum+=1
	print(flag)