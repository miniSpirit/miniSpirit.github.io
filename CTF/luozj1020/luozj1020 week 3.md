# week 3

# 2021-4-12

## RSA5

附件给了 e = 65537 和一串的 n 和 c
猜想是广播攻击
但是这个 e..... 是不是有点大？
参考 ctfwiki 的广播攻击
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210412234801450.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
其中有一个条件：n 要互素
我寻思出题人不会蠢到给个漏洞吧
然后忽略了这个条件，直接莽
用 sagemath 封装好的 CRT(中国剩余定理)，算出 $m^{e}$：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210412235137761.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
然后一开根：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210412235205677.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
结果：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210412235221683.png)
我人傻了
开出来不是整数（我囸）
看了别人的解法，才知道其中有两个 n 是不互素的（啊这）
这波是聪明反被聪明误
代码如下：

```python
from Crypto.Util.number import *
import gmpy2

e = 65537
list_n = []
list_c = []
with open('1.txt', 'r') as f:
    l = f.readlines()
for line in l:
    if line[0] == 'n':
        list_n.append(int(line.replace('\n', '').replace(' ', '')[2:]))
    elif line[0] == 'c':
        list_c.append(int(line.replace('\n', '').replace(' ', '')[2:]))
print(list_n)
print(list_c)
for i in range(len(list_n)):
    for j in range(i+1, len(list_n)):
        if gmpy2.gcd(list_n[i], list_n[j]) != 1:
            p = gmpy2.gcd(list_n[i], list_n[j])
            k_p, k_q = i, j
            print(i, j)

n = list_n[k_p]
q = n//p
print(p, q)
c = list_c[k_p]
phi = (p-1)*(q-1)
d = inverse(e, phi)
m = pow(c, d, n)
print(long_to_bytes(m))
```

结果：flag{abdcbe5fd94e23b3de429223ab9c2fdf}

## 传感器

之前吐槽过
见我 [2021-4-1的博客](https://blog.csdn.net/weixin_52446095/article/details/115384023?spm=1001.2014.3001.5501)

# 2021-4-13

## 密码学的心声

题目描述如下：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210413165527635.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
附件内容：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210413160442691.bmp?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70#pic_center)
从歌词可知，这是八进制加密，要用 ascii 码解密
尝试把全部内容八进制转十进制解密：

```python
from Crypto.Util.number import *

c = '111114157166145123145143165162151164171126145162171115165143150'
h = int(c, 8)
print(h)
print(long_to_bytes(h))
```

结果为：b'\x04\x92a\xbc\xece)\x99LgS\x91\xa4\xe8y+\x19NG\x92i\xd4\xc6h'
？？？
参考wp后得知要三个数字一组八进制转十进制解密
代码如下：

```python
c = '111114157166145123145143165162151164171126145162171115165143150'
list_c = []
for i in range(0, len(c), 3):
    list_c.append(chr(int(c[i:i+3], 8)))
m = ''
print('flag{' + m.join(list_c) + '}')
```

结果为：flag{ILoveSecurityVeryMuch}

## rot

附件内容：

```python
破解下面的密文：
83 89 78 84 45 86 96 45 115 121 110 116 136 132 132 132 108 128 117 118 134 110 123 111 110 127 108 112 124 122 108 118 128 108 131 114 127 134 108 116 124 124 113 108 76 76 76 76 138 23 90 81 66 71 64 69 114 65 112 64 66 63 69 61 70 114 62 66 61 62 69 67 70 63 61 110 110 112 64 68 62 70 61 112 111 112
flag格式flag{}
```

看到题目知道是 rot 移位加密
尝试根据 flag 的格式进行移位
代码如下：

```python
c = '83 89 78 84 45 86 96 45 115 121 110 116 136 132 132 132 108 128 117 118 134 110 123 111 110 127 108 112 124 122 108 118 128 108 131 114 127 134 108 116 124 124 113 108 76 76 76 76 138 23 90 81 66 71 64 69 114 65 112 64 66 63 69 61 70 114 62 66 61 62 69 67 70 63 61 110 110 112 64 68 62 70 61 112 111 112'
list_c = c.split(' ')
print(list_c)
k = list_c[0]
list_m = []
for i in range(len(list_c)):
    list_c[i] = chr(int(list_c[i]) + ord('f') - int(k))
    list_m.append(ord(list_c[i]))
print(list_m)
m = ''
print(m.join(list_c))
```

结果为：flag@is@
____*mdUZSX
TSURXPY
QUPQXVYRPSWQYP

flag is '一串乱码' ____ '一串乱码'
盯着这串字符琢磨了半天
最后求助wp，但是只告诉我们会得到一串带 "?" 的 flag，和一串 MD5
具体怎么得到的讲的很含糊
后来受 dl 指点，尝试将前四位向大写的 “FLAG” 移位
代码如下：

```python
c = '83 89 78 84 45 86 96 45 115 121 110 116 136 132 132 132 108 128 117 118 134 110 123 111 110 127 108 112 124 122 108 118 128 108 131 114 127 134 108 116 124 124 113 108 76 76 76 76 138 23 90 81 66 71 64 69 114 65 112 64 66 63 69 61 70 114 62 66 61 62 69 67 70 63 61 110 110 112 64 68 62 70 61 112 111 112'
list_c = c.split(' ')
print(list_c)
k = list_c[0]
list_m = []
for i in range(len(list_c)):
    list_c[i] = chr(int(list_c[i]) + ord('F') - int(k))
    list_m.append(ord(list_c[i]))
print(list_m)
m = ''
print(m.join(list_c))
```

结果为：
FLAG IS flag{www_shiyanbar_com_is_very_good_????}
MD5:38e4c352809e150186920aac37190cbc
（移位的时候中间产生了换行符）
这波啊，这波出题人在第五层
拿 MD5 [在线解密](https://www.cmd5.com/)：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210413171636859.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
啊这（这也在你的计算之中吗？出题人）

容易想到要用哈希碰撞
代码如下：

```python
flag = 'flag{www_shiyanbar_com_is_very_good_????}'
md_5 = '38e4c352809e150186920aac37190cbc'
for i in range(33, 127):
    for j in range(33, 127):
        for s in range(33, 127):
            for t in range(33, 127):
                k = flag.replace('????', chr(i) + chr(j) + chr(s) + chr(t))
                x = hashlib.md5(k.encode()).hexdigest()
                if x == md_5:
                    print(k)
```

根据 ascii 码表减少了循环次数
跑了几分钟结果出来了：flag{www_shiyanbar_com_is_very_good_@8Mu}

# 2021-4-14

## 这是base??

附件内容：

```python
dict:{0: 'J', 1: 'K', 2: 'L', 3: 'M', 4: 'N', 5: 'O', 6: 'x', 7: 'y', 8: 'U', 9: 'V', 10: 'z', 11: 'A', 12: 'B', 13: 'C', 14: 'D', 15: 'E', 16: 'F', 17: 'G', 18: 'H', 19: '7', 20: '8', 21: '9', 22: 'P', 23: 'Q', 24: 'I', 25: 'a', 26: 'b', 27: 'c', 28: 'd', 29: 'e', 30: 'f', 31: 'g', 32: 'h', 33: 'i', 34: 'j', 35: 'k', 36: 'l', 37: 'm', 38: 'W', 39: 'X', 40: 'Y', 41: 'Z', 42: '0', 43: '1', 44: '2', 45: '3', 46: '4', 47: '5', 48: '6', 49: 'R', 50: 'S', 51: 'T', 52: 'n', 53: 'o', 54: 'p', 55: 'q', 56: 'r', 57: 's', 58: 't', 59: 'u', 60: 'v', 61: 'w', 62: '+', 63: '/', 64: '='}
chipertext:
FlZNfnF6Qol6e9w17WwQQoGYBQCgIkGTa9w3IQKw
```

熟悉 base64 加密原理的容易解出这题
这里不再赘述
代码如下：

```python
# dict = 
# chipertext = 
list_d = []
for key,values in  dict.items():
    list_d.append(values)
print(list_d)
flag = ''
for i in range(len(chipertext)//4):
    tmp = ''
    for j in range(4):
        tmp += bin(list_d.index(chipertext[i*4+j])).replace('0b', '').zfill(6)
    print(tmp)
    for k in range(3):
        flag += chr(int(tmp[k*8:k*8+8], 2))
print(flag)
```

得到 flag：BJD{D0_Y0u_kNoW_Th1s_b4se_map}

## Keyboard

看到题目就知道是键盘密码
附件内容：ooo yyy ii w uuu ee uuuu yyy uuuu y w uuu i i rr w i i rr rrr uuuu rrr uuuu t ii uuuu i w u rrr ee www ee yyy eee www w tt ee
键盘密码有两种，一种是电脑键盘，另一种是手机键盘。
每段都是四个及以下字符构成，猜想对应手机键盘上按键对应的第几个字母
再看里面出现的的字母只有 “wertyui” 对应九宫格
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210414222718112.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
代码如下：

```python
m = 'ooo yyy ii w uuu ee uuuu yyy uuuu y w uuu i i rr w i i rr rrr uuuu rrr uuuu t ii uuuu i w u rrr ee www ee yyy eee www w tt ee'
list_m = m.split(' ')
dict_key1 = {'w': 1, 'e': 2, 'r': 3, 't': 4, 'y': 5, 'u': 6, 'i': 7, 'o': 8}
dict_key2 = {2: 'abc', 3: 'def', 4: 'ghi', 5: 'jkl', 6: 'mno', 7: 'pqrs', 8: 'tuv', 9: 'wxyz'}
flag = ''
for s in list_m:
    i = dict_key1[s[0]] + 1
    flag += dict_key2[i][len(s)-1]
print(flag)
```

## 这是什么

题目描述：小明是一个软件专业的高材生，但是老师布置的这次的作业似乎不怎么靠谱，因为他们老师以前是学物理的！喜欢乱七八糟命名文件，还喜欢奇奇怪怪的编码。你快帮小明看一下这题，小明准备好了一箱子辣条。 注意：得到的 flag 请包上 flag{} 提交
附件给了一个 apk 文件
第一反应，把它装到模拟器上
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210414224014231.png)
啊这
然后想通过反编译来得到内容
参考文章：[https://www.zhihu.com/question/29370382](https://www.zhihu.com/question/29370382)
结果 apktool 反编译出来只有这个：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210414224132305.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
和参考文章里所描述的 会反编译成 smali 文件 不符
求助 wp
结果只要把文件后缀改成 .text 就行了
回想题目描述：“喜欢乱七八糟命名文件，还喜欢奇奇怪怪的编码。”
恍然大悟（不过为什么一定是 .text？）
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210414224341382.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
这是 jsfuck 编码（对应题目“这是什么”）
然后拿去[在线解码](http://codertab.com/JsUnFuck)
结果如下：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210414224648589.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)

# 2021-4-15

## childRSA

题目给了 n和c
照例碰运气[爆破 n](http://factordb.com/)：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210415214932298.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
啊这
真让我爆破出来了
然后就是 RSA 常规操作
代码如下：

```python
from Crypto.Util.number import *

# p, q, c, n
e = int('0x10001', 16)
phi = (p-1)*(q-1)
d = inverse(e, phi)
m = pow(c, d, n)
print(long_to_bytes(m))
```

结果为：NCTF{Th3r3_ar3_1ns3cure_RSA_m0duli_7hat_at_f1rst_gl4nce_appe4r_t0_be_s3cur3}

## bbbbbbrsa

附件 python2 加密代码：

```python
from base64 import b64encode as b32encode
from gmpy2 import invert,gcd,iroot
from Crypto.Util.number import *
from binascii import a2b_hex,b2a_hex
import random

flag = "******************************"

nbit = 128

p = getPrime(nbit)
q = getPrime(nbit)
n = p*q

print p
print n

phi = (p-1)*(q-1)

e = random.randint(50000,70000)

while True:
	if gcd(e,phi) == 1:
		break;
	else:
		e -= 1;

c = pow(int(b2a_hex(flag),16),e,n)

print b32encode(str(c))[::-1]

# 2373740699529364991763589324200093466206785561836101840381622237225512234632
```

这个注释就很魔性
一猜就知道是 c
另一个附件内容为：
p = 177077389675257695042507998165006460849
n = 37421829509887796274897162249367329400988647145613325367337968063341372726061
c = ==gMzYDNzIjMxUTNyIzNzIjMyYTM4MDM0gTMwEjNzgTM2UTN4cjNwIjN2QzM5ADMwIDNyMTO4UzM2cTM5kDN2MTOyUTO5YDM0czM3MjM

根据加密代码，c 经过了 base64 加密并且倒序输出了
为了保险起见，还是先解码给出的 c
代码如下：

```python
import base64
import math
from Crypto.Util.number import *

c = '==gMzYDNzIjMxUTNyIzNzIjMyYTM4MDM0gTMwEjNzgTM2UTN4cjNwIjN2QzM5ADMwIDNyMTO4UzM2cTM5kDN2MTOyUTO5YDM0czM3MjM'[::-1]
base64_bytes = c.encode('ascii')
message_bytes = base64.b64decode(base64_bytes)
message = message_bytes.decode('ascii')
print(message)
c = int(message)
```

c = 2373740699529364991763589324200093466206785561836101840381622237225512234632
啊这
跟注释一模一样
解密代码：

```python
p = 177077389675257695042507998165006460849
n = 37421829509887796274897162249367329400988647145613325367337968063341372726061
q = n//p
phi = (p-1)*(q-1)

for e in range(50000, 70000):
    if math.gcd(e, phi) == 1:
        d = inverse(e, phi)
        m = str(long_to_bytes(pow(c, d, n)))
        if '{' in m and '}' in m:
            print(m)
```

结果如下：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210415215614224.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)

# 2021-4-16

## 古典密码知多少

附件如下：
![在这里插入图片描述](https://img-blog.csdnimg.cn/2021041621560778.jpg?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70#pic_center)
其中，蓝色部分为猪圈密码：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210416215729259.png)

橙色部分为圣堂武士密码：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210416215646348.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
黑色部分为[银河密码](https://blog.csdn.net/MikeCoke/article/details/105533829)：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210416215825165.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
解密结果如下：
![在这里插入图片描述](https://img-blog.csdnimg.cn/2021041621584675.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70#pic_center)
下方还有一段话，提示我们要进行栅栏解密，而且结果均为大写字母
代码如下：

```python
s = 'FGCPFLIRTUASYON'
factors = [fac for fac in range(2, len(s)) if len(s)%fac == 0] #取得密文长度的所有因数
for fac in factors:
    flag = ''
    for i in range(fac): #按一定的步长取几组字符，并连接起来，这里组数就等于步长数
        flag += s[i::fac]
    print(str(fac)+'栏：'+flag)
```

参考博客：[https://www.cnblogs.com/lnjoy/p/railfence.html](https://www.cnblogs.com/lnjoy/p/railfence.html)
结果为：FLAGISCRYPTOFUN
最后应该提交 flag{CRYPTOFUN}

## RSA

加密代码如下：

```python
from Crypto.Util.number import getPrime,bytes_to_long

flag=open("flag","rb").read()

p=getPrime(1024)
q=getPrime(1024)
assert(e<100000)
n=p*q
m=bytes_to_long(flag)
c=pow(m,e,n)
print c,n
print pow(294,e,n)

p=getPrime(1024)
n=p*q
m=bytes_to_long("BJD"*32)
c=pow(m,e,n)
print c,n
```

将上半部分的输出记为 n1, c1，pow(294,e,n) 记为 k；将下半部分的输出记为 n2, c2
容易看出 $(n1, n2) = q$ ，据此可以求出 p,q
由于 e<100000 并且知道 pow(294,e,n) 和 pow(bytes_to_long("BJD"*32),e,n2)，所以可以遍历 e 来求出 e
剩下就是 RSA 的常规操作了
解密代码如下：

```python
from Crypto.Util.number import *
import math

c1 = 12641635617803746150332232646354596292707861480200207537199141183624438303757120570096741248020236666965755798009656547738616399025300123043766255518596149348930444599820675230046423373053051631932557230849083426859490183732303751744004874183062594856870318614289991675980063548316499486908923209627563871554875612702079100567018698992935818206109087568166097392314105717555482926141030505639571708876213167112187962584484065321545727594135175369233925922507794999607323536976824183162923385005669930403448853465141405846835919842908469787547341752365471892495204307644586161393228776042015534147913888338316244169120
n1 = 13508774104460209743306714034546704137247627344981133461801953479736017021401725818808462898375994767375627749494839671944543822403059978073813122441407612530658168942987820256786583006947001711749230193542370570950705530167921702835627122401475251039000775017381633900222474727396823708695063136246115652622259769634591309421761269548260984426148824641285010730983215377509255011298737827621611158032976420011662547854515610597955628898073569684158225678333474543920326532893446849808112837476684390030976472053905069855522297850688026960701186543428139843783907624317274796926248829543413464754127208843070331063037
c2 = 979153370552535153498477459720877329811204688208387543826122582132404214848454954722487086658061408795223805022202997613522014736983452121073860054851302343517756732701026667062765906277626879215457936330799698812755973057557620930172778859116538571207100424990838508255127616637334499680058645411786925302368790414768248611809358160197554369255458675450109457987698749584630551177577492043403656419968285163536823819817573531356497236154342689914525321673807925458651854768512396355389740863270148775362744448115581639629326362342160548500035000156097215446881251055505465713854173913142040976382500435185442521721
n2 = 12806210903061368369054309575159360374022344774547459345216907128193957592938071815865954073287532545947370671838372144806539753829484356064919357285623305209600680570975224639214396805124350862772159272362778768036844634760917612708721787320159318432456050806227784435091161119982613987303255995543165395426658059462110056431392517548717447898084915167661172362984251201688639469652283452307712821398857016487590794996544468826705600332208535201443322267298747117528882985955375246424812616478327182399461709978893464093245135530135430007842223389360212803439850867615121148050034887767584693608776323252233254261047
k = 381631268825806469518166370387352035475775677163615730759454343913563615970881967332407709901235637718936184198930226303761876517101208677107311006065728014220477966000620964056616058676999878976943319063836649085085377577273214792371548775204594097887078898598463892440141577974544939268247818937936607013100808169758675042264568547764031628431414727922168580998494695800403043312406643527637667466318473669542326169218665366423043579003388486634167642663495896607282155808331902351188500197960905672207046579647052764579411814305689137519860880916467272056778641442758940135016400808740387144508156358067955215018

m = bytes(("BJD"*32).encode())
for e in range(1, 100000):
    if pow(294, e, n1) == k and pow(bytes_to_long(m), e, n2) == c2:
        break
print(e)

q = math.gcd(n1, n2)
p1 = n1 // q
phi = (p1-1)*(q-1)
d = inverse(e, phi)
m = pow(c1, d, n1)
print(long_to_bytes(m))
```

结果为：BJD{p_is_common_divisor}

# 2021-4-17

## 佛说：只能四天

附件给了一串。。。乱码？
难不成是乱码题？
尊即寂修我劫修如婆愍闍嚤婆莊愍耨羅嚴是喼婆斯吶眾喼修迦慧迦嚩喼斯願嚤摩隸所迦摩吽即塞願修咒莊波斯訶喃壽祗僧若即亦嘇蜜迦須色喼羅囉咒諦若陀喃慧愍夷羅波若劫蜜斯哆咒塞隸蜜波哆咤慧聞亦吽念彌諸嘚嚴諦咒陀叻咤叻諦缽隸祗婆諦嚩阿兜宣囉吽色缽吶諸劫婆咤咤喼愍尊寂色缽嘚闍兜阿婆若叻般壽聞彌即念若降宣空陀壽愍嚤亦喼寂僧迦色莊壽吽哆尊僧喼喃壽嘚兜我空所吶般所即諸吽薩咤諸莊囉隸般咤色空咤亦喃亦色兜哆嘇亦隸空闍修眾哆咒婆菩迦壽薩塞宣嚩缽寂夷摩所修囉菩阿伏嘚宣嚩薩塞菩波吶波菩哆若慧愍蜜訶壽色咒兜摩缽摩諦劫諸陀即壽所波咤聞如訶摩壽宣咤彌即嚩蜜叻劫嘇缽所摩闍壽波壽劫修訶如嚩嘇囉薩色嚤薩壽修闍夷闍是壽僧劫祗蜜嚴嚩我若空伏諦念降若心吽咤隸嘚耨缽伏吽色寂喃喼吽壽夷若心眾祗喃慧嚴即聞空僧須夷嚴叻心願哆波隸塞吶心須嘇摩咤壽嘚吶夷亦心亦喃若咒壽亦壽囑囑
一脸懵逼
只能找 [wp](https://blog.csdn.net/weixin_45883223/article/details/105193948)
题目有一条提示：圣经分为《旧约全书》和《新约全书》
原来是叫[新约佛论禅加密](http://hi.pcmoe.net/buddha.html)：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210417222025611.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
解密结果是一串社会主义核心价值观
又懵逼了。。。
原来是叫[核心价值观编码](http://ctf.ssleye.com/cvencode.html)。。。
解密结果：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210417222137380.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
解码结果结尾是 “doyouknowfence”
还要[栅栏解密](https://www.qqxiuzi.cn/bianma/zhalanmima.php)。。。
解密结果：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210417222335279.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
结尾出现了 “doyouknowCaesar”
结合提示：凯撒不是最后一步，by the way，凯撒为什么叫做凯撒？
还要[凯撒解密](https://www.qqxiuzi.cn/bianma/kaisamima.php)。。。
而凯撒密码最初位移是 3 位。。。（凯撒为什么叫做凯撒）
解密结果：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210417222554786.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
最后得到的结果还要 [base32 解码](https://www.qqxiuzi.cn/bianma/base.php)。。。
结果如下：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210417222706775.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
老千层饼了。。。
如果不是有 wp，我想破脑袋也不可能想出来。。。

## 天干地支+甲子

不禁想起了那题 [传统知识+古典密码](https://blog.csdn.net/weixin_52446095/article/details/115384023?spm=1001.2014.3001)
不过这题简单得多，只要找到对应的数字再 +60 用 ascii 码 转成字符就行

得到得字符串用MRCTF{}包裹
一天Eki收到了一封来自Sndav的信，但是他有点迷希望您来解决一下
甲戌  11
甲寅  51
甲寅  51
癸卯  40
己酉  46
甲寅  51
辛丑  38

```python
a = [11, 51, 51, 40, 46, 51, 38]

print(''.join(chr(i + 60) for i in a))
```

结果为：Goodjob

# 2021-4-18

## vigenere

看题目就知道是**维吉尼亚密码**
虽然清楚加密原理，但是懒得思考了
找到的解密网站都要提供 key
参考 [wp](https://blog.csdn.net/ao52426055/article/details/109304646)
直接[爆破](https://www.guballa.de/vigenere-solver)
![在这里插入图片描述](https://img-blog.csdnimg.cn/202104182239180.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
结果如下：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210418223942776.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
用下划线连接单词即为 flag

## rsa_output

看到附件内容，感觉在哪见过

```python
{21058339337354287847534107544613605305015441090508924094198816691219103399526800112802416383088995253908857460266726925615826895303377801614829364034624475195859997943146305588315939130777450485196290766249612340054354622516207681542973756257677388091926549655162490873849955783768663029138647079874278240867932127196686258800146911620730706734103611833179733264096475286491988063990431085380499075005629807702406676707841324660971173253100956362528346684752959937473852630145893796056675793646430793578265418255919376323796044588559726703858429311784705245069845938316802681575653653770883615525735690306674635167111,2767}

{21058339337354287847534107544613605305015441090508924094198816691219103399526800112802416383088995253908857460266726925615826895303377801614829364034624475195859997943146305588315939130777450485196290766249612340054354622516207681542973756257677388091926549655162490873849955783768663029138647079874278240867932127196686258800146911620730706734103611833179733264096475286491988063990431085380499075005629807702406676707841324660971173253100956362528346684752959937473852630145893796056675793646430793578265418255919376323796044588559726703858429311784705245069845938316802681575653653770883615525735690306674635167111,3659}

message1=20152490165522401747723193966902181151098731763998057421967155300933719378216342043730801302534978403741086887969040721959533190058342762057359432663717825826365444996915469039056428416166173920958243044831404924113442512617599426876141184212121677500371236937127571802891321706587610393639446868836987170301813018218408886968263882123084155607494076330256934285171370758586535415136162861138898728910585138378884530819857478609791126971308624318454905992919405355751492789110009313138417265126117273710813843923143381276204802515910527468883224274829962479636527422350190210717694762908096944600267033351813929448599

message2=11298697323140988812057735324285908480504721454145796535014418738959035245600679947297874517818928181509081545027056523790022598233918011261011973196386395689371526774785582326121959186195586069851592467637819366624044133661016373360885158956955263645614345881350494012328275215821306955212788282617812686548883151066866149060363482958708364726982908798340182288702101023393839781427386537230459436512613047311585875068008210818996941460156589314135010438362447522428206884944952639826677247819066812706835773107059567082822312300721049827013660418610265189288840247186598145741724084351633508492707755206886202876227
```

打开 CTFwiki 找
发现是共模攻击
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210418224627991.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
附件格式和下面给的例子完全一样（啊这）
只要复制粘贴然后修改一下就行
代码如下：

```python
import gmpy2
from Crypto.Util.number import *
n = 21058339337354287847534107544613605305015441090508924094198816691219103399526800112802416383088995253908857460266726925615826895303377801614829364034624475195859997943146305588315939130777450485196290766249612340054354622516207681542973756257677388091926549655162490873849955783768663029138647079874278240867932127196686258800146911620730706734103611833179733264096475286491988063990431085380499075005629807702406676707841324660971173253100956362528346684752959937473852630145893796056675793646430793578265418255919376323796044588559726703858429311784705245069845938316802681575653653770883615525735690306674635167111
e1 = 2767
e2 = 3659
message1=20152490165522401747723193966902181151098731763998057421967155300933719378216342043730801302534978403741086887969040721959533190058342762057359432663717825826365444996915469039056428416166173920958243044831404924113442512617599426876141184212121677500371236937127571802891321706587610393639446868836987170301813018218408886968263882123084155607494076330256934285171370758586535415136162861138898728910585138378884530819857478609791126971308624318454905992919405355751492789110009313138417265126117273710813843923143381276204802515910527468883224274829962479636527422350190210717694762908096944600267033351813929448599
message2=11298697323140988812057735324285908480504721454145796535014418738959035245600679947297874517818928181509081545027056523790022598233918011261011973196386395689371526774785582326121959186195586069851592467637819366624044133661016373360885158956955263645614345881350494012328275215821306955212788282617812686548883151066866149060363482958708364726982908798340182288702101023393839781427386537230459436512613047311585875068008210818996941460156589314135010438362447522428206884944952639826677247819066812706835773107059567082822312300721049827013660418610265189288840247186598145741724084351633508492707755206886202876227
# s & t
gcd, s, t = gmpy2.gcdext(e1, e2)
if s < 0:
    s = -s
    message1 = gmpy2.invert(message1, n)
if t < 0:
    t = -t
    message2 = gmpy2.invert(message2, n)
plain = gmpy2.powmod(message1, s, n) * gmpy2.powmod(message2, t, n) % n
print(long_to_bytes(plain))
```

结果为：BJD{r3a_C0mmoN_moD@_4ttack}

## keyboard

又是 keyboard。。。
键盘密码附件内容：

```python
得到的flag用
MRCTF{xxxxxx}形式上叫
都为小写字母

6
666
22
444
555
33
7
44
666
66
3
```

很明显是手机键盘加密
数字对应按键，长度对应第几个字母
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210418225113384.png)
结果为：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210418225431395.png)
但不知道为什么正确的 flag 是 “mobiephone”（因为单词拼错了？）。。。