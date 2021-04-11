# week 2

# 2021-4-5

## RSA2

dp(dq) 泄露的题没做过，不过跟 dp, dq 泄露相比容易许多
首先，根据
$${
dp \equiv d\space mod \space (p-1)
}$$联想到
$${
\varphi = (p-1) * (q-1)
}$$
那肯定就有人问了，你在 dp,dq 泄露中字母就没联想到 φ 呢？
对比 dp,dq 泄露和 dp(dq) 泄露的已知条件：前者已知 $p, q, (n), (φ), dp, dq, c$ ；而后者已知 $e, n, dp(dq), c$
我们的目的是解出私钥 $d$ ，或者 直接解出 $c^{d}$ ，通过 $m \equiv c^{d} \space mod \space n$ 来解出密文 $m$
而 RSA 加密算法中有很重要的一步
$${
e * d \equiv 1 \space mod \space \varphi
}$$dp(dq) 泄露问题中已知 $e$ ，所以可以根据此式解出私钥 $d$
而 dp,dq 泄露问题中 $e$ 未知，于是采取解出 $c^{d}$ 整体的策略

回到 dp,dq 泄露问题
因为
$$
dp \equiv d\space mod \space (p-1)
$$
所以 $\exists\space k_{1} \in\mathbb{Z}, \space s.t.$ 
$$
dp = d + k_{1} * (p-1)
$$
等式两边同时乘 $e$ 得
$$
e * dp = e * d + k_{1} * e * (p-1) \qquad \qquad (*)
$$

因为
$$
e * d \equiv 1 \space mod \space \varphi
$$
所以 $\exists\space k_{2} \in\mathbb{Z}, \space s.t.$ 
$$
e * d = 1 + k_{2} * \varphi = 1 + k_{2} * (p-1) * (q-1)
$$
将此式中的 $e * d$ 代入 $*$ 式，得
$$
e * dp = 1+k * (p-1)，
其中 k = (p-1) * (k_{1} * e + k_{2} * (q - 1)) \space \in\mathbb{Z}​
$$


由 $dp \equiv d\space mod \space (p-1)$ 可知， 
$$
dp < (p-1) < p
$$
故
$${
e > k
}$$所以，只要我们使 $k$ 遍历 $e$ 的取值就能求出 $p$ ，进而求出 $\varphi$ ，再对 $e$ 求关于 $\varphi$ 的逆元，就能求出私钥 $d$ 进行解密
实现代码如下：

```python
from Crypto.Util.number import *

e = 65537
n = 248254007851526241177721526698901802985832766176221609612258877371620580060433101538328030305219918697643619814200930679612109885533801335348445023751670478437073055544724280684733298051599167660303645183146161497485358633681492129668802402065797789905550489547645118787266601929429724133167768465309665906113
dp = 905074498052346904643025132879518330691925174573054004621877253318682675055421970943552016695528560364834446303196939207056642927148093290374440210503657
c = 140423670976252696807533673586209400575664282100684119784203527124521188996403826597436883766041879067494280957410201958935737360380801845453829293997433414188838725751796261702622028587211560353362847191060306578510511380965162133472698713063592621028959167072781482562673683090590521214218071160287665180751

for k in range(1, e):
    p = (e*dp-1) // k +1
    q = n // p
    if (n - p*q) == 0:
        break
print(p, q)
phi = (p-1) * (q-1)
d = inverse(e, phi)
print(d)
m = pow(c, d, n)
print(long_to_bytes(m))
```

得到 flag{wow_leaking_dp_breaks_rsa?_98924743502}

## RSA

打开 pub.key 文件，看到前缀后缀就知道是 SSL 证书格式
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210405195822130.png)
用解密网站：[http://ctf.ssleye.com/pub_asys.html](http://ctf.ssleye.com/pub_asys.html)![在这里插入图片描述](https://img-blog.csdnimg.cn/20210405202125892.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
得到 n 和 e
尝试用 [http://factordb.com/](http://factordb.com/) 网站爆破：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210405202415250.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
没有结果
emmm......
再用 sagemath 爆破：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210405195643588.png)
花了一点时间
这样，我们得出了 p, q, n, e，然后就可以开始解密。。。
嗯？？？
密文呢？
解压之后的文件里面还有一个 flag.enc 文件，密文应该就在里面
但是打开文件
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210405204049918.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210405204107961.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
一堆乱码是什么鬼？
用 python 读取文件：

```python
with open(r"D:\BUUCTF\Crypto\RSA(1)\0eaf8d6c-3fe5-4549-9e81-94ac42535e7b\flag.enc", "rb") as f:
    f = f.read()
print(f)
```

得到一串 bytes ：b'A\x96\xc0YJ^\x00\n\x96\xb8x\xb6|\xd7$y[\x13\xa8\xf2\xcaT\xda\x06\xd0\xf1\x9c(\xbeh\x9bb'
bytes_to_long 之后应该就是密文了
解密代码如下：

```python
from Crypto.Util.number import *

n = 86934482296048119190666062003494800588905656017203025617216654058378322103517
e = 65537
p = 285960468890451637935629440372639283459
q = 304008741604601924494328155975272418463

phi = (p-1) * (q-1)
d = inverse(e, phi)
print(d)

with open(r"D:\BUUCTF\Crypto\RSA(1)\0eaf8d6c-3fe5-4549-9e81-94ac42535e7b\flag.enc", "rb") as f:
    f = f.read()
print(f)
c = bytes_to_long(f)
print(c)

m = pow(c, d, n)
print(long_to_bytes(m))
```

这是我参考了大佬的建议自己写的版本
结果如下：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210405204527775.png)
高亮处即为 flag ，但是有一堆 padding

然后是另一个参考了 wp 的版本：

```python
from Crypto.Util.number import *
import rsa

n = 86934482296048119190666062003494800588905656017203025617216654058378322103517
e = 65537
p = 285960468890451637935629440372639283459
q = 304008741604601924494328155975272418463

phi = (p-1) * (q-1)
d = inverse(e, phi)
print(d)
key = rsa.PrivateKey(n, e, int(d), p, q)

with open(r"D:\BUUCTF\Crypto\RSA(1)\0eaf8d6c-3fe5-4549-9e81-94ac42535e7b\flag.enc", "rb") as f:
    f = f.read()
    print(rsa.decrypt(f, key))
```

结果如下：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210405204703573.png)
属实恶心人

# 2021-4-6

## 异性相吸

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210406164650644.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
??? 兄弟，你的思想很危险(滑稽)
解压后有两个文件 key.txt 和 密文.txt
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210406164744313.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210406164759249.png)
不知所云
但是根据题目推断，大概要对两条字符串之间进行操作
“异性相吸” 大概指要对两个字符串之间进行异或操作
代码如下：

```python
key = 'asadsasdasdasdasdasdasdasdasdasdqwesqf'
with open(r'D:\BUUCTF\Crypto\异性相吸\b8c1caee-43d6-42ee-aecc-d72502a5ade2\密文.txt', 'r') as f:
    m = f.read()

c = ''
for i in range(len(key)):
    c += chr(ord(m[i]) ^ ord(key[i]))
print(c)
```

得到 flag{ea1bc0988992276b7f95b54a7435e89e}

## 还原大师

![在这里插入图片描述](https://img-blog.csdnimg.cn/2021040616532680.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
题目中三处未知处均为大写字母，而且已知 MD5 加密后的部分密文
根据哈希函数的基本特征：原始输入有微小改动，哈希值的变化也会很大
我们只需用三个循环爆破结果，与 MD5 码对应即可，且不用担心 MD5 码缺失的影响
而且我们只改动三个字母，也不用担心哈希碰撞
代码如下：

```python
import hashlib

for i in range(26):
    for j in range(26):
        for k in range(26):
            test = 'TASC' + chr(ord('A') + i) + 'O3RJMV' + chr(ord('A') + j) + 'WDJKX' + chr(ord('A') + k) + 'ZM'
            s = hashlib.md5(test.encode('utf8')).hexdigest().upper()
            if s[0:4] == 'E903':
                print(s)
```

结果唯一： E9032994DABAC08080091151380478A2

## RSAROLL

题目给了花括号里面两个数字和后面一长串数字
花括号里面的应该分别是 n 和 e ，而后面一串应该就是密文
根据题目 “RSAROLL” ，推测是将 flag 拆分之后加密
先分解 n：![在这里插入图片描述](https://img-blog.csdnimg.cn/20210406171629828.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
得到 p, q
再按照 RSA 加密的一般算法进行解密即可
代码如下：

```python
from Crypto.Util.number import *

n = 920139713
p = 18443
q = 49891
e = 19

with open('data.txt', 'r') as f:
    list_c = f.readlines()[2:]

phi = (p-1)*(q-1)
d = inverse(e, phi)
flag = ''
for c in list_c:
    c = c.replace('\n', '')
    m = pow(int(c), d, n)
    flag += str(long_to_bytes(m)).replace('\'', '').replace('b', '')
print(flag)
```

实际上解出来每个 m 值就是对应的 ascii 码了，这里用 long_to_bytes 实际上是杀鸡用牛刀了
不过为了保险起见（比如会有 flag 不是逐位加密的情况，而是拆分成一段一段的情况），还是建议 long_to_bytes ，也不费事

# 2021-4-7

## robomunication

打开附件，一个 .mp3 文件，文件加密？(害怕)
点开文件，只能听到 bi bo bi bo 中间还有间段，猜想是摩斯电码，如果不是就是二进制字符串
再看标题：“机器人交流”？
可以排除文件加密的可能了

“听力测试”我们就不慢慢做了，直接看别人的 [wp](https://blog.csdn.net/CSDN___CSDN/article/details/82532090) [doge]
还有 github 上的[代码](https://gist.github.com/Zolmeister/5530467)
果不其然是摩斯电码
![https://www.jianshu.com/p/7f626c703416](https://img-blog.csdnimg.cn/20210407223942389.png)
对照摩斯电码表
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210407224024399.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
得到结果 HELLOWHATISTHEKEYITISBOOPBEEP
flag 即为 BOOPBEEP

## Unencode

题目就给了一串字符：89FQA9WMD<V1A<V1S83DY.#<W3$Q,2TM]
我直接 ？？？
最后还是只能找 [wp](https://blog.csdn.net/weixin_44017838/article/details/104885539) [捂脸]
原来是一个 UUencode（没见过😭）
UUencode 编码解码网站：[http://ctf.ssleye.com/uu.html](http://ctf.ssleye.com/uu.html)
那么，UUencode 是字母加密的？
![https://zh.wikipedia.org/wiki/Uuencode](https://img-blog.csdnimg.cn/20210407225116117.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
与 base64 有些相似，但后面 +32 的操作导致加密之后容易出现除了字母和数字的字母，这大概是一个比较明显的特征
而且加密之后最大的 ascii 码值为 95 为 “_” ，所以不可能出现小写字母，这也是一个特征

# 2021-4-8

## Morse

这题看题目就猜到是摩斯电码
打开附件：
-..../.----/-..../-..../-..../...--/--.../....-/-..../-..../--.../-.../...--/.----/--.../...--/..---/--.../--.../....-/...../..-./--.../...--/...--/-----/...../..-./...--/...--/...--/....-/...--/...../--.../----./--.../-..
直接解码：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210408231045776.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
但是结果包上 flag{} 交上去不行，换成小写也不行
重新看结果，没有 f 之后的字母，可能是十六进制数，再用 ascii 码？
代码如下：

```python
from Crypto.Util.number import *

s = '6 1 6 6 6 3 7 4 6 6 7 B 3 1 7 3 2 7 7 4 5 F 7 3 3 0 5 F 3 3 3 4 3 5 7 9 7 D '
s = s.replace(' ', '').lower()

print(long_to_bytes(int(s, 16)))
```

结果为 afctf{1s't_s0_345y}
交上去还是不对，我直接 “？”
把内容用 flag 包起来才行
答案为 flag{1s't_s0_345y}

## Dangerous RSA

看到 e = 3 就知道应该用小公钥指数攻击 
![https://ctf-wiki.org/crypto/asymmetric/rsa/rsa_e_attack/](https://img-blog.csdnimg.cn/20210408234052841.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
代码如下：

```python
from Crypto.Util.number import *
from gmpy2 import iroot

n = '0x52d483c27cd806550fbe0e37a61af2e7cf5e0efb723dfc81174c918a27627779b21fa3c851e9e94188eaee3d5cd6f752406a43fbecb53e80836ff1e185d3ccd7782ea846c2e91a7b0808986666e0bdadbfb7bdd65670a589a4d2478e9adcafe97c6ee23614bcb2ecc23580f4d2e3cc1ecfec25c50da4bc754dde6c8bfd8d1fc16956c74d8e9196046a01dc9f3024e11461c294f29d7421140732fedacac97b8fe50999117d27943c953f18c4ff4f8c258d839764078d4b6ef6e8591e0ff5563b31a39e6374d0d41c8c46921c25e5904a817ef8e39e5c9b71225a83269693e0b7e3218fc5e5a1e8412ba16e588b3d6ac536dce39fcdfce81eec79979ea6872793'
e = '0x3'
c = '0x10652cdfaa6b63f6d7bd1109da08181e500e5643f5b240a9024bfa84d5f2cac9310562978347bb232d63e7289283871efab83d84ff5a7b64a94a79d34cfbd4ef121723ba1f663e514f83f6f01492b4e13e1bb4296d96ea5a353d3bf2edd2f449c03c4a3e995237985a596908adc741f32365'

c = int(c, 16)
n = int(n, 16)
for k in range(0, 100):
    a, b = iroot(c+k*n, 3)
    if b == 1:
        m = a
        print(long_to_bytes(m))
        print(k)
        break
```

输出结果为：
![在这里插入图片描述](https://img-blog.csdnimg.cn/2021040823415366.png)
出题人还是很仁慈的，k=0 时就让我们找到了

# 2021-4-9

## Cipher

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210409231522338.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
除了“公平的玩吧（密钥自己找）”比较可疑外似乎没什么线索了
让人摸不着头脑
原本以为是普通的替换密码，尝试[爆破](https://quipqiup.com/)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210409232101709.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
没有结果

只能找 [wp](https://blog.csdn.net/MikeCoke/article/details/106105451)

“公平的玩吧”翻译成英文为 playfair
这是Playfair密码（又是没见过的密码）
[普莱费尔密码百度百科](https://baike.baidu.com/item/playfair%E5%AF%86%E7%A0%81/8999814?fr=aladdin)
[Playfair Cipher解密工具](http://rumkin.com/tools/cipher/playfair.php)

## basic rsa

这题非常简单，就是最基础的 RSA
甚至给了你 p, q
直接上解密代码：

```python
from Crypto.Util.number import *

p = 262248800182277040650192055439906580479
q = 262854994239322828547925595487519915551
e = 65533
c = 27565231154623519221597938803435789010285480123476977081867877272451638645710
n = p*q
phi = (p-1)*(q-1)
d = inverse(e, phi)

m = pow(c, d, n)
print(long_to_bytes(m))
```

得到 flag{B4by_Rs4}

## 达芬奇密码

附件内容：
达芬奇隐藏在蒙娜丽莎中的数字列:1 233 3 2584 1346269 144 5 196418 21 1597 610 377 10946 89 514229 987 8 55 6765 2178309 121393 317811 46368 4181 1 832040 2 28657 75025 34 13 17711 
记录在达芬奇窗台口的神秘数字串:36968853882116725547342176952286
一脸懵逼
怀疑可能和《达芬奇密码》这部小说有关（出题人经常干这事），可惜我没有读过
只好求助 wp，据说提到了斐波那契数列
一看还这是，只不过是乱序的
于是容易猜到数字串也是乱序的，并且和数字列的乱序一样
解密代码如下：

```python
a = '1 233 3 2584 1346269 144 5 196418 21 1597 610 377 10946 89 514229 987 8 55 6765 2178309 121393 317811 46368 4181 1 832040 2 28657 75025 34 13 17711'
list_a = a.split(' ')
m = '36968853882116725547342176952286'

list_f = [1, 1]
for i in range(0, len(list_a)-2):
    list_f.append(list_f[i] + list_f[i+1])

flag = '3'
list_a[0] = ''
for i in range(1, len(list_f)):
    flag += m[list_a.index(str(list_f[i]))]
print(flag)
```

因为 index() 是从前往后找的，而 list_a 中有两个 '1'，所以第一位第二位会重复
而易知 flag 第一位为 '3' ，所以这里选择用把 list_a 的第 0 位直接换成 '' 这种简单粗暴的办法来防止出错

# 2021-4-10

## rsa2

附件如下：

```python
N = 101991809777553253470276751399264740131157682329252673501792154507006158434432009141995367241962525705950046253400188884658262496534706438791515071885860897552736656899566915731297225817250639873643376310103992170646906557242832893914902053581087502512787303322747780420210884852166586717636559058152544979471
e = 46731919563265721307105180410302518676676135509737992912625092976849075262192092549323082367518264378630543338219025744820916471913696072050291990620486581719410354385121760761374229374847695148230596005409978383369740305816082770283909611956355972181848077519920922059268376958811713365106925235218265173085

import hashlib
flag = "flag{" + hashlib.md5(hex(d)).hexdigest() + "}"
```

是一段 py2 代码
看到 e 这么长，就知道要用维纳攻击法
脚本如下：

```python
import gmpy2
import hashlib

def transform(x, y):  # 使用辗转相处将分数 x/y 转为连分数的形式
    res = []
    while y:
        res.append(x // y)
        x, y = y, x % y
    return res


def continued_fraction(sub_res):
    numerator, denominator = 1, 0
    for i in sub_res[::-1]:  # 从sublist的后面往前循环
        denominator, numerator = numerator, i * numerator + denominator
    return denominator, numerator  # 得到渐进分数的分母和分子，并返回


# 求解每个渐进分数
def sub_fraction(x, y):
    res = transform(x, y)
    res = list(map(continued_fraction, (res[0:i] for i in range(1, len(res)))))  # 将连分数的结果逐一截取以求渐进分数
    return res


def get_pq(a, b, c):  # 由p+q和pq的值通过维达定理来求解p和q
    par = gmpy2.isqrt(b * b - 4 * a * c)  # 由上述可得，开根号一定是整数，因为有解
    x1, x2 = (-b + par) // (2 * a), (-b - par) // (2 * a)
    return x1, x2


def wienerAttack(e, n):
    for (d, k) in sub_fraction(e, n):  # 用一个for循环来注意试探e/n的连续函数的渐进分数，直到找到一个满足条件的渐进分数
        if k == 0:  # 可能会出现连分数的第一个为0的情况，排除
            continue
        if (e * d - 1) % k != 0:  # ed=1 (mod φ(n)) 因此如果找到了d的话，(ed-1)会整除φ(n),也就是存在k使得(e*d-1)//k=φ(n)
            continue

        phi = (e * d - 1) // k  # 这个结果就是 φ(n)
        px, qy = get_pq(1, n - phi + 1, n)
        if px * qy == n:
            p, q = abs(int(px)), abs(int(qy))  # 可能会得到两个负数，负负得正未尝不会出现
            d = gmpy2.invert(e, (p - 1) * (q - 1))  # 求ed=1 (mod  φ(n))的结果，也就是e关于 φ(n)的乘法逆元d
            return d
    print("该方法不适用")


n = 101991809777553253470276751399264740131157682329252673501792154507006158434432009141995367241962525705950046253400188884658262496534706438791515071885860897552736656899566915731297225817250639873643376310103992170646906557242832893914902053581087502512787303322747780420210884852166586717636559058152544979471
e = 46731919563265721307105180410302518676676135509737992912625092976849075262192092549323082367518264378630543338219025744820916471913696072050291990620486581719410354385121760761374229374847695148230596005409978383369740305816082770283909611956355972181848077519920922059268376958811713365106925235218265173085
d = wienerAttack(e, n)
print("d=", d)
k = hex(d)[2:]
flag = "flag{" + hashlib.md5(k.encode('utf-8')).hexdigest() + "}"
print(flag)
```

结果为：

```python
d= 8920758995414587152829426558580025657357328745839747693739591820283538307445
flag{a8eb82576211d716e354586aad3b099d}
```

但提交上去 flag 是错误的
用在线 MD5 加密也是错误的
只好用 [python2 加密](https://c.runoob.com/compile/6)：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210411001206339.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
结果正确

## BabyRSA

附件内容如下：

```python
p+q : 0x1232fecb92adead91613e7d9ae5e36fe6bb765317d6ed38ad890b4073539a6231a6620584cea5730b5af83a3e80cf30141282c97be4400e33307573af6b25e2ea
(p+1)(q+1) : 0x5248becef1d925d45705a7302700d6a0ffe5877fddf9451a9c1181c4d82365806085fd86fbaab08b6fc66a967b2566d743c626547203b34ea3fdb1bc06dd3bb765fd8b919e3bd2cb15bc175c9498f9d9a0e216c2dde64d81255fa4c05a1ee619fc1fc505285a239e7bc655ec6605d9693078b800ee80931a7a0c84f33c851740
e : 0xe6b1bee47bd63f615c7d0a43c529d219
d : 0x2dde7fbaed477f6d62838d55b0d0964868cf6efb2c282a5f13e6008ce7317a24cb57aec49ef0d738919f47cdcd9677cd52ac2293ec5938aa198f962678b5cd0da344453f521a69b2ac03647cdd8339f4e38cec452d54e60698833d67f9315c02ddaa4c79ebaa902c605d7bda32ce970541b2d9a17d62b52df813b2fb0c5ab1a5
enc_flag : 0x50ae00623211ba6089ddfae21e204ab616f6c9d294e913550af3d66e85d0c0693ed53ed55c46d8cca1d7c2ad44839030df26b70f22a8567171a759b76fe5f07b3c5a6ec89117ed0a36c0950956b9cde880c575737f779143f921d745ac3bb0e379c05d9a3cc6bf0bea8aa91e4d5e752c7eb46b2e023edbc07d24a7c460a34a9a
```

给了 p+q 和 (p+1)(q+1)
直接用 sagemath 一元二次方程解出 p,q:
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210411001546368.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
x 的两个解即为 p,q
然后就是最基础的 RSA 解密了
代码如下：

```python
from Crypto.Util.number import *

k1 = '0x1232fecb92adead91613e7d9ae5e36fe6bb765317d6ed38ad890b4073539a6231a6620584cea5730b5af83a3e80cf30141282c97be4400e33307573af6b25e2ea'# p+q
k2 = '0x5248becef1d925d45705a7302700d6a0ffe5877fddf9451a9c1181c4d82365806085fd86fbaab08b6fc66a967b2566d743c626547203b34ea3fdb1bc06dd3bb765fd8b919e3bd2cb15bc175c9498f9d9a0e216c2dde64d81255fa4c05a1ee619fc1fc505285a239e7bc655ec6605d9693078b800ee80931a7a0c84f33c851740'# (p+1)(q+1)
e = '0xe6b1bee47bd63f615c7d0a43c529d219'
d = '0x2dde7fbaed477f6d62838d55b0d0964868cf6efb2c282a5f13e6008ce7317a24cb57aec49ef0d738919f47cdcd9677cd52ac2293ec5938aa198f962678b5cd0da344453f521a69b2ac03647cdd8339f4e38cec452d54e60698833d67f9315c02ddaa4c79ebaa902c605d7bda32ce970541b2d9a17d62b52df813b2fb0c5ab1a5'
enc_flag = '0x50ae00623211ba6089ddfae21e204ab616f6c9d294e913550af3d66e85d0c0693ed53ed55c46d8cca1d7c2ad44839030df26b70f22a8567171a759b76fe5f07b3c5a6ec89117ed0a36c0950956b9cde880c575737f779143f921d745ac3bb0e379c05d9a3cc6bf0bea8aa91e4d5e752c7eb46b2e023edbc07d24a7c460a34a9a'

k1 = int(k1, 16)
k2 = int(k2, 16)
e = int(e, 16)
d = int(d, 16)
enc_flag = int(enc_flag, 16)
n = k2-k1-1 # p*q
p = 7021910101974335245794950722131367118195509913680915814438898999848788125908122655583911434165700354149914056221915541094395668546921268189522005629523759
q = 8228801334907462855397256098699556584084854642543205682719705217859576250443629616812386484797164506834582095674143447181804355696220642775619711451990971
phi = (p-1)*(q-1)
d = inverse(e, phi)
print(d)
m = pow(enc_flag, d, n)
print(long_to_bytes(m))
```

结果突然发现 d 已经知道了（wtm。。。）
可以通过 p+q 和 (p+1)(q+1) 直接解出 φ
代码如下：

```python
from Crypto.Util.number import *

k1 = '0x1232fecb92adead91613e7d9ae5e36fe6bb765317d6ed38ad890b4073539a6231a6620584cea5730b5af83a3e80cf30141282c97be4400e33307573af6b25e2ea'# p+q
k2 = '0x5248becef1d925d45705a7302700d6a0ffe5877fddf9451a9c1181c4d82365806085fd86fbaab08b6fc66a967b2566d743c626547203b34ea3fdb1bc06dd3bb765fd8b919e3bd2cb15bc175c9498f9d9a0e216c2dde64d81255fa4c05a1ee619fc1fc505285a239e7bc655ec6605d9693078b800ee80931a7a0c84f33c851740'# (p+1)(q+1)
e = '0xe6b1bee47bd63f615c7d0a43c529d219'
d = '0x2dde7fbaed477f6d62838d55b0d0964868cf6efb2c282a5f13e6008ce7317a24cb57aec49ef0d738919f47cdcd9677cd52ac2293ec5938aa198f962678b5cd0da344453f521a69b2ac03647cdd8339f4e38cec452d54e60698833d67f9315c02ddaa4c79ebaa902c605d7bda32ce970541b2d9a17d62b52df813b2fb0c5ab1a5'
enc_flag = '0x50ae00623211ba6089ddfae21e204ab616f6c9d294e913550af3d66e85d0c0693ed53ed55c46d8cca1d7c2ad44839030df26b70f22a8567171a759b76fe5f07b3c5a6ec89117ed0a36c0950956b9cde880c575737f779143f921d745ac3bb0e379c05d9a3cc6bf0bea8aa91e4d5e752c7eb46b2e023edbc07d24a7c460a34a9a'

k1 = int(k1, 16)
k2 = int(k2, 16)
e = int(e, 16)
d = int(d, 16)
enc_flag = int(enc_flag, 16)
n = k2-k1-1 # p*q
phi = k2 - 2*k1
d = inverse(e, phi)
print(d)
m = pow(enc_flag, d, n)
print(long_to_bytes(m))
```

结果均为：flag{cc7490e-78ab-11e9-b422-8ba97e5da1fd}

# 2021-4-11

## [虎符杯]cubic

先上题目给的附件：

```python
from math import gcd
from functools import reduce
from fractions import Fraction as Frac

N = 6

def read_num(prompt):
    try:
        num = int(input(prompt))
    except:
        return 0
    return num if num > 0 else 0

print(f"Please give me {N} pairs of positive integers (x,y,z) "
      f"satisfying the equation `x/(y+z) + y/(z+x) + z/(x+y) = {N}`\n")
anss = []
mark = 0
for i in range(N):
    x = read_num("[>] x: ")
    y = read_num("[>] y: ")
    z = read_num("[>] z: ")
    if x * y * z == 0: # positive integer
        mark = 1
        print("This is not what i want!\n")
        break
    # reduce(gcd, [x, y, z]) = gcd(gcd(x,y), z)
    if reduce(gcd, [x, y, z]) != 1: # (kx, ky, kz)
        mark = 1
        print("This is not what i want!\n")
        break
    if Frac(x, y+z) + Frac(y, z+x) + Frac(z, x+y) != N:
        mark = 1
        print("This is not what i want!\n")
        break
    ans = tuple(sorted([x, y, z])) # (y, x, z)
    if ans in anss:
        mark = 1
        print("This is not what i want!\n")
        break
    else:
        print("You are right!\n")
        anss.append(ans)
if mark == 0:
    flag = open('/flag', 'r').read()
    print("flag is: " + flag + "\n")
else:
    print("Something wrong!\n")

```

不就是找 $\frac{x}{y+z}+\frac{y}{x+z}+\frac{z}{x+y}=6$ 的 6 组正整数解吗？
直接用 sagemath 爆破（你真是个天才）：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210411092546679.png)结果：
![在这里插入图片描述](https://img-blog.csdnimg.cn/2021041109261016.png)啊这
当然不可能这么简单

事实上，$\frac{x}{y+z}+\frac{y}{x+z}+\frac{z}{x+y}=4$ 的解十分复杂：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210411094210447.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
如果能爆破出来才有问题
而这个问题可以转化成 **椭圆曲线问题**（跪谢 Pheonix dl 指点迷津）
这就涉及到我的知识盲区了
下午就开始学椭圆曲线
如 wp 中的[论文](https://ami.uni-eszterhazy.hu/uploads/papers/finalpdf/AMI_43_from29to41.pdf)所述
对于形如
$$
N=\frac{a}{b+c}+\frac{b}{a+c}+\frac{c}{a+b},其中 N \in\mathbb{N^{*}}
$$
可以转化成三元三次方程
$$
N(a+b)(b+c)(c+a)=a(a+b)(c+a)+b(b+c)(a+b)+c(c+a)(a+b)
$$
可以通过线性变换，将其转化成常见的椭圆曲线（形如 $y ^{2} = ax ^{3}+bx ^{2}+cx+d$）的形式：
$$
y ^{2} = x ^{3}+(4N ^{2} + 12N - 3)x ^{2}+32(N+3)x
$$
其中
$$
x=\frac{-4(a+b+2c)(N+3)}{(2a+2b-c)+(a+b)N}，
y=\frac{4(a-b)(N+3)(2N+5)}{(2a+2b-c)+(a+b)N}
$$
别问，问就是数理基础
当然也可以映射回去：
设 s=a+b+c
$$
\frac{a}{s}=\frac{8(N+3)-x+y}{2(4-x)(N+3)}，\\
\frac{b}{s}=\frac{8(N+3)-x-y}{2(4-x)(N+3)}，\\
\frac{c}{s}=\frac{-4(N+3)-(N+2)x}{(4-x)(N+3)}
$$
具体怎么转化，可以参考[这篇文章](https://mlzeng.com/an-interesting-equation.html)
这篇文章是以 $\frac{a}{b+c}+\frac{b}{a+c}+\frac{c}{a+b}=4$ 为例
通过介绍丢番图等式：
$$
P(x_{1},x_{2},\dots,x_{k})=\sum _{{0\leq i_{j}\leq n_{j}}}a_{{i_{1}i_{2}\dots i_{k}}}x_{1}^{{i_{1}}}x_{2}^{{i_{2}}}\dots x_{k}^{{i_{k}}}=0
$$
从一阶到三阶（三阶即为所求等式的转化形式）来介绍解法
这里不再赘述
其中的线性变换部分
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210411105005936.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
当然，下文给出了程序解法：
![在这里插入图片描述](https://img-blog.csdnimg.cn/2021041110511519.png)
数理基础不扎实的我只能代数字，套程序了

理论推导就到这里
接下来是求解
wp 中用 sagemath 封装好的椭圆曲线算法进行求解
关于椭圆曲线求解，可以参考[ECC椭圆曲线加密算法：介绍](https://zhuanlan.zhihu.com/p/36326221)
当然，这道题其实不涉及加密部分，真正的椭圆曲线加密算法复杂的多（如[应用于比特币](https://www.bilibili.com/video/BV1TE411q7mW?from=search&seid=14741657793119036139)）
自己实现其实也不麻烦
这里不再赘述

最后还有个小插曲
当时题目刚出来的时候发现没有获取 flag 的方式，然后做着做着题目下线了，添了一个得到 flag 的地址
提交答案获取 flag 的部分也是 wp 中可以借鉴（抄袭）的地方

## [BUU]CheckIn

附件给了一串字符：dikqTCpfRjA8fUBIMD5GNDkwMjNARkUwI0BFTg==
看到后面两个 “==” 大概率是 base64
随便找了个[网站](https://tool.oschina.net/encrypt?type=3)解密
![在这里插入图片描述](https://img-blog.csdnimg.cn/2021041111470534.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
这是什么玩意？
还有替换密码？
拿去[爆破](https://quipqiup.com/)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210411114904733.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
只好找 wp ，得知要拿 base64 解码出来的结果 rot 解密
解密结果以及 rot-N 加密原理如下：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210411115037868.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
rot-N 加密解密网站：[https://www.qqxiuzi.cn/bianma/ROT5-13-18-47.php](