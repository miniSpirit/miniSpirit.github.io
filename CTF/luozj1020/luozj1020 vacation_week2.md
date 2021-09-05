# 2021-7-19

## [NPUCTF2020]认清形势，建立信心

加密代码如下：

```python
from Crypto.Util.number import *
from gmpy2 import *
from secret import flag

p = getPrime(25)
e = # Hidden
q = getPrime(25)
n = p * q
m = bytes_to_long(flag.strip(b"npuctf{").strip(b"}"))

c = pow(m, e, n)
print(c)
print(pow(2, e, n))
print(pow(4, e, n))
print(pow(8, e, n))

'''
169169912654178
128509160179202
518818742414340
358553002064450
'''
```

题目给了$2^e\space mod \space n$，$4^e\space mod \space n=2^2e\space mod \space n$ 和 $8^e\space mod \space n=2^3e\space mod \space n$分别记为c2, c4, c8
容易发现，
$$
2^e\times2^e\times2^e \space mod \space n = 2^e\times4^e \space mod \space n  = 8^e \space mod \space n 
$$
由此我们可以计算```c2*c2*c2-c8```和```c2*c4-c8```得到$n$的倍数，对两数取最小公倍数再分解质因数，得到符合条件的大质数即为p和q
代码如下：

```python
import gmpy2

c = 169169912654178
c2 = 128509160179202
c4 = 518818742414340
c8 = 358553002064450

print(gmpy2.gcd(c2*c4-c8, c2*c2*c2-c8))
# 1054494004042394
```

分解质因数：
![在这里插入图片描述](luozj1020 vacation_week2.assets/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70.png)
但是这题隐藏了e，所以不能直接RSA解密，还需要求e
这是一个离散对数问题，可以参考我[2021-5-9的博客](https://blog.csdn.net/weixin_52446095/article/details/116573356?ops_request_misc=%257B%2522request%255Fid%2522%253A%2522162668720416780274174350%2522%252C%2522scm%2522%253A%252220140713.130102334.pc%255Fblog.%2522%257D&request_id=162668720416780274174350&biz_id=0&utm_medium=distribute.pc_search_result.none-task-blog-2~blog~first_rank_v2~rank_v29-1-116573356.pc_v2_rank_blog_default&utm_term=%E7%A6%BB%E6%95%A3&spm=1018.2226.3001.4450)
完整解密代码如下：

```python
from Crypto.Util.number import *
import gmpy2
import sympy

c = 169169912654178
c2 = 128509160179202
c4 = 518818742414340
c8 = 358553002064450

print(gmpy2.gcd(c2*c4-c8, c2*c2*c2-c8))
p = 18195301
q = 28977097
e = sympy.discrete_log(p*q, c2, 2)
print(e)
phi = (p-1)*(q-1)
d = inverse(e, phi)
m = pow(c, d, p*q)
print(long_to_bytes(m))
```

结果为：
![在这里插入图片描述](luozj1020 vacation_week2.assets/20210719173444760.png)



## [BJDCTF2020]伏羲六十四卦

题目给了一段文本：
这是什么，怎么看起来像是再算64卦！！！

密文:升随临损巽睽颐萃小过讼艮颐小过震蛊屯未济中孚艮困恒晋升损蛊萃蛊未济巽解艮贲未济观豫损蛊晋噬嗑晋旅解大畜困未济随蒙升解睽未济井困未济旅萃未济震蒙未济师涣归妹大有

嗯？为什么还有个b呢?
b=7

flag：请按照格式BJD{}

还给了一段意义不明的加密代码：

```python
# -- coding:UTF-8 --
from secret import flag

def encrpyt5():
    enc=''
    for i in flag:
        enc+=chr((a*(ord(i)-97)+b)%26+97)
    return(enc)

def encrypt4():
    temp=''
    offset=5
    for i in range(len(enc)):
        temp+=chr(ord(enc[i])-offset-i)
    return(temp)
```

我还特地取搜了一下[伏羲六十四卦](https://zh.wikipedia.org/wiki/%E5%85%AD%E5%8D%81%E5%9B%9B%E5%8D%A6)，发现密文的内容就是六十四卦的内容
没思路，只好找[wp](https://blog.csdn.net/weixin_44110537/article/details/107494966)
原来是要把六十四卦按顺序转化成6位二进制数，再8位一组转化成文本
结果如下：
![在这里插入图片描述](luozj1020 vacation_week2.assets/20210719174358694.png)
容易联想到是base64加密，尝试解密，结果为：
![在这里插入图片描述](luozj1020 vacation_week2.assets/202107191744409.png)
好丑，是不是解错了？
这时就要用题目给的加密代码了
观察可得，明文先经过了encrpyt5，然后经过了encrypt4
那就先"decrypt4"
结果为：
![在这里插入图片描述](luozj1020 vacation_week2.assets/20210719174745401.png)
看起来接近答案了
但是看encrpyt5，发现题目给了b，但是没给a，就很难受
wp采用爆破的方法，就借(chao)鉴(xi)了一下
完整解密代码如下：

```python
# -*- coding:utf-8 -*-

import base64

def decrypt4(c):
    temp = ''
    offset = 5
    for i in range(len(c)):
        temp += chr(ord(c[i])+offset+i)
    print(temp)
    return temp

def encrpyt5(c):
    b = 7
    for a in range(1, 200):
        temp = ''
        for i in c:
            for k in range(200):
                if (ord(i) - 97 + 26 * k - b) % a == 0:
                    temp += chr((ord(i) - 97 - 7 + 26 * k) // a + 97)
                    break
        if len(c) == len(temp) and 'flag' in temp:
            print(temp)

s = '升随临损巽睽颐萃小过讼艮颐小过震蛊屯未济中孚艮困恒晋升损蛊萃蛊未济巽解艮贲未济观豫损蛊晋噬嗑晋旅解大畜困未济随蒙升解睽未济井困未济旅萃未济震蒙未济师涣归妹大有'
table = {'坤': '000000', '剥': '000001', '比': '000010', '观': '000011', '豫': '000100', '晋': '000101', '萃': '000110', '否': '000111', '谦': '001000', '艮': '001001', '蹇': '001010', '渐': '001011', '小过': '001100', '旅': '001101', '咸': '001110', '遁': '001111', '师': '010000', '蒙': '010001', '坎': '010010', '涣': '010011', '解': '010100', '未济': '010101', '困': '010110', '讼': '010111', '升': '011000', '蛊': '011001', '井': '011010', '巽': '011011', '恒': '011100', '鼎': '011101', '大过': '011110', '姤': '011111', '复': '100000', '颐': '100001', '屯': '100010', '益': '100011', '震': '100100', '噬嗑': '100101', '随': '100110', '无妄': '100111', '明夷': '101000', '贲': '101001', '既济': '101010', '家人': '101011', '丰': '101100', '离': '101101', '革': '101110', '同人': '101111', '临': '110000', '损': '110001', '节': '110010', '中孚': '110011', '归妹': '110100', '睽': '110101', '兑': '110110', '履': '110111', '泰': '111000', '大畜': '111001', '需': '111010', '小畜': '111011', '大壮': '111100', '大有': '111101', '夬': '111110', '乾': '111111'}
b = ''
i = 0
while i < len(s):
    try:
        b += table[s[i]]
        i += 1
    except KeyError:
        b += table[s[i]+s[i+1]]
        i += 2

x = ''
for i in range(0, len(b), 8):
    x += chr(int(b[i:i+8], 2))
print(x)
x = base64.b64decode(x).decode()
print(x)
x = decrypt4(x)
encrpyt5(x)
```

结果为：![在这里插入图片描述](luozj1020 vacation_week2.assets/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70.png)
BJD congratulation son getting the flag？？？（wtm）
套上flag{}即可

# 2021-7-20

## [NPUCTF2020]共 模 攻 击

题目给了两个加密程序
一个是加密hint：

```python
from gmpy2 import *
from Crypto.Util.number import *
from secret import hint

m = bytes_to_long(hint)
p = getPrime(256)
c = pow(m, 256, p)
print(p)

p, q = getPrime(256), getPrime(256)
n = p * q
e1, e2 = getPrime(32), getPrime(32)
c1, c2 = pow(c, e1, n), pow(c, e2, n)
print(n)
print(e1, c1)
print(e2, c2)

'''
107316975771284342108362954945096489708900302633734520943905283655283318535709
6807492006219935335233722232024809784434293293172317282814978688931711423939629682224374870233587969960713638310068784415474535033780772766171320461281579
2303413961 1754421169036191391717309256938035960912941109206872374826444526733030696056821731708193270151759843780894750696642659795452787547355043345348714129217723
2622163991 1613454015951555289711148366977297613624544025937559371784736059448454437652633847111272619248126613500028992813732842041018588707201458398726700828844249
'''
```

另一个是加密flag：

```python
from gmpy2 import *
from Crypto.Util.number import *
from secret import flag

flag = flag.strip(b"npuctf{").strip(b"}")
m = bytes_to_long(flag)

p, q = getPrime(512), getPrime(512)
n = p * q
e1, e2 = p, q
c1, c2 = pow(m, e1, n), pow(m, e2, n)

print(n)
print(c1)
print(c2)

'''
128205304743751985889679351195836799434324346996129753896234917982647254577214018524580290192396070591032007818847697193260130051396080104704981594190602854241936777324431673564677900773992273463534717009587530152480725448774018550562603894883079711995434332008363470321069097619786793617099517770260029108149
96860654235275202217368130195089839608037558388884522737500611121271571335123981588807994043800468529002147570655597610639680977780779494880330669466389788497046710319213376228391138021976388925171307760030058456934898771589435836261317283743951614505136840364638706914424433566782044926111639955612412134198
9566853166416448316408476072940703716510748416699965603380497338943730666656667456274146023583837768495637484138572090891246105018219222267465595710692705776272469703739932909158740030049375350999465338363044226512016686534246611049299981674236577960786526527933966681954486377462298197949323271904405241585
'''
```

乍一看，确实很像共模攻击，但是一看这个加密指数是p和q并且未知，就知道没那么简单
首先来解密hint
第一步容易想到用共模攻击解密被加密的hint
代码如下：

```python
import gmpy2
from Crypto.Util.number import *

# hint
e1 = 2303413961
e2 = 2622163991
c1 = 1754421169036191391717309256938035960912941109206872374826444526733030696056821731708193270151759843780894750696642659795452787547355043345348714129217723
c2 = 1613454015951555289711148366977297613624544025937559371784736059448454437652633847111272619248126613500028992813732842041018588707201458398726700828844249
p1 = 107316975771284342108362954945096489708900302633734520943905283655283318535709
n = 6807492006219935335233722232024809784434293293172317282814978688931711423939629682224374870233587969960713638310068784415474535033780772766171320461281579

gcd, s, t = gmpy2.gcdext(e1, e2)
if s < 0:
    s = -s
    c1 = gmpy2.invert(c1, n)
if t < 0:
    t = -t
    c2 = gmpy2.invert(c2, n)
c = gmpy2.powmod(c1, s, n) * gmpy2.powmod(c2, t, n) % n
print(c)
```

但下一步发现，加密hint的过程为```c = pow(m, 256, p)```
原本是想类似于经典的RSA解密
p的欧拉函数为p-1，然后参考[\[De1CTF2019\]babyrsa](https://blog.csdn.net/weixin_52446095/article/details/118733418?spm=1001.2014.3001.5501)或者[EzRSA](https://blog.csdn.net/weixin_52446095/article/details/117136443?spm=1001.2014.3001.5501)，利用$gcd(256,p-1)$解出d然后求解
但是发现$gcd(256,p-1)=4$，无法用这种方法
只好找[wp](https://www.cnblogs.com/vict0r/p/13292511.html)
原来直接用sympy库的nthroot_mod方法就行，该方法可以用来求解$x^n \equiv a\space mod\space p$，其中$n,a,p$为已知数
那么，有这么好的方法，能不能直接用来求解RSA问题呢？当然是不行的
因为求解本题的$m^{256} \equiv c\space mod\space p$都要花上好几秒，求解RSA问题基本上不可能
这里附上[nthroot_mod的源代码](https://github.com/sympy/sympy/blob/46e00feeef5204d896a2fbec65390bd4145c3902/sympy/ntheory/residue_ntheory.py#L810-L874)，感兴趣的师傅可以研究研究
完整解密代码如下：

```python
import gmpy2
import sympy
from Crypto.Util.number import *

# hint
e1 = 2303413961
e2 = 2622163991
c1 = 1754421169036191391717309256938035960912941109206872374826444526733030696056821731708193270151759843780894750696642659795452787547355043345348714129217723
c2 = 1613454015951555289711148366977297613624544025937559371784736059448454437652633847111272619248126613500028992813732842041018588707201458398726700828844249
p1 = 107316975771284342108362954945096489708900302633734520943905283655283318535709
n = 6807492006219935335233722232024809784434293293172317282814978688931711423939629682224374870233587969960713638310068784415474535033780772766171320461281579

gcd, s, t = gmpy2.gcdext(e1, e2)
if s < 0:
    s = -s
    c1 = gmpy2.invert(c1, n)
if t < 0:
    t = -t
    c2 = gmpy2.invert(c2, n)
c = gmpy2.powmod(c1, s, n) * gmpy2.powmod(c2, t, n) % n
print(c)
m = sympy.nthroot_mod(c, 256, p1)
print(long_to_bytes(m))
```

结果为：
![在这里插入图片描述](luozj1020 vacation_week2.assets/20210720114243481.png)
提示m的位数小于400，有什么用吗？
wp中说可以由此联想到Coppersmith
确实，在一些高位或低位泄露的题目中，Coppersmith是常用的手段，但是只知道位数小于400怎么用呢？
wp一下的解题过程也确实没有用到Coppersmith
不过，wp给了Coppersmith定理一个比较通俗的解释：在一个$e$阶的以$n$为模的多项式$f(x)$中，如果有一个根小于$n^{1/e}$，就可以运用一个O(log n)的算法求出这些根。其中的“阶”大概就是指（循环）群的阶
在这里重新推导一遍解题思路
由加密程序可得：
$$
\begin{cases}
c_1 \equiv m^{p}\space mod\space n \equiv m^{p}\space mod\space pq \\
c_2 \equiv m^{q}\space mod\space n \equiv m^{q}\space mod\space pq
\end{cases}
$$
故$\exists t_1\in \mathbb{Z}$，$s.t. c_1 = m^p + t_1pq$
于是有
$$
c_1 \equiv m^{p}\space mod\space p
$$
由[费马小定理](https://zh.wikipedia.org/wiki/%E8%B4%B9%E9%A9%AC%E5%B0%8F%E5%AE%9A%E7%90%86)有
$$
m^{p}\equiv m\space mod\space p
$$
故
$$
c_1 \equiv m\space mod\space p
$$
同理，有
$$
c_2 \equiv m\space mod\space q
$$
故$\exists k_1,k_2\in \mathbb{Z}$，$s.t.$
$$
\begin{cases}
c_1=m+k_1p\\
c_2=m+k_2q
\end{cases}
$$
则
$$
\begin{cases}
(c_1+c_2)m=2m^2+(k_1p+k_2q)m \cdots (1)\\
c_1c_2=m^2+(k_1p+k_2q)m+k_1k_2pq \cdots (2)
\end{cases}
$$
$(1)-(2)$​得：
$$
(c_1+c_2)m-c_1c_2=m^2-k_1k_2pq=m^2-k_1k_2n
$$
移项，等式两边模$n$，得：
$$
m^2-(c_1+c_2)m+c_1c_2=k_1k_2n \equiv 0\space mod \space n
$$
所以只要在模$n$的情况下（或者说是在整数模$n$加法群中），求方程的根
参照wp，sage代码如下：
![在这里插入图片描述](luozj1020 vacation_week2.assets/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70.png)
得到m直接long_to_bytes即可
结果为：
![在这里插入图片描述](luozj1020 vacation_week2.assets/20210720165002573.png)

# 2021-7-22

## [NCTF2019]Sore

加密代码如下：

```python
from string import ascii_letters
from flag import flag


ctoi = lambda x: ascii_letters.index(x)
itoc = lambda x: ascii_letters[x]

key = flag.strip('NCTF{}')
len_key = len(key)

plaintext = open('plaintext.txt', 'r').read()

plain = ''.join(p for p in plaintext if p in ascii_letters)
cipher = ''.join(itoc((ctoi(p) + ctoi(key[i % len_key])) % 52) for i, p in enumerate(plain))

open('ciphertext.txt', 'w').write(cipher)
```

通过key在ascii_letters（"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"）中的位置，以key的长度循环加密
可以看出来，有点像维吉尼亚密码（然而我没看出来( ），但是正统的维吉尼亚密码是不区分大小写的
从出题者的角度，看[官方wp](http://yulige.top/?p=752#Sore667pt_6solvers)
![在这里插入图片描述](luozj1020 vacation_week2.assets/5c7da939e8f0cdfb4b7c69802d12c496.png)
啊这
就找了个[网站](https://www.guballa.de/vigenere-solver)爆破
![在这里插入图片描述](luozj1020 vacation_week2.assets/b9cfc3c132c6c90e035d343722996c39.png)

![在这里插入图片描述](luozj1020 vacation_week2.assets/a4cb5c195b880a77d88718eebb3882eb.png)
最后要区分大小写，把x改成X就是flag（。。。草）
至于为什么只把'x'改成大写，当然可以以ascii_letters为字母表另外写一个爆破程序，但是大可不必
或者通过解密，使得明文是一段有意义的文本
但是，其实可以耍小聪明：
设x为原文中的某个字符，y为key中对应于x的字符，z为cipher中对应于x的字符
若y为大写字母，则26<=ctoi(y)<=51，那么ctoi(x)+ctoi(y)大概率（至少大于50%的概率）会大于52，则ctoi(z)会小于ctoi(y)，故ctoi(z)-ctoi(y)小于0的次数较多的y极有可能是key中的大写字母
代码如下：

```python
from string import ascii_letters

ctoi = lambda x: ascii_letters.index(x)

cipher = 'nsfAIHFrMuLynuCApeEstxJOzniQuyBVfAChDEznppfAiEIDcyNFBsCjsLvGlDtqztuaHvHbCmuyGNsIMhGlDtbotCoDzDjhyBzHGfHGfoHsuhlssIMvwlixBHHGfDRjoCKrapNIwqNyuxIBACQhtMwCmMCfEBpsrzEuiLGBoMipTkxrznoHfAkqwzvxuzCzDbLyApCGvjpqxkuwpgsLrqsVfCRwzlFmtlyrhuyEiivruFRpCRjkEDrqEqthyGwgsLnQvHmtzwDEznopBpsDOxvgBGIKzurFQxwQxkptutxzmfeLFQoRpJRvrpHxilwqeqMeiiIGBsQpCCvrptAlHsDnuRltmHuCGFpsBcwnsEblsswEPwerNpIADpJRCvwQxrntJltNpfAuFBwRstytoyvcepwtwqNlmmNGFsJjsQvkyvrkrstxJOzniQvNvzdDUdyJzjqzsErqxEjguyFMNwtPjsDwjoDfCdxzvftNGyzKjCEjsDxjqsjGMqFpimGpIADpJRFkovHJlpthyHnpqyBOHhmDMmoosClwiehEzmffOGMvDxDSnnyLuXFlwYEPvosQxCrRxwCpDswHopxDruvEzsOgBsXxDLvvlMpezwpnOOsjrANzHDsLCnoqLCepgtaHNHfpysNHGfOMqkyvlozxHetJGfvNuCGKjIRnoDLAbpyxnJCpqeLxuBCuwCpGpOnkEywrEPrisHrItSiDQgvtLCipyJnDzwtxBnNoKxpWuCxwuiqwDmIJxffIqSGSbzGpqlDnXvNIwqNzoxBrQoXuDRjonsAozzHeBjweTBBypDtIGnvHGDiosItqGvusGrIFzoNRjsyykrExweMvDtsLGItVbAIkxrFnuEyDmuIzxMNBIyziDJfyqLqbmjAtqOEiivnwyNgwCtmzsCgFxIfEMEiiBrFzNgxRdEEKqbHtJltIEmiNzygGfHyknVwnmJtJrxvyewNBSCTsHCnptxHlFiDnJHtohmuyKztHRkvwKxopfImuWFurIGuGRpGCcCDzntlxqevJCfEHLQoXxtIgzEynqEnCgsGztiLnHrBmDQgBEGCephprHJFtiFnHrXpJAqEwvBqlwItECpbvNuuHMvIRAwFKrZtyplMvJttFnSGhuLyuzwsHfyldhcvCjicGJzzztBvrlLBXxjHoDBlcsOGzwEuNWgkCKjdzBweDdHbwuyCHSmtIknezjqDtCeDDnfxBvHuzcDSvmlJAlFxtlIOsfCuyQoXtEJcIEznplrtsEIrtMNuIIFiIRjonsAozzHeBRltgFBMsCjCRjoHAwqpwIiCzzmhjuIsAfHyknTLFXDywevDCtxNvGsRitNtknLrZlqAyIvteeHLNvHovqjoAJxYlgAyvJChsNFBsVbHQwzAGBboyDbuNzsiuGGslbNzglpujrDjxtIvCpyHqWvQjHRokDaBXtihhuyterNFuMzoNRjsyyFepsXsqDouluGmvDqGMdkmDHoprtmrzCfhMuyKztHSrzzKnaEtqeIJCfeNzyRNzDSykyLClrtuoHvCjhyBHwSJHyknTCwbHxweFMzcevySrHelFgxDzntlxptyIJmmNGFsJjsypnLDufpfCdTWlohcHMsCuDEqDzLqbAfGkMDEilyEMvDxpQokosklFyIhuxlsvIHMsKZDSeyFDmkElttxzCpjzGBsFpsBcwEzrkrNBtEJmjkMuyGzjsgvrzMpeExweMvDoxABCBFuDypCHwAjpgJtICpemxaIMNvGCpyEYxlyNAlMvtujIESofpDLKClAmTpBtruMthlNGBsQfIFgxeznopBtruvqfAEvxGQjsGpqzFrqxtHtBTGfvSyCHSmtIknDswalktwFvCfrNFQsQfLykDtFpXCtJntJFuwCqyGHuIGpqzFCepgtnsCpteHquzKXwyvSoAmtlxXwuIEvtNBNvDxxLfyHOqbCjIhuTDfpFGBsSjrIgDDswamtJgxOzmhjuIsAfpRkmvwCQsjCIwvGfmNGIvDshFgGlKBqlssiDBCjkBGHsWuIMooSwAbTxpitrljxuFyqNosRcupLqbCjHtEAJpyLqIIFiIMqSDLjoEjsgyQtokBrLHGfGCuDzxCepiDuwCDiixyyBSntwqEvwnmtyZeuKtujIEGsRitQcsolqbyxweIvtevCtBHzgICtGlJmMwjpsuosbxMqyDQfHQkxrOqbyxDmuwzeCMnSGOmtyuoEGHlFNBeqItgmNFjvNfqCqBDGvbmtsyjCluhyCLsRttBvrpzniwtJtEAxfFOGcDTuIFgnzMpemfrkyIxztIpEsSBGCpDJGDdzsCaHDofxIBMvDbHIgnxwbepBpsBJzlmHtuHLfHMtDzxorysNYEPnpyFqNsKmHFgGlKwqEtDsEMpbxGruBXnDPgWlQkbTBxlBOsfryKNHHntgnvHsCZsDpIIvteKIGSCTsIGeupLhbDLDaxzlexBrHWKmqCqxEzrpmjCcxMthlNBPsQitPgSwDFXEhwyqdHfrNBPsQbCBukEvxtytCtxDDciHpBoMeHFgGpFCXyivoJJyulypuFQpJQgvdzntlqzetvwmeLBOBCjIgoolFBepBplAzoprwruzKuwCykJsAlFssiJosfrMuyGzusMyxzFCetxqiwwCpAHoyoSvEJqyvAwdzqshEMDfXBrHHGfrytBzMBbwxIaHOpeeHqcKzurFgnswAdzfGoKIobrxnLCTosrjoCwFbCjDnBTlcsOGzwUfDPusIGCepwzitNzoxBrLwCfpLfDswBlylIhuxlsvIHMsKxpQrvlQrkrBpsiHzliarNGHonMwBPQnpTyLaIKwbCCAAwSwtPAtlRIvlssfKIyzEFyNvDlxBuupHCqCDxnwOzhvuozCQuwCiywvAfylpntNzxeMBFroiDCdolFmFHfHsEMEpjusLoHeHFgnqsuizkutxzrphxnGvNsHCdEEamfosIsqTloCNuCBFpGBqkyQCetsvTxzEimHtQwSizGfCtKrcEmtyMvyuxItLoAuwCiywvAfylNoKClwiNBFsSuwConzACXyiCoJNlzeHLNvHovghDswHclqAovAEiiSsuzKpuDdEEACpmfsivTzvwuLuBXuwGpqEGCeprlhuIEiiLvxsVbHMxoCKqbrtIovAsfvBBLGDbCBekxwxspwIoCzjpyLvxsNorCvyzLqfDyxmuNsfwuvxbNJAJlEDLFXEhwyqdEimHxczKkJQvGlLleTxpitdrbzyuyFRpBCoyCwxcsjGdEPriLyEyUDuHMooxGAbEnrkuODTlyGICJuwCfyFyqlqkBeYHypxGnxoSzDScxJExopxweIvteMEAIKgvGPAEALqbEmxnwNrprHnMHzsIyiktFcepsplBJqbwOqxsMtwCikGwvblpxsIosfrMuyvDmsFgBsswazzIaDyDbmxVNGQbxLkxraCpDyprJDyhxIEuwMJzLqGeznkHmptICpemxvNrznCLgkCCriwjsmuNsfvynwvDexLoInGjqAtrkuOlohNBIyNvIKABpvqryyxnwClueHqJISjIMpwJznXoIDnJTzvAuANwSJHyknjGDZlsLeqMtueQuCzDPzyARFJAvFuIhEPrirIJsCTstEqxysvfDxNoKMCjhylIIVpCRioEQxrCtLnxJCtiIEuBXuwGpqdznhpuIhqIrjrAnLCTosRjyFyqAtiNoKHpbrCGQvzuNMwClAmVzzGeqGwzeLrHHFpxLikHsHXyDLhuMpBvyLIIQfpJnIrGrkrmDmuvquiLJuFCtHFgkDCnaxjneqCTteCqcADbCRkDEGxFHfHnJGJjrAGIvDsXPgkwDHativoxJxfezGyFVbGBuRFJAvFuCoMdDbmxgBsSixLiCDLjoEnCgiCpseHnHrApJEjDswAqthzeJvyekIGvoBlDLvrpyxaofBcqMCpyMrFxTtIGpDtEnQsjCsxzHbpErxoKmIFgGlQjozzCdyOEjpFFBsFpIFgBzOwezwHervnlXBrHGGfvMvyyACPsjLaLzousGruBCJLyxootjZvGDyyOmfkuANCQbxLnsvwjYlxIaHyTofOpEsStXQyolJClRtsABGEiiJnLsMuHypnxGCepwHaDypwiLLvCCzLCpDzNnolsssJJzevCtBHTosCtDswAlzkDfJCpdeLEIIRfAQqDswHtzzAdDOrfxMBuyDeIMvrpKtfytGaDTEimHtvISJHRwmvsAlFssoDOsffyAwvEpGOwsEwjtsnAeYBzutLrNHXtDymsyyFbEjHpuxtbpFLGMMfrIcxoEHmlsIscTsvrNvHuGbIPgkwDHdlAtmuLFjxynFCSpuNtyEwlqttCiDvHbCvHNWFpIQqkvwmXyDLaOdojhHGwoQfIFqErzRcpqIsEylnrBnJDXbAJqpDMmapsIhuRlzsFqjvNfqCmoALpltsvaHJFohuAxoQpJLfSHsBalrCnuvCceQyCBFJuCnDDGmXxswaFKJjjSBOKzoIRquyGFqsjIrKOsJhIANyMpLUjITLFXDoJsJOsbxMuyzNpzCfCzvjjysxcuOsfAuLMvDltNvqzAwdlwDuDylohuEIIMexLjoCturphDaJvyeeFyaCCJLGurJGDZzzAdLzmfiHGBsQfiFcDDsuiTrvoyIrusNrFzzcDSvSnGDiouGorvmmCNrFzXpJUjkEamfofutuMTxiHGBCLfpLfrzORdzyHisFlohuyFoMeLFcDDuqlzqXmIPAqsMrxHNhDRqxpPCclqAavOpsMArNCTuDDjoCwkrENsoDOqfiFyCyDjIgtolDuvotCtjCluwNHztCptQpDtFCbCjHtCzEpsGHwvQjvFvxzOJizyDfFzzqpyrMDDdxynvJLqfDtCeFNJdlInHoKzHRiEJLqbJmpvuCpsiEryDRbHIkxrEnfqNBgEDyheJCFMLzHCnpHznkTlDbqxvusMpBCNmCCzDdwyqprqeHdEtwOpBoRuJNknBMnpEnDnyIxzsJvHwNoXKgkyzxtotNoKFypAQuuHXpJPgqzAwdEtsoJDwmCIHxCHuiFgkyKFbCnHyEPoprNVNvHozgcwmMCezBsoYFypAcFQszsxRukDLDmtiFuuNEjsHQVwRoIyullvjpEmtruNEpjNuyAAvIFgupwyplxziDBxfeFBNCErJCuDtGwpEtDHuyCpzyBPsQmpQvclLDoofNwyOsulCFYBFmxQjlltnqsfIsyIEimMAyKOjrRwBpznpHwxtyIrTlyJuGOstRvIlxobnytdrPEwiLLACNeAMqutFpxyDLaOJyfxCzyKGfCQjoHwwqEtIhuGlemyFLCNnLyADswqbwqsoMItoxBrIHGfGUkxrVKXDptdCzHieNVNvNvvFvkmGDqlqAtxDDtxOszWIvHRhsyABepiIeBGtokSBOoApJRKntvwqvsDwMCluxBrBsKmIMukJaovzzLaDOEpoHBQHGfIPwDsamlyyznERHieNVNvHozydyFLrqTrHoHMJJxIyxGNnpLAzpGyipfqoKOtuEvBOHzmAgmxzOrpTxDrJJqnmMFyJDsNzqnJaClwipbEPEFzyAIzCTIPcnwsCbCfCdQxvmiSsIFHoHRcxnwRqsnCkYzGfrGvMGSipRiyovjjXfJryxpJxMsOBMzSMpDpNnoEjAlqIJcsxLuBXuwGpqTxHlFiDyEPDueLGGwRtxLioGwAvmtsy'
key = 'vlbeunuozbpycklsjxlfpaq'
c = {}
count = {}
for i in range(len(key)):
    c[key[i]] = 0
    count[key[i]] = 0
for i in range(len(cipher)):
    c[key[i % len(key)]] += 1
    if (ctoi(cipher[i]) - ctoi(key[i % len(key)])) < 0:
        count[key[i % len(key)]] += 1
print(c)
print(count)
```

结果为：
![在这里插入图片描述](luozj1020 vacation_week2.assets/e3ee7edd25df4359b19cd3bdbff4049c.png)
容易看出只有'x'符合条件
从解题人的角度老老实实地解的话，可以参考[另一位师傅的wp](https://blog.csdn.net/weixin_44110537/article/details/107446238)，这里不再赘述
但仅仅解出这道题是不够的
如这位师傅在wp中分析的，维吉尼亚密码爆破需要经历三个过程
1、Kasiski 实验，通过查找相同的子串(3个字符以上)来猜测可能的key的长度
2、重合指数攻击，通过计算重合指数，进一步确定key的长度
3、字母频率分析，根据英文文档中各个字母的出现频率来推算key的内容

这里提供一个用python写的[爆破脚本示例](https://blog.csdn.net/Ni9htMar3/article/details/53371817)，具体原理也可参照[wiki](https://zh.wikipedia.org/wiki/%E7%BB%B4%E5%90%89%E5%B0%BC%E4%BA%9A%E5%AF%86%E7%A0%81)，这里不再赘述
关键是，如本题所示，如果加密用的字母表（本题为ascii_letters即包含大小写共52个字母），不是经典维吉尼亚密码的26个顺序字母，是否能用类似方法破解？
我们假设加密的内容都是有意义的英文文本，这里讨论三种情况：



### 1、乱序小写字母表

Kasiski实验至于密文有关，通过查找相同的子串(3个字符以上)来猜测可能的key的长度，因此没有影响
由于字母还是那26个字母，重合指数与各个字母的出现频率都是不变的，所以重合指数攻击和字母频率分析依然可以进行
所以上述爆破方法仍适用



### 2、缺失的字母表

同样，Kasiski实验至于密文有关，没有影响
但是，由于字母的缺失，重合指数与各个字母的出现频率与正常的英文文本不相同，所以无法进行
因此上述爆破方法并不适用
key做到避开某些字母是容易的，但是一段有意义的英文文本完全避开一些字面是困难的
但如果仅仅避开一些出现频率不高的字母（如'x','z'，频率只有0.001），上述爆破方法还是适用的



### 3、混入大写字母的小写字母表（或是混入小写字母的大写字母表）

这又会有两种情况
一种是原文的这些混入字母也是大写的（这样做可能是为了和key契合，或者混淆视听），那么只要把全部字母换成小写爆破就行
另一种就是原文特意避开这些字母，和第2种情况不同的是，key中可能含有这些大写字母，那就只要把key和字母表里的大写字母都换成小写，如果仅仅原文避开了一些出现频率不高的字母，仍然可以爆破

# 2021-7-24

## [SUCTF2019]MT

来填坑了
首先看加密代码：

```python
from Crypto.Util import number
from flag import flag

def convert(m):
    m = m ^ m >> 13
    m = m ^ m << 9 & 2029229568
    m = m ^ m << 17 & 2245263360
    m = m ^ m >> 19
    return m

def transform(message):
    assert len(message) % 4 == 0
    new_message = ''
    for i in range(len(message) / 4):
        block = message[i * 4 : i * 4 +4]
        block = number.bytes_to_long(block)
        block = convert(block)
        block = number.long_to_bytes(block, 4)
        new_message += block
    return new_message

transformed_flag = transform(flag[5:-1].decode('hex')).encode('hex')
print 'transformed_flag:', transformed_flag
# transformed_flag: 641460a9e3953b1aaa21f3a2
```

看到这个```convert```函数，我就有些胆怯了
这个位运算看起来完全打乱了加密内容（而且之前碰到类似的题目都没做出来）
尤其是第二三步，感觉完全乱了
看了一眼[别人的wp](https://blog.csdn.net/m0_49109277/article/details/117324488)，受到了启发
发现```bin(2029229568)```后9位都是0，而```bin(2245263360)```后17位(其实是18位)都是0，与移位的位数相同，那就好办了
首先要明确一件事：位运算符的优先级 移位(>>和<<) > 与运算(&) > 异或运算(^)
就以'abcd'为例，推出第四和第三步的解密过程（第一和第二步同理）
因为我没有装python2的环境，就用python3把加密代码重写了一遍，做了一点小修改
代码如下：

```python
from Crypto.Util.number import *

flag = 'abcd'

def convert(m):
    m = m ^ m >> 13
    m = m ^ m << 9 & 2029229568
    m = m ^ m << 17 & 2245263360
    m = m ^ m >> 19
    return m

def transform(message):
    assert len(message) % 4 == 0
    new_message = ''
    for i in range(len(message) // 4):
        block = message[i * 4: i * 4 + 4]
        block = bytes_to_long(block.encode())
        block = convert(block)
        block = bin(block)[2:].zfill(32)
        new_message += block
    return long_to_bytes(int(new_message, 2))

cipher = transform(flag)
```



### 第四步操作

首先要知道，">>"是二进制位向右移动，低位丢弃，高位补0
经过前三步加密的二进制结果为（当然，解密时以下结果是未知的）：
**10100101011101011110111001110111**记为m4
那么 m4>>19 的结果为
**0000000000000000000101001010111** 01011110111001110111
                        高位补0<-                               ->低位丢弃
接下来是异或运算
解密需要用到异或运算的两个性质：
1、若a=b ^ c，则c=a ^ b
2、a=a ^ 0
```cipher=m4 ^ m4 >> 19```，其中cipher是已知的
按位加密的过程中，m4的前19位都是和0做异或运算，也就是说加密结果cipher的前19位与m4是相同的，由此可以得到m4的前19位
又因为**m4后13位 ^ m4>>19的后13位 = m4后13位 ^ m4的前13位 = cipher的后13位**
所以**cipher的后13位 ^ m4的前13位 = m4后13位**
由此可以得到完整的m4
解密代码如下：

```python
block = bytes_to_long((cipher[i * 4: i * 4 + 4]))
block = bin(block)[2:].zfill(32)
# step4 decode
m4 = block[:19] + bin(int(block[:13], 2) ^ int(block[19:], 2))[2:].zfill(13)
print(m4)
print(long_to_bytes(int(m4, 2)))
```



### 第三步操作

首先要知道，"<<"是二进制位向左移动，高位丢弃，低位补0；"&"是按位做与运算，有0出0，全1出1
经过前两步加密的二进制结果为（当然，解密时以下结果是未知的）：
**00100001101100011110111001110111**记为m3
00100001101100011 **11011100111011100000000000000000**
                     高位丢弃<-                                 ->低位补0
接下来是与运算
首先看bin(2245263360)='0b**10000101110101000000000000000000**'
发现2245263360的后17位都是0
那么，**m3<<17的后17位 & 2245263360的后17位 = 00000000000000000(17个0)**
与第四步解密操作相同，就可以得到m3的后17位就是m4的后17位
又因为**m3前15位 ^ m3<<17的前15位 & 2245263360的前15位 = m3前15位 ^ m3的后15位 & 2245263360的前15位 = m4的前15位**
由此可以得到完整的m3
解密代码如下：

```python
# step3 decode
block = m4
m3 = bin((int(block[17:], 2) & int(bin(2245263360)[2:].zfill(32)[:15], 2)) ^ int(block[:15], 2))[2:].zfill(15) + block[15:]
print(m3)
print(long_to_bytes(int(m3, 2)))
```

第二和第一步的解密类似，就是需要重复操作几次
完整的测试解密代码如下：

```python
from Crypto.Util.number import *

flag = 'abcd'

def convert(m):
    m = m ^ m >> 13
    m = m ^ m << 9 & 2029229568
    m = m ^ m << 17 & 2245263360
    m = m ^ m >> 19
    return m

def transform(message):
    assert len(message) % 4 == 0
    new_message = ''
    for i in range(len(message) // 4):
        block = message[i * 4: i * 4 + 4]
        block = bytes_to_long(block.encode())
        block = convert(block)
        block = bin(block)[2:].zfill(32)
        new_message += block
    return long_to_bytes(int(new_message, 2))

cipher = transform(flag)
print(bin(bytes_to_long(cipher))[2:].zfill(32))
print(cipher)
plain = ''
for i in range(len(cipher) // 4):
    block = bytes_to_long((cipher[i * 4: i * 4 + 4]))
    block = bin(block)[2:].zfill(32)
    # step4 decode
    m4 = block[:19] + bin(int(block[:13], 2) ^ int(block[19:], 2))[2:].zfill(13)
    print(m4)
    print(long_to_bytes(int(m4, 2)))
    # step3 decode
    block = m4
    m3 = bin((int(block[17:], 2) & int(bin(2245263360)[2:].zfill(32)[:15], 2)) ^ int(block[:15], 2))[2:].zfill(15) + block[15:]
    print(m3)
    print(long_to_bytes(int(m3, 2)))
    # step2 decode
    block = m3
    m2 = bin((int(block[23:], 2) & int(bin(2029229568)[2:].zfill(32)[14:23], 2)) ^ int(block[14:23], 2))[2:].zfill(9) + block[23:]
    block = m3[:14] + m2
    m2 = bin((int(block[14:23], 2) & int(bin(2029229568)[2:].zfill(32)[5:14], 2)) ^ int(block[5:14], 2))[2:].zfill(9) + block[14:]
    block = m3[:5] + m2
    m2 = bin((int(block[9:14], 2) & int(bin(2029229568)[2:].zfill(32)[:5], 2)) ^ int(block[:5], 2))[2:].zfill(5) + block[5:]
    print(m2)
    print(long_to_bytes(int(m2, 2)))
    # step1 decode
    block = m2
    m1 = block[:13] + bin(int(block[:13], 2) ^ int(block[13:26], 2))[2:].zfill(13)
    block = m1 + block[26:]
    m1 = block[:26] + bin(int(block[13:19], 2) ^ int(block[26:], 2))[2:].zfill(6)
    print(m1)
    print(long_to_bytes(int(m1, 2)))
    plain += m1
print(long_to_bytes(int(plain, 2)))
```

结果是对的
![在这里插入图片描述](luozj1020 vacation_week2.assets/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70.png)
然后就把测试解密的代码应用于transformed_flag上
这里有个地方有点麻烦，就是原加密代码还要一步：```transformed_flag = transform(flag[5:-1].decode('hex')).encode('hex')```
而python3没有```decode('hex')```和```encode('hex')```，可以参考[Python3 字符串与hex之间的相互转换](https://www.cnblogs.com/zhaijiahui/p/9597935.html)
```.decode('hex')```对应于```bytes.fromhex()```，```.encode('hex')```对应于```.hex()```
所以，完整的解密代码如下：

```python
from Crypto.Util.number import *

cipher = bytes.fromhex('641460a9e3953b1aaa21f3a2')
print(cipher)
plain = ''
for i in range(len(cipher) // 4):
    block = bytes_to_long((cipher[i * 4: i * 4 + 4]))
    block = bin(block)[2:].zfill(32)
    # step4 decode
    m4 = block[:19] + bin(int(block[:13], 2) ^ int(block[19:], 2))[2:].zfill(13)
    print(m4)
    print(long_to_bytes(int(m4, 2)))
    # step3 decode
    block = m4
    m3 = bin((int(block[17:], 2) & int(bin(2245263360)[2:].zfill(32)[:15], 2)) ^ int(block[:15], 2))[2:].zfill(15) + block[15:]
    print(m3)
    print(long_to_bytes(int(m3, 2)))
    # step2 decode
    block = m3
    m2 = bin((int(block[23:], 2) & int(bin(2029229568)[2:].zfill(32)[14:23], 2)) ^ int(block[14:23], 2))[2:].zfill(9) + block[23:]
    block = m3[:14] + m2
    m2 = bin((int(block[14:23], 2) & int(bin(2029229568)[2:].zfill(32)[5:14], 2)) ^ int(block[5:14], 2))[2:].zfill(9) + block[14:]
    block = m3[:5] + m2
    m2 = bin((int(block[9:14], 2) & int(bin(2029229568)[2:].zfill(32)[:5], 2)) ^ int(block[:5], 2))[2:].zfill(5) + block[5:]
    print(m2)
    print(long_to_bytes(int(m2, 2)))
    # step1 decode
    block = m2
    m1 = block[:13] + bin(int(block[:13], 2) ^ int(block[13:26], 2))[2:].zfill(13)
    block = m1 + block[26:]
    m1 = block[:26] + bin(int(block[13:19], 2) ^ int(block[26:], 2))[2:].zfill(6)
    print(m1)
    print(long_to_bytes(int(m1, 2)))
    plain += m1
print(long_to_bytes(int(plain, 2)))
print(long_to_bytes(int(plain, 2)).hex())
```

结果为：
![在这里插入图片描述](luozj1020 vacation_week2.assets/ab316bbef8154b5b9629ca48f7b1efa9.png)
即为flag



### 未曾设想的道路

正如wp中所说，还有一种通过反复加密得到结果的解法
这里给出python3的代码：

```python
from Crypto.Util.number import *

def convert(m):
    m = m ^ m >> 13
    m = m ^ m << 9 & 2029229568
    m = m ^ m << 17 & 2245263360
    m = m ^ m >> 19
    return m

def transform(message):
    assert len(message) % 4 == 0
    new_message = b''
    for i in range(len(message) // 4):
        block = message[i * 4: i * 4 + 4]
        block = bytes_to_long(block)
        block = convert(block)
        block = long_to_bytes(block, 4)
        new_message += block
    return new_message

transformed_flag = '641460a9e3953b1aaa21f3a2'
cipher = bytes.fromhex('641460a9e3953b1aaa21f3a2')
# assert (transform(bytes.fromhex('84b45f89af22ce7e67275bdc')).hex() == transformed_flag)
c = cipher
s = set()
while True:
    c = transform(c.zfill(len(cipher)))
    print(c.hex())
    s.add(c.hex())
    print(len(s))
    if c.hex() == transformed_flag:
        break
```

至于为什么，是因为本题使用的加密算法是[梅森旋转算法（Mersenne twister）](https://zh.wikipedia.org/zh-cn/%E6%A2%85%E6%A3%AE%E6%97%8B%E8%BD%AC%E7%AE%97%E6%B3%95)，是一种伪随机数生成算法，该算法的一个更新的和更常用的是MT19937, 32位字长，对应了题目
并且该算法生成的随机数具有周期性，这也就不难理解为什么一直加密密文能得到明文，因为经过一个周期后得到的还是密文，那么上一个就是明文了
上述解密代码结果为：
![在这里插入图片描述](luozj1020 vacation_week2.assets/3580010fbd854aa38576b6f24675a5d6.png)
不难发现其周期为61319

更多关于MT19937伪随机数生成算法的体型可以参考madmonkey前辈的[浅析mt19937伪随机数生成算法](https://badmonkey.site/archives/mt19937.html#%E6%B5%85%E6%9E%90mt19937%E4%BC%AA%E9%9A%8F%E6%9C%BA%E6%95%B0%E7%94%9F%E6%88%90%E7%AE%97%E6%B3%95)
其中介绍了与第一种方法相同的解法，只不过和wp一样采用模块化的代码，将解密步骤打包成函数
这里给出参照其中代码的解密代码：

```python
from Crypto.Util.number import *

# right shift inverse
def inverse_right(res, shift, bits=32):
    tmp = res
    for i in range(bits // shift):
        tmp = res ^ tmp >> shift
    return tmp


# right shift with mask inverse
def inverse_right_mask(res, shift, mask, bits=32):
    tmp = res
    for i in range(bits // shift):
        tmp = res ^ tmp >> shift & mask
    return tmp

# left shift inverse
def inverse_left(res, shift, bits=32):
    tmp = res
    for i in range(bits // shift):
        tmp = res ^ tmp << shift
    return tmp


# left shift with mask inverse
def inverse_left_mask(res, shift, mask, bits=32):
    tmp = res
    for i in range(bits // shift):
        tmp = res ^ tmp << shift & mask
    return tmp


def extract_number(y):
    y = y ^ y >> 11
    y = y ^ y << 7 & 2636928640
    y = y ^ y << 15 & 4022730752
    y = y ^ y >> 18
    return y & 0xffffffff

def recover(y):
    y = inverse_right(y, 19)
    y = inverse_left_mask(y, 17, 2245263360)
    y = inverse_left_mask(y, 9, 2029229568)
    y = inverse_right(y, 13)
    return y & 0xffffffff

transformed_flag = '641460a9e3953b1aaa21f3a2'
cipher = bytes.fromhex('641460a9e3953b1aaa21f3a2')
new_message = b''
for i in range(len(cipher) // 4):
    block = cipher[i * 4: i * 4 + 4]
    block = bytes_to_long(block)
    block = recover(block)
    block = long_to_bytes(block, 4)
    new_message += block
print(new_message.hex())
```

结果是相同的：
![在这里插入图片描述](luozj1020 vacation_week2.assets/6b4452713e6c4479b4bf6b97211f4e2e.png)
另一种方法是**黑箱方法**，将密文和明文的二进制编码视为两个向量$a,b$，而由加密方法可知，两个向量存在线性关系，即存在一个方阵$M$，使得$a=Mb$
具体线性关系如下：
![在这里插入图片描述](luozj1020 vacation_week2.assets/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70.png)
这种方法没怎么看懂，以后有机会再说（溜了溜了）

# 2021-7-25

## [UTCTF2020]OTP

就给了个加密文件：
![在这里插入图片描述](luozj1020 vacation_week2.assets/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70.png)
一头雾水
搜了搜OTP是什么意思，谷歌给的第一个是One Time Password，这让我怎么搞？
一次一密？也不像啊
找了找[wp](https://blog.csdn.net/weixin_44110537/article/details/107619513)
![在这里插入图片描述](luozj1020 vacation_week2.assets/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70.png)
啊这
他的文件怎么和我不一样啊？
不管，先试试
![在这里插入图片描述](luozj1020 vacation_week2.assets/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70.png)
啊这
那没事了

