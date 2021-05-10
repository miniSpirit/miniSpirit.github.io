# week 5-6

# 2021-4-26

## babyRSA

加密代码如下：

```python
import sympy
import random

def myGetPrime():
    A= getPrime(513)
    print(A)
    B=A-random.randint(1e3,1e5)
    print(B)
    return sympy.nextPrime((B!)%A)
p=myGetPrime()
#A1=21856963452461630437348278434191434000066076750419027493852463513469865262064340836613831066602300959772632397773487317560339056658299954464169264467234407
#B1=21856963452461630437348278434191434000066076750419027493852463513469865262064340836613831066602300959772632397773487317560339056658299954464169264467140596

q=myGetPrime()
#A2=16466113115839228119767887899308820025749260933863446888224167169857612178664139545726340867406790754560227516013796269941438076818194617030304851858418927
#B2=16466113115839228119767887899308820025749260933863446888224167169857612178664139545726340867406790754560227516013796269941438076818194617030304851858351026

r=myGetPrime()

n=p*q*r
#n=85492663786275292159831603391083876175149354309327673008716627650718160585639723100793347534649628330416631255660901307533909900431413447524262332232659153047067908693481947121069070451562822417357656432171870951184673132554213690123308042697361969986360375060954702920656364144154145812838558365334172935931441424096270206140691814662318562696925767991937369782627908408239087358033165410020690152067715711112732252038588432896758405898709010342467882264362733
c=pow(flag,e,n)
#e=0x1001
#c=75700883021669577739329316795450706204502635802310731477156998834710820770245219468703245302009998932067080383977560299708060476222089630209972629755965140317526034680452483360917378812244365884527186056341888615564335560765053550155758362271622330017433403027261127561225585912484777829588501213961110690451987625502701331485141639684356427316905122995759825241133872734362716041819819948645662803292418802204430874521342108413623635150475963121220095236776428
#so,what is the flag?
```

三元的 RSA 就没解出来过[捂脸]
参考博客：[https://www.cnblogs.com/jane315/p/13805724.html](https://www.cnblogs.com/jane315/p/13805724.html)
看到阶乘，没想到威尔逊定理
p,q,r = nextPrime((B!)%A)
先上威尔逊定理：
若 $p$ 是素数，则
$$
(p-1)! \equiv -1 \space mod \space p
$$
有加密代码可得 $A$ 是素数，且 $B$ 小于 $A$
方法一：
$$
p(B+1)(B+2)\cdots(A-1) \equiv (A-1)! \equiv -1 \space mod \space A
$$
即
$$
p[-(B+1)(B+2)\cdots(A-1)]\equiv 1 \space mod \space A
$$
即 $p$ 是 $-(B+1)(B+2)\cdots(A-1)$ 模 $A$ 的逆元
求 $p,q$ 的函数如下：

```python
def get(a, b): # 求p,q
    k = 1
    for i in range(b+1, a):
        k *= i
        k %= a
    return next_prime((-inverse(k, a))%a)
```

方法二：
利用威尔逊定理的推论：
$$
(p-2)! \equiv 1 \space mod \space p
$$
推理过程如下：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210426233101517.png)
来源于 [wiki](https://zh.wikipedia.org/wiki/%E5%A8%81%E5%B0%94%E9%80%8A%E5%AE%9A%E7%90%86)
求 $p,q$ 的函数如下：

```python
def get(a, b): # 求p,q
    k = 1
    for i in range(b+1, a-1):
        k *= i
        k %= a
    return next_prime(inverse(k, a))
```

解密代码如下：

```python
from Crypto.Util.number import *
from gmpy2 import *

A1 = 21856963452461630437348278434191434000066076750419027493852463513469865262064340836613831066602300959772632397773487317560339056658299954464169264467234407
B1 = 21856963452461630437348278434191434000066076750419027493852463513469865262064340836613831066602300959772632397773487317560339056658299954464169264467140596
A2 = 16466113115839228119767887899308820025749260933863446888224167169857612178664139545726340867406790754560227516013796269941438076818194617030304851858418927
B2 = 16466113115839228119767887899308820025749260933863446888224167169857612178664139545726340867406790754560227516013796269941438076818194617030304851858351026
n = 85492663786275292159831603391083876175149354309327673008716627650718160585639723100793347534649628330416631255660901307533909900431413447524262332232659153047067908693481947121069070451562822417357656432171870951184673132554213690123308042697361969986360375060954702920656364144154145812838558365334172935931441424096270206140691814662318562696925767991937369782627908408239087358033165410020690152067715711112732252038588432896758405898709010342467882264362733
e = int('0x1001', 16)
c = 75700883021669577739329316795450706204502635802310731477156998834710820770245219468703245302009998932067080383977560299708060476222089630209972629755965140317526034680452483360917378812244365884527186056341888615564335560765053550155758362271622330017433403027261127561225585912484777829588501213961110690451987625502701331485141639684356427316905122995759825241133872734362716041819819948645662803292418802204430874521342108413623635150475963121220095236776428

def get(a, b): # 求p,q

p = get(A1, B1)
q = get(A2, B2)
r = (n // p) // q
phi = (p-1)*(q-1)*(r-1)
d = inverse(e, phi)
m = pow(c, d, n)
print(long_to_bytes(m))
```

get 函数忘记加 next_prime 然后搞了半天[捂脸]

# 2021-4-27

## RSA

附件如下：

```python
A=(((y%x)**5)%(x%y))**2019+y**316+(y+1)/x
p=next_prime(z*x*y)
q=next_prime(z)
A =  2683349182678714524247469512793476009861014781004924905484127480308161377768192868061561886577048646432382128960881487463427414176114486885830693959404989743229103516924432512724195654425703453612710310587164417035878308390676612592848750287387318129424195208623440294647817367740878211949147526287091298307480502897462279102572556822231669438279317474828479089719046386411971105448723910594710418093977044179949800373224354729179833393219827789389078869290217569511230868967647963089430594258815146362187250855166897553056073744582946148472068334167445499314471518357535261186318756327890016183228412253724
n =  117930806043507374325982291823027285148807239117987369609583515353889814856088099671454394340816761242974462268435911765045576377767711593100416932019831889059333166946263184861287975722954992219766493089630810876984781113645362450398009234556085330943125568377741065242183073882558834603430862598066786475299918395341014877416901185392905676043795425126968745185649565106322336954427505104906770493155723995382318346714944184577894150229037758434597242564815299174950147754426950251419204917376517360505024549691723683358170823416757973059354784142601436519500811159036795034676360028928301979780528294114933347127
c =  41971850275428383625653350824107291609587853887037624239544762751558838294718672159979929266922528917912189124713273673948051464226519605803745171340724343705832198554680196798623263806617998072496026019940476324971696928551159371970207365741517064295956376809297272541800647747885170905737868568000101029143923792003486793278197051326716680212726111099439262589341050943913401067673851885114314709706016622157285023272496793595281054074260451116213815934843317894898883215362289599366101018081513215120728297131352439066930452281829446586562062242527329672575620261776042653626411730955819001674118193293313612128
```

拿到 n ，先[爆破](http://factordb.com/)：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210427233142596.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
得到 p,q
但是没给 e
没想法。。。
找 [wp](https://paper.seebug.org/1059/#rsa)
爆破出 e=65537
啊这。。。
代码如下：

```python
from Crypto.Util.number import *
from gmpy2 import *

p = 842868045681390934539739959201847552284980179958879667933078453950968566151662147267006293571765463137270594151138695778986165111380428806545593588078365331313084230014618714412959584843421586674162688321942889369912392031882620994944241987153078156389470370195514285850736541078623854327959382156753458569
q = 139916095583110895133596833227506693679306709873174024876891023355860781981175916446323044732913066880786918629089023499311703408489151181886568535621008644997971982182426706592551291084007983387911006261442519635405457077292515085160744169867410973960652081452455371451222265819051559818441257438021073941183
n =  117930806043507374325982291823027285148807239117987369609583515353889814856088099671454394340816761242974462268435911765045576377767711593100416932019831889059333166946263184861287975722954992219766493089630810876984781113645362450398009234556085330943125568377741065242183073882558834603430862598066786475299918395341014877416901185392905676043795425126968745185649565106322336954427505104906770493155723995382318346714944184577894150229037758434597242564815299174950147754426950251419204917376517360505024549691723683358170823416757973059354784142601436519500811159036795034676360028928301979780528294114933347127
c =  41971850275428383625653350824107291609587853887037624239544762751558838294718672159979929266922528917912189124713273673948051464226519605803745171340724343705832198554680196798623263806617998072496026019940476324971696928551159371970207365741517064295956376809297272541800647747885170905737868568000101029143923792003486793278197051326716680212726111099439262589341050943913401067673851885114314709706016622157285023272496793595281054074260451116213815934843317894898883215362289599366101018081513215120728297131352439066930452281829446586562062242527329672575620261776042653626411730955819001674118193293313612128

e = 65537
phi = (p-1)*(q-1)
d = inverse(e, phi)
m = long_to_bytes(pow(c, d, n))
print(m)
```

（wp 爆破 x,y，我直接爆破 p,q，结果是一样的。嗯，就这样）

# 2021-4-28

## 可怜的RSA

附件给了公钥：

```python
-----BEGIN PUBLIC KEY-----
MIIBJDANBgkqhkiG9w0BAQEFAAOCAREAMIIBDAKCAQMlsYv184kJfRcjeGa7Uc/4
3pIkU3SevEA7CZXJfA44bUbBYcrf93xphg2uR5HCFM+Eh6qqnybpIKl3g0kGA4rv
tcMIJ9/PP8npdpVE+U4Hzf4IcgOaOmJiEWZ4smH7LWudMlOekqFTs2dWKbqzlC59
NeMPfu9avxxQ15fQzIjhvcz9GhLqb373XDcn298ueA80KK6Pek+3qJ8YSjZQMrFT
+EJehFdQ6yt6vALcFc4CB1B6qVCGO7hICngCjdYpeZRNbGM/r6ED5Nsozof1oMbt
Si8mZEJ/Vlx3gathkUVtlxx/+jlScjdM7AFV5fkRidt0LkwosDoPoRz/sDFz0qTM
5q5TAgMBAAE=
-----END PUBLIC KEY-----
```

提取公钥代码如下：

```python
from Crypto.PublicKey import RSA

with open("public.key","r") as f:
    key = RSA.import_key(f.read())
    print(key.n)
    print(key.e)
```

得到

```python
e = 65537
n = 79832181757332818552764610761349592984614744432279135328398999801627880283610900361281249973175805069916210179560506497075132524902086881120372213626641879468491936860976686933630869673826972619938321951599146744807653301076026577949579618331502776303983485566046485431039541708467141408260220098592761245010678592347501894176269580510459729633673468068467144199744563731826362102608811033400887813754780282628099443490170016087838606998017490456601315802448567772411623826281747245660954245413781519794295336197555688543537992197142258053220453757666537840276416475602759374950715283890232230741542737319569819793988431443
```

然后[爆破](http://factordb.com/)就可以求出 p,q
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210428222452204.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)

```python
p = 3133337
q = 25478326064937419292200172136399497719081842914528228316455906211693118321971399936004729134841162974144246271486439695786036588117424611881955950996219646807378822278285638261582099108339438949573034101215141156156408742843820048066830863814362379885720395082318462850002901605689761876319151147352730090957556940842144299887394678743607766937828094478336401159449035878306853716216548374273462386508307367713112073004011383418967894930554067582453248981022011922883374442736848045920676341361871231787163441467533076890081721882179369168787287724769642665399992556052144845878600126283968890273067575342061776244939
```

附件密文如下：

```python
GVd1d3viIXFfcHapEYuo5fAvIiUS83adrtMW/MgPwxVBSl46joFCQ1plcnlDGfL19K/3PvChV6n5QGohzfVyz2Z5GdTlaknxvHDUGf5HCukokyPwK/1EYU7NzrhGE7J5jPdi0Aj7xi/Odxy0hGMgpaBLd/nL3N8O6i9pc4Gg3O8soOlciBG/6/xdfN3SzSStMYIN8nfZZMSq3xDDvz4YB7TcTBh4ik4wYhuC77gmT+HWOv5gLTNQ3EkZs5N3EAopy11zHNYU80yv1jtFGcluNPyXYttU5qU33jcp0Wuznac+t+AZHeSQy5vk8DyWorSGMiS+J4KNqSVlDs12EqXEqqJ0uA==
```

容易发现经过了 base64 加密
尝试解密：

```python
import base64
from Crypto.Util.number import *
# p,q,n,e
c = bytes_to_long(base64.b64decode(b'GVd1d3viIXFfcHapEYuo5fAvIiUS83adrtMW/MgPwxVBSl46joFCQ1plcnlDGfL19K/3PvChV6n5QGohzfVyz2Z5GdTlaknxvHDUGf5HCukokyPwK/1EYU7NzrhGE7J5jPdi0Aj7xi/Odxy0hGMgpaBLd/nL3N8O6i9pc4Gg3O8soOlciBG/6/xdfN3SzSStMYIN8nfZZMSq3xDDvz4YB7TcTBh4ik4wYhuC77gmT+HWOv5gLTNQ3EkZs5N3EAopy11zHNYU80yv1jtFGcluNPyXYttU5qU33jcp0Wuznac+t+AZHeSQy5vk8DyWorSGMiS+J4KNqSVlDs12EqXEqqJ0uA=='))

phi = (p-1)*(q-1)
d = inverse(e, phi)
m = pow(c, d, n)

print(long_to_bytes(m))
```

发现是一堆乱码
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210428222655128.png)
嗯？
最后求助 [wp](https://www.cnblogs.com/vict0r/p/13764404.html)
代码如下：

```python
from Crypto.Cipher import PKCS1_OAEP
import base64
from Crypto.Util.number import *
# p,q,n,e
c = base64.b64decode(b'GVd1d3viIXFfcHapEYuo5fAvIiUS83adrtMW/MgPwxVBSl46joFCQ1plcnlDGfL19K/3PvChV6n5QGohzfVyz2Z5GdTlaknxvHDUGf5HCukokyPwK/1EYU7NzrhGE7J5jPdi0Aj7xi/Odxy0hGMgpaBLd/nL3N8O6i9pc4Gg3O8soOlciBG/6/xdfN3SzSStMYIN8nfZZMSq3xDDvz4YB7TcTBh4ik4wYhuC77gmT+HWOv5gLTNQ3EkZs5N3EAopy11zHNYU80yv1jtFGcluNPyXYttU5qU33jcp0Wuznac+t+AZHeSQy5vk8DyWorSGMiS+J4KNqSVlDs12EqXEqqJ0uA==')

phi = (p-1)*(q-1)
d = inverse(e, phi)
key_info = RSA.construct((n, e, d, p, q))
key = RSA.importKey(key_info.exportKey())
key = PKCS1_OAEP.new(key)
print(key.decrypt(c))
```

结果为：afctf{R54_|5_$0_B0rin9}
啊这
多西得？
我们知道，
Crypto.Util 包中 long_to_bytes 方法是将字符串转化成二进制然后转化成十进制
示例如下：

```python
>>> from Crypto.Util.number import *
>>> print(bytes_to_long(b'AB'))
16706
>>> print(bin(ord('A')))
0b1000001
>>> print(bin(ord('B')))
0b1000010
>>> print(hex(ord('A')))
0x41
>>> print(hex(ord('B')))
0x42
>>> print(int('4142',16))
16706
>>> print(int('100000101000010',2))
16706
```

然后我又找了 Crypto.Cipher 包中的 decrypt 方法[源码](https://github.com/Legrandin/pycryptodome/blob/master/lib/Crypto/Cipher/PKCS1_OAEP.py)

```python
    def decrypt(self, ciphertext):
        """Decrypt a message with PKCS#1 OAEP.
        :param ciphertext: The encrypted message.
        :type ciphertext: bytes/bytearray/memoryview
        :returns: The original message (plaintext).
        :rtype: bytes
        :raises ValueError:
            if the ciphertext has the wrong length, or if decryption
            fails the integrity check (in which case, the decryption
            key is probably wrong).
        :raises TypeError:
            if the RSA key has no private half (i.e. you are trying
            to decrypt using a public key).
        """

        # See 7.1.2 in RFC3447
        modBits = Crypto.Util.number.size(self._key.n)
        k = ceil_div(modBits,8) # Convert from bits to bytes
        hLen = self._hashObj.digest_size

        # Step 1b and 1c
        if len(ciphertext) != k or k<hLen+2:
            raise ValueError("Ciphertext with incorrect length.")
        # Step 2a (O2SIP)
        ct_int = bytes_to_long(ciphertext)
        # Step 2b (RSADP)
        m_int = self._key._decrypt(ct_int)
        # Complete step 2c (I2OSP)
        em = long_to_bytes(m_int, k)
        # Step 3a
        lHash = self._hashObj.new(self._label).digest()
        # Step 3b
        y = em[0]
        # y must be 0, but we MUST NOT check it here in order not to
        # allow attacks like Manger's (http://dl.acm.org/citation.cfm?id=704143)
        maskedSeed = em[1:hLen+1]
        maskedDB = em[hLen+1:]
        # Step 3c
        seedMask = self._mgf(maskedDB, hLen)
        # Step 3d
        seed = strxor(maskedSeed, seedMask)
        # Step 3e
        dbMask = self._mgf(seed, k-hLen-1)
        # Step 3f
        db = strxor(maskedDB, dbMask)
        # Step 3g
        one_pos = hLen + db[hLen:].find(b'\x01')
        lHash1 = db[:hLen]
        invalid = bord(y) | int(one_pos < hLen)
        hash_compare = strxor(lHash1, lHash)
        for x in hash_compare:
            invalid |= bord(x)
        for x in db[hLen:one_pos]:
            invalid |= bord(x)
        if invalid != 0:
            raise ValueError("Incorrect decryption.")
        # Step 4
        return db[one_pos + 1:]
```

其中也有 long_to_bytes 和 bytes_to_long 方法，原理类似（大概）
因为举例比较麻烦，所以就没有尝试
浏览了一下源码（因为不怎么看得懂），发现里面有 hash, xor 之类的字眼
而且看注释内容（也可见于[官方文档](https://pycryptodome.readthedocs.io/en/latest/src/cipher/oaep.html)）
发现它对密文长度也做了要求，如果密文长度错误会报错 ValueError
就很迷。。。

那么如果碰到了该怎么办？
那就先尝试第一种代码，再尝试第二种代码咯[扶额]

## Single

加密代码如下：

```cpp
#include <bits/stdc++.h>
using namespace std;
int main()
{
	freopen("Plain.txt","r",stdin);
	freopen("Cipher.txt","w",stdout);
	map<char, char> f;
	int arr[26];
	for(int i=0;i<26;++i){
		arr[i]=i;
	}
	random_shuffle(arr,arr+26);
	for(int i=0;i<26;++i){
		f['a'+i]='a'+arr[i];
		f['A'+i]='A'+arr[i];
	}
	char ch;
	while((ch=getchar())!=EOF){
		if(f.count(ch)){
			putchar(f[ch]);
		}else{
			putchar(ch);
		}
	}
	return 0;
}
```

这学期刚学 C 语言
大致看了一下
大概就是给明文随机移位了一下
密文如下：

```cpp
Jmqrida rva Lfmz (JRL) eu m uqajemf seny xl enlxdomrexn uajiderc jxoqarerexnu. Rvada mda rvdaa jxooxn rcqau xl JRLu: Paxqmdyc, Mrrmjs-Yalanja mny oekay.

Paxqmdyc-urcfa JRLu vmu m jxiqfa xl giaurexnu (rmusu) en dmnza xl jmrazxdeau. Lxd akmoqfa, Wab, Lxdanuej, Jdcqrx, Benmdc xd uxoarvenz afua. Ramo jmn zmen uxoa qxenru lxd atadc uxftay rmus. Oxda qxenru lxd oxda jxoqfejmray rmusu iuimffc. Rva nakr rmus en jvmen jmn ba xqanay xnfc mlrad uxoa ramo uxfta qdatexiu rmus. Rvan rva zmoa reoa eu xtad uio xl qxenru uvxwu cxi m JRL wenad. Lmoxiu akmoqfa xl uijv JRL eu Yaljxn JRL gimfu.

Waff, mrrmjs-yalanja eu mnxrvad enradaurenz seny xl jxoqarerexnu. Vada atadc ramo vmu xwn narwxds(xd xnfc xna vxur) werv tifnmdmbfa uadtejau. Cxid ramo vmu reoa lxd qmrjvenz cxid uadtejau mny yatafxqenz akqfxeru iuimffc. Ux, rvan xdzmnehadu jxnnajru qmdrejeqmnru xl jxoqarerexn mny rva wmdzmoa urmdru! Cxi uvxify qdxrajr xwn uadtejau lxd yalanja qxenru mny vmjs xqqxnanru lxd mrrmjs qxenru. Veurxdejmffc rveu eu m ledur rcqa xl JRLu, atadcbxyc snxwu mbxir YAL JXN JRL - uxoarvenz fesa m Wxdfy Jiq xl mff xrvad jxoqarerexnu.

Oekay jxoqarerexnu omc tmdc qxuuebfa lxdomru. Er omc ba uxoarvenz fesa wmdzmoa werv uqajemf reoa lxd rmus-bmuay afaoanru (a.z. IJUB eJRL).

JRL zmoau xlran rxijv xn omnc xrvad muqajru xl enlxdomrexn uajiderc: jdcqrxzdmqvc, urazx, benmdc mnmfcueu, datadua anzanaadenz, oxbefa uajiderc mny xrvadu. Zxxy ramou zanadmffc vmta urdxnz useffu mny akqadeanja en mff rvaua euuiau.

Iuimffc, lfmz eu uxoa urdenz xl dmnyxo ymrm xd rakr en uxoa lxdomr. Akmoqfa mljrl{Xv_I_lxiny_er_neja_rDc}
```

尝试[爆破](https://quipqiup.com/)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210428225044309.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
啊这
完事了

# 2021-4-29

## boom

附件是一个 .exe 文件
不会是个 re 题吧。。。
在命令行打开（如果不在命令行打开，最后输出会直接关闭窗口）
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210429185222439.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
Do you like van♂ you see?（大雾）
下一步
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210429185246243.png)
提交 md5
可以直接[查询](https://www.cmd5.com/)得到
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210429184816708.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
输入结果
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210429185334753.png)
下一步
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210429185357601.png)
解三元一次方程组
当然你可以手算
这里我们直接用 sagemath 计算（躺）
结果如下：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210429185524985.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
最后一步：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210429185617123.png)
还是用 sagemath 求解
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210429185656219.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
输入其中一个解即可
![在这里插入图片描述](https://img-blog.csdnimg.cn/2021042918572871.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
当然你可以 re [doge]
把它丢尽 IDA 里面，可以得到程序的框架
这里用的的软件是 IDA Freeware 7.0
先看输出 flag 的部分：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210429190130563.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
发现 flag 是由三部分组成
第一部分：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210429185912455.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
第二部分：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210429190033880.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
第三部分：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210429190054324.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
容易知道 flag 即为上面三部分答案拼接而成

## B@se

附件内容如下：

```cpp
密文：MyLkTaP3FaA7KOWjTmKkVjWjVzKjdeNvTnAjoH9iZOIvTeHbvD==
JASGBWcQPRXEFLbCDIlmnHUVKTYZdMovwipatNOefghq56rs****kxyz012789+/

oh holy shit, something is missing...
```

第一行是密文
第二行容易猜到是重新排列的 Base64 编码对照表
只是其中几个字符缺失了
编写代码：

```python
def judge(key, start, end):
    s = ''
    for i in range(start, end+1):
        if not chr(i) in key:
            s += chr(i)
    return s
unknown = judge(key, ord('A'), ord('Z')) + judge(key, ord('a'), ord('z')) + judge(key, ord('0'), ord('9'))
unknown_list = list(unknown)
print(unknown_list)
```

可以得出缺失的字符为 ['j', 'u', '3', '4']
对其进行排列组合，替换对照表中缺失的字符
然后按照 Base64 的编码规则编写程序
代码如下：

```python
import itertools

c = 'MyLkTaP3FaA7KOWjTmKkVjWjVzKjdeNvTnAjoH9iZOIvTeHbvD=='
key = 'JASGBWcQPRXEFLbCDIlmnHUVKTYZdMovwipatNOefghq56rs****kxyz012789+/'

def decrypt(c, key):
    b = ''
    s = ''
    for i in range(len(c)):
        if c[i] == '=':
            b += '0'*6
        else:
            b += bin(list(key).index(c[i]))[2:].zfill(6)
    for i in range(0, len(b), 8):
        s += chr(int(b[i:i+8], 2))
    print(s)

def judge(key, start, end):
    s = ''
    for i in range(start, end+1):
        if not chr(i) in key:
            s += chr(i)
    return s
unknown = judge(key, ord('A'), ord('Z')) + judge(key, ord('a'), ord('z')) + judge(key, ord('0'), ord('9'))
unknown_list = list(unknown)
print(unknown_list)
combination = list(itertools.permutations(unknown_list,4))
for i in range(len(combination)):
    key_new = key.replace('****', ''.join(list(combination[i])))
    print(key_new)
    decrypt(c, key_new)
```

输出结果为：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210429205713681.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
可以看到会有很多重复的内容
应该是由于有些字符在编码表中没有对应的字符，或者对应的字符在不同排列组合的编码表中的位置相同
结果为：wctf2120{base64_1s_v3ry_e@sy_and_fuN}

# 2021-4-30

## 坏蛋是雷宾

题目描述如下：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210430230435523.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
看到校验码，想起之前一个奇偶校验位的题
但是好像行不通
只能找 [wp](https://blog.csdn.net/weixin_44017838/article/details/104895787)
得知是 [RSA 衍生算法——Rabin 算法](https://ctf-wiki.org/crypto/asymmetric/rsa/rsa_e_attack/#rsa-rabin)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210430230903257.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
wp 中没有采用原始的攻击方法
而是采用下面的方法
![在这里插入图片描述](https://img-blog.csdnimg.cn/2021043023095216.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
如果把 wp 中的代码放到 python3 中运行会报错：
TypeError: pow() 3rd argument not allowed unless all arguments are integers
应该为：

```python
# p = q = 3 (mod 4)
mp = pow(c, (p + 1) // 4, p)
mq = pow(c, (q + 1) // 4, q)
```

另一处值得注意的地方是：

```python
inv_p = invert(p, q)
inv_q = invert(q, p)
```

没有采用扩展欧几里得求 $y_{p},y_{q}$ ，而是采用求逆元的方法
原理是：
由于
$$
y_{p} * p + y_{q} * q = 1
$$
所以两边分别对 $p, q$ 取模
可得
$$
y_{p}*q \equiv 1\space (mod \space p)\\
y_{q}*p \equiv 1\space (mod \space q)
$$
直接用 gmpy2 库中的 gcdext() 方法实现扩展欧几里得算法的代码如下：

```python
import gmpy2

g, yp, yq = gmpy2.gcdext(p, q)
```

下一步：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210430231746752.png)
根据题目描述：密文是162853095，校验码二进制值是110001，根据说明是放在明文后一起加密的，明文与密文长度相同。
从四个明文中找到正确的明文
完整代码如下：

```python
import gmpy2

n = 523798549
p = 10663
q = 49123
c = 162853095
# p = q = 3 (mod 4)
mp = pow(c, (p + 1) // 4, p)
mq = pow(c, (q + 1) // 4, q)

g, yp, yq = gmpy2.gcdext(p, q)

a = (yp * p * mq + yq * q * mp) % n
b = n - a
c = (yp * p * mq - yq * q * mp) % n
d = n - c

check = '110001'
for i in [a, b, c, d]:
    if bin(i)[2:][-len(check):] == check:
        print(i)
        m = i
print(int(bin(m)[2:][:-len(check)], 2))
```

n 可以直接爆破，这里不再赘述
最后得到的 m，[MD5 加密](https://tool.chinaz.com/tools/md5.aspx)
结果如下：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210430232002397.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
哈希值即为 flag

# 2021-5-6

## RSA & what

首先，加密代码如下：

```python
from Crypto.Util.number import bytes_to_long, getPrime
from random import randint
from gmpy2 import powmod

p = getPrime(2048)
q = getPrime(2048)
N = p*q
Phi = (p-1)*(q-1)
def get_enc_key(N,Phi):
    e = getPrime(N)
    if Phi % e == 0:
        return get_enc_key(N, Phi)
    else:
        return e
e1 = get_enc_key(randint(10, 12), Phi)
e2 = get_enc_key(randint(10, 12), Phi)

fr = open(r"./base64", "rb")#flag is in this file
f1 = open(r"./HUB1", "wb")
f2 = open(r"./HUB2", "wb")
base64 = fr.read(255) # 读取255个字节
f1.write("%d\n%d\n" % (N, e1))
f2.write("%d\n%d\n" % (N, e2))
while len(base64)>0:
    pt = bytes_to_long(base64)
    ct1 = powmod(pt, e1, N)
    ct2 = powmod(pt, e2, N)
    f1.write("\n%d" % ct1)
    f2.write("\n%d" % ct2)
    base64 = fr.read(255)
fr.close()
f1.close()
f2.close()
```

是[共模攻击](https://ctf-wiki.org/crypto/asymmetric/rsa/rsa_module_attack/)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210507001231135.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
将 base64 加密的文件每段读取 255 个字节用不同的 e 加密分别存储在 HUB1, HUB2 两个文件中
然后就写代码：

```python
from gmpy2 import gcdext
from Crypto.Util.number import *
import base64

def get(file):
    with open(file, 'r') as f:
        content = f.readlines()
    n = content[0]
    e = int(content[1])
    list_c = content[3:]
    return (n, e, list_c)

n, e1, list_c1 = get('HUB1')
n, e2, list_c2 = get('HUB2')
n = int(n)
g, u, v = gcdext(e1, e2)

list_c3 = []
list_c4 = []
if u < 0:
    u = -u
    for i in range(len(list_c1)):
        list_c3.append(inverse(int(list_c1[i]), n))
        list_c4.append(int(list_c2[i]))
else:
    v = -v
    for i in range(len(list_c2)):`在这里插入代码片`
        list_c4.append(inverse(int(list_c2[i]), n))
        list_c3.append(int(list_c1[i]))
list_c = list(zip(list_c3, list_c4))

mm = ''.encode()
for c3, c4 in list_c:
    m = (pow(c3, u, n) * pow(c4, v, n)) % n
    print((long_to_bytes(m)))
    mm += long_to_bytes(m)
print(mm)
print(base64.b64decode(mm))
```

输出为

```python
b'VEhJUz==\nRkxBR3==\nSVN=\nSElEREVOLo==\nQ0FO\nWU9V\nRklORM==\nSVT=\nT1VUP4==\nRE8=\nWU9V\nS05PV9==\nQkFTRTY0P5==\nWW91bmdD\nVEhJTku=\nWU9V\nQVJF\nTk9U\nVEhBVE==\nRkFNSUxJQVI=\nV0lUSO==\nQkFTRTY0Lh==\nQmFzZTY0\naXO=\nYW==\nZ3JvdXA=\nb2b=\nc2ltaWxhcn==\nYmluYXJ5LXRvLXRleHR=\nZW5jb2Rpbm'
b'e=\nc2NoZW1lc0==\ndGhhdD==\ncmVwcmVzZW50\nYmluYXJ5\nZGF0YW==\naW5=\nYW6=\nQVNDSUl=\nc3RyaW5n\nZm9ybWF0\nYnk=\ndHJhbnNsYXRpbmd=\naXS=\naW50b1==\nYT==\ncmFkaXgtNjQ=\ncmVwcmVzZW50YXRpb24u\nVGhl\ndGVybc==\nQmFzZTY0\nb3JpZ2luYXRlc8==\nZnJvbd==\nYY==\nc3BlY2lmaWN=\nTUlNRT==\nY29udGVudI='
b'=\ndHJhbnNmZXI=\nZW5jb2Rpbmcu\nVGhl\ncGFydGljdWxhct==\nc2V0\nb2b=\nNjR=\nY2hhcmFjdGVyc5==\nY2hvc2Vu\ndG+=\ncmVwcmVzZW50\ndGhl\nNjQ=\ncGxhY2UtdmFsdWVz\nZm9y\ndGhl\nYmFzZd==\ndmFyaWVz\nYmV0d2Vlbt==\naW1wbGVtZW50YXRpb25zLp==\nVGhl\nZ2VuZXJhbI==\nc3RyYXRlZ3n=\naXO=\ndG9=\nY2hvb3Nl\nNjR'
b'=\nY2hhcmFjdGVyc5==\ndGhhdA==\nYXJl\nYm90aN==\nbWVtYmVyc5==\nb2a=\nYS==\nc3Vic2V0\nY29tbW9u\ndG8=\nbW9zdM==\nZW5jb2RpbmdzLA==\nYW5k\nYWxzb8==\ncHJpbnRhYmxlLg==\nVGhpc9==\nY29tYmluYXRpb25=\nbGVhdmVz\ndGhl\nZGF0YW==\ndW5saWtlbHk=\ndG/=\nYmV=\nbW9kaWZpZWS=\naW5=\ndHJhbnNpdE==\ndGhyb3V'
b'naN==\naW5mb3JtYXRpb26=\nc3lzdGVtcyw=\nc3VjaN==\nYXM=\nRS1tYWlsLD==\ndGhhdA==\nd2VyZQ==\ndHJhZGl0aW9uYWxseQ==\nbm90\nOC1iaXQ=\nY2xlYW4uWzFd\nRm9y\nZXhhbXBsZSw=\nTUlNRSdz\nQmFzZTY0\naW1wbGVtZW50YXRpb24=\ndXNlcw==\nQahDWiw=\nYahDeiw=\nYW5k\nMKhDOQ==\nZm9y\ndGhl\nZmlyc3Q=\nNjI=\ndmFs'
b'dWVzLg==\nT3RoZXI=\ndmFyaWF0aW9ucw==\nc2hhcmU=\ndGhpcw==\ncHJvcGVydHk=\nYnV0\nZGlmZmVy\naW4=\ndGhl\nc3ltYm9scw==\nY2hvc2Vu\nZm9y\ndGhl\nbGFzdA==\ndHdv\ndmFsdWVzOw==\nYW4=\nZXhhbXBsZQ==\naXM=\nVVRGLTcu'
b'VEhJUz==\nRkxBR3==\nSVN=\nSElEREVOLo==\nQ0FO\nWU9V\nRklORM==\nSVT=\nT1VUP4==\nRE8=\nWU9V\nS05PV9==\nQkFTRTY0P5==\nWW91bmdD\nVEhJTku=\nWU9V\nQVJF\nTk9U\nVEhBVE==\nRkFNSUxJQVI=\nV0lUSO==\nQkFTRTY0Lh==\nQmFzZTY0\naXO=\nYW==\nZ3JvdXA=\nb2b=\nc2ltaWxhcn==\nYmluYXJ5LXRvLXRleHR=\nZW5jb2Rpbme=\nc2NoZW1lc0==\ndGhhdD==\ncmVwcmVzZW50\nYmluYXJ5\nZGF0YW==\naW5=\nYW6=\nQVNDSUl=\nc3RyaW5n\nZm9ybWF0\nYnk=\ndHJhbnNsYXRpbmd=\naXS=\naW50b1==\nYT==\ncmFkaXgtNjQ=\ncmVwcmVzZW50YXRpb24u\nVGhl\ndGVybc==\nQmFzZTY0\nb3JpZ2luYXRlc8==\nZnJvbd==\nYY==\nc3BlY2lmaWN=\nTUlNRT==\nY29udGVudI==\ndHJhbnNmZXI=\nZW5jb2Rpbmcu\nVGhl\ncGFydGljdWxhct==\nc2V0\nb2b=\nNjR=\nY2hhcmFjdGVyc5==\nY2hvc2Vu\ndG+=\ncmVwcmVzZW50\ndGhl\nNjQ=\ncGxhY2UtdmFsdWVz\nZm9y\ndGhl\nYmFzZd==\ndmFyaWVz\nYmV0d2Vlbt==\naW1wbGVtZW50YXRpb25zLp==\nVGhl\nZ2VuZXJhbI==\nc3RyYXRlZ3n=\naXO=\ndG9=\nY2hvb3Nl\nNjR=\nY2hhcmFjdGVyc5==\ndGhhdA==\nYXJl\nYm90aN==\nbWVtYmVyc5==\nb2a=\nYS==\nc3Vic2V0\nY29tbW9u\ndG8=\nbW9zdM==\nZW5jb2RpbmdzLA==\nYW5k\nYWxzb8==\ncHJpbnRhYmxlLg==\nVGhpc9==\nY29tYmluYXRpb25=\nbGVhdmVz\ndGhl\nZGF0YW==\ndW5saWtlbHk=\ndG/=\nYmV=\nbW9kaWZpZWS=\naW5=\ndHJhbnNpdE==\ndGhyb3VnaN==\naW5mb3JtYXRpb26=\nc3lzdGVtcyw=\nc3VjaN==\nYXM=\nRS1tYWlsLD==\ndGhhdA==\nd2VyZQ==\ndHJhZGl0aW9uYWxseQ==\nbm90\nOC1iaXQ=\nY2xlYW4uWzFd\nRm9y\nZXhhbXBsZSw=\nTUlNRSdz\nQmFzZTY0\naW1wbGVtZW50YXRpb24=\ndXNlcw==\nQahDWiw=\nYahDeiw=\nYW5k\nMKhDOQ==\nZm9y\ndGhl\nZmlyc3Q=\nNjI=\ndmFsdWVzLg==\nT3RoZXI=\ndmFyaWF0aW9ucw==\nc2hhcmU=\ndGhpcw==\ncHJvcGVydHk=\nYnV0\nZGlmZmVy\naW4=\ndGhl\nc3ltYm9scw==\nY2hvc2Vu\nZm9y\ndGhl\nbGFzdA==\ndHdv\ndmFsdWVzOw==\nYW4=\nZXhhbXBsZQ==\naXM=\nVVRGLTcu'
b'THIS'
```

嗯？怎么就一个 `b'THIS'` ？
搞了半天
心态崩了
找了很多资料（包括一些 wp）都不能解决
终于找到了合适的 [wp](https://www.codeleading.com/article/48943375092/)(泪目)
中间那个 `\n` 原来是换行符。。。
后面加了一段：

```python
temp = b''
M = b''
for i in mm:
    k = long_to_bytes(i)
    if k == b'\n':
        M += base64.b64decode(temp)
        temp = b''
        continue
    temp += k
print(M)
```

输出结果为：

```python
b"THISFLAGISHIDDEN.CANYOUFINDITOUT?DOYOUKNOWBASE64?YoungCTHINKYOUARENOTTHATFAMILIARWITHBASE64.Base64isagroupofsimilarbinary-to-textencodingschemesthatrepresentbinarydatainanASCIIstringformatbytranslatingitintoaradix-64representation.ThetermBase64originatesfromaspecificMIMEcontenttransferencoding.Theparticularsetof64characterschosentorepresentthe64place-valuesforthebasevariesbetweenimplementations.Thegeneralstrategyistochoose64charactersthatarebothmembersofasubsetcommontomostencodings,andalsoprintable.Thiscombinationleavesthedataunlikelytobemodifiedintransitthroughinformationsystems,suchasE-mail,thatweretraditionallynot8-bitclean.[1]Forexample,MIME'sBase64implementationusesA\xa8CZ,a\xa8Cz,and0\xa8C9forthefirst62values.Othervariationssharethispropertybutdifferinthesymbolschosenforthelasttwovalues;anexampleisUTF-7."
```

看了半天看不出名堂
不就是把 base64 加密解释了一遍吗？
`THIS FLAG IS HIDDEN`
所以是怎么隐藏的呢？
参照 wp ，是 base64 隐写
再加一段代码：

```python
c = mm
def get_base64_diff_value(s1, s2):
    base64chars = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    res = 0
    for i in range(len(s2)):
        if s1[i] != s2[i]:
            return abs(base64chars.index(s1[i]) - base64chars.index(s2[i]))
    return res

def solve_stego():
    line=b''
    bin_str=''
    for i in c:
        k=long_to_bytes(i)
        if k==b'\n':
            steg_line = line
            norm_line = base64.b64encode(base64.b64decode(line))
            diff = get_base64_diff_value(steg_line, norm_line)
            #print(diff)
            pads_num = steg_line.count(b'=')
            if diff:
                bin_str += bin(diff)[2:].zfill(pads_num * 2)
            else:
                bin_str += '0' * pads_num * 2
            print(goflag(bin_str))
            line=b''
            continue
        line+=k

def goflag(bin_str):
    res_str = ''
    for i in range(0, len(bin_str), 8):
        res_str += chr(int(bin_str[i:i + 8], 2))
    return res_str

if __name__ == '__main__':
    solve_stego()
```

结果为：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210507002527114.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)

# 2021-5-7

## 大数计算

题目描述：
flag等于 wctf2020{Part1-Part2-Part3-Part4} 每一Part都为数的十六进制形式（不需要0x)，并用 '-' 连接
Part1 = $2020*2019*2018* \cdots *3*2*1$ 的前8位
Part2 = $520^{1314} + 2333^{666}$ 的前8位
Part3 = 宇宙终极问题的答案 $x,y,z$ 绝对值和的前8位
Part4 = 见图片附件，计算结果乘上$1314$

### Part1

编写一个简单的代码：

```python
result = 1
for i in range(2020):
    result *= (i+1)
print(result)
```

结果为：

```python
386096951826724872377527755309254829575652833764136996704568320001962744375418996245016343070140495922821200614629613676056064037951380768693631095293969806083283419391122768593135371533669789505644746708636245286071667761717496505605794126236016354348784410240335472055757629538266448781423997420044753128592681490931155652500393981945786030349664533711594345568989302186320705026331591010701401806321162676014168267730443127229747356930582741007966787455099581158386524638372751639313267766129679555735375331455412649323831848690561911358863665291691253184884758093169216097558804246779418405854622335480512182276766264945125914275956103428084284556933827302002697216249895052496440541172520541257873419634034161103824199316296993063661010122247477806751684315159325496718242301326410047304634788457407629483612153384782033983257542806498117448100169850242485622135551834378243035590642352839055096183047501262709727667023809372071930180723811416036636750921242111077253225291490924545632327925057149716099795229733989622278323677405784299876565959582090676790727740307049077225508605566490968403536385735238912741726753153654163800192588170739101544001978507890178193666229850683801023093469605890012191345770905436000032556827322145416135640856057548854287333531160062595436210299154833029310707445362782649537335586073636441409352069691324058033881627521130303343921325446543099236423768017622330952822024309856222944411670467670029292434583401736238439303991700945727580238299750982559170548833139100553910689597287121942263594164151082680213395221663587816012606720015052645832622621471333102685422392447559330215438244237647008830170109515277728376740158127469507982306996887556451828368694363732003992198093879746125762368988032934128856143997941342867059780561839990632437177907064694382432079447096605996943877612866685823347086095028180222170710715928986388757360066746071573539728102642573049976996579847448174187164026466837941823296708220196587010386827277994485087677372620093957914089258169972214872563807439573846201771190457487767436383507920863265001158985530332683629614342467843804937221206800149726658420435494370022064907930073825842356140820286864504429150801511854514365890388184309207375633689423525046829286070427382305637485912596973375367419760345739950217980127302509287481854594278265427658981413690677647108075218848723615631183228998263867303745241836596694419145869217246024705077412378592333080136866437588005631900741990955327512376380828834010898865112109122200117679929527578871952101638590795253704401058529870302842722801768976320289167271902599225625767622305121280203492060037659871687735744553956446891872856397638184308752827275833141465241377237087280607247672227911921476510099466427100947464296939925307947903326972670620615266725024373992589830067802295068263706563543372266200657231075725406225813916087447037257516901879820294473007469699120258797394881069240769625444137446394025363698666039205630857709229029682411964627222481342313835400760000248298282014684789191216782161001313299389221096618273488723978734883910176473532912398103689047801184926163882078889516242948227926207222798398599415190198383379958023224921700008504785581886491831617089767423337158587605657695370924035915232465034278959481229277255278641922703818140279236081674495149412290836894544282115179683616118844191583046672479060000997496671880332878428953950612778358032083448023516233258828937364836898528863330898553728662430714476112310836556548819026772896916666672491022632933230082044594787660656479369609508622352899543941383995692550547567969679794689990261140429300073943357022253659335410345587776835600085239314982274092032142617241600285547606153599286848476863161163541783080974843391064827635422937416295803320652151693691769908939733927283127338535832997562295235291634892349205745118756949780889187123971284330764415768476973033998802916258114465575907763749305205635060986278491975514474464672254458806857234410272869494209351555904987662052843555593641077334735000243185871626166435489995567743531839402525319028777252590673740070657146817606781166399960411132861682002655514447098043836381875601009788125213646389121448684764478666800367960493084953255241805961090727464679546615218982157594620688546771982908471364789755878887707044374010944486692997646137003523014144478339200998768863760703237203498326237220307578035692438887844741169784356786186401985299971489879829923194004083856969480041497397289465262863214647978593940815429794201584815761969377077597754446250785589118819688309472535988847810731264852902520018791994847255177619133199103397784696304617128344478292442325121108591633318029061667864784808515527387560252024100796176430107903015131441779467272344895619105502295519265018507118428238756968370367729287885962903983789250413811180716741127223957387264111710541149510905192956624428207083391894030881029258437087456354854256388583861141432235437699695203894352189291895609764592583127247584093330090479305172063745326415499877435366649909958866611266850377258481988425964258871356114398124542854504460141256012894066714195604604296809443585918770552117029738264919661512180130075143844966812954224436082616963714987190523714733696955227936508156266340713059106114761487944040893851195897985233581632996731726844059926287692271399731200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
```

Part1：38609695
转十六进制：24D231F

### Part2

直接用 python 算：![在这里插入图片描述](https://img-blog.csdnimg.cn/20210507232309432.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
结果为：

```python
67358675073930576996073993722567461850164722807074564948878417317473402927052829127082792032180094796252395096433983198952274168335392450509538309593385666431514980590592716015855911289321506036686643999492477513757215924758776455044536037020140456863773999261918973328815695045710068615401644013371977309012103898412096306361548001024977583422217671458264501188363086490125698404411163875599250631472344791340890807258094473727320110195601853152755087240330894053335818131077110273175715028846928201286446627946414753140891422257217210657051018005119011231825729783206822743971574711110393874816976266354981853740848193017816398023462606903346766612687790408415070020255296249418676249807212441079026250983961692920652966680193496784706192692613628105543621116002202680144634223494461659625064734199269350540205779713480943543889927915919259683768965037082643370773459533965219810073840472443356812334913011267861631024583721439843313283632252393379630383299598523037929812133138807072044576906149490490113840653244256197362973674055842990181720796496141363505718393822270218527760700369994972831534842781472514105407807279417668179333578100464787815389196826955497201910672296944059409606029603730111157226386643599020499425611604798218989413785508164561159754542908177698601111851024642335136611527906723782867198103433350776510482418582828560882474001127337861205717439932975849518063393530401772837736924736914846285298676339811297353234924091794918188257309391813418599493372303068163108621417737278803530572213749972358034814384186787621021593911334049398408117962215128441151972529070470429717565266547734379348873150272523271822724131161260146953117253978239691913721988312421114234651848572209530437943447365774218261113652983590167268527243129712467973675150813885739222841289549709569689560918679552000804353102265587269536197104995365208113361238214793349376601709287320691962025569441318004962409752672175447871755400848907951316397028636550476284126600721896236978828578849024817047688627396567760215637844575781201340411713410901387415097150001810731644704906580463682092951091073376627966232966312329119203820184242415159480596553046863575499835934379905722318707119304564096837225570386337451111503621022869027771621941235105328508169429847297696160848087696110478698810948121137387936577551170478133221632051268190997414006106830275793171130669067945012054593847771690058584752626174521036167711725373472145872472987785584869677825221641781524433380680668092633822451335545271833203427482749996978964078435417941459565163307999239089382722108845684107513974453105597828187596947603390837292678451072673709372346741758978218449321284455510126397518967502185664874536990177693703924032798926123849737513057251304979953532246771553748100752530930394182885368167026727688409697271253702259642032797882327918994179815400383367337203215938064919399556687943521993823720750997305976057751840104981535895783291939176032118935838607493242555676289868798140683411268035331709077028634328818544056041101480762484035614265528718720132396302035616727694893643384384202696363883821952117653841426152212136741932330060968422184519178149199302895488289650118600183818496708016481413704242955462575482947926185049572277249034187278692428277207506362256097428904426717710977347411241809884859683037796946927621459794307572757322054131305574740424632144992602305052743261521941792148633841874961055208272462900770503933839068194426250247291864679430728943202539192872303333804358392481348403129810207376835075575297015491422237138339359562906817960418892175230875862569
```

Part2：67358675
转十六进制：403CFD3

### Part3

宇宙终极问题：求 $x,y,z$ 满足方程 $x^{3} + y^{3} + z^{3} = 42$
（别看知乎，里面答案都是错的，不过提供了 42 和 丢番图方程两个线索）
参考文章：[https://www.theregister.com/2019/09/07/three_cubes_problem/](https://www.theregister.com/2019/09/07/three_cubes_problem/)
可知
$$
x = -80538738812075974\\
y =  80435758145817515\\
z =  12602123297335631\\
$$
分别取绝对值相加：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210508000255327.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)

结果为：173576620255229120
Part3：17357662
转十六进制：108DB5E

### Part4

先计算下面的定积分：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210507233058802.jpg?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70#pic_center)
当然可以手算：
$$
\mathop{ \int }\nolimits_{{0}}^{{22}}2x \text{d} x + 36 = x^{2} |^{22}_{0} + 36 = 520
$$
或者可以用 SageMath：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210507234242652.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
计算结果：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210507234359224.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
Part4：683280
转十六进制：A6D10

最终得到 flag：wctf2020{24d231f-403cfd3-108db5e-a6d10}

# 2021-5-8

## together

附件有两个 公钥,pem 和 flag(base64编码) 文件
联想题目，容易猜想是 RSA 共模攻击
编写代码验证：

```python
from Crypto.PublicKey import RSA

with open("pubkey1.pem", "r") as f:
    key = RSA.import_key(f.read())
    print(key.n)
    print(key.e)
with open("pubkey2.pem", "r") as f:
    key = RSA.import_key(f.read())
    print(key.n)
    print(key.e)
```

输出结果：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210508125546497.png)
猜想成立
然后进行共模攻击
完整代码如下：

```python
from Crypto.PublicKey import RSA
import base64
from Crypto.Util.number import *
import gmpy2

with open("pubkey1.pem", "r") as f:
    key = RSA.import_key(f.read())
    n1 = key.n
    e1 = key.e
with open("pubkey2.pem", "r") as f:
    key = RSA.import_key(f.read())
    n2 = key.n
    e2 = key.e

assert n1 == n2
n = n1
with open('myflag1', 'r') as f:
    c1 = int(base64.b64decode(f.read()).hex(), 16)
    print(c1)
with open('myflag2', 'r') as f:
    c2 = int(base64.b64decode(f.read()).hex(), 16)
    print(c2)

g, u, v = gmpy2.gcdext(e1, e2)
if u < 0:
    u = -u
    c1 = inverse(c1, n)
if v < 0:
    v = -v
    c2 = inverse(c2, n)

m = (pow(c1, u, n) * pow(c2, v, n)) % n
print(long_to_bytes(m))
```

结果为：flag{23re_SDxF_y78hu_5rFgS}

## babyRSA

加密代码如下：

```python
import sympy
import random
from gmpy2 import gcd, invert
from Crypto.Util.number import getPrime, isPrime, getRandomNBitInteger, bytes_to_long, long_to_bytes
from z3 import *
flag = b"MRCTF{xxxx}"
base = 65537

def gen_p():
    P = [0 for i in range(17)]
    P[0] = getPrime(128)
    for i in range(1, 17):
        P[i] = sympy.nextprime(P[i-1])
    print("P_p :", P[9])
    n = 1
    for i in range(17):
        n *= P[i]
    p = getPrime(1024)
    factor = pow(p, base, n)
    print("P_factor :", factor)
    return sympy.nextprime(p)

def gen_q():
    sub_Q = getPrime(1024)
    Q_1 = getPrime(1024)
    Q_2 = getPrime(1024)
    Q = sub_Q ** Q_2 % Q_1
    print("Q_1: ", Q_1)
    print("Q_2: ", Q_2)
    print("sub_Q: ", sub_Q)
    return sympy.nextprime(Q)

if __name__ == "__main__":
    _E = base
    _P = gen_p()
    _Q = gen_q()
    assert (gcd(_E, (_P - 1) * (_Q - 1)) == 1)
    _M = bytes_to_long(flag)
    _C = pow(_M, _E, _P * _Q)
    print("Ciphertext = ", _C)
'''
P_p : 206027926847308612719677572554991143421
P_factor : 213671742765908980787116579976289600595864704574134469173111790965233629909513884704158446946409910475727584342641848597858942209151114627306286393390259700239698869487469080881267182803062488043469138252786381822646126962323295676431679988602406971858136496624861228526070581338082202663895710929460596143281673761666804565161435963957655012011051936180536581488499059517946308650135300428672486819645279969693519039407892941672784362868653243632727928279698588177694171797254644864554162848696210763681197279758130811723700154618280764123396312330032986093579531909363210692564988076206283296967165522152288770019720928264542910922693728918198338839
Q_1:  103766439849465588084625049495793857634556517064563488433148224524638105971161051763127718438062862548184814747601299494052813662851459740127499557785398714481909461631996020048315790167967699932967974484481209879664173009585231469785141628982021847883945871201430155071257803163523612863113967495969578605521
Q_2:  151010734276916939790591461278981486442548035032350797306496105136358723586953123484087860176438629843688462671681777513652947555325607414858514566053513243083627810686084890261120641161987614435114887565491866120507844566210561620503961205851409386041194326728437073995372322433035153519757017396063066469743
sub_Q:  168992529793593315757895995101430241994953638330919314800130536809801824971112039572562389449584350643924391984800978193707795909956472992631004290479273525116959461856227262232600089176950810729475058260332177626961286009876630340945093629959302803189668904123890991069113826241497783666995751391361028949651
Ciphertext =  1709187240516367141460862187749451047644094885791761673574674330840842792189795049968394122216854491757922647656430908587059997070488674220330847871811836724541907666983042376216411561826640060734307013458794925025684062804589439843027290282034999617915124231838524593607080377300985152179828199569474241678651559771763395596697140206072537688129790126472053987391538280007082203006348029125729650207661362371936196789562658458778312533505938858959644541233578654340925901963957980047639114170033936570060250438906130591377904182111622236567507022711176457301476543461600524993045300728432815672077399879668276471832
'''
```

其实他原附件给的代码里面定义的 `GCD()` 函数根本没有用到，我把它删了
分析代码，p 和 q 分别由 `gen_p()` 和 `gen_q()` 两个自定义函数获取
其中 q 很容易求，而且把需要用到的数据都给了
需要注意的就是 用原代码的 `sympy.nextprime(sub_Q ** Q_2 % Q_1)` 求 q 会非常慢，我们用 `sympy.nextprime(pow(sub_Q, Q_2, Q_1))` 的方式求解
代码如下：

```python
import sympy
# 求 q
Q_1 = 103766439849465588084625049495793857634556517064563488433148224524638105971161051763127718438062862548184814747601299494052813662851459740127499557785398714481909461631996020048315790167967699932967974484481209879664173009585231469785141628982021847883945871201430155071257803163523612863113967495969578605521
Q_2 = 151010734276916939790591461278981486442548035032350797306496105136358723586953123484087860176438629843688462671681777513652947555325607414858514566053513243083627810686084890261120641161987614435114887565491866120507844566210561620503961205851409386041194326728437073995372322433035153519757017396063066469743
sub_Q = 168992529793593315757895995101430241994953638330919314800130536809801824971112039572562389449584350643924391984800978193707795909956472992631004290479273525116959461856227262232600089176950810729475058260332177626961286009876630340945093629959302803189668904123890991069113826241497783666995751391361028949651
q = sympy.nextprime(pow(sub_Q, Q_2, Q_1))
```

然后求 p
发现 `gen_p()` 函数和 RSA 加密算法很相似，只不过 n 是 17 个素数相乘
告诉我们 P[9] 容易求得其他 16 个相邻的素数
最后类似于 RSA 解密即可
代码如下：

```python
import sympy
from Crypto.Util.number import *
# 求 p
P_p = 206027926847308612719677572554991143421
P_factor = 213671742765908980787116579976289600595864704574134469173111790965233629909513884704158446946409910475727584342641848597858942209151114627306286393390259700239698869487469080881267182803062488043469138252786381822646126962323295676431679988602406971858136496624861228526070581338082202663895710929460596143281673761666804565161435963957655012011051936180536581488499059517946308650135300428672486819645279969693519039407892941672784362868653243632727928279698588177694171797254644864554162848696210763681197279758130811723700154618280764123396312330032986093579531909363210692564988076206283296967165522152288770019720928264542910922693728918198338839
list_P = [P_p]
P = P_p
for i in range(9):
    P = sympy.prevprime(P)
    list_P.append(P)
P = P_p
for i in range(7):
    P = sympy.nextprime(P)
    list_P.append(P)

phi_p = 1
n_p = 1
for i in range(len(list_P)):
    n_p *= list_P[i]
    phi_p *= (list_P[i]-1)
d_p = inverse(e, phi_p)
p = sympy.nextprime(pow(P_factor, d_p, n_p))
```

最后就是最基础的 RSA 解密算法了
完整代码如下：

```python
import sympy
from Crypto.Util.number import *

e = 65537
c = 1709187240516367141460862187749451047644094885791761673574674330840842792189795049968394122216854491757922647656430908587059997070488674220330847871811836724541907666983042376216411561826640060734307013458794925025684062804589439843027290282034999617915124231838524593607080377300985152179828199569474241678651559771763395596697140206072537688129790126472053987391538280007082203006348029125729650207661362371936196789562658458778312533505938858959644541233578654340925901963957980047639114170033936570060250438906130591377904182111622236567507022711176457301476543461600524993045300728432815672077399879668276471832

# 求 q
Q_1 = 103766439849465588084625049495793857634556517064563488433148224524638105971161051763127718438062862548184814747601299494052813662851459740127499557785398714481909461631996020048315790167967699932967974484481209879664173009585231469785141628982021847883945871201430155071257803163523612863113967495969578605521
Q_2 = 151010734276916939790591461278981486442548035032350797306496105136358723586953123484087860176438629843688462671681777513652947555325607414858514566053513243083627810686084890261120641161987614435114887565491866120507844566210561620503961205851409386041194326728437073995372322433035153519757017396063066469743
sub_Q = 168992529793593315757895995101430241994953638330919314800130536809801824971112039572562389449584350643924391984800978193707795909956472992631004290479273525116959461856227262232600089176950810729475058260332177626961286009876630340945093629959302803189668904123890991069113826241497783666995751391361028949651
q = sympy.nextprime(pow(sub_Q, Q_2, Q_1))

# 求 p
P_p = 206027926847308612719677572554991143421
P_factor = 213671742765908980787116579976289600595864704574134469173111790965233629909513884704158446946409910475727584342641848597858942209151114627306286393390259700239698869487469080881267182803062488043469138252786381822646126962323295676431679988602406971858136496624861228526070581338082202663895710929460596143281673761666804565161435963957655012011051936180536581488499059517946308650135300428672486819645279969693519039407892941672784362868653243632727928279698588177694171797254644864554162848696210763681197279758130811723700154618280764123396312330032986093579531909363210692564988076206283296967165522152288770019720928264542910922693728918198338839
list_P = [P_p]
P = P_p
for i in range(9):
    P = sympy.prevprime(P)
    list_P.append(P)
P = P_p
for i in range(7):
    P = sympy.nextprime(P)
    list_P.append(P)

phi_p = 1
n_p = 1
for i in range(len(list_P)):
    n_p *= list_P[i]
    phi_p *= (list_P[i]-1)
d_p = inverse(e, phi_p)
p = sympy.nextprime(pow(P_factor, d_p, n_p))

# 求 c
n = p*q
phi = (p-1)*(q-1)
d = inverse(e, phi)
m = pow(c, d, n)
print(long_to_bytes(m))
```

结果：MRCTF{sti11_@_b@by_qu3st10n}

# 2021-5-9

## you_raise_me_up

加密代码如下：

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from Crypto.Util.number import *
import random

n = 2 ** 512
m = random.randint(2, n-1) | 1
c = pow(m, bytes_to_long(flag), n)
print 'm = ' + str(m)
print 'c = ' + str(c)

# m = 391190709124527428959489662565274039318305952172936859403855079581402770986890308469084735451207885386318986881041563704825943945069343345307381099559075
# c = 6665851394203214245856789450723658632520816791621796775909766895233000234023642878786025644953797995373211308485605397024123180085924117610802485972584499
```

最后一个有点像 RSA 加密最后一步
没什么思路，就去找 [wp](https://blog.csdn.net/qq_46230755/article/details/111290544) 了
原来是一道[离散对数题](https://ctf-wiki.org/crypto/asymmetric/discrete-log/discrete-log/#_1)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210509235207399.png)
对于没学过群论的我来说，一些概念需要补充
**群的阶**：
参考[知乎文章](https://zhuanlan.zhihu.com/p/262254610)
首先是群元素的阶：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210509235448191.png)
下面是两个例子：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210509235550422.png)
循环群的阶（在加密中一般都考虑循环群）就是指：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210509235721894.png)
而什么是循环群？举一个例子就是整数模 n ，容易发现在模 n 的情况下 1 和 n+1 是相等的，就像循环一样
**光滑数**：
参考 [wiki](https://zh.wikipedia.org/wiki/%E5%85%89%E6%BB%91%E6%95%B8)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210510000116914.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
讲的很明白了

然而上面两个概念这道题不需要知道
ctfwiki 提供了[暴力破解的方法](https://ctf-wiki.org/crypto/asymmetric/discrete-log/discrete-log/#baby-step-giant-step)：

```python
from Crypto.Util.number import *

m = 391190709124527428959489662565274039318305952172936859403855079581402770986890308469084735451207885386318986881041563704825943945069343345307381099559075
c = 6665851394203214245856789450723658632520816791621796775909766895233000234023642878786025644953797995373211308485605397024123180085924117610802485972584499
n = pow(2, 512)

def bsgs(g, y, p):
    m = int(pow(p - 1, 1/2))
    S = {pow(g, j, p): j for j in range(m)}
    gs = pow(g, p - 1 - m, p)
    for i in range(m):
        if y in S:
            return i * m + S[y]
        y = y * gs % p
    return None
flag = bsgs(m, c, n)
print(long_to_bytes((flag)))
```

然而跑了几分钟没有反应
如 wp 所述，建议用 sympy 库求解：

```python
from Crypto.Util.number import *
import sympy

m = 391190709124527428959489662565274039318305952172936859403855079581402770986890308469084735451207885386318986881041563704825943945069343345307381099559075
c = 6665851394203214245856789450723658632520816791621796775909766895233000234023642878786025644953797995373211308485605397024123180085924117610802485972584499
n = 2 ** 512

flag = sympy.discrete_log(2**512,c,m)
print(long_to_bytes(flag))
```

结果为：flag{5f95ca93-1594-762d-ed0b-a9139692cb4a}

