# week 1

# 2021-3-28

# Rabbit

题目就是一串加密字符：U2FsdGVkX1/+ydnDPowGbjjJXhZxm2MP2AgI
然后搜一下Rabbit加密
![解密网站：http://www.jsons.cn/rabbitencrypt/](https://img-blog.csdnimg.cn/2021032810274494.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70#pic_center)解密网站：[http://www.jsons.cn/rabbitencrypt/](http://www.jsons.cn/rabbitencrypt/)
当然，解出了题目是不够的
一个关于Rabbit加密的文档：[https://www.ietf.org/rfc/rfc4503.txt](https://www.ietf.org/rfc/rfc4503.txt)
 Rabbit流密码（Rabbit Stream Cipher）简介：
Rabbit流密码是由Cryptico公司（http://www.cryptico.com）设计的，
Rabbit输入128bit的密钥和64bit的*IV初始向量*，每次迭代后从513bit内部状态中生成128bit的伪随机序列。最大加密消息长度为 $2^{64}$ bytes，即16TB，若消息超过该长度，则需要更换密钥对剩下的消息进行处理。
那么，什么是IV初始向量呢？
在密码学的领域里，初始向量（英语：initialization vector，缩写为IV），或译初向量，又称初始变量（starting variable，缩写为SV），是一个固定长度的输入值。一般的使用上会要求它是随机数或拟随机数（pseudorandom）。使用随机数产生的初始向量才能达到语义安全（消息验证码也可能用到初始向量），并让攻击者难以对原文一致且使用同一把密钥生成的密文进行破解。（摘自wiki）

# 篱笆墙的影子

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210328105527218.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70#pic_center)
老谜语人了
一看题目就知道这是个**栅栏密码**
密文：felhaagv{ewtehtehfilnakgw}

```python
m = 'felhaagv{ewtehtehfilnakgw}'
c = ''

for i in range(0, len(m), 2):
    c += m[i]
for i in range(1, len(m), 2):
    c += m[i]
print(c)
```

# RSA

题目：在一次RSA密钥对生成中，假设p=473398607161，q=4511491，e=17
求解出d作为flag提交

RSA加密原理：
选择两个大素数p和q，计算出模数N = p * q
计算φ = (p−1) * (q−1) 即N的欧拉函数，然后选择一个e (1<e<φ)，且e和φ互质
取e的模反数为d，计算方法: e * d ≡ 1 (mod φ)
对明文m进行加密：c = pow(m, e, N)，得到的c即为密文
对密文c进行解密，m = pow(c, d, N)，得到的m即为明文

```python
import gmpy2

p = 473398607161
q = 4511491
e = 17

phi = (p-1) * (q-1)
print('d = ' + str(gmpy2.invert(e, phi)))
```

# 2021-3-29

## 丢失的MD5

原题代码：

```python
import hashlib   
for i in range(32,127):
    for j in range(32,127):
        for k in range(32,127):
            m=hashlib.md5()
            m.update('TASC'+chr(i)+'O3RJMV'+chr(j)+'WDJKX'+chr(k)+'ZM')
            des=m.hexdigest()
            if 'e9032' in des and 'da' in des and '911513' in des:
                print des
```

是用python2写的，仅仅修改了print，还是会报错

```python
Traceback (most recent call last):
  File "D:/BUUCTF/Crypto/丢失的MD5/丢失的MD5/md5 (2).py", line 6, in <module>
    m.update('TASC'+chr(i)+'O3RJMV'+chr(j)+'WDJKX'+chr(k)+'ZM')
TypeError: Unicode-objects must be encoded before hashing
```

要对 m.update() 部分进行 utf-8 编码
修改完后代码如下：

```python
import hashlib   
for i in range(32,127):
    for j in range(32,127):
        for k in range(32,127):
            m=hashlib.md5()
            m.update(('TASC'+chr(i)+'O3RJMV'+chr(j)+'WDJKX'+chr(k)+'ZM').encode('utf-8'))
            des=m.hexdigest()
            if 'e9032' in des and 'da' in des and '911513' in des:
                print(des)
```

然后运行结果为：

```python
e9032994dabac08080091151380478a2
```

之后就不知道要干什么了
搜了搜题解[捂脸]，结果说flag就是输出部分（wtm人傻了）

当然，搜题解之前搜了搜关于 MD5 的资料（对于哈希函数这块一直是云里雾里的）
MD5加密算法：[https://www.tomorrow.wiki/archives/503](https://www.tomorrow.wiki/archives/503)来源TOMORROW星辰：www.tomorrow.wik
简单概括起来，MD5 算法的过程分为四步：处理原文，设置初始值，循环加工，拼接结果。（底层实现非常复杂）
破解MD5加密算法：[https://www.tomorrow.wiki/archives/562](https://www.tomorrow.wiki/archives/562)来源TOMORROW星辰：www.tomorrow.wik
破解算法都是利用 MD5 碰撞原理：被加密的数据与 MD5 加密算法所生成的哈希值并不是一一对应的关系，而是多对一，也就是说不同的数据经过 MD5 加密算法处理后，可能生成同样的 MD5 哈希值。通过碰撞寻找可以生成相同的哈希值的数据来实现破解。
其中暴力破解法的时间成本太高了，字典法则是空间成本太高，彩虹表法的时间成本和空间成本都较为均衡，相对较低，实用性更强。但是，计算机技术发展现在，利用分布式技术仍是可以有效利用以上方法进行破解 MD5 加密的。因此，这些方法都是有广泛应用的。
2004 年，中国数学家王小云等提出了一种新的 MD5 碰撞方法，使得 MD5 加密算法破解的效率大大提高。
2009 年，冯登国、谢涛提出了利用差分攻击的，使得 MD5 加密算法的破解复杂度进一步降低。
百度上搜的差分攻击（看不懂）：[https://baike.baidu.com/item/%E5%B7%AE%E5%88%86%E6%94%BB%E5%87%BB](https://baike.baidu.com/item/%E5%B7%AE%E5%88%86%E6%94%BB%E5%87%BB)

# 2021-3-30

## Alice与Bob

题目描述：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210330075927447.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
如题，先进行大整数分解：
分解大整数网站：[http://factordb.com/](http://factordb.com/)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210330075551151.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
然后进行md5加密：
参考博文[https://blog.csdn.net/qq_878799579/article/details/74324869](https://blog.csdn.net/qq_878799579/article/details/74324869)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210330080410603.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
输出即结果

## rsarsa

题目描述：
Math is cool! Use the RSA algorithm to decode the secret message, c, p, q, and e are parameters for the RSA algorithm.

p =  9648423029010515676590551740010426534945737639235739800643989352039852507298491399561035009163427050370107570733633350911691280297777160200625281665378483
q =  11874843837980297032092405848653656852760910154543380907650040190704283358909208578251063047732443992230647903887510065547947313543299303261986053486569407
e =  65537
c =  83208298995174604174773590298203639360540024871256126892889661345742403314929861939100492666605647316646576486526217457006376842280869728581726746401583705899941768214138742259689334840735633553053887641847651173776251820293087212885670180367406807406765923638973161375817392737747832762751690104423869019034

Use RSA to find the secret message
解题代码：

```python
import gmpy2

# 导入p, q, e, c

N = p*q
phi = (p-1) * (q-1)
d = gmpy2.invert(e, phi)
m = pow(c, d, N)
print(m)
```

按道理是要 long_to_bytes 一下的，结果出来一堆乱码 b'\x12\x05\x8eC\xd9\xe0\xc2%Y\xc1\x97t'
把 m 作为 flag 提交即可

## 大帝的密码武器

题目描述：
公元前一百年，在罗马出生了一位对世界影响巨大的人物，他生前是罗马三巨头之一。他率先使用了一种简单的加密函，因此这种加密方法以他的名字命名。
以下密文被解开后可以获得一个有意义的单词：FRPHEVGL
你可以用这个相同的加密向量加密附件中的密文，作为答案进行提交。
密文：ComeChina

直接用在线工具进行解密：
随便找了个网站：[http://ctf.ssleye.com/caesar.html](http://ctf.ssleye.com/caesar.html)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210330082924129.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
位移13位得到有意义的单词SECURITY
同样对密文位移13位：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210330083129893.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
得到答案 PbzrPuvan

# 2021-3-31

## Windows系统密码

回到正题

题目给了一个 **.hash 文件**，很容易想到哈希函数 MD5 加密
文件内容如下：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210331210338650.png)
容易猜想第二行 ctf 字样即为flag
MD5 解密网站：[https://www.cmd5.com/](https://www.cmd5.com/)
先把第一段拿去 MD5 解密：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210331210518771.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
嗯？？？
还要我付钱？
再试试第二段：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210331210627845.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
诶
提交上去就是 flag

# 2021-4-1

## 传统知识+古典密码

题干如下：
小明某一天收到一封密信，信中写了几个不同的年份
          辛卯，癸巳，丙戌，辛未，庚辰，癸酉，己卯，癸巳。
          信的背面还写有“+甲子”，请解出这段密文。

key值：CTF{XXX}

一看是干支纪年法，一查表
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210331211043907.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
得到列表：[28, 30, 23, 8, 29, 10, 16, 30]
看着应该是 ascii 码
+甲子 即每个数加60（每个数加1就没有什么意义了）

上面这部分是传统知识，题目还提到古典密码，常见的加密内容为字符串，加密后还是字符串的古典密码不外乎栅栏密码、凯撒密码
而且题目信息很少，也不大可能是 维吉尼亚密码 或者 base 加密之类需要字母表的密码
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210331220339234.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
结果为 SHUANGYU

其实我是搜了题解的
由于题目给的信息很少，而且输出不是题目给的格式 CTF{XXX} 即使想到了用栅栏密码和凯撒密码，也无法判断那个是正确结果，只能一个个试过去
而且很可能做了一次栅栏（或根本没想到用栅栏），没有正确结果就放弃了
结果应该是和比赛的名字有关联（“SHUANGYU”看起来像"双语"？），比如是 XX杯，这也是 BUUOJ 一个缺失的地方吧

## 传感器

“传统知识+古典密码”的问题暂且不提，但是附件里有另一个题是什么鬼？？？（您搁这儿套娃呢）
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210401210401497.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
“传感器”解压之后题目如下：
5555555595555A65556AA696AA6666666955
这是某压力传感器无线数据包解调后但未解码的报文(hex)
已知其ID为0xFED31F，请继续将报文完整解码，提交hex。
提示1：曼联

当时我就想，这个题的结果可能是“传统知识+古典密码”的提示，然后就想先解这题，但是毫无思路
这个“提示1”给了一个足球俱乐部是什么鬼？提示是球队的比分或者创立年份之类的数字吗？可是有什么用呢？
而“压力传感器无线数据包”的线索也没有头绪（大概给的是高低电频给的二进制编码然后转成了题干（猜的））
只好去搜题解：[https://blog.csdn.net/MikeCoke/article/details/106146391](https://blog.csdn.net/MikeCoke/article/details/106146391)
好家伙，曼联原来指的是**曼彻斯特编码**，我人傻了，没见过
当然，就有必要学习一下曼彻斯特编码
**曼彻斯特码**（Manchester code），又称数字双向码、分相码或相位编码(PE)，是 一种常用的的二元码线路编码方式之一，被物理层使用来编码一个同步位流的时钟和数据。在通信技术中，用来表示所要发送比特 流中的数据与定时信号所结合起来的代码。常用在以太网通信，列车总线控制，工业总线等领域
参考文章：[CTF中常见的加解密集合](https://zhuanlan.zhihu.com/p/83958412)
曼彻斯特码编解码原理：[https://blog.csdn.net/i13919135998/article/details/52276029](https://blog.csdn.net/i13919135998/article/details/52276029)
曼彻斯特解码电路设计的关键是如何准确地从曼彻斯特码的数据流中提取出“10”和“01”信号，并且把它们转换成普通二进制编码中的“0”和“1”。例如对于曼彻斯特码“01010101”，如果从第一位开始解码，得到的二进制编码就是“1111”，而若从第二位开始解码，得到的二进制编码就是“000”和头尾两个曼彻斯特码。由此可见，如果曼彻斯特码数据流中只有“1”或“0”是不能得到正确的译码结果的，如果曼彻斯特编码数据流中出现“00”，则“00”前后的码元必定是“1”；如果曼彻斯特编码数据流中出现“11”，则“00”前后的码元必定是“0”，因此，我们可以将“00”与“11”作为曼彻斯特码译码的标志位。（阿巴阿巴阿巴）
编码的步骤，是用01表示0，用10表示1。正是因为用跳变沿表示电平，使得它的频率是信号的两倍。
将5555555595555A65556AA696AA6666666955转化为二进制，根据01->1,10->0.可以得到
0101->11
0110->10
1010->00
1001->01
将得到的二进制按照上述转换后，对比ID并不重合，根据八位倒序传输协议将二进制每八位reverse，然后转换十六进制就可以得到flag。

```python
cipher='5555555595555A65556AA696AA6666666955'
def iee(cipher):
    tmp=''
    for i in range(len(cipher)):
        a=bin(eval('0x'+cipher[i]))[2:].zfill(4)
        tmp=tmp+a[1]+a[3]
        print(tmp)
    plain=[hex(int(tmp[i:i+8][::-1],2))[2:] for i in range(0,len(tmp),8)]
    print(''.join(plain).upper())

iee(cipher)
```

原文链接：[https://blog.csdn.net/qq_45784859/article/details/105602386](https://blog.csdn.net/qq_45784859/article/details/105602386)

结果其实与 flag 没有什么影响，就不再赘述了

# 2021-4-2

## 信息化时代的步伐

打开附件，只见一串数字：”606046152623600817831216121621196386“
我直接“？？？”
再看题目描述：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210402215456169.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
还是摸不着头脑
只好搜题解
说是[中文电码](https://zh.wikipedia.org/wiki/%E4%B8%AD%E6%96%87%E7%94%B5%E7%A0%81)，又是没见过的密码[捂脸]
“也许中国可以早早进入信息化时代，但是被清政府拒绝了”：
自摩尔斯电码在1835年发明后，一直只能用来传送英语或以拉丁字母拼写的文字。1873年，法国驻华人员威基杰（S·A·Viguer）参照《康熙字典》的部首排列方法，挑选了常用汉字6800多个，编成了第一部汉字电码本《电报新书》。后由任上海电报局首任总办的郑观应将其改编成为《中国电报新编》。（摘自wiki）
flag 为：flag{计算机要从娃娃抓起}
这句话是1984年邓小平同志说的：[数十年后一位伟人说的话](http://cpc.people.com.cn/n1/2019/1030/c69113-31428714.html)
中文电码加密解密：[http://code.mcdvisa.com/](http://code.mcdvisa.com/)

## RSA1

dp dq 泄露的题没做过（别问，问就是看wp）
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210402220615920.jpg)
当然，剽窃别人的答案是可耻的，我们还要“剽窃”别人的知识（嘿嘿嘿）
参考博客：[
RSA之拒绝套路(2)](https://skysec.top/2018/08/25/RSA%E4%B9%8B%E6%8B%92%E7%BB%9D%E5%A5%97%E8%B7%AF-2/)
这篇博客讲得很详细，但仍有地方可以细化和纠错
作为一个数理基础不扎实的数院学生，花了老半天才看明白
下面，让我来逐步推导（也当练习 $Latex$了）：
首先，什么是 $dp$ 和 $dq$：
$$
dp \equiv d\space mod\space (p-1)\\dq \equiv d\space mod\space (q-1)
$$
然后，由 RSA 加密算法可得：
$$
n = p*q\\c \equiv m^{e}\space mod\space n\\m \equiv c^{d}\space mod\space n
$$
因此，要求出密文 $m$ ，我们必须求出 $c^{d}$
由 $m \equiv c^{d}\space mod\space n$ 可得 $\exists\space k_{1} \in\mathbb{Z}, \space s.t.$ 
$$
m=c^{d}+k_{1}*n=c^{d}+k_{1}*p*q
$$
再对等式两边分别模 $p, q$ ，含 $p, q$ 的项在模 $p, q$ 时为 $0$ 得
$$
\begin{cases} m_{1} \equiv c^{d}\space mod\space p\cdots\cdots (1)\\m_{2} \equiv c^{d}\space mod\space q \cdots\cdots (2)\end{cases}
$$
(原文此处标注错误)
由 $(1)$ 式可得 $\exists\space k_{2} \in\mathbb{Z}, \space s.t.$ 
$$
c^{d}=k_{2}*p+m_1
$$
代入 $(2)$ 式可得 
$$
m_{2} \equiv (m_{1}+k_{2}*p)\space mod\space q
$$
可得 $\exists\space k_{3} \in\mathbb{Z}, \space s.t.$ 
$$
m_{2}=m_{1}+k_{2}*p+k_{3}*q
$$
移项，两边模 $q$ 可得
$$
(m_{2}-m{1})\equiv k_{2}*p\space mod\space q
$$
由于 
$$
gcd(p, q)=1
$$
由裴蜀定理，$\exists\space u,v \in\mathbb{Z}, \space s.t.$ 
$$
u*p+v*q=1
$$
两边模 $q$ 得
$$
u*p\equiv 1\space mod \space q
$$
故可以求p的逆元，且上式中的 $u$ 即为 $p$ 的逆元，即 $p^{-1}(mod\space q)$ ，得到
$$
(m_{2}-m_{1})*p^{-1}\equiv k_{2}\space mod\space q
$$
将以下三式
$$
k_{2}\equiv (m_{2}-m_{1})*p^{-1}\space mod\space q\\c^{d}=k_{2}*p+m_1\\m \equiv c^{d}\space mod\space n
$$
合并可得
$$
m \equiv (((m_{2}-m_{1})*p^{-1}\space mod\space q)*p+m_1)\space mod\space n
$$
最后求 $m_{1},m_{2}$ 
因为有
$$
\begin{cases} d \equiv dp\space mod\space (p-1)\\d \equiv dq\space mod\space (q-1) \end{cases}
$$
又
$$
\begin{cases} m_{1} \equiv c^{d}\space mod\space p\\m_{2} \equiv c^{d}\space mod\space q \end{cases}
$$
代入得
$$
\begin{cases} m_{1} \equiv c^{dp\space mod\space (p-1)}\space mod\space p\\m_{2} \equiv c^{dq\space mod\space (q-1) }\space mod\space q \end{cases}
$$
以 $dp$ 为例，由 $d \equiv dp\space mod\space (p-1)$ 可得 $\exists\space k \in\mathbb{Z}, \space s.t.$ 
$$
d = dp+k*(p-1)
$$
代入得
$$
m_{1} \equiv c^{dp+k*(p-1)} \space mod \space p\equiv c^{dp}*c^{k*(p-1)} \space mod \space p
$$
由费马小定理，因为 $p$ 是素数，且 $gce(p, c) = 1$（由于 $p$ 是大素数，而 $c$ 是偶数），则 
$$
c^{(p-1)} \equiv 1\space mod\space p
$$
故 $\exists\space k_{4} \in\mathbb{Z}, \space s.t.$ 
$$
c^{k*(p-1)} = (c^{p-1})^{k} = (1+k_{4}*p)^{k}
$$
对右式二项式展开再模 $p$ 可得
$$
c^{k*(p-1)}  \equiv 1 \space mod \space p
$$
故
$$
m_{1} \equiv c^{dp} \space mod \space p
$$
同理可得
$$
m_{2} \equiv c^{dq} \space mod \space q
$$
最终得方程组
$$
\begin{cases} m_{1} \equiv c^{dp} \space mod \space p\\m_{2} \equiv c^{dq} \space mod \space q\\m \equiv (((m_{2}-m_{1})*p^{-1}\space mod\space q)*p+m_1)\space mod\space n \end{cases}
$$
代码实现如下：

```python
from Crypto.Util.number import *
import libnum

p = 8637633767257008567099653486541091171320491509433615447539162437911244175885667806398411790524083553445158113502227745206205327690939504032994699902053229
q = 12640674973996472769176047937170883420927050821480010581593137135372473880595613737337630629752577346147039284030082593490776630572584959954205336880228469
dp = 6500795702216834621109042351193261530650043841056252930930949663358625016881832840728066026150264693076109354874099841380454881716097778307268116910582929
dq = 783472263673553449019532580386470672380574033551303889137911760438881683674556098098256795673512201963002175438762767516968043599582527539160811120550041
c = 24722305403887382073567316467649080662631552905960229399079107995602154418176056335800638887527614164073530437657085079676157350205351945222989351316076486573599576041978339872265925062764318536089007310270278526159678937431903862892400747915525118983959970607934142974736675784325993445942031372107342103852

def decrypt(dp, dq, p, q, c):
    n = p*q
    InvQ = inverse(p, q)
    m1 = pow(c, dp, p)
    m2 = pow(c, dq, q)
    m = ((((m2 - m1)*InvQ) % p) * p + m1) % n
    print(libnum.n2s(m))

decrypt(dp, dq, p, q, c)
```

## # 2021-4-3

## 凯撒？替换？呵呵

密文：MTHJ{CUBCGXGUGXWREXIPOYAOEYFIGXWRXCHTKHFCOHCFDUCGTXZOHIXOEOWMEHZO}
尝试用凯撒解密：
![](https://img-blog.csdnimg.cn/2021040322124019.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
不知道什么玩意儿
再用[替换密码爆破网站](https://quipqiup.com/)：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210403221320667.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
第一条有意义的语句删除空格，加大括号即为 flag 

## old-fashion

看题目就能猜到是古典密码
然后看到题目的一串字符：Os drnuzearyuwn, y jtkjzoztzoes douwlr oj y ilzwex eq lsdexosa kn pwodw tsozj eq ufyoszlbz yrl rlufydlx pozw douwlrzlbz, ydderxosa ze y rlatfyr jnjzli; mjy gfbmw vla xy wbfnsy symmyew (mjy vrwm qrvvrf), hlbew rd symmyew, mebhsymw rd symmyew, vbomgeyw rd mjy lxrzy, lfk wr dremj. Mjy eyqybzye kyqbhjyew mjy myom xa hyedrevbfn lf bfzyewy wgxwmbmgmbrf. Wr mjy dsln bw f1_2jyf-k3_jg1-vb-vl_l
猜想是替换密码
只不过没有 flag 前缀提示了![在这里插入图片描述](https://img-blog.csdnimg.cn/2021040322135021.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
尝试爆破，结尾显示的就是 flag

## 权限获得第一步

题目内容位Administrator:500:806EDC27AA52E314AAD3B435B51404EE:F4AD50F57683D4260DFD48AA351A17A8:::
联系题目
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210403221418319.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
联想到之前的《Windows系统密码》，易知用 MD5 解密
不出所料，前面一段仍然是“付费内容”
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210403221438264.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
第二段解密后为 flag
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210403221447813.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
“答案为非常规形式”大概是指结果为纯数字

## 萌萌哒的八戒

一看跟猪有关就知道是猪圈密码了
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210403221503108.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)题目给了一张图片：

题目给了一张图片：

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210403221518318.jpg)
对照猪圈密码表：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210403221749629.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
可得明文：WHENTHEPIGWANTTOEAT

# 2021-4-4

## RSA3

看到 c1, c2, e1, e2, n 就猜到是共模攻击
见 [CTF Wiki Crypto 部分 非对称加密 RSA 模数相关攻击](https://ctf-wiki.org/crypto/asymmetric/rsa/rsa_module_attack/)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210404191609511.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)

```python
from Crypto.Util.number import *
import gmpy2

c1 = 22322035275663237041646893770451933509324701913484303338076210603542612758956262869640822486470121149424485571361007421293675516338822195280313794991136048140918842471219840263536338886250492682739436410013436651161720725855484866690084788721349555662019879081501113222996123305533009325964377798892703161521852805956811219563883312896330156298621674684353919547558127920925706842808914762199011054955816534977675267395009575347820387073483928425066536361482774892370969520740304287456555508933372782327506569010772537497541764311429052216291198932092617792645253901478910801592878203564861118912045464959832566051361
n = 22708078815885011462462049064339185898712439277226831073457888403129378547350292420267016551819052430779004755846649044001024141485283286483130702616057274698473611149508798869706347501931583117632710700787228016480127677393649929530416598686027354216422565934459015161927613607902831542857977859612596282353679327773303727004407262197231586324599181983572622404590354084541788062262164510140605868122410388090174420147752408554129789760902300898046273909007852818474030770699647647363015102118956737673941354217692696044969695308506436573142565573487583507037356944848039864382339216266670673567488871508925311154801
e1 = 11187289
c2 = 18702010045187015556548691642394982835669262147230212731309938675226458555210425972429418449273410535387985931036711854265623905066805665751803269106880746769003478900791099590239513925449748814075904017471585572848473556490565450062664706449128415834787961947266259789785962922238701134079720414228414066193071495304612341052987455615930023536823801499269773357186087452747500840640419365011554421183037505653461286732740983702740822671148045619497667184586123657285604061875653909567822328914065337797733444640351518775487649819978262363617265797982843179630888729407238496650987720428708217115257989007867331698397
e2 = 9647291

print(GCD(e1, e2)) # 1

def exgcd(a, b): # 扩展欧几里得算法，求ua+vb=gcd(a,b)中的u,v
	if b == 0:
		u, v = 1, 0
		return (u, v)
	if a < b:
		a, b = b, a
	u, v = exgcd(b, a%b)
	u, v = v, u - a // b * v
	return (u, v)

u, v = exgcd(e1, e2)
print(u, v)
m = gmpy2.powmod(c1, u, n) * gmpy2.powmod(c2, v, n) % n
print(long_to_bytes(m))
```

得到 flag : flag{49d91077a1abcb14f1a9d546c80be9ef}

## 世上无难事

题目给了一串字符：
VIZZB IFIUOJBWO NVXAP OBC XZZ UKHVN IFIUOJBWO HB XVIXW XAW VXFI X QIXN VBD KQ IFIUOJBWO WBKAH NBWXO VBD XJBCN NKG QLKEIU DI XUI VIUI DKNV QNCWIANQ XN DXPIMKIZW VKHV QEVBBZ KA XUZKAHNBA FKUHKAKX XAW DI VXFI HBN QNCWIANQ NCAKAH KA MUBG XZZ XEUBQQ XGIUKEX MUBG PKAWIUHXUNIA NVUBCHV 12NV HUXWI XAW DI XUI SCQN QB HZXW NVXN XZZ EBCZW SBKA CQ NBWXO XAW DI DXAN NB NVXAP DXPIMKIZW MBU JIKAH QCEV XA BCNQNXAWKAH VBQN HKFI OBCUQIZFIQ X JKH UBCAW BM XLLZXCQI XAW NVI PIO KQ 640I11012805M211J0XJ24MM02X1IW09
不知道是什么，猜想为替换密码，尝试爆破：[https://quipqiup.com/](https://quipqiup.com/)
得到结果：
![在这里插入图片描述](https://img-blog.csdnimg.cn/2021040419230693.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70)
flag 为 640E11012805F211B0AB24FF02A1ED09
再将大写字母替换成小写字母：

```python
key = '640E11012805F211B0AB24FF02A1ED09'
flag = ''

for i in range(len(key)):

    if ord('A') <= ord(key[i]) <= ord('Z'):
        flag += chr(ord(key[i]) - ord('A') + ord('a'))
    else:
        flag += key[i]
print(flag)
```

## 