# 2021-7-26

## [watevrCTF 2019]Swedish RSA

加密代码如下：

```python
flag = bytearray(raw_input())
flag = list(flag)
length = len(flag)
bits = 16

## Prime for Finite Field.
p = random_prime(2^bits-1, False, 2^(bits-1))

file_out = open("downloads/polynomial_rsa.txt", "w")
file_out.write("Prime: " + str(p) + "\n")

## Univariate Polynomial Ring in y over Finite Field of size p
R.<y> = PolynomialRing(GF(p))

## Analogous to the primes in Z
def gen_irreducable_poly(deg):
    while True:
        out = R.random_element(degree=deg)
        if out.is_irreducible():
            return out

## Polynomial "primes"
P = gen_irreducable_poly(ZZ.random_element(length, 2*length))
Q = gen_irreducable_poly(ZZ.random_element(length, 2*length))

## Public exponent key
e = 65537

## Modulus
N = P*Q
file_out.write("Modulus: " + str(N) + "\n")

## Univariate Quotient Polynomial Ring in x over Finite Field of size 659 with modulus N(x)
S.<x> = R.quotient(N)

## Encrypt
m = S(flag)
c = m^e

file_out.write("Ciphertext: " + str(c))
file_out.close()
```

给了密文和公钥：

```python
Prime: 43753
Modulus: 34036*y^177 + 23068*y^176 + 13147*y^175 + 36344*y^174 + 10045*y^173 + 41049*y^172 + 17786*y^171 + 16601*y^170 + 7929*y^169 + 37570*y^168 + 990*y^167 + 9622*y^166 + 39273*y^165 + 35284*y^164 + 15632*y^163 + 18850*y^162 + 8800*y^161 + 33148*y^160 + 12147*y^159 + 40487*y^158 + 6407*y^157 + 34111*y^156 + 8446*y^155 + 21908*y^154 + 16812*y^153 + 40624*y^152 + 43506*y^151 + 39116*y^150 + 33011*y^149 + 23914*y^148 + 2210*y^147 + 23196*y^146 + 43359*y^145 + 34455*y^144 + 17684*y^143 + 25262*y^142 + 982*y^141 + 24015*y^140 + 27968*y^139 + 37463*y^138 + 10667*y^137 + 39519*y^136 + 31176*y^135 + 27520*y^134 + 32118*y^133 + 8333*y^132 + 38945*y^131 + 34713*y^130 + 1107*y^129 + 43604*y^128 + 4433*y^127 + 18110*y^126 + 17658*y^125 + 32354*y^124 + 3219*y^123 + 40238*y^122 + 10439*y^121 + 3669*y^120 + 8713*y^119 + 21027*y^118 + 29480*y^117 + 5477*y^116 + 24332*y^115 + 43480*y^114 + 33406*y^113 + 43121*y^112 + 1114*y^111 + 17198*y^110 + 22829*y^109 + 24424*y^108 + 16523*y^107 + 20424*y^106 + 36206*y^105 + 41849*y^104 + 3584*y^103 + 26500*y^102 + 31897*y^101 + 34640*y^100 + 27449*y^99 + 30962*y^98 + 41434*y^97 + 22125*y^96 + 24314*y^95 + 3944*y^94 + 18400*y^93 + 38476*y^92 + 28904*y^91 + 27936*y^90 + 41867*y^89 + 25573*y^88 + 25659*y^87 + 33443*y^86 + 18435*y^85 + 5934*y^84 + 38030*y^83 + 17563*y^82 + 24086*y^81 + 36782*y^80 + 20922*y^79 + 38933*y^78 + 23448*y^77 + 10599*y^76 + 7156*y^75 + 29044*y^74 + 23605*y^73 + 7657*y^72 + 28200*y^71 + 2431*y^70 + 3860*y^69 + 23259*y^68 + 14590*y^67 + 33631*y^66 + 15673*y^65 + 36049*y^64 + 29728*y^63 + 22413*y^62 + 18602*y^61 + 18557*y^60 + 23505*y^59 + 17642*y^58 + 12595*y^57 + 17255*y^56 + 15316*y^55 + 8948*y^54 + 38*y^53 + 40329*y^52 + 9823*y^51 + 5798*y^50 + 6379*y^49 + 8662*y^48 + 34640*y^47 + 38321*y^46 + 18760*y^45 + 13135*y^44 + 15926*y^43 + 34952*y^42 + 28940*y^41 + 13558*y^40 + 42579*y^39 + 38015*y^38 + 33788*y^37 + 12381*y^36 + 195*y^35 + 13709*y^34 + 31500*y^33 + 32994*y^32 + 30486*y^31 + 40414*y^30 + 2578*y^29 + 30525*y^28 + 43067*y^27 + 6195*y^26 + 36288*y^25 + 23236*y^24 + 21493*y^23 + 15808*y^22 + 34500*y^21 + 6390*y^20 + 42994*y^19 + 42151*y^18 + 19248*y^17 + 19291*y^16 + 8124*y^15 + 40161*y^14 + 24726*y^13 + 31874*y^12 + 30272*y^11 + 30761*y^10 + 2296*y^9 + 11017*y^8 + 16559*y^7 + 28949*y^6 + 40499*y^5 + 22377*y^4 + 33628*y^3 + 30598*y^2 + 4386*y + 23814
Ciphertext: 5209*x^176 + 10881*x^175 + 31096*x^174 + 23354*x^173 + 28337*x^172 + 15982*x^171 + 13515*x^170 + 21641*x^169 + 10254*x^168 + 34588*x^167 + 27434*x^166 + 29552*x^165 + 7105*x^164 + 22604*x^163 + 41253*x^162 + 42675*x^161 + 21153*x^160 + 32838*x^159 + 34391*x^158 + 832*x^157 + 720*x^156 + 22883*x^155 + 19236*x^154 + 33772*x^153 + 5020*x^152 + 17943*x^151 + 26967*x^150 + 30847*x^149 + 10306*x^148 + 33966*x^147 + 43255*x^146 + 20342*x^145 + 4474*x^144 + 3490*x^143 + 38033*x^142 + 11224*x^141 + 30565*x^140 + 31967*x^139 + 32382*x^138 + 9759*x^137 + 1030*x^136 + 32122*x^135 + 42614*x^134 + 14280*x^133 + 16533*x^132 + 32676*x^131 + 43070*x^130 + 36009*x^129 + 28497*x^128 + 2940*x^127 + 9747*x^126 + 22758*x^125 + 16615*x^124 + 14086*x^123 + 13038*x^122 + 39603*x^121 + 36260*x^120 + 32502*x^119 + 17619*x^118 + 17700*x^117 + 15083*x^116 + 11311*x^115 + 36496*x^114 + 1300*x^113 + 13601*x^112 + 43425*x^111 + 10376*x^110 + 11551*x^109 + 13684*x^108 + 14955*x^107 + 6661*x^106 + 12674*x^105 + 21534*x^104 + 32132*x^103 + 34135*x^102 + 43684*x^101 + 837*x^100 + 29311*x^99 + 4849*x^98 + 26632*x^97 + 26662*x^96 + 10159*x^95 + 32657*x^94 + 12149*x^93 + 17858*x^92 + 35805*x^91 + 19391*x^90 + 30884*x^89 + 42039*x^88 + 17292*x^87 + 4694*x^86 + 1497*x^85 + 1744*x^84 + 31071*x^83 + 26246*x^82 + 24402*x^81 + 22068*x^80 + 39263*x^79 + 23703*x^78 + 21484*x^77 + 12241*x^76 + 28821*x^75 + 32886*x^74 + 43075*x^73 + 35741*x^72 + 19936*x^71 + 37219*x^70 + 33411*x^69 + 8301*x^68 + 12949*x^67 + 28611*x^66 + 42654*x^65 + 6910*x^64 + 18523*x^63 + 31144*x^62 + 21398*x^61 + 36298*x^60 + 27158*x^59 + 918*x^58 + 38601*x^57 + 4269*x^56 + 5699*x^55 + 36444*x^54 + 34791*x^53 + 37978*x^52 + 32481*x^51 + 8039*x^50 + 11012*x^49 + 11454*x^48 + 30450*x^47 + 1381*x^46 + 32403*x^45 + 8202*x^44 + 8404*x^43 + 37648*x^42 + 43696*x^41 + 34237*x^40 + 36490*x^39 + 41423*x^38 + 35792*x^37 + 36950*x^36 + 31086*x^35 + 38970*x^34 + 12439*x^33 + 7963*x^32 + 16150*x^31 + 11382*x^30 + 3038*x^29 + 20157*x^28 + 23531*x^27 + 32866*x^26 + 5428*x^25 + 21132*x^24 + 13443*x^23 + 28909*x^22 + 42716*x^21 + 6567*x^20 + 24744*x^19 + 8727*x^18 + 14895*x^17 + 28172*x^16 + 30903*x^15 + 26608*x^14 + 27314*x^13 + 42224*x^12 + 42551*x^11 + 37726*x^10 + 11203*x^9 + 36816*x^8 + 5537*x^7 + 20301*x^6 + 17591*x^5 + 41279*x^4 + 7999*x^3 + 33753*x^2 + 34551*x + 9659
```

多项式RSA总是避而远之，半懂不懂的sage代码，好几次比赛都没做出来
先来回顾一下传统的RSA：
![在这里插入图片描述](luozj1020 vacation_week3.assets/2478dd805e294423ba5e89570455ed03.png)
本题的加密过程与经典的RSA加密十分类似
不同的是，m、N、c都是多项式，这就难搞了
而且这个p是什么意思？$\varphi$该这么算？
找了一个[wp](https://blog.csdn.net/cccchhhh6819/article/details/103563019)
看懂了，但没完全看懂
又找了一篇博客：[有限域上的多项式](https://www.ruanx.net/polynomial-rsa/)，也是对这道题的解，而且给予了较为详细的数学知识补充
以下是对上述两个问题的解答，以及解题思路
首先看这段代码：

```python
## Analogous to the primes in Z
def gen_irreducable_poly(deg):
    while True:
        out = R.random_element(degree=deg)
        if out.is_irreducible():
            return out

## Polynomial "primes"
P = gen_irreducable_poly(ZZ.random_element(length, 2*length))
Q = gen_irreducable_poly(ZZ.random_element(length, 2*length))
```

先来看这个函数，“irreducible”意思是“不可约的”，也就是说生成了P、Q两个不可约多项式，容易联想到经典RSA的两个大质数
deg则代表了多项式的次数，也就是多项式最高次项的指数大小（高代中常用deg(f)表示多项式的次数，后知后觉）
而length则是flag的次数
也就是说$deg(flag) \leq deg(P) \leq 2deg(flag),deg(flag) \leq deg(Q) \leq 2deg(flag)$
容易想到要分解N来得到P，Q
sage代码如下：
![在这里插入图片描述](luozj1020 vacation_week3.assets/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70.png)
可以得到：

```python
P = (34036) * (y^65 + 39688*y^64 + 22199*y^63 + 41942*y^62 + 7803*y^61 + 19710*y^60 + 14794*y^59 + 41388*y^58 + 2418*y^57 + 19208*y^56 + 39941*y^55 + 36392*y^54 + 19813*y^53 + 33864*y^52 + 29099*y^51 + 15484*y^50 + 27185*y^49 + 27721*y^48 + 31508*y^47 + 19404*y^46 + 10134*y^45 + 43481*y^44 + 3899*y^43 + 32849*y^42 + 3534*y^41 + 32086*y^40 + 14221*y^39 + 42982*y^38 + 1403*y^37 + 1619*y^36 + 36054*y^35 + 33615*y^34 + 6628*y^33 + 31709*y^32 + 6968*y^31 + 28517*y^30 + 12938*y^29 + 21124*y^28 + 10400*y^27 + 28889*y^26 + 7273*y^25 + 36442*y^24 + 14935*y^23 + 29365*y^22 + 4869*y^21 + 43562*y^20 + 6435*y^19 + 4403*y^18 + 32311*y^17 + 7575*y^16 + 28199*y^15 + 28065*y^14 + 23870*y^13 + 37314*y^12 + 15299*y^11 + 7082*y^10 + 36230*y^9 + 18367*y^8 + 12531*y^7 + 25906*y^6 + 26878*y^5 + 43073*y^4 + 11582*y^3 + 4482*y^2 + 35044*y + 31388)
Q = (y^112 + 31097*y^111 + 15815*y^110 + 17170*y^109 + 43684*y^108 + 16873*y^107 + 17269*y^106 + 10853*y^105 + 10690*y^104 + 24864*y^103 + 10224*y^102 + 28704*y^101 + 16049*y^100 + 1154*y^99 + 40034*y^98 + 29922*y^97 + 27404*y^96 + 32514*y^95 + 40962*y^94 + 32858*y^93 + 36590*y^92 + 41302*y^91 + 20803*y^90 + 43521*y^89 + 13746*y^88 + 19857*y^87 + 21539*y^86 + 36888*y^85 + 16032*y^84 + 35825*y^83 + 24705*y^82 + 31143*y^81 + 22088*y^80 + 6686*y^79 + 37947*y^78 + 5661*y^77 + 29405*y^76 + 36071*y^75 + 35492*y^74 + 28985*y^73 + 36015*y^72 + 24095*y^71 + 34920*y^70 + 6615*y^69 + 9606*y^68 + 4255*y^67 + 22981*y^66 + 3910*y^65 + 23897*y^64 + 22711*y^63 + 23350*y^62 + 7969*y^61 + 8558*y^60 + 8001*y^59 + 8431*y^58 + 3314*y^57 + 23364*y^56 + 39391*y^55 + 32722*y^54 + 2543*y^53 + 22196*y^52 + 24189*y^51 + 19420*y^50 + 10649*y^49 + 19070*y^48 + 23863*y^47 + 19597*y^46 + 39699*y^45 + 7620*y^44 + 25067*y^43 + 29912*y^42 + 14998*y^41 + 14492*y^40 + 31322*y^39 + 43145*y^38 + 32006*y^37 + 38976*y^36 + 32534*y^35 + 6972*y^34 + 37351*y^33 + 30104*y^32 + 6032*y^31 + 33729*y^30 + 27110*y^29 + 5268*y^28 + 2974*y^27 + 2985*y^26 + 31610*y^25 + 28364*y^24 + 34924*y^23 + 17414*y^22 + 28813*y^21 + 43680*y^20 + 32175*y^19 + 18248*y^18 + 25171*y^17 + 31185*y^16 + 30125*y^15 + 36836*y^14 + 7218*y^13 + 11292*y^12 + 31123*y^11 + 40360*y^10 + 34093*y^9 + 39606*y^8 + 2788*y^7 + 27277*y^6 + 21835*y^5 + 1331*y^4 + 32614*y^3 + 25020*y^2 + 20981*y + 12108)
```

得知$deg(P) = 65, deg(Q) = 112$
那么欧拉函数$\varphi$该怎么算？还是$\varphi (N) = \varphi (P) \varphi (Q) = (P-1)(Q-1)$吗？
感觉好像不太对，**欧拉函数**$\varphi (n)$表示小于n的所有与n互质的数的个数，那么在多项式中应该表示小于n的所有与n互质的多项式的个数，也就是小于n的所有与n没有公因式的多项式的个数
但在第一篇wp中，就直接给了结果：
![在这里插入图片描述](luozj1020 vacation_week3.assets/b768876e1f7d48688a822b0f04451e28.png)
后来在第二篇wp中，我找到了解释：
![在这里插入图片描述](luozj1020 vacation_week3.assets/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70.png)
![在这里插入图片描述](luozj1020 vacation_week3.assets/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70.png)
现在来解决第一个问题：p是什么意思，或者说```R.<y> = PolynomialRing(GF(p))```是什么意思？
如注释中所说的：## Univariate Polynomial Ring in y over Finite Field of size p（以p为大小的有限域中的关于y的单变量多项式环）
你说这个谁懂啊！（抽象代数下学期才学，残念）
借助第二篇wp补充的数学知识，**以p为大小的有限域**可以大致理解为这个数域里的元素或者说数都是以模p的形式存在，也就是说大小不会超过p，一般记为$\mathbb{F_p}$
至于什么是多项式环，先要理解什么是环
可以简单理解为是一个满足乘法、加法并拥有分配律的数集，而多项式环就是系数取自这个数集的多项式的集合
博客中给了一个例子：
![在这里插入图片描述](luozj1020 vacation_week3.assets/572269eaad964b9984b1246715a2b991.png)
![在这里插入图片描述](luozj1020 vacation_week3.assets/3f889312dd8b42da821228ae4c039656.png)
问题基本上解决了之后，继续解题
由上述可知，$\varphi (N) = \varphi (P) \varphi (Q) = (p^{deg(P)}-1)(p^{deg(Q)}-1)=(43753^{65}-1)\times (43753^{112}-1)$
接着就是求e的逆元d，然后还原出flag即可
参考第一篇wp得到flag：
![在这里插入图片描述](luozj1020 vacation_week3.assets/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70.png)
然后将flag的系数倒序转化成字符输出即为答案：
![在这里插入图片描述](luozj1020 vacation_week3.assets/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70.png)
完整sage代码如下：

```python
R.<y> = PolynomialRing(GF(43753))
C = 5209*y^176 + 10881*y^175 + 31096*y^174 + 23354*y^173 + 28337*y^172 + 15982*y^171 + 13515*y^170 + 21641*y^169 + 10254*y^168 + 34588*y^167 + 27434*y^166 + 29552*y^165 + 7105*y^164 + 22604*y^163 + 41253*y^162 + 42675*y^161 + 21153*y^160 + 32838*y^159 + 34391*y^158 + 832*y^157 + 720*y^156 + 22883*y^155 + 19236*y^154 + 33772*y^153 + 5020*y^152 + 17943*y^151 + 26967*y^150 + 30847*y^149 + 10306*y^148 + 33966*y^147 + 43255*y^146 + 20342*y^145 + 4474*y^144 + 3490*y^143 + 38033*y^142 + 11224*y^141 + 30565*y^140 + 31967*y^139 + 32382*y^138 + 9759*y^137 + 1030*y^136 + 32122*y^135 + 42614*y^134 + 14280*y^133 + 16533*y^132 + 32676*y^131 + 43070*y^130 + 36009*y^129 + 28497*y^128 + 2940*y^127 + 9747*y^126 + 22758*y^125 + 16615*y^124 + 14086*y^123 + 13038*y^122 + 39603*y^121 + 36260*y^120 + 32502*y^119 + 17619*y^118 + 17700*y^117 + 15083*y^116 + 11311*y^115 + 36496*y^114 + 1300*y^113 + 13601*y^112 + 43425*y^111 + 10376*y^110 + 11551*y^109 + 13684*y^108 + 14955*y^107 + 6661*y^106 + 12674*y^105 + 21534*y^104 + 32132*y^103 + 34135*y^102 + 43684*y^101 + 837*y^100 + 29311*y^99 + 4849*y^98 + 26632*y^97 + 26662*y^96 + 10159*y^95 + 32657*y^94 + 12149*y^93 + 17858*y^92 + 35805*y^91 + 19391*y^90 + 30884*y^89 + 42039*y^88 + 17292*y^87 + 4694*y^86 + 1497*y^85 + 1744*y^84 + 31071*y^83 + 26246*y^82 + 24402*y^81 + 22068*y^80 + 39263*y^79 + 23703*y^78 + 21484*y^77 + 12241*y^76 + 28821*y^75 + 32886*y^74 + 43075*y^73 + 35741*y^72 + 19936*y^71 + 37219*y^70 + 33411*y^69 + 8301*y^68 + 12949*y^67 + 28611*y^66 + 42654*y^65 + 6910*y^64 + 18523*y^63 + 31144*y^62 + 21398*y^61 + 36298*y^60 + 27158*y^59 + 918*y^58 + 38601*y^57 + 4269*y^56 + 5699*y^55 + 36444*y^54 + 34791*y^53 + 37978*y^52 + 32481*y^51 + 8039*y^50 + 11012*y^49 + 11454*y^48 + 30450*y^47 + 1381*y^46 + 32403*y^45 + 8202*y^44 + 8404*y^43 + 37648*y^42 + 43696*y^41 + 34237*y^40 + 36490*y^39 + 41423*y^38 + 35792*y^37 + 36950*y^36 + 31086*y^35 + 38970*y^34 + 12439*y^33 + 7963*y^32 + 16150*y^31 + 11382*y^30 + 3038*y^29 + 20157*y^28 + 23531*y^27 + 32866*y^26 + 5428*y^25 + 21132*y^24 + 13443*y^23 + 28909*y^22 + 42716*y^21 + 6567*y^20 + 24744*y^19 + 8727*y^18 + 14895*y^17 + 28172*y^16 + 30903*y^15 + 26608*y^14 + 27314*y^13 + 42224*y^12 + 42551*y^11 + 37726*y^10 + 11203*y^9 + 36816*y^8 + 5537*y^7 + 20301*y^6 + 17591*y^5 + 41279*y^4 + 7999*y^3 + 33753*y^2 + 34551*y + 9659
N = 34036*y^177 + 23068*y^176 + 13147*y^175 + 36344*y^174 + 10045*y^173 + 41049*y^172 + 17786*y^171 + 16601*y^170 + 7929*y^169 + 37570*y^168 + 990*y^167 + 9622*y^166 + 39273*y^165 + 35284*y^164 + 15632*y^163 + 18850*y^162 + 8800*y^161 + 33148*y^160 + 12147*y^159 + 40487*y^158 + 6407*y^157 + 34111*y^156 + 8446*y^155 + 21908*y^154 + 16812*y^153 + 40624*y^152 + 43506*y^151 + 39116*y^150 + 33011*y^149 + 23914*y^148 + 2210*y^147 + 23196*y^146 + 43359*y^145 + 34455*y^144 + 17684*y^143 + 25262*y^142 + 982*y^141 + 24015*y^140 + 27968*y^139 + 37463*y^138 + 10667*y^137 + 39519*y^136 + 31176*y^135 + 27520*y^134 + 32118*y^133 + 8333*y^132 + 38945*y^131 + 34713*y^130 + 1107*y^129 + 43604*y^128 + 4433*y^127 + 18110*y^126 + 17658*y^125 + 32354*y^124 + 3219*y^123 + 40238*y^122 + 10439*y^121 + 3669*y^120 + 8713*y^119 + 21027*y^118 + 29480*y^117 + 5477*y^116 + 24332*y^115 + 43480*y^114 + 33406*y^113 + 43121*y^112 + 1114*y^111 + 17198*y^110 + 22829*y^109 + 24424*y^108 + 16523*y^107 + 20424*y^106 + 36206*y^105 + 41849*y^104 + 3584*y^103 + 26500*y^102 + 31897*y^101 + 34640*y^100 + 27449*y^99 + 30962*y^98 + 41434*y^97 + 22125*y^96 + 24314*y^95 + 3944*y^94 + 18400*y^93 + 38476*y^92 + 28904*y^91 + 27936*y^90 + 41867*y^89 + 25573*y^88 + 25659*y^87 + 33443*y^86 + 18435*y^85 + 5934*y^84 + 38030*y^83 + 17563*y^82 + 24086*y^81 + 36782*y^80 + 20922*y^79 + 38933*y^78 + 23448*y^77 + 10599*y^76 + 7156*y^75 + 29044*y^74 + 23605*y^73 + 7657*y^72 + 28200*y^71 + 2431*y^70 + 3860*y^69 + 23259*y^68 + 14590*y^67 + 33631*y^66 + 15673*y^65 + 36049*y^64 + 29728*y^63 + 22413*y^62 + 18602*y^61 + 18557*y^60 + 23505*y^59 + 17642*y^58 + 12595*y^57 + 17255*y^56 + 15316*y^55 + 8948*y^54 + 38*y^53 + 40329*y^52 + 9823*y^51 + 5798*y^50 + 6379*y^49 + 8662*y^48 + 34640*y^47 + 38321*y^46 + 18760*y^45 + 13135*y^44 + 15926*y^43 + 34952*y^42 + 28940*y^41 + 13558*y^40 + 42579*y^39 + 38015*y^38 + 33788*y^37 + 12381*y^36 + 195*y^35 + 13709*y^34 + 31500*y^33 + 32994*y^32 + 30486*y^31 + 40414*y^30 + 2578*y^29 + 30525*y^28 + 43067*y^27 + 6195*y^26 + 36288*y^25 + 23236*y^24 + 21493*y^23 + 15808*y^22 + 34500*y^21 + 6390*y^20 + 42994*y^19 + 42151*y^18 + 19248*y^17 + 19291*y^16 + 8124*y^15 + 40161*y^14 + 24726*y^13 + 31874*y^12 + 30272*y^11 + 30761*y^10 + 2296*y^9 + 11017*y^8 + 16559*y^7 + 28949*y^6 + 40499*y^5 + 22377*y^4 + 33628*y^3 + 30598*y^2 + 4386*y + 23814
e = 65537 
print(factor(N))

P = (34036) * (y^65 + 39688*y^64 + 22199*y^63 + 41942*y^62 + 7803*y^61 + 19710*y^60 + 14794*y^59 + 41388*y^58 + 2418*y^57 + 19208*y^56 + 39941*y^55 + 36392*y^54 + 19813*y^53 + 33864*y^52 + 29099*y^51 + 15484*y^50 + 27185*y^49 + 27721*y^48 + 31508*y^47 + 19404*y^46 + 10134*y^45 + 43481*y^44 + 3899*y^43 + 32849*y^42 + 3534*y^41 + 32086*y^40 + 14221*y^39 + 42982*y^38 + 1403*y^37 + 1619*y^36 + 36054*y^35 + 33615*y^34 + 6628*y^33 + 31709*y^32 + 6968*y^31 + 28517*y^30 + 12938*y^29 + 21124*y^28 + 10400*y^27 + 28889*y^26 + 7273*y^25 + 36442*y^24 + 14935*y^23 + 29365*y^22 + 4869*y^21 + 43562*y^20 + 6435*y^19 + 4403*y^18 + 32311*y^17 + 7575*y^16 + 28199*y^15 + 28065*y^14 + 23870*y^13 + 37314*y^12 + 15299*y^11 + 7082*y^10 + 36230*y^9 + 18367*y^8 + 12531*y^7 + 25906*y^6 + 26878*y^5 + 43073*y^4 + 11582*y^3 + 4482*y^2 + 35044*y + 31388)
Q = (y^112 + 31097*y^111 + 15815*y^110 + 17170*y^109 + 43684*y^108 + 16873*y^107 + 17269*y^106 + 10853*y^105 + 10690*y^104 + 24864*y^103 + 10224*y^102 + 28704*y^101 + 16049*y^100 + 1154*y^99 + 40034*y^98 + 29922*y^97 + 27404*y^96 + 32514*y^95 + 40962*y^94 + 32858*y^93 + 36590*y^92 + 41302*y^91 + 20803*y^90 + 43521*y^89 + 13746*y^88 + 19857*y^87 + 21539*y^86 + 36888*y^85 + 16032*y^84 + 35825*y^83 + 24705*y^82 + 31143*y^81 + 22088*y^80 + 6686*y^79 + 37947*y^78 + 5661*y^77 + 29405*y^76 + 36071*y^75 + 35492*y^74 + 28985*y^73 + 36015*y^72 + 24095*y^71 + 34920*y^70 + 6615*y^69 + 9606*y^68 + 4255*y^67 + 22981*y^66 + 3910*y^65 + 23897*y^64 + 22711*y^63 + 23350*y^62 + 7969*y^61 + 8558*y^60 + 8001*y^59 + 8431*y^58 + 3314*y^57 + 23364*y^56 + 39391*y^55 + 32722*y^54 + 2543*y^53 + 22196*y^52 + 24189*y^51 + 19420*y^50 + 10649*y^49 + 19070*y^48 + 23863*y^47 + 19597*y^46 + 39699*y^45 + 7620*y^44 + 25067*y^43 + 29912*y^42 + 14998*y^41 + 14492*y^40 + 31322*y^39 + 43145*y^38 + 32006*y^37 + 38976*y^36 + 32534*y^35 + 6972*y^34 + 37351*y^33 + 30104*y^32 + 6032*y^31 + 33729*y^30 + 27110*y^29 + 5268*y^28 + 2974*y^27 + 2985*y^26 + 31610*y^25 + 28364*y^24 + 34924*y^23 + 17414*y^22 + 28813*y^21 + 43680*y^20 + 32175*y^19 + 18248*y^18 + 25171*y^17 + 31185*y^16 + 30125*y^15 + 36836*y^14 + 7218*y^13 + 11292*y^12 + 31123*y^11 + 40360*y^10 + 34093*y^9 + 39606*y^8 + 2788*y^7 + 27277*y^6 + 21835*y^5 + 1331*y^4 + 32614*y^3 + 25020*y^2 + 20981*y + 12108)
phi = (43753^65-1)*(43753^112-1)  
d = inverse_mod(e, phi)  
ans = R("1")  
temp= C  
while(True):  
    if(d % 2 == 1):  
        ans = (ans * temp) % N  
        d = d - 1  
    d = d / 2  
    temp = (temp * temp) % N  
    if(d == 0):  
        break  
#快速幂  
print (ans)  

m = "125*y^62 + 111*y^61 + 114*y^60 + 117*y^59 + 53*y^58 + 51*y^57 + 51*y^56 + 100*y^55 + 106*y^54 + 110*y^53 + 102*y^52 + 106*y^51 + 100*y^50 + 104*y^49 + 101*y^48 + 117*y^47 + 52*y^46 + 52*y^45 + 57*y^44 + 48*y^43 + 50*y^42 + 107*y^41 + 35*y^40 + 101*y^39 + 114*y^38 + 117*y^37 + 99*y^36 + 101*y^35 + 115*y^34 + 110*y^33 + 105*y^32 + 95*y^31 + 116*y^30 + 117*y^29 + 98*y^28 + 95*y^27 + 110*y^26 + 117*y^25 + 102*y^24 + 95*y^23 + 115*y^22 + 105*y^21 + 95*y^20 + 97*y^19 + 101*y^18 + 107*y^17 + 105*y^16 + 95*y^15 + 109*y^14 + 111*y^13 + 114*y^12 + 102*y^11 + 95*y^10 + 65*y^9 + 83*y^8 + 82*y^7 + 123*y^6 + 114*y^5 + 118*y^4 + 101*y^3 + 116*y^2 + 97*y + 119"
ml = m.split("+")
flag = ''
for i in range(len(ml)-1, -1, -1):
    tmp = ''
    for j in range(len(ml[i])):
        if ml[i][j] == '*':
            break
        tmp += ml[i][j]
    flag += chr(int(tmp))
print(flag)
```

# 2021-7-27

## [ACTF新生赛2020]crypto-des

题目给了一串浮点数：

```python
72143238992041641000000.000000,
77135357178006504000000000000000.000000,
1125868345616435400000000.000000,
67378029765916820000000.000000,
75553486092184703000000000000.000000,
4397611913739958700000.000000,
76209378028621039000000000000000.000000
```

还有一个提示：
To solve the key, Maybe you know some interesting data format about C language?
数据类型？double？有什么用啊？
还有一个加密的压缩包，试了试爆破，没成功
直接找[wp](https://blog.csdn.net/MikeCoke/article/details/113796480)，原来考的是关于数据在内存中的存储（完全不会呢）
对wp中的解题代码做了一些修改：

```python
from Crypto.Util.number import *
import struct

s = [72143238992041641000000.000000, 77135357178006504000000000000000.000000, 1125868345616435400000000.000000, 67378029765916820000000.000000, 75553486092184703000000000000.000000, 4397611913739958700000.000000, 76209378028621039000000000000000.000000]
a = ''
b = ''
for i in s:
    a += struct.pack('<f', i).hex()        # 小端
print(a)

for j in s:
    b += struct.pack('>f', j).hex()        # 大端
print(b)

print(long_to_bytes(int(a, 16)))
print(long_to_bytes(int(b, 16)))
```

wp中的注释“大端”“小端”（wp中写成两个“小端”了）还有```struct.pack('<f', i)```让我挺在意的
于是就找了[struct库的官方文档](https://docs.python.org/zh-cn/3/library/struct.html)，有这么一段话：
![在这里插入图片描述](luozj1020 vacation_week3.assets/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70.png)
不难猜想，解题代码同时写了大端和小端是因为不同的计算机是不一样的
而后面的"f"是格式字符：
![在这里插入图片描述](luozj1020 vacation_week3.assets/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70.png)
那么什么是大端和小端呢？参考[知乎文章：什么是大端序和小端序，为什么要有字节序？](https://zhuanlan.zhihu.com/p/352145413)
![在这里插入图片描述](luozj1020 vacation_week3.assets/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70.png)
简单来说一个是正着写（按照人类阅读习惯），一个是倒着写（符合计算机读取习惯）
解题代码输出结果为：
![在这里插入图片描述](luozj1020 vacation_week3.assets/77b764b8306249358ae28ec99b03fd55.png)
得到压缩包密码：Interestring Idea to encrypt
解压之后得到一个加密程序：

```python
import pyDes
import base64
from FLAG import flag
deskey = "********"
DES = pyDes.des(deskey)
DES.setMode('ECB')
DES.Kn = [
			[1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 0],
			[1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0], 
			[0, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0],
			[1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1], 
			[0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1],
			[0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0],
			[0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0],
			[0, 0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0],
			[1, 0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0],
			[0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0],
			[0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1],
			[0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 0],
			[1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 1, 0, 0],
			[1, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1],
			[1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1],
			[1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 1]
		]
cipher_list = base64.b64encode(DES.encrypt(flag))
#b'vrkgBqeK7+h7mPyWujP8r5FqH5yyVlqv0CXudqoNHVAVdNO8ML4lM4zgez7weQXo'
```

照应了标题的crypto-des
DES和AES一样属于块加密，深究起来的话也很麻烦
这道题只要照着加密脚本写解密脚本就行了
解密代码如下：

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 7/27/2021 4:19 PM
# @Author  : Σ2333!
# @File    : solution.py
# @Software: PyCharm
import pyDes
import base64

deskey = "********"
DES = pyDes.des(deskey)
DES.setMode('ECB')
DES.Kn = [
			[1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 0],
			[1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0],
			[0, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0],
			[1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1],
			[0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1],
			[0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0],
			[0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0],
			[0, 0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0],
			[1, 0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0],
			[0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0],
			[0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1],
			[0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 0],
			[1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 1, 0, 0],
			[1, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1],
			[1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1],
			[1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 1]
		]

# cipher_list = base64.b64encode(DES.encrypt(flag))
c = b'vrkgBqeK7+h7mPyWujP8r5FqH5yyVlqv0CXudqoNHVAVdNO8ML4lM4zgez7weQXo'
m = DES.decrypt(base64.b64decode(c))
print(m)
```

# 2021-7-28

## [De1CTF2019]xorz

加密代码如下：

```python
from itertools import *
from data import flag,plain

key=flag.strip("de1ctf{").strip("}")
assert(len(key)<38)
salt="WeAreDe1taTeam"
ki=cycle(key)
si=cycle(salt)
cipher = ''.join([hex(ord(p) ^ ord(next(ki)) ^ ord(next(si)))[2:].zfill(2) for p in plain])
print cipher
# output:
# 49380d773440222d1b421b3060380c3f403c3844791b202651306721135b6229294a3c3222357e766b2f15561b35305e3c3b670e49382c295c6c170553577d3a2b791470406318315d753f03637f2b614a4f2e1c4f21027e227a4122757b446037786a7b0e37635024246d60136f7802543e4d36265c3e035a725c6322700d626b345d1d6464283a016f35714d434124281b607d315f66212d671428026a4f4f79657e34153f3467097e4e135f187a21767f02125b375563517a3742597b6c394e78742c4a725069606576777c314429264f6e330d7530453f22537f5e3034560d22146831456b1b72725f30676d0d5c71617d48753e26667e2f7a334c731c22630a242c7140457a42324629064441036c7e646208630e745531436b7c51743a36674c4f352a5575407b767a5c747176016c0676386e403a2b42356a727a04662b4446375f36265f3f124b724c6e346544706277641025063420016629225b43432428036f29341a2338627c47650b264c477c653a67043e6766152a485c7f33617264780656537e5468143f305f4537722352303c3d4379043d69797e6f3922527b24536e310d653d4c33696c635474637d0326516f745e610d773340306621105a7361654e3e392970687c2e335f3015677d4b3a724a4659767c2f5b7c16055a126820306c14315d6b59224a27311f747f336f4d5974321a22507b22705a226c6d446a37375761423a2b5c29247163046d7e47032244377508300751727126326f117f7a38670c2b23203d4f27046a5c5e1532601126292f577776606f0c6d0126474b2a73737a41316362146e581d7c1228717664091c
```

有plain，有key，不禁让人想起维吉尼亚密码，想起之前做过的一道[[NCTF2019]Sore](https://blog.csdn.net/weixin_52446095/article/details/119003999?spm=1001.2014.3001.5501)
于是就参照维吉尼亚的爆破方法来解题，参考[示例代码](https://blog.csdn.net/Ni9htMar3/article/details/53371817)
首先是Kasiski 实验：

```python
def GCD(step):
    gcd_list = []
    buf = []
    if not len(step):
        return "None has ben found"
    else:  # find GCD
        step_min = max(step) // 2
        for con in range(2, step_min + 1):
            flag = True
            for each_step in step:
                if each_step % con:
                    flag = False
                    break
            if flag:
                gcd_list.append(con)
    if len(gcd_list):
        return gcd_list
    else:  # find GCD list
        for con in range(2, step_min + 1):
            gcd_list.append([con, len(step)])
            for each_step in step:
                if each_step % con:
                    gcd_list[con - 2][1] -= 1
        for each in gcd_list:
            if each[1]:
                buf.append(each)
        for i in range(1, len(buf)):
            j = i
            while j > 0:
                if buf[j][1] < buf[j - 1][1]:
                    tem = buf[j - 1]
                    buf[j - 1] = buf[j]
                    buf[j] = tem
                j -= 1
        return buf

def find(string1, string2):
    k, t = 0, 0
    for t in range(len(string1)):
        if string1[t] == string2[0] and t+len(string2) <= len(string1):
            for k in range(len(string2)):
                if string1[t+k] != string2[k]:
                    k -= 1
                    break
            if k == len(string2)-1:
                break
    if t == len(string1)-1 or string1 == '':
        return -1
    else:
        return t

def kasiski(cipher):
    sec_msg = cipher
    step = []
    flag = False
    lenth = len(sec_msg)
    for i in range(lenth - 5):
        flag_tem = 0
        i_tem = i
        while True:
            print(sec_msg[i_tem + 3:], sec_msg[i_tem:i_tem + 3])
            flag_tem = find(sec_msg[i_tem + 3:], sec_msg[i_tem:i_tem + 3])
            # flag_tem = sec_msg[i_tem + 3:].find(sec_msg[i_tem:i_tem + 3])
            print(flag_tem)
            if flag_tem == -1:
                break
            flag_tem += 3
            step.append(flag_tem)
            i_tem += flag_tem
    # print('step:', step)
    print(GCD(step))
    return GCD(step)

if __name__ == '__main__':
    cipher = 'nsfAIHFrMuLynuCApeEstxJOzniQuyBVfAChDEznppfAiEIDcyNFBsCjsLvGlDtqztuaHvHbCmuyGNsIMhGlDtbotCoDzDjhyBzHGfHGfoHsuhlssIMvwlixBHHGfDRjoCKrapNIwqNyuxIBACQhtMwCmMCfEBpsrzEuiLGBoMipTkxrznoHfAkqwzvxuzCzDbLyApCGvjpqxkuwpgsLrqsVfCRwzlFmtlyrhuyEiivruFRpCRjkEDrqEqthyGwgsLnQvHmtzwDEznopBpsDOxvgBGIKzurFQxwQxkptutxzmfeLFQoRpJRvrpHxilwqeqMeiiIGBsQpCCvrptAlHsDnuRltmHuCGFpsBcwnsEblsswEPwerNpIADpJRCvwQxrntJltNpfAuFBwRstytoyvcepwtwqNlmmNGFsJjsQvkyvrkrstxJOzniQvNvzdDUdyJzjqzsErqxEjguyFMNwtPjsDwjoDfCdxzvftNGyzKjCEjsDxjqsjGMqFpimGpIADpJRFkovHJlpthyHnpqyBOHhmDMmoosClwiehEzmffOGMvDxDSnnyLuXFlwYEPvosQxCrRxwCpDswHopxDruvEzsOgBsXxDLvvlMpezwpnOOsjrANzHDsLCnoqLCepgtaHNHfpysNHGfOMqkyvlozxHetJGfvNuCGKjIRnoDLAbpyxnJCpqeLxuBCuwCpGpOnkEywrEPrisHrItSiDQgvtLCipyJnDzwtxBnNoKxpWuCxwuiqwDmIJxffIqSGSbzGpqlDnXvNIwqNzoxBrQoXuDRjonsAozzHeBjweTBBypDtIGnvHGDiosItqGvusGrIFzoNRjsyykrExweMvDtsLGItVbAIkxrFnuEyDmuIzxMNBIyziDJfyqLqbmjAtqOEiivnwyNgwCtmzsCgFxIfEMEiiBrFzNgxRdEEKqbHtJltIEmiNzygGfHyknVwnmJtJrxvyewNBSCTsHCnptxHlFiDnJHtohmuyKztHRkvwKxopfImuWFurIGuGRpGCcCDzntlxqevJCfEHLQoXxtIgzEynqEnCgsGztiLnHrBmDQgBEGCephprHJFtiFnHrXpJAqEwvBqlwItECpbvNuuHMvIRAwFKrZtyplMvJttFnSGhuLyuzwsHfyldhcvCjicGJzzztBvrlLBXxjHoDBlcsOGzwEuNWgkCKjdzBweDdHbwuyCHSmtIknezjqDtCeDDnfxBvHuzcDSvmlJAlFxtlIOsfCuyQoXtEJcIEznplrtsEIrtMNuIIFiIRjonsAozzHeBRltgFBMsCjCRjoHAwqpwIiCzzmhjuIsAfHyknTLFXDywevDCtxNvGsRitNtknLrZlqAyIvteeHLNvHovqjoAJxYlgAyvJChsNFBsVbHQwzAGBboyDbuNzsiuGGslbNzglpujrDjxtIvCpyHqWvQjHRokDaBXtihhuyterNFuMzoNRjsyyFepsXsqDouluGmvDqGMdkmDHoprtmrzCfhMuyKztHSrzzKnaEtqeIJCfeNzyRNzDSykyLClrtuoHvCjhyBHwSJHyknTCwbHxweFMzcevySrHelFgxDzntlxptyIJmmNGFsJjsypnLDufpfCdTWlohcHMsCuDEqDzLqbAfGkMDEilyEMvDxpQokosklFyIhuxlsvIHMsKZDSeyFDmkElttxzCpjzGBsFpsBcwEzrkrNBtEJmjkMuyGzjsgvrzMpeExweMvDoxABCBFuDypCHwAjpgJtICpemxaIMNvGCpyEYxlyNAlMvtujIESofpDLKClAmTpBtruMthlNGBsQfIFgxeznopBtruvqfAEvxGQjsGpqzFrqxtHtBTGfvSyCHSmtIknDswalktwFvCfrNFQsQfLykDtFpXCtJntJFuwCqyGHuIGpqzFCepgtnsCpteHquzKXwyvSoAmtlxXwuIEvtNBNvDxxLfyHOqbCjIhuTDfpFGBsSjrIgDDswamtJgxOzmhjuIsAfpRkmvwCQsjCIwvGfmNGIvDshFgGlKBqlssiDBCjkBGHsWuIMooSwAbTxpitrljxuFyqNosRcupLqbCjHtEAJpyLqIIFiIMqSDLjoEjsgyQtokBrLHGfGCuDzxCepiDuwCDiixyyBSntwqEvwnmtyZeuKtujIEGsRitQcsolqbyxweIvtevCtBHzgICtGlJmMwjpsuosbxMqyDQfHQkxrOqbyxDmuwzeCMnSGOmtyuoEGHlFNBeqItgmNFjvNfqCqBDGvbmtsyjCluhyCLsRttBvrpzniwtJtEAxfFOGcDTuIFgnzMpemfrkyIxztIpEsSBGCpDJGDdzsCaHDofxIBMvDbHIgnxwbepBpsBJzlmHtuHLfHMtDzxorysNYEPnpyFqNsKmHFgGlKwqEtDsEMpbxGruBXnDPgWlQkbTBxlBOsfryKNHHntgnvHsCZsDpIIvteKIGSCTsIGeupLhbDLDaxzlexBrHWKmqCqxEzrpmjCcxMthlNBPsQitPgSwDFXEhwyqdHfrNBPsQbCBukEvxtytCtxDDciHpBoMeHFgGpFCXyivoJJyulypuFQpJQgvdzntlqzetvwmeLBOBCjIgoolFBepBplAzoprwruzKuwCykJsAlFssiJosfrMuyGzusMyxzFCetxqiwwCpAHoyoSvEJqyvAwdzqshEMDfXBrHHGfrytBzMBbwxIaHOpeeHqcKzurFgnswAdzfGoKIobrxnLCTosrjoCwFbCjDnBTlcsOGzwUfDPusIGCepwzitNzoxBrLwCfpLfDswBlylIhuxlsvIHMsKxpQrvlQrkrBpsiHzliarNGHonMwBPQnpTyLaIKwbCCAAwSwtPAtlRIvlssfKIyzEFyNvDlxBuupHCqCDxnwOzhvuozCQuwCiywvAfylpntNzxeMBFroiDCdolFmFHfHsEMEpjusLoHeHFgnqsuizkutxzrphxnGvNsHCdEEamfosIsqTloCNuCBFpGBqkyQCetsvTxzEimHtQwSizGfCtKrcEmtyMvyuxItLoAuwCiywvAfylNoKClwiNBFsSuwConzACXyiCoJNlzeHLNvHovghDswHclqAovAEiiSsuzKpuDdEEACpmfsivTzvwuLuBXuwGpqEGCeprlhuIEiiLvxsVbHMxoCKqbrtIovAsfvBBLGDbCBekxwxspwIoCzjpyLvxsNorCvyzLqfDyxmuNsfwuvxbNJAJlEDLFXEhwyqdEimHxczKkJQvGlLleTxpitdrbzyuyFRpBCoyCwxcsjGdEPriLyEyUDuHMooxGAbEnrkuODTlyGICJuwCfyFyqlqkBeYHypxGnxoSzDScxJExopxweIvteMEAIKgvGPAEALqbEmxnwNrprHnMHzsIyiktFcepsplBJqbwOqxsMtwCikGwvblpxsIosfrMuyvDmsFgBsswazzIaDyDbmxVNGQbxLkxraCpDyprJDyhxIEuwMJzLqGeznkHmptICpemxvNrznCLgkCCriwjsmuNsfvynwvDexLoInGjqAtrkuOlohNBIyNvIKABpvqryyxnwClueHqJISjIMpwJznXoIDnJTzvAuANwSJHyknjGDZlsLeqMtueQuCzDPzyARFJAvFuIhEPrirIJsCTstEqxysvfDxNoKMCjhylIIVpCRioEQxrCtLnxJCtiIEuBXuwGpqdznhpuIhqIrjrAnLCTosRjyFyqAtiNoKHpbrCGQvzuNMwClAmVzzGeqGwzeLrHHFpxLikHsHXyDLhuMpBvyLIIQfpJnIrGrkrmDmuvquiLJuFCtHFgkDCnaxjneqCTteCqcADbCRkDEGxFHfHnJGJjrAGIvDsXPgkwDHativoxJxfezGyFVbGBuRFJAvFuCoMdDbmxgBsSixLiCDLjoEnCgiCpseHnHrApJEjDswAqthzeJvyekIGvoBlDLvrpyxaofBcqMCpyMrFxTtIGpDtEnQsjCsxzHbpErxoKmIFgGlQjozzCdyOEjpFFBsFpIFgBzOwezwHervnlXBrHGGfvMvyyACPsjLaLzousGruBCJLyxootjZvGDyyOmfkuANCQbxLnsvwjYlxIaHyTofOpEsStXQyolJClRtsABGEiiJnLsMuHypnxGCepwHaDypwiLLvCCzLCpDzNnolsssJJzevCtBHTosCtDswAlzkDfJCpdeLEIIRfAQqDswHtzzAdDOrfxMBuyDeIMvrpKtfytGaDTEimHtvISJHRwmvsAlFssoDOsffyAwvEpGOwsEwjtsnAeYBzutLrNHXtDymsyyFbEjHpuxtbpFLGMMfrIcxoEHmlsIscTsvrNvHuGbIPgkwDHdlAtmuLFjxynFCSpuNtyEwlqttCiDvHbCvHNWFpIQqkvwmXyDLaOdojhHGwoQfIFqErzRcpqIsEylnrBnJDXbAJqpDMmapsIhuRlzsFqjvNfqCmoALpltsvaHJFohuAxoQpJLfSHsBalrCnuvCceQyCBFJuCnDDGmXxswaFKJjjSBOKzoIRquyGFqsjIrKOsJhIANyMpLUjITLFXDoJsJOsbxMuyzNpzCfCzvjjysxcuOsfAuLMvDltNvqzAwdlwDuDylohuEIIMexLjoCturphDaJvyeeFyaCCJLGurJGDZzzAdLzmfiHGBsQfiFcDDsuiTrvoyIrusNrFzzcDSvSnGDiouGorvmmCNrFzXpJUjkEamfofutuMTxiHGBCLfpLfrzORdzyHisFlohuyFoMeLFcDDuqlzqXmIPAqsMrxHNhDRqxpPCclqAavOpsMArNCTuDDjoCwkrENsoDOqfiFyCyDjIgtolDuvotCtjCluwNHztCptQpDtFCbCjHtCzEpsGHwvQjvFvxzOJizyDfFzzqpyrMDDdxynvJLqfDtCeFNJdlInHoKzHRiEJLqbJmpvuCpsiEryDRbHIkxrEnfqNBgEDyheJCFMLzHCnpHznkTlDbqxvusMpBCNmCCzDdwyqprqeHdEtwOpBoRuJNknBMnpEnDnyIxzsJvHwNoXKgkyzxtotNoKFypAQuuHXpJPgqzAwdEtsoJDwmCIHxCHuiFgkyKFbCnHyEPoprNVNvHozgcwmMCezBsoYFypAcFQszsxRukDLDmtiFuuNEjsHQVwRoIyullvjpEmtruNEpjNuyAAvIFgupwyplxziDBxfeFBNCErJCuDtGwpEtDHuyCpzyBPsQmpQvclLDoofNwyOsulCFYBFmxQjlltnqsfIsyIEimMAyKOjrRwBpznpHwxtyIrTlyJuGOstRvIlxobnytdrPEwiLLACNeAMqutFpxyDLaOJyfxCzyKGfCQjoHwwqEtIhuGlemyFLCNnLyADswqbwqsoMItoxBrIHGfGUkxrVKXDptdCzHieNVNvNvvFvkmGDqlqAtxDDtxOszWIvHRhsyABepiIeBGtokSBOoApJRKntvwqvsDwMCluxBrBsKmIMukJaovzzLaDOEpoHBQHGfIPwDsamlyyznERHieNVNvHozydyFLrqTrHoHMJJxIyxGNnpLAzpGyipfqoKOtuEvBOHzmAgmxzOrpTxDrJJqnmMFyJDsNzqnJaClwipbEPEFzyAIzCTIPcnwsCbCfCdQxvmiSsIFHoHRcxnwRqsnCkYzGfrGvMGSipRiyovjjXfJryxpJxMsOBMzSMpDpNnoEjAlqIJcsxLuBXuwGpqTxHlFiDyEPDueLGGwRtxLioGwAvmtsy'
    kasiski(cipher)
```

稍微修改了一下原代码，放弃了原来只对字符串起作用的.find()方法，重新定义了一个find函数，使得对列表也管用
这里选用的cipher是[NCTF2019]Sore中的cipher，试验与结果相吻合
![在这里插入图片描述](luozj1020 vacation_week3.assets/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70.png)
得到本题的key的长度代码如下：

```python
from itertools import *
from kasiski import *

salt = "WeAreDe1taTeam"
si = cycle(salt)
c = '49380d773440222d1b421b3060380c3f403c3844791b202651306721135b6229294a3c3222357e766b2f15561b35305e3c3b670e49382c295c6c170553577d3a2b791470406318315d753f03637f2b614a4f2e1c4f21027e227a4122757b446037786a7b0e37635024246d60136f7802543e4d36265c3e035a725c6322700d626b345d1d6464283a016f35714d434124281b607d315f66212d671428026a4f4f79657e34153f3467097e4e135f187a21767f02125b375563517a3742597b6c394e78742c4a725069606576777c314429264f6e330d7530453f22537f5e3034560d22146831456b1b72725f30676d0d5c71617d48753e26667e2f7a334c731c22630a242c7140457a42324629064441036c7e646208630e745531436b7c51743a36674c4f352a5575407b767a5c747176016c0676386e403a2b42356a727a04662b4446375f36265f3f124b724c6e346544706277641025063420016629225b43432428036f29341a2338627c47650b264c477c653a67043e6766152a485c7f33617264780656537e5468143f305f4537722352303c3d4379043d69797e6f3922527b24536e310d653d4c33696c635474637d0326516f745e610d773340306621105a7361654e3e392970687c2e335f3015677d4b3a724a4659767c2f5b7c16055a126820306c14315d6b59224a27311f747f336f4d5974321a22507b22705a226c6d446a37375761423a2b5c29247163046d7e47032244377508300751727126326f117f7a38670c2b23203d4f27046a5c5e1532601126292f577776606f0c6d0126474b2a73737a41316362146e581d7c1228717664091c'
list_c = []
for i in range(0, len(c), 2):
    list_c.append(int(c[i:i + 2], 16) ^ ord(next(si)))
print(list_c)
len_key = max(kasiski(list_c))
print(len_key)
```

结果为：
![在这里插入图片描述](luozj1020 vacation_week3.assets/635fa959e251453195d3e37a34dac79d.png)
后来找wp时发现也是正确的
但是下一步重合指数攻击和字母频率分析出现了瓶颈，原来的维吉尼亚密码爆破采用的把加密视作凯撒密码，只要进行位移即可，但本题是异或加密，几乎是重新把脚本写一遍了
直接找到了[官方wp](https://github.com/De1ta-team/De1CTF2019/blob/master/writeup/crypto/Xorz/README_zh.md)，稍微修改了一下：

```python
from itertools import cycle

c = "49380d773440222d1b421b3060380c3f403c3844791b202651306721135b6229294a3c3222357e766b2f15561b35305e3c3b670e49382c295c6c170553577d3a2b791470406318315d753f03637f2b614a4f2e1c4f21027e227a4122757b446037786a7b0e37635024246d60136f7802543e4d36265c3e035a725c6322700d626b345d1d6464283a016f35714d434124281b607d315f66212d671428026a4f4f79657e34153f3467097e4e135f187a21767f02125b375563517a3742597b6c394e78742c4a725069606576777c314429264f6e330d7530453f22537f5e3034560d22146831456b1b72725f30676d0d5c71617d48753e26667e2f7a334c731c22630a242c7140457a42324629064441036c7e646208630e745531436b7c51743a36674c4f352a5575407b767a5c747176016c0676386e403a2b42356a727a04662b4446375f36265f3f124b724c6e346544706277641025063420016629225b43432428036f29341a2338627c47650b264c477c653a67043e6766152a485c7f33617264780656537e5468143f305f4537722352303c3d4379043d69797e6f3922527b24536e310d653d4c33696c635474637d0326516f745e610d773340306621105a7361654e3e392970687c2e335f3015677d4b3a724a4659767c2f5b7c16055a126820306c14315d6b59224a27311f747f336f4d5974321a22507b22705a226c6d446a37375761423a2b5c29247163046d7e47032244377508300751727126326f117f7a38670c2b23203d4f27046a5c5e1532601126292f577776606f0c6d0126474b2a73737a41316362146e581d7c1228717664091c"


def getCipher(c):
    codeintlist = []
    codeintlist.extend(
        (map(lambda i: int(c[i:i + 2], 16), range(0, len(c), 2))))
    salt = "WeAreDe1taTeam"
    si = cycle(salt)
    newcodeintlist = [ci ^ ord(next(si)) for ci in codeintlist]
    return newcodeintlist


def getKeyPool(cipher, stepSet, plainSet, keySet):
    ''' 传入的密文串、明文字符集、密钥字符集、密钥长度范围均作为数字列表处理.形如[0x11,0x22,0x33]
        返回一个字典，以可能的密钥长度为键，以对应的每一字节的密钥字符集构成的列表为值，密钥字符集为数字列表。
            形如{
                    1:[[0x11]],
                    3:[
                        [0x11,0x33,0x46],
                        [0x22,0x58],
                        [0x33]
                       ]
                }
    '''
    keyPool = dict()
    for step in stepSet:
        maybe = [None] * step
        for pos in range(step):
            maybe[pos] = []
            for k in keySet:
                flag = 1
                for c in cipher[pos::step]:
                    if c ^ k not in plainSet:
                        flag = 0
                if flag:
                    maybe[pos].append(k)
        for posPool in maybe:
            if len(posPool) == 0:
                maybe = []
                break
        if len(maybe) != 0:
            keyPool[step] = maybe
    return keyPool


def calCorrelation(cpool):
    '''传入字典，形如{'e':2,'p':3}
        返回可能性，0~1,值越大可能性越大
        (correlation between the decrypted column letter frequencies and
        the relative letter frequencies for normal English text)
    '''
    frequencies = {"e": 0.12702, "t": 0.09056, "a": 0.08167, "o": 0.07507, "i": 0.06966,
                   "n": 0.06749, "s": 0.06327, "h": 0.06094, "r": 0.05987, "d": 0.04253,
                   "l": 0.04025, "c": 0.02782, "u": 0.02758, "m": 0.02406, "w": 0.02360,
                   "f": 0.02228, "g": 0.02015, "y": 0.01974, "p": 0.01929, "b": 0.01492,
                   "v": 0.00978, "k": 0.00772, "j": 0.00153, "x": 0.00150, "q": 0.00095,
                   "z": 0.00074}
    relative = 0.0
    total = 0
    fpool = 'etaoinshrdlcumwfgypbvkjxqz'
    total = sum(cpool.values())  # 总和应包括字母和其他可见字符
    for i in cpool.keys():
        if i in fpool:
            relative += frequencies[i] * cpool[i] / total
    return relative


def analyseFrequency(cfreq):
    key = []
    for posFreq in cfreq:
        mostRelative = 0
        for keyChr in posFreq.keys():
            r = calCorrelation(posFreq[keyChr])
            if r > mostRelative:
                mostRelative = r
                keychar = keyChr
        key.append(keychar)
    return key


def getFrequency(cipher, keyPoolList):
    ''' 传入的密文作为数字列表处理
        传入密钥的字符集应为列表，依次包含各字节字符集。
            形如[[0x11,0x12],[0x22]]
        返回字频列表，依次为各字节字符集中每一字符作为密钥组成部分时对应的明文字频
            形如[{
                    0x11:{'a':2,'b':3},
                    0x12:{'e':6}
                 },
                 {
                    0x22:{'g':1}
                 }]
    '''
    freqList = []
    keyLen = len(keyPoolList)
    for i in range(keyLen):
        posFreq = dict()
        for k in keyPoolList[i]:
            posFreq[k] = dict()
            for c in cipher[i::keyLen]:
                p = chr(k ^ c)
                posFreq[k][p] = posFreq[k][p] + 1 if p in posFreq[k] else 1
        freqList.append(posFreq)
    return freqList


def vigenereDecrypt(cipher, key):
    plain = ''
    cur = 0
    ll = len(key)
    for c in cipher:
        plain += chr(c ^ key[cur])
        cur = (cur + 1) % ll
    return plain


def main():
    ps = []
    ks = []
    ss = []
    ps.extend(range(32, 127))
    ks.extend(range(0xff + 1))
    ss.extend(range(38))
    cipher = getCipher(c)

    keyPool = getKeyPool(cipher=cipher, stepSet=ss, plainSet=ps, keySet=ks)
    for i in keyPool:
        freq = getFrequency(cipher, keyPool[i])
        key = analyseFrequency(freq)
        plain = vigenereDecrypt(cipher, key)
        print(plain, "\n")
        print(''.join(map(chr, key)))


if __name__ == '__main__':
    main()
```

思想与维吉尼亚密码爆破相同，利用plain是一段有意义的字符，统计字母频率来得到key和plain
结果如下：
![在这里插入图片描述](luozj1020 vacation_week3.assets/62ccf4b4262a4f60bf8485bd9b3ba660.png)
容易发现，得到的key的第二位是不对的
经过修改，结果为：W3lc0m3tOjo1nu55un1ojOt3q0cl3W

出了官方给出的解法，还找到了[另一种解法](https://blog.csdn.net/ao52426055/article/details/110420027)，使得密文不同位置对应的同一key的字母之间的汉明距离最小来得到key的长度，进而还原key和plain
至于什么是[汉明距离](https://baike.baidu.com/item/%E6%B1%89%E6%98%8E%E8%B7%9D%E7%A6%BB/475174#:~:text=%E6%B1%89%E6%98%8E%E8%B7%9D%E7%A6%BB%E6%98%AF%E4%BD%BF%E7%94%A8,%E6%95%B0%E5%B0%B1%E6%98%AF%E6%B1%89%E6%98%8E%E8%B7%9D%E7%A6%BB%E3%80%82)，摘自百度百科：
![在这里插入图片描述](luozj1020 vacation_week3.assets/392f37229f8f4c3d8b9306bf0d29ba95.png)
代码如下：

```python
import string
from binascii import unhexlify, hexlify
from itertools import *


def bxor(a, b):  # xor two byte strings of different lengths
    if len(a) > len(b):
        return bytes([x ^ y for x, y in zip(a[:len(b)], b)])
    else:
        return bytes([x ^ y for x, y in zip(a, b[:len(a)])])


def hamming_distance(b1, b2):
    differing_bits = 0
    for byte in bxor(b1, b2):
        differing_bits += bin(byte).count("1")
    return differing_bits


def break_single_key_xor(text):
    key = 0
    possible_space = 0
    max_possible = 0
    letters = string.ascii_letters.encode('ascii')
    for a in range(0, len(text)):
        maxpossible = 0
        for b in range(0, len(text)):
            if (a == b):
                continue
            c = text[a] ^ text[b]
            if c not in letters and c != 0:
                continue
            maxpossible += 1
        if maxpossible > max_possible:
            max_possible = maxpossible
            possible_space = a
    key = text[possible_space] ^ 0x20
    return chr(key)


salt = "WeAreDe1taTeam"
si = cycle(salt)
b = unhexlify(
    b'49380d773440222d1b421b3060380c3f403c3844791b202651306721135b6229294a3c3222357e766b2f15561b35305e3c3b670e49382c295c6c170553577d3a2b791470406318315d753f03637f2b614a4f2e1c4f21027e227a4122757b446037786a7b0e37635024246d60136f7802543e4d36265c3e035a725c6322700d626b345d1d6464283a016f35714d434124281b607d315f66212d671428026a4f4f79657e34153f3467097e4e135f187a21767f02125b375563517a3742597b6c394e78742c4a725069606576777c314429264f6e330d7530453f22537f5e3034560d22146831456b1b72725f30676d0d5c71617d48753e26667e2f7a334c731c22630a242c7140457a42324629064441036c7e646208630e745531436b7c51743a36674c4f352a5575407b767a5c747176016c0676386e403a2b42356a727a04662b4446375f36265f3f124b724c6e346544706277641025063420016629225b43432428036f29341a2338627c47650b264c477c653a67043e6766152a485c7f33617264780656537e5468143f305f4537722352303c3d4379043d69797e6f3922527b24536e310d653d4c33696c635474637d0326516f745e610d773340306621105a7361654e3e392970687c2e335f3015677d4b3a724a4659767c2f5b7c16055a126820306c14315d6b59224a27311f747f336f4d5974321a22507b22705a226c6d446a37375761423a2b5c29247163046d7e47032244377508300751727126326f117f7a38670c2b23203d4f27046a5c5e1532601126292f577776606f0c6d0126474b2a73737a41316362146e581d7c1228717664091c')
plain = ''.join([hex(ord(c) ^ ord(next(si)))[2:].zfill(2) for c in b.decode()])
b = unhexlify(plain)
print(plain)

normalized_distances = []

for KEYSIZE in range(2, 40):
    n = len(b) // KEYSIZE
    list_b = []
    for i in range(n - 1):
        list_b.append(b[i * KEYSIZE: (i + 1) * KEYSIZE])

    normalized_distance = 0
    for i in range(len(list_b) - 1):
        normalized_distance += hamming_distance(list_b[i], list_b[i + 1])
    normalized_distance = float(normalized_distance) / (KEYSIZE * (len(list_b) - 1))

    normalized_distances.append(
        (KEYSIZE, normalized_distance)
    )
normalized_distances = sorted(normalized_distances, key=lambda x: x[1])
print(normalized_distances)

for KEYSIZE, _ in normalized_distances[:5]:
    block_bytes = [[] for _ in range(KEYSIZE)]
    for i, byte in enumerate(b):
        block_bytes[i % KEYSIZE].append(byte)
    keys = ''
    try:
        for bbytes in block_bytes:
            keys += break_single_key_xor(bbytes)
        key = bytearray(keys * len(b), "utf-8")
        plaintext = bxor(b, key)
        print("keysize:", KEYSIZE)
        print("key is:", keys)
        s = bytes.decode(plaintext)
        print(s)
    except Exception:
        continue
```

对代码进行了一些修改，得到结果：
![在这里插入图片描述](luozj1020 vacation_week3.assets/232b0175520c4f8a8ba0dbbdfcbcccce.png)
经过测试，在某些情况下，该程序对key长度的计算会有偏差，会出现key内容缺失，或者重复的情况，但是对plain的还原比较准确
与第一种方法相比各有优劣
以```key = 'a24jq354qgikamzasmglzhjapwmiq3OMM93FI'```为例
方法一的结果为：
![在这里插入图片描述](luozj1020 vacation_week3.assets/e95229e381ea4a039a9acdf0bcf015ff.png)
方法二的结果为：
![在这里插入图片描述](luozj1020 vacation_week3.assets/6d658064cd5a445f8f5ebad6f4902fe7.png)
具体解题时，可以对照着看

还有一个问题就是方法二代码的第37行有一个```^ 0x20```不知道是什么意思，但是去掉了又不行，希望明白的师傅能指点指点

# 2021-7-29

## [AFCTF2018]One Secret, Two encryption

题面：
一份秘密发送给两个人不太好吧，那我各自加密一次好啦~~~
素数生成好慢呀
偷个懒也……不会有问题的吧？

给了两个公钥文件
先转成能看懂的：

```python
from Crypto.PublicKey import RSA

with open("public1.pub", "r") as f:
    key = RSA.import_key(f.read())
    n1 = key.n
    e1 = key.e
    print('n1:', key.n)
    print('e1:', key.e)

with open("public2.pub", "r") as f:
    key = RSA.import_key(f.read())
    n2 = key.n
    e2 = key.e
    print('n2:', key.n)
    print('e2:', key.e)
```

得到n和e：
![在这里插入图片描述](luozj1020 vacation_week3.assets/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70.png)
先尝试爆破，发现都可以暴力分解（啊这）
得到p,q：

```python
p1 = 27809722472252756488236572384949349891208643090117349509994417047989746484576130392206781875743390815588696964830219136848285391966773129269973231061599768809907518881304479207799187410626121509031210549317480187679455501340422680238395009932081263455435640341892702399022829951248686529928945588545968218943
q1 = 174410123761631337520799179808598127914184971978811796722414215239874114048347830609255805203105210941441708658356189056418366104015120153227123562166980882513945308613658062284844636341082646995916907680076101741743945938845994542592182491688095893467336553001430454260431413695816790105384153941685561590503
p2 = 13574537518864130340355432541118272197612469786472599699388744722964224446468845332277885224151359348751827390453295742493408690917441802418376492710577443748707324892538263470296850322457820732500754398379697996486797672220145645775197396918813888878389297506519458452871204328250224991572191181011886880259
q2 = 174410123761631337520799179808598127914184971978811796722414215239874114048347830609255805203105210941441708658356189056418366104015120153227123562166980882513945308613658062284844636341082646995916907680076101741743945938845994542592182491688095893467336553001430454260431413695816790105384153941685561590503
```

发现q1=q2
原来题面说的“偷个懒”是这个意思
然后就是常规的RSA解密，代码如下：

```python
from Crypto.PublicKey import RSA
from Crypto.Util.number import *
import rsa

with open("public1.pub", "r") as f:
    key = RSA.import_key(f.read())
    n1 = key.n
    e1 = key.e
    print('n1:', key.n)
    print('e1:', key.e)

with open("public2.pub", "r") as f:
    key = RSA.import_key(f.read())
    n2 = key.n
    e2 = key.e
    print('n2:', key.n)
    print('e2:', key.e)

p1 = 27809722472252756488236572384949349891208643090117349509994417047989746484576130392206781875743390815588696964830219136848285391966773129269973231061599768809907518881304479207799187410626121509031210549317480187679455501340422680238395009932081263455435640341892702399022829951248686529928945588545968218943
q1 = 174410123761631337520799179808598127914184971978811796722414215239874114048347830609255805203105210941441708658356189056418366104015120153227123562166980882513945308613658062284844636341082646995916907680076101741743945938845994542592182491688095893467336553001430454260431413695816790105384153941685561590503
p2 = 13574537518864130340355432541118272197612469786472599699388744722964224446468845332277885224151359348751827390453295742493408690917441802418376492710577443748707324892538263470296850322457820732500754398379697996486797672220145645775197396918813888878389297506519458452871204328250224991572191181011886880259
q2 = 174410123761631337520799179808598127914184971978811796722414215239874114048347830609255805203105210941441708658356189056418366104015120153227123562166980882513945308613658062284844636341082646995916907680076101741743945938845994542592182491688095893467336553001430454260431413695816790105384153941685561590503
print(q1 == q2)

d1 = inverse(e1, (p1 - 1) * (q1 - 1))
Rsa = rsa.PrivateKey(n1, e1, d1, p1, q1)

with open('flag_encry1', 'rb') as f:
    c1 = f.read()
    print(rsa.decrypt(c1, Rsa))

d2 = inverse(e2, (p2 - 1) * (q2 - 1))
Rsa = rsa.PrivateKey(n2, e2, d2, p2, q2)
with open('flag_encry2', 'rb') as f:
    c2 = f.read()
    print(rsa.decrypt(c2, Rsa))
```


## [AFCTF2018]MyOwnCBC

加密代码如下：

```python
from Crypto.Cipher import AES
from Crypto.Random import random
from Crypto.Util.number import long_to_bytes

def MyOwnCBC(key, plain):
	if len(key)!=32:
		return "error!"
	cipher_txt = b""
	cipher_arr = []
	cipher = AES.new(key, AES.MODE_ECB, "")
	plain = [plain[i:i+32] for i in range(0, len(plain), 32)]
	print plain
	cipher_arr.append(cipher.encrypt(plain[0]))
	cipher_txt += cipher_arr[0]
	for i in range(1, len(plain)):
		cipher = AES.new(cipher_arr[i-1], AES.MODE_ECB, "")
		cipher_arr.append(cipher.encrypt(plain[i]))
		cipher_txt += cipher_arr[i]
	return cipher_txt
	
key = random.getrandbits(256)
key = long_to_bytes(key)

s = ""
with open("flag.txt","r") as f:
	s = f.read()
	f.close()

with open("flag_cipher","wb") as f:
	f.write(MyOwnCBC(key, s))
	f.close()
```

题面：
CBC什么东西呀？不就是把上一轮加密的影响扩散到下一轮嘛
它写的CBC一点都不正宗
我这样写肯定也行的！

大概吧？

观察代码，发现是先随机生成了一个key然后把plain按每段32位分割，第一段用生成的key进行AES加密，后面每段plain以前面一段加密后的plain（也就是cipher）作为key进行加密，最后拼接在一起，题面里“把上一轮加密的影响扩散到下一轮”就是这个意思
由于第一段key是随机生成的，也没有线索来还原，就以第一段cipher作为key来还原后面的内容，代码如下：

```python
from Crypto.Cipher import AES

with open("flag_cipher", "rb") as f:
    cipher = f.read()

key = cipher[:32]
plain_txt = b""
cipher = [cipher[i:i + 32] for i in range(0, len(cipher), 32)]
for i in range(1, len(cipher)):
    aes = AES.new(key, AES.MODE_ECB)
    plain_txt += aes.decrypt(cipher[i])
    key = cipher[i]
print(plain_txt)
```

结果为：
![在这里插入图片描述](luozj1020 vacation_week3.assets/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70.png)

# 2021-7-31

## [AFCTF2018]Tiny LFSR

加密代码如下：

```python
import sys
from binascii import unhexlify

if(len(sys.argv)<4):
	print("Usage: python Encrypt.py keyfile plaintext ciphername")
	exit(1)

def lfsr(R, mask):
	output = (R << 1) & 0xffffffffffffffff
	i=(R&mask)&0xffffffffffffffff
	lastbit=0
	while i!=0:
		lastbit^=(i&1)
		i=i>>1
	output^=lastbit
	return (output,lastbit)

R = 0
key = ""
with open(sys.argv[1],"r") as f:
	key = f.read()
	R = int(key,16)
	f.close
	
mask = 0b1101100000000000000000000000000000000000000000000000000000000000

a = ''.join([chr(int(b, 16)) for b in [key[i:i+2] for i in range(0, len(key), 2)]])

f=open(sys.argv[2],"r")
ff = open(sys.argv[3],"wb")
s = f.read()
f.close()
lent = len(s)

for i in range(0, len(a)):
	ff.write((ord(s[i])^ord(a[i])).to_bytes(1, byteorder='big'))

for i in range(len(a), lent):
    tmp=0
    for j in range(8):
        (R,out)=lfsr(R,mask)
        tmp=(tmp << 1)^out
    ff.write((tmp^ord(s[i])).to_bytes(1, byteorder='big'))
ff.close()
```

搜了一下LFSR是什么：
![在这里插入图片描述](luozj1020 vacation_week3.assets/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70.png)
好像是一种伪随机数生成器（你说这个谁懂啊！）
但是在CTFwiki伪随机数生成器那块没有找到，就放弃了
看到这个```lfsr()```函数就头皮发麻，还有一堆```argv[]```不知道是干什么，看了几眼，找[wp](https://www.ruanx.net/tiny-lfsr-writeup/)去了（看了wp之后发现也没那么难嘛[doge]）
附件里面还有一个.bash_history.txt文件：

```bash
python Encrypt.py key.txt Plain.txt cipher.txt
python Encrypt.py key.txt flag.txt flag_encode.txt
rm flag.txt
rm key.txt
```

大概就是用加密程序和key.txt先加密了Encrypt.py文件，再加密了flag.txt，然后删除了flag.txt和key.txt
还给了Plain.txt，cipher.txt和flag_encode.txt，我们就可能要先用Plain.txt和cipher.txt解出key.txt，然后用flag_encode.txt和key.txt解出flag.txt

观察加密代码后半部分：

```python
for i in range(0, len(a)):
	ff.write((ord(s[i])^ord(a[i])).to_bytes(1, byteorder='big'))

for i in range(len(a), lent):
    tmp=0
    for j in range(8):
        (R,out)=lfsr(R,mask)
        tmp=(tmp << 1)^out
    ff.write((tmp^ord(s[i])).to_bytes(1, byteorder='big'))
```

容易发现明文以```len(a)```为边界被分成两部分加密
前一部分是和```a[i]```作异或
这个```a```则是由```a = ''.join([chr(int(b, 16)) for b in [key[i:i+2] for i in range(0, len(key), 2)]])```得来的，也就是说```a```是由key得来的，因此前半部分是解出key的关键
但是我们不知道key的长度，先做个测试：

```python
from Crypto.Util.number import *


def lfsr(R, mask):
    output = (R << 1) & 0xffffffffffffffff
    i = (R & mask) & 0xffffffffffffffff
    lastbit = 0
    while i != 0:
        lastbit ^= (i & 1)
        i = i >> 1
    output ^= lastbit
    return (output, lastbit)


R = 0
mask = 0b1101100000000000000000000000000000000000000000000000000000000000

with open('Plain.txt', 'rb') as f:
    s = f.read()
with open('cipher.txt', 'rb') as f:
    cipher = f.read()

t = hex(bytes_to_long(s) ^ bytes_to_long(cipher))[2:]
s = 'sdgfjkahblskdjxbvfskljdfbguisldfbvghkljsdfbghsjkldhbgjklsdbgvlkjsdgbkljb sdkljfhwelo;sdfghioeurthgbnjl k'
lent = len(s)
for i in range(1, len(t)):
    key = t[:i]
    R = int(key, 16)
    a = ''.join([chr(int(b, 16)) for b in [key[i:i + 2] for i in range(0, len(key), 2)]])
    c = b''
    for j in range(0, len(a)):
        c += (ord(s[j]) ^ ord(a[j])).to_bytes(1, byteorder='big')

    for j in range(len(a), lent):
        tmp = 0
        for k in range(8):
            (R, out) = lfsr(R, mask)
            tmp = (tmp << 1) ^ out
        c += (tmp ^ ord(s[j])).to_bytes(1, byteorder='big')

    print(key)
    print(c)
    print(cipher)
    print(c == cipher)
    if c == cipher:
        print(i)
        break
```

发现都是False
是不是key前面缺个“0”？
修改代码：```t = '0' + hex(bytes_to_long(s) ^ bytes_to_long(cipher))[2:]```
得到结果：
![在这里插入图片描述](luozj1020 vacation_week3.assets/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70.png)
所以 **key 为 0123456789abcdef**
得到key之后前半段只要key和密文做异或即可得到明文，那后半段怎么办？
再观察代码可以发现，每次```for i```循环，都经过内部的```for j```循环生成一个```tmp```与明文作异或运算生成密文，而这个```tmp```与函数```lfsr()```有关，而```lfsr()```的参数一个参数```R```只与key有关，另一个参数```mask```是常量
那我们就可以不用管```lfsr()```函数，只要生成```tmp```与密文作异或运算就行了，也就是wp中所说的**黑箱方法**
解密代码如下（照搬wp）：

```python
key = '123456789abcdef'
R = int(key, 16)
mask = 0b1101100000000000000000000000000000000000000000000000000000000000


def lfsr(R, mask):
    output = (R << 1) & 0xffffffffffffffff
    i = (R & mask) & 0xffffffffffffffff
    lastbit = 0
    while i != 0:
        lastbit ^= (i & 1)
        i = i >> 1
    output ^= lastbit
    return (output, lastbit)


cipher = open('flag_encode.txt', 'rb').read()
a = ''.join([chr(int(b, 16)) for b in [key[i:i + 2] for i in range(0, len(key), 2)]])
ans = []
lent = len(cipher)

for i in range(0, len(a)):
    ans.append(chr(cipher[i] ^ ord(a[i])))

for i in range(len(a), lent):
    tmp = 0
    for j in range(8):
        (R, out) = lfsr(R, mask)
        tmp = (tmp << 1) ^ out
    ans.append(chr(tmp ^ cipher[i]))

flag = ''.join(ans)
print(flag)
```

结果为：
![在这里插入图片描述](luozj1020 vacation_week3.assets/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70.png)
关于线性反馈移位寄存器 - LFSR，后来在CTFwiki中找到了[相关结束](https://ctf-wiki.org/crypto/streamcipher/fsr/lfsr/)
题面的代码大都是先定义一个函数```lfsr()```
这里附上wp中的注释帮助理解：

```python
def lfsr(R, mask):
    # 左移1位：保留末尾 63 位，在最后添加一个0
    output = (R << 1) & 0xffffffffffffffff
    
    # i：保留 R 的前 0、1、3、4位
    i=(R&mask)&0xffffffffffffffff
    
    
    lastbit=0
    while i!=0:
        lastbit^=(i&1)
        i=i>>1
    # lastbit：统计 i 里面有多少个1, 奇数个则为1, 偶数个则为0

    # output: R 左移1位，再添加 lastbit
    output^=lastbit
    return (output,lastbit)
```

不同的地方就是这个```0xffffffffffffffff```里面“f”的个数，也就是初态的比特数
后面也会有一个生成```tmp```的过程：

```python
for i in range(len(a), lent):
    tmp = 0
    for j in range(8):
        (R, out) = lfsr(R, mask)
        tmp = (tmp << 1) ^ out
```

方法和具体原理感兴趣的可以研究一下

# 2021-8-1

## [2021i春秋云上巅峰赛]MediclImage

题面：
![在这里插入图片描述](luozj1020 vacation_week3.assets/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70.png)
加密代码如下：

```python
from PIL import Image
from decimal import *
import numpy as np
import random
getcontext().prec = 20

def f1(x):
    # It is based on logistic map in chaotic systems
    # The parameter r takes the largest legal value
    assert(x>=0)
    assert(x<=1)
    ...

def f2(x):
    # same as f1
    ...
def f3(x):
    # same as f1
    ...

def encryptImage(path):
    im = Image.open(path)
    size = im.size
    pic  = np.array(im) 
    im.close()
    r1 = Decimal('0.478706063089473894123')
    r2 = Decimal('0.613494245341234672318')
    r3 = Decimal('0.946365754637812381837')
    w,h = size
    for i in range(200):
        r1 = f1(r1)
        r2 = f2(r2)
        r3 = f3(r3)
    const = 10**14
    for x in range(w):
        for y in range(h):
            x1 = int(round(const*r1))%w
            y1 = int(round(const*r2))%h
            r1 = f1(r1)
            r2 = f2(r2)
            tmp = pic[y,x]
            pic[y,x] = pic[y1,x1]
            pic[y1,x1] = tmp
    p0 = random.randint(100,104)
    c0 = random.randint(200,204)
    config = (p0,c0)
    for x in range(w):
        for y in range(h):
            k = int(round(const*r3))%256
            k = bin(k)[2:].ljust(8,'0')
            k = int(k[p0%8:]+k[:p0%8],2)
            r3 = f3(r3)

            p0 = pic[y,x]
            c0 = k^((k+p0)%256)^c0
            pic[y,x] = c0

    return pic,size,config
def outputImage(path,pic,size):
    im = Image.new('P', size,'white')
    pixels = im.load()
    for i in range(im.size[0]):
        for j in range(im.size[1]):
            pixels[i,j] = (int(pic[j][i]))

    im.save(path)


def decryptImage(pic,size,config):
    .....
    
enc_img = 'flag.bmp'
out_im = 'flag_enc.bmp'

pic,size,_ = encryptImage(enc_img)
outputImage(out_im,pic,size)
```

看起来很复杂，而且函数```f1(x)```，```f2(x)```和```f3(x)```是未知的（虽然三个函数是一样的，不妨都记为f(x)）
根据注释内容搜了一下[Logistic map（单峰映象）](https://en.wikipedia.org/wiki/Logistic_map)：
![在这里插入图片描述](luozj1020 vacation_week3.assets/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70.png)
又搜了一下[针对医学影像的加密系统](http://www.cxyzjd.com/article/zsheng_/105904595)，里面也提到了一个Logistic映射
基本上可以确定f(x)=rx(1-x)，关键是确定这个r
wiki里面也提到了r不同情况下x的变化趋势：
![在这里插入图片描述](luozj1020 vacation_week3.assets/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl81MjQ0NjA5NQ==,size_16,color_FFFFFF,t_70.png)
注释中说是在混沌系统中，可以排除r小于3的情况
比较常见也是最初研究的是r=4的情况，那姑且认为r=4
再看加密函数```encryptImage(path)```，分成两段看
先看第一段：

```python
    im = Image.open(path)
    size = im.size
    pic  = np.array(im) 
    im.close()
    r1 = Decimal('0.478706063089473894123')
    r2 = Decimal('0.613494245341234672318')
    r3 = Decimal('0.946365754637812381837')
    w,h = size
    for i in range(200):
        r1 = f1(r1)
        r2 = f2(r2)
        r3 = f3(r3)
    const = 10**14
    for x in range(w):
        for y in range(h):
            x1 = int(round(const*r1))%w
            y1 = int(round(const*r2))%h
            r1 = f1(r1)
            r2 = f2(r2)
            tmp = pic[y,x]
            pic[y,x] = pic[y1,x1]
            pic[y1,x1] = tmp
```

先导入图片，这没什么好说的
然后r1，r2，r3经过200次f(x)后和常量const生成新的坐标，对原来的图片像素进行移位
要解密的话，只要存储原来坐标的列表或者矩阵，然后换回来就行
再看第二段：

```python
    p0 = random.randint(100,104)
    c0 = random.randint(200,204)
    config = (p0,c0)
    for x in range(w):
        for y in range(h):
            k = int(round(const*r3))%256
            k = bin(k)[2:].ljust(8,'0')
            k = int(k[p0%8:]+k[:p0%8],2)
            r3 = f3(r3)

            p0 = pic[y,x]
            c0 = k^((k+p0)%256)^c0
            pic[y,x] = c0
```

先随机生成了一个```config = (p0,c0)```，不过幸运的是p0和c0的范围都在```random.randint(100,104)```，遍历config的话也只要25种情况
后面就是对每个像素的加密，也可以分成两段
前一段：

```python
k = int(round(const*r3))%256
k = bin(k)[2:].ljust(8,'0')
k = int(k[p0%8:]+k[:p0%8],2)
r3 = f3(r3)
p0 = pic[y,x]
```

就是搞了个k，解密的时候也只要把每一次的k存储起来就行
后一段：

```python
p0 = pic[y,x]
c0 = k^((k+p0)%256)^c0
pic[y,x] = c0
```

这里把之前生成的p0和c0给换了，也就是```pic[y,x] = c0 = k ^ ((k+p0)%256) ^ c0```，而这里的```p0```是未加密时该点的像素值，这里的```c0```是加密过的前面一点的像素值
解密的时候只要将加密后的像素值与前一点的像素值还有之前储存的k的值作异或就可以得到```(k+p0)%256```，记为```k_p```
又因为k和p0都是小于等于256的，为了得到p0，也就是原来的像素值，只要

```python
k_p -= k
if k_p < 0:
	k_p += 256
```

得到的k_p就是原来的像素值
分析完毕，完整的解密代码如下：

```python
from PIL import Image
import numpy as np
from decimal import *
getcontext().prec = 20

def f(x):
    # It is based on logistic map in chaotic systems
    # The parameter r takes the largest legal value
    assert (x >= 0)
    assert (x <= 1)
    r = 4
    x = r * x * (1 - x)
    return x

im = Image.open('flag_enc.bmp')
pixels = im.load()
size = im.size
w, h = size
print(size)
# print(np.array(im))
pic = np.zeros((h, w))
const = 10 ** 14
r1 = Decimal('0.478706063089473894123')
r2 = Decimal('0.613494245341234672318')
r3 = Decimal('0.946365754637812381837')
for i in range(im.size[0]):
    for j in range(im.size[1]):
        pic[j][i] = pixels[i, j]
print(pic)

for i in range(200):
    r1 = f(r1)
    r2 = f(r2)
    r3 = f(r3)
p0 = range(100, 105)
c0 = range(200, 205)
config = []
# 列出(p0, c0)的所有情况
for p in p0:
    for c in c0:
        config.append((p, c))

# 记录原先的坐标x1, y1
list_x1 = np.zeros((h, w))
list_y1 = np.zeros((h, w))
for x in range(w):
    for y in range(h):
        x1 = int(round(const * r1)) % w
        y1 = int(round(const * r2)) % h
        list_x1[y][x] = x1
        list_y1[y][x] = y1
        r1 = f(r1)
        r2 = f(r2)

list_k = []
for conf in config:
    arrk = np.zeros((h, w))
    k = 0
    p0 = conf[0]
    c0 = conf[1]
    for x in range(w):
        for y in range(h):
            k = int(round(const * r3)) % 256
            k = bin(k)[2:].ljust(8, '0')
            k = int(k[p0 % 8:] + k[:p0 % 8], 2)
            r3 = f(r3)
            p0 = int(pic[y, x])
            arrk[y][x] = k
    list_k.append(arrk)
print(list_k)

list_p = []
for conf in config:
    x1 = 0
    y1 = 0
    picture = pic.copy()
    arrk = list_k[config.index(conf)]
    p0 = conf[0]
    c0 = conf[1]
    for x in range(w-1, -1, -1):
        for y in range(h-1, -1, -1):
            k = int(arrk[y][x])
            p0 = pic[y][x]
            if (y-1) >= 0:
                c0 = int(pic[y-1][x])
            elif (y - 1) < 0 and (x-1) < 0:
                pass
            else:
                c0 = int(pic[h-1][x-1])

            k_p = k ^ (int(pic[y][x])) ^ c0
            k_p -= k
            if k_p < 0:
                k_p += 256
            picture[y][x] = k_p

    for x in range(w - 1, -1, -1):
        for y in range(h - 1, -1, -1):
            x1 = int(list_x1[y][x])
            y1 = int(list_y1[y][x])
            tmp = picture[y1][x1]
            picture[y1][x1] = picture[y][x]
            picture[y][x] = tmp
    list_p.append(picture)
    print(picture)

for k in range(len(list_p)):
    im = Image.new('P', size, 'white')
    pixels = im.load()
    for i in range(im.size[0]):
        for j in range(im.size[1]):
            pixels[i, j] = (int(list_p[k][j][i]))
    im.save('p' + str(k) + '.bmp')
```

最后得到25张图片，出了第一张图片，都能看到flag
挑了一张比较清晰的：
![在这里插入图片描述](luozj1020 vacation_week3.assets/6bf6b68ee2b84e5cae6127d74a127386.bmp)
看不清的话可以和别的比对着看

