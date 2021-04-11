[**BugKu  这是一张单纯的图片**](https://ctf.bugku.com/challenges/detail/id/2.html)

strings file.jpg

&#为Unicode，解码即可

*key{you are right}*

[**BugKu 隐写**](https://ctf.bugku.com/challenges/detail/id/3.html)

png图片头IHDR后三四位为宽，七八位为高，一般会有一个出错。

可以[爆破](https://wiki.x10sec.org/misc/picture/png-zh/)验证CRC，这里是将高改为和宽一样。

*BUGKU{a1e5aSA}*

[**BugKu 眼见非实**](https://ctf.bugku.com/challenges/detail/id/5.html)

docx改为zip，得到document.xml

*flag{F1@g}*

[**BugKu 啊哒**](https://ctf.bugku.com/challenges/detail/id/6.html)

binwalk得到加密35695.zip，查看图片详细信息（mac下为工具-检查器-型号）可以看到base16编码，解码得到sdnisc_2018，从而打开压缩包得到flag.txt

*flag{3XiF_iNf0rM@ti0n}*

[**BugKu 又一张图片，还单纯吗**](https://ctf.bugku.com/challenges/detail/id/7.html)

foremost -i file.jpg

*falg{NSCTF_e6532a34928a3d1dadd0b049d5a3cc57}*

```fcrackzip -b -c aA1 -l 6-6 -p 000000 a.zip```

若密码在密码本文件里，则`fcrackzip -D -p passwd a.zip`

[**BugKu 多种方法解决**](https://ctf.bugku.com/challenges/detail/id/11.html)

文本编辑器打开，直接复制到浏览器就能打开。

或者base64转图片，扫描二维码。

*KEY{dca57f966e4e4e31fd5b15417da63269}*

[**BugKu 白哥的鸽子**](https://ctf.bugku.com/challenges/detail/id/14.html)

Hex打开发现fg2ivyo}l{2s3_o@aw__rcl@，栅栏数3解密即可。

*flag{w22_is_v3ry_cool}*

[**BugKu linux**](https://ctf.bugku.com/challenges/detail/id/15.html)

strings flag

*key{feb81d3834e2423c9903f4755464060b}*

[**BugKu 富强民主**](https://ctf.bugku.com/challenges/detail/id/61.html)

社会主义核心价值观编码 http://mix.bid/a/decoder/

*flag{90025f7fb1959936}*

[**BugKu 隐写3**](https://ctf.bugku.com/challenges/detail/id/16.html)

高度改为01DF即可

*flag{He1l0_d4_ba1}*

[**BugKu zip伪加密**](https://ctf.bugku.com/challenges/detail/id/57.html)

`50 4B 03 04 ** ** 00 00`（头文件标记）以及`50 4B 01 02 ** ** ** ** 00 00`（目录中文件文件头标记，中间分别表示压缩使用的软件和使用的版本）

*flag{Adm1N-B2G-kU-SZIP}*

[**BugKu Linux2**](https://ctf.bugku.com/challenges/detail/id/19.html)

strings搜索KEY

*KEY{24f3627a86fc740a7f36ee2c7a1c124a}*

[**BUU 金三胖**](https://buuoj.cn/challenges#%E9%87%91%E4%B8%89%E8%83%96)

gif逐帧查找flag

*flag{he11ohongke}*

[**BUU 二维码**](https://buuoj.cn/challenges#%E4%BA%8C%E7%BB%B4%E7%A0%81)

`binwalk -e` `fcrackzip -b -c1 -l 4 -u`得到密码7639

*flag{vjpw_wnoei}*

[**BUU N种方法解决**](https://buuoj.cn/challenges#N%E7%A7%8D%E6%96%B9%E6%B3%95%E8%A7%A3%E5%86%B3)

base64转图片

*KEY{dca57f966e4e4e31fd5b15417da63269}*

[**BUU 大白**](https://buuoj.cn/challenges#%E5%A4%A7%E7%99%BD)

png高度错误

```python
import os
import binascii
import struct


misc = open("dabai.png","rb").read()

for i in range(1024):
    data = misc[12:20] +struct.pack('>i',i)+ misc[24:29]
    crc32 = binascii.crc32(data) & 0xffffffff
    if crc32 == 0x6d7c7135:
        print i
```

正确高度479

*flag{He1l0_d4_ba1}*

[**BUU 文件中的秘密**](https://buuoj.cn/challenges)

Hex Friend

*flag{870c5a72806115cb5439345d8b014396}*

[**BUU zip伪加密**](https://buuoj.cn/challenges#zip%E4%BC%AA%E5%8A%A0%E5%AF%86)

两处09 00改为00 00即可

*flag{Adm1N-B2G-kU-SZIP}*

[**BUU ningen**](https://buuoj.cn/challenges#ningen)

4位密码fcrackzip得到密码8368

*flag{b025fc9ca797a67d2103bfbc407a6d5f}*

