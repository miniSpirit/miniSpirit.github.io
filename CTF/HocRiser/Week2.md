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

[**BUUCTF ningen**](https://buuoj.cn/challenges#ningen)

4位密码fcrackzip得到密码8368

*flag{b025fc9ca797a67d2103bfbc407a6d5f}*

[**BugKu web1**](https://ctf.bugku.com/challenges/detail/id/68.html)

查看源代码即可

[**BugKu web2**](https://ctf.bugku.com/challenges/detail/id/69.html)

审查元素，修改maxlength="2"即可。

[**BugKu web3**](https://ctf.bugku.com/challenges/detail/id/70.html)

index.php?what=flag

[**BugKu web5**](https://ctf.bugku.com/challenges/detail/id/72.html)

php中`==`为弱相等（值相等即可），`===`为强相等（类型与值均一样），故"1a"与"1"比较时会将"1a"截取前面尽量多位的纯数字，故"1a"=="1"。

[**BugKu web6**](https://ctf.bugku.com/challenges/detail/id/73.html)

源码中&#形式编码为Unicode，解码即可。

[**BugKu web7**](https://ctf.bugku.com/challenges/detail/id/74.html)

Burp suite中repeater功能逐步查看，获得flag
