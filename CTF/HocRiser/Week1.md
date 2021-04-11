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
