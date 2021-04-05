<!--more-->

IDA打开，用了个不知道是什么的库，盲猜是大整数，一个16进制数，一个10进制大数，一个65537，一个pow带模函数，盲猜RSA，直接yafu分解

payload

```python
import gmpy2
import binascii

p = 282164587459512124844245113950593348271
q = 366669102002966856876605669837014229419
c = 0xad939ff59f6e70bcbfad406f2494993757eee98b91bc244184a377520d06fc35
n = 103461035900816914121390101299049044413950405173712170434161686539878160984549
e = 65537
d = gmpy2.invert(e,(p-1)*(q-1))
m = gmpy2.powmod(c,d,n)
print(binascii.unhexlify(hex(m)[2:]).decode(encoding="utf-8"))

```

### Flag :suctf{Pwn_@_hundred_years}, BUU上要换成flag

