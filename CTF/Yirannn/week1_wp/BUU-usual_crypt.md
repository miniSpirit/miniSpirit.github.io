<!--more-->

进到main，第一个函数传入了输入、输入长度和v5，结合下面的循环猜测：将输入转化后存入v5，该函数是关键函数

进入该函数（之所以不写函数地址是因为我都改过名字了，不方便看）

有一个索引表byte_40E0A0, 跳转看值，挺明显的一个base64表。

前面有一个函数401000，后面有一个函数401030，分别进入查看一下

401000是很明显的更改BASE64索引表，我选择直接写代码找到真的BASE64索引表

```cpp
#include <cstdio>
char s[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/\0";
int main() {
    char* _a0 = s;
    char* _aa = s+10;
    int cur = 6;
    do {
        char tmp = _aa[cur];
        _aa[cur] = _a0[cur];
        _a0[cur++] = tmp;
    }while(cur < 15);

    puts(s);
}
```

 转化后的索引表是`ABCDEFQRSTUVWXYPGHIJKLMNOZabcdefghijklmnopqrstuvwxyz0123456789+/`

401030好乱，怎么就和HIDWORD干上了，略微分析一下，应该是大小写转换，至于为什么用了那么多HIDWORD和LOBYTE，我只能理解为IDA抽风了。

因为v2-32或者+32恰好是对应的大写/小写，而把v1赋值给a1[hiword[v1]]，a1对应位也只会获得v1的lobyte。但是hiword(v1)还没有分析。个人认为原程序，应该是两个int，被IDA分析成了一个long long，还拆来拆去的。

最后得到的结果需要等于BYTE_40E0E4,

zMXHz3TIgnxLxJhFAdtZn2fFk3lYCrtPC2l9`

先大小写转换，再去cyberchef上用已经获得的密码表解密

getFlag

### flag{bAse64_h2s_a_Surprise}