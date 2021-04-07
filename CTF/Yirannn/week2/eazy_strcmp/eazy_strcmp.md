<!--more-->

以后写wp可能不会传到博客上了，都会统一传到训练的GitHub库里。

这道题很有意思，还是有必要记录一下的。网上的WP大多是知其然不知其所以然。本着透过现象看本质的思路，找到双草帮我看懂了这道题。

IDA打开，直接查看main函数，发现仅仅是把flag字符串和输入进行对比，这显然是不太行的，浏览函数，发现了关键函数Sub_6EA，这个函数显然是按8位的16进制对原字符串做了一个减法，最后得到\*\*\*\*CENSORED\*\*\*\*，思路很清晰。但是我在做的时候，从init到start都翻了一下，SUB_6EA也没有交叉引用，那到底是在哪里调用的这个函数？

双草分析之后发现这道题用了很巧妙的一个方法：答案在SUB_795中，发现SUB795保存并返回了strcmp的地址，存到了qword_201090中，我们去追一下这个qword的xref

发现sub_6EA返回的是qword_201090(a1, a2),也就是这个地方调用了strcmp。另外sub_795把off_201028改成了sub_6EA, 查看off_201028之后真相大白，原来off_201028原本存的是libc中的strcmp，sub795把原本指向strcmp的调用指向了sub6EA,而真正的strcmp被放在了qword201090中

exp

```cpp
#include <cstdio>

unsigned char Tar[] = "********CENSORED********";

unsigned char enc[25] = {
    0x42, 0x09, 0x4A, 0x49, 0x35, 0x43, 0x0A, 0x41,
    0xF0, 0x19, 0xE6, 0x0B, 0xF5, 0xF2, 0x0E, 0x0B,
    0x2B, 0x28, 0x35, 0x4A, 0x06, 0x3A, 0x0A, 0x4F
};
int main() {
    // for(int i = 0; i < 25; i ++ ) {
    //     printf("%c", (Tar[i]+enc[i])%128);
    // }
    int flg = 0;
    for(int i = 0; i < 25; i ++ ) {
        printf("%c", Tar[i]+enc[i]+flg);
        flg = (int)Tar[i]+enc[i] > 255;
    }
}
```

PS:注释部分是我一开始错误的想法，我想直接一个个加就好了，但是发现无论如何都不对，在进行代码检查的时候，偶然发现enc数组里面有0xF0，这个数字太大了，显然不是个ASCII字符，说明这个char溢出了，单独一个char溢出什么也不会出现，但是如果按原题8位一起加减的话，需要进行一个进位。问题就出在这个进位上。我们手动进位一下即可

### FLAG:l3ts_m4k3_4_DETOUR_t0d4y