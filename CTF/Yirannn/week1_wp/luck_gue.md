<!--more-->

Check sec, 64位

扔进IDA，找到main 先f5

第一步需要输入一个偶数进入操作函数

操作函数只有case1，4，5有用

4是给f2赋值，5是对f2操作，1是接一下f1，f2，输出

f1明文 `GXY{do_not_`

f2 自己动手做一下即可，但要注意到IDA里看到的字符串是反的，需要手动反序一下。

f2有16位HEX，转Char之后只能看到7位char，少一位先没管

```cpp
#include <cstdio>
#include <cstring>
int main() {
    char str1[] = "icug`of\0";
    for(int i = 0; i < 8; i ++ ) {
        *(str1 + i) = --*(str1 + i) - (i&1);
    }
    printf("GXY{do_not_");
    puts(str1);
}
```

 运行结果是 

`GXY{do_not_hate_me�`

一位不可见字符，显然是}

其实这个不用程序，直接肉眼逆向也能看出来

提交提示incorrect，把GXY改成flag之后通过

### Flag:`flag{do_not_hate_me}`