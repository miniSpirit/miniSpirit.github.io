简单的python逆向，先用uncompyle6把pyc文件反编译成py

正向是先把第i位＋i，在模128意义下。

然后把第i位和第i+1位异或，最后应当得到code那样的一个数组。

异或是最简单的逆向了，我们先把第i位和第i+1位异或的操作反向做一次。

然后把第i位-i，再加上0或1个128，且只输出可见码。

payload：

```cpp
#include <cstdio>
#include <cstring>
int num[] = {
    0x1f,
    0x12,
    0x1d,
    '(',
    '0',
    '4',
    0x01,
    0x06,
    0x14,
    '4',
    ',',
    0x1b,
    'U',
    '?',
    'o',
    '6',
    '*',
    ':',
    0x01,
    'D',
    ';',
    '%',
    0x13
};
int main() {
    int len = 23;
    for(int i = len-2; i > 0; i --) {
        num[i] ^= num[i+1];
    }
    for(int i = 0; i < len; i ++ ) {
        for(int j = 0; j < 2; j ++ ) {
            char ch = num[i]-i+128*j;
            if(ch >= 32 && ch <= 126) putchar(ch);
        }
    }
}
```

### Flag:`WHT{Just_Re_1s_Ha66y!}`

把WHT改成flag即可