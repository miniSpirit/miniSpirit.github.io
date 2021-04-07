函数很少，4010F0是读入字符串到byte403078里面，

401050是一个check函数

401020是一个strlen

401000的返回值是固定的, 里面有一个ROL，这东西是一个IDA的宏定义，就是循环左移，懒得找的话也可以动态调试，直接拿到它的值.

然后通过异或把input的值逐个加密到403180里面，最后和target比对。

这个异或就是403180[i] = input[i]^input[i+1], 403180[n] = input[n] ^ v4

所以input[n] = target[n]\(也就是403180)^v4

​		input[i] = target[i]^input[i+1]

v4的原始值是4

所以payload如下：

```cpp
#include <cstdio>
int target[] = {0x0D, 0x26, 0x49, 0x45, 0x2A, 0x17, 0x78, 0x44, 0x2B, 0x6C, 0x5D, 0x5E, 0x45, 0x12, 0x2F, 0x17, 0x2B, 0x44, 0x6F, 0x6E, 0x56, 9, 0x5F, 0x45, 0x47, 0x73, 0x26, 0x0A, 0x0D, 0x13, 0x17, 0x48, 0x42, 1, 0x40, 0x4D, 0x0C, 2, 0x69};
int input[40] = {};
int main() {
    input[38] = target[38] ^ 4;
    for(int i = 37; i >= 0; i -- ) {
        input[i] = target[i] ^ input[i+1];
    }
    for(int i = 0; i < 39; i ++ ) putchar(input[i]);
}
```

### flag{R_y0u_H0t_3n0ugH_t0_1gn1t3@flare-on.com}

