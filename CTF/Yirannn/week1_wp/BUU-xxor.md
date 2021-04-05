比较明确的加密：

先读进来一个数组（实际上是六个int，不看下标看指针就好了）

分为三组，每次把一组结合601060加密，然后赋值给v11这个数组

最后进一个check函数，解一个三元一次方程。。。

```
a0 = -548868226
a1 = 550153460
a2 = 3774025685
a3 = 1548802262
a4 = 2652626477
a5 = -2064448480
```

对于加密函数，逆向脚本：

```cpp
#include <cstdio>
int a2[] = {2, 2, 3, 4};
unsigned int tar[] = {-548868226, 3774025685, 2652626477};
void solve(int x) {
    int v3 = x >> 16;
    int v4 = x & 0xffff;
    int tmp1 = 0;
    for(int i = 0; i <= 0x3f; i ++ ) tmp1 += 1166789954;
    for(int i = 0; i <= 0x3f; i ++ ) {
        v4 -= (v3 + tmp1 + 20) ^ ((v3 << 6) + a2[2]) ^ ((v3 >> 9) + a2[3]) ^ 0x10;
        v3 -= (v4 + tmp1 + 11) ^ ((v4 << 6) + *a2) ^ ((v4 >> 9) + a2[1]) ^ 0x20;
        tmp1 -= 1166789954;
    }
    int ans = ( v3 << 16 ) + (v4 & 0xffff);
    printf("%d\n", ans);
}
int main() {
    for(int i = 0; i < 3; i ++ ) {
        solve(tar[i]);
    }
}
```

然鹅这份脚本是错的。原来是我对DWORD的理解有误，DWORD和int是一样大的，修改后的如下：

```cpp
#include <cstdio>
int a2[] = {2, 2, 3, 4};
unsigned tar[] = {-548868226, 550153460, 3774025685, 1548802262, 2652626477, -2064448480};
void solve(unsigned* x) {
    unsigned v3 = *x;
    unsigned v4 = *(x+1);
    int v5 = 0x40 * 1166789954;
    for(int i = 0; i <= 0x3f; i ++ ) {
        v4 -= (v3 + v5 + 20) ^ ((v3 << 6) + a2[2]) ^ ((v3 >> 9) + a2[3]) ^ 0x10;
        v3 -= (v4 + v5 + 11) ^ ((v4 << 6) + *a2) ^ ((v4 >> 9) + a2[1]) ^ 0x20;
        v5 -= 1166789954;
    }
    *x = v3;
    *(x+1) = v4;
}
int main() {
    for(int i = 0; i < 6; i += 2 ) {
        solve(tar+i);
    }
    for(int i = 0; i < 6; i ++ ) printf("%c%c%c", (tar[i] >> 16) & 0xff, (tar[i] >> 8) & 0xff, tar[i]&0xff);
}
```

### flag : flag{re_is_great!}