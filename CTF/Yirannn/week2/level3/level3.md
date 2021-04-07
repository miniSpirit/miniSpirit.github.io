main函数，rand&1，两个不同分支。

第二个分支输出了一个b64，扔到cyberchef里看看，无意义字符串，但是能正常解码，考虑是替换了码表。

看看base64_encode函数，发现调用了base64_table这个数组，查询交叉引用，发现关键函数。

按关键函数整理一下base64_table即可。很简单的逆向

exp :

```cpp
#include <cstdio>
#include <iostream>
using namespace std;
char b64_tab[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
int main() {
    for(int i = 0; i <= 9; ++i ) {
        swap(b64_tab[i], b64_tab[19-i]);
    }
    puts(b64_tab);
}
```

b64_table :

TSRQPONMLKJIHGFEDCBAUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/

### Flag :wctf2020{Base64_is_the_start_of_reverse}