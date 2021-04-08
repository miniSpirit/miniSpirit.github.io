#include <cstdio>
// flag{d0_y0u_know_x86-64_a5m?}
// 66 2e 61 25 7b 26 30 1d 79 72 75 1d 6b 2c 6f 35 5f 3a 38 74 2d 74 34 1d 61 77 6d 7d 7d
int main() {
    int x, t = 0;
    while(~scanf("%x", &x)) {
        if(t & 1) x ^= 0x42;
        printf("%c", x);
        t ++;
    }
}