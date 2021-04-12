#include <cstdio>
#include <cstdlib>
long long *trans(long long* inp, int a2, int a3) {
    long long *v6 =(long long*)malloc(0x18);
    v6[0] = inp[a2];
    v6[1] = (long long)trans(inp, 2*a2+1, a3);
    v6[2] = (long long)trans(inp, 2*(a2+1), a3);
    return v6;
}
int main() {
    char a[10];
    scanf("%s", a);
    long long *v4 = trans((long long*)a, 0, 10);
    for(int i = 0; i <= 20; i ++) {
        printf("%p %c\n", v4, *v4);
        v4 ++;
    }
}
