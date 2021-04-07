#include <cstdio>
#include <cstring>
int main() {
    for(int i = 1; i <= 16; i ++ ) {
        for(int j = 1; j <= 16; j ++ ) {
            int tmp;
            scanf("%x", &tmp);
            if(!tmp) printf(".");
            else if(tmp == 0x21)printf("!");
            else printf("*");
        }
        puts("");
    }
}