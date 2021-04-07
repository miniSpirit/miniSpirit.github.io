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