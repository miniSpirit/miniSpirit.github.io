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