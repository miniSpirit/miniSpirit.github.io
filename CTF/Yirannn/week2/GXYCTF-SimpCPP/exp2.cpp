#include <cstdio>
unsigned char s[] = {
	0x3e, 0x3a, 0x46, 0x05, 0x33, 0x28, 0x6f, 0x0d,
	0x0d, 0x44, 0x33, 0x5b, 0x30, 0x1b, 0x2c, 0x3e,
	0x08, 0x02, 0x07, 0x17, 0x15, 0x3e, 0x30, 0x13,
	0x32, 0x31, 0x06, 0x00
};
char table[] = "i_will_check_is_debug_or_not";
int main(){
	for(int i = 0; i < 28; i ++ ) s[i] ^= table[i%27];
	printf("%s\n", s);
}