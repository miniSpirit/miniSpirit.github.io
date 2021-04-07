变种Base64，直接暴力枚举

exp如下

```cpp
#include <cstdio>
#include <cstring>
#include <iostream>
char target[13][5] = {"x2dt", "JEOm", "yjac", "xDem", "x2ec", "zT5c", "VS9f", "VUGv", "WTuZ", "Wjue", "xjRq", "y24r", "V29q"};
char table[] = {0x5A,0x59,0x58,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4A,0x4B,0x4C,0x4D,
0x4E,0x4F,0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57,0x7A,0x79,0x78,0x61,0x62,0x63,
0x64,0x65,0x66,0x67,0x68,0x69,0x6A,0x6B,0x6C,0x6D,0x6E,0x6F,0x70,0x71,0x72,0x73,
0x74,0x75,0x76,0x77,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x2B,0x2F};
char* encode(char *input1, unsigned int len)
{
  unsigned int v3; // ST24_4
  int v4; // ST2C_4
  int v5; // [esp+Ch] [ebp-24h]
  int v6; // [esp+10h] [ebp-20h]
  int v7; // [esp+14h] [ebp-1Ch]
  int i; // [esp+1Ch] [ebp-14h]
  char *v9; // [esp+24h] [ebp-Ch]
  int v10; // [esp+28h] [ebp-8h]
  unsigned int v11; // [esp+2Ch] [ebp-4h]

  v9 = (char*)malloc(4 * ((len + 2) / 3) + 1);
  if ( !v9 )
    return 0;
  v11 = 0;
  v10 = 0;
  while ( v11 < len )
  {
    if ( v11 >= len )
      v7 = 0;
    else
      v7 = input1[v11++];
    if ( v11 >= len )
      v6 = 0;
    else
      v6 = input1[v11++];
    if ( v11 >= len )
      v5 = 0;
    else
      v5 = input1[v11++];
    v3 = v5 + (v7 << 16) + (v6 << 8);
    v9[v10] = table[(v3 >> 18) & 0x3F];
    v4 = v10 + 1;
    v9[v4++] = table[(v3 >> 12) & 0x3F];
    v9[v4++] = table[(v3 >> 6) & 0x3F];
    v9[v4] = table[v5 & 0x3F];
    v10 = v4 + 1;
  }
  v9[4 * ((len + 2) / 3)] = 0;
  return v9;
}
int main () {
  for(int i = 0; i < 13; i ++ ) {
    for(int a1 = 32; a1 <= 126; a1 ++ ) for(int a2 = 32; a2 <= 126; a2 ++ ) 
    for(int a3 = 32; a3 <= 126; a3 ++ ) {
      char inp[4] = {a1, a2, a3, 0};
      char* now = encode(inp, 4);
      now[4] = 0;
      // printf("%s\n", now);
      if(!strcmp(now, target[i])) {
        printf("%s", inp);
        a1 = a2 = a3 = 32;
        i ++;
        if(i >= 13) return 0;
      }
    }

  }
}
```

