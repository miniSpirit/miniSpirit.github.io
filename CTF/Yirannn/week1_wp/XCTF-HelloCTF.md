丢IDA，查字符串，看到有Success字样，直接返回去找。

对一个输入的字符串做某种处理之后使得它和`437261636b4d654a757374466f7246756e`一样，要求是17位字符串。

每次把读入的十六进制打出来嘛，那就找两位十六进制对应的ASCII码就行了

payload：

```cpp
#include <cstdio>
char buf[] = "437261636b4d654a757374466f7246756e";
int main() {
    for(int i = 0; i < 34; i +=2 ) {
        int ASC;
        sscanf(buf+i, "%2x", &ASC);
        printf("%c", ASC);
    }
}
```

### Flag:CrackMeJustForFun