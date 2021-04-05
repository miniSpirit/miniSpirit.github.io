IDA 打开，发现有 upx 壳，先脱壳

IDA打开，找到main, 先f5，创建了两个线程，先进第一个线程看看

进入411090的时候出现栈不平衡，回到汇编界面修改栈指针

具体操作是：先在option里面打开stack pointer，这样就能看到栈指针（地址右侧的绿色数字）

到函数retn部分，发现红色的sp-analysis failed，在retn上面一行alt+k修改栈指针。

自己做的时候出现了修改栈指针失败`Command "ChangeStackPointer" failed`的情况，需要在retn上一行而不是那一行改就好了

发现是一个针对大小写加密的函数，针对大写字符，-38然后作为下标改为对应密码表中字符，针对小写，-96然后作为下标

从后往前做，每次下标指针--。

去看看另一个线程，只有下标指针--，因为改了全局变量名字，可以发现这两个线程操作的是同一个下标变量。

都说re有4分都在猜，这个可以大胆猜测是隔一个一改。由于对多线程的理解还很一般，只是简单了解了一下releasemutex和waitforsingleobject，大概能猜到一个是释放一个是接管，应该是线程交替接管程序，吧。

密码表`QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm`

encoded `TOiZiZtOrYaToUwPnToBsOaOapsyS`

payload:

```python
trans = "QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm"

targt = "TOiZiZtOrYaToUwPnToBsOaOapsyS"

ans = ""
for i in range(0, len(targt)) :
    if i & 1 :
        pos = trans.find(targt[i])
        if targt[i].isupper() :
            ans = ans + chr(pos+96)
        else :
            ans = ans + chr(pos+38)
    else :
        ans = ans + targt[i]
print(ans)
```

第一次写的时候竟然把 i&1写成了i and 1，我智障了

decode得到`ThisisthreadofwindowshahaIsES`

但是比要求的输入少一个字符，爆破得到应该是E

### flag{ThisisthreadofwindowshahaIsESE}