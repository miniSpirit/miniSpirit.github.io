很简单的异或加密，查看字符串找到关键函数，无法反汇编，直接看汇编。

注意到%s, 所以call 401050大概是一个scanf，另外上面还push了一个4212C0，所以输入应该存在4212C0中

4010B6应该是一个strlen，如果输入长度不是0x1B就直接wrong。

关键点在4010D0，每次把一个读入扔到cl里，然后cl和al 异或，之后cl和target 进行比较

al就是ax的低位，在上面我们xor eax，eax已经把ax清零了，同时ax还是一个自增的循环变量。

又一次不得不说这题难度低于前面的，BUU的刷题顺序不靠谱

exp很明显了：

```python
tar = "MSAWB~FXZ:J:`tQJ\"N@ bpdd}8g"
ans = ""
for i in range(0, 0x1B) :
    ans += chr(ord(tar[i])^i)
print(ans)
```

### flag:MRCTF{@_R3@1ly_E2_R3verse!}