丢进IDA，找到main

F5一下，我直接？又去看了诸多的函数，我人傻了，这就是babyre么？这不是入门题吧。

算了，好像不是这样子的。

回头看汇编，main的汇编一大串mov，好像不是很常见的亚子。

move的值实际上是一些Hex ASCII，按R转成Char之后发现前两位是fl，继续搞下去得到flag

## Flag：flag{Re_1s_S0_C0OL}