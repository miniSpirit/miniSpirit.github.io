<!--more-->

题如其名，的确easy

IDA打开发现main啥也没干

直接打开exe还是啥也没干，干脆一个一个函数翻一下，发现_ques函数应该是关键函数，还有输出。

直接patch原main，把对__main的调用指向\_ques, 再打开程序获得flag

无payload

### FLAG : flag{HACKIT4FUN}