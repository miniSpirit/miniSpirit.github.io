丢进IDA，查看字符串，发现

`BJD{%d%d2069a45792d233ac}`

直接找到调用的函数位置，发现就是简单的sprintf，19999和0对应替换进去即可

### Flag  : `BJD{1999902069a45792d233ac}`

把BJD替换成flag即可