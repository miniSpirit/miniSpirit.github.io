拿到手里，checksec，32位，没查壳扔到IDA里

main里乱七八糟的流符号估计是cin cout啥的，没管，看到了一个把v40加密的md5函数

接下来是非常明显的判断，如果加密之后的值是

`780438d5b6e29db0898bc4f0225935c0`

则是有效的key。

丢到cmd5上，结果是grape，很像对的答案了。

交上去一试，不对？什么情况？

把grape重新md5一下，发现grape的md5并不是‘780438...’什么的，人懵了

觉得可能是cmd5不对？换了个网站解md5发现这个md5的编码方式是把md5再md5一次。所以正确答案是grape的md5值