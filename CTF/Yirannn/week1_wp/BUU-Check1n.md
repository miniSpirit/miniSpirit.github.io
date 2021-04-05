EXE对用Apple Silicon的我来说实在是太不友好了。。



丢进IDA，先瞅一眼字符串。

发现这样一串东西，我赌它和Flag有关

`2i9Q8AtFJTfL3ahU2XGuemEqZJ2ensozjg1EjPJwCHy4RY1Nyvn1ZE1bZe`

(事实上后来发现的确有关，但是不必要，直接把它丢到BASE58解码即可)

大概看了几眼程序，发现不太能读懂，字符串下面有控制台画界面的东西，这么大个程序，应该可以运行一下。

九牛二虎之力翻出来一个家里的windows电脑，打开程序发现是台电脑。。。

要输入密码，随便输入的话是“密 码 错 误”四个大字。

去IDA里搜“密”然后回到汇编进而发现密码是"HelloWorld"

进到主界面发现flag.txt，告诉我是虚假的flag。。。BASE64解码后让去玩打砖块。

我很努力的玩了，但是难逃一死，发现死之后会把Flag给出。。

没有什么难度的一道题

### Flag：flag{f5dfd0f5-0343-4642-8f28-9adbb74c4ede}

