### .DS_Store
：.DS_Store 是Mac OS保存文件夹的自定义属性的隐藏文件。
通过.DS_Store 可以知道这个目录里面所有文件的清单。
打开环境后直接加/.DS_Store 可以得到一个文件，用notepad++打开后
出现如下内容会发现这样的内容：


$99e2199cb23887aaad9c63ffa2ed3386.txttnoteustrflaghere!


发现.txt后缀，输入99e2199cb23887aaad9c63ffa2ed3386.txt 发现正好是32位，猜测可能是MD5加密，访问后得到flag。

注：这里看见别人使用了010Editor,它是一个专业的文本编辑器和十六进制编辑器，可以更清晰简明地得到文件内容
界面比notepad++强百倍。


### 网站源码

：当开发人员在线上环境中对源代码进行了备份操作，并且将备份文件放在了 web 目录下，就会引起网站源码泄露


这个因为dirsearch卡了好久。
还是一直没能成功，最后换了dirmap来跑。
dirmap跑完之后一般都会把所得到的内容放在output文件夹中
并自动生成.txt文件，但是我在文件夹output中没有找到，
我重新看了下命令窗口，发现它将内容放入了字典模式时的文件
于是打开dict_mode_dict.txt文件，得到网页目录。
访问www.zip得到一个文件
打开后得到where is flag？的内容。
没有其余任何有用的文件。
然后发现该txt被命名为flag_20448922.txt
于是尝试访问一下
果然得到了flag。


### git泄露
花了一段时间在处理python2和3 共存的问题。
因为GitHack必须在python2环境下，但是使用的时候又出现了如下错误


urrlib2.urlopen error [errno 10060]

线程无端被挂，搜解决办法，但是都没找到具体可行的（我tcl）。

被学长推荐使用scrabble或者dvcs ripper

试一下。


