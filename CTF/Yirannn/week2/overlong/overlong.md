很有意思的一道小题：

进入IDA，逻辑很简单，调用了一个函数，目的是修改402008的值

进到402008里面，发现这是一个超长的数组，结合题目名字overlong，发现main传入的循环上限太小了。该循环上限应当为0xAF

直接IDA patch，getflag

### **flag{I_a_M_t_h_e_e_n_C_o_D_i_n_g@flare-on.com}**

其实我做的时候并没有patch，是直接把整个函数拿下来自己跑的，后来看师傅们的wp，发现patch一下真方便啊。另外做的时候其实没有意识到是循环上限的问题，因为我看整个字符串最多能跑0x1c * 4（将近128了）位字符，而且text只能存128。

